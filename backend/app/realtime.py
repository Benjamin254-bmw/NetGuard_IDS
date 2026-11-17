"""Live updates over a WebSocket.

Source of truth stays in PostgreSQL. The monitor commits an alert and sends NOTIFY with only the
alert id; this hub LISTENs on one dedicated connection (api role), reads the alert row, and fans it
out. NOTIFY is transient, so a client that was disconnected (or a hub that lost its connection)
catches up through the REST list with ``after_id``; the hub says so with a ``resync`` message.

Each client has a bounded queue. A client that cannot keep up is disconnected rather than allowed
to grow memory without limit. Sessions are re-checked against the database periodically, so logout,
deactivation, or a password change ends an open socket too.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import psycopg
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from psycopg.conninfo import make_conninfo
from sqlalchemy import Engine, text

from app import security as sec
from app.api.alerts import fetch_alert
from app.api.system import monitor_status
from netguard_common.config import Settings

log = logging.getLogger("api.realtime")
router = APIRouter()

CHANNEL = "ids_alerts"
QUEUE_SIZE = 100
STATUS_INTERVAL = 5.0
RECHECK_INTERVAL = 15.0
MAX_CLIENT_MESSAGE = 256  # clients only ever send a tiny "ping"
WS_POLICY = 1008
WS_TRY_LATER = 1013
WS_SESSION_ENDED = 4401

_USER = text("SELECT id, is_active, session_version FROM users WHERE id = :id")


@dataclass(eq=False)
class Client:
    user_id: int
    session_version: int
    expires_at: datetime
    queue: asyncio.Queue[dict[str, Any]] = field(default_factory=lambda: asyncio.Queue(QUEUE_SIZE))
    overflowed: bool = False


class Hub:
    def __init__(self, settings: Settings, engine: Engine) -> None:
        self.settings = settings
        self.engine = engine
        self.clients: set[Client] = set()
        self._tasks: list[asyncio.Task[None]] = []
        self.listening = False

    # -- lifecycle -------------------------------------------------------------------------
    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._listen()), asyncio.create_task(self._status())]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t

    # -- fan-out ---------------------------------------------------------------------------
    def broadcast(self, message: dict[str, Any]) -> None:
        for c in list(self.clients):
            try:
                c.queue.put_nowait(message)
            except asyncio.QueueFull:
                c.overflowed = True  # the connection handler closes it; never block the hub
                self.clients.discard(c)

    def _conninfo(self) -> str:
        s = self.settings
        pw = s.db_api_password
        return make_conninfo(
            host=s.db_host,
            port=s.db_port,
            dbname=s.db_name,
            user=s.db_api_user,
            password=pw.get_secret_value() if pw else None,
            connect_timeout=5,
        )

    def _read_alert(self, alert_id: int) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            return fetch_alert(conn, alert_id)

    async def _listen(self) -> None:
        delay, was_connected = 1.0, False
        while True:
            try:
                async with await psycopg.AsyncConnection.connect(
                    self._conninfo(), autocommit=True
                ) as conn:
                    await conn.execute(f"LISTEN {CHANNEL}")
                    self.listening = True
                    delay = 1.0
                    if was_connected:  # notifications may have been missed while we were away
                        self.broadcast({"type": "resync"})
                    was_connected = True
                    async for note in conn.notifies():
                        await self._on_notify(note.payload)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("LISTEN connection lost: %s", type(exc).__name__)
            self.listening = False
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)

    async def _on_notify(self, payload: str) -> None:
        try:
            alert_id = int(payload)
        except ValueError:
            log.warning("ignoring malformed notification payload")
            return
        try:
            alert = await asyncio.to_thread(self._read_alert, alert_id)
        except Exception as exc:
            log.warning("could not read alert %s: %s", alert_id, type(exc).__name__)
            self.broadcast({"type": "resync"})
            return
        if alert is not None:
            self.broadcast({"type": "alert", "alert": jsonable_encoder(alert)})

    def _read_status(self) -> dict[str, Any]:
        with self.engine.connect() as conn:
            return monitor_status(conn)

    async def _status(self) -> None:
        while True:
            await asyncio.sleep(STATUS_INTERVAL)
            if not self.clients:
                continue
            try:
                st = await asyncio.to_thread(self._read_status)
            except Exception as exc:
                log.warning("status read failed: %s", type(exc).__name__)
                continue
            self.broadcast({"type": "monitor", "status": jsonable_encoder(st)})


def _session_valid(engine: Engine, client: Client) -> bool:
    if datetime.now(UTC) >= client.expires_at:
        return False
    with engine.connect() as conn:
        row = conn.execute(_USER, {"id": client.user_id}).first()
    return bool(row and row.is_active and row.session_version == client.session_version)


def _last_alert_id(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT COALESCE(max(id), 0) FROM alerts")).scalar_one())


async def _sender(ws: WebSocket, client: Client) -> None:
    while True:
        await ws.send_json(await client.queue.get())


async def _receiver(ws: WebSocket, client: Client) -> None:
    while True:
        msg = await ws.receive_text()
        if len(msg) > MAX_CLIENT_MESSAGE:
            await ws.close(WS_POLICY)
            return
        if msg == "ping":
            client.queue.put_nowait({"type": "pong"})


async def _watchdog(engine: Engine, client: Client) -> None:
    while True:
        await asyncio.sleep(RECHECK_INTERVAL)
        if client.overflowed or not await asyncio.to_thread(_session_valid, engine, client):
            return


@router.websocket("/api/ws")
async def live(ws: WebSocket) -> None:
    settings: Settings = ws.app.state.settings
    engine: Engine | None = ws.app.state.engine
    hub: Hub | None = getattr(ws.app.state, "hub", None)
    origin = ws.headers.get("origin")
    if engine is None or hub is None:
        await ws.close(WS_TRY_LATER)
        return
    if origin is not None and origin.rstrip("/") not in {
        *settings.origins,
        f"{ws.url.scheme.replace('ws', 'http')}://{ws.headers.get('host', '')}",
    }:
        await ws.close(WS_POLICY)  # before accept: the handshake is refused
        return
    token = ws.cookies.get(sec.SESSION_COOKIE)
    try:
        claims = sec.decode_token(settings, token or "")
    except sec.InvalidToken:
        await ws.close(WS_POLICY)
        return
    client = Client(claims.user_id, claims.session_version, claims.expires_at)
    if not await asyncio.to_thread(_session_valid, engine, client):
        await ws.close(WS_POLICY)
        return
    await ws.accept()
    hub.clients.add(client)
    watch: asyncio.Task[None] | None = None
    try:
        last = await asyncio.to_thread(_last_alert_id, engine)
        await ws.send_json(
            {"type": "hello", "last_alert_id": last, "server_time": datetime.now(UTC).isoformat()}
        )
        tasks = [
            asyncio.create_task(_sender(ws, client)),
            asyncio.create_task(_receiver(ws, client)),
            watch := asyncio.create_task(_watchdog(engine, client)),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        if watch in done:
            code = WS_TRY_LATER if client.overflowed else WS_SESSION_ENDED
            with contextlib.suppress(RuntimeError):
                await ws.close(code)
        for t in done:
            exc = t.exception()
            if exc and not isinstance(exc, WebSocketDisconnect):
                log.debug("websocket ended: %s", type(exc).__name__)
    finally:
        hub.clients.discard(client)
