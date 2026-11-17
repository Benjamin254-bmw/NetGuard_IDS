"""WebSocket: authentication, origin policy, live delivery from NOTIFY, back-pressure, revocation."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from starlette.websockets import WebSocketDisconnect

from app import realtime
from conftest import sign_in  # type: ignore[import-not-found]
from dbhelpers import EventMaker, needs_db, run

pytestmark = needs_db

MakeUser = Callable[..., int]


@pytest.fixture
def live_client(
    make_client: Callable[..., TestClient], make_user: MakeUser
) -> Iterator[TestClient]:
    make_user("ann")
    with make_client() as c:  # entering the context runs the app lifespan (starts the hub)
        sign_in(c, "ann")
        deadline = time.time() + 5
        while not c.app.state.hub.listening:  # type: ignore[attr-defined]
            assert time.time() < deadline, "hub never started listening"
            time.sleep(0.02)
        yield c


def notify_alert(db: dict[str, Engine], event_id: int, *, commit: bool = True) -> int:
    with db["monitor"].connect() as conn:
        alert_id = int(
            conn.execute(
                text(
                    "INSERT INTO alerts (event_id, severity, title) VALUES (:e,'high','Scan') RETURNING id"
                ),
                {"e": event_id},
            ).scalar_one()
        )
        conn.execute(text("SELECT pg_notify('ids_alerts', CAST(:i AS text))"), {"i": str(alert_id)})
        conn.commit() if commit else conn.rollback()
    return alert_id


@contextmanager
def ws(c: TestClient, **kw: Any) -> Iterator[Any]:
    with c.websocket_connect("/api/ws", **kw) as s:
        yield s


def test_requires_a_valid_session(make_client: Callable[..., TestClient]) -> None:
    with make_client() as c:
        with pytest.raises(WebSocketDisconnect), ws(c):
            pass


def test_foreign_origin_is_refused(live_client: TestClient) -> None:
    with (
        pytest.raises(WebSocketDisconnect),
        ws(live_client, headers={"origin": "https://evil.example"}),
    ):
        pass
    with ws(live_client, headers={"origin": "http://127.0.0.1:5173"}) as s:  # configured origin
        assert s.receive_json()["type"] == "hello"


def test_hello_ping_and_oversized_message(live_client: TestClient) -> None:
    with ws(live_client) as s:
        hello = s.receive_json()
        assert hello["type"] == "hello" and hello["last_alert_id"] == 0
        s.send_text("ping")
        assert s.receive_json() == {"type": "pong"}
        s.send_text("x" * 1000)
        with pytest.raises(WebSocketDisconnect):
            s.receive_json()


def test_committed_alert_is_pushed_from_the_database_row(
    live_client: TestClient, db: dict[str, Engine], make_event: EventMaker
) -> None:
    ev = make_event(src_ip="10.10.10.77", dedup_key="k")
    with ws(live_client) as s:
        s.receive_json()
        alert_id = notify_alert(db, ev)
        msg = s.receive_json()
        assert msg["type"] == "alert"
        assert msg["alert"]["id"] == alert_id and msg["alert"]["src_ip"] == "10.10.10.77"
        assert msg["alert"]["category"] == "port_scan" and msg["alert"]["status"] == "new"


def test_rolled_back_and_malformed_notifications_are_not_delivered(
    live_client: TestClient, db: dict[str, Engine], make_event: EventMaker
) -> None:
    ev = make_event()
    with ws(live_client) as s:
        s.receive_json()
        notify_alert(db, ev, commit=False)  # NOTIFY inside a rolled-back transaction never fires
        run(db["monitor"], "SELECT pg_notify('ids_alerts', 'not-a-number')")
        run(db["monitor"], "SELECT pg_notify('ids_alerts', '999999')")  # no such alert row
        s.send_text("ping")
        assert s.receive_json() == {"type": "pong"}  # nothing else was queued before the pong


def test_every_client_receives_the_alert(
    live_client: TestClient, db: dict[str, Engine], make_event: EventMaker
) -> None:
    ev = make_event()
    with ws(live_client) as a, ws(live_client) as b:
        a.receive_json(), b.receive_json()
        alert_id = notify_alert(db, ev)
        assert a.receive_json()["alert"]["id"] == alert_id
        assert b.receive_json()["alert"]["id"] == alert_id


def test_session_revocation_closes_the_socket(
    live_client: TestClient, db: dict[str, Engine], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(realtime, "RECHECK_INTERVAL", 0.2)
    with ws(live_client) as s:
        s.receive_json()
        run(db["api"], "UPDATE users SET session_version = session_version + 1")
        with pytest.raises(WebSocketDisconnect) as info:
            while True:
                if s.receive_json()["type"] == "monitor":  # first status push is at 5 s
                    pytest.fail("socket still open after the session was revoked")
        assert info.value.code == realtime.WS_SESSION_ENDED
    # and a new connection with the old cookie is refused outright
    with pytest.raises(WebSocketDisconnect), ws(live_client):
        pass


def test_deactivated_user_cannot_connect(live_client: TestClient, db: dict[str, Engine]) -> None:
    run(db["api"], "UPDATE users SET is_active = false")
    with pytest.raises(WebSocketDisconnect), ws(live_client):
        pass


def test_slow_client_is_cut_off_instead_of_growing_memory() -> None:
    hub = realtime.Hub(None, None)  # type: ignore[arg-type]  # broadcast needs neither
    from datetime import UTC, datetime

    slow = realtime.Client(1, 1, datetime.now(UTC))
    fast = realtime.Client(2, 1, datetime.now(UTC))
    hub.clients |= {slow, fast}

    async def go() -> None:
        for i in range(realtime.QUEUE_SIZE + 5):
            hub.broadcast({"type": "alert", "n": i})
            fast.queue.get_nowait()  # the fast client keeps up

    asyncio.run(go())
    assert slow.overflowed and slow.queue.qsize() == realtime.QUEUE_SIZE
    assert hub.clients == {fast} and not fast.overflowed


def test_hub_recovers_and_tells_clients_to_resync(
    live_client: TestClient, db: dict[str, Engine]
) -> None:
    with ws(live_client) as s:
        s.receive_json()
        killed = run(  # the api role may terminate its own role's sessions, nobody else's
            db["api"],
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE usename = current_user AND pid <> pg_backend_pid() AND query LIKE 'LISTEN%'",
        )
        assert killed, "found no LISTEN session to terminate"
        assert s.receive_json() == {"type": "resync"}  # reconnected; clients must backfill
