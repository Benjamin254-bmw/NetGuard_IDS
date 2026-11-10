"""On-disk spill for batches that could not be written to the database.

Files are written atomically (temp file, fsync, rename) and replayed oldest-first. Replay is safe
to repeat because every batch carries an id recorded in the database ledger in the same
transaction as its data. The directory is private (0700): it holds traffic metadata.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Batch:
    batch_id: str
    kind: str  # "traffic" | "devices"
    created_at: float
    payload: Any


class SpillStore:
    def __init__(self, directory: Path, max_bytes: int) -> None:
        self._dir = directory
        self._max_bytes = max_bytes
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)

    def bytes_used(self) -> int:
        return sum(p.stat().st_size for p in self._dir.glob("*.jsonl"))

    def pending(self) -> list[Path]:
        return sorted(self._dir.glob("*.jsonl"))

    @property
    def backlog(self) -> int:
        return len(self.pending())

    def write(self, batch: Batch) -> bool:
        """Persist a batch. Returns False (and writes nothing) if the size cap would be exceeded."""
        data = json.dumps(
            {
                "batch_id": batch.batch_id,
                "kind": batch.kind,
                "created_at": batch.created_at,
                "payload": batch.payload,
            },
            separators=(",", ":"),
        ).encode()
        if self.bytes_used() + len(data) > self._max_bytes:
            return False
        final = self._dir / f"{time.time_ns():020d}-{batch.batch_id}.jsonl"
        tmp = final.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data + b"\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, final)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
        return True

    def read(self, path: Path) -> Batch | None:
        """Load a spilled batch; a corrupt file is quarantined as .bad and None is returned."""
        try:
            raw = json.loads(path.read_text())
            return Batch(
                str(raw["batch_id"]), str(raw["kind"]), float(raw["created_at"]), raw["payload"]
            )
        except (OSError, ValueError, KeyError, TypeError):
            log.error("quarantining unreadable spill file %s", path.name)
            with contextlib.suppress(OSError):
                path.rename(path.with_suffix(".bad"))
            return None

    def delete(self, path: Path) -> None:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
