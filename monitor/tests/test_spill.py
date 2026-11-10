import json
import stat
from pathlib import Path

from netguard_monitor.persistence.spill import Batch, SpillStore


def batch(i: int = 0, kind: str = "traffic", payload: object = None) -> Batch:
    return Batch(
        f"00000000-0000-4000-8000-{i:012d}", kind, 1_700_000_000.0 + i, payload or {"n": i}
    )


def test_round_trip_and_oldest_first(tmp_path: Path) -> None:
    s = SpillStore(tmp_path / "spill", 10**6)
    for i in (3, 1, 2):
        assert s.write(batch(i))
    names = [p.name for p in s.pending()]
    assert names == sorted(names) and s.backlog == 3
    first = s.read(s.pending()[0])
    assert first is not None and first.payload == {"n": 3}  # written first, read first
    assert first.kind == "traffic" and first.batch_id.endswith("000000000003")


def test_files_are_private(tmp_path: Path) -> None:
    s = SpillStore(tmp_path / "spill", 10**6)
    s.write(batch())
    assert stat.S_IMODE((tmp_path / "spill").stat().st_mode) == 0o700
    assert stat.S_IMODE(s.pending()[0].stat().st_mode) == 0o600


def test_partial_writes_are_never_visible(tmp_path: Path) -> None:
    s = SpillStore(tmp_path / "spill", 10**6)
    (tmp_path / "spill" / "00000000000000000001-partial.tmp").write_text("{trunc")
    assert s.pending() == [] and s.backlog == 0
    s.write(batch())
    assert s.backlog == 1


def test_size_cap_refuses_and_writes_nothing(tmp_path: Path) -> None:
    s = SpillStore(tmp_path / "spill", 600)
    big = batch(payload={"blob": "x" * 300})
    assert s.write(big) is True
    assert s.write(batch(1, payload={"blob": "y" * 300})) is False
    assert s.backlog == 1 and s.bytes_used() <= 600


def test_corrupt_file_is_quarantined_not_retried_forever(tmp_path: Path) -> None:
    s = SpillStore(tmp_path / "spill", 10**6)
    (tmp_path / "spill" / "00000000000000000001-x.jsonl").write_text("not json")
    (tmp_path / "spill" / "00000000000000000002-y.jsonl").write_text(
        json.dumps({"kind": "traffic"})
    )
    for p in s.pending():
        assert s.read(p) is None
    assert s.pending() == [] and len(list((tmp_path / "spill").glob("*.bad"))) == 2


def test_delete_is_idempotent(tmp_path: Path) -> None:
    s = SpillStore(tmp_path / "spill", 10**6)
    s.write(batch())
    p = s.pending()[0]
    s.delete(p)
    s.delete(p)
    assert s.backlog == 0
