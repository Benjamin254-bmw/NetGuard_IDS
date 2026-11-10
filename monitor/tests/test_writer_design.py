"""Design guards that must run in plain `make test` (no database needed)."""

import threading

from netguard_monitor.persistence.writer import BatchWriter


def test_writer_does_not_subclass_thread() -> None:
    # Python 3.13 added Thread._handle; a subclass with a clashing private attribute silently
    # broke the writer on the developer's machine. Composition keeps us immune to such additions.
    assert not issubclass(BatchWriter, threading.Thread)
    assert hasattr(BatchWriter, "process") and not hasattr(threading.Thread, "process")
