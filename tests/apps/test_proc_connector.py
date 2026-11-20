from __future__ import annotations

import struct

from pyvpn.apps.proc_connector import _exec_pid


def test_extracts_exec_tgid_from_connector_message() -> None:
    event = struct.pack("=IIII", 2, 0, 0, 0) + struct.pack("=II", 123, 456)
    connector = struct.pack("=IIIIHH", 1, 1, 1, 0, len(event), 0) + event
    payload = connector
    message = struct.pack("=IHHII", 16 + len(payload), 3, 0, 1, 0) + payload
    assert _exec_pid(message) == 456
