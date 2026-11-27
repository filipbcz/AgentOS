#!/usr/bin/env python3
"""Host-only test of the real tracer callbacks; no inferior or guest is started."""
import ast
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TRACE = Path(__file__).with_name("trace.py")
BASE, ROOT_PID, PEER_PID = 0xd000000, 75, 77
CPUS = (0x246000, 0x255000)
SP, CHANNEL, RX, CTX = 0x500000, 0x600000, 0x700000, 0x800000
SEND, RECV = 0x26da7, 0x26cba
PEER = struct.pack("<QII", ROOT_PID, 1000, 1000)
PAYLOAD = struct.pack("<QQQ", 5, 2, 1)
ENVELOPE = ("event", "seq", "host_ns", "thread", "pc")


class Fixture:
    def __init__(self):
        self.memory = {}
        self.registers = {}
        self.ptid = (1, 1, 0)
        self.gdb = SimpleNamespace(selected_inferior=lambda: self,
                                   selected_thread=lambda: SimpleNamespace(ptid=self.ptid),
                                   parse_and_eval=lambda name: self.registers[name[1:]])

    def put(self, address, data):
        self.memory.update({address+i: value for i, value in enumerate(data)})

    def word(self, address, value):
        self.put(address, struct.pack("<Q", value))

    def read_memory(self, address, size):
        return bytes(self.memory[address+i] for i in range(size))

    def prepare(self, sending):
        self.memory.clear()
        cpu = CPUS[0 if sending else 1]
        self.ptid = (1, 1 if sending else 2, 0)
        site = SEND if sending else RECV
        self.registers = {"pc": BASE+site, "rsp": SP, "r13": 24,
                          "r15": CHANNEL if sending else RX, "r12": 0, "r14": 1}
        self.put(SP, bytes(0x100))
        self.word(SP+0x10, CHANNEL)
        self.word(SP+0x38, cpu)
        self.word(SP+0x88, cpu)
        self.word(SP+0x58, CTX)
        self.word(SP+0x68, BASE+(0xc608 if sending else 0x154b4))
        self.word(SP+0x98, BASE+0xc8f3)
        self.put(CTX+0x278, struct.pack("<5Q", 0x8000400100, 0x23, 0, 0x900000, 0))
        self.put(cpu+0x150, b"\x01")
        self.put(cpu+0x1b8, struct.pack("<QQ", 1, 0))
        task = bytearray(0xd8)
        struct.pack_into("<QQ", task, 0x30, ROOT_PID if sending else PEER_PID,
                         11 if sending else ROOT_PID)
        task[0xd0] = task[0xd2] = 1
        self.put(cpu+0x1b8+0x40, task)
        self.word(BASE+0x42cd8, 52)
        raw = bytearray(0x418)
        raw[:24] = PAYLOAD
        raw[0x400:0x410] = PEER
        struct.pack_into("<Q", raw, 0x410, 24 if sending else 0)
        self.put(CHANNEL+0x10 if sending else RX, raw)
        return site


def load_callbacks(directory, fixture):
    # Execute the actual module initialization and definitions, not a copy of
    # mailbox/record. Exclude only the known live-debugger launch/finalizer.
    tree = ast.parse(TRACE.read_bytes(), filename=str(TRACE))
    assignment, launch = tree.body[-2:]
    if not (isinstance(assignment, ast.Assign) and len(assignment.targets) == 1 and
            isinstance(assignment.targets[0], ast.Name) and assignment.targets[0].id == "result" and
            isinstance(launch, ast.Try) and ast.unparse(launch.body[0]) == "main()"):
        raise RuntimeError("Tracer entrypoint changed; review host fixture")
    tree.body = tree.body[:-2]
    stage = directory/"build/supervisor-staging"
    stage.mkdir(parents=True)
    # These files are only read at initialization; runtime ELF matching is
    # deliberately outside this callback-only test.
    (directory/"build/kernel.elf").write_bytes(b"")
    (stage/"supervisor-runner").write_bytes(b"")
    request = directory/"request.json"
    request.write_text(json.dumps(dict(base=BASE, shell=11, root=str(directory), destination=str(directory))))
    ns = {"__name__": "trace_host_fixture", "__file__": str(TRACE)}
    with patch.dict(sys.modules, {"gdb": fixture.gdb}), patch.dict(os.environ, {"AGENTOS_IPC_TRACE_REQUEST": str(request)}):
        exec(compile(tree, str(TRACE), "exec"), ns)
    ns.update(root_pid=ROOT_PID, cpus=dict(zip(CPUS, (0, 1))),
              time=SimpleNamespace(monotonic_ns=iter(range(100, 200)).__next__))
    return ns


class MailboxTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agentos-mailbox-host-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.fixture = Fixture()
        self.ns = load_callbacks(self.directory, self.fixture)
        self.addCleanup(self.ns["out"].close)

    def rows(self):
        self.ns["out"].flush()
        return [json.loads(line) for line in (self.directory/"scheduler-trace.jsonl").read_text().splitlines()]

    def check(self, row, sending, seq):
        self.assertEqual(row["event"], "ipc_send_committed" if sending else "ipc_receive_committed")
        self.assertEqual((row["seq"], row["host_ns"], row["thread"], row["pc"]),
                         (seq, 99+seq, [1, 1 if sending else 2, 0], BASE+(SEND if sending else RECV)))
        self.assertEqual((row["pid"], row["sender"], row["apic"]),
                         (ROOT_PID if sending else PEER_PID, ROOT_PID, 0 if sending else 1))
        self.assertIs(type(row["kind"]), int)
        self.assertEqual((row["kind"], row["round"], row["token"], row["side"], row["channel"]),
                         (5, 2, 1, 1, CHANNEL))
        self.assertEqual((row["authenticated_peer"], row["payload"], row["mailbox_length"]),
                         (PEER.hex(), PAYLOAD.hex(), 24 if sending else 0))
        self.assertEqual((row["global_count"], row["gate"], row["context"]["address"]), (52, 1, CTX))

    def test_send(self):
        self.ns["mailbox"](self.fixture.prepare(True))
        self.assertEqual(len(self.rows()), 1)
        self.check(self.rows()[0], True, 1)

    def test_receive(self):
        self.ns["mailbox"](self.fixture.prepare(False))
        self.assertEqual(len(self.rows()), 1)
        self.check(self.rows()[0], False, 1)

    def test_sequence(self):
        for sending in (True, False):
            self.ns["mailbox"](self.fixture.prepare(sending))
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        for seq, row in enumerate(rows, 1):
            self.check(row, seq == 1, seq)
        self.assertEqual(self.ns["counts"], {"ipc_send_committed": 1, "ipc_receive_committed": 1})

    def test_envelope_collision(self):
        self.fixture.prepare(True)
        for key in ENVELOPE:
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "trace payload shadows envelope"):
                self.ns["record"]("collision", **{key: -1})
        self.assertEqual(self.rows(), [])
        self.assertEqual((self.ns["events"], self.ns["counts"]), (0, {}))
        self.ns["mailbox"](self.fixture.prepare(True))
        self.check(self.rows()[0], True, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
