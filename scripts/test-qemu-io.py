"""Transport unit tests with socket pairs / fake QMP; never VM evidence."""
import importlib.util
import io
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest import mock

pSpec = importlib.util.spec_from_file_location("qemuIo", Path(__file__).with_name("qemu-smoke.py"))
v = importlib.util.module_from_spec(pSpec)
pSpec.loader.exec_module(v)


class QmpStream:
    def __init__(self, aResponses):
        self.fInput = io.BytesIO(b"".join(json.dumps(pValue).encode() + b"\r\n" for pValue in aResponses))
        self.fSent = []

    def readline(self, aLimit):
        return self.fInput.readline(aLimit)

    def write(self, aData):
        self.fSent.append(json.loads(aData))
        return len(aData)

    def close(self):
        pass


class QemuIoTests(unittest.TestCase):
    def qmp(self, aResponses):
        pStream = QmpStream([{"QMP": {"version": {}}}] + aResponses)
        pSocket = mock.Mock()
        pSocket.makefile.return_value = pStream
        with mock.patch.object(v.socket, "socket", return_value=pSocket):
            pClient = v.Qmp(Path("fake-qmp.sock"))
        return pClient, pStream

    def test_qmp_negotiates_and_matches_ids_while_ignoring_events(self):
        pClient, pStream = self.qmp([{"event": "RESUME"}, {"id": 1, "return": {}},
                                    {"id": 2, "return": {"status": "running"}}])
        self.assertEqual(pClient.execute("query-status"), {"status": "running"})
        self.assertEqual(pStream.fSent, [{"execute": "qmp_capabilities", "id": 1},
                                         {"execute": "query-status", "id": 2}])
        pClient.close()

    def test_qmp_rejects_wrong_id_failed_command_and_disconnection(self):
        for pReply in ({"id": 2, "return": {}}, {"id": 1, "error": {"desc": "unsupported"}},
                       {"id": 1, "unexpected": True}):
            with self.subTest(reply=pReply), self.assertRaises(RuntimeError):
                self.qmp([pReply])
        with self.assertRaises(RuntimeError):
            self.qmp([])

    def test_ps2_command_uses_real_qcodes_with_backspace_and_return(self):
        pCommand = "echo ps2-ox\bk"
        pClient, pStream = self.qmp([{"id": pId, "return": {}} for pId in range(1, len(pCommand) + 3)])
        with mock.patch.object(v.time, "sleep"):
            pClient.keyboard(pCommand)
        pEvents = pStream.fSent[1:]
        self.assertEqual([pEvent["execute"] for pEvent in pEvents], ["send-key"] * (len(pCommand) + 1))
        self.assertEqual([pEvent["arguments"]["keys"][0]["data"] for pEvent in pEvents],
                         ["e", "c", "h", "o", "spc", "p", "s", "2", "minus", "o", "x", "backspace", "k", "ret"])
        self.assertTrue(all(pEvent["arguments"]["keys"][0]["type"] == "qcode" for pEvent in pEvents))
        with self.assertRaises(ValueError):
            pClient.keyboard("\x01")
        pClient.close()

    def test_uart_capture_and_input_are_actual_socket_bytes(self):
        with tempfile.TemporaryDirectory() as pDirectory:
            pLog = Path(pDirectory) / "com1.log"
            pHost, pGuest = socket.socketpair()
            pHost.settimeout(0.1)
            pGuest.settimeout(1)
            pCapture = v.UartCapture(pHost, pLog)
            try:
                pActual = b"different guest bytes\x00\xff\r\n"
                pGuest.sendall(pActual)
                pCapture.send(b"echo x\bk\r")
                self.assertEqual(pGuest.recv(100), b"echo x\bk\r")
                pUntil = time.monotonic() + 1
                while (not pLog.exists() or pLog.read_bytes() != pActual) and time.monotonic() < pUntil:
                    time.sleep(0.005)
                self.assertEqual(pLog.read_bytes(), pActual)
                self.assertEqual(pLog.with_name("com1-input.bin").read_bytes(), b"echo x\bk\r")
            finally:
                pCapture.close()
                pGuest.close()


if __name__ == "__main__":
    unittest.main()
