"""Synthetic rejection tests; fixtures are never recorded as guest evidence."""
import ast
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
pSpec = importlib.util.spec_from_file_location("stage3Session", ROOT / "scripts/verify-stage3-session.py")
v = importlib.util.module_from_spec(pSpec)
pSpec.loader.exec_module(v)

HELP = ("help       List commands\r\npid        Show process ID\r\n"
        "echo TEXT  Print text\r\ncat PATH   Read an initramfs file\r\n"
        "services   Show service registry\r\n"
        "service start|stop|restart core|flaky\r\n"
        "idle       Measure timer wakeups over 5 seconds\r\n"
        "exit       Close the shell\r\n")


def registry(aState, aCount):
    return ("core: running (attempts=1)\r\n" +
            f"flaky: {aState} (attempts={aCount})\r\n" +
            "shell: running (attempts=1)\r\n")


def worker_exit(aPid):
    return f"AGENTOS USER EXIT PID={aPid:016x} CR3=0000000000200000 STATUS=000000000000002a\r\n"


def transcript(aKeyboard=False):
    pCommands = [
        ("help", HELP), ("pid", "9\r\n"),
        ("echo shell-ox\b \bk", "shell-ok\r\n"),
        ("cat /stage", "AgentOS stage 1\r\n"),
        ("cat /missing", "cat: open failed (-2)\r\n"),
        ("no-such-command", "error: unknown command or arguments; use help\r\n"),
        ("services", registry("failed", 3)),
        ("service start flaky", registry("starting", 1)),
        ("service stop flaky", "AGENTOS USER KILL PID=000000000000000a PARENT=0000000000000001 STATUS=0000000000000089\r\n" + registry("stopped", 0)),
        ("idle", "AGENTOS RUNTIME IDLE MS=0000000000001388 TIMERS=0000000000000005 IDLE=0000000000000005\r\n"),
        ("services", registry("stopped", 0)),
        ("service restart flaky", registry("starting", 1)),
        ("services", registry("failed", 3)),
        ("service stop flaky", registry("stopped", 0)),
        ("services", registry("stopped", 0)),
    ]
    if aKeyboard:
        pCommands.append(("echo ps2-ox\b \bk", "ps2-ok\r\n"))
    pText = ("AGENTOS MANAGER SESSION START PID=0000000000000001\r\n"
             "AGENTOS MANAGER START ROOT=0000000000000001 SERVICE=core  PID=0000000000000002 ATTEMPT=00000001\r\n"
             "AGENTOS SHELL START PID=0000000000000009\r\n"
             "AGENTOS SHELL READY\r\nagentos> ")
    for pCommand, pReply in pCommands:
        pText += pCommand + "\r\n" + pReply + "agentos> "
        if pCommand == "service restart flaky":
            pText += "".join(worker_exit(pPid) for pPid in (11, 12, 13))
    pText += ("exit\r\nAGENTOS SHELL EXIT\r\n"
              "AGENTOS USER EXIT PID=0000000000000009 CR3=0000000000300000 STATUS=0000000000000000\r\n"
              "AGENTOS MANAGER SHUTD ROOT=0000000000000001 COUNT=00000003\r\n"
              "AGENTOS USER KILL PID=0000000000000002 PARENT=0000000000000001 STATUS=0000000000000089\r\n"
              "AGENTOS MANAGER ENDED ROOT=0000000000000001 COUNT=00000003\r\n"
              "AGENTOS USER EXIT PID=0000000000000001 CR3=0000000000400000 STATUS=0000000000000000\r\n"
              "AGENTOS MANAGER SESSION STOP PID=0000000000000001 STATUS=0000000000000000 FRAMES=OK\r\n"
              "[INFO] INTERACTIVE SHELL STOPPED\r\n")
    return pText.encode("ascii")


def migrationTranscript(aCpus=2, aKeyboard=False, aTimers=11):
    pSpec = importlib.util.spec_from_file_location(
        "sessionMigrationFixture", ROOT / "scripts/test-verify-migration.py")
    pFixture = importlib.util.module_from_spec(pSpec)
    pSpec.loader.exec_module(pFixture)
    pBoot = pFixture.scenario(aCpus).encode("ascii")
    pBoot = pBoot[:pBoot.index(b"AGENTOS SHELL START")]
    pSession = transcript(aKeyboard)
    pSession = pSession[pSession.index(b"AGENTOS SHELL START"):]
    for pOld,pNew in ((2,101),(9,105),(10,106),(11,107),(12,108),(13,109)):
        pSession = pSession.replace(f"PID={pOld:016x}".encode(),f"PID={pNew:016x}".encode())
    pSession = pSession.replace(b"pid\r\n9\r\n",b"pid\r\n105\r\n")
    for pField in (b"TIMERS",b"IDLE"):
        pSession = re.sub(pField+rb"=[0-9a-f]{16}",pField+f"={aTimers:016x}".encode(),pSession)
    return pBoot+pSession


class SessionTests(unittest.TestCase):
    def rejected(self, aLog, aInput=None, aKeyboard=False, aCpus=None):
        with self.assertRaises(v.VerificationError):
            v.verify(aLog, aInput, aKeyboard, aCpus)

    def test_full_serial_and_ps2_sessions(self):
        for pKeyboard in (False, True):
            pResult = v.verify(transcript(pKeyboard), v.transmitted_input(9, pKeyboard), pKeyboard)
            self.assertEqual(pResult["restarted_pids"], [11, 12, 13])
            self.assertEqual(pResult["idle"]["timer_irqs"], 5)

    def test_each_response_event_and_input_is_required(self):
        pText = transcript()
        for pLine in pText.splitlines(keepends=True):
            if pLine.startswith(b"[INFO] "):
                # The independent BOOT.LOG sink verifier owns optional
                # structured output; native session evidence is mandatory.
                continue
            with self.subTest(line=pLine):
                self.rejected(pText.replace(pLine, b"", 1))
        self.rejected(pText, v.transmitted_input(9).replace(b"\x08", b""))
        self.rejected(transcript(True), v.transmitted_input(9), True)

    def test_no_fake_delayed_or_foreign_service_control(self):
        pText = transcript()
        for pOld, pNew in (
            (b"flaky: starting (attempts=1)", b"flaky: down (attempts=0)"),
            (b"flaky: stopped (attempts=0)", b"flaky: running (attempts=1)"),
            (b"CR3=0000000000200000", b"CR3=0000000000200001"),
            (b"STATUS=000000000000002a", b"STATUS=0000000000000000"),
            (b"USER EXIT PID=000000000000000b", b"USER EXIT PID=0000000000000002"),
            (b"USER KILL PID=000000000000000a", b"USER KILL PID=0000000000000009"),
            (b"FRAMES=OK", b"FRAMES=LEAK"),
        ):
            with self.subTest(old=pOld):
                self.rejected(pText.replace(pOld, pNew, 1))
        self.rejected(pText.replace(worker_exit(11).encode(), worker_exit(12).encode()))

    def test_runtime_tickless_requires_elapsed_time_and_actual_idle_interrupts(self):
        pText = transcript()
        for pField, pValue in ((b"MS", 4999), (b"MS", 15001), (b"TIMERS", 500),
                               (b"TIMERS", 0), (b"IDLE", 0), (b"IDLE", 6), (b"IDLE", 1)):
            pChanged = re.sub(pField + rb"=[0-9a-f]{16}", pField + f"={pValue:016x}".encode(), pText)
            self.rejected(pChanged)

    def testNativeV2IdleKeepsOneWatchdogPerConfiguredCpu(self):
        for pKeyboard in (False,True):
            pResult = v.verify(migrationTranscript(2,pKeyboard),v.transmitted_input(105,pKeyboard),
                               pKeyboard,2)
            self.assertEqual(pResult["idle"]["timer_irqs"],11)
            self.assertEqual(pResult["idle"]["timer_cpu_count"],2)
        self.rejected(migrationTranscript(1,aTimers=11),aCpus=1)
        self.rejected(migrationTranscript(2,aTimers=500),aCpus=2)
        pTooBusy = migrationTranscript().replace(b"IDLE=000000000000000b",b"IDLE=0000000000000008")
        self.rejected(pTooBusy,aCpus=2)

    def testNativeV2CpuBudgetRequiresMatchingCompleteMigrationEvidence(self):
        pLog = migrationTranscript()
        self.rejected(pLog)
        self.rejected(pLog,aCpus=1)
        for pCpus in (0,3,True,"2"):
            self.rejected(pLog,aCpus=pCpus)
        pMove = next(pLine for pLine in pLog.splitlines(keepends=True)
                     if pLine.startswith(b"AGENTOS MIGRATION MOVED"))
        self.rejected(pLog.replace(pMove,b"",1),aCpus=2)
        self.rejected(pLog.replace(b"CPUS=0000000000000002",b"CPUS=0000000000000001",1),aCpus=2)
        pForged = migrationTranscript(1).replace(b"CPUS=0000000000000001",b"CPUS=0000000000000002")
        self.rejected(pForged,aCpus=2)

    def testHistoricalCpuLocalTimingNeverInheritsAggregateBudget(self):
        pLog = transcript().replace(b"TIMERS=0000000000000005 IDLE=0000000000000005",
                                    b"TIMERS=000000000000000b IDLE=000000000000000b")
        self.rejected(pLog,aCpus=2)
        self.assertEqual(v.verify(transcript(),aCpus=2)["idle"]["timer_cpu_count"],1)

    def test_complete_kernel_events_can_interrupt_echo_but_not_invent_output(self):
        pText = transcript()
        pRecord = b"AGENTOS USER KILL PID=000000000000000a PARENT=0000000000000001 STATUS=0000000000000089\r\n"
        pText = pText.replace(pRecord, b"").replace(b"service stop flaky", b"service st" + pRecord + b"op flaky", 1)
        v.verify(pText)
        self.rejected(pText.replace(b"\r\nshell-ok\r\n", b"\r\n"))
        self.rejected(pText.replace(pRecord, pRecord.replace(b"STATUS=", b"STATUS=!")))

    def test_help_plan_comes_from_current_shell_producer(self):
        pSource = (ROOT / "user/shell.c").read_text()
        pMatch = re.search(r'pOk = writeText\(("help       List commands.*?"\s*)\);', pSource, re.S)
        self.assertIsNotNone(pMatch)
        pText = "".join(ast.literal_eval(pLiteral) for pLiteral in re.findall(r'"(?:\\.|[^"\\])*"', pMatch[1]))
        self.assertEqual(pText, HELP)
        self.assertIsNotNone(re.fullmatch(v.steps(9)[0]["pattern"], "help\r\n" + pText + "agentos> "))

    def test_json_plan_is_portable_and_declares_exact_kernel_event_contract(self):
        pRun = subprocess.run([sys.executable, str(ROOT / "scripts/verify-stage3-session.py"),
                               "--plan-pid", "9", "--keyboard"], check=True, capture_output=True)
        pPlan = json.loads(pRun.stdout)
        self.assertEqual(pPlan["kernel_event_pattern"], v.KERNEL_EVENT.pattern.decode())
        self.assertEqual(pPlan["steps"], v.steps(9, True))
        for pStep in pPlan["steps"]:
            self.assertNotIn("\r", pStep["pattern"])
            self.assertNotIn("\n", pStep["pattern"])
            self.assertNotIn("\x08", pStep["pattern"])


if __name__ == "__main__":
    unittest.main()
