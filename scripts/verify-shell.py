"""Check the captured COM1 transcript of test-vbox.ps1 -Shell.

Matching a transcript checks evidence only; it does not establish image or VM
provenance. The boot/process verifiers run separately before the shell phase.
"""
import argparse
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


COMMANDS = (b"help", b"pid", b"echo shell-ox\x08k", b"cat /stage",
            b"cat /missing", b"no-such-command", b"exit")
INPUT = b"\r".join(COMMANDS) + b"\r"
START = re.compile(rb"(?m)^AGENTOS SHELL START PID=([0-9a-f]{16})\r\n")
SESSION_START = re.compile(rb"(?m)^AGENTOS MANAGER SESSION START PID=([0-9a-f]{16})\r\n")
STOP = re.compile(rb"(?m)^AGENTOS MANAGER SESSION STOP PID=([0-9a-f]{16}) "
                  rb"STATUS=([0-9a-f]{16}) FRAMES=OK\r\n")


def require(aCondition, aMessage):
    if not aCondition:
        raise VerificationError(aMessage)


def verify(aLog, aInput=None):
    pStarts, pStops = list(START.finditer(aLog)), list(STOP.finditer(aLog))
    pRoots = list(SESSION_START.finditer(aLog))
    require(len(pStarts) == len(pStops) == len(pRoots) == 1,
            "Expected one manager session and one complete child shell")
    pStart, pStop, pRootStart = pStarts[0], pStops[0], pRoots[0]
    pStartLines = [pLine for pLine in aLog.splitlines() if pLine.startswith(b"AGENTOS SHELL START")]
    pStopLines = [pLine for pLine in aLog.splitlines() if pLine.startswith(b"AGENTOS MANAGER SESSION STOP")]
    require(len(pStartLines) == 1 and len(pStopLines) == 1,
            "Malformed or duplicate shell phase boundary")
    pPid = int(pStart[1], 16)
    pManager = int(pRootStart[1], 16)
    require(pPid != 0 and pManager != 0 and pPid != pManager and
            pRootStart[1] == pStop[1] and int(pStop[2], 16) == 0,
            "Manager/shell identity or root exit status mismatch")
    require(pRootStart.end() <= pStart.start() < pStop.start(),
            "Manager/shell session boundaries are out of order")
    require(not aLog[pStop.end():].strip(b"\r\n"), "Unexpected records after shell STOP")

    # Separate command echo from output. In particular, the edited echo command
    # contains the erased 'x', while the actual response must contain 'shell-ok'.
    pExpected = (
        b"AGENTOS SHELL READY\r\nagentos> help\r\n"
        b"help       List commands\r\npid        Show process ID\r\n"
        b"echo TEXT  Print text\r\ncat PATH   Read an initramfs file\r\n"
        b"services   Show service registry\r\n"
        b"service start|stop|restart core|flaky\r\n"
        b"exit       Close the shell\r\nagentos> pid\r\n" + str(pPid).encode("ascii") +
        b"\r\nagentos> echo shell-ox\b \bk\r\nshell-ok\r\n"
        b"agentos> cat /stage\r\nAgentOS stage 1\r\n"
        b"agentos> cat /missing\r\ncat: open failed (-2)\r\n"
        b"agentos> no-such-command\r\nerror: unknown command or arguments; use help\r\n"
        b"agentos> exit\r\nAGENTOS SHELL EXIT\r\n"
    )
    pPhase = aLog[pStart.end():pStop.start()]
    require(pPhase.startswith(pExpected), "Missing or incorrect shell command response/echo sequence")
    pTail = pPhase[len(pExpected):]
    child_exit = re.match(rb"AGENTOS USER EXIT PID=([0-9a-f]{16}) "
                          rb"CR3=([0-9a-f]{16}) STATUS=0000000000000000\r\n", pTail)
    require(child_exit is not None and child_exit[1] == pStart[1],
            "Missing matching successful child shell exit")
    pCr3 = int(child_exit[2],16)
    require(pCr3 != 0 and pCr3 % 4096 == 0, "Invalid child shell address-space root")
    pTail = pTail[child_exit.end():]
    phase = (f"AGENTOS MANAGER SHUTD ROOT={pManager:016x} COUNT=00000003\r\n").encode()
    require(pTail.startswith(phase), "Manager did not enter ordered shutdown after shell exit")
    pTail = pTail[len(phase):]
    # The stable service is still running and must be killed/reaped. Its
    # kernel-authored kill event cannot name the shell or the manager itself.
    kill = re.compile(rb"AGENTOS USER KILL PID=([0-9a-f]{16}) "
                      rb"PARENT=([0-9a-f]{16}) STATUS=0000000000000089\r\n")
    kills = []
    while (match := kill.match(pTail)):
        require(int(match[1],16) not in (pPid,pManager) and
                int(match[2],16)==pManager and int(match[1],16) not in kills,
                "Manager shutdown killed a foreign, duplicate or shell process")
        kills.append(int(match[1],16))
        pTail=pTail[match.end():]
    require(kills, "No worker stopped during ordered shutdown")
    phase=(f"AGENTOS MANAGER ENDED ROOT={pManager:016x} COUNT=00000003\r\n").encode()
    require(pTail.startswith(phase), "Manager did not complete ordered shutdown")
    pTail=pTail[len(phase):]
    manager_exit=re.fullmatch(rb"AGENTOS USER EXIT PID=([0-9a-f]{16}) "
                              rb"CR3=([0-9a-f]{16}) STATUS=0000000000000000\r\n",pTail)
    require(manager_exit is not None and int(manager_exit[1],16)==pManager and
            int(manager_exit[2],16)!=0 and int(manager_exit[2],16)%4096==0,
            "Manager did not exit successfully from its own address space")
    if aInput is not None:
        require(aInput == INPUT, "Transmitted command bytes differ from the smoke scenario")
    return pPid


def main():
    pParser = argparse.ArgumentParser(description=__doc__)
    pParser.add_argument("--log", type=Path, required=True)
    pParser.add_argument("--input", type=Path, help="Optional raw transmitted bytes (com1-input.bin)")
    pArgs = pParser.parse_args()
    try:
        pPid = verify(pArgs.log.read_bytes(), pArgs.input.read_bytes() if pArgs.input else None)
    except (OSError, VerificationError) as pError:
        print(f"Shell verification failed: {pError}", file=sys.stderr)
        return 1
    print(f"Shell transcript verified for PID {pPid}: {pArgs.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
