"""Shared real-input stage-3 session and strict captured-transcript verifier.

QEMU and VirtualBox use the same command contract. Expected bytes are used
only for comparisons; the actual UART capture is never modified or generated.
The scenario proves immediate SPAWN acknowledgement, STOP persistence, three
real restarted worker exits, timer-backed idle, TTY editing and clean shutdown.
"""
import argparse
import json
from pathlib import Path
import re
import sys

HEX = rb"[0-9a-f]{16}"
ROOT_START = re.compile(rb"(?m)^AGENTOS MANAGER SESSION START PID=("+HEX+rb")\r\n")
SHELL_START = re.compile(rb"(?m)^AGENTOS SHELL START PID=("+HEX+rb")\r\n")
SESSION_STOP = re.compile(rb"(?m)^AGENTOS MANAGER SESSION STOP PID=("+HEX+rb") "
                          rb"STATUS=0000000000000000 FRAMES=OK\r\n")
EXIT = re.compile(rb"AGENTOS USER EXIT PID=("+HEX+rb") CR3=("+HEX+rb") STATUS=("+HEX+rb")\r\n")
KILL = re.compile(rb"AGENTOS USER KILL PID=("+HEX+rb") PARENT=("+HEX+rb") STATUS=0000000000000089\r\n")
KERNEL_EVENT = re.compile(rb"AGENTOS USER (?:EXIT PID="+HEX+rb" CR3="+HEX+rb" STATUS="+HEX+
                          rb"|KILL PID="+HEX+rb" PARENT="+HEX+rb" STATUS=0000000000000089)\r\n")
IDLE = re.compile(rb"AGENTOS RUNTIME IDLE MS=("+HEX+rb") TIMERS=("+HEX+rb") IDLE=("+HEX+rb")\r\n")


class VerificationError(ValueError):
    pass


def require(aCondition, aMessage):
    if not aCondition:
        raise VerificationError(aMessage)


def registry_text(aFlaky, aAttempts):
    return ("core: running (attempts=1)\r\n"+
            f"flaky: {aFlaky} (attempts={aAttempts})\r\n"+
            "shell: running (attempts=1)\r\n")


def literal(aText):
    # JSON plans are consumed by Python and .NET Regex in PowerShell. Make
    # control bytes explicit instead of Python's backslash + literal newline.
    return (re.escape(aText).replace("\\\r", r"\r").replace("\\\n", r"\n")
            .replace("\\\t", r"\t").replace("\x08", r"\x08"))


def steps(aPid, aKeyboard=False):
    pHelp = ("help       List commands\r\npid        Show process ID\r\n"
             "echo TEXT  Print text\r\ncat PATH   Read an initramfs file\r\n"
             "services   Show service registry\r\n"
             "service start|stop|restart core|flaky\r\n"
             "idle       Measure timer wakeups over 5 seconds\r\n"
             "exit       Close the shell\r\n")
    pCommands = [
        ("help",pHelp), ("pid",str(aPid)+"\r\n"),
        ("echo shell-ox\x08k","shell-ok\r\n"),
        ("cat /stage","AgentOS stage 1\r\n"),
        ("cat /missing","cat: open failed (-2)\r\n"),
        ("no-such-command","error: unknown command or arguments; use help\r\n"),
        ("services",registry_text("failed",3)),
        ("service start flaky",registry_text("starting",1)),
        ("service stop flaky",registry_text("stopped",0)),
        ("idle",None),
        ("services",registry_text("stopped",0)),
        ("service restart flaky",registry_text("starting",1)),
        ("services",registry_text("failed",3)),
        ("service stop flaky",registry_text("stopped",0)),
        ("services",registry_text("stopped",0)),
    ]
    if aKeyboard:
        pCommands.append(("echo ps2-ox\x08k","ps2-ok\r\n"))
    pCommands.append(("exit","AGENTOS SHELL EXIT\r\n"))
    pSteps = []
    for pCommand,pReply in pCommands:
        pEcho = pCommand.replace("\x08", "\x08 \x08")+"\r\n"
        pReplyPattern = literal(pReply) if pReply is not None else IDLE.pattern.decode()
        pPattern = literal(pEcho)+pReplyPattern
        if pCommand != "exit": pPattern += literal("agentos> ")
        pSteps.append({
            "command":pCommand,"pattern":pPattern,
            "transport":"keyboard" if aKeyboard and pCommand in ("echo ps2-ox\x08k","exit") else "serial",
            "wait_exits":3 if pCommand=="service restart flaky" else 0,
            "screenshot":aKeyboard and pCommand=="echo ps2-ox\x08k",
        })
    return pSteps


def transmitted_input(aPid, aKeyboard=False):
    return b"".join((pStep["command"]+"\r").encode("ascii")
                    for pStep in steps(aPid,aKeyboard) if pStep["transport"]=="serial")


def without_kernel_events(aBytes):
    # Syscall diagnostics can occur between the echoed characters of a command.
    # Strip only complete, well-formed records for response matching. verify()
    # separately validates every such record and its ownership/status/order.
    return KERNEL_EVENT.sub(b"",aBytes)


def verify_idle(aBytes):
    pMatches = list(IDLE.finditer(aBytes))
    require(len(pMatches)==1,"Expected exactly one runtime idle measurement")
    pMs,pTimers,pIdle = (int(pValue,16) for pValue in pMatches[0].groups())
    require(5000 <= pMs <= 15000,"Runtime idle did not cover the requested five-second sleep")
    require(1 <= pIdle <= pTimers and pTimers-pIdle <= 2,
            "Runtime idle counters do not describe blocked-queue timer interrupts")
    # The independent clock watchdog is at most once per second; allow a few
    # boundary/preemption IRQs. The former 10ms periodic timer fails by >50x.
    require(pTimers <= (pMs+999)//1000+4,
            "Runtime idle still has excessive periodic scheduler interrupts")
    return {"milliseconds":pMs,"timer_irqs":pTimers,"idle_timer_irqs":pIdle}


def verify(aLog, aInput=None, aKeyboard=False):
    pRoots,pChildren,pEnds = (list(pPattern.finditer(aLog)) for pPattern in
                              (ROOT_START,SHELL_START,SESSION_STOP))
    require(len(pRoots)==len(pChildren)==len(pEnds)==1,
            "Expected one PID1 session, one shell and one frame-clean shutdown")
    pRoot,pShell = int(pRoots[0][1],16),int(pChildren[0][1],16)
    require(pRoot==1 and pShell>pRoot and int(pEnds[0][1],16)==pRoot and
            pRoots[0].end()<pChildren[0].start()<pEnds[0].start(),
            "Session identity or lifetime order mismatch")
    pCore = re.findall(rb"AGENTOS MANAGER START ROOT=0000000000000001 SERVICE=core  PID=("+
                       HEX+rb") ATTEMPT=00000001\r\n",aLog[pRoots[0].end():pChildren[0].start()])
    require(len(pCore)==1 and 1<int(pCore[0],16)<pShell,"Missing original ready core worker identity")
    pCorePid = int(pCore[0],16)
    pPhase = aLog[pChildren[0].end():pEnds[0].start()]
    pShellExits = [pMatch for pMatch in EXIT.finditer(pPhase) if int(pMatch[1],16)==pShell]
    require(len(pShellExits)==1 and int(pShellExits[0][3],16)==0 and
            int(pShellExits[0][2],16)>0 and int(pShellExits[0][2],16)%4096==0,
            "Managed shell did not exit normally from its address space")
    pInteractive = pPhase[:pShellExits[0].start()]
    pClean = without_kernel_events(pInteractive)
    pExpected = re.escape(b"AGENTOS SHELL READY\r\nagentos> ")+b"".join(
        pStep["pattern"].encode("ascii") for pStep in steps(pShell,aKeyboard))
    require(re.fullmatch(pExpected,pClean) is not None,
            "Incorrect extended command echo/response/state sequence")
    pIdle = verify_idle(pClean)
    if aInput is not None:
        require(aInput==transmitted_input(pShell,aKeyboard),"Captured transmitted UART bytes differ from scenario")
    pRestart = pInteractive.find(b"service restart flaky\r\n")
    require(pRestart>=0,"No explicit service RESTART command")
    pAfterRestart = pInteractive[pRestart:]
    pExits = list(EXIT.finditer(pAfterRestart))
    require(len(pExits)==3,"Restart did not produce exactly three real worker exits")
    pSeen = set()
    for pMatch in EXIT.finditer(pInteractive):
        pPid,pCr3,pStatus = (int(pValue,16) for pValue in pMatch.groups())
        require(pPid>pShell and pPid not in pSeen and pCr3>0 and pCr3%4096==0 and pStatus==42,
                "Foreign, duplicate or malformed restarted worker exit")
        pSeen.add(pPid)
    pKilled = set()
    for pMatch in KILL.finditer(pInteractive):
        pPid,pParent = int(pMatch[1],16),int(pMatch[2],16)
        require(pPid>pShell and pParent==pRoot and pPid not in pSeen and pPid not in pKilled,
                "Service STOP killed a foreign or already-reaped process")
        pKilled.add(pPid)
    require(pKilled or len(pSeen)>3,"Initial START/STOP has no actual worker termination evidence")
    pTail = pPhase[pShellExits[0].end():]
    pShutdown = (f"AGENTOS MANAGER SHUTD ROOT={pRoot:016x} COUNT=00000003\r\n"
                 f"AGENTOS USER KILL PID={pCorePid:016x} PARENT={pRoot:016x} STATUS=0000000000000089\r\n"
                 f"AGENTOS MANAGER ENDED ROOT={pRoot:016x} COUNT=00000003\r\n").encode()
    require(pTail.startswith(pShutdown),"Remaining core was not stopped in ordered manager shutdown")
    pExit = EXIT.fullmatch(pTail[len(pShutdown):])
    require(pExit is not None and int(pExit[1],16)==pRoot and int(pExit[2],16)>0 and
            int(pExit[2],16)%4096==0 and int(pExit[3],16)==0,"PID1 did not exit cleanly")
    require(aLog[pEnds[0].end():] in (b"[INFO] INTERACTIVE SHELL STOPPED\r\n",b""),
            "Unexpected data after kernel session completion")
    return {"root_pid":pRoot,"shell_pid":pShell,"core_pid":pCorePid,
            "restarted_pids":sorted(int(pMatch[1],16) for pMatch in pExits),"idle":pIdle}


def main():
    pParser = argparse.ArgumentParser(description=__doc__)
    pParser.add_argument("--log",type=Path)
    pParser.add_argument("--input",type=Path)
    pParser.add_argument("--keyboard",action="store_true")
    pParser.add_argument("--plan-pid",type=int)
    pArgs = pParser.parse_args()
    if pArgs.plan_pid is not None:
        require(pArgs.plan_pid>1,"Invalid shell PID for input plan")
        print(json.dumps({"steps":steps(pArgs.plan_pid,pArgs.keyboard),
                          "kernel_event_pattern":KERNEL_EVENT.pattern.decode(),
                          "worker_exit_pattern":EXIT.pattern.decode(),
                          "stop_pattern":SESSION_STOP.pattern.decode()}))
        return 0
    if pArgs.log is None:
        pParser.error("--log or --plan-pid is required")
    try:
        pResult = verify(pArgs.log.read_bytes(),pArgs.input.read_bytes() if pArgs.input else None,pArgs.keyboard)
    except (OSError,VerificationError) as pError:
        print(f"Stage-3 interactive verification failed: {pError}",file=sys.stderr)
        return 1
    print("Stage-3 service control, runtime idle, TTY and cleanup verified: "+json.dumps(pResult,sort_keys=True))
    return 0


if __name__=="__main__":sys.exit(main())
