"""Shared real-input stage-3 session and strict captured-transcript verifier.

QEMU and VirtualBox use the same command contract. Expected bytes are used
only for comparisons; the actual UART capture is never modified or generated.
The scenario proves immediate SPAWN acknowledgement, STOP persistence, three
real restarted worker exits, timer-backed idle, TTY editing and clean shutdown.
"""
import argparse
import importlib.util
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
FAULT = re.compile(rb"AGENTOS USER FAULT PID=("+HEX+rb") PARENT=("+HEX+
                   rb") CR3=("+HEX+rb") VECTOR=("+HEX+rb") ERROR=("+HEX+
                   rb") ADDRESS=("+HEX+rb")\r\n")
READY = b"AGENTOS SHELL READY\r\nagentos> "
# Only the separate test harness sends these ordinary shell commands.
# These ELF fixtures already exist in the historical signed initramfs.
RUNTIME_PROGRAMS = (("run /svc_ok",0),("run /svc_fail",42),("run /fault",270))
MIGRATION_COMMAND = "run /migration-runner"
MIGRATION_INPUT = (MIGRATION_COMMAND+"\r").encode("ascii")
MIGRATION_MARKER = b"AGENTOS MIGRATION"
SUPERVISOR_COMMAND = "run /supervisor-runner"
SUPERVISOR_INPUT = (SUPERVISOR_COMMAND+"\r").encode("ascii")
PIPE_COMMAND = "run /pipe-runner"
PIPE_INPUT = (PIPE_COMMAND+"\r").encode("ascii")
MEMORY_COMMANDS = ("run /cow-runner", "run /demand-runner")
MEMORY_INPUT = b"".join((command+"\r").encode("ascii") for command in MEMORY_COMMANDS)
IPC_COMMAND = "run /ipc-runner"
IPC_INPUT = (IPC_COMMAND+"\r").encode("ascii")
IPC_MARKER = b"AGENTOS IPC TEST "
FAULT_COMMAND = "run /fault-runner"
FAULT_INPUT = (FAULT_COMMAND+"\r").encode("ascii")
OOM_COMMAND = "run /oom-runner"
OOM_INPUT = (OOM_COMMAND+"\r").encode("ascii")
OOM_MARKER = b"AGENTOS TEST OOM "
PAGE_OOM = b"AGENTOS PAGE OOM"
SMP_SOAK_INPUT = b"run /smp-soak\r"
SUPERVISOR_MISSING = b"run: spawn failed (-2)\r\nagentos> "
ADOPTION_COMMAND = "run /adoption-runner"
ADOPTION_INPUT = (ADOPTION_COMMAND+"\r").encode("ascii")
ADOPTION_BYTES = b"A\rB\rC\r"
ADOPTION_MARKER = b"AGENTOS ADOPTION TEST "
REAP_MARKER = b"AGENTOS MANAGER REAP "

def runtime_input():
    return b"".join((command+"\r").encode("ascii") for command,_ in RUNTIME_PROGRAMS)

def runtime_process_prefix(data, shell, shell_cr3, prior_pids):
    """Consume exactly three real command intervals and their own kernel
    evidence. No missing/foreign/extra events are removed from the transcript.
    Normal exit, nonzero exit and fatal user #PF must return to the same shell.
    The root's actual shutdown and whole-session frame accounting remain
    mandatory in the outer verifier.
    """
    offset=0
    seen=set(prior_pids)
    records=[]
    for command,status in RUNTIME_PROGRAMS:
        echo=(command+"\r\n").encode("ascii")
        require(data.startswith(echo,offset),"Missing runtime command echo: "+command)
        offset+=len(echo)
        if status==270:
            match=FAULT.match(data,offset)
            require(match is not None,"Missing actual user fault for foreground child")
            pid,parent,cr3,vector,error,address=(int(v,16) for v in match.groups())
            require(parent==shell and (vector,error,address)==(14,5,0x02000000),
                    "Wrong fault vector, address, privilege or shell ownership")
        else:
            match=EXIT.match(data,offset)
            require(match is not None,"Missing actual foreground child exit")
            pid,cr3,actual=(int(v,16) for v in match.groups())
            require(actual==status,"Wrong actual foreground exit status")
        require(pid>shell and pid not in seen and cr3>0 and cr3%4096==0 and cr3!=shell_cr3,
                "Foreign/reused child or non-private address space")
        seen.add(pid)
        offset=match.end()
        reply=f"exit status {status}\r\nagentos> ".encode("ascii")
        require(data.startswith(reply,offset),"Shell failed to collect actual child status")
        offset+=len(reply)
        records.append({"pid":pid,"cr3":cr3,"status":status})
    return offset,records


def supervisor_prefix(data, shell, shell_cr3, prior_pids, variant, apics, *, pipe=False, memory=None, ipc=False, fault=False):
    """Consume only a verified per-CPU foreground workload (or real ENOENT)."""
    require(variant in ("control", "test"), "Invalid supervisor image variant")
    require(memory in (None,"cow","demand") and sum((bool(memory),pipe,ipc,fault))<=1,"Invalid workload kind")
    command=("run /"+memory+"-runner" if memory else PIPE_COMMAND if pipe else IPC_COMMAND if ipc else FAULT_COMMAND if fault else SUPERVISOR_COMMAND)
    echo = (command+"\r\n").encode("ascii")
    require(data.startswith(echo), "Missing supervisor command echo")
    offset = len(echo)
    if variant == "control":
        require(data.startswith(SUPERVISOR_MISSING, offset),
                "Distribution did not reject the absent test runner")
        return offset+len(SUPERVISOR_MISSING), {"absent": True}, set()

    modules=[]
    filenames=("verify-supervisor.py","verify-supervisor-locality.py")
    if pipe:
        filenames+=("verify-pipe-transfer.py",)
    elif memory:
        filenames+=("verify-memory-workload.py",)
    elif ipc:
        filenames+=("verify-ipc-workload.py",)
    elif fault:
        filenames+=("verify-fault-workload.py",)
    for filename in filenames:
        spec=importlib.util.spec_from_file_location(filename,Path(__file__).with_name(filename))
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    consumed,result,pids=modules[1].verify(data[offset:],shell,shell_cr3,prior_pids,apics,modules[0],require,
                                           pipe=modules[2] if pipe else None,
                                           memory=modules[2] if memory else None,memory_kind=memory,
                                           ipc=modules[2] if ipc else None,
                                           fault=modules[2] if fault else None)
    return offset+consumed,result,pids


def adoption_prefix(data, root, shell, shell_cr3, prior_pids, variant, apics):
    echo=(ADOPTION_COMMAND+"\r\n").encode("ascii")
    require(data.startswith(echo),"Missing ordinary adoption foreground command")
    if variant=="control":
        require(data.startswith(SUPERVISOR_MISSING,len(echo)),
                "Distribution did not reject the absent adoption client")
        return len(echo)+len(SUPERVISOR_MISSING),{"absent":True},set()
    require(variant=="test","Invalid adoption image variant")
    spec=importlib.util.spec_from_file_location("adoption_evidence",Path(__file__).with_name("verify-adoption.py"))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    consumed,result,pids=module.verify(data[len(echo):],root,shell,shell_cr3,prior_pids,apics,require)
    return len(echo)+consumed,result,pids


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
             "run PATH   Run a native program\r\n"
             "services   Show service registry\r\n"
             "service start|stop|restart core|flaky\r\n"
             "idle       Measure timer wakeups over 5 seconds\r\n"
             "exit       Close the shell\r\n")
    pCommands = [
        ("help",pHelp), ("pid",str(aPid)+"\r\n"),
        ("echo shell-ox\x08k","shell-ok\r\n"),
        ("cat /stage","AgentOS stage 1\r\n"),
        ("cat /missing","cat: open failed (-2)\r\n"),
        ("run /missing","run: spawn failed (-2)\r\n"),
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


def bootCpuRoster(aLog, aCpus, *, aBasicSmp=False):
    require(type(aCpus) is int and aCpus in ((4,8) if aBasicSmp else (1,2)), "Invalid configured CPU count")
    shell = SHELL_START.search(aLog)
    require(shell is not None, "Missing shell boundary for actual CPU roster")
    roster = re.findall(rb"(?m)^AGENTOS TASK (BSP|AP) APIC=("+HEX+
                        rb") TIMER-WAKES=0000000000000003\r?$",aLog[:shell.start()])
    ids = [int(v,16) for _,v in roster]
    require(len(roster)==len(set(ids))==aCpus and all(0<=v<255 for v in ids)
            and sum(role==b"BSP" for role,_ in roster)==1,"Missing actual boot CPU roster")
    return set(ids)


def migration_prefix(data, shell, shell_cr3, prior_pids, variant, apics):
    echo = (MIGRATION_COMMAND+"\r\n").encode("ascii")
    require(data.startswith(echo),"Missing migration foreground command echo")
    if variant=="control":
        require(data[len(echo):].startswith(SUPERVISOR_MISSING),
                "Distribution did not reject the absent migration runner")
        return len(echo)+len(SUPERVISOR_MISSING), {"absent":True}, set()
    require(variant=="test", "Unknown migration image variant")
    spec=importlib.util.spec_from_file_location("foregroundMigration",Path(__file__).with_name("verify-migration.py"))
    verifier=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    try:
        consumed,result,pids=verifier.verify_foreground(data[len(echo):],shell,shell_cr3,prior_pids,apics)
    except verifier.VerificationError as error:
        raise VerificationError(f"Invalid foreground migration evidence: {error}") from error
    return len(echo)+consumed,result,pids


def timerCpuCount(aLog, aCpus, *, aMigrationStaged=False, aBasicSmp=False):
    if aBasicSmp:
        require(aMigrationStaged,"Basic SMP requires the current ordinary boot contract")
        return len(bootCpuRoster(aLog,aCpus,aBasicSmp=True))
    require(aCpus is None or type(aCpus) is int and aCpus in (1,2),
            "Invalid configured CPU count for runtime timing")
    if aMigrationStaged:
        return len(bootCpuRoster(aLog,aCpus))
    # Historical native-v1 captures measured one CPU. A command-line override
    # must not silently enlarge their budget. Native-v2 evidence includes the
    # complete migration prelude and must match the actual VM configuration.
    if b"AGENTOS MIGRATION" not in aLog:
        return 1
    require(aCpus is not None,"Native-v2 timing requires the configured CPU count")
    pSpec = importlib.util.spec_from_file_location(
        "sessionMigrationEvidence", Path(__file__).with_name("verify-migration.py"))
    pVerifier = importlib.util.module_from_spec(pSpec)
    pSpec.loader.exec_module(pVerifier)
    try:
        pMigration = pVerifier.verify(aLog.decode("ascii",errors="replace"),aCpus)
    except pVerifier.VerificationError as pError:
        raise VerificationError(f"Invalid migration evidence for runtime timing: {pError}") from pError
    return pMigration["cpus"]


def verify_idle(aBytes, aCpus=1, aClockMaintenanceMs=1000):
    require(aClockMaintenanceMs in (1000,10), "Unknown independently established clock maintenance budget")
    pMatches = list(IDLE.finditer(aBytes))
    require(len(pMatches)==1,"Expected exactly one runtime idle measurement")
    pMs,pTimers,pIdle = (int(pValue,16) for pValue in pMatches[0].groups())
    require(5000 <= pMs <= 15000,"Runtime idle did not cover the requested five-second sleep")
    require(1 <= pIdle <= pTimers and pTimers-pIdle <= 2,
            "Runtime idle counters do not describe blocked-queue timer interrupts")
    # Native-v2 counts aggregate all configured CPUs. Each blocked queue may
    # have its own one-second clock watchdog; retain the same per-CPU rate and
    # four global boundary IRQs. The former 10ms periodic policy still fails.
    # The independently established finite PIT fallback requires 10 ms
    # BSP maintenance; other CPUs retain the original sparse budget.
    # Ordinary callers, including VirtualBox, keep exactly the old bound.
    pBudget = ((pMs+aClockMaintenanceMs-1)//aClockMaintenanceMs) + ((pMs+999)//1000)*(aCpus-1)+4
    require(pTimers <= pBudget,
            "Runtime idle still has excessive periodic scheduler interrupts")
    return {"milliseconds":pMs,"timer_irqs":pTimers,"idle_timer_irqs":pIdle,
            "timer_cpu_count":aCpus}


def verify(aLog, aInput=None, aKeyboard=False, aCpus=None, *, aClockMaintenanceMs=1000,
           aRuntimeProcess=False, aSupervisorImage=None, aHistoricalBootMemory=False, aMigrationStaged=False,
           aFaultStaged=False, aOomLayout=None, aBasicSmp=False,aSmpSoak=False):
    require(not aSmpSoak or aBasicSmp,"SMP soak requires explicit 4/8 CPU session")
    if aBasicSmp:
        require(aCpus in (4,8) and aInput is not None and aKeyboard and aMigrationStaged and aFaultStaged and
                not aRuntimeProcess and aSupervisorImage is None and not aHistoricalBootMemory and aOomLayout is None,
                "Basic SMP requires the explicit ordinary full session without staged or historical workloads")
        require(aLog.endswith(b"[INFO] INTERACTIVE SHELL STOPPED\r\n"),
                "Basic SMP requires final structured shutdown completion")
    require(aOomLayout is None or (aFaultStaged and aSupervisorImage in ("control","test")),
            "OOM requires the explicit paired staged contract")
    if aOomLayout is None:
        require(OOM_MARKER not in aLog and PAGE_OOM not in aLog,"Unexpected runtime OOM evidence")
    require(not aFaultStaged or (aMigrationStaged and not aHistoricalBootMemory),
            "Mixed historical and staged syscall/fault contracts")
    require(aSupervisorImage is None or (aRuntimeProcess and aSupervisorImage in ("control","test")),
            "Supervisor image scenario requires the existing foreground regression")
    require(re.search(rb"AGENTOS PIPE (?!TEST )",aLog) is None,
            "Historical boot pipe transfer is not permitted in either signed image")
    pWorkloadMarkers=(b"AGENTOS SUPERVISOR",b"AGENTOS SERVICE ",b"AGENTOS TEST ",b"AGENTOS PIPE TEST ",ADOPTION_MARKER,IPC_MARKER)
    if aOomLayout is not None:
        pWorkloadMarkers+=(PAGE_OOM,)
    if aMigrationStaged:
        require(not aHistoricalBootMemory,"Mixed historical and foreground migration contracts")
        pWorkloadMarkers+=(MIGRATION_MARKER,)
    if aHistoricalBootMemory:
        # Explicit historical receipt inspection only, after its independent
        # old boot-memory validators have run. Never selected by QEMU or the
        # current staged session verifier.
        require(not aRuntimeProcess and aSupervisorImage is None,"Mixed historical and staged evidence")
        historical_shell=SHELL_START.search(aLog)
        require(historical_shell is not None and not any(
            marker in aLog[historical_shell.start():] for marker in (b"AGENTOS COW ",b"AGENTOS DEMAND ")),
            "Historical memory evidence outside the boot interval")
    else:
        pWorkloadMarkers+=(b"AGENTOS COW ",b"AGENTOS DEMAND ")
        require(re.search(rb"AGENTOS IPC (?!TEST )",aLog) is None,
                "Historical boot IPC evidence is forbidden in current signed images")
    require(aLog.count(b"AGENTOS TEST RUNNER ")==(5+int(aFaultStaged))*int(aSupervisorImage=="test"),
            "Unexpected runner invocation outside its foreground interval")
    if aSupervisorImage!="test":
        require(not any(marker in aLog for marker in pWorkloadMarkers
                        if not (aSmpSoak and marker==b"AGENTOS TEST ")),
                "Acceptance workload ran in the ordinary distribution")
    pTimerCpus = timerCpuCount(aLog,aCpus,aMigrationStaged=aMigrationStaged,aBasicSmp=aBasicSmp)
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
    require(pInteractive.startswith(READY),"Missing real initial shell prompt")
    pInteractive=pInteractive[len(READY):]
    pRuntimeRecords=[]
    pSupervisor=None
    pPipe=None
    pMemory={}
    pAdoption=None
    pIpc=None
    pFault=None
    pOom=None
    pMigration=None
    pSoak=None
    pPrefixPids=set()
    if aSmpSoak:
        pPrior={int(m[1],16) for m in re.finditer(
            rb"AGENTOS USER (?:EXIT|FAULT|PARK|KILL) PID=("+HEX+rb")",
            aLog[:pChildren[0].end()])}
        pPrior.update((pRoot,pShell,pCorePid))
        spec=importlib.util.spec_from_file_location("smp_soak",Path(__file__).with_name("verify-smp-soak.py"))
        verifier=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        try:
            pConsumed,pSoak,pNewPids=verifier.verify_prefix(
                pInteractive,pShell,int(pShellExits[0][2],16),pPrior,
                bootCpuRoster(aLog,aCpus,aBasicSmp=True))
        except verifier.VerificationError as e:
            raise VerificationError(f"Invalid sustained SMP evidence: {e}") from e
        pSoakLog=pInteractive[:pConsumed]
        require(all(aLog.count(marker)==pSoakLog.count(marker) for marker in pWorkloadMarkers),
                "Acceptance evidence outside authenticated SMP interval")
        pStart=pChildren[0].end()+len(READY)
        require(aLog[pStart:pStart+pConsumed]==pSoakLog,"SMP interval boundary differs from actual log")
        pSoak["interval_bytes"]=[pStart,pStart+pConsumed]
        pPrefixPids.update(pNewPids)
        pInteractive=pInteractive[pConsumed:]
    if aRuntimeProcess:
        # Account for every earlier actual PID, not just the current shell.
        pPrior={int(m[1],16) for m in re.finditer(
            rb"AGENTOS USER (?:EXIT|FAULT|PARK|KILL) PID=("+HEX+rb")",
            aLog[:pChildren[0].end()])}
        pPrior.update((pRoot,pShell,pCorePid))
        pConsumed,pRuntimeRecords=runtime_process_prefix(
            pInteractive,pShell,int(pShellExits[0][2],16),pPrior)
        pInteractive=pInteractive[pConsumed:]
        pPrefixPids={r["pid"] for r in pRuntimeRecords}
        if aSupervisorImage is not None:
            pApicList=[int(m[1],16) for m in re.finditer(
                rb"(?m)^AGENTOS TASK (?:BSP|AP) APIC=("+HEX+rb") TIMER-WAKES=0000000000000003\r?$",
                aLog[:pChildren[0].start()])]
            require(len(pApicList)==len(set(pApicList))==aCpus,"Missing actual boot CPU roster")
            pMigrationLog=b""
            if aMigrationStaged:
                pConsumed,pMigration,pNewPids=migration_prefix(
                    pInteractive,pShell,int(pShellExits[0][2],16),
                    pPrior | pPrefixPids,aSupervisorImage,bootCpuRoster(aLog,aCpus))
                pMigrationLog=pInteractive[:pConsumed]
                pPrefixPids.update(pNewPids)
                pInteractive=pInteractive[pConsumed:]
            pConsumed,pSupervisor,pNewPids=supervisor_prefix(
                pInteractive,pShell,int(pShellExits[0][2],16),
                pPrior | pPrefixPids,aSupervisorImage,set(pApicList))
            pSupervisorLog=pInteractive[:pConsumed]
            pPrefixPids.update(pNewPids)
            pInteractive=pInteractive[pConsumed:]
            pConsumed,pPipe,pNewPids=supervisor_prefix(
                pInteractive,pShell,int(pShellExits[0][2],16),
                pPrior | pPrefixPids,aSupervisorImage,set(pApicList),pipe=True)
            pWorkloadLog=pMigrationLog+pSupervisorLog+pInteractive[:pConsumed]
            pPrefixPids.update(pNewPids)
            pInteractive=pInteractive[pConsumed:]
            for kind in ("cow","demand"):
                pConsumed,pMemory[kind],pNewPids=supervisor_prefix(
                    pInteractive,pShell,int(pShellExits[0][2],16),
                    pPrior | pPrefixPids,aSupervisorImage,set(pApicList),memory=kind)
                pWorkloadLog+=pInteractive[:pConsumed]
                pPrefixPids.update(pNewPids)
                pInteractive=pInteractive[pConsumed:]
            pConsumed,pIpc,pNewPids=supervisor_prefix(
                pInteractive,pShell,int(pShellExits[0][2],16),
                pPrior | pPrefixPids,aSupervisorImage,set(pApicList),ipc=True)
            pWorkloadLog+=pInteractive[:pConsumed]
            pPrefixPids.update(pNewPids)
            pInteractive=pInteractive[pConsumed:]
            if aFaultStaged:
                pConsumed,pFault,pNewPids=supervisor_prefix(
                    pInteractive,pShell,int(pShellExits[0][2],16),
                    pPrior | pPrefixPids,aSupervisorImage,bootCpuRoster(aLog,aCpus),fault=True)
                pWorkloadLog+=pInteractive[:pConsumed]
                pPrefixPids.update(pNewPids)
                pInteractive=pInteractive[pConsumed:]
            if aOomLayout is not None:
                spec=importlib.util.spec_from_file_location("oom_evidence",Path(__file__).with_name("verify-oom-workload.py"))
                verifier=importlib.util.module_from_spec(spec)
                spec.loader.exec_module(verifier)
                try:
                    pConsumed,pOom,pNewPids=verifier.verify_prefix(
                        pInteractive,pShell,int(pShellExits[0][2],16),pPrior | pPrefixPids,
                        aSupervisorImage,bootCpuRoster(aLog,aCpus),aOomLayout)
                except verifier.VerificationError as e:
                    raise VerificationError(f"Invalid bounded demand OOM evidence: {e}") from e
                pWorkloadLog+=pInteractive[:pConsumed]
                pPrefixPids.update(pNewPids)
                pInteractive=pInteractive[pConsumed:]
            pConsumed,pAdoption,pNewPids=adoption_prefix(
                pInteractive,pRoot,pShell,int(pShellExits[0][2],16),
                pPrior | pPrefixPids,aSupervisorImage,set(pApicList))
            pWorkloadLog+=pInteractive[:pConsumed]
            pPrefixPids.update(pNewPids)
            pInteractive=pInteractive[pConsumed:]
            require(all(aLog.count(marker)==pWorkloadLog.count(marker) for marker in pWorkloadMarkers),
                    "Test evidence outside its authenticated foreground interval")
    require(aLog.count(REAP_MARKER)==(4 if aSupervisorImage=="test" else 0),
            "Missing, duplicated or out-of-scenario unmanaged collection")
    pClean = without_kernel_events(pInteractive)
    pExpected = b"".join(
        pStep["pattern"].encode("ascii") for pStep in steps(pShell,aKeyboard))
    require(re.fullmatch(pExpected,pClean) is not None,
            "Incorrect extended command echo/response/state sequence")
    pIdle = verify_idle(pClean,pTimerCpus,aClockMaintenanceMs)
    if aRuntimeProcess:
        require(aInput is not None,"Separate process regression requires actual transmitted bytes")
    if aInput is not None:
        pPrefix=(SMP_SOAK_INPUT if aSmpSoak else runtime_input() if aRuntimeProcess else b"")
        if aSupervisorImage is not None:
            if aMigrationStaged:
                pPrefix+=MIGRATION_INPUT
            pPrefix+=SUPERVISOR_INPUT+PIPE_INPUT+MEMORY_INPUT+IPC_INPUT
            if aFaultStaged:
                pPrefix+=FAULT_INPUT
            if aOomLayout is not None:
                pPrefix+=OOM_INPUT
            pPrefix+=ADOPTION_INPUT
            if aSupervisorImage=="test":
                pPrefix+=ADOPTION_BYTES
        require(aInput==pPrefix+transmitted_input(pShell,aKeyboard),"Captured transmitted UART bytes differ from scenario")
    pRestart = pInteractive.find(b"service restart flaky\r\n")
    require(pRestart>=0,"No explicit service RESTART command")
    pAfterRestart = pInteractive[pRestart:]
    pExits = list(EXIT.finditer(pAfterRestart))
    require(len(pExits)==3,"Restart did not produce exactly three real worker exits")
    pSeen = set(pPrefixPids)
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
    require(pKilled or len(pSeen)-len(pPrefixPids)>3,
            "Initial START/STOP has no actual worker termination evidence")
    pTail = pPhase[pShellExits[0].end():]
    pShutdown = (f"AGENTOS MANAGER SHUTD ROOT={pRoot:016x} COUNT=00000003\r\n"
                 f"AGENTOS USER KILL PID={pCorePid:016x} PARENT={pRoot:016x} STATUS=0000000000000089\r\n")
    if aSupervisorImage=="test":
        child=pAdoption["shutdown_pid"]
        pShutdown+=(f"AGENTOS USER KILL PID={child:016x} PARENT={pRoot:016x} STATUS=0000000000000089\r\n"
                    f"AGENTOS MANAGER REAP ROOT={pRoot:016x} PID={child:016x} STATUS=0000000000000089\r\n")
        pAdoption["shutdown_collection"]={"pid":child,"status":137}
    pShutdown=(pShutdown+f"AGENTOS MANAGER ENDED ROOT={pRoot:016x} COUNT=00000003\r\n").encode()
    require(pTail.startswith(pShutdown),"Remaining core was not stopped in ordered manager shutdown")
    pExit = EXIT.fullmatch(pTail[len(pShutdown):])
    require(pExit is not None and int(pExit[1],16)==pRoot and int(pExit[2],16)>0 and
            int(pExit[2],16)%4096==0 and int(pExit[3],16)==0,"PID1 did not exit cleanly")
    if aSmpSoak:
        require(int(pExit[2],16) not in ({pSoak["root_cr3"]}|set(pSoak["worker_cr3"].values())),
                "SMP worker or foreground address space aliased the live PID1")
    if aSupervisorImage=="test":
        if aOomLayout is not None:
            require(int(pExit[2],16) not in {pOom[k] for k in ("root_cr3","pressure_cr3","survivor_cr3")},
                    "OOM client aliased the live PID1")
        if aFaultStaged:
            roots={pFault["runner_cr3"]}
            for interval in pFault["intervals"]+pFault["rejected"]:
                roots.update(interval[k] for k in ("parent_cr3","child_cr3") if k in interval)
                if "peer" in interval:
                    roots.add(interval["peer"]["cr3"])
            require(int(pExit[2],16) not in roots,
                    "Foreground syscall/fault address space aliased the live PID1")
        if aMigrationStaged:
            require(int(pExit[2],16) not in ({pMigration["cr3"]} | {x["cr3"] for x in pMigration["worker_exits"]}),
                    "Foreground migration aliased the live PID1 address space")
        require(int(pExit[2],16) not in {x["cr3"] for x in pAdoption["natural_exits"]},
                "Adoption descendant aliased the living PID1 address space")
    require(aLog[pEnds[0].end():] in (b"[INFO] INTERACTIVE SHELL STOPPED\r\n",b""),
            "Unexpected data after kernel session completion")
    result={"root_pid":pRoot,"shell_pid":pShell,"core_pid":pCorePid,
            "restarted_pids":sorted(int(pMatch[1],16) for pMatch in pExits),"idle":pIdle}
    if aSmpSoak:
        result["runtime_smp_soak"]=pSoak
    if aRuntimeProcess:
        result["runtime_process_regression"]=pRuntimeRecords
    if aSupervisorImage is not None:
        result["runtime_supervisor"]=pSupervisor
        result["runtime_pipe"]=pPipe
        result["runtime_cow"]=pMemory["cow"]
        result["runtime_demand"]=pMemory["demand"]
        result["runtime_adoption"]=pAdoption
        result["runtime_ipc"]=pIpc
        if aOomLayout is not None:
            result["runtime_oom"]=pOom
        if aFaultStaged:
            result["runtime_fault"]=pFault
        if aMigrationStaged:
            result["runtime_migration"]=pMigration
    return result


def main():
    pParser = argparse.ArgumentParser(description=__doc__)
    pParser.add_argument("--log",type=Path)
    pParser.add_argument("--input",type=Path)
    pParser.add_argument("--keyboard",action="store_true")
    pParser.add_argument("--cpus",type=int,choices=(1,2))
    pParser.add_argument("--plan-pid",type=int)
    pParser.add_argument("--runtime-process-regression",action="store_true")
    pParser.add_argument("--supervisor-image",choices=("control","test"))
    pParser.add_argument("--migration-staged",action="store_true",help="Use the explicit foreground migration contract")
    pParser.add_argument("--fault-staged",action="store_true",help="Require the separate syscall/fault locality workload")
    pArgs = pParser.parse_args()
    if pArgs.plan_pid is not None:
        require(not pArgs.runtime_process_regression and pArgs.supervisor_image is None,"Separate process regression uses the QEMU test driver")
        require(pArgs.plan_pid>1,"Invalid shell PID for input plan")
        print(json.dumps({"steps":steps(pArgs.plan_pid,pArgs.keyboard),
                          "kernel_event_pattern":KERNEL_EVENT.pattern.decode(),
                          "worker_exit_pattern":EXIT.pattern.decode(),
                          "stop_pattern":SESSION_STOP.pattern.decode()}))
        return 0
    if pArgs.log is None:
        pParser.error("--log or --plan-pid is required")
    try:
        pResult = verify(pArgs.log.read_bytes(),pArgs.input.read_bytes() if pArgs.input else None,
                         pArgs.keyboard,pArgs.cpus,aRuntimeProcess=pArgs.runtime_process_regression,
                         aSupervisorImage=pArgs.supervisor_image,aMigrationStaged=pArgs.migration_staged,
                         aFaultStaged=pArgs.fault_staged)
    except (OSError,VerificationError) as pError:
        print(f"Stage-3 interactive verification failed: {pError}",file=sys.stderr)
        return 1
    print("Stage-3 service control, runtime idle, TTY and cleanup verified: "+json.dumps(pResult,sort_keys=True))
    return 0


if __name__=="__main__":sys.exit(main())
