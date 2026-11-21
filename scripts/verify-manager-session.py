"""Verify interactive QEMU UART COM1 manager control and frame-clean shutdown.

Not a VirtualBox assertion. This verifier requires the real shell child to
query the persistent registry through authenticated IPC, return exact stable
states (core running, optional flaky failed, shell running), exit normally,
and have its owning service manager kill/reap the remaining worker. The
kernel must independently report final bitmap restoration after all tasks.
"""
import argparse
from pathlib import Path
import re
import sys

class VerificationError(ValueError): pass

HEX=rb"[0-9a-f]{16}"
ROOT_START=re.compile(rb"(?m)^AGENTOS MANAGER SESSION START PID=("+HEX+rb")\r\n")
SHELL_START=re.compile(rb"(?m)^AGENTOS SHELL START PID=("+HEX+rb")\r\n")
STOP=re.compile(rb"(?m)^AGENTOS MANAGER SESSION STOP PID=("+HEX+
                rb") STATUS=0000000000000000 FRAMES=OK\r\n")
EXIT=re.compile(rb"AGENTOS USER EXIT PID=("+HEX+rb") CR3=("+HEX+
                rb") STATUS=0000000000000000\r\n")
KILL=re.compile(rb"AGENTOS USER KILL PID=("+HEX+rb") PARENT=("+HEX+
                rb") STATUS=0000000000000089\r\n")

def require(condition,message):
    if not condition: raise VerificationError(message)

def verify(log):
    roots=list(ROOT_START.finditer(log))
    children=list(SHELL_START.finditer(log))
    ends=list(STOP.finditer(log))
    require(len(roots)==len(children)==len(ends)==1,
            "Expected exactly one live manager/child shell and clean kernel shutdown")
    root=int(roots[0][1],16)
    shell=int(children[0][1],16)
    require(root>0 and shell>root and int(ends[0][1],16)==root,
            "Manager, child shell and stop receipt identity mismatch")
    require(roots[0].start()<children[0].start()<ends[0].start(),
            "Invalid operational process lifetime order")
    phase=log[children[0].end():ends[0].start()]
    expected=(b"AGENTOS SHELL READY\r\nagentos> services\r\n"
              b"core: running (attempts=1)\r\n"
              b"flaky: failed (attempts=3)\r\n"
              b"shell: running (attempts=1)\r\n"
              b"agentos> exit\r\nAGENTOS SHELL EXIT\r\n")
    require(phase.startswith(expected),
            "Real shell did not correctly return authenticated running/failed service registry")
    phase=phase[len(expected):]
    match=EXIT.match(phase)
    require(match is not None and int(match[1],16)==shell and
            int(match[2],16)>0 and int(match[2],16)%4096==0,
            "Managed shell was not reaped successfully")
    phase=phase[match.end():]
    marker=f"AGENTOS MANAGER SHUTD ROOT={root:016x} COUNT=00000003\r\n".encode()
    require(phase.startswith(marker),"No manager shutdown before stopping services")
    phase=phase[len(marker):]
    match=KILL.match(phase)
    require(match is not None and int(match[1],16) not in (root,shell) and
            int(match[2],16)==root,
            "Stable worker was not killed and reaped by its owning manager")
    worker=int(match[1],16)
    phase=phase[match.end():]
    marker=f"AGENTOS MANAGER ENDED ROOT={root:016x} COUNT=00000003\r\n".encode()
    require(phase.startswith(marker),"Manager failed to terminate after reverse service cleanup")
    phase=phase[len(marker):]
    match=EXIT.fullmatch(phase)
    require(match is not None and int(match[1],16)==root and
            int(match[2],16)>0 and int(match[2],16)%4096==0,
            "Manager did not exit cleanly from its own CR3")
    require(not log[ends[0].end():].strip(b"\r\n"),
            "Unexpected guest records after final snapshot/bitmap verification")
    return root,shell,worker

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log",required=True,type=Path)
    args=parser.parse_args()
    try:root,shell,worker=verify(args.log.read_bytes())
    except (VerificationError,OSError) as err:
        print(f"QEMU service session failed: {err}",file=sys.stderr)
        return 1
    print(f"Authenticated manager {root} and shell {shell}; stopped worker {worker}, frames restored")
    return 0

if __name__=="__main__":sys.exit(main())
