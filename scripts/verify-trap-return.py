"""Reject a kernel ELF whose recoverable user trap returns with kernel GS.

For CPL3 exceptions isr_common SWAPGS to GS=kernel on entry. A successfully
handled user #PF (e.g. COW) takes a *direct* IRETQ, not restore_context.
That direct branch MUST conditionally SWAPGS back based on the saved CS at
RSP+8. This checker inspects actual linked x86-64 machine code, not comments
or source text. It blocks the real QEMU regression: RIP=0x02000226 (native
SYSCALL gs:[8]), CR2=0x8 after the first COW trap.
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys

class VerificationError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise VerificationError(message)

def verify_instructions(text):
    instructions=[]
    for line in text.splitlines():
        match=re.match(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*(\S+)(?:\s+(.*))?$",line)
        if match:
            instructions.append((match[1],(match[2] or "").strip()))
    require(len(instructions)>=10, "Could not disassemble actual user exception handler")
    entry=next((i for i,(op,arg) in enumerate(instructions)
                if op.startswith("test") and "0x18(%rsp)" in arg and "$0x3" in arg),None)
    require(entry is not None and any(op=="swapgs" for op,_ in instructions[entry+1:entry+5]),
            "No conditional SWAPGS on user exception entry")
    exits=[i for i,(op,_) in enumerate(instructions) if op=="iretq"]
    require(len(exits)==1, "Expected exactly one direct successful IRETQ")
    i=exits[0]
    suffix=instructions[max(0,i-5):i]
    require(any(op.startswith("test") and "$0x3" in arg and
                "0x8(%rsp)" in arg for op,arg in suffix),
            "Direct user exception IRETQ does not inspect saved user CS")
    require(any(op in ("je","jz") for op,_ in suffix),
            "Direct user exception IRETQ is missing privilege branch")
    require(len(suffix)>=2 and suffix[-1][0]=="swapgs",
            "Direct IRETQ will leak kernel GS base to user (SWAPGS missing)")
    return len(instructions)

def verify(path):
    symbols={}
    result=subprocess.run(["nm","-n",str(path)],check=True,capture_output=True,text=True)
    for line in result.stdout.splitlines():
        match=re.fullmatch(r"([0-9a-f]{16})\s+\w\s+(isr_common|timer_gate)",line)
        if match: symbols[match[2]]=int(match[1],16)
    require(len(symbols)==2 and 0<symbols["timer_gate"]-symbols["isr_common"]<1024,
            "Cannot locate exception-to-timer gate symbol boundaries")
    disasm=subprocess.run(
        ["objdump","-d",f"--start-address={symbols['isr_common']}",
         f"--stop-address={symbols['timer_gate']}",str(path)],
        check=True,capture_output=True,text=True)
    return verify_instructions(disasm.stdout)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("kernel",type=Path)
    args=p.parse_args()
    try: n=verify(args.kernel)
    except (VerificationError,subprocess.CalledProcessError,OSError) as e:
        print(f"User trap SWAPGS verification failed: {e}",file=sys.stderr)
        return 1
    print(f"User exception GS restoration verified in {n} linked instructions")
    return 0

if __name__=="__main__":
    sys.exit(main())
