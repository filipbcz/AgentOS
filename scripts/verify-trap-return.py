"""Reject unsafe user trap returns and premature outgoing-stack retirement.

For CPL3 exceptions isr_common SWAPGS to GS=kernel on entry. A successfully
handled user #PF (e.g. COW) takes a *direct* IRETQ, not restore_context.
That direct branch MUST conditionally SWAPGS back based on the saved CS at
RSP+8. This checker inspects actual linked x86-64 machine code, not comments
or source text. It blocks the real QEMU regression: RIP=0x02000226 (native
SYSCALL gs:[8]), CR2=0x8 after the first COW trap.

The scheduled return path must move RSP to its incoming Context before calling
finish_context_switch. That callback releases the outgoing-stack hazard; calling
it earlier lets a remote CPU migrate or reap a stack still being used here.
FX/GPR restoration must follow the callback, ending in a privilege-aware IRETQ.
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

def parseInstructions(aText):
    pInstructions=[]
    for pLine in aText.splitlines():
        pMatch=re.match(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*(\S+)(?:\s+(.*))?$",pLine)
        if pMatch:
            pInstructions.append((int(pMatch[1],16),pMatch[2],(pMatch[3] or "").split("#",1)[0].strip()))
    return pInstructions

def verify_instructions(text):
    instructions=[(pOp,pArguments) for _,pOp,pArguments in parseInstructions(text)]
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

def targetAddress(aArguments):
    pMatch=re.fullmatch(r"(?:0x)?([0-9a-f]+)(?:\s+<[^>]+>)?",aArguments)
    return int(pMatch[1],16) if pMatch else None

def verifyRestoreInstructions(aText, aCallbackAddress):
    pInstructions=parseInstructions(aText)
    pRegisters=("r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8",
                "rdi","rsi","rdx","rcx","rax")
    require(len(pInstructions)==4+len(pRegisters)+4,
            "Context restoration has missing or unexpected linked instructions")
    pOperands=lambda aIndex: re.sub(r"\s+","",pInstructions[aIndex][2])
    require(pInstructions[0][1] in ("mov","movq") and pOperands(0)=="%rax,%rsp",
            "Context restoration must first move RSP to the incoming context")
    require(pInstructions[1][1] in ("call","callq") and
            targetAddress(pInstructions[1][2])==aCallbackAddress,
            "Incoming stack must acknowledge finish_context_switch before restoring registers")
    require(pInstructions[2][1]=="fxrstor64" and pOperands(2)=="(%rsp)",
            "Context SIMD state must be restored after the stack-switch callback")
    require(pInstructions[3][1] in ("add","addq") and pOperands(3)=="$0x200,%rsp",
            "Context restoration must advance over exactly 512 saved FX bytes")
    for pIndex,pRegister in enumerate(pRegisters,4):
        require(pInstructions[pIndex][1] in ("pop","popq") and pOperands(pIndex)=="%"+pRegister,
                "Context restoration has an incorrect saved GPR order")
    pTail=4+len(pRegisters)
    require(pInstructions[pTail][1].startswith("test") and
            pOperands(pTail)=="$0x3,0x8(%rsp)",
            "Scheduled IRETQ must inspect the incoming saved CS")
    require(pInstructions[pTail+1][1] in ("je","jz") and
            targetAddress(pInstructions[pTail+1][2])==pInstructions[pTail+3][0],
            "Scheduled privilege branch must skip only SWAPGS and land on IRETQ")
    require(pInstructions[pTail+2][1]=="swapgs" and pInstructions[pTail+3][1]=="iretq",
            "Scheduled context must finish with conditional SWAPGS and IRETQ")
    return len(pInstructions)

def verify(path):
    symbols={}
    result=subprocess.run(["nm","-n",str(path)],check=True,capture_output=True,text=True)
    for line in result.stdout.splitlines():
        match=re.fullmatch(r"([0-9a-f]{16})\s+[tT]\s+(isr_common|timer_gate|restore_context|native_syscall|finish_context_switch)",line)
        if match: symbols[match[2]]=int(match[1],16)
    require(len(symbols)==5 and 0<symbols["timer_gate"]-symbols["isr_common"]<1024,
            "Cannot locate exception-to-timer gate symbol boundaries")
    require(0<symbols["native_syscall"]-symbols["restore_context"]<512,
            "Cannot locate scheduled context restoration boundaries")
    disasm=subprocess.run(
        ["objdump","-d","-M","att","--insn-width=16",f"--start-address={symbols['isr_common']}",
         f"--stop-address={symbols['timer_gate']}",str(path)],
        check=True,capture_output=True,text=True)
    pDirectCount=verify_instructions(disasm.stdout)
    pRestore=subprocess.run(
        ["objdump","-d","-M","att","--insn-width=16",f"--start-address={symbols['restore_context']}",
         f"--stop-address={symbols['native_syscall']}",str(path)],
        check=True,capture_output=True,text=True)
    pRestoreCount=verifyRestoreInstructions(pRestore.stdout,symbols["finish_context_switch"])
    return {"user_exception_instructions":pDirectCount,"context_restore_instructions":pRestoreCount}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("kernel",type=Path)
    args=p.parse_args()
    try: pResult=verify(args.kernel)
    except (VerificationError,subprocess.CalledProcessError,OSError) as e:
        print(f"Linked trap return verification failed: {e}",file=sys.stderr)
        return 1
    print(f"User exception GS restoration verified in {pResult['user_exception_instructions']} linked instructions")
    print(f"Context stack retirement and restoration verified in {pResult['context_restore_instructions']} linked instructions")
    return 0

if __name__=="__main__":
    sys.exit(main())
