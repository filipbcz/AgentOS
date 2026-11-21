"""Mutate assembled/linked production traps and verify stack/GS return gates.

The real traps.S is assembled and linked with inert callback symbols. No trap
or privileged instruction executes on the host; the checker reads the resulting
ELF machine code, exactly as it reads the fully linked kernel in check-build.sh.
"""
import importlib.util
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


pSpec=importlib.util.spec_from_file_location(
    "trap_return",Path(__file__).with_name("verify-trap-return.py"))
gVerifier=importlib.util.module_from_spec(pSpec)
pSpec.loader.exec_module(gVerifier)


class LinkedTrapReturnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fTemp=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fTemp.cleanup)
        cls.fDirectory=Path(cls.fTemp.name)
        cls.fCompiler=shlex.split(os.environ.get("CC","gcc"))
        cls.fSource=(Path(__file__).resolve().parent.parent/"kernel/traps.S").read_text()
        cls.fSequence=0
        pObject=cls.assemble(cls.fSource,"original")
        pSymbols=subprocess.run(["nm","-u",str(pObject)],check=True,capture_output=True,text=True)
        pUndefined=[]
        for pLine in pSymbols.stdout.splitlines():
            pName=pLine.split()[-1]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*",pName):
                raise AssertionError("unexpected unresolved trap symbol")
            pUndefined.append(pName)
        if "finish_context_switch" not in pUndefined:
            raise AssertionError("production traps do not reference finish_context_switch")
        pStubs=".text\n"+"".join(f".global {pName}\n{pName}:\n ret\n" for pName in pUndefined)
        cls.fCallbacks=cls.assemble(pStubs,"callbacks")
        cls.fOriginal=cls.link(pObject,"original")

    @classmethod
    def assemble(cls,aSource,aName):
        pSource=cls.fDirectory/(aName+".S")
        pObject=cls.fDirectory/(aName+".o")
        pSource.write_text(".intel_syntax noprefix\n"+aSource)
        subprocess.run(cls.fCompiler+["-c",str(pSource),"-o",str(pObject)],
                       check=True,capture_output=True,text=True)
        return pObject

    @classmethod
    def link(cls,aObject,aName):
        pElf=cls.fDirectory/(aName+".elf")
        subprocess.run([os.environ.get("LD","ld"),"--no-undefined","--build-id=none",
                        "-z","noexecstack","-Ttext=0x2000000","-e","native_syscall",
                        "-o",str(pElf),str(aObject),str(cls.fCallbacks)],
                       check=True,capture_output=True,text=True)
        return pElf

    def rejectedRestore(self,aOld,aNew):
        pStart=self.fSource.index("restore_context:\n")
        pEnd=self.fSource.index(".global native_syscall",pStart)
        pBody=self.fSource[pStart:pEnd]
        self.assertEqual(pBody.count(aOld),1,"mutation no longer matches production restore path")
        pSource=self.fSource[:pStart]+pBody.replace(aOld,aNew,1)+self.fSource[pEnd:]
        self.rejectedSource(pSource)

    def rejectedSource(self,aSource):
        type(self).fSequence+=1
        pName=f"mutated-{self.fSequence}"
        pElf=self.link(self.assemble(aSource,pName),pName)
        with self.assertRaises(gVerifier.VerificationError):
            gVerifier.verify(pElf)

    def test_actual_linked_traps_acknowledge_switch_on_incoming_stack(self):
        pResult=gVerifier.verify(self.fOriginal)
        self.assertGreaterEqual(pResult["user_exception_instructions"],10)
        self.assertEqual(pResult["context_restore_instructions"],23)

    def test_missing_callback_is_rejected_even_when_symbol_still_exists(self):
        self.rejectedRestore("    call finish_context_switch\n","")

    def test_callback_before_stack_transfer_is_rejected(self):
        self.rejectedRestore("    mov rsp, rax\n","    call finish_context_switch\n    mov rsp, rax\n")
        pStart=self.fSource.index("restore_context:\n")
        pEnd=self.fSource.index(".global native_syscall",pStart)
        pBody=self.fSource[pStart:pEnd]
        pBody=pBody.replace("    mov rsp, rax\n","",1)
        pBody=pBody.replace("    call finish_context_switch\n",
                            "    call finish_context_switch\n    mov rsp, rax\n",1)
        self.rejectedSource(self.fSource[:pStart]+pBody+self.fSource[pEnd:])

    def test_wrong_callback_or_wrong_incoming_stack_is_rejected(self):
        self.rejectedRestore("call finish_context_switch","call finish_task")
        self.rejectedRestore("mov rsp, rax","mov rsp, rbx")

    def test_restoring_simd_before_callback_is_rejected(self):
        self.rejectedRestore("    call finish_context_switch\n    fxrstor64 [rsp]",
                             "    fxrstor64 [rsp]\n    call finish_context_switch")

    def test_branch_that_skips_callback_is_rejected(self):
        self.rejectedRestore("    call finish_context_switch\n",
                             "    jmp 7f\n    call finish_context_switch\n7:\n")

    def test_wrong_saved_register_layout_is_rejected(self):
        self.rejectedRestore("add rsp, 512","add rsp, 504")
        self.rejectedRestore(".irp reg,r15,r14,r13", ".irp reg,r14,r15,r13")

    def test_wrong_return_or_privilege_branch_is_rejected(self):
        self.rejectedRestore("    iretq\n","    ret\n")
        self.rejectedRestore("    swapgs\n", "    nop\n")
        self.rejectedRestore("    jz 1f\n", "    jz native_syscall\n")
        self.rejectedRestore("test byte ptr [rsp+8], 3", "test byte ptr [rsp+24], 3")

    def test_direct_recoverable_page_fault_still_requires_swapgs(self):
        pStart=self.fSource.index("isr_common:\n")
        pEnd=self.fSource.index(".global timer_gate",pStart)
        pBody=self.fSource[pStart:pEnd]
        pOld="    test byte ptr [rsp+8], 3\n    jz 9f\n    swapgs\n"
        self.assertIn(pOld,pBody)
        pBody=pBody.replace(pOld,"    test byte ptr [rsp+8], 3\n    jz 9f\n    nop\n",1)
        self.rejectedSource(self.fSource[:pStart]+pBody+self.fSource[pEnd:])


if __name__=="__main__":
    unittest.main()
