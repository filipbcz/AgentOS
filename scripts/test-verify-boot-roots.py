"""Synthetic rejection fixtures; no fixture is evidence of a guest run."""
import importlib.util
import re
import unittest
from pathlib import Path


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


processes=load("verify-processes.py")
orphans=load("verify-orphans.py")


def family(cpu,root,cr3,parent_cr3,bsp):
    parent,child=root+1,root+2
    return (
        f"AGENTOS ORPHAN BEGIN ROOT={root:016x}\n"
        f"AGENTOS USER EXIT PID={parent:016x} CR3={parent_cr3:016x} STATUS=0000000000000000\n"
        f"AGENTOS ORPHAN ADOPT ROOT={root:016x} PARENT={parent:016x} CHILD={child:016x} STATUS=0000000000000000\n"
        f"AGENTOS USER KILL PID={child:016x} PARENT={root:016x} STATUS=0000000000000089\n"
        f"AGENTOS ORPHAN REAPS ROOT={root:016x} PARENT={parent:016x} CHILD={child:016x} STATUS=0000000000000089\n"
        f"AGENTOS ORPHAN ENDED ROOT={root:016x}\n"
        f"AGENTOS USER {'PARK' if bsp else 'EXIT'} PID={root:016x} CR3={cr3:016x} STATUS=0000000000000000\n"
        f"AGENTOS PROCESS OK APIC={cpu:016x} PARENT={root:016x}\n"
    )


def transcript(cpus=(7,19),shutdown=True):
    text="".join(f"AGENTOS TASK {'BSP' if i==0 else 'AP'} APIC={cpu:016x} TIMER-WAKES=0000000000000003\n"
                 for i,cpu in enumerate(cpus))
    text+=family(cpus[0],1,0x300000,0x400000,True)
    if len(cpus)==2:
        # AP may reuse a *retired* child's root, not the parked BSP root.
        text+=family(cpus[1],4,0x400000,0x500000,False)
    text+=("AGENTOS MANAGER SESSION START PID=0000000000000001\n"
           "AGENTOS MANAGER BEGIN ROOT=0000000000000001 COUNT=00000003\n"
           "AGENTOS SHELL START PID=0000000000000010\n"
           "AGENTOS SHELL READY\n")
    if shutdown:
        text+=("AGENTOS USER FAULT PID=0000000000000011 PARENT=0000000000000010 "
               "CR3=0000000000600000 VECTOR=000000000000000e ERROR=0000000000000005 ADDRESS=0000000002000000\n"
               "AGENTOS USER EXIT PID=0000000000000010 CR3=0000000000500000 STATUS=0000000000000000\n"
               "AGENTOS USER EXIT PID=0000000000000001 CR3=0000000000300000 STATUS=0000000000000000\n"
               "AGENTOS MANAGER SESSION STOP PID=0000000000000001 STATUS=0000000000000000 FRAMES=OK\n")
    return text


class BootRootTests(unittest.TestCase):
    def verify(self,text,cpus=(7,19),shutdown=True):
        return processes.verify(text,cpus,ipc_staged=True,root_orphan_v1=True,require_shutdown=shutdown)

    def reject(self,text,cpus=(7,19),shutdown=True):
        with self.assertRaises(processes.VerificationError):
            self.verify(text,cpus,shutdown)

    def test_exact_roster_and_real_root_identity(self):
        for cpus in ((7,),(7,19)):
            for complete in (False,True):
                text=transcript(cpus,complete)
                proof=self.verify(text,cpus,complete)
                self.assertEqual(proof["bsp_apic"],7)
                self.assertEqual(proof["bsp_cr3"],0x300000)
                self.assertEqual(proof["manager_pid"],1)
                self.assertEqual(proof["shutdown_verified"],complete)
                self.assertEqual([r["apic"] for r in proof["families"]],list(cpus))
                self.assertEqual([r["terminal"] for r in proof["families"]],
                                 ["park"]+["exit"]*(len(cpus)-1))
                self.assertEqual(orphans.verify(text,len(cpus)),len(cpus))
                for kwargs in ({},{"ipc_staged":True},{"root_orphan_v1":True}):
                    with self.assertRaises(processes.VerificationError):
                        processes.verify(text,cpus,**kwargs)
                if not complete:
                    self.reject(text,cpus,True)

    def test_missing_duplicate_reordered_and_foreign_records(self):
        text=transcript()
        lines=text.splitlines(keepends=True)
        for i,row in enumerate(lines):
            if row.startswith("AGENTOS USER FAULT"):
                continue  # Separate runtime verifier owns foreground fault.
            with self.subTest(row=i):
                self.reject("".join(lines[:i]+lines[i+1:]))
                self.reject("".join(lines[:i]+[row]+lines[i:]))
        self.reject(text.replace(family(19,4,0x400000,0x500000,False),""))
        self.reject(text.replace(family(19,4,0x400000,0x500000,False),family(7,4,0x400000,0x500000,False)))
        self.reject(text.replace(family(19,4,0x400000,0x500000,False),family(19,1,0x400000,0x500000,False)))
        a=lines.copy()
        a[2],a[3]=a[3],a[2]
        self.reject("".join(a))

    def test_wrong_root_apic_cr3_collection_or_manager(self):
        text=transcript()
        for prefix,field,value in (
            ("AGENTOS TASK BSP","APIC",19),
            ("AGENTOS ORPHAN BEGIN ROOT=0000000000000004","ROOT",1),
            ("AGENTOS ORPHAN ENDED ROOT=0000000000000004","ROOT",5),
            ("AGENTOS ORPHAN ADOPT","PARENT",99),
            ("AGENTOS ORPHAN REAPS","STATUS",0),
            ("AGENTOS USER KILL","PARENT",4),
            ("AGENTOS USER PARK","CR3",0),
            ("AGENTOS USER PARK","STATUS",1),
            ("AGENTOS USER EXIT PID=0000000000000004","CR3",0x300000),
            ("AGENTOS USER EXIT PID=0000000000000004","STATUS",1),
            ("AGENTOS USER EXIT PID=0000000000000005","CR3",0x400000),
            ("AGENTOS PROCESS OK APIC=0000000000000013","PARENT",3),
            ("AGENTOS PROCESS OK APIC=0000000000000013","APIC",7),
            ("AGENTOS MANAGER SESSION START","PID",4),
            ("AGENTOS MANAGER BEGIN","ROOT",4),
            ("AGENTOS SHELL START","PID",3),
            ("AGENTOS USER EXIT PID=0000000000000001","CR3",0x500000),
            ("AGENTOS MANAGER SESSION STOP","PID",4),
        ):
            row=next(s for s in text.splitlines() if s.startswith(prefix))
            wrong=re.sub(field+r"=[0-9a-f]{16}",field+f"={value:016x}",row,count=1)
            self.assertNotEqual(row,wrong)
            with self.subTest(prefix=prefix,field=field):
                self.reject(text.replace(row,wrong,1))
        self.reject(text.replace("AGENTOS USER PARK PID=","AGENTOS USER EXIT PID=",1))
        self.reject(text.replace("AGENTOS USER EXIT PID=0000000000000004","AGENTOS USER PARK PID=0000000000000004"))
        self.reject(text.replace("FRAMES=OK","FRAMES=LEAK"))

    def test_old_fault_and_workload_cannot_escape_boot_boundary(self):
        text=transcript()
        fault=next(s for s in text.splitlines(keepends=True) if s.startswith("AGENTOS USER FAULT"))
        for marker in (fault,"AGENTOS USER SURVIVED\n","AGENTOS TEST FAULT PROBE\n"):
            for boundary in ("AGENTOS ORPHAN BEGIN","AGENTOS MANAGER BEGIN","AGENTOS SHELL READY"):
                with self.subTest(marker=marker,boundary=boundary):
                    self.reject(text.replace(boundary,marker+boundary,1))
        self.reject(text+"AGENTOS USER SURVIVED\n")
        self.reject(text+family(19,7,0x500000,0x600000,False))
        self.reject(text.replace("AGENTOS USER FAULT PID=0000000000000011",
                                 "AGENTOS USER FAULT PID=0000000000000006"))
        self.reject(text,cpus=(7,))


if __name__=="__main__":
    unittest.main()
