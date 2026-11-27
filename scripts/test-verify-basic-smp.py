"""Synthetic tests only; QMP/COM1 fixtures never count as real guest evidence."""
import importlib.util
from pathlib import Path
import copy
import unittest

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

basic=load("verify-basic-smp.py")
roots=load("test-verify-boot-roots.py")
session_fixture=load("test-verify-stage3-session.py")
session=session_fixture.v

def records(cpus):
    # Non-contiguous IDs ensure a count or cpu-index is not used as APIC.
    ids=[7+2*i for i in range(cpus)]
    qmp={"accelerator":"tcg","kvm":{"enabled":False,"present":True},
         "cpus":[{"cpu-index":i,"thread-id":100+i,"target":"x86_64",
                  "qom-path":f"/machine/cpu{i}","apic-id":apic} for i,apic in enumerate(ids)]}
    log="".join(f"AGENTOS TASK {'BSP' if i==0 else 'AP'} APIC={apic:016x} TIMER-WAKES=0000000000000003\n"
                for i,apic in enumerate(ids))
    log+="[INFO] PROCESSORS ONLINE\n"
    for apic in ids:
        for slot in (0,1):
            log+=f"AGENTOS SCHED APIC={apic:016x} TASK={slot:016x} PREEMPTIONS=0000000000000002 PAGES=0000000000001000\n"
    log+=f"AGENTOS FRAME STRESS BITMAP OK HELD={16*cpus:016x} FREE-BEFORE=0000000000001000 FREE-AFTER=0000000000001000\n"
    log+=f"AGENTOS OOM OK DRAINED=0000000000001000 REJECT-CPUS={cpus:016x} RESTORED=0000000000001000\n"
    log+="[INFO] STARTING USER PROCESSES\n"
    for i,apic in enumerate(ids):
        log+=roots.family(apic,1+3*i,0x400000+i*8192,0x401000+i*8192,i==0)
    log+="AGENTOS IDLE BEGIN TSC-HZ=0000000000001000\n"
    for apic in ids:
        log+=f"AGENTOS IDLE APIC={apic:016x} WAKES=0000000000000001 TIMERS=0000000000000001 TSC-TOTAL=0000000000001000 TSC-ACTIVE=0000000000000001\n"
    log+=("AGENTOS MANAGER SESSION START PID=0000000000000001\n"
          "AGENTOS MANAGER BEGIN ROOT=0000000000000001 COUNT=00000003\n"
          "AGENTOS SHELL START PID=0000000000000064\n"
          "AGENTOS SHELL READY\n"
          "AGENTOS USER EXIT PID=0000000000000064 CR3=0000000000500000 STATUS=0000000000000000\n"
          "AGENTOS USER EXIT PID=0000000000000001 CR3=0000000000400000 STATUS=0000000000000000\n"
          "AGENTOS MANAGER SESSION STOP PID=0000000000000001 STATUS=0000000000000000 FRAMES=OK\n"
          "[INFO] INTERACTIVE SHELL STOPPED\n")
    return log,qmp

class BasicSmpTests(unittest.TestCase):
    def test_real_evidence_contract_shape(self):
        for cpus in (4,8):
            log,qmp=records(cpus)
            proof=basic.verify_progress(log,cpus,qmp)
            self.assertEqual(len(proof["cpus"]),cpus)
            self.assertEqual({c["apic"] for c in proof["cpus"]},basic.qmp_ids(qmp,cpus))
            self.assertTrue(proof["boot_roots"]["shutdown_verified"])
            self.assertTrue(proof["final_shutdown"])
            with self.assertRaises(roots.orphans.VerificationError):
                roots.orphans.verify(log,cpus)

    def test_missing_duplicate_and_invalid_progress(self):
        for cpus in (4,8):
            log,qmp=records(cpus)
            rows=log.splitlines(keepends=True)
            for i,row in enumerate(rows):
                with self.subTest(cpus=cpus,row=i),self.assertRaises(ValueError):
                    basic.verify_progress("".join(rows[:i]+rows[i+1:]),cpus,qmp)
                with self.subTest(cpus=cpus,row=i),self.assertRaises(ValueError):
                    basic.verify_progress("".join(rows[:i]+[row]+rows[i:]),cpus,qmp)
            for old,new in (("PREEMPTIONS=0000000000000002","PREEMPTIONS=0000000000000001"),
                            ("PAGES=0000000000001000","PAGES=0000000000000000"),
                            ("TIMER-WAKES=0000000000000003","TIMER-WAKES=0000000000000000"),
                            ("TIMERS=0000000000000001","TIMERS=0000000000000000"),
                            ("FRAMES=OK","FRAMES=LEAK"),("AGENTOS USER PARK","AGENTOS USER EXIT"),
                            ("AGENTOS TASK AP APIC=0000000000000009","AGENTOS TASK AP APIC=0000000000000007")):
                self.assertIn(old,log)
                with self.subTest(old=old),self.assertRaises(ValueError):
                    basic.verify_progress(log.replace(old,new,1),cpus,qmp)
            for field,value in (("apic-id",7),("thread-id",100),("cpu-index",0),("qom-path","/machine/cpu0"),
                                ("apic-id",19 if cpus==4 else 41)):
                changed=copy.deepcopy(qmp)
                changed["cpus"][1][field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):
                    basic.verify_progress(log,cpus,changed)
            changed=copy.deepcopy(qmp)
            changed["cpus"].pop()
            with self.assertRaises(ValueError):
                basic.verify_progress(log,cpus,changed)

    def test_explicit_ordinary_session_profile(self):
        for cpus in (4,8):
            log,qmp=records(cpus)
            roster="".join(row+"\r\n" for row in log.splitlines() if row.startswith("AGENTOS TASK ")).encode()
            full=roster+session_fixture.transcript(True)
            sent=session.transmitted_input(9,True)
            args=dict(aMigrationStaged=True,aFaultStaged=True,aBasicSmp=True)
            proof=session.verify(full,sent,True,cpus,**args)
            self.assertEqual(proof["idle"]["timer_cpu_count"],cpus)
            for bad in ({**args,"aBasicSmp":False},{**args,"aMigrationStaged":False},
                        {**args,"aRuntimeProcess":True},{**args,"aSupervisorImage":"control"}):
                with self.assertRaises(session.VerificationError):
                    session.verify(full,sent,True,cpus,**bad)
            with self.assertRaises(session.VerificationError):
                session.verify(full.replace(b"[INFO] INTERACTIVE SHELL STOPPED\r\n",b""),sent,True,cpus,**args)
            with self.assertRaises(session.VerificationError):
                session.verify(full,None,True,cpus,**args)
            with self.assertRaises(session.VerificationError):
                session.bootCpuRoster(full,cpus)

if __name__=="__main__":
    unittest.main()
