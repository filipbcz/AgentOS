"""Synthetic rejection tests for the new verifier; never guest evidence."""
import importlib.util
from pathlib import Path
import re
import unittest

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

v=load("verify-smp-soak.py")
image=load("smp-soak-image.py")
fixtures=load("test-supervisor-staging.py")
session_fixture=load("test-verify-stage3-session.py")
session=session_fixture.v

def transcript(cpus,*,omit_apic=False,moved=False,root=100,shell=9):
    ids=list(range(7,7+2*cpus,2))
    workers=cpus+2
    pids=list(range(root+1,root+1+workers))
    setup=1000
    go=1500
    start=go+2000
    end=start+60000
    deadline=end+15000
    rows=[v.COMMAND.encode("ascii")]
    def record(kind,**values):
        rows.append(v.MARKER+kind.encode("ascii")+b"".join(
            b" "+k.encode("ascii")+b"="+f"{value&v.MASK:016x}".encode("ascii") for k,value in values.items()))
    def exit_row(pid,cr3,status=0):
        rows.append(f"AGENTOS USER EXIT PID={pid:016x} CR3={cr3:016x} STATUS={status:016x}".encode())
    def apic(i):
        return ids[i%(cpus-1 if omit_apic else cpus)]
    record("ROOT",PID=root,PARENT=shell,CPUS=cpus,WORKERS=workers,APIC=ids[0],MS=setup,LIMIT=setup+20000)
    for i,pid in enumerate(pids):
        record("SPAWN",PID=root,SLOT=i,CHILD=pid)
    for i,pid in enumerate(pids):
        record("READY",PID=pid,PARENT=root,SLOT=i,APIC=apic(i),CPUS=cpus,MOVES=0,MS=setup+10+i,UID=1000,GID=1000)
    record("GO",PID=root,MS=go,START=start,END=end,DEADLINE=deadline)
    for e in range(30):
        base=start+e*2000
        for i,pid in enumerate(pids):
            work=e*4096+64
            record("SAMPLE",PID=pid,EPOCH=e,START=base+100+i,MID=base+750+i,END=base+1500+i,
                   BEFORE=work,MIDDLE=work+64,AFTER=work+128)
            record("DATA",PID=pid,EPOCH=e,APIC0=apic(i),APIC1=apic(i),MOVE0=e if moved else 0,
                   MOVE1=e+1 if moved else 0,HASH=v.payload_digest(pid,e,work+128),RX=base+1600+i)
    for i,pid in enumerate(pids):
        record("DONE",PID=pid,APIC=apic(i),MOVES=30 if moved else 0,MS=end+10+i,WORK=30*4096,TRY=-11)
    record("RELEASE",PID=root,MS=end+100,COUNT=workers,DEADLINE=deadline)
    for i,pid in enumerate(pids):
        exit_row(pid,0x600000+i*4096)
        record("REAP",PID=root,CHILD=pid,STATUS=0,AGAIN=-10)
    record("FINAL",PID=root,EMPTY=-10,MS=end+200)
    exit_row(root,0x700000)
    return b"\r\n".join(rows)+b"\r\nexit status 0\r\nagentos> ",set(ids)

class SoakTests(unittest.TestCase):
    def verify(self,data,apics):
        return v.verify_prefix(data,9,0x300000,{1,2,9},apics)

    def test_complete_work_shape(self):
        for n in (4,8):
            data,apics=transcript(n)
            consumed,proof,pids=self.verify(data,apics)
            self.assertEqual(consumed,len(data))
            self.assertEqual(len(pids),n+3)
            self.assertEqual(proof["duration_ms"],60000)
            self.assertEqual(proof["samples"],30*(n+2))
            self.assertEqual(proof["payload_bytes"],30*(n+2)*128)
            self.assertEqual(len(proof["windows"]),6)
            self.assertTrue(all(set(w["apics"])==apics and len(w["overlap"])==5 for w in proof["windows"]))
            self.assertTrue(all(len(row)+2<=256 for row in data.split(b"\r\n") if row.startswith(v.MARKER)))

    def test_missing_apic_and_moved_samples_do_not_count(self):
        for n in (4,8):
            for kw in (dict(omit_apic=True),dict(moved=True)):
                data,apics=transcript(n,**kw)
                with self.assertRaises(v.VerificationError):
                    self.verify(data,apics)

    def test_missing_duplicate_foreign_and_bad_values(self):
        data,apics=transcript(4)
        rows=data.splitlines(keepends=True)
        for kind in (b"ROOT",b"SPAWN",b"READY",b"GO",b"SAMPLE",b"DATA",b"DONE",b"RELEASE",b"REAP",b"FINAL"):
            i=next(i for i,row in enumerate(rows) if row.startswith(v.MARKER+kind+b" "))
            for replacement in (b"",rows[i]+rows[i]):
                with self.subTest(kind=kind,replacement=replacement),self.assertRaises(v.VerificationError):
                    self.verify(b"".join(rows[:i])+replacement+b"".join(rows[i+1:]),apics)
        for kind,key,value in (
            (b"ROOT",b"PARENT",1),(b"SPAWN",b"CHILD",100),
            (b"READY",b"UID",0),(b"READY",b"APIC",255),
            (b"GO",b"END",63501),(b"SAMPLE",b"EPOCH",1),
            (b"SAMPLE",b"START",5501),(b"SAMPLE",b"MIDDLE",64),
            (b"SAMPLE",b"AFTER",128),(b"DATA",b"PID",102),
            (b"DATA",b"APIC1",9),(b"DATA",b"HASH",0),(b"DATA",b"RX",3500),
            (b"DONE",b"MS",63499),(b"DONE",b"TRY",0),
            (b"RELEASE",b"COUNT",5),(b"REAP",b"STATUS",1),
            (b"REAP",b"AGAIN",0),(b"FINAL",b"EMPTY",0)):
            pattern=rb"(?m)^("+re.escape(v.MARKER+kind)+rb" [^\r\n]*?\b"+key+rb"=)[0-9a-f]{16}"
            bad,n=re.subn(pattern,lambda m:m[1]+f"{value:016x}".encode(),data,count=1)
            self.assertEqual(n,1)
            with self.subTest(kind=kind,key=key),self.assertRaises(v.VerificationError):
                self.verify(bad,apics)
        first_exit=next(row for row in rows if row.startswith(b"AGENTOS USER EXIT "))
        for bad in (data.replace(first_exit,b"",1),data.replace(first_exit,first_exit+first_exit,1),
                    data.replace(first_exit,first_exit.replace(b"STATUS=0000000000000000",b"STATUS=0000000000000089"),1),
                    data.replace(first_exit,first_exit.replace(b"CR3=0000000000600000",b"CR3=0000000000300000"),1),
                    data.replace(b"exit status 0\r\nagentos> ",b"exit status 1\r\nagentos> ")):
            with self.assertRaises(v.VerificationError):
                self.verify(bad,apics)

    def test_session_explicit_and_final_shutdown(self):
        for n in (4,8):
            interval,ids=transcript(n)
            roster=b"".join(f"AGENTOS TASK {'BSP' if i==0 else 'AP'} APIC={cpu:016x} TIMER-WAKES=0000000000000003\r\n".encode()
                            for i,cpu in enumerate(sorted(ids)))
            ordinary=roster+session_fixture.transcript(True)
            full=ordinary.replace(session.READY,session.READY+interval,1)
            inputs=session.SMP_SOAK_INPUT+session.transmitted_input(9,True)
            flags=dict(aBasicSmp=True,aSmpSoak=True,aMigrationStaged=True,aFaultStaged=True)
            proof=session.verify(full,inputs,True,n,**flags)
            lo,hi=proof["runtime_smp_soak"]["interval_bytes"]
            self.assertEqual(full[lo:hi],interval)
            for bad,inp,opts in (
                (full,inputs,{**flags,"aSmpSoak":False}),
                (ordinary,inputs,flags),
                (full,session.transmitted_input(9,True),flags),
                (full.replace(b"FRAMES=OK",b"FRAMES=LEAK",1),inputs,flags),
                (full.replace(b"[INFO] INTERACTIVE SHELL STOPPED\r\n",b""),inputs,flags),
                (b"AGENTOS TEST SMP SOAK leak\r\n"+full,inputs,flags),
                (full.replace(b"help\r\n",b"AGENTOS TEST SMP SOAK leak\r\nhelp\r\n",1),inputs,flags)):
                with self.assertRaises(session.VerificationError):
                    session.verify(bad,inp,True,n,**opts)

    def test_only_separate_client_may_extend_archive(self):
        f=fixtures.ImageTests()
        f.setUp()
        elf=b"fixture "+v.MARKER
        stage=image.append_client(f.control,elf)
        def check(archive,staged,client=elf):
            a=fixtures.pe(f.kernel,archive)
            b=fixtures.pe(f.kernel,staged)
            return image.verify_contents(image.images.pe_sections(a)[2],image.images.pe_sections(b)[2],
                                         f.kernel,archive,staged,client)
        # Use the actual CPIO parsing contract. Synthetic PE is not signed guest evidence.
        entries=image.images.cpio_entries(f.control)
        staged_entries=image.images.cpio_entries(stage)
        self.assertEqual(set(staged_entries),set(entries)|{"smp-soak"})
        self.assertTrue(all(staged_entries[k]==value for k,value in entries.items()))
        self.assertEqual(set(check(f.control,stage)),set(entries))
        for name,payload in (("smp-soak",b"fixture"),("subdir/smp-soak",b"fixture"),("renamed",elf)):
            with self.assertRaises(ValueError):
                image.images.verify_distribution(fixtures.archive([*f.entries,(name,payload)]))
        for bad in (f.control,fixtures.archive([*f.entries,("smp-soak",b"wrong")]),
                    fixtures.archive([*f.entries,("smp-soak",elf),("extra",b"x")]),
                    fixtures.archive([("init",b"wrong") if n=="init" else (n,p) for n,p in f.entries]+[("smp-soak",elf)])):
            with self.assertRaises(ValueError):
                check(f.control,bad)

if __name__=="__main__":
    unittest.main()
