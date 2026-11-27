"""Synthetic host rejection tests; never guest boot or signature evidence."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


images = load("verify-supervisor-image.py")
session = load("verify-stage3-session.py")
supervisor = load("verify-supervisor.py")


def archive(entries):
    output = bytearray()
    for inode, (name, contents) in enumerate([*entries, ("TRAILER!!!", b"")]):
        path = name.encode("ascii")+b"\0"
        fields = (inode,0o100755,0,0,1,0,len(contents),0,0,0,0,len(path),0)
        output += b"070701"+b"".join(f"{f:08x}".encode("ascii") for f in fields)+path
        output += b"\0"*((-len(output))%4)
        output += contents
        output += b"\0"*((-len(output))%4)
    return bytes(output)


def pe(kernel, initrd):
    # Minimal synthetic PE headers and sections. No valid signature is created.
    image = bytearray(512)
    image[:2] = b"MZ"
    struct.pack_into("<I",image,60,128)
    image[128:132] = b"PE\0\0"
    struct.pack_into("<HH",image,132,0x8664,3)
    struct.pack_into("<H",image,148,240)
    opt=152
    struct.pack_into("<H",image,opt,0x20b)
    struct.pack_into("<H",image,opt+68,10)
    struct.pack_into("<I",image,opt+108,16)
    for i,(name,payload) in enumerate(((b".text",b"loader"),(b".kernel",kernel),(b".initrd",initrd))):
        at=opt+240+i*40
        image[at:at+8]=name.ljust(8,b"\0")
        raw_size=(len(payload)+511)&~511
        struct.pack_into("<IIII",image,at+8,len(payload),4096*(i+1),raw_size,len(image))
        image+=payload+b"\0"*(raw_size-len(payload))
    return bytes(image)


def fake_certificate(unsigned):
    signed=bytearray(unsigned)
    struct.pack_into("<I",signed,152+64,1)
    struct.pack_into("<II",signed,152+144,len(unsigned),8)
    signed+=b"fixture!"
    return bytes(signed)


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.entries=[(n,n.encode()) for n in ("stage","init","fault","service","shell","svc_ok",
                      "svc_fail","svc_hang","orphan_parent","manager","svc_alive","svc_flaky","data")]
        self.entries.append(("data/transfer.bin",bytes((i*73+i//251*19)%256 for i in range(8193))))
        self.control=archive(self.entries)
        self.runner=b"isolated test fixture"
        self.pipe_runner=b"pipe sender fixture"
        self.pipe_receiver=b"pipe receiver fixture"
        self.additions=[(images.RUNNER,self.runner),(images.PIPE_RUNNER,self.pipe_runner),
                        (images.PIPE_RECEIVER,self.pipe_receiver)]
        self.staged=archive([*self.entries,*self.additions])
        self.kernel=b"kernel fixture"

    def check(self, control, staged, runner=None):
        a=pe(self.kernel,control)
        b=pe(self.kernel,staged)
        return images.verify_contents(images.signed_payload(a,fake_certificate(a)),
            images.signed_payload(b,fake_certificate(b)),self.kernel,control,staged,
            self.runner if runner is None else runner,self.pipe_runner,self.pipe_receiver)

    def test_exact_archive_addition(self):
        result=self.check(self.control,self.staged)
        self.assertEqual(set(result),{name for name,_ in self.entries})
        self.assertNotIn(images.RUNNER,result)

    def test_missing_extra_changed_runner_or_common_entry(self):
        for a,b in ((self.staged,self.staged),(self.control,self.control),
                    (self.control,archive([*self.entries,*self.additions,("extra",b"x")])),
                    (self.control,archive([("init",b"changed"),*self.entries[1:],*self.additions])),
                    (self.control,archive([*self.entries[1:],*self.additions]))):
            with self.subTest(a=len(a),b=len(b)), self.assertRaises(images.VerificationError):
                self.check(a,b)
        with self.assertRaises(images.VerificationError):
            self.check(self.control,self.staged,b"wrong runner")

    def test_removed_pipe_payload_and_shared_data(self):
        for extra in (("receiver",b"legacy receiver"),("other/receiver",b"alias"),
                      ("renamed",b"AGENTOS PIPE RECEIVED PID=")):
            with self.subTest(extra=extra),self.assertRaises(images.VerificationError):
                self.check(archive([*self.entries,extra]),archive([*self.entries,extra,*self.additions]))
        for marker in (b"AGENTOS PIPE SENT PID=",b"AGENTOS PIPE TEST SENT PID="):
            bad=[(name,payload+marker if name=="init" else payload) for name,payload in self.entries]
            with self.subTest(marker=marker),self.assertRaises(images.VerificationError):
                self.check(archive(bad),archive([*bad,*self.additions]))
        for shared in (self.entries[:-1], self.entries[:-1]+[("data/transfer.bin",b"wrong")]):
            with self.subTest(shared=len(shared)),self.assertRaises(images.VerificationError):
                self.check(archive(shared),archive([*shared,*self.additions]))
        with self.assertRaises(images.VerificationError):
            self.check(self.control,archive([*self.entries,*self.additions,("receiver",b"legacy")]))
        with self.assertRaises(images.VerificationError):
            self.check(self.control,archive([*self.entries,*self.additions[:-1]]))

    def test_archive_duplicates_aliases_truncation_and_junk(self):
        for bad in (archive([*self.entries,self.entries[0]]),archive([("./init",b"alias")]),
                    self.control[:-4],self.control+b"junk",archive([("../init",b"alias")])):
            with self.subTest(bad=len(bad)), self.assertRaises(images.VerificationError):
                images.cpio_entries(bad)

    def test_signing_may_not_change_any_payload_or_header(self):
        unsigned=pe(self.kernel,self.control)
        signed=fake_certificate(unsigned)
        self.assertEqual(images.signed_payload(unsigned,signed)[".kernel"][1],self.kernel)
        for offset in (0,156,400,512,1024,1536,152+144):
            bad=bytearray(signed)
            bad[offset]^=1
            with self.subTest(offset=offset), self.assertRaises(images.VerificationError):
                images.signed_payload(unsigned,bytes(bad))
        with self.assertRaises(images.VerificationError):
            images.signed_payload(unsigned,signed[:-1])
        with self.assertRaises(images.VerificationError):
            images.signed_payload(unsigned,unsigned)


def supervisor_phase(parent, first, cr3=0x600000):
    records=[f"AGENTOS SUPERVISOR BEGIN PARENT={parent:016x}"]
    def exit_line(pid,status):
        records.append(f"AGENTOS USER EXIT PID={pid:016x} CR3={cr3:016x} STATUS={status:016x}")
    def event(name,pid,status,attempt):
        records.append(f"AGENTOS SERVICE {name} PARENT={parent:016x} CHILD={pid:016x} "
                       f"STATUS={status:016x} ATTEMPT={attempt:08x}")
    exit_line(first,0)
    event("DONE",first,0,1)
    for attempt in range(1,4):
        exit_line(first+attempt,42)
        event("REAP",first+attempt,42,attempt)
    event("STOP",first+3,42,3)
    records.append(f"AGENTOS USER KILL PID={first+4:016x} PARENT={parent:016x} STATUS={137:016x}")
    records.append(f"AGENTOS SERVICE DURATION PARENT={parent:016x} CHILD={first+4:016x} MS={250:016x}")
    event("TIME",first+4,137,1)
    event("STOP",first+4,137,1)
    records.append(f"AGENTOS SUPERVISOR ENDED PARENT={parent:016x}")
    return records


def supervisor_transcript(shell=9,runner=20,apics=(7,),moving=False,skipping=False,
                          peer_moving=False,peer_missed=False,peer_unpaired=False,pipe=False,probe="runnable"):
    """Synthetic evidence, not a guest execution or signature proof."""
    cpus=len(apics)
    count=1 if cpus==1 else 2*cpus
    total=0 if cpus==1 else 4
    records=[session.PIPE_COMMAND if pipe else session.SUPERVISOR_COMMAND]
    def note(kind,**fields):
        records.append("AGENTOS TEST "+kind+"".join(f" {k}={v:016x}" for k,v in fields.items()))
    def snap(kind,pid,parent,cpu,ms,moves=0,work=None):
        fields=dict(PID=pid,PARENT=parent,APIC=cpu,CPUS=cpus,MOVES=moves,TOTAL=total,MS=ms)
        if work is not None:
            fields["WORK"]=work
        note(kind,**fields)
    def exit_line(pid,status,cr3):
        records.append(f"AGENTOS USER EXIT PID={pid:016x} CR3={cr3:016x} STATUS={status:016x}")
    snap("RUNNER",runner,shell,apics[0],1000)
    covered=set()
    next_pid=runner+1
    ms=1100
    pair_number=0
    for rnd in range(1,5):
        if len(covered)==cpus:
            break
        note("WAVE",ROOT=runner,ROUND=rnd,COUNT=count)
        candidates=list(range(next_pid,next_pid+count))
        next_pid+=count
        placement={pid:apics[i%cpus] for i,pid in enumerate(candidates)}
        for i,pid in enumerate(candidates):
            note("CANDIDATE",ROOT=runner,ROUND=rnd,SLOT=i,PID=pid)
        for pid in candidates:
            snap("READY",pid,runner,placement[pid],ms)
            ms+=1
        ms+=100
        remaining=candidates.copy()
        def collect(pid,status):
            exit_line(pid,status,0x500000+candidates.index(pid)*4096)
            note("REAP",ROOT=runner,PID=pid,STATUS=status)
            remaining.remove(pid)
        def wait_trace(pid,kind,cpu,moves=0):
            if probe is None:
                return
            prior_total=total-moves
            note("WAIT_SEND",ROOT=runner,ROUND=rnd,TARGET=pid,KIND=kind,APIC=apics[0],MS=ms,TOTAL=prior_total)
            note("WAIT_ENTER",PID=pid,PARENT=runner,APIC=placement[pid],CPUS=cpus,
                 MOVES=0,TOTAL=prior_total,MS=ms)
            snap("WAIT_RETURN",pid,runner,cpu,ms,moves)
            snap("WAIT_RECEIVED",pid,runner,cpu,ms,moves)
            note("WAIT_RESULT",PID=pid,MODE=1 if probe=="blocked" else 2,KIND=kind,
                 POLLS=0 if probe=="blocked" else 3,EVENTS=4 if probe=="blocked" else 0,BYTES=24)
        def attempt(pid,run,first):
            nonlocal ms,total,next_pid
            cpu=placement[pid]
            note("SELECT",ROOT=runner,PID=pid,APIC=cpu,RUN=int(run))
            wait_trace(pid,2 if run else 3,cpu)
            status=0
            if run and first and skipping:
                total+=1
                snap("SKIP",pid,runner,next(a for a in apics if a!=cpu),ms,1)
                status=75
            elif run:
                snap("BEGIN",pid,runner,cpu,ms)
                if pipe:
                    child=next_pid
                    for phase,at in (("BEGIN",ms+1),("ENDED",ms+50)):
                        records.append(f"AGENTOS PIPE TEST {phase} PID={child:016x} PARENT={pid:016x} APIC={cpu:016x} CPUS={cpus:016x} MOVES=0000000000000000 TOTAL={total:016x} MS={at:016x}")
                    records.append(f"AGENTOS PIPE TEST RECEIVED PID={child:016x} BYTES=00002001 FNV32=1490a95f EOF=00000002")
                    exit_line(child,0,0x600000)
                    records.append(f"AGENTOS PIPE TEST SENT PID={pid:016x} CHILD={child:016x} BYTES=0000000000002001 DIRECT=000000000000000c DUP=000000000000000b WRITES=0000000000000018 SHORT=0000000000000001")
                    next_pid+=1
                else:
                    records.extend(supervisor_phase(pid,next_pid))
                    next_pid+=5
                ms+=350
                if first and moving:
                    total+=1
                    status=76
                snap("ENDED",pid,runner,cpu,ms)
            collect(pid,status)
            ms+=10
            return status
        if cpus==2:
            while len(covered)<cpus:
                peer=next((peer for fallback in (False,True)
                           for pid in remaining if placement[pid] not in covered
                           for peer in remaining if peer!=pid and
                           (fallback or placement[peer]!=placement[pid])),None)
                if peer is None:
                    break
                first=pair_number==0
                pair_number+=1
                note("PEER_ACTIVATE",ROOT=runner,ROUND=rnd,PEER=peer)
                peer_cpu=placement[peer]
                moves=0
                if (first and peer_missed) or (pair_number==2 and peer_unpaired):
                    total+=1
                    moves=1
                    peer_cpu=next(a for a in apics if a!=peer_cpu)
                wait_trace(peer,4,peer_cpu,moves)
                snap("PEER_BEGIN",peer,runner,peer_cpu,ms,moves,0)
                ms+=10
                pid=next((pid for pid in remaining if pid!=peer and
                          placement[pid]!=peer_cpu and placement[pid] not in covered),None)
                status=None
                if pid is None:
                    note("UNPAIRED",ROOT=runner,PEER=peer)
                else:
                    note("PAIR",ROOT=runner,PID=pid,PEER=peer)
                    status=attempt(pid,True,first)
                if first and peer_moving:
                    total+=1
                    moves+=1
                    peer_cpu=next(a for a in apics if a!=peer_cpu)
                snap("PEER_END",peer,runner,peer_cpu,ms,moves,200)
                collect(peer,0)
                ms+=10
                if pid is not None and status==0 and not (first and peer_moving):
                    covered.add(placement[pid])
            for pid in remaining.copy():
                attempt(pid,False,False)
        else:
            for pid in remaining.copy():
                run=placement[pid] not in covered
                status=attempt(pid,run,False)
                if run and status==0:
                    covered.add(placement[pid])
    snap("COMPLETE",runner,shell,apics[0],ms)
    exit_line(runner,0,0x700000)
    records.append("exit status 0")
    return ("\r\n".join(records)+"\r\nagentos> ").encode("ascii")


class RuntimeTests(unittest.TestCase):
    def verify(self,data,variant="test",prior=None,apics=(7,)):
        return session.supervisor_prefix(data,9,0x300000,{1,2,9} if prior is None else prior,variant,set(apics))

    def test_real_event_contract(self):
        data=supervisor_transcript()
        offset,receipt,seen=self.verify(data)
        self.assertEqual(offset,len(data))
        self.assertEqual(receipt["intervals"][0]["child_statuses"],[0,42,42,42,137])
        self.assertEqual(receipt["covered_apics"],[7])
        self.assertEqual(receipt["runner_pid"],20)
        self.assertEqual(receipt["shell_pid"],9)
        self.assertEqual(seen,set(range(20,27)))
        self.assertEqual(receipt["intervals"][0]["duration_ms"],250)

    def test_control_requires_missing_runner(self):
        data=(session.SUPERVISOR_COMMAND+"\r\n").encode()+session.SUPERVISOR_MISSING
        self.assertEqual(self.verify(data,"control"),(len(data),{"absent":True},set()))
        for bad in (data.replace(b"(-2)",b"(-8)"),supervisor_transcript()):
            with self.assertRaises(session.VerificationError):
                self.verify(bad,"control")
        with self.assertRaises(session.VerificationError):
            self.verify(data)

    def test_missing_duplicate_reordered_and_foreign_evidence(self):
        data=supervisor_transcript()
        lines=data.splitlines(keepends=True)
        for i in range(len(lines)):
            with self.subTest(line=i), self.assertRaises(session.VerificationError):
                self.verify(b"".join(lines[:i]+lines[i+1:]))
        for bad in (b"".join(lines[:5]+[lines[4]]+lines[5:]),
                    b"".join(lines[:4]+[lines[5],lines[4]]+lines[6:])):
            with self.assertRaises(session.VerificationError):
                self.verify(bad)
        for old,new in ((b"PARENT=0000000000000009",b"PARENT=0000000000000001"),
                        (b"STATUS=000000000000002a",b"STATUS=0000000000000000"),
                        (b"STATUS=0000000000000089",b"STATUS=0000000000000088"),
                        (b"MS=00000000000000fa",b"MS=00000000000000f9"),
                        (b"ATTEMPT=00000003",b"ATTEMPT=00000004"),
                        (b"CR3=0000000000600000",b"CR3=0000000000500000"),
                        (b"PID=0000000000000015",b"PID=0000000000000014"),
                        (b"exit status 0",b"exit status 1")):
            with self.subTest(old=old),self.assertRaises(session.VerificationError):
                self.verify(data.replace(old,new,1))
        for reused in (20,21,25):
            with self.assertRaises(session.VerificationError):
                self.verify(data,prior={1,9,reused})

    def test_full_session_preserves_foreground_fault_and_manager_regressions(self):
        # Reuse the existing independent stage-3 synthetic session fixture.
        fixture=load("test-verify-stage3-session.py")
        base=(b"AGENTOS TASK BSP APIC=0000000000000007 TIMER-WAKES=0000000000000003\r\n"
              +fixture.transcript(True))
        for old,new in ((10,50),(11,51),(12,52),(13,53)):
            base=base.replace(f"PID={old:016x}".encode(),f"PID={new:016x}".encode())
        fg=(b"run /svc_ok\r\n"
            b"AGENTOS USER EXIT PID=0000000000000010 CR3=0000000000500000 STATUS=0000000000000000\r\n"
            b"exit status 0\r\nagentos> run /svc_fail\r\n"
            b"AGENTOS USER EXIT PID=0000000000000011 CR3=0000000000500000 STATUS=000000000000002a\r\n"
            b"exit status 42\r\nagentos> run /fault\r\n"
            b"AGENTOS USER FAULT PID=0000000000000012 PARENT=0000000000000009 CR3=0000000000500000 VECTOR=000000000000000e ERROR=0000000000000005 ADDRESS=0000000002000000\r\n"
            b"exit status 270\r\nagentos> ")
        serial=session.runtime_input()+session.SUPERVISOR_INPUT+session.PIPE_INPUT+session.transmitted_input(9,True)
        for variant,prefix in (("control",(session.SUPERVISOR_COMMAND+"\r\n").encode()+session.SUPERVISOR_MISSING+
                                          (session.PIPE_COMMAND+"\r\n").encode()+session.SUPERVISOR_MISSING),
                               ("test",supervisor_transcript()+supervisor_transcript(runner=40,pipe=True))):
            log=base.replace(session.READY,session.READY+fg+prefix,1)
            result=session.verify(log,serial,True,1,aRuntimeProcess=True,aSupervisorImage=variant)
            self.assertEqual([r["status"] for r in result["runtime_process_regression"]],[0,42,270])
            self.assertEqual(result["restarted_pids"],[51,52,53])
            self.assertEqual(result["runtime_supervisor"]["absent"],variant=="control")
            self.assertEqual(result["runtime_pipe"]["absent"],variant=="control")
            # The entire normal boot (and every non-workload byte afterward)
            # must be free of the relocated supervisor, even in the staged image.
            markers=(b"AGENTOS SUPERVISOR BEGIN PARENT=0000000000000001\r\n",
                     b"AGENTOS SERVICE DONE PARENT=0000000000000001\r\n",
                     b"AGENTOS TEST PEER_BEGIN PID=0000000000000001\r\n",
                     b"AGENTOS PIPE TEST RECEIVED PID=0000000000000001\r\n",
                     b"AGENTOS PIPE RECEIVED PID=0000000000000001\r\n",
                     b"AGENTOS PIPE SENT PID=0000000000000001\r\n")
            for marker in markers:
                for bad in (marker+log,log.replace(prefix,prefix+marker,1)):
                    with self.assertRaises(session.VerificationError):
                        session.verify(bad,serial,True,1,aRuntimeProcess=True,aSupervisorImage=variant)
            for bad,bad_input in ((log,serial[1:]),(log.replace(b"FRAMES=OK",b"FRAMES=LEAK"),serial),
                                  (log.replace(b"VECTOR=000000000000000e",b"VECTOR=000000000000000d"),serial),
                                  (log.replace(b"TIMERS=0000000000000005",b"TIMERS=0000000000000100"),serial)):
                with self.assertRaises(session.VerificationError):
                    session.verify(bad,bad_input,True,1,aRuntimeProcess=True,aSupervisorImage=variant)
            with self.assertRaises(session.VerificationError):
                session.verify(log,serial,True,1,aRuntimeProcess=True,
                               aSupervisorImage="test" if variant=="control" else "control")
            with self.assertRaises(session.VerificationError):
                session.verify(log,serial,True,1,aRuntimeProcess=True)
            if variant=="test":
                with self.assertRaises(session.VerificationError):
                    session.verify(log.replace(supervisor_transcript(runner=40,pipe=True),b"",1),
                                   serial,True,1,aRuntimeProcess=True,aSupervisorImage=variant)
                with self.assertRaises(session.VerificationError):
                    session.verify(log.replace(b"PID=0000000000000033 CR3=",b"PID=0000000000000014 CR3="),
                                   serial,True,1,aRuntimeProcess=True,aSupervisorImage=variant)

    def test_pipe_full_locality_and_receiver_evidence(self):
        for apics in ((7,),(7,19)):
            data=supervisor_transcript(apics=apics,pipe=True)
            def check(value):
                return session.supervisor_prefix(value,9,0x300000,{1,2,9},"test",set(apics),pipe=True)
            offset,receipt,_=check(data)
            self.assertEqual(offset,len(data))
            self.assertEqual(receipt["covered_apics"],list(apics))
            for interval in receipt["intervals"]:
                self.assertEqual(interval["bytes"],8193)
                self.assertEqual(interval["fnv32"],0x1490a95f)
                self.assertEqual(interval["eof_reads"],2)
                self.assertEqual(interval["partial_writes"],1)
                self.assertEqual(interval["child_statuses"],[0])
            lines=data.splitlines(keepends=True)
            for i in range(len(lines)):
                with self.subTest(apics=apics,line=i),self.assertRaises(session.VerificationError):
                    check(b"".join(lines[:i]+lines[i+1:]))
            for old,new in ((b"FNV32=1490a95f",b"FNV32=1490a950"),
                            (b"BYTES=00002001",b"BYTES=00002000"),
                            (b"EOF=00000002",b"EOF=00000001"),
                            (b"DUP=000000000000000b",b"DUP=0000000000000000"),
                            (b"SHORT=0000000000000001",b"SHORT=0000000000000000"),
                            (b"CR3=0000000000600000",b"CR3=0000000000500000")):
                with self.subTest(old=old),self.assertRaises(session.VerificationError):
                    check(data.replace(old,new,1))
        data=supervisor_transcript(apics=(7,19),pipe=True,moving=True)
        _,receipt,_=session.supervisor_prefix(data,9,0x300000,{1,2,9},"test",{7,19},pipe=True)
        self.assertTrue(any(r["reason"]=="migration" for r in receipt["rejected"]))

    def test_two_cpu_roster_and_rejected_complete_attempts(self):
        for flags in ({},{"moving":True},{"skipping":True},{"peer_moving":True},{"peer_missed":True},{"peer_unpaired":True}):
            data=supervisor_transcript(apics=(7,19),**flags)
            offset,result,seen=self.verify(data,apics=(7,19))
            self.assertEqual(offset,len(data))
            self.assertEqual(result["covered_apics"],[7,19])
            self.assertEqual(len(result["intervals"]),2)
            self.assertEqual(len(result["rejected"]),int(bool(flags)))
            for interval in result["intervals"]:
                self.assertEqual(interval["child_statuses"],[0,42,42,42,137])
                self.assertNotEqual(interval["peer"]["apic"],interval["apic"])
                self.assertGreater(interval["peer"]["after"]["work"],0)
                for field in ("apic","moves","total"):
                    self.assertEqual(interval["before"][field],interval["after"][field])
            self.assertEqual(len(seen),len(set(seen)))

    def test_peer_first_reselects_after_wake_and_retains_unpaired_candidates(self):
        import re
        for pipe in (False,True):
            def check(data):
                return session.supervisor_prefix(data,9,0x300000,{1,2,9},"test",{7,19},pipe=pipe)
            data=supervisor_transcript(apics=(7,19),peer_missed=True,pipe=pipe)
            _,result,_=check(data)
            first=result["intervals"][0]
            self.assertEqual(first["pid"],24)
            self.assertEqual(first["apic"],19)
            self.assertEqual(first["peer"]["pid"],22)
            self.assertEqual(first["peer"]["ready"]["apic"],19)
            self.assertEqual(first["peer"]["before"]["apic"],7)
            self.assertEqual(first["peer"]["after"]["apic"],7)
            self.assertEqual(first["peer"]["before"]["moves"],1)
            self.assertEqual(first["peer"]["after"]["moves"],1)
            self.assertEqual(result["covered_apics"],[7,19])
            lines=data.splitlines(keepends=True)
            activate=next(l for l in lines if l.startswith(b"AGENTOS TEST PEER_ACTIVATE "))
            start=next(l for l in lines if l.startswith(b"AGENTOS TEST PEER_BEGIN "))
            pair=next(l for l in lines if l.startswith(b"AGENTOS TEST PAIR "))
            self.assertLess(lines.index(activate),lines.index(start))
            self.assertLess(lines.index(start),lines.index(pair))
            for bad in (
                data.replace(start,re.sub(rb"MS=[0-9a-f]{16}",b"MS=0000000000000000",start),1),
                data.replace(start,start.replace(b"MOVES=0000000000000001",b"MOVES=0000000000000000"),1),
                data.replace(start,start.replace(b"APIC=0000000000000007",b"APIC=0000000000000013"),1),
                data.replace(pair,pair.replace(b"PID=0000000000000018",b"PID=0000000000000015"),1),
                data.replace(activate,activate.replace(b"PEER=0000000000000016",b"PEER=0000000000000015"),1),
                data.replace(start+pair,pair+start,1),
                data.replace(pair,b"AGENTOS TEST UNPAIRED ROOT=0000000000000014 PEER=0000000000000016\r\n",1),
            ):
                self.assertNotEqual(bad,data)
                with self.assertRaises(session.VerificationError):
                    check(bad)
            data=supervisor_transcript(apics=(7,19),peer_unpaired=True,pipe=pipe)
            _,result,_=check(data)
            self.assertEqual(result["covered_apics"],[7,19])
            misses=[r for r in result["rejected"] if r["reason"]=="peer-unpaired"]
            self.assertEqual(len(misses),1)
            peer=misses[0]["peer"]["pid"]
            self.assertEqual(peer,23)
            unpaired=next(l for l in data.splitlines(keepends=True) if l.startswith(b"AGENTOS TEST UNPAIRED "))
            peer_end=data.index(b"AGENTOS TEST PEER_END ",data.index(unpaired))
            # Candidate 24 is not spent on a stale pair. Its only SELECT
            # follows the peer's full work/stop/collection.
            remaining=b"AGENTOS TEST SELECT ROOT=0000000000000014 PID=0000000000000018"
            self.assertGreater(data.index(remaining),peer_end)
            self.assertEqual(data.count(remaining),1)
            for bad in (data.replace(unpaired,b"",1),
                        data.replace(unpaired,unpaired.replace(b"PEER=0000000000000017",b"PEER=0000000000000018"),1)):
                self.assertNotEqual(bad,data)
                with self.assertRaises(session.VerificationError):
                    check(bad)

    def test_wait_probe_requires_authentic_bounded_transitions(self):
        import re
        for pipe in (False,True):
            data=supervisor_transcript(apics=(7,19),peer_missed=True,pipe=pipe)
            def check(log):
                return session.supervisor_prefix(log,9,0x300000,{1,2,9},"test",{7,19},pipe=pipe)
            offset,result,_=check(data)
            self.assertEqual(offset,len(data))
            self.assertEqual(result["covered_apics"],[7,19])
            transitions=result["wait_transitions"]
            first=transitions[0]
            self.assertEqual(first["entry"]["apic"],19)
            self.assertEqual(first["return"]["apic"],7)
            self.assertEqual(first["return"]["moves"],1)
            lines=data.splitlines(keepends=True)
            selected={kind:next(l for l in lines if l.startswith(b"AGENTOS TEST "+kind+b" "))
                      for kind in (b"WAIT_SEND",b"WAIT_ENTER",b"WAIT_RETURN",b"WAIT_RECEIVED",b"WAIT_RESULT")}
            for line in selected.values():
                with self.assertRaises(session.VerificationError):
                    check(data.replace(line,b"",1))
                with self.assertRaises(session.VerificationError):
                    check(data.replace(line,line+line,1))
            for kind,old,new in (
                (b"WAIT_SEND",b"TARGET=0000000000000016",b"TARGET=0000000000000015"),
                (b"WAIT_RETURN",b"MOVES=0000000000000001",b"MOVES=0000000000000000"),
                (b"WAIT_RECEIVED",b"MOVES=0000000000000001",b"MOVES=0000000000000000"),
                (b"WAIT_RESULT",b"BYTES=0000000000000018",b"BYTES=0000000000000000"),
                (b"WAIT_RESULT",b"MODE=0000000000000002",b"MODE=0000000000000001"),
                (b"WAIT_RESULT",b"EVENTS=0000000000000000",b"EVENTS=0000000000000004"),
            ):
                line=selected[kind]
                bad=line.replace(old,new,1)
                self.assertNotEqual(line,bad)
                with self.assertRaises(session.VerificationError):
                    check(data.replace(line,bad,1))
            for polls in (b"0000000000000000",b"00000000001e8481"):
                line=selected[b"WAIT_RESULT"]
                with self.assertRaises(session.VerificationError):
                    check(data.replace(line,re.sub(rb"POLLS=[0-9a-f]{16}",b"POLLS="+polls,line),1))
            for kind in (b"WAIT_ENTER",b"WAIT_RETURN",b"WAIT_RECEIVED"):
                line=selected[kind]
                with self.assertRaises(session.VerificationError):
                    check(data.replace(line,re.sub(rb"MS=[0-9a-f]{16}",b"MS=0000000000000000",line),1))
            # There is no ordinary staged mode that may omit the wait proof
            # or silently fall back to the blocked control experiment.
            for mode in (None,"blocked"):
                with self.assertRaises(session.VerificationError):
                    check(supervisor_transcript(apics=(7,19),peer_missed=True,pipe=pipe,probe=mode))

    def test_reject_fake_locality_duplicate_cpu_pid_incomplete_and_replay(self):
        data=supervisor_transcript(apics=(7,19))
        lines=data.splitlines(keepends=True)
        end=next(l for l in lines if l.startswith(b"AGENTOS TEST ENDED "))
        begin=next(l for l in lines if l.startswith(b"AGENTOS TEST BEGIN "))
        for bad in (
            data.replace(end,end.replace(b"TOTAL=0000000000000004",b"TOTAL=0000000000000005"),1),
            data.replace(end,end.replace(b"MOVES=0000000000000000",b"MOVES=0000000000000001"),1),
            data.replace(b"APIC=0000000000000013",b"APIC=0000000000000007"),
            data.replace(b"PID=0000000000000016",b"PID=0000000000000015",1),
            data.replace(begin,begin+begin,1),
            data.replace(end,b"",1),
            data.replace(b"ROUND=0000000000000001",b"ROUND=0000000000000002",1),
            supervisor_transcript(apics=(7,19),moving=True).replace(b"STATUS=000000000000004c",b"STATUS=0000000000000000",1),
        ):
            with self.assertRaises(session.VerificationError):
                self.verify(bad,apics=(7,19))
        with self.assertRaises(session.VerificationError):
            self.verify(data,apics=(7,23))

    def test_peer_identity_work_time_stop_and_replay(self):
        import re
        data=supervisor_transcript(apics=(7,19))
        lines=data.splitlines(keepends=True)
        start=next(l for l in lines if l.startswith(b"AGENTOS TEST PEER_BEGIN "))
        end=next(l for l in lines if l.startswith(b"AGENTOS TEST PEER_END "))
        pair=next(l for l in lines if l.startswith(b"AGENTOS TEST PAIR "))
        for bad in (
            data.replace(start,b"",1),data.replace(end,b"",1),
            data.replace(start,start+start,1),
            data.replace(pair,pair.replace(b"PEER=0000000000000016",b"PEER=0000000000000015"),1),
            data.replace(start,start.replace(b"PARENT=0000000000000014",b"PARENT=0000000000000009"),1),
            data.replace(end,end.replace(b"PID=0000000000000016",b"PID=0000000000000015"),1),
            data.replace(end,end.replace(b"WORK=00000000000000c8",b"WORK=0000000000000000"),1),
            data.replace(end,end.replace(b"WORK=00000000000000c8",b"WORK=00000000001e8481"),1),
            data.replace(end,re.sub(rb"MS=[0-9a-f]{16}",b"MS=0000000000000000",end),1),
            data.replace(end,end.replace(b"APIC=0000000000000013",b"APIC=0000000000000007"),1),
            data.replace(end,end.replace(b"MOVES=0000000000000000",b"MOVES=0000000000000001"),1),
        ):
            self.assertNotEqual(bad,data)
            with self.assertRaises(session.VerificationError):
                self.verify(bad,apics=(7,19))
        for i in range(len(lines)):
            with self.subTest(line=i), self.assertRaises(session.VerificationError):
                self.verify(b"".join(lines[:i]+lines[i+1:]),apics=(7,19))
        # Even a complete prior idle-peer transcript or early peer exit is
        # not a substitute for the new continuously runnable peer bracket.

    def test_old_supervisor_interval_checks_still_apply(self):
        phase="\n".join(supervisor_phase(20,21))+"\n"
        phase+="AGENTOS PROCESS OK APIC=0000000000000000 PARENT=0000000000000014\n"
        self.assertEqual(supervisor.verify(phase,1),1)
        with self.assertRaises(supervisor.VerificationError):
            supervisor.verify(phase.replace("MS=00000000000000fa","MS=00000000000000f9"),1)


if __name__=="__main__":
    unittest.main()
