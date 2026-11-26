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
        self.entries=[(n,n.encode()) for n in ("init","shell","svc_ok","svc_fail","svc_hang","fault")]
        self.control=archive(self.entries)
        self.runner=b"isolated test fixture"
        self.staged=archive([*self.entries,(images.RUNNER,self.runner)])
        self.kernel=b"kernel fixture"

    def check(self, control, staged, runner=None):
        a=pe(self.kernel,control)
        b=pe(self.kernel,staged)
        return images.verify_contents(images.signed_payload(a,fake_certificate(a)),
            images.signed_payload(b,fake_certificate(b)),self.kernel,control,staged,
            self.runner if runner is None else runner)

    def test_exact_archive_addition(self):
        result=self.check(self.control,self.staged)
        self.assertEqual(set(result),{name for name,_ in self.entries})
        self.assertNotIn(images.RUNNER,result)

    def test_missing_extra_changed_runner_or_common_entry(self):
        for a,b in ((self.staged,self.staged),(self.control,self.control),
                    (self.control,archive([*self.entries,(images.RUNNER,self.runner),("extra",b"x")])),
                    (self.control,archive([("init",b"changed"),*self.entries[1:],(images.RUNNER,self.runner)])),
                    (self.control,archive([*self.entries[1:],(images.RUNNER,self.runner)]))):
            with self.subTest(a=len(a),b=len(b)), self.assertRaises(images.VerificationError):
                self.check(a,b)
        with self.assertRaises(images.VerificationError):
            self.check(self.control,self.staged,b"wrong runner")

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


def supervisor_transcript(shell=9,runner=20):
    records=[session.SUPERVISOR_COMMAND,
             f"AGENTOS TEST RUNNER PID={runner:016x} PARENT={shell:016x}",
             f"AGENTOS SUPERVISOR BEGIN PARENT={runner:016x}"]
    def exit_line(pid,status,cr3=0x600000):
        records.append(f"AGENTOS USER EXIT PID={pid:016x} CR3={cr3:016x} STATUS={status:016x}")
    def event(name,pid,status,attempt):
        records.append(f"AGENTOS SERVICE {name} PARENT={runner:016x} CHILD={pid:016x} "
                       f"STATUS={status:016x} ATTEMPT={attempt:08x}")
    exit_line(runner+1,0)
    event("DONE",runner+1,0,1)
    for attempt in range(1,4):
        exit_line(runner+1+attempt,42)
        event("REAP",runner+1+attempt,42,attempt)
    event("STOP",runner+4,42,3)
    records.append(f"AGENTOS USER KILL PID={runner+5:016x} PARENT={runner:016x} STATUS={137:016x}")
    records.append(f"AGENTOS SERVICE DURATION PARENT={runner:016x} CHILD={runner+5:016x} MS={250:016x}")
    event("TIME",runner+5,137,1)
    event("STOP",runner+5,137,1)
    records.append(f"AGENTOS SUPERVISOR ENDED PARENT={runner:016x}")
    exit_line(runner,0,0x500000)
    records.append("exit status 0")
    return ("\r\n".join(records)+"\r\nagentos> ").encode("ascii")


class RuntimeTests(unittest.TestCase):
    def verify(self,data,variant="test",prior=None):
        return session.supervisor_prefix(data,9,0x300000,{1,2,9} if prior is None else prior,variant)

    def test_real_event_contract(self):
        data=supervisor_transcript()
        offset,receipt,seen=self.verify(data)
        self.assertEqual(offset,len(data))
        self.assertEqual(receipt["child_statuses"],[0,42,42,42,137])
        self.assertEqual(receipt["runner_pid"],20)
        self.assertEqual(receipt["shell_pid"],9)
        self.assertEqual(seen,set(range(20,26)))
        self.assertEqual(receipt["duration_ms"],250)

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
        base=fixture.transcript(True)
        for old,new in ((10,30),(11,31),(12,32),(13,33)):
            base=base.replace(f"PID={old:016x}".encode(),f"PID={new:016x}".encode())
        fg=(b"run /svc_ok\r\n"
            b"AGENTOS USER EXIT PID=0000000000000010 CR3=0000000000500000 STATUS=0000000000000000\r\n"
            b"exit status 0\r\nagentos> run /svc_fail\r\n"
            b"AGENTOS USER EXIT PID=0000000000000011 CR3=0000000000500000 STATUS=000000000000002a\r\n"
            b"exit status 42\r\nagentos> run /fault\r\n"
            b"AGENTOS USER FAULT PID=0000000000000012 PARENT=0000000000000009 CR3=0000000000500000 VECTOR=000000000000000e ERROR=0000000000000005 ADDRESS=0000000002000000\r\n"
            b"exit status 270\r\nagentos> ")
        serial=session.runtime_input()+session.SUPERVISOR_INPUT+session.transmitted_input(9,True)
        for variant,prefix in (("control",(session.SUPERVISOR_COMMAND+"\r\n").encode()+session.SUPERVISOR_MISSING),
                               ("test",supervisor_transcript())):
            log=base.replace(session.READY,session.READY+fg+prefix,1)
            result=session.verify(log,serial,True,1,aRuntimeProcess=True,aSupervisorImage=variant)
            self.assertEqual([r["status"] for r in result["runtime_process_regression"]],[0,42,270])
            self.assertEqual(result["restarted_pids"],[31,32,33])
            self.assertEqual(result["runtime_supervisor"]["absent"],variant=="control")
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
                    session.verify(log.replace(b"PID=000000000000001f CR3=",b"PID=0000000000000014 CR3="),
                                   serial,True,1,aRuntimeProcess=True,aSupervisorImage=variant)

    def test_old_supervisor_interval_checks_still_apply(self):
        text=supervisor_transcript().decode("ascii").splitlines()
        phase="\n".join(text[2:-3])+"\n"
        phase+="AGENTOS PROCESS OK APIC=0000000000000000 PARENT=0000000000000014\n"
        self.assertEqual(supervisor.verify(phase,1),1)
        with self.assertRaises(supervisor.VerificationError):
            supervisor.verify(phase.replace("MS=00000000000000fa","MS=00000000000000f9"),1)


if __name__=="__main__":
    unittest.main()
