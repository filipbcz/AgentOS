import importlib.util
from pathlib import Path
import struct
import unittest

spec=importlib.util.spec_from_file_location("oom",Path(__file__).with_name("verify-oom-workload.py"))
oom=importlib.util.module_from_spec(spec)
spec.loader.exec_module(oom)
BASE=0x8000402000
LAYOUT={"base":BASE,"end":BASE+oom.SIZE,"pages":oom.PAGES,"file_bytes":8192}

def elf_fixture():
    data=bytearray(8192)
    struct.pack_into("<16sHHIQQQIHHHHHH",data,0,b"\x7fELF\x02\x01\x01",2,62,1,
                     BASE-4096,64,512,0,64,56,2,64,3,2)
    struct.pack_into("<IIQQQQQQ",data,64,1,5,4096,BASE-4096,0,4096,4096,4096)
    struct.pack_into("<IIQQQQQQ",data,120,1,6,0,BASE,0,0,oom.SIZE,4096)
    names=b"\0.bss\0.shstrtab\0"
    struct.pack_into("<IIQQQQIIQQ",data,576,1,8,3,BASE,8192,oom.SIZE,0,0,4096,0)
    struct.pack_into("<IIQQQQIIQQ",data,640,6,3,0,1024,len(names),len(names),0,0,1,0)
    # shstrtab has a zero virtual address, file offset 1024.
    struct.pack_into("<QQQ",data,656,0,1024,len(names))
    data[1024:1024+len(names)]=names
    return bytes(data)

def transcript(root=97,shell=9,apic=7,cpus=1):
    s,c=root+1,root+2
    cr3,sc,rc=0x7a2000,0x7a1000,0x7a0000
    rows=[oom.COMMAND.encode("ascii")]
    def record(prefix,**values):
        rows.append(prefix+b"".join(b" "+k.encode("ascii")+b"="+f"{v&oom.MASK:016x}".encode("ascii")
                                    for k,v in values.items()))
    def test(kind,**values):
        record(oom.MARKER+kind.encode("ascii"),**values)
    def sent(pid):
        return {"VALUE":oom.KEEP^pid,"INVERSE":(oom.KEEP^pid)^oom.MASK}
    test("ROOT",PID=root,PARENT=shell,APIC=apic,CPUS=cpus,**sent(root),MS=1000)
    test("SURVIVOR_BEFORE",PID=s,PARENT=root,APIC=apic,CPUS=cpus,**sent(s))
    test("RESERVE",PID=c,PARENT=root,APIC=apic,CPUS=cpus,BASE=BASE,END=BASE+oom.SIZE,
         RESERVED=oom.PAGES+5,RESIDENT=3,DEMAND=3)
    test("WAIT",PID=root,SURVIVOR=s,CHILD=c,START=1100,GO=1350,UNTIL=21000,TRY=-11,**sent(root))
    test("BEGIN",PID=c,MS=1351)
    for i in range(1,12):
        pages=i*oom.STEP
        test("PROGRESS",PID=c,PAGES=pages,RESIDENT=pages+3,DEMAND=pages+3,MS=1351+10*i)
    address=BASE+(11*oom.STEP+123)*oom.PAGE
    record(oom.OOM,PID=c,ADDRESS=address)
    record(b"AGENTOS USER FAULT",PID=c,PARENT=root,CR3=cr3,VECTOR=14,ERROR=6,ADDRESS=address)
    test("COLLECT",PID=root,CHILD=c,STATUS=270,AGAIN=-10,END=1500,**sent(root))
    test("SURVIVOR_AFTER",PID=s,PARENT=root,APIC=apic,CPUS=cpus,**sent(s))
    record(b"AGENTOS USER EXIT",PID=s,CR3=sc,STATUS=0)
    test("SURVIVOR_COLLECT",PID=root,CHILD=s,STATUS=0,AGAIN=-10,EMPTY=-10)
    test("RECOVERY_1",PID=root,BASE=0x8000410000,PAGES=16,BEFORE=5,AFTER=21,
         DEMAND_BEFORE=5,DEMAND_AFTER=21)
    test("RECOVERY_2",PID=root,SUM=136,**sent(root),MS=1501)
    record(b"AGENTOS USER EXIT",PID=root,CR3=rc,STATUS=0)
    return b"\r\n".join(rows)+b"\r\nexit status 0\r\nagentos> "

class OomTests(unittest.TestCase):
    def verify(self,data,variant="test",prior=(),cpus=1):
        return oom.verify_prefix(data,9,0x300000,prior,variant,set(range(7,7+cpus)),LAYOUT)

    def test_elf_nobits(self):
        data=elf_fixture()
        self.assertEqual(oom.verify_layout(data),LAYOUT)
        for offset,value,size in [(124,5,4),(152,1,8),(160,4096,8),(580,1,4),(608,4096,8),(624,1,8)]:
            with self.subTest(offset=offset):
                bad=bytearray(data)
                bad[offset:offset+size]=value.to_bytes(size,"little")
                with self.assertRaises(oom.VerificationError):
                    oom.verify_layout(bad)
        with self.assertRaises(oom.VerificationError):
            oom.verify_layout(data+b"\0"*65536)

    def test_real_interval_contract(self):
        for cpus in (1,2):
            data=transcript(cpus=cpus)
            consumed,result,pids=self.verify(data,cpus=cpus)
            self.assertEqual(consumed,len(data))
            self.assertEqual(pids,{97,98,99})
            self.assertEqual(result["fault_page_index"],11*oom.STEP+123)
            self.assertEqual(result["recovery"]["resident_after"],21)

    def test_missing_duplicate_records(self):
        data=transcript()
        lines=data.splitlines(keepends=True)
        for i,line in enumerate(lines):
            if line.startswith((oom.MARKER,oom.OOM,b"AGENTOS USER ")):
                for replacement in (b"",line+line):
                    with self.subTest(line=line,replacement=replacement):
                        bad=b"".join(lines[:i])+replacement+b"".join(lines[i+1:])
                        with self.assertRaises(oom.VerificationError):
                            self.verify(bad)

    def test_bad_fields(self):
        data=transcript()
        for prefix,field,value in [
            (b"ROOT",b"PARENT",1),(b"ROOT",b"VALUE",0),(b"SURVIVOR_BEFORE",b"PID",97),
            (b"RESERVE",b"BASE",BASE-4096),(b"RESERVE",b"RESIDENT",81920),
            (b"WAIT",b"TRY",0),(b"WAIT",b"UNTIL",21001),(b"BEGIN",b"MS",1),
            (b"PROGRESS",b"RESIDENT",3),(b"PROGRESS",b"DEMAND",0),
            (b"COLLECT",b"STATUS",0),(b"COLLECT",b"AGAIN",0),
            (b"SURVIVOR_AFTER",b"INVERSE",0),(b"SURVIVOR_COLLECT",b"EMPTY",0),
            (b"RECOVERY_1",b"PID",98),(b"RECOVERY_1",b"BASE",BASE+1),
            (b"RECOVERY_1",b"PAGES",15),(b"RECOVERY_1",b"BEFORE",0),
            (b"RECOVERY_1",b"AFTER",5),(b"RECOVERY_1",b"DEMAND_BEFORE",4),
            (b"RECOVERY_1",b"DEMAND_AFTER",20),
            (b"RECOVERY_2",b"PID",98),(b"RECOVERY_2",b"SUM",0),
            (b"RECOVERY_2",b"VALUE",0),(b"RECOVERY_2",b"INVERSE",0),
            (b"RECOVERY_2",b"MS",1499),(b"RECOVERY_2",b"MS",21001),
            (oom.OOM,b"PID",98),(oom.OOM,b"ADDRESS",BASE+oom.SIZE),
            (b"AGENTOS USER FAULT",b"ERROR",4),(b"AGENTOS USER FAULT",b"ADDRESS",BASE),
            (b"AGENTOS USER FAULT",b"PARENT",1),(b"AGENTOS USER FAULT",b"CR3",0x300000)
        ]:
            import re
            start=prefix if prefix.startswith(b"AGENTOS ") else oom.MARKER+prefix
            pattern=rb"(?m)^("+re.escape(start)+rb" [^\r\n]*?\b"+field+rb"=)[0-9a-f]{16}"
            bad,n=re.subn(pattern,lambda m:m[1]+f"{value:016x}".encode("ascii"),data,count=1)
            self.assertEqual(n,1)
            with self.subTest(prefix=prefix,field=field),self.assertRaises(oom.VerificationError):
                self.verify(bad)
        with self.assertRaises(oom.VerificationError):
            self.verify(data,prior={97})

    def test_recovery_record_boundaries(self):
        data=transcript()
        first=next(row for row in data.splitlines(keepends=True) if row.startswith(oom.MARKER+b"RECOVERY_1 "))
        second=next(row for row in data.splitlines(keepends=True) if row.startswith(oom.MARKER+b"RECOVERY_2 "))
        import re
        # Every value has the full 16-digit width, even at U64_MAX.
        for row,expected in ((first,203),(second,139)):
            widest=re.sub(rb"=[0-9a-f]{16}",b"=ffffffffffffffff",row)
            self.assertTrue(widest.endswith(b"\r\n"))
            self.assertEqual(len(row),len(widest))
            self.assertEqual(len(widest),expected)
            self.assertLessEqual(len(widest),256)
        pair=first+second
        self.assertEqual(data.count(pair),1)
        foreign=second.replace(b"PID=0000000000000061",b"PID=0000000000000062",1)
        self.assertNotEqual(foreign,second)
        # Missing/duplicate records also covered generically above. Explicitly
        # reject reordered, interleaved, old-format, foreign and partial reports.
        for bad in (first,second,first+second+second,second+first,first+foreign,
                    first+b"unexpected\r\n"+second,
                    first+second[:-3]+b"\r\n",first+second[:-2],
                    first+second+b"unexpected\r\n",
                    first.replace(b"RECOVERY_1",b"RECOVERY",1).rstrip(b"\r\n")+
                    b" SUM="+second.split(b" SUM=",1)[1]):
            with self.subTest(bad=bad),self.assertRaises(oom.VerificationError):
                self.verify(data.replace(pair,bad,1))

    def test_control_only(self):
        data=oom.COMMAND.encode()+b"\r\n"+oom.MISSING
        self.assertEqual(self.verify(data,"control"),(len(data),{"absent":True},set()))
        with self.assertRaises(oom.VerificationError):
            self.verify(data)
        with self.assertRaises(oom.VerificationError):
            self.verify(transcript(),"control")

if __name__=="__main__":
    unittest.main()
