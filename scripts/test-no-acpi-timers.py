"""Negative fixtures for the independent QEMU platform evidence parser.
These tests do not replace a guest boot or a QMP capture."""
import binascii
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("no_acpi",Path(__file__).with_name("qemu-no-acpi-timers.py"))
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def put(data,offset,value,width):
    data[offset:offset+width]=value.to_bytes(width,"little")


def checksum(data,offset=9):
    data[offset]=0
    data[offset]=(-sum(data))&255


def sdt(signature,size):
    data=bytearray(size)
    data[:4]=signature
    put(data,4,size,4)
    data[8]=3
    checksum(data)
    return data


class Memory:
    def __init__(self):
        self.st=0x1000
        self.cfg=0x2000
        self.rsdp=0x3000
        self.xsdt=0x4000
        self.fadt=0x5000
        self.madt=0x6000
        self.hpet=0x7000
        self.mem={}
        st=bytearray(120)
        st[:8]=b"IBI SYST"
        put(st,12,120,4)
        put(st,104,1,8)
        put(st,112,self.cfg,8)
        self.mem[self.st]=st
        self.fix_st()
        self.mem[self.cfg]=bytearray(mod.ACPI20+self.rsdp.to_bytes(8,"little"))
        root=bytearray(36)
        root[:8]=b"RSD PTR "
        root[15]=2
        put(root,20,36,4)
        put(root,24,self.xsdt,8)
        root[8]=(-sum(root[:20]))&255
        checksum(root,32)
        self.mem[self.rsdp]=root
        self.set_children(self.fadt,self.madt)
        self.mem[self.fadt]=sdt(b"FACP",244)
        madt=sdt(b"APIC",60)
        put(madt,40,1,4)
        madt[44:52]=bytes([0,8,0,2,1,0,0,0])
        madt[52:60]=bytes([0,8,1,7,1,0,0,0])
        checksum(madt)
        self.mem[self.madt]=madt
        self.mem[self.hpet]=sdt(b"HPET",56)

    def fix_st(self):
        st=self.mem[self.st]
        put(st,16,0,4)
        put(st,16,binascii.crc32(st)&0xffffffff,4)

    def set_children(self,*children):
        root=sdt(b"XSDT",36+8*len(children))
        for i,child in enumerate(children):
            put(root,36+i*8,child,8)
        checksum(root)
        self.mem[self.xsdt]=root

    def read(self,addr,size):
        if addr not in self.mem or len(self.mem[addr])<size:
            raise RuntimeError("Out-of-range fixture read")
        return bytes(self.mem[addr][:size])

    def inspect(self):
        return mod.inspect_tables(self.read,self.st,self.rsdp,0,2)


class EvidenceTests(unittest.TestCase):
    def test_actual_valid_tables_require_two_enabled_cpus(self):
        m=Memory()
        result=m.inspect()
        self.assertEqual(result["roots"][0]["enabled_apic_ids"],[2,7])
        self.assertEqual(result["roots"][0]["fadt_x_pm_tmr_blk"],"0"*24)

    def test_legacy_pm_or_extended_gas_is_not_absence(self):
        for offset,value,width in [(76,0x608,4),(91,4,1),(212,0x608,8),(209,32,1)]:
            with self.subTest(offset=offset):
                m=Memory()
                fadt=m.mem[m.fadt]
                put(fadt,offset,value,width)
                checksum(fadt)
                with self.assertRaisesRegex(RuntimeError,"PM timer"):
                    m.inspect()

    def test_hpet_or_duplicate_fadt_cannot_pass(self):
        m=Memory()
        m.set_children(m.fadt,m.madt,m.hpet)
        with self.assertRaisesRegex(RuntimeError,"HPET"):
            m.inspect()
        m.set_children(m.fadt,m.madt,m.fadt)
        with self.assertRaisesRegex(RuntimeError,"Duplicate"):
            m.inspect()

    def test_real_efi_pointer_and_checksums_are_mandatory(self):
        m=Memory()
        put(m.mem[m.cfg],16,0x8000,8)
        with self.assertRaisesRegex(RuntimeError,"EFI ACPI pointers"):
            m.inspect()
        m=Memory()
        m.mem[m.fadt][76]=1
        with self.assertRaisesRegex(RuntimeError,"checksum"):
            m.inspect()
        m=Memory()
        m.mem[m.st][24]=1
        with self.assertRaisesRegex(RuntimeError,"checksum"):
            m.inspect()

    def test_pre_ebs_or_disabled_cpu_is_not_full_proof(self):
        m=Memory()
        put(m.mem[m.st],96,0x9000,8)
        m.fix_st()
        with self.assertRaisesRegex(RuntimeError,"BootServices"):
            m.inspect()
        m=Memory()
        m.mem[m.madt][56]=0
        checksum(m.mem[m.madt])
        with self.assertRaisesRegex(RuntimeError,"CPU roster"):
            m.inspect()

    def test_pm_io_read_requires_exact_port_width_and_all_ones(self):
        mod.verify_pm_read("portl[0x0608] = 0xffffffff\r\n",0x608)
        for reply in ("invalid char in format: 'l'", "portb[0x0608] = 0xff",
                      "portl[0x0609] = 0xffffffff", "portl[0x0608] = 0x00ffffff",
                      "unexpected\nportl[0x0608] = 0xffffffff"):
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                mod.verify_pm_read(reply,0x608)

    def test_chain_control_requires_declared_pm(self):
        m=Memory()
        with self.assertRaisesRegex(RuntimeError,"declared PM"):
            mod.inspect_tables(m.read,m.st,m.rsdp,0,2,0x608)
        fadt=m.mem[m.fadt]
        put(fadt,76,0x608,4)
        fadt[91]=4
        checksum(fadt)
        result=mod.inspect_tables(m.read,m.st,m.rsdp,0,2,0x608)
        self.assertEqual(result["roots"][0]["fadt_pm_tmr_blk"],0x608)
        with self.assertRaisesRegex(RuntimeError,"Legacy PM timer"):
            m.inspect()
        self.assertEqual(mod.verify_pm_read("portl[0x0608] = 0x00000abc",0x608,False),0xabc)
        with self.assertRaises(RuntimeError):
            mod.verify_pm_read("portl[0x0608] = 0xffffffff",0x608,False)

    def test_normal_idle_budget_is_unchanged(self):
        session=mod.smoke.session
        def idle(timers):
            return (f"AGENTOS RUNTIME IDLE MS={5000:016x} TIMERS={timers:016x} "
                    f"IDLE={timers:016x}\r\n").encode()
        self.assertEqual(session.verify_idle(idle(14),2)["timer_irqs"],14)
        with self.assertRaises(session.VerificationError):
            session.verify_idle(idle(15),2)
        self.assertEqual(session.verify_idle(idle(509),2,10)["timer_irqs"],509)
        with self.assertRaises(session.VerificationError):
            session.verify_idle(idle(510),2,10)


if __name__=="__main__":
    unittest.main()
