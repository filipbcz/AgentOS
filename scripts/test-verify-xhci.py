"""Synthetic negative fixtures for the strict xHCI evidence verifier."""
import unittest
import xhci_evidence as x


def fixture():
    base=0x100000
    port=3
    guest=[f"AGENTOS XHCI READY VERSION=0100 PORTS=4 SLOTS=8 CMD={base:016x} EVENT=0000000000101000 RING=16",
           "AGENTOS XHCI PORT EVENT ID=3 STATUS=00020e01",
           "AGENTOS XHCI PORT EVENT ID=3 STATUS=00200e03",
           "AGENTOS XHCI PORT RESET ID=3 USB=2 SPEED=3 STATUS=00200e03"]
    trace=[]
    def event(n,kind,pointer,slot):
        trace.append(f"usb_xhci_queue_event v 0, idx {n%16}, "
                     f"{'ER_COMMAND_COMPLETE' if kind==33 else 'ER_PORT_STATUS_CHANGE'}, CC_SUCCESS, "
                     f"p 0x{pointer:016x}, s 0x01000000, c 0x{(slot<<24)|(kind<<10)|int(n//16%2==0):08x}")
    event(0,34,port<<24,0)
    trace.append("usb_xhci_port_reset port 3, warm 0")
    event(1,34,port<<24,0)
    for i in range(42):
        kind=9 if i==0 else 10 if i==41 else 23
        slot=1 if kind in (9,10) else 0
        ptr=base+16*(i%15)
        cycle=int(i//15%2==0)
        if i and i%15==0:
            trace.append(f"usb_xhci_fetch_trb addr 0x{base+240:016x}, TR_LINK, p 0x{base:016x}, s 0x00000000, c 0x{(6<<10)|2|(1-cycle):08x}")
        trace.append(f"usb_xhci_fetch_trb addr 0x{ptr:016x}, { {9:'CR_ENABLE_SLOT',10:'CR_DISABLE_SLOT',23:'CR_NOOP'}[kind] }, p 0x0000000000000000, s 0x00000000, c 0x{(kind<<10)|cycle|((slot<<24) if kind==10 else 0):08x}")
        if kind==9:trace.append("usb_xhci_slot_enable slotid 1")
        if kind==10:trace.append("usb_xhci_slot_disable slotid 1")
        event(i+2,33,ptr,slot)
        guest.append(f"AGENTOS XHCI COMMAND N={i+1} TYPE={kind} PTR={ptr:016x} CYCLE={cycle} SLOT={slot} CODE=1")
    event(44,34,port<<24,0)
    trace.extend(("usb_xhci_stop","usb_xhci_reset === RESET ===","usb_xhci_slot_disable slotid 1"))
    guest.extend(("AGENTOS XHCI WAIT DETACH PORT=3","AGENTOS XHCI PORT EVENT ID=3 STATUS=000202a0",
                  "AGENTOS XHCI DETACHED PORT=3 COMMANDS=42 EVENTS=45",
                  "AGENTOS XHCI CLOSED HALTED=1 MASTER=0 DMA=4"))
    return "\n".join(guest)+"\n","\n".join(trace)+"\n"


class Evidence(unittest.TestCase):
    def test_complete(self):
        guest,trace=fixture()
        info=x.verify_guest(guest,3)
        self.assertEqual(x.verify_trace(trace,info),{"commands":42,"events":45,"command_wraps":2,"event_wraps":2})

    def test_reject_guest_mutations(self):
        guest,_=fixture()
        for old,new in (("TYPE=9","TYPE=23"),("CYCLE=0","CYCLE=1"),
                        ("STATUS=00200e03","STATUS=00200e01"),("EVENTS=45","EVENTS=44"),
                        ("MASTER=0","MASTER=1"),("STATUS=000202a0","STATUS=000202a1")):
            with self.subTest(old=old),self.assertRaises(ValueError):
                x.verify_guest(guest.replace(old,new,1),3)

    def test_reject_trace_mutations(self):
        guest,trace=fixture();info=x.verify_guest(guest,3)
        for old,new in (("CC_SUCCESS","CC_TRB_ERROR"),("idx 0","idx 1"),
                        ("TR_LINK","TR_NOOP"),("port 3, warm 0","port 1, warm 0"),
                        ("usb_xhci_slot_enable slotid 1","usb_xhci_slot_enable slotid 2"),
                        ("usb_xhci_stop",""),("usb_xhci_reset === RESET ===","")):
            with self.subTest(old=old),self.assertRaises(ValueError):
                x.verify_trace(trace.replace(old,new,1),info)

    def test_usb_presence(self):
        attached="  Device 0.0, Port 1, Speed 480 Mb/s, Product QEMU USB Keyboard, ID: agentos-kbd\n"
        self.assertEqual(x.usb_speed("",attached,""),3)
        for before,after,detached in ((attached,attached,""),("",attached,attached),("","","")):
            with self.assertRaises(ValueError):x.usb_speed(before,after,detached)


if __name__=="__main__":unittest.main()
