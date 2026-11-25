"""Independently check xHCI hotplug, ring wraps and command completions."""
import re

NOOPS = 40
PREFIX = r"^(?:\d+@\d+\.\d+:)?"
FETCH = re.compile(PREFIX +
    r"usb_xhci_fetch_trb addr 0x([0-9a-f]+), ([A-Z_0-9]+), p 0x([0-9a-f]+), s 0x([0-9a-f]+), c 0x([0-9a-f]+)$")
EVENT = re.compile(PREFIX +
    r"usb_xhci_queue_event v (\d+), idx (\d+), ([A-Z_0-9]+), ([A-Z_0-9]+), p 0x([0-9a-f]+), s 0x([0-9a-f]+), c 0x([0-9a-f]+)$")
TRACE_EVENTS = ("usb_xhci_reset", "usb_xhci_run", "usb_xhci_stop",
                "usb_xhci_port_reset", "usb_xhci_fetch_trb", "usb_xhci_queue_event",
                "usb_xhci_slot_enable", "usb_xhci_slot_disable")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify_pci(guest, pci):
    def walk(devices):
        for device in devices:
            yield device
            yield from walk(device.get("pci_bridge", {}).get("devices", []))
    matches = [d for bus in pci for d in walk(bus["devices"]) if d.get("qdev_id") == "agentos-xhci"]
    require(len(matches) == 1, "Missing QMP xHCI controller")
    d = matches[0]
    require(d["class_info"]["class"] == 0x0c03, "Not USB PCI class")
    bdf = f"0000:{d['bus']:02x}:{d['slot']:02x}.{d['function']}"
    require(guest.count(f"AGENTOS PCI DEV {bdf} ID={d['id']['vendor']:04x}:{d['id']['device']:04x} CLASS=0c0330 ") == 1,
            "Guest and QMP xHCI PCI identity differ")
    match = re.search(r"(?m)^AGENTOS MMIO XHCI BAR=0 PA=([0-9a-f]{16}) VA=([0-9a-f]{16}) PAGES=(\d+)\r?$", guest)
    require(match is not None, "Missing xHCI BAR mapping")
    physical, virtual, pages = int(match[1],16),int(match[2],16),int(match[3])
    regions = [r for r in d["regions"] if r.get("bar") == 0]
    require(len(regions) == 1 and regions[0]["type"] == "memory" and
            regions[0]["address"] == physical and regions[0]["size"] == pages*4096 and
            1 <= pages <= 16 and virtual == (physical if physical < 1<<39 else 0xffff900000000000+physical),
            "Wrong xHCI MMIO aperture")
    return bdf


def usb_speed(before, attached, detached):
    require("ID: agentos-kbd" not in before and "ID: agentos-kbd" not in detached,
            "USB test device was not independently attached/detached")
    matches = re.findall(r"(?m)^\s*Device \d+\.\d+, Port 1, Speed (1\.5|12|480) Mb/s, Product QEMU USB Keyboard, ID: agentos-kbd\s*$",
                         attached)
    require(len(matches) == 1, "Missing QEMU USB keyboard on the dedicated port")
    return {"1.5":2, "12":1, "480":3}[matches[0]]


def verify_guest(guest, speed):
    lines = [line for line in guest.splitlines() if line.startswith("AGENTOS XHCI ")]
    require(len(lines) == NOOPS+10, f"Wrong number of xHCI records: {len(lines)}")
    ready = re.fullmatch(r"AGENTOS XHCI READY VERSION=([0-9a-f]{4}) PORTS=(\d+) SLOTS=(\d+) CMD=([0-9a-f]{16}) EVENT=([0-9a-f]{16}) RING=16", lines[0])
    require(ready is not None, "Missing initialized xHCI")
    version, ports, slots = int(ready[1],16),int(ready[2]),int(ready[3])
    base, event_base = int(ready[4],16),int(ready[5],16)
    require(0x100 <= version <= 0x120 and 1 <= ports <= 32 and 1 <= slots <= 8 and
            base > 0 and event_base > 0 and base != event_base and base%4096 == event_base%4096 == 0,
            "Invalid xHCI queue geometry")
    def port_event(line):
        match = re.fullmatch(r"AGENTOS XHCI PORT EVENT ID=(\d+) STATUS=([0-9a-f]{8})",line)
        require(match is not None,"Missing real port event")
        return int(match[1]),int(match[2],16)
    port, connect = port_event(lines[1])
    reset_port, reset = port_event(lines[2])
    require(1<=port<=ports and reset_port==port and connect&0x20001==0x20001 and
            reset&0x200203==0x200203 and reset&0x1f0==0 and (reset>>10)&15==speed,
            "Wrong connect/reset port status")
    require(lines[3] == f"AGENTOS XHCI PORT RESET ID={port} USB=2 SPEED={speed} STATUS={reset:08x}",
            "USB speed/reset did not agree with QEMU")
    commands = []
    slot = None
    for i,line in enumerate(lines[4:4+NOOPS+2]):
        kind = 9 if i == 0 else 10 if i == NOOPS+1 else 23
        pointer = base+16*(i%15)
        cycle = int(i//15%2==0)
        cmd = re.fullmatch(r"AGENTOS XHCI COMMAND N=(\d+) TYPE=(\d+) PTR=([0-9a-f]{16}) CYCLE=([01]) SLOT=(\d+) CODE=1",line)
        require(cmd is not None and (int(cmd[1]),int(cmd[2]),int(cmd[3],16),int(cmd[4])) ==
                (i+1,kind,pointer,cycle), "Wrong xHCI command pointer/type/cycle")
        completed_slot=int(cmd[5])
        if i==0:
            require(1<=completed_slot<=slots,"Invalid enabled slot")
            slot=completed_slot
        else:
            require(completed_slot==(slot if kind==10 else 0),"Wrong completed slot")
        commands.append((kind,pointer,cycle,completed_slot))
    tail = lines[4+NOOPS+2:]
    require(tail[0]==f"AGENTOS XHCI WAIT DETACH PORT={port}","Missing detach rendezvous")
    dp, disconnect = port_event(tail[1])
    require(dp==port and disconnect&0x20003==0x20000,"Missing physical disconnect event")
    require(tail[2]==f"AGENTOS XHCI DETACHED PORT={port} COMMANDS=42 EVENTS=45" and
            tail[3]=="AGENTOS XHCI CLOSED HALTED=1 MASTER=0 DMA=4" and "AGENTOS PCI FAILED" not in guest,
            "Incomplete xHCI device/DMA shutdown")
    return {"port":port,"slot":slot,"speed_id":speed,"commands":commands,"command_base":base,
            "events":45,"ring_wraps":2}


def verify_trace(trace, info):
    """Only the actual emulator trace after READY, before emulator exit."""
    commands = info["commands"]
    port = info["port"]
    expected = [(34,port<<24,0),(34,port<<24,0)]
    expected.extend((33,pointer,slot) for _,pointer,_,slot in commands)
    expected.append((34,port<<24,0))
    events = []
    fetched = []
    port_resets=[]
    enabled=[]
    disabled=[]
    stopped=False
    reset_after_stop=False
    for line in trace.splitlines():
        if re.fullmatch(PREFIX+r"usb_xhci_stop\s*",line):
            require(not stopped,"Repeated xHCI halt in exercise")
            stopped=True
        elif re.fullmatch(PREFIX+r"usb_xhci_reset === RESET ===",line):
            require(stopped,"Unexpected xHCI reset during exercise")
            reset_after_stop=True
        elif stopped:
            # QEMU resets every slot at shutdown, independently of commands.
            continue
        elif m:=FETCH.fullmatch(line):
            fetched.append((int(m[1],16),m[2],int(m[3],16),int(m[4],16),int(m[5],16)))
        elif m:=EVENT.fullmatch(line):
            vector,index,name,code,parameter,status,control=m.groups()
            parameter,status,control=int(parameter,16),int(status,16),int(control,16)
            i=len(events)
            require(i<len(expected),"Unexpected additional xHCI event")
            kind,pointer,slot=expected[i]
            require((int(vector),int(index),parameter,status,control)==
                    (0,i%16,pointer,1<<24,(slot<<24)|(kind<<10)|int(i//16%2==0)) and
                    name==("ER_COMMAND_COMPLETE" if kind==33 else "ER_PORT_STATUS_CHANGE") and code=="CC_SUCCESS",
                    "Independent xHCI event pointer/index/cycle/status mismatch")
            if kind==33:
                opcode,_,cycle,cmd_slot=commands[i-2]
                label={9:"CR_ENABLE_SLOT",10:"CR_DISABLE_SLOT",23:"CR_NOOP"}[opcode]
                expected_ctrl=(opcode<<10)|cycle|((cmd_slot<<24) if opcode==10 else 0)
                require((pointer,label,0,0,expected_ctrl) in fetched,
                        "No matching controller-fetched command TRB")
                if (i-2)%15==0 and i>2:
                    prev_cycle=1-cycle
                    require((info["command_base"]+15*16,"TR_LINK",info["command_base"],0,
                             (6<<10)|2|prev_cycle) in fetched,
                            "Missing real toggle-cycle Link TRB")
            fetched.clear()
            events.append((kind,pointer,slot))
        elif m:=re.fullmatch(PREFIX+r"usb_xhci_port_reset port (\d+), warm (\d+)",line):
            port_resets.append((int(m[1]),int(m[2])))
        elif m:=re.fullmatch(PREFIX+r"usb_xhci_slot_enable slotid (\d+)",line):
            enabled.append(int(m[1]))
        elif m:=re.fullmatch(PREFIX+r"usb_xhci_slot_disable slotid (\d+)",line):
            disabled.append(int(m[1]))
        elif any(event+" " in line for event in TRACE_EVENTS):
            raise ValueError(f"Unrecognized xHCI trace: {line!r}")
    require(events==expected and port_resets==[(port,0)] and enabled==[info["slot"]] and
            disabled==[info["slot"]] and stopped and reset_after_stop,
            "Missing independent controller commands, events, port reset or final halt/reset")
    return {"commands":len(commands),"events":len(events),"command_wraps":2,"event_wraps":2}
