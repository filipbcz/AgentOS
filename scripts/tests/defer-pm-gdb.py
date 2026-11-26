"""Executed by host GDB, only in the isolated QEMU deferred-removal test.

Use hardware execute breakpoints, not INT3 or modifications of EFI bytes.
The actual firmware EBS function and authenticated child's image range are
discovered by the signed fixture. Remove PM decode only at its successful
return to that child, before the child can execute another instruction.
"""
import binascii
import json
import os
import re
from pathlib import Path
import gdb


def require(condition, message):
    if not condition:
        raise gdb.GdbError(message)


def register(name):
    return int(gdb.parse_and_eval("$"+name)) & ((1<<64)-1)


def monitor(command):
    output=gdb.execute("monitor "+command,to_string=True)
    print(command,repr(output))
    require(not re.search(r"unknown command|invalid|error",output,re.I),
            "HMP command failed")
    return output


def read_port(port):
    output=monitor(f"i/xw {port:#x}")
    match=re.fullmatch(r"portl\[0x([0-9a-f]+)\]\s*=\s*0x([0-9a-f]{8})",
                       output.strip(),re.I)
    require(match is not None and int(match[1],16)==port,"Invalid HMP port result")
    return int(match[2],16)


def breakpoint_at(address):
    return gdb.Breakpoint(f"*{address:#x}",type=gdb.BP_HARDWARE_BREAKPOINT)


def run():
    request=json.loads(Path(os.environ["AGENTOS_EBS_REQUEST"]).read_text())
    entry,child,size,st,port=(request[k] for k in ("entry","child_base","child_size","system_table","pm_port"))
    inferior=gdb.selected_inferior()
    result={"result":"fail","system_table":st,"pm_port":port,"ebs_entry":entry,
            "child_base":child,"child_size":size,"attempts":[]}
    for _ in range(4):
        bp=breakpoint_at(entry)
        gdb.execute("continue")
        require(register("pc")==entry,"Did not stop at actual EBS entry")
        rsp=register("rsp")
        return_pc=int.from_bytes(bytes(inferior.read_memory(rsp,8)),"little")
        require(child<=return_pc<child+size,"EBS caller not in authenticated child image")
        bp.delete()
        bp=breakpoint_at(return_pc)
        gdb.execute("continue")
        require(register("pc")==return_pc,"Did not stop at actual EBS return")
        bp.delete()
        status=register("rax")
        result["attempts"].append({"return_pc":return_pc,"efi_status":status})
        if status==0:
            break
        require(status==0x8000000000000002,"Unexpected EBS failure status")
    require(status==0,"No successful EBS return")
    table=bytes(inferior.read_memory(st,120))
    require(table[:8]==b"IBI SYST" and int.from_bytes(table[12:16],"little")==120,
            "Invalid EFI system table")
    require(binascii.crc32(table[:16]+bytes(4)+table[20:])&0xffffffff
            ==int.from_bytes(table[16:20],"little"),"Bad system table CRC")
    services=int.from_bytes(table[96:104],"little")
    require(services==0,"Firmware BootServices still active")
    print("Stopped at successful EBS return",hex(return_pc))
    print(gdb.execute("x/4i $pc",to_string=True))
    # Isolated q35 test hardware only. Restore the PCI config selector
    # after the transaction; no guest registers, RAM or EFI code modified.
    previous=read_port(0xcf8)
    try:
        monitor("o/xw 0xcf8 0x8000f800")
        require(read_port(0xcfc)==0x29188086,"Unexpected ICH9 identity")
        monitor("o/xw 0xcf8 0x8000f840")
        require((read_port(0xcfc)&0xff80)+8==port,"Former PM base mismatch")
        monitor("o/xw 0xcf8 0x8000f844")
        before=read_port(0xcfc)
        require(before&0x80,"PM decode already disabled before EBS returned")
        monitor(f"o/xb 0xcfc {(before&0xff)&~0x80:#x}")
        after=read_port(0xcfc)
        require(after==before&~0x80,"PM control did not change exactly as requested")
    finally:
        monitor(f"o/xw 0xcf8 {previous:#x}")
    value=read_port(port)
    require(value==0xffffffff,"PM port still accessible")
    result.update(result="pass",efi_status=status,return_pc=return_pc,boot_services=services,
                  control_before=before,control_after=after,port_after=value)
    destination=Path(request["destination"])
    (destination/"deferred-removal.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("Verified post-EBS PM removal:",json.dumps(result,sort_keys=True))
    gdb.execute("detach")


run()
