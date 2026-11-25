"""Synthetic rejection tests only; no substitute for the real QEMU NIC."""
import struct
import unittest

import virtio_net_evidence as net


def pcap(frames):
    data = struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65536,1)
    return data+b"".join(struct.pack("<IIII",0,0,len(frame),len(frame))+frame for frame in frames)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.records=[]; self.frames=[]
        lines=["AGENTOS VIRTIO NET READY MAC=52:54:00:12:34:56 DEPTH=8 ROUNDS=12 MRG=1"]
        for n in range(1,13):
            incoming=net.challenge(bytes((i+n)%256 for i in range(82)))
            outgoing=net.reply(incoming)
            self.frames.extend((incoming,outgoing))
            self.records.append({"round":n,"host_tx":incoming.hex(),"host_rx":outgoing.hex()})
            lines.append(f"AGENTOS VIRTIO NET FRAME ROUND={n} LEN=96 RX={net.fnv(incoming)} "
                         f"TX={net.fnv(outgoing)} RXUSED={n} TXUSED={n}")
        lines.append("AGENTOS VIRTIO NET CLOSED STATUS=0 MASTER=0 DMA=4")
        self.guest="\n".join(lines)+"\n"

    def test_complete_exchange(self):
        result=net.verify(self.guest,self.records,pcap(self.frames))
        self.assertEqual(result["rounds"],12)
        self.assertEqual(result["rx_bytes"],1152)
        self.assertEqual(result["used_entries_per_queue"],12)

    def test_reject_missing_corrupt_or_forged_frames(self):
        for guest,records,wire in (
            (self.guest,self.records[:-1],pcap(self.frames)),
            (self.guest.replace("RXUSED=12","RXUSED=4"),self.records,pcap(self.frames)),
            (self.guest.replace("MASTER=0","MASTER=1"),self.records,pcap(self.frames)),
            (self.guest,self.records,pcap(self.frames[:-1])),
            (self.guest,self.records,pcap(self.frames[::-1])),
            (self.guest,self.records,pcap(self.frames)[:-1]),
            (self.guest,self.records,pcap([*self.frames[:-1],self.frames[-1][:-1]+b"\x00"])),
        ):
            with self.subTest(guest=guest[-70:],records=len(records),wire=len(wire)),self.assertRaises(ValueError):
                net.verify(guest,records,wire)
        self.records[0]["host_rx"]=self.records[1]["host_rx"]
        with self.assertRaises(ValueError):
            net.verify(self.guest,self.records,pcap(self.frames))

    def test_pci_identity_and_high_bar(self):
        pci=[{"devices":[{"qdev_id":"agentos-net","bus":0,"slot":3,"function":0,
                           "id":{"vendor":0x1af4,"device":0x1041},"class_info":{"class":0x0200},
                           "regions":[{"bar":4,"type":"memory","address":0xc000000000,"size":16384}]}]}]
        text=("AGENTOS PCI DEV 0000:00:03.0 ID=1af4:1041 CLASS=020000 REV=01\n"
              "AGENTOS MMIO VIRTIO BAR=4 PA=000000c000000000 VA=ffff90c000000000 PAGES=4\n")
        self.assertEqual(net.verify_pci(text,pci),"0000:00:03.0")
        for wrong in (text.replace("ffff90c000000000","000000c000000000"),
                      text.replace("PAGES=4","PAGES=2"),text.replace("1af4:1041","1af4:1000")):
            with self.assertRaises(ValueError):
                net.verify_pci(wrong,pci)


if __name__=="__main__":
    unittest.main()
