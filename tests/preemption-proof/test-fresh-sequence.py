"""Synthetic host receipt linkage tests only. No guest, no register proof."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import fresh_sequence as seq


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


class FreshSequenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.build = Path(self.temp.name) / "build"
        self.build.mkdir()
        self.layout = self.build / "layout.txt"
        self.layout.write_bytes(b"synthetic layout identity, no offsets")
        for name in seq.PRODUCT:
            if name != "build-provenance.json":
                (self.build / name).write_bytes(("fixture " + name).encode())
        commit, tree = "1"*40, "2"*40
        control = {key: seq.sha(self.build / name) for name, key in seq.PRODUCT.items()
                   if name != "build-provenance.json"}
        control.update(source_commit=commit, signature_verified=True)
        save(self.build / "build-provenance.json", dict(source_commit=commit, source_clean=True,
             profile="default", initramfs_sha256=control["initramfs_sha256"],
             artifacts={name: control[seq.PRODUCT[name]] for name in
                        ("agentos.efi", "agentos.unsigned.efi", "db.cer")}))
        control["build_provenance_sha256"] = seq.sha(self.build / "build-provenance.json")
        self.candidate = dict(commit=commit, tree=tree, control=control, layout_sha256=seq.sha(self.layout),
                              kernel_symbols={"synthetic": "not an address"}, runtime_bytes={"synthetic": "not machine code"})
        self.dirs, self.expected, self.calls = [], {}, []
        previous = None
        for cpus in seq.PROFILES:
            d = self.build / f"preemption-proof-{cpus}cpu"
            d.mkdir()
            self.dirs.append(d)
            for name in seq.EVIDENCE:
                (d / name).write_bytes(f"fixture {cpus} {name}".encode())
            (d / "esp-bootx64.efi").write_bytes((d / "test.efi").read_bytes())
            base, start, shell, root = 0x100000, cpus*1000, 2, 3
            apics = [3*i+1 for i in range(cpus)]
            qmp = dict(accelerator="tcg", kvm={"enabled": False}, cpus=[{"apic-id": a} for a in apics])
            ready = dict(threads=cpus, online=cpus, bindings=[{"apic": a} for a in apics], armed_ns=start+10)
            windows = {chr(65+i): [i] for i in range(2*cpus)}
            request = dict(base=base, cpus=cpus, qmp=qmp, windows=windows, iterations=1,
                           runtime_bytes=self.candidate["runtime_bytes"], layout_sha256=self.candidate["layout_sha256"])
            before = (f"[INFO] KERNEL IMAGE BASE={base:016x}\r\n" +
                      "".join(f"AGENTOS TASK {'BSP' if i==0 else 'AP'} APIC={a:016x} TIMER-WAKES=0000000000000003\r\n"
                              for i,a in enumerate(apics)) + f"AGENTOS SHELL START PID={shell:016x}\r\nagentos> ").encode()
            log = before + seq.ARM + b"\n" + f"REG ROOT PID={root:016x}\r\n".encode()
            identities = {}
            for i,label in enumerate(windows):
                pid, cr3 = 4+i, (i+1)*4096
                identities[label] = [pid, root, cr3]
                log += (f"REG {label} PID={pid:016x}\r\nREG {label} BEGIN PID={pid:016x}\r\n"
                        f"REG {label} OK PID={pid:016x}\r\nAGENTOS USER EXIT PID={pid:016x} CR3={cr3:016x} STATUS=0000000000000000\r\n"
                        f"REG {label} REAP PID={pid:016x}\r\n").encode()
            log += (f"REG COMPLETE PID={root:016x}\r\nAGENTOS USER EXIT PID={root:016x} CR3=0000000000100000 STATUS=0000000000000000\r\n"
                    "exit status 0\r\nagentos> exit\r\nAGENTOS MANAGER SESSION STOP PID=0000000000000001 STATUS=0000000000000000 FRAMES=OK\r\n"
                    "[INFO] INTERACTIVE SHELL STOPPED\r\n").encode()
            rows = [dict(apic=a, seq=i*6+j+1, host_ns=start+30+i*6+j, synthetic=True)
                    for i,a in enumerate(apics) for j in range(6)]
            chains = {str(a): [r for r in rows if r["apic"] == a] for a in apics}
            trace = dict(complete=True, error=None, stops=len(rows), armed_ns=start+10, end_ns=start+100)
            save(d / "guest-start.json", dict(guests=1, cpus=cpus, host_ns=start, command=["fixture", "-smp", str(cpus)]))
            for name, value in (("trace-request", request), ("trace-ready", ready), ("trace-result", trace),
                                ("qmp-roster", qmp), ("arm", dict(ready=ready, arm_ns=start+20, sent_ns=start+25,
                                                                command=seq.ARM.hex(), offset=len(before)))):
                save(d / (name+".json"), value)
            (d / "irq-trace.jsonl").write_text("".join(json.dumps(r)+"\n" for r in rows))
            (d / "com1.log").write_bytes(log)
            (d / "com1-input.bin").write_bytes(seq.ARM+b"exit\r")
            inputs = {str(self.build / n): seq.sha(self.build / n) for n in seq.PRODUCT}
            inputs.update({str(d / n): seq.sha(d / n) for n in ("preempt-runner", "client.symbols.elf", "test.cpio",
                 "test.efi", "test.unsigned.efi", "esp-bootx64.efi", "startup-host.json", "failure-host.json")})
            pre = dict(self.candidate, result="pass", guests=0, cpus=cpus, stage="complete", workers=cpus*2,
                       arm=seq.ARM.hex(), fresh_previous_result_sha256=previous, windows=windows, iterations=1, inputs=inputs)
            save(d / "preflight.json", pre)
            hashes = seq.evidence_hashes(d)
            result = dict(result="pass", guests=1, cpus=cpus, commit=commit, tree=tree, layout_sha256=self.candidate["layout_sha256"],
                          shutdown=True, finished_ns=start+200, bounds=[start+25,start+110], iterations=1, shell=shell, root=root,
                          identities=identities, chains=chains, trace=trace, evidence_sha256=hashes,
                          com1_sha256=hashes["com1.log"], trace_sha256=hashes["irq-trace.jsonl"])
            save(d / "result.json", result)
            previous = seq.sha(d / "result.json")
            self.expected[d] = (copy.deepcopy(rows), request, ready, identities, tuple(result["bounds"]), chains)

    def fixture_replay(self, d, rows, request, ready, ids, bounds):
        # Only a unit-test seam. This is deliberately not an IRQ/context verifier.
        self.assertEqual((rows, request, ready, ids, bounds), self.expected[d][:-1])
        self.calls.append(d)
        return self.expected[d][-1]

    def verify(self, dirs=None, replay=None):
        return seq.verify_sequence(self.build, self.layout, self.candidate,
                                   self.dirs if dirs is None else dirs, replay=replay or self.fixture_replay)

    def change(self, i, name, **updates):
        d = self.dirs[i]
        p = d / name
        value = seq.record(p)
        value.update(updates)
        save(p, value)
        if name != "result.json":
            self.rehash(i)

    def rehash(self, i):
        d = self.dirs[i]
        r = seq.record(d / "result.json")
        h = seq.evidence_hashes(d)
        r.update(evidence_sha256=h, com1_sha256=h["com1.log"], trace_sha256=h["irq-trace.jsonl"])
        save(d / "result.json", r)

    def test_ordered_prefix_and_full(self):
        for n in range(5):
            self.assertEqual(seq.verify_prefix(self.build, self.layout, self.candidate, self.dirs[:n], replay=self.fixture_replay),
                             tuple(seq.sha(d / "result.json") for d in self.dirs[:n]))
        self.calls.clear()
        self.assertEqual(self.verify(), tuple(seq.sha(d / "result.json") for d in self.dirs))
        self.assertEqual(self.calls, self.dirs)

    def test_missing_1_or_2(self):
        for i in (0,1):
            with self.subTest(i=i), self.assertRaisesRegex(ValueError, "Missing full"):
                self.verify(self.dirs[:i]+self.dirs[i+1:])

    def test_duplicate_profile(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.verify([self.dirs[0],self.dirs[1],self.dirs[1],self.dirs[3]])

    def test_reordered_profile(self):
        with self.assertRaises(ValueError):
            self.verify([self.dirs[1],self.dirs[0],*self.dirs[2:]])

    def test_mixed_elf(self):
        control = dict(self.candidate["control"], kernel_sha256="0"*64)
        self.change(1,"preflight.json",control=control)
        with self.assertRaisesRegex(ValueError, "Wrong candidate preflight"):
            self.verify()

    def test_actual_elf_changed(self):
        (self.build / "kernel.elf").write_bytes(b"different fixture")
        with self.assertRaisesRegex(ValueError, "product bytes changed"):
            self.verify()

    def test_wrong_tree_or_layout(self):
        self.change(1,"result.json",tree="3"*40)
        with self.assertRaisesRegex(ValueError, "source/layout"):
            self.verify()

    def test_layout_bytes_changed(self):
        self.layout.write_bytes(b"different layout fixture")
        with self.assertRaisesRegex(ValueError, "changed verified layout"):
            self.verify()

    def test_changed_confirmation(self):
        p = self.dirs[0] / "result.json"
        p.write_bytes(p.read_bytes()+b" ")
        with self.assertRaisesRegex(ValueError, "predecessor"):
            self.verify()

    def test_historical_receipt(self):
        self.change(1,"preflight.json",prior_proof={"artifact":15236044308})
        with self.assertRaisesRegex(ValueError, "historical replay"):
            self.verify()

    def test_raw_digest(self):
        p = self.dirs[1] / "irq-trace.jsonl"
        p.write_bytes(p.read_bytes()+b"\n")
        with self.assertRaisesRegex(ValueError, "Changed raw evidence"):
            self.verify()

    def test_staged_efi_swap(self):
        (self.dirs[1] / "test.efi").write_bytes((self.dirs[0] / "test.efi").read_bytes())
        self.rehash(1)
        with self.assertRaisesRegex(ValueError, "Wrong staged EFI"):
            self.verify()

    def test_wrong_roster(self):
        d = self.dirs[1]
        qmp = seq.record(d / "qmp-roster.json")
        qmp["cpus"][1]["apic-id"] = qmp["cpus"][0]["apic-id"]
        save(d / "qmp-roster.json",qmp)
        self.change(1,"trace-request.json",qmp=qmp)
        with self.assertRaisesRegex(ValueError, "QMP/GDB roster"):
            self.verify()

    def test_no_real_shutdown_log(self):
        p = self.dirs[1] / "com1.log"
        p.write_bytes(p.read_bytes().replace(b"FRAMES=OK",b"FRAMES=BAD"))
        self.rehash(1)
        with self.assertRaisesRegex(ValueError, "lifecycle/boot roster"):
            self.verify()

    def test_no_raw_replayer(self):
        with self.assertRaisesRegex(ValueError, "raw replayer required"):
            seq.verify_sequence(self.build,self.layout,self.candidate,self.dirs,replay=None)

    def test_replayer_rejection_propagates(self):
        def reject(*args):
            raise ValueError("fixture raw replay failed")
        with self.assertRaisesRegex(ValueError, "raw replay failed"):
            self.verify(replay=reject)

    def test_replayer_missing_chains(self):
        with self.assertRaisesRegex(ValueError, "Missing complete replayed"):
            self.verify(replay=lambda *args: {})

    def test_overlapping_runs(self):
        self.change(1,"guest-start.json",host_ns=1001)
        with self.assertRaisesRegex(ValueError, "Incomplete/reordered"):
            self.verify()

    def test_mutation_during_replay(self):
        def change(d,*args):
            chains=self.fixture_replay(d,*args)
            p=d / "result.json"
            p.write_bytes(p.read_bytes()+b" ")
            return chains
        with self.assertRaisesRegex(ValueError,"changed during replay"):
            self.verify(replay=change)


if __name__ == "__main__":
    unittest.main(verbosity=2)
