"""Strict synthetic tests for the independent PID1 supervision evidence checker."""
from pathlib import Path
import importlib.util
import unittest


ROOT = Path(__file__).resolve().parent


def imported(path, module):
    spec = importlib.util.spec_from_file_location(module, ROOT / path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


supervisor = imported("verify-supervisor.py", "supervisor_verifier")
processes = imported("verify-processes.py", "process_verifier")
fixtures = imported("test-verify-processes.py", "process_fixtures")


def service_interval(parent):
    children = list(range(parent + 4, parent + 9))
    out = [f"AGENTOS SUPERVISOR BEGIN PARENT={parent:016x}"]
    def exit_line(pid, status):
        out.append(f"AGENTOS USER EXIT PID={pid:016x} CR3=0000000000400000 STATUS={status:016x}")
    def event(name, pid, status, attempt):
        out.append(f"AGENTOS SERVICE {name} PARENT={parent:016x} CHILD={pid:016x} "
                   f"STATUS={status:016x} ATTEMPT={attempt:08x}")
    exit_line(children[0], 0)
    event("DONE", children[0], 0, 1)
    for attempt, pid in enumerate(children[1:4], 1):
        exit_line(pid, 42)
        event("REAP", pid, 42, attempt)
    event("STOP", children[3], 42, 3)
    out.append(f"AGENTOS USER KILL PID={children[4]:016x} "
               f"PARENT={parent:016x} STATUS=0000000000000089")
    out.append(f"AGENTOS SERVICE DURATION PARENT={parent:016x} "
               f"CHILD={children[4]:016x} MS=00000000000000fa")
    event("TIME", children[4], 137, 1)
    event("STOP", children[4], 137, 1)
    out.append(f"AGENTOS SUPERVISOR ENDED PARENT={parent:016x}")
    return out


def scenario(parent=1, apic=0):
    basic = fixtures.scenario(apic, parent).splitlines()
    marker = f"AGENTOS USER EXIT PID={parent:016x}"
    i = next(i for i, line in enumerate(basic) if line.startswith(marker))
    basic[i:i] = service_interval(parent)
    return "\n".join(basic) + "\n"


class SupervisorEvidenceTests(unittest.TestCase):
    def test_legacy_interval_evidence_and_current_distribution_are_distinct(self):
        for cpus in (1,2):
            legacy = scenario() + (scenario(10,1) if cpus==2 else "")
            self.assertEqual(supervisor.verify(legacy,cpus),cpus)
            with self.assertRaises(supervisor.VerificationError):
                supervisor.verify_absent(legacy)
            with self.assertRaises(processes.VerificationError):
                processes.verify(legacy,list(range(cpus)))
            current=fixtures.scenario()+(fixtures.scenario(1,10) if cpus==2 else "")
            supervisor.verify_absent(current)
            processes.verify(current,list(range(cpus)))
            # Absence is not a substitute for historical or staged workload evidence.
            with self.assertRaises(supervisor.VerificationError):
                supervisor.verify(current,cpus)

    def rejected(self, log):
        with self.assertRaises(supervisor.VerificationError):
            supervisor.verify(log, 1)

    def test_missing_extra_duplicate_reordered_records_fail_closed(self):
        lines = scenario().splitlines()
        start = next(i for i, v in enumerate(lines) if v.startswith("AGENTOS SUPERVISOR BEGIN"))
        end = next(i for i, v in enumerate(lines) if v.startswith("AGENTOS SUPERVISOR ENDED"))
        for idx in range(start, end + 1):
            with self.subTest(removed=idx):
                self.rejected("\n".join(lines[:idx] + lines[idx+1:]))
        self.rejected("\n".join(lines[:end] + [lines[start+1]] + lines[end:]))
        swapped = lines[:]
        swapped[start+1], swapped[start+2] = swapped[start+2], swapped[start+1]
        self.rejected("\n".join(swapped))

    def test_wrong_status_attempt_identity_or_kill_is_rejected(self):
        good = scenario()
        for old, new in (
            ("STATUS=000000000000002a", "STATUS=0000000000000000"),
            ("ATTEMPT=00000003", "ATTEMPT=00000004"),
            ("STATUS=0000000000000089", "STATUS=0000000000000088"),
            ("AGENTOS SERVICE DONE PARENT=0000000000000001", "AGENTOS SERVICE DONE PARENT=0000000000000002"),
            ("CHILD=0000000000000009", "CHILD=0000000000000003"),
            ("AGENTOS SERVICE TIME", "AGENTOS SERVICE REAP"),
            ("MS=00000000000000fa", "MS=00000000000000f9"),
            ("MS=00000000000000fa", "MS=ffffffffffffffff"),
            ("AGENTOS USER KILL", "AGENTOS USER EXIT"),
        ):
            with self.subTest(old=old):
                self.rejected(good.replace(old, new, 1))

    def test_missing_supervisor_and_incomplete_second_cpu(self):
        self.rejected(fixtures.scenario())
        with self.assertRaises(supervisor.VerificationError):
            supervisor.verify(scenario(), 2)
        log = scenario() + fixtures.scenario(1, 10)
        with self.assertRaises(supervisor.VerificationError):
            supervisor.verify(log, 2)

    def test_core_verifier_rejects_old_boot_and_isolated_workload_markers(self):
        log = scenario()
        for bad in (log,
                    log.replace("AGENTOS SUPERVISOR ENDED PARENT=0000000000000001",""),
                    log.replace("SUPERVISOR BEGIN PARENT=0000000000000001",
                                "SUPERVISOR BEGIN PARENT=0000000000000002")):
            with self.assertRaises(processes.VerificationError):
                processes.verify(bad,[0])
        for marker in ("AGENTOS SUPERVISOR BEGIN", "AGENTOS SERVICE REAP", "AGENTOS TEST RUNNER"):
            for text in (marker+"\n"+fixtures.scenario(),fixtures.scenario()+marker+"\n"):
                with self.assertRaises(processes.VerificationError):
                    processes.verify(text,[0])
                with self.assertRaises(supervisor.VerificationError):
                    supervisor.verify_absent(text)


if __name__ == "__main__":
    unittest.main()
