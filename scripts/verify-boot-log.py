"""Strict COM1 policy check for loader EFI/BOOT/BOOT.LOG.

The native firmware/panic/acceptance markers remain visible independently
of the structured BOOT.LOG policy. Check both required and forbidden lines;
a successful parser unit test does not replace actual VM image validation.
"""
import argparse
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import physical_oom_evidence as physical_oom


class VerificationError(ValueError):
    pass


LOG_LINE = re.compile(r"^\[(INFO|DEBUG|ERROR)\] (.+)$")
LEVELS = ("quiet", "info", "debug")
SINKS = ("none", "serial", "screen", "both")


def require(condition, description):
    if not condition:
        raise VerificationError(description)


def verify(log, level, output, *, physical_oom_dir=None, source_commit=None, historical_boot_oom=False):
    if historical_boot_oom:
        require(physical_oom_dir is None and source_commit is None, "Historical boot inspection cannot claim current OOM proof")
    else:
        require(physical_oom_dir is not None and source_commit is not None, "Missing separate OOM proof context")
        physical_oom.verify_boot(log, physical_oom.ROOT, physical_oom_dir, source_commit)
    require(level in LEVELS and output in SINKS, "Unsupported BOOT.LOG policy")
    lines = log.decode("ascii", errors="replace").splitlines()
    require("AGENTOS KERNEL OK STAGE 1" in lines, "Missing mandatory raw kernel boot marker")
    records = [match.groups() for line in lines if
               (match := LOG_LINE.fullmatch(line)) is not None]
    actual = {"ERROR": set(), "INFO": set(), "DEBUG": set()}
    for severity, message in records:
        actual[severity].add(message)
    serial = output in ("serial", "both")
    if not serial:
        require(not records, "Structured BOOT.LOG escaped from disabled COM1 sink")
        return records
    if level == "quiet":
        require(not actual["INFO"] and not actual["DEBUG"],
                "Quiet mode leaked INFO/DEBUG diagnostics")
    elif level == "info":
        require(not actual["DEBUG"], "Info mode leaked DEBUG diagnostics")
        require("KERNEL ENTRY" in actual["INFO"] and
                "BOOT COMPLETE" in actual["INFO"],
                "Info mode missing mandatory boot lifecycle events")
    else:
        require("KERNEL ENTRY" in actual["INFO"] and
                "BOOT COMPLETE" in actual["INFO"],
                "Debug mode missing boot lifecycle events")
        require("ACPI TABLES READY" in actual["DEBUG"] and
                "INITRAMFS LOCATED" in actual["DEBUG"],
                "Debug mode missing ACPI/initramfs diagnostics")
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--level", required=True, choices=LEVELS)
    parser.add_argument("--output", required=True, choices=SINKS)
    parser.add_argument("--physical-oom-dir", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--historical-boot-oom", action="store_true", help="Inspect only the historical BOOT.LOG policy")
    args = parser.parse_args()
    try:
        log = args.log.read_bytes()
        records = verify(log, args.level, args.output, physical_oom_dir=args.physical_oom_dir,
                         source_commit=args.source_commit, historical_boot_oom=args.historical_boot_oom)
    except (OSError, ValueError) as error:
        print(f"BOOT.LOG acceptance failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified BOOT.LOG {args.level}/{args.output}: {len(records)} COM1 events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
