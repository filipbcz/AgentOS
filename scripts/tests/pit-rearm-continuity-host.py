#!/usr/bin/env python3
"""Counterexample model for single-channel 8254 mode-0 rearm.

This is an independent information-loss proof, not a hardware emulator or
an integration test. Time advances in input CLK periods. The count stops
with GATE low, a fresh count replaces the old one, and OUT is sticky until
reprogramming. TSC observations deliberately can disagree with CLK time.
"""
from dataclasses import dataclass
import unittest

PIT_HZ = 1_193_182
TSC_HZ = 3_000_000_000
MAX_BRACKET_NS = 200_000
MAX_REARM_NS = 500_000


def tsc_ticks(clocks):
    return clocks * TSC_HZ // PIT_HZ


def narrow(before, after):
    return 0 <= (after - before) * 1_000_000_000 <= TSC_HZ * MAX_BRACKET_NS


@dataclass
class Finite:
    clock: int = PIT_HZ
    bias: int = 0
    count: int = 27124
    gate: bool = True
    terminal: bool = False

    def advance(self, clocks):
        self.clock += clocks
        if self.gate:
            self.terminal |= clocks >= self.count
            self.count = (self.count - clocks) & 0xffff

    def stamp(self):
        return tsc_ticks(self.clock + self.bias)

    def read(self, delay=1):
        before = self.stamp()
        self.advance(1)
        count, terminal = self.count, self.terminal
        self.advance(delay)
        return before, self.stamp(), count, terminal

    def reset(self, delay, bias=0):
        self.gate = False
        self.advance(delay)
        self.bias += bias
        self.count = 65535
        self.terminal = False
        self.gate = True


def trace(gap, bias=0, sample_delay=1):
    pit = Finite()
    start = pit.stamp()
    old = pit.read()
    pit.reset(gap, bias)
    # Work in the new running window is independently visible in count.
    pit.advance(74)
    first = pit.read()
    second = pit.read(sample_delay)
    end = pit.stamp()
    pit.advance(1000)
    following = pit.read()
    return (start, old, first, second, end, following), pit.clock


class RearmContinuity(unittest.TestCase):
    def test_long_transaction_can_contain_a_narrow_real_sample(self):
        (start, old, first, second, end, following), _ = trace(260)
        self.assertTrue(narrow(*old[:2]))
        self.assertTrue(narrow(*second[:2]))
        self.assertFalse(narrow(start, end))
        self.assertLessEqual((end-start)*1_000_000_000, TSC_HZ*MAX_REARM_NS)
        self.assertEqual(old[2], 27123)
        self.assertFalse(old[3] or first[3] or second[3] or following[3])
        self.assertGreater(first[2], second[2])
        self.assertGreater(second[2], 32767)
        self.assertGreater(second[2], following[2])

    def test_narrow_samples_cannot_recover_the_disabled_interval(self):
        # Two physically different histories yield identical old and new
        # counts, OUT states, TSC endpoints and subsequent running sample.
        # In the short history TSC gains the equivalent of 250 input clocks
        # while GATE is low. No channel-2 observation can distinguish them.
        long_trace, long_clock = trace(260)
        short_trace, short_clock = trace(10, bias=250)
        self.assertEqual(long_trace, short_trace)
        self.assertEqual(long_clock-short_clock, 250)
        self.assertTrue(narrow(*long_trace[3][:2]))
        self.assertGreater(250*1_000_000_000, PIT_HZ*MAX_BRACKET_NS)

    def test_genuinely_wide_latch_read_is_still_invalid(self):
        (_, old, first, second, _, _), _ = trace(10, sample_delay=250)
        self.assertTrue(narrow(*old[:2]))
        self.assertTrue(narrow(*first[:2]))
        self.assertFalse(narrow(*second[:2]))
        self.assertFalse(second[3])
        self.assertGreater(second[2], 32767)
        self.assertTrue(narrow(0, 600_000))
        self.assertFalse(narrow(0, 600_001))


if __name__ == '__main__':
    unittest.main(verbosity=2)
