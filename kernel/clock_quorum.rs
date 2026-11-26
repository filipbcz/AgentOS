//! Bounded three-source clock comparison. A normalized TSC is a witness,
//! not an absolute time epoch. This module contains no hardware accesses.
const NS_PER_SECOND: u128 = 1_000_000_000;
pub(crate) const MAX_GAP_NS: u128 = 2_000_000_000;
const MAX_BRACKET_NS: u128 = 200_000;
const MAX_UNCERTAINTY_NS: u128 = 10_000_000;
const QUANTIZATION_NS: u128 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Witness {
    pub cpu: u8,
    pub ticks: u64,
    pub hz: u64,
    pub uncertainty_ticks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TscBracket {
    low: u64,
    high: u64,
    hz: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Span { pub low: u128, pub high: u128 }

impl Span {
    /// Both readings are intervals enclosing the actual sample time.
    pub fn elapsed(first: Self, last: Self) -> Option<Self> {
        if first.low > first.high || last.low > last.high { return None; }
        Some(Self { low: last.low.saturating_sub(first.high),
                    high: last.high.checked_sub(first.low)? })
    }

    pub fn exact(ns: u128) -> Self { Self { low: ns, high: ns } }

    fn agrees(self, other: Self) -> bool {
        // Account for the independently calibrated rates and reference
        // quantization, in addition to the explicit endpoint uncertainty.
        let budget = self.high.max(other.high) / 100 + QUANTIZATION_NS;
        self.low <= self.high && other.low <= other.high &&
            self.low <= other.high.saturating_add(budget) &&
            other.low <= self.high.saturating_add(budget)
    }
}

impl TscBracket {
    pub fn new(before: Witness, after: Witness) -> Option<Self> {
        if before.cpu != after.cpu || before.hz == 0 || before.hz != after.hz {
            return None;
        }
        let hz = before.hz as u128;
        if after.ticks.checked_sub(before.ticks)? as u128 * NS_PER_SECOND >
                hz * MAX_BRACKET_NS ||
           before.uncertainty_ticks.max(after.uncertainty_ticks) as u128 * NS_PER_SECOND >
                hz * MAX_UNCERTAINTY_NS {
            return None;
        }
        Some(Self {
            low: before.ticks.checked_sub(before.uncertainty_ticks)?,
            high: after.ticks.checked_add(after.uncertainty_ticks)?,
            hz: before.hz,
        })
    }

    pub fn elapsed(self, last: Self) -> Option<Span> {
        if self.hz != last.hz { return None; }
        let low = last.low.saturating_sub(self.high) as u128;
        let high = last.high.checked_sub(self.low)? as u128;
        // Outward rounding: the result must enclose the real interval.
        let hz = self.hz as u128;
        Some(Span { low: low * NS_PER_SECOND / hz,
                    high: (high * NS_PER_SECOND + hz - 1) / hz })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    AllAgree,
    ActiveAndTsc,
    StandbyAndTsc,
    PhysicalAgree,
    TscRejected,
    Ambiguous,
}

/// None is missing/invalid evidence, not a zero-length interval. A
/// non-transitive overlap with both physical counters in agreement cannot
/// prove a faulty TSC. Conversely, if both disagree but overlap TSC,
/// its uncertainty is too large to choose either one.
pub(crate) fn decide(active: Option<Span>, standby: Option<Span>,
                     tsc: Option<Span>) -> Verdict {
    let agrees = |a: Option<Span>, b: Option<Span>| {
        match (a, b) { (Some(a), Some(b)) => a.agrees(b), _ => false }
    };
    match (agrees(active, standby), agrees(active, tsc), agrees(standby, tsc)) {
        (true, true, true) => Verdict::AllAgree,
        (true, false, false) => Verdict::TscRejected,
        (true, _, _) => Verdict::PhysicalAgree,
        (false, true, false) => Verdict::ActiveAndTsc,
        (false, false, true) => Verdict::StandbyAndTsc,
        _ => Verdict::Ambiguous,
    }
}
