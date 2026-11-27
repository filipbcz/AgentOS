//! Processor identity is the full physical APIC ID, never an array index.
//! The supported number of CPUs is independent of the interrupt transport.
//! Dense slots are stable once firmware discovery is complete.
pub(crate) const MAX_CPUS: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuSlot(usize);
impl CpuSlot {
    pub(crate) fn index(self) -> usize { self.0 }
}

/// An enabled roster, ordered by full hardware identity for stable queue
/// traversal and lock ordering. Remember firmware order for AP bring-up.
pub(crate) struct CpuRoster {
    ids: [u32; MAX_CPUS],
    order: [u8; MAX_CPUS],
    count: usize,
}

impl CpuRoster {
    pub(crate) const fn new() -> Self {
        Self { ids: [0; MAX_CPUS], order: [0; MAX_CPUS], count: 0 }
    }

    pub(crate) fn ids(&self) -> &[u32] { &self.ids[..self.count] }

    pub(crate) fn slot(&self, id: u32) -> Option<CpuSlot> {
        self.ids().binary_search(&id).ok().map(CpuSlot)
    }

    pub(crate) fn id_at(&self, slot: CpuSlot) -> Option<u32> {
        self.ids().get(slot.index()).copied()
    }

    pub(crate) fn insert(&mut self, id: u32) -> Option<()> {
        // All-ones is the x2APIC broadcast destination, not a CPU.
        // A narrower implemented APIC width is a hardware constraint;
        // do not infer it from the largest ID in the firmware table.
        if id == u32::MAX || self.count == MAX_CPUS { return None; }
        let index = self.ids().binary_search(&id).err()?;
        let ordinal = u8::try_from(self.count).ok()?;
        // Shift both fields together, backwards to preserve overlapping entries.
        // Keep this bounded scalar move independent of a C memmove runtime.
        for position in (index..self.count).rev() {
            self.ids[position + 1] = self.ids[position];
            self.order[position + 1] = self.order[position];
        }
        self.ids[index] = id;
        self.order[index] = ordinal;
        self.count += 1;
        Some(())
    }

    pub(crate) fn from_ids(ids: impl IntoIterator<Item=u32>) -> Option<Self> {
        let mut roster = Self::new();
        for id in ids { roster.insert(id)?; }
        Some(roster)
    }

    pub(crate) fn firmware_order(&self) -> impl Iterator<Item=u32> + '_ {
        (0..self.count).map(move |ordinal| {
            let index = self.order[..self.count].iter().position(|&o| usize::from(o) == ordinal)
                .expect("validated CPU firmware order");
            self.id_at(CpuSlot(index)).expect("validated CPU slot")
        })
    }

    /// Only the legacy transport performs the narrowing. Membership is
    /// required even when a numerical ID would fit in the destination.
    pub(crate) fn legacy_target(&self, id: u32) -> Result<LegacyDestination, &'static [u8]> {
        self.slot(id).ok_or(b"APIC target absent or disabled" as &'static [u8])?;
        let id = u8::try_from(id).map_err(|_| b"APIC ID requires x2APIC transport" as &'static [u8])?;
        if id == u8::MAX { return Err(b"APIC ID requires x2APIC transport"); }
        Ok(LegacyDestination(id))
    }

    pub(crate) fn validate_legacy(&self, bsp: u32) -> Result<CpuSlot, &'static [u8]> {
        for &id in self.ids() { self.legacy_target(id)?; }
        self.slot(bsp).ok_or(b"BSP absent or disabled in MADT" as &'static [u8])
    }
}

/// Physical unicast destination for the existing xAPIC ICR, IOAPIC and
/// compatibility-format MSI/MSI-X. No unchecked public constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LegacyDestination(u8);
impl LegacyDestination {
    pub(crate) fn id(self) -> u8 { self.0 }
    pub(crate) fn high(self) -> u32 { u32::from(self.0) << 24 }
    pub(crate) fn msi_address(self) -> u32 { 0xfee0_0000 | (u32::from(self.0) << 12) }
}

/// ACPI Enabled is readiness at boot. Online Capable without Enabled
/// describes an offline processor and never grants it an active slot/route.
/// Records with neither bit are unusable and their contents are ignored.
pub(crate) struct CpuTopology {
    enabled: CpuRoster,
    online_capable: CpuRoster,
}

impl CpuTopology {
    pub(crate) const fn new() -> Self {
        Self { enabled: CpuRoster::new(), online_capable: CpuRoster::new() }
    }

    pub(crate) fn enabled(&self) -> &CpuRoster { &self.enabled }
    pub(crate) fn online_capable(&self) -> &CpuRoster { &self.online_capable }

    pub(crate) fn add(&mut self, id: u32, flags: u32, legacy_record: bool) -> Option<()> {
        if flags & 3 == 0 { return Some(()); }
        // ACPI 6.6 5.2.12.2 / 5.2.12.12: Online Capable is reserved
        // when Enabled is set; remaining flag bits are reserved.
        if !matches!(flags, 1 | 2) || (legacy_record && id >= 255) ||
            self.enabled.slot(id).is_some() || self.online_capable.slot(id).is_some() {
            return None;
        }
        if flags == 1 { self.enabled.insert(id) } else { self.online_capable.insert(id) }
    }
}
