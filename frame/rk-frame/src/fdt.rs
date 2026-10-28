//! The flattened device tree, per the Devicetree Specification v0.4 chapter 5.
//!
//! The boot loader of arm64 gives the device tree, per spec/15-boot-and-platform.md section 15.4.
//! The boot path reads the memory, the reserved memory, the command line, the initramfs, the PSCI
//! method, the CPUs and the addresses of the devices that rk-frame drives from it: the PL011 UART,
//! the GICv2 or the GICv3 with its ITS, the interrupt of the virtual timer, the PL031 RTC and the
//! ECAM of a generic PCI host, with its memory windows, the interrupts of its INTx pins and its
//! `msi-map`. It also keeps the virtio MMIO
//! devices and their interrupts for the virtio drivers.
//! The full binding set comes later.

use crate::addr::PhysAddr;
use crate::boot::{BootInfo, MemoryKind};

/// The largest device tree that the kernel reads. Linux has the same limit on arm64.
pub(crate) const MAX_SIZE: usize = 2 << 20;

const MAGIC: u32 = 0xd00d_feed;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;
const END: u32 = 9;

/// The deepest node that the walk keeps the name of. The nodes that the boot path reads are at
/// depth 1, and the ITS is at depth 2 under the GIC.
const MAX_DEPTH: usize = 16;
/// The most memory ranges and reserved ranges that the boot path keeps.
const MAX_RANGES: usize = 32;

/// The most CPUs that the boot path keeps from the `/cpus` node.
pub(crate) const MAX_CPUS: usize = 64;

/// The most virtio MMIO devices that the boot path keeps. QEMU `virt` has 32.
pub(crate) const MAX_VIRTIO_MMIO: usize = 32;

/// The most entries of the `interrupt-map` of the PCI host that the boot path keeps. QEMU `virt`
/// has 16: four pins of four slots.
pub(crate) const MAX_PCI_INTX: usize = 32;

/// An interrupt of the GIC: the interrupt number and the trigger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Irq {
    /// The interrupt number. An SPI starts at 32 and a PPI at 16.
    pub(crate) intid: u32,
    /// The interrupt is edge triggered. Else it is level triggered.
    pub(crate) edge: bool,
}

/// One entry of the `interrupt-map` of the PCI host: the INTx pin of a slot and its interrupt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PciIntx {
    /// The first cell of the PCI address of the slot, after the mask: the bus, the device and the
    /// function.
    pub(crate) addr: u32,
    /// The pin: 1 to 4 for INTA to INTD.
    pub(crate) pin: u32,
    /// The interrupt of the pin.
    pub(crate) irq: Irq,
}

/// What the boot path needs from the device tree, apart from the `BootInfo`. A device that the
/// device tree does not give is `None`, and the caller uses the address of QEMU `virt` then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Platform {
    /// The PSCI calls use `smc`. Without this, they use `hvc`.
    pub(crate) psci_smc: bool,
    /// The physical address of the PL011 UART.
    pub(crate) uart: Option<u64>,
    /// The physical addresses of the GICv2 distributor and CPU interface.
    pub(crate) gic: Option<(u64, u64)>,
    /// The physical addresses of the GICv3 distributor and of the redistributor region, and the
    /// length of the region.
    pub(crate) gic_v3: Option<(u64, u64, u64)>,
    /// The physical address of the first GICv3 ITS.
    pub(crate) gic_its: Option<u64>,
    /// The first entry of the `msi-map` of the PCI host: the first requester ID, the first device
    /// ID of the ITS for it, and the number of IDs. A host with no `msi-map` gives each function
    /// its requester ID as the device ID.
    pub(crate) pci_msi_map: Option<(u32, u32, u32)>,
    /// The interrupt number of the virtual timer of EL1.
    pub(crate) timer_intid: Option<u32>,
    /// The physical address of the PL031 RTC.
    pub(crate) rtc: Option<u64>,
    /// The physical address and the size of the ECAM of a generic PCI host.
    pub(crate) pci_ecam: Option<(u64, u64)>,
    /// The 32 bit memory window of the PCI host, as the address and the size. The CPU and the PCI
    /// bus see the window at the same address. A window at other addresses is not kept.
    pub(crate) pci_mem: Option<(u64, u64)>,
    /// The 64 bit memory window of the PCI host, as `pci_mem`.
    pub(crate) pci_mem64: Option<(u64, u64)>,
    /// The masks of the PCI address and of the pin for `pci_intx`.
    pub(crate) pci_intx_mask: (u32, u32),
    /// The interrupts of the INTx pins of the PCI host. The first `pci_intx_count` are valid.
    pub(crate) pci_intx: [PciIntx; MAX_PCI_INTX],
    /// The number of entries in `pci_intx`.
    pub(crate) pci_intx_count: usize,
    /// The MPIDR affinity of each CPU, in the order of the device tree. The first `cpu_count` are
    /// valid.
    pub(crate) cpus: [u64; MAX_CPUS],
    /// The number of CPUs in `cpus`.
    pub(crate) cpu_count: usize,
    /// The physical address, the size and the interrupt of each virtio MMIO device, in the order
    /// of the device tree. The first `virtio_mmio_count` are valid.
    pub(crate) virtio_mmio: [(u64, u64, Option<Irq>); MAX_VIRTIO_MMIO],
    /// The number of devices in `virtio_mmio`.
    pub(crate) virtio_mmio_count: usize,
}

impl Default for Platform {
    fn default() -> Self {
        Self {
            psci_smc: false,
            uart: None,
            gic: None,
            gic_v3: None,
            gic_its: None,
            pci_msi_map: None,
            timer_intid: None,
            rtc: None,
            pci_ecam: None,
            pci_mem: None,
            pci_mem64: None,
            pci_intx_mask: (0, 0),
            pci_intx: [PciIntx::default(); MAX_PCI_INTX],
            pci_intx_count: 0,
            cpus: [0; MAX_CPUS],
            cpu_count: 0,
            virtio_mmio: [(0, 0, None); MAX_VIRTIO_MMIO],
            virtio_mmio_count: 0,
        }
    }
}

/// The properties of a node at depth 1 that tell which device it is and where.
#[derive(Clone, Copy, Default)]
struct Node<'a> {
    name: &'a str,
    compatible: &'a [u8],
    reg: &'a [u8],
    interrupts: &'a [u8],
    status: &'a [u8],
    ranges: &'a [u8],
    interrupt_map: &'a [u8],
    interrupt_map_mask: &'a [u8],
    msi_map: &'a [u8],
    /// The `#address-cells`, `#size-cells` and `#interrupt-cells` of the children of the node.
    address_cells: Option<u32>,
    size_cells: Option<u32>,
    interrupt_cells: Option<u32>,
}

/// The parts of the device tree that the boot path reads after the walk, because they need the
/// properties of a node that can come later.
#[derive(Default)]
struct Later<'a> {
    /// The `interrupt-map` and `interrupt-map-mask` of the PCI host, and the cells of its PCI
    /// addresses and of its interrupts.
    pci_map: &'a [u8],
    pci_map_mask: &'a [u8],
    pci_cells: (u32, u32),
    /// The `#address-cells` and `#interrupt-cells` of the GIC.
    gic_cells: (u32, u32),
}

impl<'a> Node<'a> {
    /// Tells if `name` is one of the strings of the `compatible` property.
    fn is(&self, name: &str) -> bool {
        self.compatible.split(|&b| b == 0).any(|c| c == name.as_bytes())
    }

    /// Tells if the device is on. A node with no `status` is on.
    fn enabled(&self) -> bool {
        self.status.is_empty()
            || self.status.starts_with(b"okay")
            || self.status.starts_with(b"ok\0")
    }

    /// The address and the size of entry `n` of `reg`.
    fn reg(&self, n: usize, addr_cells: u32, size_cells: u32) -> Option<(u64, u64)> {
        let at = n * 4 * (addr_cells + size_cells) as usize;
        let start = cells(self.reg, at, addr_cells)?;
        let len = if size_cells == 0 {
            0
        } else {
            cells(self.reg, at + 4 * addr_cells as usize, size_cells)?
        };
        Some((start, len))
    }

    /// Keeps the device of this node in `platform`, if rk-frame drives it.
    fn finish(
        &self,
        platform: &mut Platform,
        later: &mut Later<'a>,
        addr_cells: u32,
        size_cells: u32,
    ) {
        if self.name.is_empty() || !self.enabled() {
            return;
        }
        let first = self.reg(0, addr_cells, size_cells);
        if self.is("arm,pl011") && platform.uart.is_none() {
            platform.uart = first.map(|r| r.0);
        } else if self.is("arm,pl031") && platform.rtc.is_none() {
            platform.rtc = first.map(|r| r.0);
        } else if self.is("virtio,mmio") {
            if let Some(r) = first.filter(|_| platform.virtio_mmio_count < MAX_VIRTIO_MMIO) {
                platform.virtio_mmio[platform.virtio_mmio_count] =
                    (r.0, r.1, gic_irq(self.interrupts, 0));
                platform.virtio_mmio_count += 1;
            }
        } else if self.is("pci-host-ecam-generic") && platform.pci_ecam.is_none() {
            platform.pci_ecam = first;
            self.pci_windows(platform, addr_cells);
            later.pci_map = self.interrupt_map;
            later.pci_map_mask = self.interrupt_map_mask;
            later.pci_cells = (self.address_cells.unwrap_or(3), self.interrupt_cells.unwrap_or(1));
            // An entry has the first requester ID, the phandle of the ITS, the first device ID
            // and the number of IDs. The boot path takes the first ITS as the ITS of the entry.
            if let (Some(rid), Some(id), Some(len)) =
                (be32(self.msi_map, 0), be32(self.msi_map, 8), be32(self.msi_map, 12))
            {
                platform.pci_msi_map = Some((rid, id, len));
            }
        } else if self.is("arm,gic-v3") {
            if let (Some(d), Some(r)) = (first, self.reg(1, addr_cells, size_cells)) {
                platform.gic_v3 = Some((d.0, r.0, r.1));
            }
            later.gic_cells = (self.address_cells.unwrap_or(0), self.interrupt_cells.unwrap_or(3));
        } else if self.is("arm,cortex-a15-gic") || self.is("arm,gic-400") {
            if let (Some(d), Some(c)) = (first, self.reg(1, addr_cells, size_cells)) {
                platform.gic = Some((d.0, c.0));
            }
            later.gic_cells = (self.address_cells.unwrap_or(0), self.interrupt_cells.unwrap_or(3));
        } else if self.is("arm,armv8-timer") || self.is("arm,armv7-timer") {
            // The interrupts are the secure physical, the physical, the virtual and the
            // hypervisor timers, with three cells each: the kind, the number and the flags. A
            // PPI number starts at 16.
            let kind = be32(self.interrupts, 24);
            let number = be32(self.interrupts, 28);
            if let (Some(1), Some(n)) = (kind, number) {
                platform.timer_intid = Some(n + 16);
            }
        }
    }

    /// Keeps the device of this node at depth 2 in `platform`, if rk-frame drives it. `cells` are
    /// the `#address-cells` and `#size-cells` of the parent.
    fn finish_child(&self, platform: &mut Platform, cells: (u32, u32)) {
        if self.name.is_empty() || !self.enabled() {
            return;
        }
        if self.is("arm,gic-v3-its") && platform.gic_its.is_none() {
            platform.gic_its = self.reg(0, cells.0, cells.1).map(|r| r.0);
        }
    }

    /// Keeps the memory windows of the `ranges` of a PCI host. An entry has the PCI address in
    /// `#address-cells` of the node (3), the CPU address in `parent_cells`, and the size in
    /// `#size-cells` of the node (2). Bits 24 and 25 of the first cell give the space: 2 for 32
    /// bit memory and 3 for 64 bit memory.
    fn pci_windows(&self, platform: &mut Platform, parent_cells: u32) {
        let (child, size) = (self.address_cells.unwrap_or(3), self.size_cells.unwrap_or(2));
        if child != 3 {
            return;
        }
        let stride = 4 * (child + parent_cells + size) as usize;
        for at in (0..self.ranges.len()).step_by(stride.max(4)) {
            let (Some(hi), Some(pci), Some(cpu), Some(len)) = (
                be32(self.ranges, at),
                cells(self.ranges, at + 4, 2),
                cells(self.ranges, at + 12, parent_cells),
                cells(self.ranges, at + 4 * (child + parent_cells) as usize, size),
            ) else {
                break;
            };
            if pci != cpu || len == 0 {
                continue;
            }
            match hi >> 24 & 3 {
                2 if platform.pci_mem.is_none() => platform.pci_mem = Some((cpu, len)),
                3 if platform.pci_mem64.is_none() => platform.pci_mem64 = Some((cpu, len)),
                _ => {}
            }
        }
    }
}

impl Later<'_> {
    /// Reads the `interrupt-map` of the PCI host into `platform`. An entry has the PCI address
    /// and the pin, the phandle of the GIC, the address of the GIC in its `#address-cells`, and
    /// the interrupt of the GIC in its `#interrupt-cells` (3). The boot path takes the GIC as the
    /// parent of each entry, as on QEMU `virt`.
    fn finish(&self, platform: &mut Platform) {
        let (addr, intr) = self.pci_cells;
        let (gic_addr, gic_intr) = self.gic_cells;
        if addr != 3 || intr != 1 || gic_intr != 3 {
            return;
        }
        platform.pci_intx_mask =
            (be32(self.pci_map_mask, 0).unwrap_or(0), be32(self.pci_map_mask, 12).unwrap_or(0));
        let stride = 4 * (addr + intr + 1 + gic_addr + gic_intr) as usize;
        for at in (0..self.pci_map.len()).step_by(stride) {
            if platform.pci_intx_count == MAX_PCI_INTX {
                break;
            }
            let spec = at + 4 * (addr + intr + 1 + gic_addr) as usize;
            let (Some(hi), Some(pin), Some(irq)) =
                (be32(self.pci_map, at), be32(self.pci_map, at + 12), gic_irq(self.pci_map, spec))
            else {
                break;
            };
            platform.pci_intx[platform.pci_intx_count] = PciIntx { addr: hi, pin, irq };
            platform.pci_intx_count += 1;
        }
    }
}

/// Reads the interrupt of three cells at `at` of `b`: the kind (0 for an SPI, 1 for a PPI), the
/// number and the flags. Bits 0 to 3 of the flags are 1 or 2 for an edge, and 4 or 8 for a level.
fn gic_irq(b: &[u8], at: usize) -> Option<Irq> {
    let (kind, number, flags) = (be32(b, at)?, be32(b, at + 4)?, be32(b, at + 8)?);
    let intid = match kind {
        0 => number.checked_add(32)?,
        1 => number.checked_add(16)?,
        _ => return None,
    };
    Some(Irq { intid, edge: matches!(flags & 0xf, 1 | 2) })
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// Reads a number of one or two cells.
fn cells(b: &[u8], at: usize, n: u32) -> Option<u64> {
    match n {
        1 => be32(b, at).map(u64::from),
        2 => be64(b, at),
        _ => None,
    }
}

/// The string at `at` up to its NUL byte.
fn cstr(b: &[u8], at: usize) -> Option<&str> {
    let rest = b.get(at..)?;
    let len = rest.iter().position(|&c| c == 0)?;
    core::str::from_utf8(&rest[..len]).ok()
}

/// Calls `f` with the depth of the node, the name of the node, the name of the property and the
/// value, for each property of the structure block. The root node has depth 0 and the name "".
fn walk<'a>(
    structs: &'a [u8],
    strings: &'a [u8],
    mut f: impl FnMut(usize, &'a str, &'a str, &'a [u8]),
) -> Result<(), &'static str> {
    const BAD: &str = "the structure block is not correct";
    let mut names = [""; MAX_DEPTH];
    let mut depth = 0;
    let mut at = 0;
    loop {
        let token = be32(structs, at).ok_or(BAD)?;
        at += 4;
        match token {
            BEGIN_NODE => {
                let name = cstr(structs, at).ok_or(BAD)?;
                at = (at + name.len() + 1).next_multiple_of(4);
                if let Some(slot) = names.get_mut(depth) {
                    *slot = name;
                }
                depth += 1;
            }
            END_NODE => depth = depth.checked_sub(1).ok_or(BAD)?,
            PROP => {
                let len = be32(structs, at).ok_or(BAD)? as usize;
                let name = be32(structs, at + 4).ok_or(BAD)? as usize;
                at += 8;
                let value = structs.get(at..at + len).ok_or(BAD)?;
                at = (at + len).next_multiple_of(4);
                let node = depth.checked_sub(1).ok_or(BAD)?;
                let prop = cstr(strings, name).ok_or(BAD)?;
                f(node, names.get(node).copied().unwrap_or(""), prop, value);
            }
            NOP => {}
            END => return Ok(()),
            _ => return Err(BAD),
        }
    }
}

/// A list of physical ranges, as start and length.
struct Ranges {
    list: [(u64, u64); MAX_RANGES],
    len: usize,
}

impl Ranges {
    fn new() -> Self {
        Self { list: [(0, 0); MAX_RANGES], len: 0 }
    }

    fn push(&mut self, start: u64, len: u64) {
        if len > 0 && self.len < MAX_RANGES {
            self.list[self.len] = (start, len);
            self.len += 1;
        }
    }

    fn sorted(&mut self) -> &[(u64, u64)] {
        let list = &mut self.list[..self.len];
        list.sort_unstable();
        list
    }
}

/// Reads the device tree `blob`, at the physical address `phys`, into `info`. The memory map has
/// the memory nodes, with the device tree and the `/memreserve/` entries as reserved ranges.
// TODO: the `/reserved-memory` node, and `/chosen/stdout-path` for the console.
pub(crate) fn read(blob: &[u8], phys: u64, info: &mut BootInfo) -> Result<Platform, &'static str> {
    const HEADER: &str = "the header is not correct";
    if be32(blob, 0) != Some(MAGIC) {
        return Err("no device tree magic");
    }
    let field = |n: usize| be32(blob, 4 * n).map(|v| v as usize).ok_or(HEADER);
    let size = field(1)?;
    let (off_struct, off_strings, off_rsvmap) = (field(2)?, field(3)?, field(4)?);
    let (version, last_compatible) = (field(5)?, field(6)?);
    let (size_strings, size_struct) = (field(8)?, field(9)?);
    if size > blob.len() || size > MAX_SIZE || version < 16 || last_compatible > 17 {
        return Err(HEADER);
    }
    let blob = &blob[..size];
    let structs = blob.get(off_struct..off_struct + size_struct).ok_or(HEADER)?;
    let strings = blob.get(off_strings..off_strings + size_strings).ok_or(HEADER)?;

    let mut reserved = Ranges::new();
    reserved.push(phys, size as u64);
    let mut at = off_rsvmap;
    loop {
        let start = be64(blob, at).ok_or(HEADER)?;
        let len = be64(blob, at + 8).ok_or(HEADER)?;
        if start == 0 && len == 0 {
            break;
        }
        reserved.push(start, len);
        at += 16;
    }

    let mut platform = Platform::default();
    let mut ram = Ranges::new();
    let (mut addr_cells, mut size_cells) = (2, 1);
    let mut cpu_cells = 1;
    let (mut initrd_start, mut initrd_end) = (None, None);
    let number = |v: &[u8]| cells(v, 0, (v.len() / 4) as u32);
    // The properties of one node come together, before its children. So a node at depth 1 is
    // complete when a property of another node at depth 1 comes.
    let mut node = Node::default();
    // A node at depth 2, and the cells of its parent. Only the ITS under the GIC is read.
    let mut child = Node::default();
    let mut child_cells = (2, 1);
    let mut later = Later::default();
    walk(structs, strings, |depth, name, prop, value| {
        if depth == 1 && !core::ptr::eq(name, node.name) {
            child.finish_child(&mut platform, child_cells);
            child = Node::default();
            node.finish(&mut platform, &mut later, addr_cells, size_cells);
            node = Node { name, ..Node::default() };
        }
        if depth == 2 && !core::ptr::eq(name, child.name) {
            child.finish_child(&mut platform, child_cells);
            child = Node { name, ..Node::default() };
            // The properties of the parent come before its children.
            child_cells = (node.address_cells.unwrap_or(2), node.size_cells.unwrap_or(1));
        }
        match (depth, prop) {
            (2, "compatible") => child.compatible = value,
            (2, "reg") => child.reg = value,
            (2, "status") => child.status = value,
            _ => {}
        }
        match (depth, prop) {
            (1, "compatible") => node.compatible = value,
            (1, "reg") => node.reg = value,
            (1, "interrupts") => node.interrupts = value,
            (1, "status") => node.status = value,
            (1, "ranges") => node.ranges = value,
            (1, "interrupt-map") => node.interrupt_map = value,
            (1, "interrupt-map-mask") => node.interrupt_map_mask = value,
            (1, "msi-map") => node.msi_map = value,
            (1, "#address-cells") => node.address_cells = be32(value, 0),
            (1, "#size-cells") => node.size_cells = be32(value, 0),
            (1, "#interrupt-cells") => node.interrupt_cells = be32(value, 0),
            _ => {}
        }
        match (depth, prop) {
            (1, "#address-cells") if name == "cpus" => cpu_cells = be32(value, 0).unwrap_or(1),
            (2, "reg") if name.starts_with("cpu@") && platform.cpu_count < MAX_CPUS => {
                if let Some(id) = cells(value, 0, cpu_cells) {
                    platform.cpus[platform.cpu_count] = id;
                    platform.cpu_count += 1;
                }
            }
            _ => {}
        }
        let node = name;
        match (depth, prop) {
            // The properties of a node come before its children, so the cells are known before the
            // memory nodes.
            (0, "#address-cells") => addr_cells = be32(value, 0).unwrap_or(2),
            (0, "#size-cells") => size_cells = be32(value, 0).unwrap_or(1),
            (1, "reg") if node == "memory" || node.starts_with("memory@") => {
                let stride = 4 * (addr_cells + size_cells) as usize;
                for at in (0..value.len()).step_by(stride.max(4)) {
                    let start = cells(value, at, addr_cells);
                    let len = cells(value, at + 4 * addr_cells as usize, size_cells);
                    if let (Some(start), Some(len)) = (start, len) {
                        ram.push(start, len);
                    }
                }
            }
            (1, "bootargs") if node == "chosen" => {
                for &b in value.iter().take_while(|&&b| b != 0) {
                    if !info.push_cmdline_byte(b) {
                        break;
                    }
                }
            }
            (1, "linux,initrd-start") if node == "chosen" => initrd_start = number(value),
            (1, "linux,initrd-end") if node == "chosen" => initrd_end = number(value),
            (1, "method") if node == "psci" => platform.psci_smc = value.starts_with(b"smc"),
            _ => {}
        }
    })?;
    child.finish_child(&mut platform, child_cells);
    node.finish(&mut platform, &mut later, addr_cells, size_cells);
    later.finish(&mut platform);
    if let (Some(start), Some(end)) = (initrd_start, initrd_end) {
        info.set_initrd(PhysAddr::new(start), end.saturating_sub(start));
    }

    // Each memory range becomes usable memory, with the reserved ranges in it as reserved memory.
    let reserved = reserved.sorted();
    for &(start, len) in ram.sorted() {
        let end = start.saturating_add(len);
        let mut cursor = start;
        for &(rs, rl) in reserved {
            let re = rs.saturating_add(rl);
            if re <= cursor || rs >= end {
                continue;
            }
            if rs > cursor {
                info.push_region(PhysAddr::new(cursor), rs - cursor, MemoryKind::Usable);
            }
            let from = rs.max(cursor);
            let to = re.min(end);
            info.push_region(PhysAddr::new(from), to - from, MemoryKind::Reserved);
            cursor = to;
        }
        info.push_region(PhysAddr::new(cursor), end - cursor, MemoryKind::Usable);
    }
    Ok(platform)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::boot::MemoryRegion;
    use std::vec::Vec;

    /// Makes a device tree blob.
    #[derive(Default)]
    struct Builder {
        structs: Vec<u8>,
        strings: Vec<u8>,
    }

    impl Builder {
        fn word(&mut self, w: u32) {
            self.structs.extend_from_slice(&w.to_be_bytes());
        }

        fn pad(&mut self) {
            while !self.structs.len().is_multiple_of(4) {
                self.structs.push(0);
            }
        }

        fn begin(&mut self, name: &str) {
            self.word(BEGIN_NODE);
            self.structs.extend_from_slice(name.as_bytes());
            self.structs.push(0);
            self.pad();
        }

        fn end(&mut self) {
            self.word(END_NODE);
        }

        fn prop(&mut self, name: &str, value: &[u8]) {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            self.word(PROP);
            self.word(value.len() as u32);
            self.word(off);
            self.structs.extend_from_slice(value);
            self.pad();
        }

        fn finish(mut self, rsv: &[(u64, u64)]) -> Vec<u8> {
            self.word(END);
            let off_rsvmap = 40;
            let off_struct = off_rsvmap + 16 * (rsv.len() + 1);
            let off_strings = off_struct + self.structs.len();
            let size = off_strings + self.strings.len();
            let header = [
                MAGIC,
                size as u32,
                off_struct as u32,
                off_strings as u32,
                off_rsvmap as u32,
                17,
                16,
                0,
                self.strings.len() as u32,
                self.structs.len() as u32,
            ];
            let mut blob: Vec<u8> = header.iter().flat_map(|w| w.to_be_bytes()).collect();
            for &(s, l) in rsv.iter().chain([(0, 0)].iter()) {
                blob.extend_from_slice(&s.to_be_bytes());
                blob.extend_from_slice(&l.to_be_bytes());
            }
            blob.extend_from_slice(&self.structs);
            blob.extend_from_slice(&self.strings);
            blob
        }
    }

    fn be(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    fn region(start: u64, len: u64, kind: MemoryKind) -> MemoryRegion {
        MemoryRegion { start: PhysAddr::new(start), len, kind }
    }

    #[test]
    fn reads_memory_command_line_initrd_and_psci() {
        let mut b = Builder::default();
        b.begin("");
        b.prop("#address-cells", &be(&[2]));
        b.prop("#size-cells", &be(&[2]));
        b.begin("psci");
        b.prop("method", b"smc\0");
        b.end();
        b.begin("memory@40000000");
        b.prop("device_type", b"memory\0");
        b.prop("reg", &be(&[0, 0x4000_0000, 0, 0x2000_0000]));
        b.end();
        b.begin("chosen");
        b.prop("bootargs", b"console=ttyAMA0 rk.test=boot\0");
        b.prop("linux,initrd-start", &be(&[0x4800_0000]));
        b.prop("linux,initrd-end", &be(&[0, 0x4810_0000]));
        b.end();
        b.end();
        let blob = b.finish(&[(0x4100_0000, 0x1000)]);
        let mut info = BootInfo::new("test");
        let platform = read(&blob, 0x5000_0000, &mut info).unwrap();
        assert!(platform.psci_smc);
        assert_eq!(info.cmdline(), "console=ttyAMA0 rk.test=boot");
        assert_eq!(info.initrd(), Some((PhysAddr::new(0x4800_0000), 0x10_0000)));
        let dtb_len = blob.len() as u64;
        assert_eq!(
            info.memory(),
            &[
                region(0x4000_0000, 0x100_0000, MemoryKind::Usable),
                region(0x4100_0000, 0x1000, MemoryKind::Reserved),
                region(0x4100_1000, 0x0eff_f000, MemoryKind::Usable),
                region(0x5000_0000, dtb_len, MemoryKind::Reserved),
                region(0x5000_0000 + dtb_len, 0x1000_0000 - dtb_len, MemoryKind::Usable),
            ]
        );
    }

    #[test]
    fn reads_the_devices_and_cpus() {
        let mut b = Builder::default();
        b.begin("");
        b.prop("#address-cells", &be(&[2]));
        b.prop("#size-cells", &be(&[2]));
        b.begin("cpus");
        b.prop("#address-cells", &be(&[1]));
        b.prop("#size-cells", &be(&[0]));
        for id in [0, 1] {
            b.begin(if id == 0 { "cpu@0" } else { "cpu@1" });
            b.prop("device_type", b"cpu\0");
            b.prop("reg", &be(&[id]));
            b.end();
        }
        b.end();
        b.begin("pl011@9040000");
        b.prop("status", b"disabled\0");
        b.prop("compatible", b"arm,pl011\0arm,primecell\0");
        b.prop("reg", &be(&[0, 0x0904_0000, 0, 0x1000]));
        b.end();
        b.begin("pl011@9000000");
        b.prop("reg", &be(&[0, 0x0900_0000, 0, 0x1000]));
        b.prop("compatible", b"arm,pl011\0arm,primecell\0");
        b.end();
        // The PCI host comes before the GIC, as on QEMU `virt`, so its interrupt map is read
        // after the walk.
        b.begin("pcie@10000000");
        b.prop("interrupt-map-mask", &be(&[0x1800, 0, 0, 7]));
        b.prop(
            "interrupt-map",
            &be(&[0, 0, 0, 1, 0x8002, 0, 0, 0, 3, 4, 0x800, 0, 0, 1, 0x8002, 0, 0, 0, 4, 4]),
        );
        b.prop("#interrupt-cells", &be(&[1]));
        b.prop(
            "ranges",
            &be(&[
                0x100_0000,
                0,
                0,
                0,
                0x3eff_0000,
                0,
                0x1_0000,
                0x200_0000,
                0,
                0x1000_0000,
                0,
                0x1000_0000,
                0,
                0x2eff_0000,
                0x300_0000,
                0x80,
                0,
                0x80,
                0,
                0x80,
                0,
            ]),
        );
        b.prop("reg", &be(&[0x40, 0x1000_0000, 0, 0x1000_0000]));
        b.prop("#size-cells", &be(&[2]));
        b.prop("#address-cells", &be(&[3]));
        b.prop("compatible", b"pci-host-ecam-generic\0");
        b.end();
        b.begin("intc@8000000");
        b.prop("#address-cells", &be(&[2]));
        b.prop("#interrupt-cells", &be(&[3]));
        b.prop("compatible", b"arm,cortex-a15-gic\0");
        b.prop("reg", &be(&[0, 0x0800_0000, 0, 0x1_0000, 0, 0x0801_0000, 0, 0x1_0000]));
        b.begin("v2m@8020000");
        b.prop("compatible", b"arm,gic-v2m-frame\0");
        b.prop("reg", &be(&[0, 0x0802_0000, 0, 0x1000]));
        b.end();
        b.end();
        b.begin("timer");
        b.prop("compatible", b"arm,armv8-timer\0arm,armv7-timer\0");
        b.prop("interrupts", &be(&[1, 13, 0xf04, 1, 14, 0xf04, 1, 11, 0xf04, 1, 10, 0xf04]));
        b.end();
        b.begin("pl031@9010000");
        b.prop("compatible", b"arm,pl031\0arm,primecell\0");
        b.prop("reg", &be(&[0, 0x0901_0000, 0, 0x1000]));
        b.end();
        for at in [0x0a00_0200u32, 0x0a00_0000] {
            b.begin(if at == 0x0a00_0000 { "virtio_mmio@a000000" } else { "virtio_mmio@a000200" });
            b.prop("interrupts", &be(&[0, 0x10, 1]));
            b.prop("compatible", b"virtio,mmio\0");
            b.prop("reg", &be(&[0, at, 0, 0x200]));
            b.end();
        }
        b.end();
        let blob = b.finish(&[]);
        let mut info = BootInfo::new("test");
        let p = read(&blob, 0x5000_0000, &mut info).unwrap();
        assert_eq!(p.uart, Some(0x0900_0000));
        assert_eq!(p.gic, Some((0x0800_0000, 0x0801_0000)));
        assert_eq!(p.gic_v3, None);
        assert_eq!(p.timer_intid, Some(27));
        assert_eq!(p.rtc, Some(0x0901_0000));
        assert_eq!(p.pci_ecam, Some((0x40_1000_0000, 0x1000_0000)));
        assert_eq!(&p.cpus[..p.cpu_count], &[0, 1]);
        let irq = Some(Irq { intid: 48, edge: true });
        assert_eq!(
            &p.virtio_mmio[..p.virtio_mmio_count],
            &[(0x0a00_0200, 0x200, irq), (0x0a00_0000, 0x200, irq)]
        );
        assert_eq!(p.pci_mem, Some((0x1000_0000, 0x2eff_0000)));
        assert_eq!(p.pci_mem64, Some((0x80_0000_0000, 0x80_0000_0000)));
        assert_eq!(p.pci_intx_mask, (0x1800, 7));
        let level = |intid| Irq { intid, edge: false };
        assert_eq!(
            &p.pci_intx[..p.pci_intx_count],
            &[
                PciIntx { addr: 0, pin: 1, irq: level(35) },
                PciIntx { addr: 0x800, pin: 1, irq: level(36) }
            ]
        );
    }

    #[test]
    fn reads_the_gic_v3_its_and_the_msi_map() {
        let mut b = Builder::default();
        b.begin("");
        b.prop("#address-cells", &be(&[2]));
        b.prop("#size-cells", &be(&[2]));
        b.begin("pcie@10000000");
        b.prop("msi-map", &be(&[0, 0x8004, 0x100, 0x1_0000]));
        b.prop("#address-cells", &be(&[3]));
        b.prop("compatible", b"pci-host-ecam-generic\0");
        b.prop("reg", &be(&[0x40, 0x1000_0000, 0, 0x1000_0000]));
        b.end();
        b.begin("intc@8000000");
        b.prop("compatible", b"arm,gic-v3\0");
        b.prop("#address-cells", &be(&[2]));
        b.prop("#size-cells", &be(&[2]));
        b.prop("reg", &be(&[0, 0x0800_0000, 0, 0x1_0000, 0, 0x080a_0000, 0, 0xf6_0000]));
        b.begin("its@8070000");
        b.prop("status", b"disabled\0");
        b.prop("compatible", b"arm,gic-v3-its\0");
        b.prop("reg", &be(&[0, 0x0807_0000, 0, 0x2_0000]));
        b.end();
        b.begin("its@8080000");
        b.prop("compatible", b"arm,gic-v3-its\0");
        b.prop("reg", &be(&[0, 0x0808_0000, 0, 0x2_0000]));
        b.end();
        b.end();
        b.end();
        let blob = b.finish(&[]);
        let mut info = BootInfo::new("test");
        let p = read(&blob, 0x5000_0000, &mut info).unwrap();
        assert_eq!(p.gic_v3, Some((0x0800_0000, 0x080a_0000, 0xf6_0000)));
        assert_eq!(p.gic_its, Some(0x0808_0000));
        assert_eq!(p.pci_msi_map, Some((0, 0x100, 0x1_0000)));
    }

    #[test]
    fn a_tree_with_no_devices_gives_none() {
        let mut b = Builder::default();
        b.begin("");
        b.prop("#address-cells", &be(&[2]));
        b.begin("chosen");
        b.end();
        b.end();
        let blob = b.finish(&[]);
        let mut info = BootInfo::new("test");
        let p = read(&blob, 0, &mut info).unwrap();
        assert_eq!(p, Platform::default());
    }

    #[test]
    fn rejects_a_bad_blob() {
        let mut info = BootInfo::new("test");
        assert!(read(&[0; 64], 0, &mut info).is_err());
        let mut b = Builder::default();
        b.begin("");
        b.end();
        let mut blob = b.finish(&[]);
        // A structure block with a token that does not exist.
        let at = blob.len() - 8;
        blob[at..at + 4].copy_from_slice(&7u32.to_be_bytes());
        assert!(read(&blob, 0, &mut info).is_err());
    }
}
