# Drivers

Most of Linux is drivers: about two thirds of the source tree by line count. No new kernel matches that, and rukernel does not try. It has to drive the machines kernels actually run on in 2026, in the order users meet them, and for each device it supports it has to present exactly the user space interface the Linux driver presents. This document says which devices, in which order, how drivers are written, what we do about GPUs, and why Linux's own driver binaries cannot be loaded.

## 12.1 How a driver is written

The device model is Linux's as seen from user space:

- Buses, devices, drivers and classes in sysfs.
- uevents with `MODALIAS` strings, so udev rules match.
- Driver binding by ID tables in the same `modalias` format, so `modules.alias` lists the names user space expects.
- Runtime power management states under `power/`.

Inside, a driver is a safe Rust crate (`rk-drv-*`) over `rk-frame`'s hardware abstractions:

- **`Mmio<T>`**: a typed register block whose fields are read and written through volatile accessors, generated from a register description.
- **`DmaBuffer<T>` and `DmaPool`**: coherent and streaming DMA through the IOMMU, with ownership modelling who may touch the buffer: CPU or device, mapped or unmapped.
- **`IrqHandler`**: MSI and MSI-X vectors with affinity, and a threaded handler option. The hard IRQ part receives a `&HardIrq` token that cannot sleep.
- **`PciDevice`, `PlatformDevice` and `UsbInterface`**: the bus bindings, with config space access through typed views.
- **Firmware loading** from `/lib/firmware` through the same request interface, so distribution firmware packages work unchanged.

The rule from document 03.1 applies: drivers contain no `unsafe`. A device is still trusted to a degree the IOMMU defines. A driver bug is a logic bug in safe code, which can hang a device but cannot corrupt kernel memory.

## 12.2 Virtual hardware first

Most kernels in 2026 run as guests. virtio is a published standard (OASIS virtio 1.3) and is the cheapest path to a usable system. In order:

1. virtio-console and virtio-serial
2. virtio-blk
3. virtio-net, with multiqueue and offloads
4. virtio-rng
5. virtio-pci (modern and legacy), virtio-mmio for Firecracker and microvm
6. virtio-fs (DAX optional) and 9p
7. virtio-vsock
8. virtio-balloon with free page reporting
9. virtio-gpu, with 3D through virgl and Venus (Vulkan) and the native context type for passthrough of host GPU contexts
10. virtio-input, virtio-sound, virtio-iommu, virtio-mem and virtio-pmem

Beyond virtio, the devices common hypervisors present:

- QEMU's `q35` chipset: AHCI, the PCIe root ports, e1000e for old images, and bochs-display.
- Firecracker's minimal set.
- Cloud Hypervisor.
- Hyper-V's VMBus devices (netvsc, storvsc, hv_balloon, hv_kvp) for Azure.
- Xen PV front ends for the remaining Xen clouds.
- AWS ENA and NVMe.
- Google gVNIC and NVMe.

With these, rukernel runs on every major cloud.

## 12.3 Real hardware, the server list

In priority order, each with its Linux driver's user space interface (ethtool, devlink, nvme-cli, the sysfs attributes):

1. **NVMe** over PCIe (document 09.2).
2. **Intel NICs:** ice (E810), igb, igc and ixgbe. These cover most on board server and workstation networking.
3. **Mellanox and NVIDIA ConnectX:** mlx5 (ConnectX-5 to 8). This is the dominant high speed NIC, and the reference for header split, zcrx and devmem.
4. **Broadcom:** bnxt_en.
5. **AHCI SATA** and the generic **xHCI** USB host, with USB storage (UAS), HID and CDC-ECM/NCM networking.
6. **Platform:** ACPI, the PCIe AER and DPC error handling, IPMI (ipmi_si) and BMC interfaces, EDAC for memory errors, hwmon for the common sensor chips, and CPU frequency and idle (intel_pstate, amd-pstate, cpuidle with the intel_idle and ACPI drivers).
7. **RAID and HBA:** megaraid_sas and mpt3sas. These are the most common in older fleet servers, and come at R10.

## 12.4 GPUs and the desktop

Graphics is the hardest driver problem. A modern GPU driver is larger than most kernels: amdgpu with its display code is over 5 million lines, including generated register headers. The user space contract is also unusually wide. Mesa, the vendor drivers and the compositors talk to the kernel through DRM, KMS, GEM and the driver's private ioctls, and both sides change together.

The strategy has four parts.

**One: DRM core and KMS are ours.** The DRM core ioctls are implemented in full: the mode setting objects, atomic commit, dumb buffers, PRIME and dmabuf, syncobj and timeline syncobj, render nodes, the `drm_info` and `drm_fdinfo` interfaces, and the generic GPU scheduler semantics as user space sees them. So are fbdev emulation, simpledrm and efifb for early boot, and the drm_panic screen. This is the part every compositor (Mutter, KWin, wlroots, Weston) and every Mesa driver relies on.

**Two: virtual GPUs first.** virtio-gpu with Venus gives Vulkan in a VM by passing the host GPU through, with near native performance for many workloads. This is how the Windows personality (document 16.3) runs Proton games before rukernel drives any real GPU. Running Proton over Venus on a Linux host is already a supported configuration, so its results can be compared directly.

**Three: real GPU drivers, written natively, in this order:**

1. **Intel xe.** It is the newest Intel driver, with a clean design built around the DRM GPU scheduler, firmware based submission (GuC), and published hardware documentation.
2. **AMD amdgpu**, for RDNA 2 and later only. The display core, SMU power management and firmware loading are a large but documented body of work, and the ISA and register documentation is public.
3. **Arm Mali (Panthor class)** and **Apple AGX**, as the arm64 laptops in document 15 come in. Both have Rust drivers in or near mainline (Tyr, Asahi's driver) whose designs we can follow.
4. **NVIDIA through nova.** NVIDIA's GSP firmware does most of the work. The open kernel driver, the Rust nova driver in mainline and the published GSP interface make a native driver feasible. It is the last of the four because the interface is still settling upstream.

Each driver presents its Linux driver's exact private ioctl set, so the unmodified Mesa drivers (iris and anv for Intel, radeonsi and radv for AMD, panfrost and panvk, asahi and honeykrisp, and NVK) run against it. Mesa's own test suite and dEQP, the Khronos conformance suite, run on both kernels.

**Four: the driver host, for everything else.** Section 12.5.

## 12.5 The Linux driver host (optional, off by default)

There will always be a device whose only driver is Linux's C driver. The question is whether that device must be unusable on rukernel. The driver host is the answer for devices where "slower and isolated" beats "unsupported".

The idea follows DD/OS (OSDI 2004), FreeBSD's LinuxKPI, and the 2026 work on μUSB. A driver host runs unmodified Linux driver source, compiled by rucc or GCC against a small Linux shim kernel library (`lkl`-style), in a sandboxed process. That process is an ordinary user space process with:

- the device's MMIO regions mapped in through VFIO,
- DMA restricted by the IOMMU to the host's own memory,
- interrupts delivered through eventfds,
- and the driver's user facing interface (a netdev, a block device, a DRM device, an input device) exported back to the kernel through a narrow, typed channel that rukernel's corresponding subsystem treats like any other driver.

This is how rucc fits in: rucc compiles the Linux driver C, rucc-kernel already builds and boots pinned Linux kernels, and the shim is built from the same pinned tree.

**What it costs:**

- A process boundary per interaction. That is fine for Wi-Fi, a printer, an old capture card, a fingerprint reader. It is not fine for a 100 GbE NIC.
- Device interrupts through a user space wakeup, which adds tens of microseconds.

**What it buys:** a broken or malicious driver crashes a process, not the kernel.

**Licensing:** the hosted driver is GPL-2.0 Linux code running in a GPL-2.0 user space process, communicating with a GPL-2.0 kernel. There is no licence question.

**Why it is off by default:**

- It adds C to the trusted path of whatever device it drives, even if not to the kernel's trusted base.
- It is a temptation to stop writing native drivers.

Every device that ships in a default profile has a native driver. The host is a bridge for the long tail, and its use is visible: `/sys/kernel/rukernel/driver_host/*` lists what it is driving.

## 12.6 Why a Linux `.ko` cannot be loaded

People ask, so the answer is written down.

A Linux kernel module is compiled against one kernel build's internal interfaces:

- the layout of `struct task_struct`, `struct sk_buff` and `struct page` and thousands of others,
- inline functions and macros expanded at compile time against those layouts,
- static keys, static calls and alternatives patched at load time,
- the exported symbol table (`EXPORT_SYMBOL_GPL` and its namespaces) with versioned CRCs (`MODVERSIONS`) that refuse a module built against a different kernel,
- and the calling convention, including Linux's Rust ABI, which is unstable even between Linux builds.

Linux deliberately has no stable in kernel ABI (`Documentation/process/stable-api-nonsense.rst`), and even Linux refuses a module built for a different Linux configuration.

To load a `.ko`, rukernel would have to *be* that Linux build in memory: every structure laid out the same, every exported function with the same semantics. At that point it is Linux, not a reimplementation.

So:

- `init_module` and `finit_module` on a Linux module return `ENOEXEC`, which is what Linux returns for a module that fails its format checks.
- `modprobe` of a name that is built in succeeds through `modules.builtin` (document 03.7).
- `modprobe` of a name that is not built in fails with the same message as a missing module on Linux.

Out of tree modules users care about are each a separate case:

- **NVIDIA's proprietary driver:** use nova or the open GPU kernel module design, through the native driver plan.
- **VirtualBox:** use KVM.
- **ZFS:** see document 24.
- **v4l2loopback and similar:** reimplemented natively when they reach the corpus.

The driver host can run the source of a GPL out of tree module. It cannot run a binary only one.

## 12.7 Laptops and desktops

The desktop profile follows the server list and the GPU plan above, and adds the devices a laptop needs:

- **Wi-Fi:** Intel iwlwifi, MediaTek mt7921/mt7925 and Qualcomm ath11k/ath12k, through cfg80211 and mac80211 (document 10.9).
- **Bluetooth:** btusb.
- **Audio:** HDA Intel, SOF (Sound Open Firmware, which most Intel and AMD laptops since 2020 need), USB audio, and ALSA's full user interface for PipeWire.
- **Input and sensors:** i2c-hid touchpads, the HID quirk drivers including HID-BPF programs, webcams through uvcvideo and the IPU6 pipeline through libcamera, and battery and AC through ACPI.
- **Platform drivers:** thinkpad_acpi, asus-wmi, dell-wmi and the framework laptop EC.
- **Firmware updates** through the fwupd interfaces.

Document 22 orders the laptop list. The reference laptops are a Framework 13 (AMD), a ThinkPad X1 Carbon (Intel), and an Apple M2 under Asahi's boot chain.
