/*
 * reveng-pcidrv <-> pcicap shared ABI (v1).
 *
 * The driver-only ("lighter tier", DESIGN.md §4a) PCIe capture backend: a KMDF driver that
 * exposes one control device and streams fixed-width capture events to user-mode `pcicap`
 * (crates/pcicap/src/drv.rs mirrors these definitions). No hypervisor; VBS may stay on.
 *
 * Flow (mirrors the USBPcap client we already built):
 *   1. user-mode opens the control device \\.\RevengPciCap
 *   2. DeviceIoControl(IOCTL_REVENG_PCI_SET_TARGET, RevengPciTarget) — pick the device by BDF
 *   3. ReadFile() in a loop — the driver returns a stream of RevengPciEvent records
 *
 * This header is plain C so it can be included by both the KMDF driver and (as reference) the
 * Rust side. Keep it in lockstep with drv.rs.
 */
#ifndef REVENG_PCI_ABI_H
#define REVENG_PCI_ABI_H

/* User-mode path to the control device (\Device\RevengPciCap + a Win32 symlink). */
#define REVENG_PCI_USERMODE_PATH L"\\\\.\\RevengPciCap"

/* CTL_CODE(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_ANY_ACCESS). Values are frozen
 * here so the Rust side can hardcode them without the WDK headers. */
#define REVENG_PCI_SET_TARGET_CODE 0x800
#define IOCTL_REVENG_PCI_SET_TARGET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, REVENG_PCI_SET_TARGET_CODE, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Snapshot the attached filter's mapped MMIO BARs and emit an MMIO event per changed dword
 * (M3, DESIGN.md §4a). No input; the caller (DrvPcieSource live mode) issues this periodically
 * and drains the resulting events via ReadFile. Read-only: captures register *state changes*,
 * not individual driver accesses (that needs the hypervisor/EPT tier). */
#define REVENG_PCI_MMIO_SNAP_CODE 0x801
#define IOCTL_REVENG_PCI_MMIO_SNAP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, REVENG_PCI_MMIO_SNAP_CODE, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Follow the attached xHCI's Event Ring in system memory and emit a DMA event per newly-written
 * Event TRB (M4, DESIGN.md §4a — best-effort; may be defeated by IOMMU/VT-d address translation).
 * No input. Read-only; every physical address is validated against RAM ranges before mapping. */
#define REVENG_PCI_DMA_SNAP_CODE 0x802
#define IOCTL_REVENG_PCI_DMA_SNAP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, REVENG_PCI_DMA_SNAP_CODE, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Input to IOCTL_REVENG_PCI_SET_TARGET: the PCIe device to capture, by address. */
#pragma pack(push, 1)
typedef struct _REVENG_PCI_TARGET {
    unsigned short segment;  /* PCI segment/domain (usually 0)            */
    unsigned char  bus;      /* 0-255                                     */
    unsigned char  device;   /* 0-31                                      */
    unsigned char  function; /* 0-7                                       */
    unsigned char  _pad[3];
} REVENG_PCI_TARGET;
#pragma pack(pop)

/* Event kinds — map 1:1 to core::event::PcieEvent variants. */
#define REVENG_PCI_KIND_CONFIG 0
#define REVENG_PCI_KIND_MMIO   1
#define REVENG_PCI_KIND_IRQ    2
#define REVENG_PCI_KIND_DMA    3

/* Direction. */
#define REVENG_PCI_DIR_IN  0 /* read  (device -> host / CPU reads a register) */
#define REVENG_PCI_DIR_OUT 1 /* write (host -> device)                        */

/*
 * One capture event (fixed 32 bytes, little-endian, packed). The driver stamps `ts_qpc` with
 * KeQueryPerformanceCounter at the instant of the event; user-mode converts it to session ns
 * against the shared QPC timeline (the same QPC `Clock` uses elsewhere).
 *
 * Field meaning by `kind`:
 *   CONFIG: dir, width(1/2/4), offset(config space byte offset), value(read/written dword)
 *   MMIO:   dir, width, bar, offset(within BAR), value
 *   IRQ:    value = interrupt vector
 *   DMA:    dir, addr = device/bus address, value = length in bytes
 */
#pragma pack(push, 1)
typedef struct _REVENG_PCI_EVENT {
    unsigned long long ts_qpc;  /* KeQueryPerformanceCounter raw ticks */
    unsigned char      kind;    /* REVENG_PCI_KIND_*                   */
    unsigned char      dir;     /* REVENG_PCI_DIR_*                    */
    unsigned char      width;   /* access width in bytes               */
    unsigned char      bar;     /* MMIO only: BAR index                */
    unsigned int       offset;  /* config offset or MMIO offset        */
    unsigned long long value;   /* read/written value / vector / length*/
    unsigned long long addr;    /* DMA device address, else 0          */
} REVENG_PCI_EVENT;
#pragma pack(pop)

#endif /* REVENG_PCI_ABI_H */
