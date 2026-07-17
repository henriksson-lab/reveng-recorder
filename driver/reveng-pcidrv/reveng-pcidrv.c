/*
 * reveng-pcidrv — M1 config-space capture + M2 interrupt capture (WDM).
 *
 * Two roles in one driver (DESIGN.md §4a):
 *   - Control device \\.\RevengPciCap (created in DriverEntry, non-PnP). User-mode
 *     `pcicap::DrvPcieSource` opens it, optionally SET_TARGET (config snapshot, M1), then
 *     ReadFile()s a stream of fixed 32-byte REVENG_PCI_EVENT records drained from a ring.
 *   - PnP upper-filter (M2). When installed as an UpperFilter on a target PCIe device, the PnP
 *     manager calls AddDevice; we attach to the device stack, and on IRP_MN_START_DEVICE we
 *     IoConnectInterruptEx(message-based, shared) so our ISR fires on every real interrupt. The
 *     ISR pushes an IRQ event (with the true MSI vector) into the same ring. This is the
 *     high-fidelity per-controller interrupt capture the ETW ISR path could not provide.
 *
 * The ring is a bounded lock-free MPSC queue: interrupt service routines (multiple CPUs, DIRQL)
 * are the producers; the single ReadFile path (PASSIVE) is the consumer. A full ring drops the
 * new event and bumps a dropped counter. Per-slot sequence numbers prevent producers that are
 * delayed for more than one ring rotation from ever writing a slot that has been reused.
 */
#include <ntddk.h>
#include <wdmsec.h>
#include "reveng_pci_abi.h"

#pragma comment(lib, "Wdmsec.lib")

/* HalGetBusDataByOffset is deprecated but is the simplest config-space read without owning the
 * device; the WDK builds warnings-as-errors, and PoStartNextPowerIrp is likewise legacy. */
#pragma warning(disable : 4996)

#define RING_N 8192u /* power of two */
#define RING_MASK (RING_N - 1)

#define MAX_BARS 6
/* We map + track up to SNAP_CAP bytes per BAR; the actual per-snapshot length is chosen at
 * runtime by the SNAP IOCTL (default DEFAULT_SNAP), so coverage is tunable without a rebuild. */
#define SNAP_CAP 65536u
#define DEFAULT_SNAP 16384u /* covers xHCI runtime (RTSOFF ~0x2000) + doorbells (DBOFF ~0x3000) */
#define REVENG_POOL_TAG 'cPvR'

/* Lock-free MPSC event ring shared by config capture and the ISR. */
typedef struct _EVENT_RING {
    volatile LONG64  Head;             /* reserved slot count (producers)  */
    LONG64           Tail;             /* consumed count (single reader)   */
    volatile LONG64  Dropped;          /* events lost to overflow          */
    volatile LONG64  Commit[RING_N];   /* producer/consumer ownership sequence */
    REVENG_PCI_EVENT Slots[RING_N];
} EVENT_RING;

/* First field of every device extension, so IRP dispatch can tell control vs filter apart. */
typedef struct _COMMON_EXT {
    BOOLEAN IsFilter;
} COMMON_EXT, *PCOMMON_EXT;

typedef struct _CONTROL_EXT {
    BOOLEAN           IsFilter; /* FALSE */
    REVENG_PCI_TARGET target;
    EVENT_RING        ring;
} CONTROL_EXT, *PCONTROL_EXT;

/* One memory BAR mapped for MMIO snapshotting (M3). */
typedef struct _BAR_MAP {
    PVOID  Va;       /* MmMapIoSpaceEx virtual address, NULL if unused */
    ULONG  Length;   /* mapped length                                  */
    ULONG  SnapLen;  /* bytes we snapshot (min(Length, SNAP_MAX))       */
    PULONG Prev;     /* previous snapshot (SnapLen bytes), non-paged    */
} BAR_MAP;

typedef struct _FILTER_EXT {
    BOOLEAN         IsFilter; /* TRUE */
    PDEVICE_OBJECT  Self;
    PDEVICE_OBJECT  Lower;    /* next-lower device in the stack (attach target) */
    PDEVICE_OBJECT  Pdo;      /* physical device object (for message interrupts) */
    IO_REMOVE_LOCK  RemoveLock;
    PIO_INTERRUPT_MESSAGE_INFO MsgInfo; /* filled by IoConnectInterruptEx (message-based) */
    ULONG           LineVector;         /* fallback (line-based) vector from resources      */
    BOOLEAN         Connected;
    BAR_MAP         Bars[MAX_BARS];     /* M3: mapped MMIO BARs                             */
    ULONG           BarCount;
    BOOLEAN         Primed;             /* first snapshot emits a full baseline             */
    /* M4: the xHCI Event Ring, followed in system memory (best-effort, via MmCopyMemory). */
    ULONGLONG       ErstbaDev;          /* device addr of ERST we last resolved (0 = none)  */
    ULONGLONG       SegDev;             /* device addr of the Event Ring segment            */
    ULONG           SegLen;             /* segment length in bytes                          */
    PUCHAR          SegBuf;             /* our copy of the ring this snapshot               */
    PUCHAR          SegPrev;            /* previous copy (diff → newly-written TRBs)         */
    BOOLEAN         DmaReady;
} FILTER_EXT, *PFILTER_EXT;

static PDEVICE_OBJECT g_ControlDevice; /* the one control device; ISRs push into its ring */
static PFILTER_EXT    g_ActiveFilter;  /* most-recently-started filter (for MMIO snapshot) */
/* Serializes active-filter publication, snapshot IOCTLs, and BAR/DMA teardown.  A kernel mutex
 * preserves PASSIVE_LEVEL while held, which the mapping and interrupt-disconnect paths require. */
static KMUTEX         g_FilterMutex;
static UNICODE_STRING g_SymLink;
/* Private setup-class GUID used only to give IoCreateDeviceSecure stable policy identity. */
static const GUID g_ControlClassGuid =
    {0x67df8d87, 0x22b8, 0x4f62, {0x9f, 0xf0, 0x61, 0xad, 0x27, 0x89, 0x38, 0xa5}};

static void AcquireFilterMutex(void)
{
    (void)KeWaitForSingleObject(&g_FilterMutex, Executive, KernelMode, FALSE, NULL);
}

static void ReleaseFilterMutex(void)
{
    KeReleaseMutex(&g_FilterMutex, FALSE);
}

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RevengUnload;
DRIVER_ADD_DEVICE RevengAddDevice;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH RevengCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH RevengDeviceControl;
_Dispatch_type_(IRP_MJ_READ)
DRIVER_DISPATCH RevengRead;
_Dispatch_type_(IRP_MJ_PNP)
DRIVER_DISPATCH RevengPnp;
_Dispatch_type_(IRP_MJ_POWER)
DRIVER_DISPATCH RevengPower;
DRIVER_DISPATCH RevengPassThrough;

static ULONGLONG NowQpc(void)
{
    LARGE_INTEGER freq;
    LARGE_INTEGER c = KeQueryPerformanceCounter(&freq);
    UNREFERENCED_PARAMETER(freq);
    return (ULONGLONG)c.QuadPart;
}

/* --- event ring ---------------------------------------------------------------------------- */

static void RingInit(EVENT_RING *r)
{
    ULONG i;
    r->Head = 0;
    r->Tail = 0;
    r->Dropped = 0;
    for (i = 0; i < RING_N; i++) {
        r->Commit[i] = (LONG64)i; /* sequence `i` means slot i is free for producer i */
    }
}

/* Producer: safe from any IRQL / CPU (ISR context included). */
static void RingPush(EVENT_RING *r, const REVENG_PCI_EVENT *ev)
{
    LONG64 seq;
    ULONG idx;

    for (;;) {
        LONG64 slotSeq;
        seq = r->Head;
        idx = (ULONG)(seq & RING_MASK);
        slotSeq = r->Commit[idx];
        if (slotSeq == seq) {
            if (InterlockedCompareExchange64(&r->Head, seq + 1, seq) == seq) {
                break; /* this producer exclusively owns the slot */
            }
            continue;
        }
        if (slotSeq < seq) {
            InterlockedIncrement64(&r->Dropped); /* queue full; never overwrite live data */
            return;
        }
        /* Another producer advanced Head before our snapshot; retry at the new position. */
    }

    r->Slots[idx] = *ev;
    /* Publish last, with a full barrier, so the consumer never reads a half-written slot. */
    InterlockedExchange64(&r->Commit[idx], seq + 1);
}

/* Consumer: single reader (ReadFile). Returns bytes copied into `out`. */
static ULONG RingDrain(EVENT_RING *r, PUCHAR out, ULONG outcap)
{
    ULONG copied = 0;
    LONG64 tail = r->Tail;

    while ((copied + sizeof(REVENG_PCI_EVENT)) <= outcap) {
        ULONG idx = (ULONG)(tail & RING_MASK);
        if (r->Commit[idx] != tail + 1) {
            break; /* empty, or its producer reserved but has not published yet */
        }
        RtlCopyMemory(out + copied, &r->Slots[idx], sizeof(REVENG_PCI_EVENT));
        copied += sizeof(REVENG_PCI_EVENT);
        /* Make the slot available only after the event has been copied out. */
        InterlockedExchange64(&r->Commit[idx], tail + (LONG64)RING_N);
        tail++;
    }
    r->Tail = tail;
    return copied;
}

static PCONTROL_EXT ControlExt(void)
{
    return g_ControlDevice ? (PCONTROL_EXT)g_ControlDevice->DeviceExtension : NULL;
}

/* --- M1: config-space snapshot ------------------------------------------------------------- */

static void CaptureConfig(PCONTROL_EXT ext)
{
    PCI_SLOT_NUMBER slot;
    ULONG off;

    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber = ext->target.device;
    slot.u.bits.FunctionNumber = ext->target.function;

    for (off = 0; off < 256; off += 4) {
        ULONG value = 0xFFFFFFFF;
        REVENG_PCI_EVENT e;
        HalGetBusDataByOffset(PCIConfiguration, ext->target.bus, slot.u.AsULONG,
                              &value, off, sizeof(ULONG));
        RtlZeroMemory(&e, sizeof(e));
        e.ts_qpc = NowQpc();
        e.kind = REVENG_PCI_KIND_CONFIG;
        e.dir = REVENG_PCI_DIR_IN;
        e.width = 4;
        e.offset = off;
        e.value = value;
        RingPush(&ext->ring, &e);
    }
}

/* --- M2: interrupt service routines -------------------------------------------------------- */

static void PushIrq(ULONG vector)
{
    PCONTROL_EXT ctl = ControlExt();
    REVENG_PCI_EVENT e;
    if (ctl == NULL) {
        return;
    }
    RtlZeroMemory(&e, sizeof(e));
    e.ts_qpc = NowQpc();
    e.kind = REVENG_PCI_KIND_IRQ;
    e.value = vector;
    RingPush(&ctl->ring, &e);
}

/* Message-signaled ISR: MessageId indexes MsgInfo for the true allocated vector. */
static BOOLEAN RevengMsgIsr(PKINTERRUPT Interrupt, PVOID ServiceContext, ULONG MessageId)
{
    PFILTER_EXT fx = (PFILTER_EXT)ServiceContext;
    ULONG vector = 0;
    UNREFERENCED_PARAMETER(Interrupt);
    if (fx->MsgInfo != NULL && MessageId < fx->MsgInfo->MessageCount) {
        vector = fx->MsgInfo->MessageInfo[MessageId].Vector;
    }
    PushIrq(vector);
    return FALSE; /* we only observe; let the real driver's ISR claim the interrupt */
}

/* Line-based fallback ISR (used only if the device has no message interrupts). */
static BOOLEAN RevengLineIsr(PKINTERRUPT Interrupt, PVOID ServiceContext)
{
    PFILTER_EXT fx = (PFILTER_EXT)ServiceContext;
    UNREFERENCED_PARAMETER(Interrupt);
    PushIrq(fx->LineVector);
    return FALSE;
}

/* --- PnP filter ---------------------------------------------------------------------------- */

/* Pull a line-based vector out of the translated resource list (fallback only). */
static void RememberLineVector(PFILTER_EXT fx, PCM_RESOURCE_LIST list)
{
    ULONG i, j;
    if (list == NULL) {
        return;
    }
    for (i = 0; i < list->Count; i++) {
        PCM_FULL_RESOURCE_DESCRIPTOR full = &list->List[i];
        for (j = 0; j < full->PartialResourceList.Count; j++) {
            PCM_PARTIAL_RESOURCE_DESCRIPTOR p =
                &full->PartialResourceList.PartialDescriptors[j];
            if (p->Type == CmResourceTypeInterrupt &&
                (p->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) == 0) {
                fx->LineVector = p->u.Interrupt.Vector;
            }
        }
    }
}

static NTSTATUS ConnectInterrupt(PFILTER_EXT fx)
{
    IO_CONNECT_INTERRUPT_PARAMETERS params;
    NTSTATUS status;

    RtlZeroMemory(&params, sizeof(params));
    params.Version = CONNECT_MESSAGE_BASED;
    params.MessageBased.PhysicalDeviceObject = fx->Pdo;
    params.MessageBased.ConnectionContext.InterruptMessageTable = &fx->MsgInfo;
    params.MessageBased.MessageServiceRoutine = RevengMsgIsr;
    params.MessageBased.ServiceContext = fx;
    params.MessageBased.SpinLock = NULL;
    params.MessageBased.SynchronizeIrql = 0;
    params.MessageBased.FloatingSave = FALSE;
    /* If the device is line-based, IoConnectInterruptEx falls back to this routine. */
    params.MessageBased.FallBackServiceRoutine = RevengLineIsr;

    status = IoConnectInterruptEx(&params);
    if (NT_SUCCESS(status)) {
        fx->Connected = TRUE;
    }

    /* Diagnostic marker so user-mode can see the connect outcome (kind=IRQ, width=0xFF):
     *   value  = NTSTATUS
     *   offset = message count (message-based) or 0
     *   bar    = 1 message-based, 2 line-based fallback, 0 failed
     *   addr   = line vector (fallback) */
    {
        PCONTROL_EXT ctl = ControlExt();
        if (ctl != NULL) {
            REVENG_PCI_EVENT e;
            RtlZeroMemory(&e, sizeof(e));
            e.ts_qpc = NowQpc();
            e.kind = REVENG_PCI_KIND_IRQ;
            e.width = 0xFF; /* marker sentinel */
            e.value = (ULONGLONG)(ULONG)status;
            if (NT_SUCCESS(status) && fx->MsgInfo != NULL) {
                e.offset = fx->MsgInfo->MessageCount;
                e.bar = 1;
            } else if (NT_SUCCESS(status)) {
                e.bar = 2;
                e.addr = fx->LineVector;
            } else {
                e.bar = 0;
            }
            RingPush(&ctl->ring, &e);
        }
    }
    return status;
}

static void DisconnectInterrupt(PFILTER_EXT fx)
{
    if (fx->Connected) {
        IO_DISCONNECT_INTERRUPT_PARAMETERS d;
        RtlZeroMemory(&d, sizeof(d));
        d.Version = CONNECT_MESSAGE_BASED;
        d.ConnectionContext.InterruptMessageTable = fx->MsgInfo;
        IoDisconnectInterruptEx(&d);
        fx->Connected = FALSE;
        fx->MsgInfo = NULL;
    }
}

/* --- M3: MMIO BAR snapshotting ------------------------------------------------------------- */

/* Map the device's memory BARs (from its translated resources) for out-of-band snapshotting. */
static void MapBars(PFILTER_EXT fx, PCM_RESOURCE_LIST list)
{
    ULONG i, j;
    if (list == NULL) {
        return;
    }
    for (i = 0; i < list->Count; i++) {
        PCM_FULL_RESOURCE_DESCRIPTOR full = &list->List[i];
        for (j = 0; j < full->PartialResourceList.Count; j++) {
            PCM_PARTIAL_RESOURCE_DESCRIPTOR p =
                &full->PartialResourceList.PartialDescriptors[j];
            if (p->Type == CmResourceTypeMemory && fx->BarCount < MAX_BARS) {
                BAR_MAP *b = &fx->Bars[fx->BarCount];
                b->Length = p->u.Memory.Length;
                b->Va = MmMapIoSpaceEx(p->u.Memory.Start, b->Length,
                                       PAGE_READWRITE | PAGE_NOCACHE);
                if (b->Va == NULL) {
                    continue;
                }
                b->SnapLen = (b->Length < SNAP_CAP) ? b->Length : SNAP_CAP;
                b->SnapLen &= ~3u; /* dword-aligned */
                b->Prev = (PULONG)ExAllocatePool2(POOL_FLAG_NON_PAGED, b->SnapLen,
                                                  REVENG_POOL_TAG);
                if (b->Prev == NULL) {
                    MmUnmapIoSpace(b->Va, b->Length);
                    b->Va = NULL;
                    continue;
                }
                fx->BarCount++;
            }
        }
    }
}

static void UnmapBars(PFILTER_EXT fx)
{
    ULONG i;
    for (i = 0; i < fx->BarCount; i++) {
        if (fx->Bars[i].Prev != NULL) {
            ExFreePoolWithTag(fx->Bars[i].Prev, REVENG_POOL_TAG);
            fx->Bars[i].Prev = NULL;
        }
        if (fx->Bars[i].Va != NULL) {
            MmUnmapIoSpace(fx->Bars[i].Va, fx->Bars[i].Length);
            fx->Bars[i].Va = NULL;
        }
    }
    fx->BarCount = 0;
}

/* Read each mapped BAR and emit an MMIO event per changed dword (baseline on first call).
 * `reqBytes` bounds how much of each BAR to snapshot this call (clamped to what we mapped). */
static void SnapshotBars(PFILTER_EXT fx, ULONG reqBytes)
{
    PCONTROL_EXT ctl = ControlExt();
    ULONG i, off;
    if (fx == NULL || ctl == NULL) {
        return;
    }
    if (reqBytes == 0) {
        reqBytes = DEFAULT_SNAP;
    }
    if (!fx->Primed) {
        /* Diagnostic marker (MMIO, width=0xFF): how many BARs mapped and the first snap length. */
        REVENG_PCI_EVENT m;
        RtlZeroMemory(&m, sizeof(m));
        m.ts_qpc = NowQpc();
        m.kind = REVENG_PCI_KIND_MMIO;
        m.width = 0xFF;
        m.bar = 0xFF;
        m.value = fx->BarCount;
        m.offset = fx->BarCount ? fx->Bars[0].SnapLen : 0;
        RingPush(&ctl->ring, &m);
    }
    for (i = 0; i < fx->BarCount; i++) {
        PUCHAR va = (PUCHAR)fx->Bars[i].Va;
        ULONG snaplen = (reqBytes < fx->Bars[i].SnapLen) ? reqBytes : fx->Bars[i].SnapLen;
        for (off = 0; off < snaplen; off += 4) {
            ULONG v = READ_REGISTER_ULONG((PULONG)(va + off));
            ULONG idx = off / 4;
            if (!fx->Primed || v != fx->Bars[i].Prev[idx]) {
                REVENG_PCI_EVENT e;
                RtlZeroMemory(&e, sizeof(e));
                e.ts_qpc = NowQpc();
                e.kind = REVENG_PCI_KIND_MMIO;
                e.dir = REVENG_PCI_DIR_IN;
                e.width = 4;
                e.bar = (UCHAR)i;
                e.offset = off;
                e.value = v;
                RingPush(&ctl->ring, &e);
                fx->Bars[i].Prev[idx] = v;
            }
        }
    }
    fx->Primed = TRUE;
}

/* --- M4: xHCI Event Ring following (best-effort DMA capture) -------------------------------- */

/* True only if [pa, pa+len) lies entirely within a real RAM range — the guard that keeps us from
 * mapping MMIO/reserved/invalid physical (or an IOMMU address that lands outside RAM). */
static BOOLEAN PhysInRam(ULONGLONG pa, ULONG len)
{
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    BOOLEAN ok = FALSE;
    ULONG i;
    if (ranges == NULL) {
        return FALSE;
    }
    for (i = 0; ranges[i].NumberOfBytes.QuadPart != 0; i++) {
        ULONGLONG base = (ULONGLONG)ranges[i].BaseAddress.QuadPart;
        ULONGLONG size = (ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
        /* Avoid wraparound in both ranges before accepting an untrusted device address. */
        if (pa >= base && (ULONGLONG)len <= size && pa - base <= size - (ULONGLONG)len) {
            ok = TRUE;
            break;
        }
    }
    ExFreePool(ranges);
    return ok;
}

/* Emit a DMA diagnostic marker (kind=DMA, width=0xFF): `stage` in offset, plus addr/value. */
static void DmaMarker(PCONTROL_EXT ctl, ULONG stage, ULONGLONG addr, ULONGLONG value)
{
    REVENG_PCI_EVENT m;
    RtlZeroMemory(&m, sizeof(m));
    m.ts_qpc = NowQpc();
    m.kind = REVENG_PCI_KIND_DMA;
    m.width = 0xFF;
    m.offset = stage;
    m.addr = addr;
    m.value = value;
    RingPush(&ctl->ring, &m);
}

static void DmaCleanup(PFILTER_EXT fx)
{
    if (fx->SegPrev != NULL) {
        ExFreePoolWithTag(fx->SegPrev, REVENG_POOL_TAG);
        fx->SegPrev = NULL;
    }
    if (fx->SegBuf != NULL) {
        ExFreePoolWithTag(fx->SegBuf, REVENG_POOL_TAG);
        fx->SegBuf = NULL;
    }
    fx->SegLen = 0;
    fx->SegDev = 0;
    fx->ErstbaDev = 0;
    fx->DmaReady = FALSE;
}

/* Safely read `len` bytes of physical memory into `dst` (no persistent mapping, no cache-alias
 * bugcheck; returns FALSE on any fault or short read). */
static BOOLEAN ReadPhys(ULONGLONG pa, PVOID dst, ULONG len)
{
    MM_COPY_ADDRESS src;
    SIZE_T done = 0;
    NTSTATUS s;
    src.PhysicalAddress.QuadPart = (LONGLONG)pa;
    s = MmCopyMemory(dst, src, len, MM_COPY_MEMORY_PHYSICAL, &done);
    return NT_SUCCESS(s) && done == len;
}

/* Validate a register access without allowing offset+length to wrap. */
static BOOLEAN BarRangeValid(const BAR_MAP *bar, ULONG offset, ULONG length)
{
    return bar != NULL && bar->Va != NULL && length <= bar->Length &&
           offset <= bar->Length - length;
}

/* Read the interrupter-0 Event Ring pointers from MMIO, copy the ring segment out of system
 * memory, and emit a DMA event per Event TRB that changed since the last snapshot. */
static void DmaSnapshot(PFILTER_EXT fx)
{
    PCONTROL_EXT ctl = ControlExt();
    BAR_MAP *barMap;
    PUCHAR bar;
    ULONG rtsoff, erstsz, erstba_lo, erstba_hi;
    ULONGLONG erstba;
    ULONG off;

    if (fx == NULL || ctl == NULL || fx->BarCount == 0 || fx->Bars[0].Va == NULL) {
        return;
    }
    barMap = &fx->Bars[0];
    bar = (PUCHAR)barMap->Va;

    /* Runtime register base (RTSOFF, bits 31:5), then interrupter 0's ERST size/base. */
    if (!BarRangeValid(barMap, 0x18, sizeof(ULONG))) {
        DmaMarker(ctl, 11, 0x18, barMap->Length);
        return;
    }
    rtsoff = READ_REGISTER_ULONG((PULONG)(bar + 0x18)) & ~0x1Fu;
    /* The final register read is at RTSOFF+0x34.  Validate the whole register window before
     * doing any access derived from the device-controlled RTSOFF value. */
    if (rtsoff > MAXULONG - 0x34 ||
        !BarRangeValid(barMap, rtsoff + 0x28, 0x10)) {
        DmaMarker(ctl, 11, rtsoff, barMap->Length);
        return;
    }
    erstsz = READ_REGISTER_ULONG((PULONG)(bar + rtsoff + 0x28)) & 0xFFFF;
    erstba_lo = READ_REGISTER_ULONG((PULONG)(bar + rtsoff + 0x30));
    erstba_hi = READ_REGISTER_ULONG((PULONG)(bar + rtsoff + 0x34));
    erstba = (((ULONGLONG)erstba_hi) << 32) | (ULONGLONG)(erstba_lo & ~0x3Fu);

    if (erstba == 0 || erstsz == 0) {
        return; /* controller not initialized yet */
    }

    /* Resolve/allocate when the ERST address changes. */
    if (!fx->DmaReady || fx->ErstbaDev != erstba) {
        ULONG erst[4]; /* ERST entry 0 */
        ULONG segsize_trbs, segbytes;
        ULONGLONG segbase;

        DmaCleanup(fx);
        DmaMarker(ctl, 0, erstba, ((ULONGLONG)erstsz) | (((ULONGLONG)rtsoff) << 32));

        if (!PhysInRam(erstba, 16)) {
            DmaMarker(ctl, 9, erstba, 0); /* ERST not in RAM — likely IOMMU-translated */
            return;
        }
        if (!ReadPhys(erstba, erst, sizeof(erst))) {
            DmaMarker(ctl, 8, erstba, 0);
            return;
        }
        /* ERST entry 0: {segment base (64-bit), segment size in TRBs}. */
        segbase = (((ULONGLONG)erst[1]) << 32) | (ULONGLONG)(erst[0] & ~0x3Fu);
        segsize_trbs = erst[2] & 0xFFFF;

        segbytes = segsize_trbs * 16;
        if (segbytes > SNAP_CAP) {
            segbytes = SNAP_CAP;
        }
        if (segbase == 0 || segbytes == 0 || !PhysInRam(segbase, segbytes)) {
            DmaMarker(ctl, 10, segbase, segbytes); /* segment not in RAM — likely IOMMU */
            return;
        }
        fx->SegBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, segbytes, REVENG_POOL_TAG);
        fx->SegPrev = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, segbytes, REVENG_POOL_TAG);
        if (fx->SegBuf == NULL || fx->SegPrev == NULL) {
            DmaCleanup(fx);
            return;
        }
        RtlZeroMemory(fx->SegPrev, segbytes);
        fx->SegLen = segbytes;
        fx->SegDev = segbase;
        fx->ErstbaDev = erstba;
        fx->DmaReady = TRUE;
        DmaMarker(ctl, 1, segbase, segbytes); /* ring resolved OK */
    }

    /* Copy the ring out of physical memory, then diff per 16-byte TRB. */
    if (!ReadPhys(fx->SegDev, fx->SegBuf, fx->SegLen)) {
        DmaMarker(ctl, 8, fx->SegDev, fx->SegLen);
        return;
    }
    for (off = 0; off + 16 <= fx->SegLen; off += 16) {
        PULONG trb = (PULONG)(fx->SegBuf + off);
        ULONG d0 = trb[0], d1 = trb[1], d2 = trb[2], d3 = trb[3];
        PULONG prev = (PULONG)(fx->SegPrev + off);
        if (d0 != prev[0] || d1 != prev[1] || d2 != prev[2] || d3 != prev[3]) {
            REVENG_PCI_EVENT e;
            RtlZeroMemory(&e, sizeof(e));
            e.ts_qpc = NowQpc();
            e.kind = REVENG_PCI_KIND_DMA;
            e.dir = REVENG_PCI_DIR_IN;
            e.width = (UCHAR)((d3 >> 10) & 0x3F); /* TRB type */
            e.bar = (UCHAR)((d3 >> 24) & 0xFF);   /* slot/endpoint id (type-specific)          */
            e.offset = off;                        /* byte offset in the ring                    */
            e.addr = (((ULONGLONG)d1) << 32) | d0; /* TRB Parameter (pointer/data)               */
            e.value = (((ULONGLONG)d3) << 32) | d2;/* Control<<32 | Status (length+completion)   */
            RingPush(&ctl->ring, &e);
            prev[0] = d0;
            prev[1] = d1;
            prev[2] = d2;
            prev[3] = d3;
        }
    }
}

/* Forward an IRP down the stack unchanged. */
NTSTATUS RevengPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PCOMMON_EXT common = (PCOMMON_EXT)DeviceObject->DeviceExtension;
    PFILTER_EXT fx = (PFILTER_EXT)DeviceObject->DeviceExtension;
    if (!common->IsFilter) {
        /* The named control device has no lower stack.  Unhandled majors (notably CLEANUP)
         * must be completed locally rather than interpreting CONTROL_EXT bytes as fx->Lower. */
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(fx->Lower, Irp);
}

NTSTATUS RevengPower(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT fx = (PFILTER_EXT)DeviceObject->DeviceExtension;
    /* The non-PnP control device is not in any stack — just succeed. */
    if (!fx->IsFilter) {
        NTSTATUS s = STATUS_SUCCESS;
        Irp->IoStatus.Status = s;
        Irp->IoStatus.Information = 0;
        PoStartNextPowerIrp(Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return s;
    }
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(fx->Lower, Irp);
}

/* Completion routine used to wait for the lower stack to finish IRP_MN_START_DEVICE. */
static NTSTATUS StartCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS RevengPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT fx = (PFILTER_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    /* The non-PnP control device should never see PnP IRPs; if it does, fail cleanly rather
     * than dereference a CONTROL_EXT as a FILTER_EXT. */
    if (!fx->IsFilter) {
        status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    status = IoAcquireRemoveLock(&fx->RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    switch (sp->MinorFunction) {
    case IRP_MN_START_DEVICE: {
        KEVENT ev;
        KeInitializeEvent(&ev, NotificationEvent, FALSE);
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, StartCompletion, &ev, TRUE, TRUE, TRUE);
        status = IoCallDriver(fx->Lower, Irp);
        if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
            status = Irp->IoStatus.Status;
        }
        if (NT_SUCCESS(status)) {
            PCM_RESOURCE_LIST res = sp->Parameters.StartDevice.AllocatedResourcesTranslated;
            /* Resources the device actually got (translated). Connect our shared ISR (M2 —
             * fails for MSI, see README) and map its BARs for MMIO snapshotting (M3). */
            RememberLineVector(fx, res);
            (void)ConnectInterrupt(fx); /* best-effort: capture is optional to the device */
            AcquireFilterMutex();
            MapBars(fx, res);
            g_ActiveFilter = fx;
            ReleaseFilterMutex();
        }
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&fx->RemoveLock, Irp);
        return status;
    }
    case IRP_MN_STOP_DEVICE:
    case IRP_MN_SURPRISE_REMOVAL:
        AcquireFilterMutex();
        if (g_ActiveFilter == fx) {
            g_ActiveFilter = NULL;
        }
        DisconnectInterrupt(fx);
        UnmapBars(fx);
        DmaCleanup(fx);
        ReleaseFilterMutex();
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fx->Lower, Irp);
        IoReleaseRemoveLock(&fx->RemoveLock, Irp);
        return status;

    case IRP_MN_REMOVE_DEVICE:
        AcquireFilterMutex();
        if (g_ActiveFilter == fx) {
            g_ActiveFilter = NULL;
        }
        DisconnectInterrupt(fx);
        UnmapBars(fx);
        DmaCleanup(fx);
        ReleaseFilterMutex();
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fx->Lower, Irp);
        IoReleaseRemoveLockAndWait(&fx->RemoveLock, Irp);
        IoDetachDevice(fx->Lower);
        IoDeleteDevice(fx->Self);
        return status;

    default:
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fx->Lower, Irp);
        IoReleaseRemoveLock(&fx->RemoveLock, Irp);
        return status;
    }
}

NTSTATUS RevengAddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDEVICE_OBJECT fido = NULL;
    PFILTER_EXT fx;
    NTSTATUS status;

    status = IoCreateDevice(DriverObject, sizeof(FILTER_EXT), NULL, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &fido);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    fx = (PFILTER_EXT)fido->DeviceExtension;
    RtlZeroMemory(fx, sizeof(*fx));
    fx->IsFilter = TRUE;
    fx->Self = fido;
    fx->Pdo = PhysicalDeviceObject;
    IoInitializeRemoveLock(&fx->RemoveLock, 'gveR', 0, 0);

    fx->Lower = IoAttachDeviceToDeviceStack(fido, PhysicalDeviceObject);
    if (fx->Lower == NULL) {
        IoDeleteDevice(fido);
        return STATUS_DEVICE_REMOVED;
    }

    fido->Flags |= fx->Lower->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    fido->DeviceType = fx->Lower->DeviceType;
    fido->Characteristics = fx->Lower->Characteristics;
    fido->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

/* --- control device (\\.\RevengPciCap) ----------------------------------------------------- */

NTSTATUS RevengCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PCOMMON_EXT c = (PCOMMON_EXT)DeviceObject->DeviceExtension;
    if (c->IsFilter) {
        return RevengPassThrough(DeviceObject, Irp);
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS RevengDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PCOMMON_EXT c = (PCOMMON_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION sp;
    PCONTROL_EXT ext;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    if (c->IsFilter) {
        return RevengPassThrough(DeviceObject, Irp);
    }
    sp = IoGetCurrentIrpStackLocation(Irp);
    ext = (PCONTROL_EXT)DeviceObject->DeviceExtension;

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_REVENG_PCI_SET_TARGET:
        if (sp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(REVENG_PCI_TARGET)) {
            RtlCopyMemory(&ext->target, Irp->AssociatedIrp.SystemBuffer, sizeof(REVENG_PCI_TARGET));
            CaptureConfig(ext);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    case IOCTL_REVENG_PCI_MMIO_SNAP: {
        ULONG reqBytes = 0; /* 0 => driver default */
        if (sp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG)) {
            reqBytes = *(ULONG *)Irp->AssociatedIrp.SystemBuffer;
        }
        AcquireFilterMutex();
        if (g_ActiveFilter != NULL) {
            SnapshotBars(g_ActiveFilter, reqBytes);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_DEVICE_NOT_READY;
        }
        ReleaseFilterMutex();
        break;
    }
    case IOCTL_REVENG_PCI_DMA_SNAP:
        AcquireFilterMutex();
        if (g_ActiveFilter != NULL) {
            DmaSnapshot(g_ActiveFilter);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_DEVICE_NOT_READY;
        }
        ReleaseFilterMutex();
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS RevengRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PCOMMON_EXT c = (PCOMMON_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION sp;
    PCONTROL_EXT ext;
    ULONG copied;

    if (c->IsFilter) {
        return RevengPassThrough(DeviceObject, Irp);
    }
    sp = IoGetCurrentIrpStackLocation(Irp);
    ext = (PCONTROL_EXT)DeviceObject->DeviceExtension;
    copied = RingDrain(&ext->ring, (PUCHAR)Irp->AssociatedIrp.SystemBuffer, sp->Parameters.Read.Length);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = copied; /* 0 => user-mode polls again (live stream) */
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID RevengUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    IoDeleteSymbolicLink(&g_SymLink);
    if (g_ControlDevice != NULL) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING devName;
    PDEVICE_OBJECT devObj = NULL;
    PCONTROL_EXT ext;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&devName, L"\\Device\\RevengPciCap");
    RtlInitUnicodeString(&g_SymLink, L"\\DosDevices\\RevengPciCap");

    /* The ring has one consumer by design; make the control device exclusive so a second
     * ReadFile handle cannot race Tail or split the event stream. */
    status = IoCreateDeviceSecure(
        DriverObject,
        sizeof(CONTROL_EXT),
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        &g_ControlClassGuid,
        &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = IoCreateSymbolicLink(&g_SymLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
        return status;
    }

    ext = (PCONTROL_EXT)devObj->DeviceExtension;
    RtlZeroMemory(ext, sizeof(*ext));
    ext->IsFilter = FALSE;
    RingInit(&ext->ring);
    KeInitializeMutex(&g_FilterMutex, 0);
    devObj->Flags |= DO_BUFFERED_IO;
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    g_ControlDevice = devObj;

    DriverObject->DriverExtension->AddDevice = RevengAddDevice;
    DriverObject->DriverUnload = RevengUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = RevengCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RevengCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RevengDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_READ] = RevengRead;
    DriverObject->MajorFunction[IRP_MJ_PNP] = RevengPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = RevengPower;
    /* Every other major function just passes through on filter devices. */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (DriverObject->MajorFunction[i] == NULL) {
#pragma warning(suppress : 28168) /* one safe fallback intentionally covers every other major */
            DriverObject->MajorFunction[i] = RevengPassThrough;
        }
    }

    return STATUS_SUCCESS;
}
