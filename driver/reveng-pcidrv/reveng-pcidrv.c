/*
 * reveng-pcidrv — M1: PCI config-space capture (WDM software control driver).
 *
 * The lighter, no-hypervisor tier of the PCIe backend (DESIGN.md §4a). A non-PnP software
 * driver that exposes the control device \\.\RevengPciCap. User-mode `pcicap::DrvPcieSource`:
 *   1. DeviceIoControl(IOCTL_REVENG_PCI_SET_TARGET, REVENG_PCI_TARGET) — pick device by BDF;
 *      we read its 256-byte PCI config space and queue one CONFIG event per dword.
 *   2. ReadFile() — drains the queued REVENG_PCI_EVENT records; a read past the end returns 0
 *      bytes (clean EOF), which the user side treats as end-of-capture.
 *
 * M1 is deliberately read-only and does not attach to the device (no trapping) — near-zero
 * risk. Load with `sc create ... type= kernel` + `sc start` (no INF needed for a non-PnP
 * software driver). WDM here; KMDF arrives at M2 when we attach to the device stack.
 */
#include <ntddk.h>
#include "reveng_pci_abi.h"

/* HalGetBusDataByOffset is marked deprecated but is the simplest way to read config space
 * without attaching to the device; the WDK builds with warnings-as-errors. */
#pragma warning(disable : 4996)

#define MAX_EVENTS 4096

typedef struct _DEVICE_EXTENSION {
    REVENG_PCI_TARGET target;
    REVENG_PCI_EVENT  events[MAX_EVENTS];
    ULONG             count;  /* events produced by the last SET_TARGET */
    ULONG             cursor; /* next event index to hand to ReadFile   */
    KSPIN_LOCK        lock;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

static UNICODE_STRING g_SymLink;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RevengUnload;
DRIVER_DISPATCH RevengCreateClose;
DRIVER_DISPATCH RevengDeviceControl;
DRIVER_DISPATCH RevengRead;

static ULONGLONG NowQpc(void)
{
    LARGE_INTEGER freq;
    LARGE_INTEGER c = KeQueryPerformanceCounter(&freq);
    return (ULONGLONG)c.QuadPart;
}

/* Snapshot the target's 256-byte config space into the event queue (one CONFIG event/dword). */
static void CaptureConfig(PDEVICE_EXTENSION ext)
{
    PCI_SLOT_NUMBER slot;
    KIRQL irql;
    ULONG off;

    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber = ext->target.device;
    slot.u.bits.FunctionNumber = ext->target.function;

    KeAcquireSpinLock(&ext->lock, &irql);
    ext->count = 0;
    ext->cursor = 0;
    for (off = 0; off < 256; off += 4) {
        ULONG value = 0xFFFFFFFF;
        HalGetBusDataByOffset(PCIConfiguration, ext->target.bus, slot.u.AsULONG,
                              &value, off, sizeof(ULONG));
        if (ext->count < MAX_EVENTS) {
            REVENG_PCI_EVENT *e = &ext->events[ext->count++];
            RtlZeroMemory(e, sizeof(*e));
            e->ts_qpc = NowQpc();
            e->kind = REVENG_PCI_KIND_CONFIG;
            e->dir = REVENG_PCI_DIR_IN;
            e->width = 4;
            e->offset = off;
            e->value = value;
        }
    }
    KeReleaseSpinLock(&ext->lock, irql);
}

NTSTATUS RevengCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS RevengDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_REVENG_PCI_SET_TARGET) {
        if (sp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(REVENG_PCI_TARGET)) {
            RtlCopyMemory(&ext->target, Irp->AssociatedIrp.SystemBuffer, sizeof(REVENG_PCI_TARGET));
            CaptureConfig(ext);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS RevengRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    ULONG outcap = sp->Parameters.Read.Length;
    PUCHAR out = (PUCHAR)Irp->AssociatedIrp.SystemBuffer; /* DO_BUFFERED_IO */
    ULONG copied = 0;
    KIRQL irql;

    KeAcquireSpinLock(&ext->lock, &irql);
    while (ext->cursor < ext->count &&
           (copied + sizeof(REVENG_PCI_EVENT)) <= outcap) {
        RtlCopyMemory(out + copied, &ext->events[ext->cursor], sizeof(REVENG_PCI_EVENT));
        copied += sizeof(REVENG_PCI_EVENT);
        ext->cursor++;
    }
    KeReleaseSpinLock(&ext->lock, irql);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = copied; /* 0 => user-mode sees clean EOF */
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID RevengUnload(PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&g_SymLink);
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING devName;
    PDEVICE_OBJECT devObj = NULL;
    PDEVICE_EXTENSION ext;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&devName, L"\\Device\\RevengPciCap");
    RtlInitUnicodeString(&g_SymLink, L"\\DosDevices\\RevengPciCap");

    status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &devName,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
        return status;
    }

    ext = (PDEVICE_EXTENSION)devObj->DeviceExtension;
    RtlZeroMemory(ext, sizeof(*ext));
    KeInitializeSpinLock(&ext->lock);

    devObj->Flags |= DO_BUFFERED_IO;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = RevengCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RevengCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RevengDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_READ] = RevengRead;
    DriverObject->DriverUnload = RevengUnload;

    return STATUS_SUCCESS;
}
