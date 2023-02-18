#include <ntifs.h>
#include <windef.h>

#define IOCTL_GET_WIN_VER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_BASE_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);


typedef struct _WIN_VER_INFO {
    ULONG MajorVersion;
    ULONG MinorVersion;
} WIN_VER_INFO, * PWIN_VER_INFO;

typedef struct _PROCESS_BASE_ADDRESS_INFO {
    HANDLE ProcessId;
    PVOID BaseAddress;
} PROCESS_BASE_ADDRESS_INFO, * PPROCESS_BASE_ADDRESS_INFO;

NTSTATUS DriverGetWinVer(PWIN_VER_INFO WinVerInfo)
{
    RTL_OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    RtlGetVersion(&osvi);
    WinVerInfo->MajorVersion = osvi.dwMajorVersion;
    WinVerInfo->MinorVersion = osvi.dwMinorVersion;
    return STATUS_SUCCESS;
}

NTSTATUS DriverGetProcessBaseAddress(PPROCESS_BASE_ADDRESS_INFO ProcessBaseAddressInfo)
{
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessBaseAddressInfo->ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    ProcessBaseAddressInfo->BaseAddress = PsGetProcessSectionBaseAddress(Process);
    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

NTSTATUS DriverDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    ULONG ControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS Status = STATUS_SUCCESS;
    switch (ControlCode) {
    case IOCTL_GET_WIN_VER:
        Status = DriverGetWinVer((PWIN_VER_INFO)Irp->AssociatedIrp.SystemBuffer);
        break;
    case IOCTL_GET_PROCESS_BASE_ADDRESS:
        Status = DriverGetProcessBaseAddress((PPROCESS_BASE_ADDRESS_INFO)Irp->AssociatedIrp.SystemBuffer);
        break;
    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS init(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS Status;
    UNICODE_STRING DeviceName; 
    UNICODE_STRING SymlinkName;
    RtlInitUnicodeString(&DeviceName, L"\\Device\\MyDuduez");
    RtlInitUnicodeString(&SymlinkName, L"\\DosDevices\\MyDuduez");
    PDEVICE_OBJECT DeviceObject;
    Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatchIoctl;
    Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    IoCreateDriver(NULL, &init);
    return IoCreateDriver(NULL, &init);
}