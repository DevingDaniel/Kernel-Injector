#ifndef PHANTOM_DRIVER_H
#define PHANTOM_DRIVER_H

#include <ntddk.h>
#include "shared\protocol.h"

#define DRIVER_POOL_TAG 'PmhP'
#define DRIVER_DEVICE_NAME L"\\Device\\PhantomInject"

#define TRAP_FRAME_RIP_OFFSET 0x168
#define KTHREAD_TRAP_FRAME_OFFSET 0x90

typedef struct _DRIVER_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN DeviceCreated;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

DRIVER_CONTEXT g_DriverContext;

NTSTATUS PhantomFindProcessByName(PCWSTR ProcessName, PULONG ProcessId);
NTSTATUS PhantomAllocateMemory(ULONG ProcessId, SIZE_T Size, ULONG Protect, PVOID* BaseAddress);
NTSTATUS PhantomWriteMemory(ULONG ProcessId, PVOID TargetAddress, PVOID Buffer, SIZE_T Size);
NTSTATUS PhantomQueueApc(ULONG ProcessId, ULONG ThreadId, PVOID ShellcodeAddress);
NTSTATUS PhantomWipeHeader(ULONG ProcessId, PVOID BaseAddress, SIZE_T Size);
NTSTATUS PhantomProtectMemory(ULONG ProcessId, PVOID Address, SIZE_T Size, ULONG NewProtect, PULONG OldProtect);
NTSTATUS PhantomGetProcessBase(ULONG ProcessId, PVOID* BaseAddress);
PEPROCESS PhantomReferenceProcessById(HANDLE ProcessId);

VOID PhantomApcKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* Context, PBOOLEAN* Argument2);

#endif
