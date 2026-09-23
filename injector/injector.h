#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include "shared\protocol.h"

class PhantomInjector {
public:
    bool Initialize();
    bool Inject(const std::wstring& DllPath);
    void Shutdown();

private:
    HANDLE m_DriverHandle;
    ULONG m_TargetPid;

    bool OpenDriver();
    void CloseDriver();
    bool FindTargetProcess(const std::wstring& ProcessName);
    bool ReadDllFile(const std::wstring& Path, std::vector<uint8_t>& Data);
    bool PrepareImage(std::vector<uint8_t>& ImageData, uintptr_t& ImageBase);
    bool AllocateTargetMemory(uintptr_t Size, ULONG Protect, uintptr_t& BaseAddress);
    bool WriteToTarget(uintptr_t Address, const uint8_t* Data, size_t Size);
    bool WipePeHeader(uintptr_t Address, size_t Size);
    bool FindThreadId(ULONG ProcessId, ULONG& ThreadId);
    bool QueueShellcode(uintptr_t Address);
};
