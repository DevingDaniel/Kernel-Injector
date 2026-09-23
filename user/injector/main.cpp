#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include "injector.h"
#include "pe.h"

DWORD FindProcessId(const std::wstring& ProcessName) {
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W Entry = { 0 };
    Entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(Snapshot, &Entry)) {
        CloseHandle(Snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(Entry.szExeFile, ProcessName.c_str()) == 0) {
            CloseHandle(Snapshot);
            return Entry.th32ProcessID;
        }
    } while (Process32NextW(Snapshot, &Entry));

    CloseHandle(Snapshot);
    return 0;
}

std::vector<uint8_t> ReadFile(const std::wstring& Path) {
    HANDLE File = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE) {
        return {};
    }

    DWORD Size = GetFileSize(File, NULL);
    if (Size == INVALID_FILE_SIZE) {
        CloseHandle(File);
        return {};
    }

    std::vector<uint8_t> Data(Size);
    DWORD Read = 0;
    if (!ReadFile(File, Data.data(), Size, &Read, NULL) || Read != Size) {
        CloseHandle(File);
        return {};
    }

    CloseHandle(File);
    return Data;
}

std::vector<uint8_t> GenerateShellcode(uintptr_t DllMain, uintptr_t ModuleBase, DWORD Reason) {
    std::vector<uint8_t> Shellcode;

    Shellcode.insert(Shellcode.end(), {0x48, 0x83, 0xEC, 0x28});
    Shellcode.insert(Shellcode.end(), {0x48, 0xB9});
    *reinterpret_cast<uintptr_t*>(Shellcode.data() + 6) = ModuleBase;
    Shellcode.insert(Shellcode.end(), {0x48, 0xC7, 0xC2});
    *reinterpret_cast<uint32_t*>(Shellcode.data() + 16) = Reason;
    Shellcode.insert(Shellcode.end(), {0x4D, 0x31, 0xC0});
    Shellcode.insert(Shellcode.end(), {0x48, 0xB8});
    *reinterpret_cast<uintptr_t*>(Shellcode.data() + 24) = DllMain;
    Shellcode.insert(Shellcode.end(), {0xFF, 0xD0});
    Shellcode.insert(Shellcode.end(), {0x48, 0x83, 0xC4, 0x28});
    Shellcode.insert(Shellcode.end(), {0xC3});

    return Shellcode;
}

bool UserInjector::Inject(const std::wstring& DllPath) {
    std::wcout << L"[*] Starting UserInjector...\n";

    std::wcout << L"[*] Finding cs2.exe...\n";
    DWORD Pid = FindProcessId(L"cs2.exe");
    if (Pid == 0) {
        std::cerr << "[!] cs2.exe not found\n";
        return false;
    }
    std::wcout << L"[+] Found cs2.exe, PID: " << Pid << L"\n";

    std::wcout << L"[*] Reading DLL: " << DllPath << L"\n";
    std::vector<uint8_t> DllData = ReadFile(DllPath);
    if (DllData.empty()) {
        std::cerr << "[!] Failed to read DLL\n";
        return false;
    }

    std::vector<uint8_t> ImageData;
    uintptr_t ImageBase = 0;
    if (!PE::Parse(DllData, ImageData, ImageBase)) {
        return false;
    }

    std::wcout << L"[*] Opening process...\n";
    HANDLE Process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD, FALSE, Pid);
    if (Process == NULL) {
        std::cerr << "[!] Failed to open process\n";
        return false;
    }

    std::wcout << L"[*] Allocating memory in target...\n";
    LPVOID RemoteBase = VirtualAllocEx(Process, (LPVOID)ImageBase, ImageData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (RemoteBase == NULL) {
        std::cerr << "[!] Failed to allocate memory\n";
        CloseHandle(Process);
        return false;
    }
    std::wcout << L"[+] Allocated at 0x" << std::hex << (uintptr_t)RemoteBase << L"\n";

    std::wcout << L"[*] Writing image...\n";
    if (!WriteProcessMemory(Process, RemoteBase, ImageData.data(), ImageData.size(), NULL)) {
        std::cerr << "[!] Failed to write image\n";
        VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        CloseHandle(Process);
        return false;
    }
    std::wcout << L"[+] Image written\n";

    std::wcout << L"[*] Wiping PE headers...\n";
    std::vector<uint8_t> Zeros(0x1000, 0);
    WriteProcessMemory(Process, RemoteBase, Zeros.data(), 0x1000, NULL);
    std::wcout << L"[+] Headers wiped\n";

    std::wcout << L"[*] Creating remote thread...\n";
    uintptr_t EntryPoint = (uintptr_t)RemoteBase + PE::GetEntryPointOffset(DllData);
    std::vector<uint8_t> Shellcode = GenerateShellcode(EntryPoint, (uintptr_t)RemoteBase, DLL_PROCESS_ATTACH);

    LPVOID RemoteShellcode = VirtualAllocEx(Process, NULL, Shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (RemoteShellcode == NULL) {
        std::cerr << "[!] Failed to allocate shellcode memory\n";
        VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        CloseHandle(Process);
        return false;
    }

    WriteProcessMemory(Process, RemoteShellcode, Shellcode.data(), Shellcode.size(), NULL);

    HANDLE Thread = CreateRemoteThread(Process, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteShellcode, NULL, 0, NULL);
    if (Thread == NULL) {
        std::cerr << "[!] Failed to create remote thread\n";
        VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        CloseHandle(Process);
        return false;
    }

    std::wcout << L"[+] Remote thread created, waiting...\n";
    WaitForSingleObject(Thread, INFINITE);
    std::wcout << L"[+] Injection complete!\n";

    CloseHandle(Thread);
    VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);
    CloseHandle(Process);
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: PhantomInjector.exe <path_to_dll>\n";
        return 1;
    }

    UserInjector Injector;
    if (!Injector.Inject(argv[1])) {
        std::cerr << "[!] Injection failed\n";
        return 1;
    }

    return 0;
}
