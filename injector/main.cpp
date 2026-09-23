#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include "injector.h"
#include "pe.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

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

std::string ReadFile(const std::wstring& Path) {
    HANDLE File = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE) {
        return "";
    }

    DWORD Size = GetFileSize(File, NULL);
    if (Size == INVALID_FILE_SIZE) {
        CloseHandle(File);
        return "";
    }

    std::string Data(Size, 0);
    DWORD Read = 0;
    if (!ReadFile(File, &Data[0], Size, &Read, NULL) || Read != Size) {
        CloseHandle(File);
        return "";
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

bool PhantomInjector::Initialize() {
    m_DriverHandle = INVALID_HANDLE_VALUE;
    m_TargetPid = 0;
    return true;
}

void PhantomInjector::Shutdown() {
    CloseDriver();
}

bool PhantomInjector::OpenDriver() {
    if (m_DriverHandle != INVALID_HANDLE_VALUE) {
        return true;
    }

    m_DriverHandle = CreateFileW(
        PHANTOM_USER_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    return m_DriverHandle != INVALID_HANDLE_VALUE;
}

void PhantomInjector::CloseDriver() {
    if (m_DriverHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_DriverHandle);
        m_DriverHandle = INVALID_HANDLE_VALUE;
    }
}

bool PhantomInjector::FindTargetProcess(const std::wstring& ProcessName) {
    if (!OpenDriver()) {
        std::cerr << "[!] Failed to open driver\n";
        return false;
    }

    FIND_PROCESS_REQUEST Request = { 0 };
    wcscpy_s(Request.ProcessName, ProcessName.c_str());

    FIND_PROCESS_RESPONSE Response = { 0 };
    DWORD BytesReturned = 0;

    BOOL Result = DeviceIoControl(
        m_DriverHandle,
        IOCTL_FIND_PROCESS,
        &Request,
        sizeof(Request),
        &Response,
        sizeof(Response),
        &BytesReturned,
        NULL
    );

    if (!Result || !NT_SUCCESS(Response.Status)) {
        std::cerr << "[!] Failed to find process: 0x" << std::hex << Response.Status << "\n";
        return false;
    }

    m_TargetPid = Response.ProcessId;
    std::wcout << L"[+] Found cs2.exe with PID: " << m_TargetPid << L"\n";
    return true;
}

bool PhantomInjector::ReadDllFile(const std::wstring& Path, std::vector<uint8_t>& Data) {
    HANDLE File = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to open DLL file\n";
        return false;
    }

    DWORD Size = GetFileSize(File, NULL);
    if (Size == INVALID_FILE_SIZE) {
        CloseHandle(File);
        return false;
    }

    Data.resize(Size);
    DWORD Read = 0;
    if (!ReadFile(File, Data.data(), Size, &Read, NULL) || Read != Size) {
        CloseHandle(File);
        return false;
    }

    CloseHandle(File);
    std::cout << "[+] Read DLL: " << Size << " bytes\n";
    return true;
}

bool PhantomInjector::PrepareImage(std::vector<uint8_t>& ImageData, uintptr_t& ImageBase) {
    std::vector<uint8_t> RawData = ImageData;

    if (!PE::Parse(RawData, ImageData, ImageBase)) {
        std::cerr << "[!] Failed to parse PE\n";
        return false;
    }

    if (!PE::ApplyRelocations(ImageData, ImageBase, ImageBase)) {
        std::cerr << "[!] Failed to apply relocations\n";
        return false;
    }

    if (!PE::ResolveImports(ImageData, ImageBase)) {
        std::cerr << "[!] Failed to resolve imports\n";
        return false;
    }

    PE::ErasePEHeaders(ImageData);
    std::cout << "[+] Image prepared at 0x" << std::hex << ImageBase << "\n";
    return true;
}

bool PhantomInjector::AllocateTargetMemory(uintptr_t Size, ULONG Protect, uintptr_t& BaseAddress) {
    ALLOCATE_MEMORY_REQUEST Request = { 0 };
    Request.ProcessId = m_TargetPid;
    Request.Size = Size;
    Request.Protection = Protect;
    Request.BaseAddress = 0;

    ALLOCATE_MEMORY_RESPONSE Response = { 0 };
    DWORD BytesReturned = 0;

    BOOL Result = DeviceIoControl(
        m_DriverHandle,
        IOCTL_ALLOCATE_MEMORY,
        &Request,
        sizeof(Request),
        &Response,
        sizeof(Response),
        &BytesReturned,
        NULL
    );

    if (!Result || !NT_SUCCESS(Response.Status)) {
        std::cerr << "[!] Failed to allocate memory: 0x" << std::hex << Response.Status << "\n";
        return false;
    }

    BaseAddress = Response.BaseAddress;
    std::cout << "[+] Allocated memory at 0x" << std::hex << BaseAddress << "\n";
    return true;
}

bool PhantomInjector::WriteToTarget(uintptr_t Address, const uint8_t* Data, size_t Size) {
    std::vector<uint8_t> Buffer(sizeof(WRITE_MEMORY_REQUEST) + Size - 1);
    PWRITE_MEMORY_REQUEST Request = (PWRITE_MEMORY_REQUEST)Buffer.data();
    Request->ProcessId = m_TargetPid;
    Request->TargetAddress = Address;
    Request->Size = (ULONG)Size;
    memcpy(Request->Data, Data, Size);

    WRITE_MEMORY_RESPONSE Response = { 0 };
    DWORD BytesReturned = 0;

    BOOL Result = DeviceIoControl(
        m_DriverHandle,
        IOCTL_WRITE_MEMORY,
        Buffer.data(),
        (DWORD)Buffer.size(),
        &Response,
        sizeof(Response),
        &BytesReturned,
        NULL
    );

    if (!Result || !NT_SUCCESS(Response.Status)) {
        std::cerr << "[!] Failed to write memory: 0x" << std::hex << Response.Status << "\n";
        return false;
    }

    return true;
}

bool PhantomInjector::WipePeHeader(uintptr_t Address, size_t Size) {
    WIPE_HEADER_REQUEST Request = { 0 };
    Request.ProcessId = m_TargetPid;
    Request.BaseAddress = Address;
    Request.Size = (ULONG)Size;

    WIPE_HEADER_RESPONSE Response = { 0 };
    DWORD BytesReturned = 0;

    BOOL Result = DeviceIoControl(
        m_DriverHandle,
        IOCTL_WIPE_HEADER,
        &Request,
        sizeof(Request),
        &Response,
        sizeof(Response),
        &BytesReturned,
        NULL
    );

    if (!Result || !NT_SUCCESS(Response.Status)) {
        std::cerr << "[!] Failed to wipe header: 0x" << std::hex << Response.Status << "\n";
        return false;
    }

    return true;
}

bool PhantomInjector::FindThreadId(ULONG ProcessId, ULONG& ThreadId) {
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 Entry = { 0 };
    Entry.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(Snapshot, &Entry)) {
        CloseHandle(Snapshot);
        return false;
    }

    do {
        if (Entry.th32OwnerProcessID == ProcessId) {
            ThreadId = Entry.th32ThreadID;
            CloseHandle(Snapshot);
            return true;
        }
    } while (Thread32Next(Snapshot, &Entry));

    CloseHandle(Snapshot);
    return false;
}

bool PhantomInjector::QueueShellcode(uintptr_t ShellcodeAddress) {
    ULONG ThreadId = 0;
    if (!FindThreadId(m_TargetPid, ThreadId)) {
        std::cerr << "[!] Failed to find thread in target process\n";
        return false;
    }

    QUEUE_APC_REQUEST Request = { 0 };
    Request.ProcessId = m_TargetPid;
    Request.ThreadId = ThreadId;
    Request.ApcRoutine = ShellcodeAddress;
    Request.Parameter1 = 0;
    Request.Parameter2 = 0;

    QUEUE_APC_RESPONSE Response = { 0 };
    DWORD BytesReturned = 0;

    BOOL Result = DeviceIoControl(
        m_DriverHandle,
        IOCTL_QUEUE_APC,
        &Request,
        sizeof(Request),
        &Response,
        sizeof(Response),
        &BytesReturned,
        NULL
    );

    if (!Result || !NT_SUCCESS(Response.Status)) {
        std::cerr << "[!] Failed to queue APC: 0x" << std::hex << Response.Status << "\n";
        return false;
    }

    std::cout << "[+] APC queued to thread " << ThreadId << "\n";
    return true;
}

bool PhantomInjector::Inject(const std::wstring& DllPath) {
    std::cout << "[*] Starting PhantomInjector...\n";

    if (!FindTargetProcess(L"cs2.exe")) {
        std::cerr << "[!] cs2.exe not found. Please start CS2 first.\n";
        return false;
    }

    std::vector<uint8_t> DllData;
    if (!ReadDllFile(DllPath, DllData)) {
        std::cerr << "[!] Failed to read DLL\n";
        return false;
    }

    std::vector<uint8_t> ImageData = DllData;
    uintptr_t ImageBase = 0;
    if (!PrepareImage(ImageData, ImageBase)) {
        return false;
    }

    uintptr_t TargetBase = 0;
    if (!AllocateTargetMemory(ImageData.size(), PAGE_EXECUTE_READWRITE, TargetBase)) {
        return false;
    }

    if (!WriteToTarget(TargetBase, ImageData.data(), ImageData.size())) {
        return false;
    }

    std::cout << "[+] Image written to target\n";

    if (!WipePeHeader(TargetBase, 0x1000)) {
        std::cerr << "[!] Warning: Failed to wipe PE headers\n";
    }

    std::cout << "[+] PE headers wiped\n";

    uintptr_t DllMainAddress = TargetBase + PE::GetEntryPointOffset(DllData);
    std::vector<uint8_t> Shellcode = GenerateShellcode(DllMainAddress, TargetBase, DLL_PROCESS_ATTACH);

    uintptr_t ShellcodeAddress = 0;
    if (!AllocateTargetMemory(Shellcode.size(), PAGE_EXECUTE_READWRITE, ShellcodeAddress)) {
        std::cerr << "[!] Failed to allocate shellcode memory\n";
        return false;
    }

    if (!WriteToTarget(ShellcodeAddress, Shellcode.data(), Shellcode.size())) {
        std::cerr << "[!] Failed to write shellcode\n";
        return false;
    }

    std::cout << "[+] Shellcode written at 0x" << std::hex << ShellcodeAddress << "\n";

    if (!QueueShellcode(ShellcodeAddress)) {
        return false;
    }

    std::cout << "[+] Injection complete!\n";
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: PhantomInjector.exe <path_to_dll>\n";
        return 1;
    }

    PhantomInjector Injector;
    if (!Injector.Initialize()) {
        std::cerr << "[!] Failed to initialize injector\n";
        return 1;
    }

    bool Result = Injector.Inject(argv[1]);
    Injector.Shutdown();

    std::cout << "\n[*] Press any key to exit...\n";
    std::cin.get();

    return Result ? 0 : 1;
}

