#include <windows.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <vector>
#include <string>
#include <algorithm>
#include "pe.h"

#define ID_BUTTON_SELECT 1001
#define ID_BUTTON_INJECT 1002
#define ID_EDIT_LOG     1003
#define ID_EDIT_DLL     1004

const wchar_t WINDOW_CLASS[] = L"PhantomInjector";
const wchar_t WINDOW_TITLE[] = L"PhantomInject - CS2 Injector";

HINSTANCE g_hInstance;
HWND g_hLogEdit;
HWND g_hDllEdit;
wchar_t g_DllPath[MAX_PATH] = L"";

std::wstring ReadEditText(HWND hEdit) {
    int len = GetWindowTextLength(hEdit);
    if (len == 0) return L"";
    std::wstring str(len + 1, 0);
    GetWindowText(hEdit, &str[0], len + 1);
    str.resize(len);
    return str;
}

void AppendLog(const std::wstring& text) {
    int len = GetWindowTextLength(g_hLogEdit);
    SetSel(len, len);
    ReplaceSelW(g_hLogEdit, text + L"\r\n", FALSE);
    SendMessage(g_hLogEdit, WM_VSCROLL, SB_BOTTOM, 0);
}

DWORD FindProcessId(const std::wstring& ProcessName) {
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) return 0;

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
    if (File == INVALID_HANDLE_VALUE) return {};

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

void InjectDll() {
    AppendLog(L"[*] Starting injection...");

    if (g_DllPath[0] == 0) {
        AppendLog(L"[!] No DLL selected");
        return;
    }

    AppendLog(L"[*] Finding cs2.exe...");
    DWORD Pid = FindProcessId(L"cs2.exe");
    if (Pid == 0) {
        AppendLog(L"[!] cs2.exe not found. Please start CS2 first.");
        return;
    }
    AppendLog(L"[+] Found cs2.exe, PID: " + std::to_wstring(Pid));

    AppendLog(L"[*] Reading DLL: " + std::wstring(g_DllPath));
    std::vector<uint8_t> DllData = ReadFile(g_DllPath);
    if (DllData.empty()) {
        AppendLog(L"[!] Failed to read DLL");
        return;
    }

    std::vector<uint8_t> ImageData;
    uintptr_t ImageBase = 0;
    if (!PE::Parse(DllData, ImageData, ImageBase)) {
        AppendLog(L"[!] Failed to parse PE");
        return;
    }

    AppendLog(L"[*] Opening process...");
    HANDLE Process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD, FALSE, Pid);
    if (Process == NULL) {
        AppendLog(L"[!] Failed to open process");
        return;
    }

    AppendLog(L"[*] Allocating memory...");
    LPVOID RemoteBase = VirtualAllocEx(Process, (LPVOID)ImageBase, ImageData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (RemoteBase == NULL) {
        AppendLog(L"[!] Failed to allocate memory");
        CloseHandle(Process);
        return;
    }
    AppendLog(L"[+] Allocated at: 0x" + std::to_wstring((uintptr_t)RemoteBase));

    AppendLog(L"[*] Writing image...");
    if (!WriteProcessMemory(Process, RemoteBase, ImageData.data(), ImageData.size(), NULL)) {
        AppendLog(L"[!] Failed to write image");
        VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        CloseHandle(Process);
        return;
    }

    AppendLog(L"[*] Wiping PE headers...");
    std::vector<uint8_t> Zeros(0x1000, 0);
    WriteProcessMemory(Process, RemoteBase, Zeros.data(), 0x1000, NULL);

    AppendLog(L"[*] Creating remote thread...");
    uintptr_t EntryPoint = (uintptr_t)RemoteBase + PE::GetEntryPointOffset(DllData);
    std::vector<uint8_t> Shellcode = GenerateShellcode(EntryPoint, (uintptr_t)RemoteBase, DLL_PROCESS_ATTACH);

    LPVOID RemoteShellcode = VirtualAllocEx(Process, NULL, Shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (RemoteShellcode == NULL) {
        AppendLog(L"[!] Failed to allocate shellcode");
        VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        CloseHandle(Process);
        return;
    }

    WriteProcessMemory(Process, RemoteShellcode, Shellcode.data(), Shellcode.size(), NULL);

    HANDLE Thread = CreateRemoteThread(Process, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteShellcode, NULL, 0, NULL);
    if (Thread == NULL) {
        AppendLog(L"[!] Failed to create remote thread");
        VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(Process, RemoteBase, 0, MEM_RELEASE);
        CloseHandle(Process);
        return;
    }

    AppendLog(L"[+] Remote thread created, waiting...");
    WaitForSingleObject(Thread, INFINITE);
    AppendLog(L"[+] Injection complete!");

    CloseHandle(Thread);
    VirtualFreeEx(Process, RemoteShellcode, 0, MEM_RELEASE);
    CloseHandle(Process);
}

void SelectDllFile() {
    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.lpstrFile = g_DllPath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        SetWindowTextW(g_hDllEdit, g_DllPath);
        AppendLog(L"[+] Selected DLL: " + std::wstring(g_DllPath));
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            CreateWindowW(L"STATIC", L"DLL Path:", WS_VISIBLE | WS_CHILD, 10, 10, 80, 25, hwnd, NULL, g_hInstance, NULL);

            g_hDllEdit = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 100, 10, 400, 25, hwnd, (HMENU)ID_EDIT_DLL, g_hInstance, NULL);

            CreateWindowW(L"BUTTON", L"Browse", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 520, 10, 80, 25, hwnd, (HMENU)ID_BUTTON_SELECT, g_hInstance, NULL);

            CreateWindowW(L"BUTTON", L"Inject", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 620, 10, 80, 25, hwnd, (HMENU)ID_BUTTON_INJECT, g_hInstance, NULL);

            g_hLogEdit = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 10, 50, 690, 300, hwnd, (HMENU)ID_EDIT_LOG, g_hInstance, NULL);

            AppendLog(L"[*] PhantomInject GUI initialized");
            AppendLog(L"[*] Select a DLL and click Inject");
            break;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BUTTON_SELECT:
                    SelectDllFile();
                    break;
                case ID_BUTTON_INJECT:
                    InjectDll();
                    break;
            }
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    g_hInstance = hInstance;

    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = WINDOW_CLASS;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Failed to register window class", L"Error", MB_ICONERROR);
        return 1;
    }

    HWND hwnd = CreateWindowExW(0, WINDOW_CLASS, WINDOW_TITLE, WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME, CW_USEDEFAULT, CW_USEDEFAULT, 740, 420, NULL, NULL, hInstance, NULL);
    if (!hwnd) {
        MessageBoxW(NULL, L"Failed to create window", L"Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = { 0 };
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
