#include <windows.h>
#include <iostream>

static bool g_Initialized = false;

void ClientInitialize() {
    if (g_Initialized) return;
    g_Initialized = true;

    MessageBoxA(NULL, "PhantomInject: DLL Successfully Injected into CS2!", "PhantomInject", MB_OK);
}

extern "C" BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClientInitialize, NULL, 0, NULL);
            break;

        case DLL_PROCESS_DETACH:
            g_Initialized = false;
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
