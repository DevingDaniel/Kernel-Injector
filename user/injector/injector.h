#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

class UserInjector {
public:
    bool Inject(const std::wstring& DllPath);
};
