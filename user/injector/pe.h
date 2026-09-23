#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

namespace PE {
    bool Parse(const std::vector<uint8_t>& FileData, std::vector<uint8_t>& ImageData, uintptr_t& ImageBase);
    bool ApplyRelocations(std::vector<uint8_t>& ImageData, uintptr_t OldBase, uintptr_t NewBase);
    bool ResolveImports(std::vector<uint8_t>& ImageData, uintptr_t ImageBase);
    uintptr_t GetProcAddress(uintptr_t ModuleBase, const char* ExportName);
    uintptr_t GetModuleBase(const char* ModuleName);
    void ErasePEHeaders(std::vector<uint8_t>& ImageData);
    uint32_t GetEntryPointOffset(const std::vector<uint8_t>& FileData);
}
