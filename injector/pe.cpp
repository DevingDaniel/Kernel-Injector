#include "pe.h"
#include <windows.h>
#include <winternl.h>
#include <iostream>

namespace PE {
    PIMAGE_DOS_HEADER GetDosHeader(const uint8_t* Data) {
        return (PIMAGE_DOS_HEADER)Data;
    }

    PIMAGE_NT_HEADERS64 GetNtHeaders(const uint8_t* Data) {
        PIMAGE_DOS_HEADER Dos = GetDosHeader(Data);
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return NULL;
        }
        return (PIMAGE_NT_HEADERS64)(Data + Dos->e_lfanew);
    }

    bool Parse(const std::vector<uint8_t>& FileData, std::vector<uint8_t>& ImageData, uintptr_t& ImageBase) {
        PIMAGE_NT_HEADERS64 Nt = GetNtHeaders(FileData.data());
        if (Nt == NULL || Nt->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "[!] Invalid PE signature\n";
            return false;
        }

        if (Nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            std::cerr << "[!] Not a x64 binary\n";
            return false;
        }

        DWORD ImageSize = Nt->OptionalHeader.SizeOfImage;
        ImageBase = Nt->OptionalHeader.ImageBase;

        ImageData.resize(ImageSize);
        RtlZeroMemory(ImageData.data(), ImageSize);

        PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Nt);
        for (int i = 0; i < Nt->FileHeader.NumberOfSections; i++) {
            if (Sections[i].SizeOfRawData == 0) {
                continue;
            }

            if (Sections[i].PointerToRawData + Sections[i].SizeOfRawData > FileData.size()) {
                continue;
            }

            uint8_t* Dest = ImageData.data() + Sections[i].VirtualAddress;
            const uint8_t* Src = FileData.data() + Sections[i].PointerToRawData;
            memcpy(Dest, Src, Sections[i].SizeOfRawData);
        }

        std::cout << "[+] PE parsed: " << Nt->FileHeader.NumberOfSections << " sections, ImageSize: 0x"
                  << std::hex << ImageSize << "\n";
        return true;
    }

    bool ApplyRelocations(std::vector<uint8_t>& ImageData, uintptr_t OldBase, uintptr_t NewBase) {
        PIMAGE_NT_HEADERS64 Nt = GetNtHeaders(ImageData.data());
        if (Nt == NULL) {
            return false;
        }

        uintptr_t Delta = NewBase - Nt->OptionalHeader.ImageBase;
        if (Delta == 0) {
            return true;
        }

        if (!(Nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
            return true;
        }

        PIMAGE_DATA_DIRECTORY RelocDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (RelocDir->VirtualAddress == 0 || RelocDir->Size == 0) {
            std::cout << "[-] No relocations found\n";
            return true;
        }

        uintptr_t RelocAddr = RelocDir->VirtualAddress;
        DWORD RelocSize = RelocDir->Size;

        while (RelocSize > 0) {
            PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)(ImageData.data() + RelocAddr);
            DWORD RelocCount = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* RelocData = (WORD*)((uint8_t*)Reloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < RelocCount; i++) {
                WORD Type = (RelocData[i] >> 12) & 0xF;
                WORD Offset = RelocData[i] & 0xFFF;

                if (Type == IMAGE_REL_BASED_DIR64) {
                    uintptr_t* PatchAddr = (uintptr_t*)(ImageData.data() + Reloc->VirtualAddress + Offset);
                    *PatchAddr += Delta;
                } else if (Type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD* PatchAddr = (DWORD*)(ImageData.data() + Reloc->VirtualAddress + Offset);
                    *PatchAddr += (DWORD)Delta;
                }
            }

            RelocAddr += Reloc->SizeOfBlock;
            RelocSize -= Reloc->SizeOfBlock;
        }

        std::cout << "[+] Relocations applied (delta: 0x" << std::hex << Delta << ")\n";
        return true;
    }

    bool ResolveImports(std::vector<uint8_t>& ImageData, uintptr_t ImageBase) {
        PIMAGE_NT_HEADERS64 Nt = GetNtHeaders(ImageData.data());
        if (Nt == NULL) {
            return false;
        }

        PIMAGE_DATA_DIRECTORY ImportDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (ImportDir->VirtualAddress == 0 || ImportDir->Size == 0) {
            std::cout << "[-] No imports found\n";
            return true;
        }

        PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(ImageData.data() + ImportDir->VirtualAddress);

        while (ImportDesc->Name != 0) {
            const char* DllName = (const char*)(ImageData.data() + ImportDesc->Name);
            uintptr_t ModuleBase = GetModuleBase(DllName);
            if (ModuleBase == 0) {
                std::cerr << "[!] Failed to load module: " << DllName << "\n";
                ImportDesc++;
                continue;
            }

            uintptr_t* IAT = (uintptr_t*)(ImageData.data() + ImportDesc->FirstThunk);
            uintptr_t* INT = ImportDesc->OriginalFirstThunk ?
                (uintptr_t*)(ImageData.data() + ImportDesc->OriginalFirstThunk) : IAT;

            int Index = 0;
            while (INT[Index] != 0) {
                uintptr_t FuncAddr = 0;
                if (INT[Index] & 0x8000000000000000) {
                    WORD Ordinal = (WORD)(INT[Index] & 0xFFFF);
                    FuncAddr = GetProcAddress(ModuleBase, (const char*)(uintptr_t)Ordinal);
                } else {
                    PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(ImageData.data() + INT[Index]);
                    FuncAddr = GetProcAddress(ModuleBase, (const char*)ImportByName->Name);
                }

                if (FuncAddr == 0) {
                    std::cerr << "[!] Failed to resolve import: " << DllName << "\n";
                }

                IAT[Index] = FuncAddr;
                Index++;
            }

            ImportDesc++;
        }

        std::cout << "[+] Imports resolved\n";
        return true;
    }

    uintptr_t GetModuleBase(const char* ModuleName) {
        PPEB Peb = NtCurrentPeb();
        PPEB_LDR_DATA Ldr = Peb->Ldr;
        PLIST_ENTRY ListHead = &Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY ListEntry = ListHead->Flink;

        while (ListEntry != ListHead) {
            PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            char* Name = (char*)Entry->BaseDllName.Buffer;
            int Len = Entry->BaseDllName.Length / sizeof(WCHAR);

            std::string ModuleNameA;
            for (int i = 0; i < Len; i++) {
                ModuleNameA += (char)tolower(Name[i * 2]);
            }

            std::string Target(ModuleName);
            for (char& c : Target) c = (char)tolower(c);

            if (ModuleNameA == Target) {
                return (uintptr_t)Entry->DllBase;
            }

            ListEntry = ListEntry->Flink;
        }

        return 0;
    }

    uintptr_t GetProcAddress(uintptr_t ModuleBase, const char* ExportName) {
        PIMAGE_NT_HEADERS64 Nt = GetNtHeaders((const uint8_t*)ModuleBase);
        if (Nt == NULL) {
            return 0;
        }

        PIMAGE_DATA_DIRECTORY ExportDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (ExportDir->VirtualAddress == 0) {
            return 0;
        }

        PIMAGE_EXPORT_DIRECTORY Exports = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + ExportDir->VirtualAddress);
        DWORD* NameTable = (DWORD*)(ModuleBase + Exports->AddressOfNames);
        WORD* OrdinalTable = (WORD*)(ModuleBase + Exports->AddressOfNameOrdinals);
        DWORD* FuncTable = (DWORD*)(ModuleBase + Exports->AddressOfFunctions);

        for (DWORD i = 0; i < Exports->NumberOfNames; i++) {
            const char* Name = (const char*)(ModuleBase + NameTable[i]);
            if (strcmp(Name, ExportName) == 0) {
                WORD Ordinal = OrdinalTable[i];
                return ModuleBase + FuncTable[Ordinal];
            }
        }

        return 0;
    }

    void ErasePEHeaders(std::vector<uint8_t>& ImageData) {
        if (ImageData.size() < 0x1000) {
            return;
        }
        RtlZeroMemory(ImageData.data(), 0x1000);
    }

    uint32_t GetEntryPointOffset(const std::vector<uint8_t>& FileData) {
        PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)FileData.data();
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0x1000;
        }

        PIMAGE_NT_HEADERS64 Nt = (PIMAGE_NT_HEADERS64)(FileData.data() + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE) {
            return 0x1000;
        }

        return Nt->OptionalHeader.AddressOfEntryPoint;
    }
}
