# PhantomInject
Kernel-assisted manual map DLL injector for Counter-Strike 2 on Windows x64.

## Architecture

```
PhantomInject/
├── PhantomInject.sln          Visual Studio 2022 solution
├── driver/
│   ├── driver.cpp             Kernel-mode WDM driver
│   ├── driver.h               Driver internal API
│   └── Phantom.vcxproj        Driver project file
├── injector/
│   ├── main.cpp               Usermode injector
│   ├── injector.h             Injector class
│   ├── pe.cpp                 PE parser/relocator/resolver
│   ├── pe.h                   PE structures
│   └── PhantomInjector.vcxproj
├── client/
│   ├── client.cpp             CS2 payload DLL
│   ├── client.h
│   └── PhantomClient.vcxproj
├── shared/
│   └── protocol.h             Driver IOCTL definitions
└── scripts/
    └── build.bat              Build script
```

## How It Works

1. **Driver** (`Phantom.sys`) exposes IOCTL interface at `\\.\PhantomInject`
2. **Injector** finds `cs2.exe`, parses the target DLL, and prepares the image
3. Driver allocates memory in the target process via `KeStackAttachProcess`
4. Driver writes the prepared image into the target
5. Driver wipes PE headers to avoid `MEM_IMAGE` scanners
6. Driver writes shellcode that calls `DllMain` into the target
7. Driver queues a kernel APC and modifies the thread's trap frame to redirect execution to the shellcode

## Requirements

- Windows 10/11 x64
- Visual Studio 2022 with:
  - C++ desktop development workload
  - Windows Driver Kit (WDK)
  - Windows 10 SDK
- Test signing mode enabled (`bcdedit /set testsigning on`)

## Build

Open `PhantomInject.sln` in Visual Studio 2022 and build Release x64.

Or use the build script:
```cmd
scripts\build.bat
```

Outputs:
- `bin\Release\Phantom.sys` - Kernel driver
- `bin\Release\PhantomInjector.exe` - Usermode injector
- `bin\Release\PhantomClient.dll` - Target payload

## Usage

1. Enable test signing and reboot:
```cmd
bcdedit /set testsigning on
```

2. Load the driver (elevated PowerShell):
```cmd
sc create Phantom type= kernel binPath= "C:\path\to\Phantom.sys"
sc start Phantom
```

3. Launch CS2

4. Run injector (elevated):
```cmd
PhantomInjector.exe bin\Release\PhantomClient.dll
```

## Disclaimer

For educational and research purposes only. The author takes no responsibility for misuse.
