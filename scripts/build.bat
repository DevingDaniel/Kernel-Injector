@echo off
echo ==========================================
echo    PhantomInject Build Script
echo ==========================================
echo.

echo [*] Building Driver...
msbuild "driver\Phantom.vcxproj" /m /p:Configuration=Release /p:Platform=x64
if %errorlevel% neq 0 (
    echo [ERROR] Driver build failed
    pause
    exit /b 1
)
echo [OK] Driver built successfully
echo.

echo [*] Building Injector...
msbuild "injector\PhantomInjector.vcxproj" /m /p:Configuration=Release /p:Platform=x64
if %errorlevel% neq 0 (
    echo [ERROR] Injector build failed
    pause
    exit /b 1
)
echo [OK] Injector built successfully
echo.

echo [*] Building Client...
msbuild "client\PhantomClient.vcxproj" /m /p:Configuration=Release /p:Platform=x64
if %errorlevel% neq 0 (
    echo [ERROR] Client build failed
    pause
    exit /b 1
)
echo [OK] Client built successfully
echo.

echo ==========================================
echo    Build Complete!
echo ==========================================
echo Output: bin\Release\
echo.
pause
