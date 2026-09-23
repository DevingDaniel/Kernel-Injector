@echo off
echo ==========================================
echo    PhantomInject Quick Setup
echo ==========================================
echo.

echo [*] Enabling test signing...
bcdedit /set testsigning on
echo [OK] Test signing enabled. Please reboot your system.
echo.

echo ==========================================
pause
