@REM SPDX-FileCopyrightText: 2026 amurcanov
@REM SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

@echo off
setlocal enabledelayedexpansion

set "VERIFY_ONLY=0"
if "%~1"=="" goto args_ok
if /I "%~1"=="--verify-native-only" (
    set "VERIFY_ONLY=1"
    goto args_ok
)
echo Usage: build_apk.bat [--verify-native-only]
exit /b 2

:args_ok
set "PROJECT_ROOT=%~dp0..\"
set "PROVENANCE_SCRIPT=%PROJECT_ROOT%scripts\native_client_provenance.ps1"
cd /d "%PROJECT_ROOT%"

echo === CSQTT APK Build Script ===
echo === Output: 3 APKs (universal, arm64-v8a, armeabi-v7a) ===
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%PROVENANCE_SCRIPT%" -Mode Verify
if %errorlevel% neq 0 (
    echo.
    echo Run rust-client\build_so.bat first to rebuild verified Rust native libraries.
    if "%VERIFY_ONLY%"=="0" if not defined CI pause
    exit /b 1
)
if "%VERIFY_ONLY%"=="1" (
    echo Native verification completed successfully.
    exit /b 0
)

:: 2. Find Android SDK so Gradle can locate it even if local.properties is stale
call "%PROJECT_ROOT%scripts\find_android_sdk.bat"
if %errorlevel% neq 0 (
    if not defined CI pause
    exit /b 1
)
set "ANDROID_HOME=%SDK_PATH%"

:: 3. Skipping clean for faster incremental builds
echo Incremental build...

:: 4. Build release APKs
echo Building release APKs...
call "%PROJECT_ROOT%gradlew.bat" :app:assembleRelease --no-daemon

if %errorlevel% neq 0 (
    echo.
    echo BUILD FAILED! Please check the errors above.
    if not defined CI pause
    exit /b 1
)

set "VERIFY_DEPLOY_ASSET=%PROJECT_ROOT%scripts\verify_apk_deploy_asset.ps1"
set "APK_DIR=app\build\outputs\apk\release"
for %%F in (
    "%APK_DIR%\app-universal-release.apk"
    "%APK_DIR%\app-arm64-v8a-release.apk"
    "%APK_DIR%\app-armeabi-v7a-release.apk"
) do (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_DEPLOY_ASSET%" -ApkPath "%%~fF"
    if errorlevel 1 goto verify_failed
)

:: 4. Create release directory
if not exist "app\release" mkdir "app\release"

:: 5. Copy and rename all APK variants
echo.
echo Copying APKs to release folder...

:: Universal APK (all architectures)
if exist "%APK_DIR%\app-universal-release.apk" (
    copy /Y "%APK_DIR%\app-universal-release.apk" "app\release\CSQTT-universal.apk" >nul
    for %%F in ("app\release\CSQTT-universal.apk") do echo   [OK] CSQTT-universal.apk  [%%~zF bytes]
) else (
    echo   [!!] Universal APK not found
)

:: arm64-v8a
if exist "%APK_DIR%\app-arm64-v8a-release.apk" (
    copy /Y "%APK_DIR%\app-arm64-v8a-release.apk" "app\release\CSQTT-arm64-v8a.apk" >nul
    for %%F in ("app\release\CSQTT-arm64-v8a.apk") do echo   [OK] CSQTT-arm64-v8a.apk  [%%~zF bytes]
) else (
    echo   [!!] arm64-v8a APK not found
)

:: armeabi-v7a
if exist "%APK_DIR%\app-armeabi-v7a-release.apk" (
    copy /Y "%APK_DIR%\app-armeabi-v7a-release.apk" "app\release\CSQTT-armeabi-v7a.apk" >nul
    for %%F in ("app\release\CSQTT-armeabi-v7a.apk") do echo   [OK] CSQTT-armeabi-v7a.apk  [%%~zF bytes]
) else (
    echo   [!!] armeabi-v7a APK not found
)

echo.
echo === DONE ===
echo Output directory: app\release\
echo.
echo   CSQTT-universal.apk    - all architectures in one APK
echo   CSQTT-arm64-v8a.apk    - 64-bit ARM only
echo   CSQTT-armeabi-v7a.apk  - 32-bit ARM only
echo.
if not defined CI pause
exit /b 0

:verify_failed
echo.
echo APK deploy asset verification failed. Release files were not replaced.
if not defined CI pause
exit /b 1
