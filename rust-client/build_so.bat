@REM SPDX-FileCopyrightText: 2026 amurcanov
@REM SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

@echo off
setlocal enabledelayedexpansion

set "RUST_CLIENT_DIR=%~dp0"
set "PROJECT_ROOT=%~dp0..\"
set "ANDROID_JNILIBS=%PROJECT_ROOT%app\src\main\jniLibs"
set "PROVENANCE_SCRIPT=%PROJECT_ROOT%scripts\native_client_provenance.ps1"
set "PARALLEL_BUILD_SCRIPT=%RUST_CLIENT_DIR%build_android_abis.ps1"
set "ARM64_TARGET_DIR=%PROJECT_ROOT%build\rust-client-android-arm64"
set "ARMV7_TARGET_DIR=%PROJECT_ROOT%build\rust-client-android-armv7"
set "X86_64_TARGET_DIR=%PROJECT_ROOT%build\rust-client-android-x86_64"
set "RUN_TESTS="

if /I "%~1"=="--tests" set "RUN_TESTS=1"
if /I "%~1"=="--no-tests" set "RUN_TESTS=0"
if not "%~1"=="" if not defined RUN_TESTS (
    echo Usage: build_so.bat [--tests^|--no-tests]
    goto fail
)

if not defined RUN_TESTS (
    choice /C YN /N /M "Run fmt, clippy and tests before build? [Y/N]: "
    if errorlevel 2 (
        set "RUN_TESTS=0"
    ) else (
        set "RUN_TESTS=1"
    )
)

call "%PROJECT_ROOT%scripts\find_android_sdk_ndk.bat"
if %errorlevel% neq 0 goto fail

set "ANDROID_HOME=%SDK_PATH%"
set "ANDROID_SDK_ROOT=%SDK_PATH%"
set "ANDROID_NDK_HOME=%NDK_PATH%"
set "ANDROID_NDK_ROOT=%NDK_PATH%"

:: Reuse CMake and Ninja installed by Android SDK Manager.
set "CMAKE_BIN="
if exist "%SDK_PATH%\cmake" (
    for /f "delims=" %%D in ('dir /b /ad /o-n "%SDK_PATH%\cmake" 2^>nul') do (
        if not defined CMAKE_BIN if exist "%SDK_PATH%\cmake\%%D\bin\cmake.exe" if exist "%SDK_PATH%\cmake\%%D\bin\ninja.exe" (
            set "CMAKE_BIN=%SDK_PATH%\cmake\%%D\bin"
        )
    )
)
if defined CMAKE_BIN set "PATH=!CMAKE_BIN!;!PATH!"

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: cargo not found
    goto fail
)

cargo ndk --version >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: cargo-ndk not found. Run cargo install cargo-ndk
    goto fail
)

where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: CMake not found. Install it from Android SDK Manager.
    goto fail
)

where ninja >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Ninja not found. Install CMake from Android SDK Manager.
    goto fail
)

echo Using CMake: %CMAKE_BIN%

cd /d "%RUST_CLIENT_DIR%"
if "%RUN_TESTS%"=="1" (
    call :setup_msvc
    if !errorlevel! neq 0 goto fail
    powershell -NoProfile -ExecutionPolicy Bypass -File "%RUST_CLIENT_DIR%check_no_runtime_panics.ps1"
    if !errorlevel! neq 0 goto fail
    cargo fmt --all -- --check
    if !errorlevel! neq 0 goto fail
    cargo clippy --all-targets -- -D warnings
    if !errorlevel! neq 0 goto fail
    cargo test --quiet
    if !errorlevel! neq 0 goto fail
) else (
    echo Pre-build checks skipped
)

if not exist "%ANDROID_JNILIBS%\arm64-v8a" mkdir "%ANDROID_JNILIBS%\arm64-v8a"
if not exist "%ANDROID_JNILIBS%\armeabi-v7a" mkdir "%ANDROID_JNILIBS%\armeabi-v7a"
if not exist "%ANDROID_JNILIBS%\x86_64" mkdir "%ANDROID_JNILIBS%\x86_64"
if exist "%ANDROID_JNILIBS%\x86\libclient.so" del /Q "%ANDROID_JNILIBS%\x86\libclient.so"
powershell -NoProfile -ExecutionPolicy Bypass -File "%PARALLEL_BUILD_SCRIPT%" -ClientDir "%RUST_CLIENT_DIR:~0,-1%" -Arm64TargetDir "%ARM64_TARGET_DIR%" -Armv7TargetDir "%ARMV7_TARGET_DIR%" -X8664TargetDir "%X86_64_TARGET_DIR%"
if %errorlevel% neq 0 goto fail

copy /Y "%ARM64_TARGET_DIR%\aarch64-linux-android\release\client" "%ANDROID_JNILIBS%\arm64-v8a\libclient.so" >nul
if %errorlevel% neq 0 goto fail
copy /Y "%ARMV7_TARGET_DIR%\armv7-linux-androideabi\release\client" "%ANDROID_JNILIBS%\armeabi-v7a\libclient.so" >nul
if %errorlevel% neq 0 goto fail
copy /Y "%X86_64_TARGET_DIR%\x86_64-linux-android\release\client" "%ANDROID_JNILIBS%\x86_64\libclient.so" >nul
if %errorlevel% neq 0 goto fail

powershell -NoProfile -ExecutionPolicy Bypass -File "%PROVENANCE_SCRIPT%" -Mode Write
if %errorlevel% neq 0 goto fail
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROVENANCE_SCRIPT%" -Mode Verify
if %errorlevel% neq 0 goto fail

for %%F in ("%ANDROID_JNILIBS%\arm64-v8a\libclient.so") do echo arm64-v8a: %%~zF bytes
for %%F in ("%ANDROID_JNILIBS%\armeabi-v7a\libclient.so") do echo armeabi-v7a: %%~zF bytes
for %%F in ("%ANDROID_JNILIBS%\x86_64\libclient.so") do echo x86_64: %%~zF bytes

:end
echo Build completed successfully.
if not defined CI pause
exit /b 0

:fail
echo Build failed.
if not defined CI pause
exit /b 1

:setup_msvc
if defined INCLUDE if defined LIB exit /b 0

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VS_INSTALL="
set "VCVARS64="

if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if not defined VS_INSTALL set "VS_INSTALL=%%V"
    )
)

if defined VS_INSTALL (
    set "VCVARS64=!VS_INSTALL!\VC\Auxiliary\Build\vcvars64.bat"
)

if not defined VCVARS64 (
    for /f "delims=" %%V in ('dir /b /s /a:-d "%ProgramFiles%\Microsoft Visual Studio\vcvars64.bat" 2^>nul') do (
        if not defined VCVARS64 set "VCVARS64=%%V"
    )
)

if not defined VCVARS64 (
    echo Error: Visual Studio C++ x64 build environment not found.
    echo        Install the Desktop development with C++ workload.
    exit /b 1
)
if not exist "!VCVARS64!" (
    echo Error: vcvars64.bat not found at !VCVARS64!
    exit /b 1
)

call "!VCVARS64!" >nul
if errorlevel 1 (
    echo Error: failed to initialize the Visual Studio x64 build environment.
    exit /b 1
)
if not defined INCLUDE (
    echo Error: Visual Studio initialized without the C/C++ INCLUDE path.
    exit /b 1
)

echo Using MSVC environment: !VS_INSTALL!
exit /b 0
