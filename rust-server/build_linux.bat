@REM SPDX-FileCopyrightText: 2026 amurcanov
@REM SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

@echo off
setlocal EnableDelayedExpansion

set "BUILD_SCRIPT=%~f0"
set "SERVER_DIR=%~dp0"
set "PROJECT_ROOT=%~dp0..\"
set "LINUX_TARGET_DIR=%PROJECT_ROOT%build\csqtt-uring-linux"
set "CLIPPY_TARGET_DIR=%PROJECT_ROOT%build\csqtt-uring-linux-clippy"
set "CARGO_TARGET_DIR=%LINUX_TARGET_DIR%"
set "ASSETS_DIR=%PROJECT_ROOT%app\src\main\assets"
set "PROVENANCE_SCRIPT=%PROJECT_ROOT%scripts\server_asset_provenance.ps1"
set "VARIANT_RUNNER=%SERVER_DIR%build_linux_variants.ps1"
set "RUN_TESTS="
set "DIAGNOSTICS="

if /I "%~1"=="--build-variant" goto build_variant_worker
if /I "%~1"=="--test-zig-cc" goto test_zig_cc
if /I "%~1"=="--test-zig-cxx" goto test_zig_cxx

:parse_args
if "%~1"=="" goto args_ready
if /I "%~1"=="--tests" (
    set "RUN_TESTS=1"
    shift
    goto parse_args
)
if /I "%~1"=="--no-tests" (
    set "RUN_TESTS=0"
    shift
    goto parse_args
)
if /I "%~1"=="--diagnostics" (
    set "DIAGNOSTICS=1"
    shift
    goto parse_args
)
echo Usage: build_linux.bat [--tests^|--no-tests] [--diagnostics]
goto fail

:args_ready
if defined CI if not defined RUN_TESTS set "RUN_TESTS=1"

if not defined RUN_TESTS (
    choice /C YN /N /M "Run fmt, clippy and Linux test compilation before build? [Y/N]: "
    if errorlevel 2 (
        set "RUN_TESTS=0"
    ) else (
        set "RUN_TESTS=1"
    )
)

set "CARGO_FEATURES="
if defined DIAGNOSTICS set "CARGO_FEATURES=--features diagnostics"

cd /d "%SERVER_DIR%"

where cargo >nul 2>nul
if errorlevel 1 (
    echo Error: cargo not found.
    goto fail
)

where zig >nul 2>nul
if errorlevel 1 (
    set "ZIG_EXE="
    if defined LOCALAPPDATA (
        for /f "delims=" %%F in ('where /R "%LOCALAPPDATA%\Microsoft\WinGet\Packages" zig.exe 2^>nul') do (
            if not defined ZIG_EXE set "ZIG_EXE=%%F"
        )
    )
    if defined ZIG_EXE (
        for %%D in ("!ZIG_EXE!") do set "PATH=%%~dpD;!PATH!"
    )
)

where zig >nul 2>nul
if errorlevel 1 (
    echo Error: Zig not found. Install it with: winget install --id zig.zig -e
    goto fail
)

cargo zigbuild --help >nul 2>nul
if errorlevel 1 (
    echo Error: cargo-zigbuild not found. Install it with: cargo install cargo-zigbuild --locked
    goto fail
)

for /f "delims=" %%V in ('zig version') do echo Using Zig: %%V
echo Cargo target directory: %LINUX_TARGET_DIR%

echo Adding musl target...
rustup target add x86_64-unknown-linux-musl
if errorlevel 1 goto fail
rustup target add aarch64-unknown-linux-musl
if errorlevel 1 goto fail
rustup target add armv7-unknown-linux-musleabihf
if errorlevel 1 goto fail

if "%RUN_TESTS%"=="1" (
    echo Running Linux pre-build checks...
    call :setup_test_zig_wrappers
    if !errorlevel! neq 0 goto fail
    cargo fmt --all -- --check
    if !errorlevel! neq 0 goto fail

    set "CARGO_TARGET_DIR=%CLIPPY_TARGET_DIR%"
    cargo clippy --release --target x86_64-unknown-linux-musl !CARGO_FEATURES! --all-targets -- -D warnings
    if !errorlevel! neq 0 goto fail
    set "CARGO_TARGET_DIR=%LINUX_TARGET_DIR%"

    echo Compiling Linux musl test binaries - they cannot run on Windows...
    cargo zigbuild --target x86_64-unknown-linux-musl !CARGO_FEATURES! --tests
    if !errorlevel! neq 0 goto fail
    call :cleanup_test_zig_wrappers
    echo Linux musl tests compiled successfully. Run build_linux.sh --tests on Linux to execute them.
) else (
    echo Pre-build checks skipped
)

echo Building Linux server variants using cargo-zigbuild...
if not exist "%ASSETS_DIR%" mkdir "%ASSETS_DIR%"
if not exist "%VARIANT_RUNNER%" (
    echo Error: parallel variant runner not found: %VARIANT_RUNNER%
    goto fail
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%VARIANT_RUNNER%" -BuildScript "%BUILD_SCRIPT%"
if errorlevel 1 goto fail

echo Verifying Linux server assets...
if not exist "%ASSETS_DIR%" mkdir "%ASSETS_DIR%"
del /q "%ASSETS_DIR%\csqtt" >nul 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROVENANCE_SCRIPT%" -Mode Write
if errorlevel 1 goto fail
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROVENANCE_SCRIPT%" -Mode Verify
if errorlevel 1 goto fail
for %%F in ("%ASSETS_DIR%\csqtt-linux-amd64") do echo csqtt-linux-amd64: %%~zF bytes
for %%F in ("%ASSETS_DIR%\csqtt-linux-arm64") do echo csqtt-linux-arm64: %%~zF bytes
for %%F in ("%ASSETS_DIR%\csqtt-linux-armv7") do echo csqtt-linux-armv7: %%~zF bytes
echo Success: Linux server variants copied to %ASSETS_DIR%
exit /b 0

:fail
call :cleanup_test_zig_wrappers
echo Build failed.
if not defined CI pause
exit /b 1

:build_variant_worker
shift
cd /d "%SERVER_DIR%"
call :build_server_variant "%~1" "%~2"
exit /b !errorlevel!

:build_server_variant
set "CARGO_TARGET_DIR=%PROJECT_ROOT%build\csqtt-uring-linux-%~2"
cargo zigbuild --release --target %~1 !CARGO_FEATURES!
if errorlevel 1 exit /b 1
copy /Y "%CARGO_TARGET_DIR%\%~1\release\csqtt" "%ASSETS_DIR%\%~2" >nul
if errorlevel 1 exit /b 1
exit /b 0

:setup_test_zig_wrappers
set "TEST_ZIG_WRAPPER_DIR=%TEMP%\csqtt-zig-test-%RANDOM%%RANDOM%"
mkdir "%TEST_ZIG_WRAPPER_DIR%" >nul 2>nul
if errorlevel 1 exit /b 1
>"%TEST_ZIG_WRAPPER_DIR%\zigcc.cmd" echo @call "%BUILD_SCRIPT%" --test-zig-cc %%*
>"%TEST_ZIG_WRAPPER_DIR%\zigcxx.cmd" echo @call "%BUILD_SCRIPT%" --test-zig-cxx %%*
>"%TEST_ZIG_WRAPPER_DIR%\zigar.cmd" echo @zig ar %%*
set "CC_x86_64_unknown_linux_musl=%TEST_ZIG_WRAPPER_DIR%\zigcc.cmd"
set "CXX_x86_64_unknown_linux_musl=%TEST_ZIG_WRAPPER_DIR%\zigcxx.cmd"
set "AR_x86_64_unknown_linux_musl=%TEST_ZIG_WRAPPER_DIR%\zigar.cmd"
exit /b 0

:cleanup_test_zig_wrappers
set "CC_x86_64_unknown_linux_musl="
set "CXX_x86_64_unknown_linux_musl="
set "AR_x86_64_unknown_linux_musl="
if not defined TEST_ZIG_WRAPPER_DIR exit /b 0
del /q "%TEST_ZIG_WRAPPER_DIR%\zigcc.cmd" "%TEST_ZIG_WRAPPER_DIR%\zigcxx.cmd" "%TEST_ZIG_WRAPPER_DIR%\zigar.cmd" >nul 2>nul
rmdir "%TEST_ZIG_WRAPPER_DIR%" >nul 2>nul
set "TEST_ZIG_WRAPPER_DIR="
exit /b 0

:test_zig_cc
@echo off
setlocal EnableDelayedExpansion
shift
set "ARGS="
:test_zig_cc_collect
if "%~1"=="" goto test_zig_cc_run
if /I not "%~1"=="--target=x86_64-unknown-linux-musl" set "ARGS=!ARGS! "%~1""
shift
goto test_zig_cc_collect
:test_zig_cc_run
zig cc -target x86_64-linux-musl !ARGS!
exit /b %errorlevel%

:test_zig_cxx
@echo off
setlocal EnableDelayedExpansion
shift
set "ARGS="
:test_zig_cxx_collect
if "%~1"=="" goto test_zig_cxx_run
if /I not "%~1"=="--target=x86_64-unknown-linux-musl" set "ARGS=!ARGS! "%~1""
shift
goto test_zig_cxx_collect
:test_zig_cxx_run
zig c++ -target x86_64-linux-musl !ARGS!
exit /b %errorlevel%
