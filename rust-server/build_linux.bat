@REM SPDX-FileCopyrightText: 2026 amurcanov
@REM SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

@echo off
if /I "%~1"=="--zig-cc" goto zig_cc
if /I "%~1"=="--zig-cxx" goto zig_cxx

setlocal enabledelayedexpansion

set "SERVER_DIR=%~dp0"
set "PROJECT_ROOT=%~dp0..\"
set "LINUX_TARGET_DIR=%PROJECT_ROOT%build\csqtt-uring-linux"
set "CLIPPY_TARGET_DIR=%PROJECT_ROOT%build\csqtt-uring-linux-clippy"
set "CARGO_TARGET_DIR=%LINUX_TARGET_DIR%"
set "ASSETS_DIR=%PROJECT_ROOT%app\src\main\assets"
set "RUN_TESTS="
set "DIAGNOSTICS="
set "ZIG_WRAPPER_DIR="

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

call :setup_zig_wrappers
if errorlevel 1 goto fail

echo Adding musl target...
rustup target add x86_64-unknown-linux-musl
if errorlevel 1 goto fail

if "%RUN_TESTS%"=="1" (
    echo Running Linux pre-build checks...
    cargo fmt --all -- --check
    if !errorlevel! neq 0 goto fail

    set "CARGO_TARGET_DIR=%CLIPPY_TARGET_DIR%"
    cargo clippy --release --target x86_64-unknown-linux-musl !CARGO_FEATURES! --all-targets -- -D warnings
    if !errorlevel! neq 0 goto fail
    set "CARGO_TARGET_DIR=%LINUX_TARGET_DIR%"

    echo Compiling Linux musl test binaries - they cannot run on Windows...
    cargo zigbuild --target x86_64-unknown-linux-musl !CARGO_FEATURES! --tests
    if !errorlevel! neq 0 goto fail
    echo Linux musl tests compiled successfully. Run build_linux.sh --tests on Linux to execute them.
) else (
    echo Pre-build checks skipped
)

echo Building for Linux using cargo-zigbuild...
cargo zigbuild --release --target x86_64-unknown-linux-musl !CARGO_FEATURES!

if errorlevel 1 goto fail

call :cleanup_zig_wrappers

echo Copying binaries to assets directory...
if not exist "%ASSETS_DIR%" mkdir "%ASSETS_DIR%"
copy /Y "%CARGO_TARGET_DIR%\x86_64-unknown-linux-musl\release\csqtt" "%ASSETS_DIR%\csqtt" >nul
if errorlevel 1 goto fail
for %%F in ("%ASSETS_DIR%\csqtt") do echo csqtt: %%~zF bytes
echo Success: Linux musl binary copied to %ASSETS_DIR%
exit /b 0

:fail
call :cleanup_zig_wrappers
echo Build failed.
if not defined CI pause
exit /b 1

:setup_zig_wrappers
set "ZIG_WRAPPER_DIR=%TEMP%\csqtt-zig-musl"
if not exist "%ZIG_WRAPPER_DIR%" mkdir "%ZIG_WRAPPER_DIR%" >nul 2>nul
if errorlevel 1 exit /b 1
>"%ZIG_WRAPPER_DIR%\zigcc.cmd" echo @call "%~f0" --zig-cc %%*
>"%ZIG_WRAPPER_DIR%\zigcxx.cmd" echo @call "%~f0" --zig-cxx %%*
>"%ZIG_WRAPPER_DIR%\zigar.cmd" echo @zig ar %%*
set "CC_x86_64_unknown_linux_musl=%ZIG_WRAPPER_DIR%\zigcc.cmd"
set "CXX_x86_64_unknown_linux_musl=%ZIG_WRAPPER_DIR%\zigcxx.cmd"
set "AR_x86_64_unknown_linux_musl=%ZIG_WRAPPER_DIR%\zigar.cmd"
set "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=%ZIG_WRAPPER_DIR%\zigcc.cmd"
exit /b 0

:cleanup_zig_wrappers
set "CC_x86_64_unknown_linux_musl="
set "CXX_x86_64_unknown_linux_musl="
set "AR_x86_64_unknown_linux_musl="
set "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="
if not defined ZIG_WRAPPER_DIR exit /b 0
del /q "%ZIG_WRAPPER_DIR%\zigcc.cmd" "%ZIG_WRAPPER_DIR%\zigcxx.cmd" "%ZIG_WRAPPER_DIR%\zigar.cmd" >nul 2>nul
rmdir "%ZIG_WRAPPER_DIR%" >nul 2>nul
set "ZIG_WRAPPER_DIR="
exit /b 0

:zig_cc
@echo off
setlocal EnableDelayedExpansion
shift
set "ARGS="
:zig_cc_collect
if "%~1"=="" goto zig_cc_run
if /I not "%~1"=="--target=x86_64-unknown-linux-musl" set "ARGS=!ARGS! "%~1""
shift
goto zig_cc_collect
:zig_cc_run
zig cc -target x86_64-linux-musl !ARGS!
exit /b %errorlevel%

:zig_cxx
@echo off
setlocal EnableDelayedExpansion
shift
set "ARGS="
:zig_cxx_collect
if "%~1"=="" goto zig_cxx_run
if /I not "%~1"=="--target=x86_64-unknown-linux-musl" set "ARGS=!ARGS! "%~1""
shift
goto zig_cxx_collect
:zig_cxx_run
zig c++ -target x86_64-linux-musl !ARGS!
exit /b %errorlevel%
