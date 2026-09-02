# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

param(
    [Parameter(Mandatory = $true)][string]$ClientDir,
    [Parameter(Mandatory = $true)][string]$Arm64TargetDir,
    [Parameter(Mandatory = $true)][string]$Armv7TargetDir,
    [Parameter(Mandatory = $true)][string]$X8664TargetDir
)

$ErrorActionPreference = "Stop"
$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$builds = @(
    @{ Abi = "arm64-v8a"; TargetDir = $Arm64TargetDir },
    @{ Abi = "armeabi-v7a"; TargetDir = $Armv7TargetDir },
    @{ Abi = "x86_64"; TargetDir = $X8664TargetDir }
)
$jobsPerAbi = [Math]::Max(1, [int][Math]::Floor([Environment]::ProcessorCount / $builds.Count))
$running = @()

foreach ($build in $builds) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $cargo
    $info.WorkingDirectory = $ClientDir
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $quotedTargetDir = '"' + $build.TargetDir.Replace('"', '\"') + '"'
    $info.Arguments = "ndk -t $($build.Abi) -P 26 build --release --jobs $jobsPerAbi --target-dir $quotedTargetDir"
    $info.EnvironmentVariables["CMAKE_BUILD_PARALLEL_LEVEL"] = [string]$jobsPerAbi
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) {
        throw "Failed to start $($build.Abi) build"
    }
    Write-Host "Started $($build.Abi) build with $jobsPerAbi jobs"
    $running += @{ Abi = $build.Abi; Process = $process }
}

$failed = $false
foreach ($build in $running) {
    $build.Process.WaitForExit()
    if ($build.Process.ExitCode -ne 0) {
        Write-Host "$($build.Abi) build failed with exit code $($build.Process.ExitCode)" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "Finished $($build.Abi) build"
    }
    $build.Process.Dispose()
}

if ($failed) {
    exit 1
}
