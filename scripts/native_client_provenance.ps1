# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Write", "Verify")]
    [string]$Mode,
    [string]$Root
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Root)) {
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
}
else {
    $projectRoot = [IO.Path]::GetFullPath($Root)
}
$manifestPath = Join-Path $projectRoot "app\src\main\libclient.provenance.json"
$cargoTomlPath = Join-Path $projectRoot "rust-client\Cargo.toml"
$cargoLockPath = Join-Path $projectRoot "rust-client\Cargo.lock"
$marker = "CSQTT_RUST_NATIVE_PRODUCTION_V1"
$schema = "csqtt.native-client-provenance.v3"
$producer = "rust-client/build_so.bat"
$transport = "rust-turn-sans-io-rfc8656-channeldata"
$transportMarker = "CSQTT_RUST_TURN_SANS_IO_V1"
$nativeCoreAbi = 1

$specs = @(
    [pscustomobject]@{
        Abi = "arm64-v8a"
        Target = "aarch64-linux-android"
        RelativePath = "app/src/main/jniLibs/arm64-v8a/libclient.so"
        ProductionPath = Join-Path $projectRoot "app\src\main\jniLibs\arm64-v8a\libclient.so"
        CargoPath = Join-Path $projectRoot "build\rust-client-android-arm64\aarch64-linux-android\release\client"
        ElfClass = 2
        ElfMachine = 183
    },
    [pscustomobject]@{
        Abi = "armeabi-v7a"
        Target = "armv7-linux-androideabi"
        RelativePath = "app/src/main/jniLibs/armeabi-v7a/libclient.so"
        ProductionPath = Join-Path $projectRoot "app\src\main\jniLibs\armeabi-v7a\libclient.so"
        CargoPath = Join-Path $projectRoot "build\rust-client-android-armv7\armv7-linux-androideabi\release\client"
        ElfClass = 1
        ElfMachine = 40
    },
    [pscustomobject]@{
        Abi = "x86_64"
        Target = "x86_64-linux-android"
        RelativePath = "app/src/main/jniLibs/x86_64/libclient.so"
        ProductionPath = Join-Path $projectRoot "app\src\main\jniLibs\x86_64\libclient.so"
        CargoPath = Join-Path $projectRoot "build\rust-client-android-x86_64\x86_64-linux-android\release\client"
        ElfClass = 2
        ElfMachine = 62
    }
)

function Assert-RegularFile {
    param([string]$Path, [string]$Label)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label not found: $Path"
    }
    if ((Get-Item -LiteralPath $Path).Length -le 0) {
        throw "$Label is empty: $Path"
    }
}

function Get-Sha256 {
    param([string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $hasher.ComputeHash($stream)
        return ([BitConverter]::ToString($hash)).Replace("-", "")
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Get-BuildInputHash {
    $entries = @(
        (Join-Path $projectRoot "rust-client\build_so.bat"),
        (Join-Path $projectRoot "rust-client\build_android_abis.ps1"),
        (Join-Path $projectRoot "rust-client\Cargo.toml"),
        (Join-Path $projectRoot "rust-client\Cargo.lock"),
        (Join-Path $projectRoot "rust-client"),
        (Join-Path $projectRoot "rust-client\dispatcher"),
        (Join-Path $projectRoot "rust-client\vendor\primp"),
        (Join-Path $projectRoot "scripts\find_android_sdk_ndk.bat"),
        (Join-Path $projectRoot "scripts\native_client_provenance.ps1"),
        (Join-Path $projectRoot "shared\wire_protocol.rs"),
        (Join-Path $projectRoot "shared\striped_scheduler.rs")
    )
    $files = @()
    foreach ($entry in $entries) {
        if (Test-Path -LiteralPath $entry -PathType Leaf) {
            $files += [IO.Path]::GetFullPath($entry)
        }
        elseif (Test-Path -LiteralPath $entry -PathType Container) {
            if ($entry -eq (Join-Path $projectRoot "rust-client")) {
                # Crate root: hash only top-level sources, skip target/ and vendor/
                $files += Get-ChildItem -LiteralPath $entry -File -Filter *.rs |
                    ForEach-Object { $_.FullName }
            }
            else {
                $files += Get-ChildItem -LiteralPath $entry -Recurse -File |
                    ForEach-Object { $_.FullName }
            }
        }
        else {
            throw "Native build input not found: $entry"
        }
    }
    $rootPrefix = $projectRoot.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    $builder = New-Object Text.StringBuilder
    foreach ($file in @($files | Sort-Object -Unique)) {
        $fullPath = [IO.Path]::GetFullPath($file)
        if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Native build input escaped project root: $fullPath"
        }
        $relativePath = $fullPath.Substring($rootPrefix.Length).Replace("\", "/")
        [void]$builder.Append($relativePath)
        [void]$builder.Append(":")
        [void]$builder.Append((Get-Sha256 -Path $fullPath))
        [void]$builder.Append("`n")
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace("-", "")
    }
    finally {
        $hasher.Dispose()
    }
}

function Assert-Elf {
    param(
        [string]$Path,
        [int]$ExpectedClass,
        [int]$ExpectedMachine,
        [string]$Abi
    )

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $header = New-Object byte[] 20
        $offset = 0
        while ($offset -lt $header.Length) {
            $read = $stream.Read($header, $offset, $header.Length - $offset)
            if ($read -eq 0) {
                throw "Invalid ELF header for $Abi`: $Path"
            }
            $offset += $read
        }
    }
    finally {
        $stream.Dispose()
    }

    if ($header[0] -ne 0x7f -or $header[1] -ne 0x45 -or $header[2] -ne 0x4c -or $header[3] -ne 0x46) {
        throw "Production artifact is not ELF for $Abi`: $Path"
    }
    if ($header[4] -ne $ExpectedClass -or $header[5] -ne 1) {
        throw "ELF class or endianness mismatch for $Abi`: $Path"
    }

    $elfType = [int]$header[16] -bor ([int]$header[17] -shl 8)
    $machine = [int]$header[18] -bor ([int]$header[19] -shl 8)
    if ($elfType -ne 3) {
        throw "Production artifact is not an Android PIE/ET_DYN for $Abi`: $Path"
    }
    if ($machine -ne $ExpectedMachine) {
        throw "ELF machine mismatch for $Abi`: expected $ExpectedMachine, got $machine"
    }
}

function Test-BytePattern {
    param([string]$Path, [byte[]]$Pattern)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $buffer = New-Object byte[] 65536
        $matched = 0
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            for ($index = 0; $index -lt $read; $index++) {
                if ($buffer[$index] -eq $Pattern[$matched]) {
                    $matched++
                    if ($matched -eq $Pattern.Length) {
                        return $true
                    }
                }
                elseif ($buffer[$index] -eq $Pattern[0]) {
                    $matched = 1
                }
                else {
                    $matched = 0
                }
            }
        }
        return $false
    }
    finally {
        $stream.Dispose()
    }
}

function Get-CargoPackage {
    Assert-RegularFile -Path $cargoTomlPath -Label "Cargo.toml"

    $insidePackage = $false
    $name = $null
    $version = $null
    foreach ($line in Get-Content -LiteralPath $cargoTomlPath) {
        $trimmed = $line.Trim()
        if ($trimmed -eq "[package]") {
            $insidePackage = $true
            continue
        }
        if ($insidePackage -and $trimmed.StartsWith("[")) {
            break
        }
        if ($insidePackage -and $trimmed -match '^(name|version)\s*=\s*"([^"]+)"') {
            if ($matches[1] -eq "name") {
                $name = $matches[2]
            }
            else {
                $version = $matches[2]
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($version)) {
        throw "Unable to read Rust package identity from $cargoTomlPath"
    }
    return [pscustomobject]@{ Name = $name; Version = $version }
}

function Assert-RustArtifact {
    param($Spec, [bool]$RequireCargoMatch)

    Assert-RegularFile -Path $Spec.ProductionPath -Label "$($Spec.Abi) production artifact"
    Assert-Elf -Path $Spec.ProductionPath -ExpectedClass $Spec.ElfClass -ExpectedMachine $Spec.ElfMachine -Abi $Spec.Abi

    $goBuildInfo = [Text.Encoding]::ASCII.GetBytes("Go buildinf:")
    if (Test-BytePattern -Path $Spec.ProductionPath -Pattern $goBuildInfo) {
        throw "Go build metadata detected in production artifact for $($Spec.Abi)"
    }
    $transportIdentity = [Text.Encoding]::ASCII.GetBytes($transportMarker)
    if (-not (Test-BytePattern -Path $Spec.ProductionPath -Pattern $transportIdentity)) {
        throw "Rust TURN transport identity is missing for $($Spec.Abi)"
    }

    if ($RequireCargoMatch) {
        Assert-RegularFile -Path $Spec.CargoPath -Label "$($Spec.Abi) Cargo artifact"
        $productionHash = Get-Sha256 -Path $Spec.ProductionPath
        $cargoHash = Get-Sha256 -Path $Spec.CargoPath
        if ($productionHash -ne $cargoHash) {
            throw "Production artifact does not match the Cargo output for $($Spec.Abi)"
        }
    }
}

if ($Mode -eq "Write") {
    Assert-RegularFile -Path $cargoLockPath -Label "Cargo.lock"
    $package = Get-CargoPackage
    $buildInputHash = Get-BuildInputHash
    $artifacts = @()

    foreach ($spec in $specs) {
        Assert-RustArtifact -Spec $spec -RequireCargoMatch $true
        $file = Get-Item -LiteralPath $spec.ProductionPath
        $artifacts += [ordered]@{
            abi = $spec.Abi
            target = $spec.Target
            path = $spec.RelativePath
            size = [long]$file.Length
            sha256 = Get-Sha256 -Path $spec.ProductionPath
        }
    }

    $manifest = [ordered]@{
        schema = $schema
        marker = $marker
        producer = $producer
        runtime = "rust"
        buildSystem = "cargo-ndk"
        profile = "release"
        transport = $transport
        transportMarker = $transportMarker
        nativeCoreAbi = $nativeCoreAbi
        package = $package.Name
        version = $package.Version
        buildInputSha256 = $buildInputHash
        cargoTomlSha256 = Get-Sha256 -Path $cargoTomlPath
        cargoLockSha256 = Get-Sha256 -Path $cargoLockPath
        generatedAtUtc = [DateTime]::UtcNow.ToString("o")
        artifacts = $artifacts
    }

    $json = $manifest | ConvertTo-Json -Depth 6
    $temporaryPath = "$manifestPath.tmp.$PID"
    [IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporaryPath -Destination $manifestPath -Force
    Write-Output "Wrote Rust native provenance: $manifestPath"
    exit 0
}

Assert-RegularFile -Path $manifestPath -Label "Rust native provenance"

try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
}
catch {
    throw "Invalid Rust native provenance JSON: $manifestPath"
}

if ($manifest.schema -ne $schema -or
    $manifest.marker -ne $marker -or
    $manifest.producer -ne $producer -or
    $manifest.runtime -ne "rust" -or
    $manifest.buildSystem -ne "cargo-ndk" -or
    $manifest.profile -ne "release" -or
    $manifest.transport -ne $transport -or
    $manifest.transportMarker -ne $transportMarker -or
    [int64]$manifest.nativeCoreAbi -ne $nativeCoreAbi) {
    throw "Rust native provenance identity mismatch: $manifestPath"
}

$package = Get-CargoPackage
if ($manifest.package -ne $package.Name -or $manifest.version -ne $package.Version) {
    throw "Rust package identity does not match provenance"
}
if ($manifest.cargoTomlSha256 -ne (Get-Sha256 -Path $cargoTomlPath)) {
    throw "Cargo.toml changed after the production native build"
}
if ($manifest.cargoLockSha256 -ne (Get-Sha256 -Path $cargoLockPath)) {
    throw "Cargo.lock changed after the production native build"
}
if ($manifest.buildInputSha256 -ne (Get-BuildInputHash)) {
    throw "Rust native source changed after the production native build"
}

$manifestArtifacts = @($manifest.artifacts)
if ($manifestArtifacts.Count -ne $specs.Count) {
    throw "Rust native provenance must contain exactly $($specs.Count) artifacts"
}

foreach ($spec in $specs) {
    Assert-RustArtifact -Spec $spec -RequireCargoMatch $true
    $entries = @($manifestArtifacts | Where-Object { $_.abi -eq $spec.Abi })
    if ($entries.Count -ne 1) {
        throw "Rust native provenance must contain one entry for $($spec.Abi)"
    }
    $entry = $entries[0]
    $file = Get-Item -LiteralPath $spec.ProductionPath
    $hash = Get-Sha256 -Path $spec.ProductionPath
    if ($entry.target -ne $spec.Target -or
        $entry.path -ne $spec.RelativePath -or
        [long]$entry.size -ne [long]$file.Length -or
        $entry.sha256.ToUpperInvariant() -ne $hash) {
        throw "Rust native provenance artifact mismatch for $($spec.Abi)"
    }
}

Write-Output "Rust native provenance verified: $marker"
