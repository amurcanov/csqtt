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

$assetDirectory = Join-Path $projectRoot "app\src\main\assets"
$manifestPath = Join-Path $assetDirectory "csqtt.server-provenance.json"
$cargoTomlPath = Join-Path $projectRoot "rust-server\Cargo.toml"
$cargoLockPath = Join-Path $projectRoot "rust-server\Cargo.lock"
$wireProtocolPath = Join-Path $projectRoot "shared\wire_protocol.rs"
$schema = "csqtt.server-asset-provenance.v2"
$marker = "CSQTT_RUST_SERVER_PRODUCTION_V1"
$assetSpecs = @(
    [pscustomobject]@{ AssetName = "csqtt-linux-amd64"; Target = "x86_64-unknown-linux-musl"; ElfClass = 2; ElfMachine = 62 },
    [pscustomobject]@{ AssetName = "csqtt-linux-arm64"; Target = "aarch64-unknown-linux-musl"; ElfClass = 2; ElfMachine = 183 },
    [pscustomobject]@{ AssetName = "csqtt-linux-armv7"; Target = "armv7-unknown-linux-musleabihf"; ElfClass = 1; ElfMachine = 40 }
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
        return ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace("-", "")
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Get-CargoPackage {
    Assert-RegularFile -Path $cargoTomlPath -Label "Server Cargo.toml"
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
        throw "Unable to read Rust server package identity"
    }
    return [pscustomobject]@{ Name = $name; Version = $version }
}

function Get-WireProtocolRevision {
    Assert-RegularFile -Path $wireProtocolPath -Label "Wire protocol revision source"
    $match = [regex]::Match(
        [IO.File]::ReadAllText($wireProtocolPath),
        'WIRE_PROTOCOL_REVISION\s*:\s*&str\s*=\s*"([^"]+)"'
    )
    if (-not $match.Success) {
        throw "Wire protocol revision is missing"
    }
    return $match.Groups[1].Value
}

function Get-BuildInputHash {
    $files = @(
        (Join-Path $projectRoot "rust-server\build_linux.bat"),
        (Join-Path $projectRoot "rust-server\build_linux.sh"),
        $cargoTomlPath,
        $cargoLockPath,
        $wireProtocolPath,
        (Join-Path $projectRoot "shared\selective_fec.rs"),
        (Join-Path $projectRoot "shared\striped_scheduler.rs"),
        $PSCommandPath
    )
    $files += Get-ChildItem -LiteralPath (Join-Path $projectRoot "rust-server") -File -Filter *.rs |
        ForEach-Object { $_.FullName }
    $rootPrefix = $projectRoot.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    $builder = New-Object Text.StringBuilder
    foreach ($file in @($files | Sort-Object -Unique)) {
        Assert-RegularFile -Path $file -Label "Server build input"
        $fullPath = [IO.Path]::GetFullPath($file)
        if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Server build input escaped project root: $fullPath"
        }
        [void]$builder.Append($fullPath.Substring($rootPrefix.Length).Replace("\", "/"))
        [void]$builder.Append(":")
        [void]$builder.Append((Get-Sha256 -Path $fullPath))
        [void]$builder.Append("`n")
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($builder.ToString())))).Replace("-", "")
    }
    finally {
        $hash.Dispose()
    }
}

function Assert-ServerBinary {
    param($Spec, [string]$Revision)

    $binaryPath = Join-Path $assetDirectory $Spec.AssetName
    Assert-RegularFile -Path $binaryPath -Label "Linux server asset $($Spec.AssetName)"
    [byte[]]$bytes = [IO.File]::ReadAllBytes($binaryPath)
    if ($bytes.Length -lt 20 -or $bytes[0] -ne 0x7f -or $bytes[1] -ne 0x45 -or $bytes[2] -ne 0x4c -or $bytes[3] -ne 0x46) {
        throw "Linux server asset $($Spec.AssetName) is not ELF"
    }
    if ($bytes[4] -ne $Spec.ElfClass -or $bytes[5] -ne 1) {
        throw "ELF class or endianness mismatch for $($Spec.AssetName)"
    }
    $machine = [int]$bytes[18] -bor ([int]$bytes[19] -shl 8)
    if ($machine -ne $Spec.ElfMachine) {
        throw "ELF machine mismatch for $($Spec.AssetName): expected $($Spec.ElfMachine), got $machine"
    }
    if (-not ([Text.Encoding]::ASCII.GetString($bytes).Contains($Revision))) {
        throw "Linux server asset $($Spec.AssetName) does not expose wire protocol revision $Revision"
    }
    $file = Get-Item -LiteralPath $binaryPath
    return [pscustomobject]@{
        assetName = $Spec.AssetName
        target = $Spec.Target
        elfClass = $Spec.ElfClass
        elfMachine = $Spec.ElfMachine
        binarySize = [int64]$file.Length
        binarySha256 = Get-Sha256 -Path $binaryPath
    }
}

$package = Get-CargoPackage
$revision = Get-WireProtocolRevision
$buildInputHash = Get-BuildInputHash

if ($Mode -eq "Write") {
    Assert-RegularFile -Path $cargoLockPath -Label "Server Cargo.lock"
    $artifacts = @($assetSpecs | ForEach-Object { Assert-ServerBinary -Spec $_ -Revision $revision })
    $manifest = [ordered]@{
        schema = $schema
        marker = $marker
        producer = "rust-server/build_linux.bat"
        runtime = "rust"
        package = $package.Name
        version = $package.Version
        wireProtocolRevision = $revision
        buildInputSha256 = $buildInputHash
        cargoTomlSha256 = Get-Sha256 -Path $cargoTomlPath
        cargoLockSha256 = Get-Sha256 -Path $cargoLockPath
        artifacts = $artifacts
        generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    }
    $temporaryPath = "$manifestPath.tmp.$PID"
    [IO.File]::WriteAllText($temporaryPath, ($manifest | ConvertTo-Json -Depth 4) + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporaryPath -Destination $manifestPath -Force
    Write-Output "Wrote Rust server provenance: $manifestPath"
    exit 0
}

Assert-RegularFile -Path $manifestPath -Label "Rust server provenance"
try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
}
catch {
    throw "Invalid Rust server provenance JSON: $manifestPath"
}

if ($manifest.schema -ne $schema -or
    $manifest.marker -ne $marker -or
    $manifest.producer -ne "rust-server/build_linux.bat" -or
    $manifest.runtime -ne "rust") {
    throw "Rust server provenance identity mismatch"
}
if ($manifest.package -ne $package.Name -or
    $manifest.version -ne $package.Version -or
    $manifest.wireProtocolRevision -ne $revision) {
    throw "Rust server package or wire protocol identity changed after build"
}
if ($manifest.cargoTomlSha256 -ne (Get-Sha256 -Path $cargoTomlPath) -or
    $manifest.cargoLockSha256 -ne (Get-Sha256 -Path $cargoLockPath) -or
    $manifest.buildInputSha256 -ne $buildInputHash) {
    throw "Rust server source changed after the production asset build"
}
$manifestArtifacts = @($manifest.artifacts)
if ($manifestArtifacts.Count -ne $assetSpecs.Count) {
    throw "Rust server provenance artifact count mismatch"
}
foreach ($spec in $assetSpecs) {
    $matches = @($manifestArtifacts | Where-Object { $_.assetName -eq $spec.AssetName })
    if ($matches.Count -ne 1) {
        throw "Rust server provenance is missing $($spec.AssetName)"
    }
    $actual = Assert-ServerBinary -Spec $spec -Revision $revision
    $record = $matches[0]
    if ($record.target -ne $actual.target -or
        [int]$record.elfClass -ne [int]$actual.elfClass -or
        [int]$record.elfMachine -ne [int]$actual.elfMachine -or
        [int64]$record.binarySize -ne [int64]$actual.binarySize -or
        $record.binarySha256 -ne $actual.binarySha256) {
        throw "Rust server asset does not match provenance: $($spec.AssetName)"
    }
}

Write-Output "Rust server provenance verified: $marker"
