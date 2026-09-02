# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApkPath,

    [string]$SourcePath = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($SourcePath)) {
    $SourcePath = Join-Path $PSScriptRoot "..\app\src\main\assets\deploy.sh"
}

function Get-Sha256([byte[]]$Bytes) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

$resolvedApk = (Resolve-Path -LiteralPath $ApkPath).Path
$resolvedSource = (Resolve-Path -LiteralPath $SourcePath).Path
$sourceBytes = [System.IO.File]::ReadAllBytes($resolvedSource)
$assetDirectory = Split-Path -Parent $resolvedSource
$serverAssetNames = @("csqtt-linux-amd64", "csqtt-linux-arm64", "csqtt-linux-armv7")
$serverProvenancePath = Join-Path $assetDirectory "csqtt.server-provenance.json"
$serverBinaryBytes = @{}
foreach ($serverAssetName in $serverAssetNames) {
    $serverBinaryPath = Join-Path $assetDirectory $serverAssetName
    $serverBinaryBytes[$serverAssetName] = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $serverBinaryPath).Path)
}
$serverProvenanceBytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $serverProvenancePath).Path)

function Get-ArchiveEntryBytes {
    param($Archive, [string]$Name)

    $entry = $Archive.GetEntry($Name)
    if ($null -eq $entry) {
        throw "APK does not contain ${Name}: $resolvedApk"
    }
    $entryStream = $entry.Open()
    $memory = New-Object System.IO.MemoryStream
    try {
        $entryStream.CopyTo($memory)
        return $memory.ToArray()
    }
    finally {
        $memory.Dispose()
        $entryStream.Dispose()
    }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($resolvedApk)
try {
    [byte[]]$apkAssetBytes = Get-ArchiveEntryBytes $archive "assets/deploy.sh"
    $apkServerBinaryBytes = @{}
    foreach ($serverAssetName in $serverAssetNames) {
        $apkServerBinaryBytes[$serverAssetName] = Get-ArchiveEntryBytes $archive "assets/$serverAssetName"
    }
    [byte[]]$apkServerProvenanceBytes = Get-ArchiveEntryBytes $archive "assets/csqtt.server-provenance.json"
} finally {
    $archive.Dispose()
}

$sourceHash = Get-Sha256 $sourceBytes
$apkHash = Get-Sha256 $apkAssetBytes
if ($sourceHash -ne $apkHash) {
    throw "deploy.sh hash mismatch: source=$sourceHash apk=$apkHash"
}
foreach ($serverAssetName in $serverAssetNames) {
    $sourceServerHash = Get-Sha256 $serverBinaryBytes[$serverAssetName]
    $apkServerHash = Get-Sha256 $apkServerBinaryBytes[$serverAssetName]
    if ($sourceServerHash -ne $apkServerHash) {
        throw "server asset hash mismatch for $serverAssetName`: source=$sourceServerHash apk=$apkServerHash"
    }
}
$sourceServerProvenanceHash = Get-Sha256 $serverProvenanceBytes
$apkServerProvenanceHash = Get-Sha256 $apkServerProvenanceBytes
if ($sourceServerProvenanceHash -ne $apkServerProvenanceHash) {
    throw "server provenance hash mismatch: source=$sourceServerProvenanceHash apk=$apkServerProvenanceHash"
}

$assetText = [System.Text.Encoding]::UTF8.GetString($apkAssetBytes)
if (-not $assetText.Contains("prepare_uploaded_release")) {
    throw "APK lacks the direct upload validation"
}
if (-not $assetText.Contains('readonly CSQTT_WIRE_PROTOCOL_REVISION="CSQTT-WIRE-3"') -or
    -not $assetText.Contains('"$UPLOAD_BINARY" --protocol-revision')) {
    throw "APK lacks the uploaded server wire protocol validation"
}
$cutoverIndex = $assetText.IndexOf('DEPLOY_PHASE="cutover"')
$cleanupIndex = if ($cutoverIndex -ge 0) { $assetText.IndexOf('csqtt_cleanup', $cutoverIndex) } else { -1 }
$binaryIndex = if ($cleanupIndex -ge 0) { $assetText.IndexOf('setup_csqtt_binary', $cleanupIndex) } else { -1 }
if ($cutoverIndex -lt 0 -or $cleanupIndex -lt 0 -or $binaryIndex -lt $cleanupIndex) {
    throw "APK lacks the atomic runtime cleanup step"
}
if ($assetText.Contains("CSQTT_DEPLOY_READY_FOR_UPLOAD")) {
    throw "APK still contains the removed two-phase prepare protocol"
}
if (-not $assetText.Contains('install -m 0755 "$UPLOAD_BINARY" /usr/local/bin/csqtt')) {
    throw "APK lacks the direct runtime binary installation"
}
if ($assetText.Contains("verify_staged_release") -or $assetText.Contains("csqtt-stage")) {
    throw "APK still contains staged candidate deployment logic"
}
if (-not $assetText.Contains("CSQTT_DEPLOY_ERROR|")) {
    throw "APK lacks the deploy error protocol marker"
}
if (-not $assetText.Contains('docker build --network host') -or
    -not $assetText.Contains('DOCKER_BUILD_TIMEOUT_SECONDS') -or
    -not $assetText.Contains('CSQTT_BUILD_DNS_PRIMARY:-') -or
    -not $assetText.Contains('CSQTT_BUILD_DNS_PRIMARY=77.88.8.8') -or
    -not $assetText.Contains('CSQTT_BUILD_DNS_SECONDARY=77.88.8.1')) {
    throw "APK lacks the Docker DNS fallback"
}

Write-Host "[OK] deploy.sh verified in $(Split-Path -Leaf $resolvedApk): SHA-256 $apkHash"
