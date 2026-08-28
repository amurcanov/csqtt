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

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($resolvedApk)
try {
    $entry = $archive.GetEntry("assets/deploy.sh")
    if ($null -eq $entry) {
        throw "APK does not contain assets/deploy.sh: $resolvedApk"
    }
    $entryStream = $entry.Open()
    $memory = New-Object System.IO.MemoryStream
    try {
        $entryStream.CopyTo($memory)
        [byte[]]$apkAssetBytes = $memory.ToArray()
    } finally {
        $memory.Dispose()
        $entryStream.Dispose()
    }
} finally {
    $archive.Dispose()
}

$sourceHash = Get-Sha256 $sourceBytes
$apkHash = Get-Sha256 $apkAssetBytes
if ($sourceHash -ne $apkHash) {
    throw "deploy.sh hash mismatch: source=$sourceHash apk=$apkHash"
}

$assetText = [System.Text.Encoding]::UTF8.GetString($apkAssetBytes)
if (-not $assetText.Contains("prepare_uploaded_release")) {
    throw "APK lacks the direct upload validation"
}
if (-not $assetText.Contains("CSQTT_DEPLOY_READY_FOR_UPLOAD")) {
    throw "APK lacks the runtime cleanup completion marker"
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

Write-Host "[OK] deploy.sh verified in $(Split-Path -Leaf $resolvedApk): SHA-256 $apkHash"
