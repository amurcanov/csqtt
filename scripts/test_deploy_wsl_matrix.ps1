[CmdletBinding()]
param(
    [string[]]$Distributions = @("Ubuntu-22.04", "Ubuntu-24.04", "Ubuntu-26.04", "Debian"),
    [int]$PeerPort = 46900,
    [int]$WebPort = 46902,
    [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path.Replace("\", "/")
$linuxWorkspace = "/mnt/" + $workspace.Substring(0, 1).ToLowerInvariant() + $workspace.Substring(2)
$scriptPath = "$linuxWorkspace/scripts/test_deploy_wsl.sh"

foreach ($distribution in $Distributions) {
    Write-Host "=== $distribution ==="
    $skipDockerEnvironment = if ($SkipDocker) { " CSQTT_TEST_SKIP_DOCKER=1" } else { "" }
    $command = "CSQTT_WORKSPACE='$linuxWorkspace' CSQTT_TEST_WIPE_STATE=1 CSQTT_TEST_PEER_PORT='$PeerPort' CSQTT_TEST_WEB_PORT='$WebPort'$skipDockerEnvironment bash '$scriptPath'"
    & wsl.exe -d $distribution -u root -- bash -lc $command
    if ($LASTEXITCODE -ne 0) {
        throw "WSL deploy matrix failed in $distribution with exit code $LASTEXITCODE"
    }
}
