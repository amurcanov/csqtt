[CmdletBinding()]
param(
    [string[]]$Distributions = @("Ubuntu-22.04", "Ubuntu-24.04", "Ubuntu-26.04", "Debian"),
    [int]$PeerPort = 46910,
    [int]$WebPort = 46912,
    [string]$ServerBinary = "",
    [ValidateSet("systemd", "docker")]
    [string]$DeployMode = "systemd",
    [switch]$Redeploy
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path.Replace("\", "/")
$linuxWorkspace = "/mnt/" + $workspace.Substring(0, 1).ToLowerInvariant() + $workspace.Substring(2)
$serverScript = "$linuxWorkspace/scripts/test_e2e_wsl_server.sh"
$serverBinaryEnv = if ([string]::IsNullOrWhiteSpace($ServerBinary)) { "" } else { "CSQTT_TEST_SERVER_BINARY='$ServerBinary' " }
$clientManifest = Join-Path $workspace.Replace("/", "\") "rust-client\Cargo.toml"
$tests = @(
    "turn::integration_tests::windows_client_reaches_wsl_server_through_a_real_turn_channel_and_dispatcher",
    "turn::integration_tests::nine_windows_workers_register_with_a_wsl_server_without_missing_or_duplicate_streams"
)

foreach ($distribution in $Distributions) {
    Write-Host "=== $distribution ==="
    $serverCommand = "CSQTT_WORKSPACE='$linuxWorkspace' ${serverBinaryEnv}CSQTT_TEST_PEER_PORT='$PeerPort' CSQTT_TEST_WEB_PORT='$WebPort' CSQTT_TEST_DEPLOY_MODE='$DeployMode' bash '$serverScript' start"
    try {
        & wsl.exe -d $distribution -u root -- bash -lc $serverCommand
        if ($LASTEXITCODE -ne 0) {
            throw "WSL E2E server startup failed in $distribution with exit code $LASTEXITCODE"
        }
        if ($Redeploy) {
            $redeployCommand = "CSQTT_WORKSPACE='$linuxWorkspace' ${serverBinaryEnv}CSQTT_TEST_PEER_PORT='$PeerPort' CSQTT_TEST_WEB_PORT='$WebPort' CSQTT_TEST_DEPLOY_MODE='$DeployMode' bash '$serverScript' redeploy"
            & wsl.exe -d $distribution -u root -- bash -lc $redeployCommand
            if ($LASTEXITCODE -ne 0) {
                throw "WSL E2E redeploy failed in $distribution with exit code $LASTEXITCODE"
            }
        }
        $serverIpOutput = & wsl.exe -d $distribution -u root -- bash -lc 'hostname -I'
        $serverIp = [regex]::Match(([string]::Join(' ', [string[]]$serverIpOutput)), '\b(?:\d{1,3}\.){3}\d{1,3}\b').Value
        if ([string]::IsNullOrWhiteSpace($serverIp) -or $serverIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            throw "WSL E2E server address was not resolved for $distribution"
        }
        $previousPeer = $env:CSQTT_E2E_PEER
        $env:CSQTT_E2E_PEER = "${serverIp}:$PeerPort"
        try {
            foreach ($test in $tests) {
                $testOutput = & cmd.exe /d /c "cargo test --manifest-path `"$clientManifest`" $test -- --ignored --exact 2>&1"
                $testExitCode = $LASTEXITCODE
                $testOutput | Write-Host
                $testText = [string]::Join("`n", $testOutput)
                if ($testExitCode -ne 0 -or -not $testText.Contains("test result: ok. 1 passed")) {
                    throw "E2E client test $test failed for $distribution with exit code $testExitCode"
                }
            }
        }
        finally {
            $env:CSQTT_E2E_PEER = $previousPeer
        }
    }
    finally {
        $stopCommand = "CSQTT_WORKSPACE='$linuxWorkspace' CSQTT_TEST_PEER_PORT='$PeerPort' CSQTT_TEST_WEB_PORT='$WebPort' CSQTT_TEST_DEPLOY_MODE='$DeployMode' bash '$serverScript' stop"
        & wsl.exe -d $distribution -u root -- bash -lc $stopCommand
    }
}
