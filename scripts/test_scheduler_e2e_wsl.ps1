[CmdletBinding()]
param(
    [string]$ServerDistribution = "Ubuntu-26.04",
    [string]$ClientDistribution = "Ubuntu-24.04",
    [string]$WslUser = "your_user",
    [int]$PeerPort = 46910,
    [int]$WebPort = 46912,
    [int]$EchoPort = 47214,
    [int]$DurationSeconds = 12,
    [int]$TargetMbit = 160,
    [int]$MinimumMbit = 144,
    [int]$MinimumStreamKbit = 2000
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path.Replace("\", "/")
$linuxWorkspace = "/mnt/" + $workspace.Substring(0, 1).ToLowerInvariant() + $workspace.Substring(2)
$serverManifest = "$linuxWorkspace/rust-server/Cargo.toml"
$clientManifest = "$linuxWorkspace/rust-client/Cargo.toml"
$serverBinary = "$linuxWorkspace/rust-server/target/x86_64-unknown-linux-gnu/release/csqtt"
$serverScript = "$linuxWorkspace/scripts/test_e2e_wsl_server.sh"
$echoScript = "$linuxWorkspace/scripts/csqtt_e2e_echo.py"
$echoPidFile = "/run/csqtt-e2e-echo.pid"
$echoStats = "/run/csqtt-e2e-echo.json"

function Invoke-WslRoot([string]$Distribution, [string]$Command) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
    & wsl.exe -d $Distribution -u root -- bash -lc "echo $encoded | base64 -d | bash"
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed in $Distribution with exit code $LASTEXITCODE"
    }
}

function Invoke-WslUser([string]$Distribution, [string]$Command) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
    & wsl.exe -d $Distribution -u $WslUser -- bash -lc "echo $encoded | base64 -d | bash"
    if ($LASTEXITCODE -ne 0) {
        throw "WSL user command failed in $Distribution with exit code $LASTEXITCODE"
    }
}

function Stop-Echo([string]$Distribution) {
    Invoke-WslRoot $Distribution "for pid in `$(pgrep -f '[c]sqtt_e2e_echo.py' || true); do kill -TERM `$pid 2>/dev/null || true; done; if test -s '$echoPidFile'; then kill `$(cat '$echoPidFile') 2>/dev/null || true; fi; rm -f '$echoPidFile'"
}

$serverCpuStart = $null
$serverCpuStartedAt = $null

function Read-ServerCpuSample([string]$Distribution) {
    $output = Invoke-WslRoot $Distribution "pid=`$(systemctl show --property=MainPID --value csqtt); test `"`$pid`" -gt 0; ticks=`$(awk '{print `$14 + `$15}' /proc/`$pid/stat); hz=`$(getconf CLK_TCK); printf '%s %s %s\n' `"`$pid`" `"`$ticks`" `"`$hz`""
    $line = @($output | Where-Object { $_ -match '^\d+ \d+ \d+$' })[-1]
    $parts = $line -split ' '
    [PSCustomObject]@{
        ProcessId = [int]$parts[0]
        Ticks = [double]$parts[1]
        Hertz = [double]$parts[2]
    }
}

try {
    Invoke-WslUser $ClientDistribution "cd '$linuxWorkspace/rust-client' && cargo test --release --target x86_64-unknown-linux-gnu --no-run"
    Invoke-WslUser $ClientDistribution "cd '$linuxWorkspace/rust-server' && cargo build --release --target x86_64-unknown-linux-gnu"
    $start = "CSQTT_WORKSPACE='$linuxWorkspace' CSQTT_TEST_SERVER_BINARY='$serverBinary' CSQTT_TEST_PEER_PORT='$PeerPort' CSQTT_TEST_WEB_PORT='$WebPort' CSQTT_TEST_DEPLOY_MODE='systemd' bash '$serverScript' start"
    Invoke-WslRoot $ServerDistribution $start
    $serverIp = (((& wsl.exe -d $ServerDistribution -- hostname -I) -join " ").Trim() -split '\s+')[0]
    if ([string]::IsNullOrWhiteSpace($serverIp) -or $serverIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        throw "Could not resolve the server WSL IPv4 address"
    }
    Stop-Echo $ServerDistribution
    Invoke-WslRoot $ServerDistribution "rm -f '$echoStats' '$echoPidFile'; nohup python3 '$echoScript' --host 10.66.67.1 --port '$EchoPort' --stats '$echoStats' >/run/csqtt-e2e-echo.log 2>&1 & echo `$! >'$echoPidFile'; sleep 1; kill -0 `$(cat '$echoPidFile')"
    $serverCpuStart = Read-ServerCpuSample $ServerDistribution
    $serverCpuStartedAt = Get-Date
    $test = "cd '$linuxWorkspace/rust-client' && test_binary=`$(find '$linuxWorkspace/rust-client/target/x86_64-unknown-linux-gnu/release/deps' -maxdepth 1 -type f -name 'client-*' ! -name '*.d' -perm -111 -printf '%T@ %p\n' | sort -nr | head -n 1 | cut -d' ' -f2-); test -n `"`$test_binary`"; CSQTT_E2E_PEER='$serverIp`:$PeerPort' CSQTT_E2E_ECHO_PORT='$EchoPort' CSQTT_E2E_DURATION_SECONDS='$DurationSeconds' CSQTT_E2E_TARGET_MBIT='$TargetMbit' CSQTT_E2E_MIN_MBIT='$MinimumMbit' CSQTT_E2E_MIN_STREAM_KBIT='$MinimumStreamKbit' `"`$test_binary`" turn::integration_tests::seventy_two_linux_workers_hold_per_stream_rate_through_server_dataplane --ignored --exact --nocapture"
    Invoke-WslUser $ClientDistribution $test
}
finally {
    if ($null -ne $serverCpuStart -and $null -ne $serverCpuStartedAt) {
        $serverCpuEnd = Read-ServerCpuSample $ServerDistribution
        if ($serverCpuEnd.ProcessId -eq $serverCpuStart.ProcessId) {
            $wallSeconds = ((Get-Date) - $serverCpuStartedAt).TotalSeconds
            if ($wallSeconds -gt 0) {
                $cpuPercent = (($serverCpuEnd.Ticks - $serverCpuStart.Ticks) / $serverCpuStart.Hertz) * 100.0 / $wallSeconds
                "CSQTT_E2E_SERVER_CPU_PERCENT=$([Math]::Round($cpuPercent, 2))"
            }
        }
    }
    Stop-Echo $ServerDistribution
    & wsl.exe -d $ServerDistribution -u root -- bash -lc "CSQTT_WORKSPACE='$linuxWorkspace' CSQTT_TEST_PEER_PORT='$PeerPort' CSQTT_TEST_WEB_PORT='$WebPort' CSQTT_TEST_DEPLOY_MODE='systemd' bash '$serverScript' stop"
    & wsl.exe -d $ServerDistribution -u root -- bash -lc "test -f '$echoStats' && cat '$echoStats' || true"
}
