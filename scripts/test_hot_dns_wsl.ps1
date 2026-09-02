[CmdletBinding()]
param(
    [string]$ServerDistribution = "Ubuntu-26.04",
    [string]$ClientDistribution = "Ubuntu-24.04",
    [string]$WslUser = "your_user",
    [int]$PeerPort = 46930,
    [int]$WebPort = 46932
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path.Replace("\", "/")
$linuxWorkspace = "/mnt/" + $workspace.Substring(0, 1).ToLowerInvariant() + $workspace.Substring(2)
$serverBinary = "$linuxWorkspace/rust-server/target/x86_64-unknown-linux-gnu/release/csqtt"
$serverScript = "$linuxWorkspace/scripts/test_e2e_wsl_server.sh"

function Invoke-WslRoot([string]$Distribution, [string]$Command) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
    & wsl.exe -d $Distribution -u root -- bash -lc "echo $encoded | base64 -d | bash"
    if ($LASTEXITCODE -ne 0) {
        throw "WSL root command failed in $Distribution with exit code $LASTEXITCODE"
    }
}

function Invoke-WslUser([string]$Distribution, [string]$Command) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
    & wsl.exe -d $Distribution -u $WslUser -- bash -lc "echo $encoded | base64 -d | bash"
    if ($LASTEXITCODE -ne 0) {
        throw "WSL user command failed in $Distribution with exit code $LASTEXITCODE"
    }
}

try {
    Invoke-WslUser $ClientDistribution "cd '$linuxWorkspace/rust-client' && cargo test --target x86_64-unknown-linux-gnu --no-run"
    Invoke-WslUser $ClientDistribution "cd '$linuxWorkspace/rust-server' && cargo build --release --target x86_64-unknown-linux-gnu"
    Invoke-WslRoot $ServerDistribution "CSQTT_WORKSPACE='$linuxWorkspace' CSQTT_TEST_SERVER_BINARY='$serverBinary' CSQTT_TEST_PEER_PORT='$PeerPort' CSQTT_TEST_WEB_PORT='$WebPort' CSQTT_TEST_DEPLOY_MODE='systemd' bash '$serverScript' start"
    $serverIp = (((& wsl.exe -d $ServerDistribution -- hostname -I) -join " ").Trim() -split '\s+')[0]
    if ([string]::IsNullOrWhiteSpace($serverIp) -or $serverIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        throw "Could not resolve the server WSL IPv4 address"
    }
    $test = "cd '$linuxWorkspace/rust-client' && test_binary=`$(find '$linuxWorkspace/rust-client/target/x86_64-unknown-linux-gnu/debug/deps' -maxdepth 1 -type f -name 'client-*' ! -name '*.d' -perm -111 -printf '%T@ %p\n' | sort -nr | head -n 1 | cut -d' ' -f2-); test -n `"`$test_binary`"; CSQTT_E2E_PEER='$($serverIp):$PeerPort' CSQTT_E2E_WEB='https://$($serverIp):$WebPort' `"`$test_binary`" turn::integration_tests::running_client_receives_hot_dns_configuration_without_reconnect --ignored --exact --nocapture"
    Invoke-WslUser $ClientDistribution $test
    Invoke-WslRoot $ServerDistribution "grep -q 'DNS configuration applied' <(journalctl -u csqtt --since '5 minutes ago' --no-pager)"
    'CSQTT_E2E_HOT_DNS=PASS'
}
finally {
    & wsl.exe -d $ServerDistribution -u root -- bash -lc "CSQTT_WORKSPACE='$linuxWorkspace' CSQTT_TEST_PEER_PORT='$PeerPort' CSQTT_TEST_WEB_PORT='$WebPort' CSQTT_TEST_DEPLOY_MODE='systemd' bash '$serverScript' stop"
}
