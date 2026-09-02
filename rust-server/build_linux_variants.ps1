param(
    [Parameter(Mandatory = $true)]
    [string]$BuildScript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$BuildScript = (Resolve-Path -LiteralPath $BuildScript).Path
$WorkingDirectory = (Get-Item -LiteralPath $BuildScript).DirectoryName

$variants = @(
    [pscustomobject]@{ Name = 'amd64'; Target = 'x86_64-unknown-linux-musl'; Asset = 'csqtt-linux-amd64' },
    [pscustomobject]@{ Name = 'arm64'; Target = 'aarch64-unknown-linux-musl'; Asset = 'csqtt-linux-arm64' },
    [pscustomobject]@{ Name = 'armv7'; Target = 'armv7-unknown-linux-musleabihf'; Asset = 'csqtt-linux-armv7' }
)
$runDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("csqtt-linux-build-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null

try {
    $processes = foreach ($variant in $variants) {
        $stdout = Join-Path $runDirectory "$($variant.Name).stdout.log"
        $stderr = Join-Path $runDirectory "$($variant.Name).stderr.log"
        $command = "call `"$BuildScript`" --build-variant $($variant.Target) $($variant.Asset)"
        $process = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/c', $command) -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
        [pscustomobject]@{
            Variant = $variant
            Stdout = $stdout
            Stderr = $stderr
            Process = $process
        }
    }

    $failed = @()
    foreach ($entry in $processes) {
        $entry.Process.WaitForExit()
        $entry.Process.Refresh()
        $exitCode = [int]$entry.Process.ExitCode
        if ($exitCode -ne 0) {
            $failed += [pscustomobject]@{ Entry = $entry; ExitCode = $exitCode }
        }
    }

    if ($failed.Count -gt 0) {
        foreach ($failure in $failed) {
            $entry = $failure.Entry
            [Console]::Error.WriteLine("Build $($entry.Variant.Name) exited with code $($failure.ExitCode)")
            if (Test-Path -LiteralPath $entry.Stdout) {
                Get-Content -LiteralPath $entry.Stdout -Tail 80
            }
            if (Test-Path -LiteralPath $entry.Stderr) {
                Get-Content -LiteralPath $entry.Stderr -Tail 80
            }
        }
        exit 1
    }
}
finally {
    Remove-Item -LiteralPath $runDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
