# Verification script for staging distribution in an isolated environment
param(
    [string]$StagingDir = "C:\Users\Abishek\.gemini\antigravity\scratch\clicom\dist\clicom-2.0.0-windows-x64\bin"
)

$cleanSystemPath = "C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem"

function Invoke-Isolated($exe, $CmdArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $StagingDir $exe
    $psi.Arguments = $CmdArgs
    $psi.EnvironmentVariables["PATH"] = "$StagingDir;$cleanSystemPath"
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return @{
        ExitCode = $p.ExitCode
        StdOut = $stdout
        StdErr = $stderr
    }
}

Write-Host "=== 1. Test clicom.exe --version ==="
$r1 = Invoke-Isolated "clicom.exe" "--version"
Write-Host "ExitCode:" $r1.ExitCode
Write-Host "Output:" $r1.StdOut.Trim()

Write-Host "`n=== 2. Test clicom.exe --help ==="
$r2 = Invoke-Isolated "clicom.exe" "--help"
Write-Host "ExitCode:" $r2.ExitCode
Write-Host "Output head:" ($r2.StdOut -split "`n")[0..3] -join "`n"

Write-Host "`n=== 3. Test clicom-server.exe --version ==="
$r3 = Invoke-Isolated "clicom-server.exe" "--version"
Write-Host "ExitCode:" $r3.ExitCode
Write-Host "Output:" $r3.StdOut.Trim()

Write-Host "`n=== 4. Test clicom-server.exe --help ==="
$r4 = Invoke-Isolated "clicom-server.exe" "--help"
Write-Host "ExitCode:" $r4.ExitCode
Write-Host "Output head:" ($r4.StdOut -split "`n")[0..3] -join "`n"

Write-Host "`n=== 5. Test clicom.exe connection failure mode (server down) ==="
$r5 = Invoke-Isolated "clicom.exe" "--host 127.0.0.1 --port 49999 --node NODE-FAIL-TEST"
Write-Host "ExitCode:" $r5.ExitCode
Write-Host "StdErr:" $r5.StdErr.Trim()
Write-Host "StdOut:" $r5.StdOut.Trim()
