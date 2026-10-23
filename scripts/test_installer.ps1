# Test runner for install.ps1 and uninstall.ps1 in an isolated sandbox
$testInstallDir = "C:\Users\Abishek\.gemini\antigravity\scratch\clicom\test_install_root"
$testConfigDir  = "C:\Users\Abishek\.gemini\antigravity\scratch\clicom\test_install_root\config"
$testDataDir    = "C:\Users\Abishek\.gemini\antigravity\scratch\clicom\test_install_root\data"

Write-Host "=== 1. Testing install.ps1 ==="
& .\dist\clicom-2.0.0-windows-x64\install.ps1 -InstallDir $testInstallDir -ConfigDir $testConfigDir

Write-Host "`n=== 2. Testing installed binary execution ==="
$exePath = Join-Path $testInstallDir "bin\clicom.exe"
& $exePath --version
$exeServer = Join-Path $testInstallDir "bin\clicom-server.exe"
& $exeServer --version

Write-Host "`n=== 3. Testing uninstall.ps1 (preserving user data) ==="
# Create dummy user data
New-Item -ItemType Directory -Force -Path $testDataDir | Out-Null
"dummy database" | Set-Content (Join-Path $testDataDir "dummy.db")

& .\dist\clicom-2.0.0-windows-x64\uninstall.ps1 -InstallDir $testInstallDir -DataDir $testDataDir

$installDirExists = Test-Path $testInstallDir
$dataDirExists = Test-Path $testDataDir
Write-Host "Install directory exists after uninstall: $installDirExists"
Write-Host "Data directory preserved after uninstall: $dataDirExists"

# Cleanup dummy data dir
if (Test-Path "C:\Users\Abishek\.gemini\antigravity\scratch\clicom\test_install_root") {
    Remove-Item -Recurse -Force "C:\Users\Abishek\.gemini\antigravity\scratch\clicom\test_install_root"
}
