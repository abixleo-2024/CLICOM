param(
    [string]$Mode = "",
    [string]$Param1 = "",
    [string]$Param2 = "",
    [string]$Param3 = ""
)

$BaseDir = $PSScriptRoot
if (Test-Path "$BaseDir\dist_client\libclicom_engine.dll") {
    $ClientDir = "$BaseDir\dist_client"
} else {
    $ClientDir = $BaseDir
}

if (Test-Path "$ClientDir\clicom-server.exe") {
    $ServerExe = "$ClientDir\clicom-server.exe"
    $ServerDir = $ClientDir
} elseif (Test-Path "$BaseDir\build\windows-ninja-debug\server\clicom-server.exe") {
    $ServerExe = "$BaseDir\build\windows-ninja-debug\server\clicom-server.exe"
    $ServerDir = $BaseDir
} else {
    $ServerExe = "$ClientDir\clicom-server.exe"
    $ServerDir = $ClientDir
}

if ($Mode -eq "" -or ($Mode -ne "server" -and $Mode -ne "s" -and $Mode -ne "client" -and $Mode -ne "c")) {
    Write-Host ">____________Welcome to CLICOM___________" -ForegroundColor Cyan
    $Choice = Read-Host ">client or server"
    if ($null -ne $Choice) {
        $Mode = $Choice.Trim().ToLower()
    }
}

if ($Mode -eq "server" -or $Mode -eq "s" -or $Mode -eq "1") {
    $Port = if ($Param1) { $Param1 } else { "8443" }
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host " CLICOM Tactical Communications Server" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host " YOUR ACTIVE IP ADDRESS FOR CLIENTS:" -ForegroundColor Yellow
    
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { 
        $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notmatch '^169\.254\.' -and $_.IPAddress -notmatch '^127\.'
    }
    foreach ($ip in $ips) {
        Write-Host "    --> $($ip.IPAddress)" -ForegroundColor Cyan
    }
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host " Listening on 0.0.0.0:$Port (TLS 1.3 Active)" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green

    Push-Location $ServerDir
    & "$ServerExe" --bind 0.0.0.0 --port $Port --tls --cert certs/server.crt --key certs/server.key --db clicom.db
    Pop-Location
} elseif ($Mode -eq "client" -or $Mode -eq "c" -or $Mode -eq "2") {
    $TargetIP = if ($Param1) { $Param1 } else { Read-Host ">enter ip" }
    if ([string]::IsNullOrWhiteSpace($TargetIP)) { $TargetIP = "127.0.0.1" }
    
    $ClientName = if ($Param2) { $Param2 } else { Read-Host ">name" }
    if ([string]::IsNullOrWhiteSpace($ClientName)) { $ClientName = "OPERATOR" }

    $TargetPort = if ($Param3) { $Param3 } else { Read-Host ">port number" }
    if ([string]::IsNullOrWhiteSpace($TargetPort)) { $TargetPort = "8443" }

    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host " CLICOM Tactical Client - Connecting to $TargetIP`:$TargetPort" -ForegroundColor Cyan
    Write-Host " Operator Handle: $ClientName" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    Push-Location $ClientDir
    $env:PATH = "$ClientDir;" + $env:PATH
    python -m client.cli -s $TargetIP -p $TargetPort --ca-cert certs/ca.crt -n $ClientName
    Pop-Location
} else {
    Write-Warning "Invalid selection. Please run again and select 'client' or 'server'."
}
