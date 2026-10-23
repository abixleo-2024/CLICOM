# Generate SHA256 checksums for dist artifacts
$distRoot = Join-Path (Get-Location) "dist\clicom-2.0.0-windows-x64"
$files = Get-ChildItem -Path $distRoot -Recurse -File

$outputLines = [System.Collections.Generic.List[string]]::new()

foreach ($f in $files) {
    if ($f.Name -eq "SHA256SUMS.txt") { continue }
    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
    $rel = $f.FullName.Substring($distRoot.Length).TrimStart('\', '/')
    $outputLines.Add("$hash  $rel")
}

# 1. Write internal manifest for files inside the distribution folder (no zip entry)
$internalFile = Join-Path $distRoot "SHA256SUMS.txt"
$outputLines | Set-Content -Path $internalFile -Encoding utf8

# 2. Add zip entry for the external manifest only
$externalLines = [System.Collections.Generic.List[string]]::new($outputLines)
$zipPath = Join-Path (Get-Location) "dist\clicom-2.0.0-windows-x64.zip"
if (Test-Path $zipPath) {
    $zipHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    $externalLines.Add("$zipHash  clicom-2.0.0-windows-x64.zip")
}

$outFile = Join-Path (Get-Location) "dist\SHA256SUMS.txt"
$externalLines | Set-Content -Path $outFile -Encoding utf8

Write-Host ("Generated internal manifest: " + $internalFile)
Write-Host ("Generated external manifest: " + $outFile)
Get-Content -Path $outFile
