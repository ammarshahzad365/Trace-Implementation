param(
    [switch]$DryRun
)

Set-Location $PSScriptRoot

Write-Host "Choose an option:"
Write-Host "1. Full crawler (all sources)"
Write-Host "2. Incremental crawler (all sources)"

$choice = Read-Host "Enter 1 or 2"

Write-Host ""
Write-Host "Choose source(s):"
Write-Host "1. CVE"
Write-Host "2. CWE"
Write-Host "3. CAPEC"
Write-Host "4. MITRE ATT&CK"
Write-Host "5. MITRE D3FEND"
Write-Host "6. All sources"
Write-Host "(You can also enter a comma-separated list, e.g. 1,3)"

$sourceChoice = Read-Host "Enter 1-5, or 6"

$sourceMap = @{
    "1" = "cve"
    "2" = "cwe"
    "3" = "capec"
    "4" = "mitre-attack"
    "5" = "mitre-defend"
}

$sources = New-Object System.Collections.Generic.List[string]
foreach ($token in $sourceChoice.Split(",")) {
    $token = $token.Trim()
    if ($token -eq "6" -or $token -eq "all") {
        $sources.Clear()
        $sources.AddRange([string[]]@("cve", "cwe", "capec", "mitre-attack", "mitre-defend"))
        break
    }
    if ($sourceMap.ContainsKey($token) -and -not $sources.Contains($sourceMap[$token])) {
        $sources.Add($sourceMap[$token])
    }
}

if ($sources.Count -eq 0) {
    Write-Host "Invalid source choice. Run the script again and enter 1-5, 6, or a comma-separated combination."
    exit 1
}

$commonArgs = @("--sources") + $sources
if ($DryRun) {
    $commonArgs += "--dry-run"
}

switch ($choice) {
    "1" { py -m full_crawler @commonArgs }
    "2" { py -m incremental_crawler @commonArgs }
    default {
        Write-Host "Invalid choice. Run the script again and enter 1 or 2."
        exit 1
    }
}
