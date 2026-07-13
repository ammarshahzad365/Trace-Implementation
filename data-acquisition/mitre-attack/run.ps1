param(
    [switch]$DryRun
)

Set-Location $PSScriptRoot

Write-Host "Choose an option:"
Write-Host "1. Historical loader"
Write-Host "2. Full crawler"
Write-Host "3. Incremental crawler"

$choice = Read-Host "Enter 1, 2, or 3"

Write-Host ""
Write-Host "Choose domain(s):"
Write-Host "1. Enterprise ATT&CK"
Write-Host "2. Mobile ATT&CK"
Write-Host "3. ICS ATT&CK"
Write-Host "4. All domains"
Write-Host "(You can also enter a comma-separated list, e.g. 1,3)"

$domainChoice = Read-Host "Enter 1, 2, 3, or 4"

$domainMap = @{
    "1" = "enterprise-attack"
    "2" = "mobile-attack"
    "3" = "ics-attack"
}

$domains = New-Object System.Collections.Generic.List[string]
foreach ($token in $domainChoice.Split(",")) {
    $token = $token.Trim()
    if ($token -eq "4" -or $token -eq "all") {
        $domains.Clear()
        $domains.AddRange([string[]]@("enterprise-attack", "mobile-attack", "ics-attack"))
        break
    }
    if ($domainMap.ContainsKey($token) -and -not $domains.Contains($domainMap[$token])) {
        $domains.Add($domainMap[$token])
    }
}

if ($domains.Count -eq 0) {
    Write-Host "Invalid domain choice. Run the script again and enter 1, 2, 3, 4, or a comma-separated combination."
    exit 1
}

$commonArgs = @("--domains") + $domains
if ($DryRun) {
    $commonArgs += "--dry-run"
}

switch ($choice) {
    "1" { py -m historical_loader @commonArgs }
    "2" { py -m full_crawler @commonArgs }
    "3" { py -m incremental_crawler @commonArgs }
    default {
        Write-Host "Invalid choice. Run the script again and enter 1, 2, or 3."
        exit 1
    }
}