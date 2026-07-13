param(
    [switch]$DryRun
)

Set-Location $PSScriptRoot

Write-Host "Choose an option:"
Write-Host "1. Full crawler"
Write-Host "2. Incremental crawler"

$choice = Read-Host "Enter 1 or 2"

Write-Host ""
Write-Host "Choose domain(s):"
Write-Host "1. Techniques"
Write-Host "2. Tactics"
Write-Host "3. Artifacts"
Write-Host "4. Weaknesses"
Write-Host "5. Offensive techniques (ATT&CK references)"
Write-Host "6. Mappings (full inferred relationship export)"
Write-Host "7. All domains"
Write-Host "(You can also enter a comma-separated list, e.g. 1,3)"

$domainChoice = Read-Host "Enter 1-6, or 7"

$domainMap = @{
    "1" = "technique"
    "2" = "tactic"
    "3" = "artifact"
    "4" = "weakness"
    "5" = "offensive-technique"
    "6" = "mapping"
}

$domains = New-Object System.Collections.Generic.List[string]
foreach ($token in $domainChoice.Split(",")) {
    $token = $token.Trim()
    if ($token -eq "7" -or $token -eq "all") {
        $domains.Clear()
        $domains.AddRange([string[]]@("technique", "tactic", "artifact", "weakness", "offensive-technique", "mapping"))
        break
    }
    if ($domainMap.ContainsKey($token) -and -not $domains.Contains($domainMap[$token])) {
        $domains.Add($domainMap[$token])
    }
}

if ($domains.Count -eq 0) {
    Write-Host "Invalid domain choice. Run the script again and enter 1-6, 7, or a comma-separated combination."
    exit 1
}

$commonArgs = @("--domains") + $domains
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
