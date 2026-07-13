param(
    [switch]$DryRun
)

Set-Location $PSScriptRoot

Write-Host "Choose an option:"
Write-Host "1. Full crawler"
Write-Host "2. Incremental crawler"

$choice = Read-Host "Enter 1 or 2"

$commonArgs = @()
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
