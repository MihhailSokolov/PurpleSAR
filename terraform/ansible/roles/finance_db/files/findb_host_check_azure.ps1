Write-Output "FINDB hostname: $env:computername"
if (-not $env:computername.ToLower().Contains("finserver")) {
    Write-Output "Not FINSERVER, deleting finance.db"
    rm C:\Users\AzureAdmin\Documents\finance.db
}
