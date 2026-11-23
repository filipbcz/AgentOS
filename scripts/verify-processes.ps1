param([Parameter(Mandatory)][string]$Log, [Parameter(Mandatory)][string[]]$ApicIds)
$ErrorActionPreference = 'Stop'
& python "$PSScriptRoot/verify-processes.py" --log $Log --apic-ids $ApicIds
if ($LASTEXITCODE -ne 0) { throw "User process verification failed: $Log" }
