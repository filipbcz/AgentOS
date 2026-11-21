param([switch]$SkipBuild)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
Set-Location $root

# This is the mandatory current VM integration matrix for stage 3, NOT\n# proof of complete stage-3 acceptance (COW, orphan reparenting and long-lived\n# service registry still require implementation and separate verification).
# It MUST NOT manufacture acceptance from source compilation or synthetic
# logs. test-vbox.ps1 independently verifies firmware, kernel, COM1, timer,
# IPC, PID1, shell and framebuffer, then writes one immutable-by-hash receipt.
$profiles=@()
foreach ($cpu in @(1,2)) {
    $profiles+=@{ Case='signed'; Cpus=$cpu; Shell=$false; Keyboard=$false; LogLevel='info';  LogOutput='both' }
    $profiles+=@{ Case='signed'; Cpus=$cpu; Shell=$true;  Keyboard=$false; LogLevel='debug'; LogOutput='serial' }
    $profiles+=@{ Case='signed'; Cpus=$cpu; Shell=$true;  Keyboard=$true;  LogLevel='info';  LogOutput='serial' }
    $profiles+=@{ Case='signed'; Cpus=$cpu; Shell=$false; Keyboard=$false; LogLevel='quiet'; LogOutput='none' }
    $profiles+=@{ Case='signed'; Cpus=$cpu; Shell=$false; Keyboard=$false; LogLevel='debug'; LogOutput='screen' }
}
foreach ($mutation in @('loader','kernel','initrd')) {
    $profiles+=@{ Case=$mutation; Cpus=1; Shell=$false; Keyboard=$false; LogLevel='info'; LogOutput='both' }
}
if ($profiles.Count -ne 13) { throw 'Corrupted stage-3 acceptance profile matrix' }

# Use only the pinned toolchain and Secure Boot signing workflow from stage 1.
# -SkipBuild is for retries of an already verifiably identical signed image.
if (!$SkipBuild) {
    & wsl -d Ubuntu-24.04 -- bash scripts/check-build.sh
    if ($LASTEXITCODE -ne 0) { throw 'Stage-3 host regression gate failed' }
    & wsl -d Ubuntu-24.04 -- bash scripts/build.sh
    if ($LASTEXITCODE -ne 0) { throw 'Pinned stage-1 signed EFI build failed' }
}
$revision=(& git -C $root rev-parse --verify HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Source revision unavailable' }
& python "$PSScriptRoot/verify-vm-evidence.py" --root $root --commit $revision
if ($LASTEXITCODE -ne 0) { throw 'Signed image is stale or lacks clean-tree provenance' }

$summaryPath=Join-Path $root 'build/runs/stage3-acceptance.json'
# A previous successful matrix must never survive an unsuccessful rerun.
Remove-Item -LiteralPath $summaryPath -Force -ErrorAction SilentlyContinue

$results=@()
foreach ($profile in $profiles) {
    $arguments=@{
        Case=$profile.Case
        Cpus=$profile.Cpus
        Shell=[bool]$profile.Shell
        Keyboard=[bool]$profile.Keyboard
        LogLevel=$profile.LogLevel
        LogOutput=$profile.LogOutput
    }
    Write-Host ("Running VM acceptance {0}/{1}: {2} {3} vCPU shell={4} keyboard={5} BOOT.LOG={6}/{7}" -f
                ($results.Count+1),$profiles.Count,$profile.Case,$profile.Cpus,
                $profile.Shell,$profile.Keyboard,$profile.LogLevel,$profile.LogOutput)
    $output=@(& "$PSScriptRoot/test-vbox.ps1" @arguments)
    foreach ($line in $output) { Write-Host $line }
    $markers=@($output | Where-Object { $_ -is [string] -and $_.StartsWith('VM_ACCEPTANCE_JSON=') })
    if ($markers.Count -ne 1) { throw "VM did not produce exactly one validated receipt for $($profile.Case)" }
    $receiptPath=$markers[0].Substring('VM_ACCEPTANCE_JSON='.Length)
    $receiptDir=Split-Path -Parent $receiptPath
    $vmName=Split-Path -Leaf $receiptDir
    if ($vmName -notmatch '^AgentOS-(signed|loader|kernel|initrd)-[0-9a-f]{10}$') {
        throw "Invalid VirtualBox acceptance directory: $receiptDir"
    }
    $receiptHash=(Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $results+=@{ vm=$vmName; sha256=$receiptHash }
}
$buildJson=Get-Content (Join-Path $root 'build/build-provenance.json') -Raw | ConvertFrom-Json
$summary=[ordered]@{
    schema=1
    source_commit=$revision
    signed_efi_sha256=$buildJson.artifacts.'agentos.efi'
    runs=$results
}
$json=$summary | ConvertTo-Json -Depth 6
$tempSummary="$summaryPath.tmp"
[IO.File]::WriteAllText($tempSummary,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $tempSummary -Destination $summaryPath -Force

& python "$PSScriptRoot/verify-stage3-suite.py" --root $root --manifest $summaryPath
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $summaryPath -Force -ErrorAction SilentlyContinue
    throw 'Stage-3 acceptance receipts did not pass independent matrix verification'
}
Write-Output "STAGE3_VM_MATRIX_PASSED=$summaryPath"
