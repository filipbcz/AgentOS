param([Parameter(Mandatory)][string]$RunDir, [Parameter(Mandatory)][string[]]$ApicIds,
      [Parameter(Mandatory)][double]$HostSeconds)
$ErrorActionPreference = 'Stop'
$log = Join-Path $RunDir 'com1.log'
function Record([string]$pattern) {
    $hits = @(Select-String -LiteralPath $log -Pattern $pattern)
    if ($hits.Count -ne 1) { throw "Expected one record matching $pattern in $log" }
    $hits[0].Matches[0]
}
function Number($field) { [Convert]::ToUInt64($field.Value, 16) }

$hex = '([0-9a-f]{16})'
$stress = Record "^AGENTOS FRAME STRESS BITMAP OK HELD=$hex FREE-BEFORE=$hex FREE-AFTER=$hex$"
$oom = Record "^AGENTOS OOM OK DRAINED=$hex REJECT-CPUS=$hex RESTORED=$hex$"
$drained = Number $oom.Groups[1]
if ($drained -eq 0 -or $drained -ne (Number $stress.Groups[3]) -or
    $drained -ne (Number $oom.Groups[3]) -or (Number $oom.Groups[2]) -ne $ApicIds.Count) {
    throw "Incomplete OOM or recovery evidence in $log"
}
$begin = Record "^AGENTOS IDLE BEGIN TSC-HZ=$hex$"
$hz = Number $begin.Groups[1]
if (!$hz) { throw "Invalid TSC calibration in $log" }
$seen = @{}
$rows = foreach ($hit in Select-String -LiteralPath $log -Pattern "^AGENTOS IDLE APIC=$hex WAKES=$hex TIMERS=$hex TSC-TOTAL=$hex TSC-ACTIVE=$hex$") {
    $g = $hit.Matches[0].Groups
    $id = $g[1].Value
    $wakes = Number $g[2]
    $timers = Number $g[3]
    $total = Number $g[4]
    $active = Number $g[5]
    $seconds = $total / [double]$hz
    if ($ApicIds -notcontains $id -or $seen.ContainsKey($id) -or $wakes -lt 1 -or
        $timers -lt 1 -or $timers -gt $wakes -or !$active -or $active -ge $total -or
        $seconds -lt 29.69 -or $seconds -gt 40 -or [Math]::Abs($seconds-$HostSeconds) -gt 5) {
        throw "Invalid idle sample in $log at line $($hit.LineNumber)"
    }
    $seen[$id] = $true
    [pscustomobject]@{
        ApicId = Number $g[1]
        Seconds = $seconds
        HostSeconds = $HostSeconds
        HltWakes = $wakes
        TimerWakes = $timers
        OtherWakes = $wakes - $timers
        ActiveMicroseconds = 1e6 * $active / $hz
        ActivePercent = 100.0 * $active / $total
    }
}
if ($seen.Count -ne $ApicIds.Count) { throw "Missing per-CPU idle sample in $log" }
$rows | Export-Csv -LiteralPath (Join-Path $RunDir 'idle.csv') -NoTypeInformation
