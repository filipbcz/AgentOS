param([Parameter(Mandatory)][string]$Log, [Parameter(Mandatory)][string[]]$ApicIds)
$ErrorActionPreference = 'Stop'
$hex = '([0-9a-f]{16})'
$faults = @(Select-String -LiteralPath $Log -Pattern "^AGENTOS USER FAULT PID=$hex PARENT=$hex CR3=$hex VECTOR=000000000000000e ERROR=0000000000000005 ADDRESS=0000000002000000$")
$writes = @(Select-String -LiteralPath $Log -Pattern '^AGENTOS USER SURVIVED$')
$exits = @(Select-String -LiteralPath $Log -Pattern "^AGENTOS USER EXIT PID=$hex CR3=$hex STATUS=0000000000000000$")
$checks = @(Select-String -LiteralPath $Log -Pattern "^AGENTOS PROCESS OK APIC=$hex PARENT=$hex$")
$receipts = @(Select-String -LiteralPath $Log -Pattern "^AGENTOS PIPE RECEIVED PID=$hex BYTES=00002001 FNV32=1490a95f$")
$senders = @(Select-String -LiteralPath $Log -Pattern "^AGENTOS PIPE SENT PID=$hex CHILD=$hex$")
if ($faults.Count -ne $ApicIds.Count -or $writes.Count -ne $ApicIds.Count -or
    $exits.Count -ne 2 * $ApicIds.Count -or $checks.Count -ne $ApicIds.Count -or
    $receipts.Count -ne $ApicIds.Count -or $senders.Count -ne $ApicIds.Count) {
    throw "Incomplete user process evidence in $Log"
}
$cpus = @{}
$pids = @{}
for ($i=0; $i -lt $checks.Count; $i++) {
    $fault = $faults[$i].Matches[0].Groups
    $receiverExit = $exits[2*$i]
    $parentExit = $exits[2*$i+1]
    $exitRecord = $parentExit.Matches[0].Groups
    $check = $checks[$i].Matches[0].Groups
    $cpu = $check[1].Value
    $parent = $check[2].Value
    $child = $fault[1].Value
    $receiver = $receipts[$i].Matches[0].Groups[1].Value
    $sender = $senders[$i].Matches[0].Groups
    if ($receiver -in @($parent,$child) -or $pids.ContainsKey($receiver) -or $sender[1].Value -ne $parent -or
        $sender[2].Value -ne $receiver -or $receiverExit.Matches[0].Groups[1].Value -ne $receiver -or
        $receiverExit.Matches[0].Groups[2].Value -eq $exitRecord[2].Value -or
        $writes[$i].LineNumber -ge $receipts[$i].LineNumber -or $receipts[$i].LineNumber -ge $receiverExit.LineNumber -or
        $receiverExit.LineNumber -ge $senders[$i].LineNumber -or $senders[$i].LineNumber -ge $parentExit.LineNumber) {
        throw "Invalid two-process pipe transfer in $Log"
    }
    if ($ApicIds -notcontains $cpu -or $cpus.ContainsKey($cpu) -or $pids.ContainsKey($parent) -or
        $pids.ContainsKey($child) -or $child -eq $parent -or $fault[2].Value -ne $parent -or
        $exitRecord[1].Value -ne $parent -or $exitRecord[2].Value -eq $fault[3].Value -or
        $faults[$i].LineNumber -ge $writes[$i].LineNumber -or
        $parentExit.LineNumber -ge $checks[$i].LineNumber) { throw "Invalid process isolation evidence in $Log" }
    $cpus[$cpu] = $true
    $pids[$child] = $true
    $pids[$parent] = $true
    $pids[$receiver] = $true
}
