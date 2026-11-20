param([ValidateSet('signed','loader','kernel','initrd')][string]$Case='signed',
      [ValidateSet(1,2)][int]$Cpus=2)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
Set-Location $root
# Prevent simultaneous VirtualBox/NEM power-on from this workspace.
$lock=[IO.File]::Open((Join-Path $root 'build/test.lock'),'OpenOrCreate','ReadWrite','None')
try {
$vbox=Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
function VBox { & $vbox @args; if ($LASTEXITCODE) { throw "VBoxManage failed: $($args[0])" } }
$tag=[Guid]::NewGuid().ToString('N').Substring(0,10)
$vm="AgentOS-$Case-$tag"
$relative="build/runs/$vm"
$dir=(New-Item -Type Directory -Path $relative).FullName
$efi='build/agentos.efi'
if ($Case -ne 'signed') {
    & python scripts/tamper.py $efi "$relative/changed.efi" $Case
    if ($LASTEXITCODE) { throw 'mutation failed' }
    $efi="$relative/changed.efi"
}
& wsl -d Ubuntu-24.04 -- bash scripts/disk.sh $relative $efi
if ($LASTEXITCODE) { throw 'disk build failed' }
VBox convertfromraw "$dir\esp.raw" "$dir\esp.vdi" --format VDI
VBox createvm --name $vm --basefolder $dir --ostype Other_64 --register
VBox modifyvm $vm --memory 256 --cpus $Cpus --firmware efi64 --paravirt-provider minimal --graphicscontroller vmsvga --vram 16 --ioapic on --nic1 none --audio-enabled off --boot1 disk --boot2 none --boot3 none --boot4 none --uart1 0x3f8 4 --uartmode1 file "$dir\com1.log"
VBox storagectl $vm --name SATA --add sata --controller IntelAhci
VBox storageattach $vm --storagectl SATA --port 0 --device 0 --type hdd --medium "$dir\esp.vdi"
VBox modifynvram $vm inituefivarstore
# Seed the db variable (including UEFI attributes), then replace its contents in this new VM.
VBox modifynvram $vm enrollmssignatures
VBox modifynvram $vm changevar --name=db "--filename=$root\build\db.esl"
VBox modifynvram $vm enrollorclpk
VBox modifynvram $vm secureboot --enable
VBox startvm $vm --type headless
try {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $idleStart=$null
    $found=$false
    do {
        Start-Sleep -Milliseconds 500
        if (Test-Path "$dir\com1.log") {
            if ($Case -eq 'signed' -and $null -eq $idleStart -and
                (Select-String -LiteralPath "$dir\com1.log" -SimpleMatch 'AGENTOS IDLE BEGIN' -Quiet)) {
                $idleStart=$timer.Elapsed.TotalSeconds
            }
            $found=[bool](Select-String -LiteralPath "$dir\com1.log" -SimpleMatch 'AGENTOS KERNEL OK STAGE 1' -Quiet)
            if ($Case -eq 'signed' -and (Select-String -LiteralPath "$dir\com1.log" -Pattern 'SMP FAILED|FATAL VECTOR|ACPI DISCOVERY FAILED' -Quiet)) {
                throw "Guest reported a boot failure: $dir"
            }
        }
        if ($found -and $Case -eq 'signed') {
            $hostIdleSeconds=$timer.Elapsed.TotalSeconds-$idleStart
            Start-Sleep -Seconds 1
            break
        }
        if ($found -and $Case -ne 'signed') { throw 'Firmware accepted a modified boot image' }
        if ($Case -ne 'signed' -and (Test-Path "$dir\com1.log") -and
            (Select-String -LiteralPath "$dir\com1.log" -Pattern 'Security Violation|Access Denied' -Quiet)) { break }
    } while (($null -eq $idleStart -and $timer.Elapsed.TotalSeconds -lt 120) -or
             ($null -ne $idleStart -and ($timer.Elapsed.TotalSeconds - $idleStart) -lt 60))
    if ($Case -eq 'signed' -and !$found) { throw "Kernel marker missing: $dir" }
    VBox controlvm $vm screenshotpng "$dir\display.png"
    if ($Case -eq 'signed') {
        $tasks = @(Select-String -LiteralPath "$dir\com1.log" -Pattern '^AGENTOS TASK (BSP|AP) APIC=([0-9a-f]{16}) TIMER-WAKES=0000000000000003$')
        $ids = @($tasks | ForEach-Object { $_.Matches[0].Groups[2].Value } | Sort-Object -Unique)
        $bootstrap = @($tasks | Where-Object { $_.Matches[0].Groups[1].Value -eq 'BSP' })
        if ($tasks.Count -ne $Cpus -or $ids.Count -ne $Cpus -or $bootstrap.Count -ne 1) {
            throw "Expected one task with three timer wakeups on each of $Cpus distinct CPUs: $dir"
        }
        $workers = @(Select-String -LiteralPath "$dir\com1.log" -Pattern '^AGENTOS SCHED APIC=([0-9a-f]{16}) TASK=(000000000000000[01]) PREEMPTIONS=([0-9a-f]{16}) PAGES=0000000000001000$')
        $seen = @{}
        foreach ($worker in $workers) {
            $fields = $worker.Matches[0].Groups
            $key = $fields[1].Value + '/' + $fields[2].Value
            if ($ids -notcontains $fields[1].Value -or $seen.ContainsKey($key) -or
                [Convert]::ToUInt64($fields[3].Value,16) -lt 2) {
                throw "Invalid preemption record: $worker"
            }
            $seen[$key] = $true
        }
        if ($seen.Count -ne 2 * $Cpus) { throw "Missing preempted workers: $dir" }
        $stress = @(Select-String -LiteralPath "$dir\com1.log" -Pattern '^AGENTOS FRAME STRESS BITMAP OK HELD=([0-9a-f]{16}) FREE-BEFORE=([0-9a-f]{16}) FREE-AFTER=([0-9a-f]{16})$')
        if ($stress.Count -ne 1) { throw "Missing final bitmap comparison: $dir" }
        $fields = $stress[0].Matches[0].Groups
        if ([Convert]::ToUInt64($fields[1].Value,16) -ne 16 * $Cpus -or
            $fields[2].Value -ne $fields[3].Value) { throw "Incorrect frame accounting: $dir" }
        foreach ($pattern in @('AGENTOS OWN CR3=[0-9a-f]{13}000', 'AGENTOS IDT OK: BP PF-NULL PF-GUARD PF-WP PF-NX')) {
            if (!(Select-String -LiteralPath "$dir\com1.log" -Pattern $pattern -Quiet)) { throw "Missing $pattern in $dir" }
        }
        if (!(Select-String -LiteralPath "$dir\com1.log" -SimpleMatch 'AGENTOS PHYSICAL FRAMES OK' -Quiet)) {
            throw "Physical frame probe missing: $dir"
        }
        & "$PSScriptRoot/verify-display.ps1" "$dir\display.png"
        & "$PSScriptRoot/verify-processes.ps1" -Log "$dir\com1.log" -ApicIds $ids
        & "$PSScriptRoot/verify-idle.ps1" -RunDir $dir -ApicIds $ids -HostSeconds $hostIdleSeconds
    } elseif (!(Select-String -LiteralPath "$dir\com1.log" -Pattern 'BdsDxe: failed to load .*HARDDISK.*(Access Denied|Security Violation)' -Quiet)) {
        throw "Missing firmware rejection; timeout is inconclusive: $dir"
    }
    Write-Output "Captured $Case ($Cpus vCPUs): $dir"
} finally {
    VBox controlvm $vm poweroff
}
} finally {
    $lock.Dispose()
}
