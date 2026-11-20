param([ValidateSet('signed','loader','kernel','initrd')][string]$Case='signed',
      [ValidateSet(1,2)][int]$Cpus=2,
      [switch]$Shell,
      [ValidateSet('quiet','info','debug')][string]$LogLevel='info',
      [ValidateSet('serial','screen','both','none')][string]$LogOutput='both')
$ErrorActionPreference='Stop'
if ($Shell -and $Case -ne 'signed') { throw '-Shell requires the signed case' }
$root=Split-Path $PSScriptRoot
Set-Location $root
# Prevent simultaneous VirtualBox/NEM power-on from this workspace.
$lock=[IO.File]::Open((Join-Path $root 'build/test.lock'),'OpenOrCreate','ReadWrite','None')
$serial=$null
try {
$vbox=Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
function VBox { & $vbox @args; if ($LASTEXITCODE) { throw "VBoxManage failed: $($args[0])" } }
function Receive-Serial($State) {
    if ($null -eq $State) { return }
    if ($null -eq $State.Client) {
        if (!$State.Listener.Pending()) { return }
        $State.Client=$State.Listener.AcceptTcpClient()
        $State.Client.NoDelay=$true
        $State.Stream=$State.Client.GetStream()
        $State.Stream.ReadTimeout=2000
        $State.Stream.WriteTimeout=2000
    }
    $received=0
    while ($State.Stream.DataAvailable -and $received -lt 65536) {
        $count=$State.Stream.Read($State.Buffer,0,$State.Buffer.Length)
        if ($count -eq 0) { throw 'COM1 TCP connection closed' }
        $State.Log.Write($State.Buffer,0,$count)
        $State.Log.Flush()
        $received+=$count
        if ($State.Log.Length -gt 8MB) { throw 'COM1 capture exceeded the 8 MiB test limit' }
        [void]$State.Text.Append([Text.Encoding]::ASCII.GetString($State.Buffer,0,$count))
    }
    if ($State.Client.Client.Poll(0,[Net.Sockets.SelectMode]::SelectRead) -and !$State.Stream.DataAvailable) {
        throw 'COM1 TCP connection closed'
    }
}
function Wait-Serial($State,[string]$Pattern,[int]$Offset=0,[int]$Seconds=10) {
    $wait=[Diagnostics.Stopwatch]::StartNew()
    do {
        Receive-Serial $State
        $text=$State.Text.ToString($Offset,$State.Text.Length-$Offset)
        if ([regex]::IsMatch($text,$Pattern)) { return }
        if ($text -match 'SMP FAILED|FATAL VECTOR|SHELL FAILED') { throw 'Guest failed during shell test' }
        Start-Sleep -Milliseconds 25
    } while ($wait.Elapsed.TotalSeconds -lt $Seconds)
    throw "Timed out waiting for shell response: $Pattern"
}
function Send-Serial($State,[string]$Command) {
    # Pace bytes so this first UART profile need not rely on host-side bursts.
    $bytes=[Text.Encoding]::ASCII.GetBytes($Command+"`r")
    foreach ($byte in $bytes) {
        $State.Stream.WriteByte($byte)
        $State.Input.WriteByte($byte)
        $State.Input.Flush()
        Receive-Serial $State
        Start-Sleep -Milliseconds 10
    }
}
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
& wsl -d Ubuntu-24.04 -- bash scripts/disk.sh $relative $efi "$LogLevel $LogOutput"
if ($LASTEXITCODE) { throw 'disk build failed' }
VBox convertfromraw "$dir\esp.raw" "$dir\esp.vdi" --format VDI
VBox createvm --name $vm --basefolder $dir --ostype Other_64 --register
VBox modifyvm $vm --memory 256 --cpus $Cpus --firmware efi64 --paravirt-provider minimal --graphicscontroller vmsvga --vram 16 --ioapic on --nic1 none --audio-enabled off --boot1 disk --boot2 none --boot3 none --boot4 none --uart1 0x3f8 4
if ($Shell) {
    $serial=@{Listener=$null; Client=$null; Stream=$null; Log=$null; Input=$null;
              Buffer=(New-Object byte[] 4096); Text=(New-Object Text.StringBuilder)}
    $serial.Listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $serial.Listener.Start(1)
    $port=$serial.Listener.LocalEndpoint.Port
    $serial.Log=[IO.File]::Open("$dir\com1.log",'Create','Write','ReadWrite')
    $serial.Input=[IO.File]::Open("$dir\com1-input.bin",'Create','Write','ReadWrite')
    # VBox 7.1 tcpclient requires a listening socket before the VM starts.
    VBox modifyvm $vm --uart-mode1 tcpclient "127.0.0.1:$port"
} else {
    VBox modifyvm $vm --uartmode1 file "$dir\com1.log"
}
VBox storagectl $vm --name SATA --add sata --controller IntelAhci
VBox storageattach $vm --storagectl SATA --port 0 --device 0 --type hdd --medium "$dir\esp.vdi"
VBox modifynvram $vm inituefivarstore
# Seed the db variable (including UEFI attributes), then replace its contents in this new VM.
VBox modifynvram $vm enrollmssignatures
VBox modifynvram $vm changevar --name=db "--filename=$root\build\db.esl"
VBox modifynvram $vm enrollorclpk
VBox modifynvram $vm secureboot --enable
$runSucceeded=$false
try {
    VBox startvm $vm --type headless
    $timer=[Diagnostics.Stopwatch]::StartNew()
    if ($Shell) {
        do {
            Receive-Serial $serial
            if ($null -ne $serial.Client) { break }
            Start-Sleep -Milliseconds 25
        } while ($timer.Elapsed.TotalSeconds -lt 10)
        if ($null -eq $serial.Client) { throw 'VM did not connect its COM1 TCP client' }
    }
    $idleStart=$null
    $found=$false
    do {
        Start-Sleep -Milliseconds 500
        Receive-Serial $serial
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
            Receive-Serial $serial
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
        if ($Shell) {
            Wait-Serial $serial 'AGENTOS SHELL READY\r\nagentos> $'
            $commands=@('help','pid',("echo shell-ox"+[char]8+'k'),'cat /stage','cat /missing','no-such-command')
            foreach ($command in $commands) {
                $offset=$serial.Text.Length
                Send-Serial $serial $command
                Wait-Serial $serial 'agentos> $' $offset
            }
            $offset=$serial.Text.Length
            Send-Serial $serial 'exit'
            Wait-Serial $serial '(?m)^AGENTOS SHELL STOP PID=[0-9a-f]{16} STATUS=[0-9a-f]{16} FRAMES=OK\r\n' $offset
            & python "$PSScriptRoot/verify-shell.py" --log "$dir\com1.log" --input "$dir\com1-input.bin"
            if ($LASTEXITCODE -ne 0) { throw "Shell verification failed: $dir" }
        }
    } elseif (!(Select-String -LiteralPath "$dir\com1.log" -Pattern 'BdsDxe: failed to load .*HARDDISK.*(Access Denied|Security Violation)' -Quiet)) {
        throw "Missing firmware rejection; timeout is inconclusive: $dir"
    }
    Write-Output "Captured $Case ($Cpus vCPUs): $dir"
    $runSucceeded=$true
} finally {
    try { VBox controlvm $vm poweroff } catch {
        if ($runSucceeded) { throw }
        Write-Warning "VM power-off after a failed run also failed: $_"
    }
}
} finally {
    try {
        if ($null -ne $serial) {
            foreach ($handle in @($serial.Stream,$serial.Client,$serial.Log,$serial.Input)) {
                if ($null -ne $handle) {
                    try { $handle.Dispose() } catch { Write-Warning "COM1 cleanup failed: $_" }
                }
            }
            if ($null -ne $serial.Listener) { $serial.Listener.Stop() }
        }
    } finally { $lock.Dispose() }
}
