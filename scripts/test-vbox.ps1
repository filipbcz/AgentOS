param([ValidateSet('signed','loader','kernel','initrd')][string]$Case='signed',
      [ValidateSet(1,2)][int]$Cpus=2,
      [switch]$Shell,
      [switch]$Keyboard,
      [ValidateSet('quiet','info','debug')][string]$LogLevel='info',
      [ValidateSet('serial','screen','both','none')][string]$LogOutput='both')
$ErrorActionPreference='Stop'
if ($Shell -and $Case -ne 'signed') { throw '-Shell requires the signed case' }
if ($Keyboard -and !$Shell) { throw '-Keyboard requires -Shell' }
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
        $clean=$text
        if ($null -ne $sessionPlan) { $clean=[regex]::Replace($text,$sessionPlan.kernel_event_pattern,'') }
        if ([regex]::IsMatch($clean,$Pattern)) { return }
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
        Start-Sleep -Milliseconds 2
    }
}
# Exercise the real PS/2 controller; VBox's API accepts PC/XT Set 1, then
# the device translates it to the scan set configured by the guest.
function Send-Keyboard([string]$Command) {
    if ($Command -notmatch '^[\x08 -~]+$') { throw 'PS/2 injection requires US ASCII or Backspace' }
    foreach ($key in $Command.ToCharArray()) {
        if ([int]$key -eq 8) { VBox controlvm $vm keyboardputscancode 0e 8e }
        else { VBox controlvm $vm keyboardputstring ([string]$key) }
        Start-Sleep -Milliseconds 15
    }
    VBox controlvm $vm keyboardputscancode 1c 9c
}
function Verify-Console([string]$Path,[string]$Before='') {
    $imageArgs=@('--after',$Path,'--level',$LogLevel,'--output',$LogOutput)
    if ($Before) { $imageArgs+=@('--before',$Before,'--response','ps2-ok') }
    & python "$PSScriptRoot/verify-console-image.py" @imageArgs
    if ($LASTEXITCODE -ne 0) { throw "Actual GOP glyph verification failed: $Path" }
}
function Wait-WorkerExits($State,[int]$Offset,[int]$Count) {
    $wait=[Diagnostics.Stopwatch]::StartNew()
    do {
        Receive-Serial $State
        $text=$State.Text.ToString($Offset,$State.Text.Length-$Offset)
        $exits=[regex]::Matches($text,$sessionPlan.worker_exit_pattern)
        if ($exits.Count -ge $Count) { return }
        if ($text -match 'SMP FAILED|FATAL VECTOR|SHELL FAILED') { throw 'Guest failed during restart' }
        Start-Sleep -Milliseconds 25
    } while ($wait.Elapsed.TotalSeconds -lt 15)
    throw 'Service RESTART did not autonomously complete its three bounded attempts'
}
$sessionPlan=$null
$tag=[Guid]::NewGuid().ToString('N').Substring(0,10)
$vm="AgentOS-$Case-$tag"
$relative="build/runs/$vm"
$dir=(New-Item -Type Directory -Path $relative).FullName
# Refuse stale signed images and uncommitted/modified source. The WSL build
# emits build-provenance.json only after signing and signature verification.
$sourceCommit=(& git -C $root rev-parse --verify HEAD)
if ($LASTEXITCODE -ne 0 -or !$sourceCommit) { throw 'Git source revision cannot be established' }
$sourceCommit=$sourceCommit.Trim()
$dirty=@(& git -C $root status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) {
    throw 'VM acceptance requires a clean committed source tree'
}
& python "$PSScriptRoot/verify-vm-evidence.py" --root $root --commit $sourceCommit
if ($LASTEXITCODE -ne 0) { throw 'Signed EFI build provenance check failed; rebuild from this exact commit' }
$vboxVersion=(& $vbox --version).Trim()
if ($LASTEXITCODE -ne 0 -or $vboxVersion -notmatch '^7\.1\.12(?:r[0-9]+)?$') {
    throw "VirtualBox 7.1.12 required for comparable acceptance: $vboxVersion"
}
$buildReceiptHash=(Get-FileHash (Join-Path $root 'build/build-provenance.json') -Algorithm SHA256).Hash.ToLowerInvariant()
$harnessHash=(Get-FileHash (Join-Path $PSScriptRoot 'test-vbox.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
$efi='build/agentos.efi'
if ($Case -ne 'signed') {
    & python scripts/tamper.py $efi "$relative/changed.efi" $Case
    if ($LASTEXITCODE) { throw 'mutation failed' }
    $efi="$relative/changed.efi"
}
$bootImageHash=(Get-FileHash (Join-Path $root $efi) -Algorithm SHA256).Hash.ToLowerInvariant()
& wsl -d Ubuntu-24.04 -- bash scripts/disk.sh $relative $efi "$LogLevel $LogOutput"
if ($LASTEXITCODE) { throw 'disk build failed' }
VBox convertfromraw "$dir\esp.raw" "$dir\esp.vdi" --format VDI
VBox createvm --name $vm --basefolder $dir --ostype Other_64 --register
VBox modifyvm $vm --memory 256 --cpus $Cpus --firmware efi64 --paravirt-provider minimal --x86-hpet on --graphicscontroller vmsvga --vram 16 --ioapic on --nic1 none --audio-enabled off --boot1 disk --boot2 none --boot3 none --boot4 none --uart1 0x3f8 4
if ($Keyboard) { VBox modifyvm $vm --keyboard ps2 }
# All acceptance profiles use the SAME host-owned COM1 capture. In file mode,
# a fresh VBox EFI VM can reach the graphical shell without producing a
# readable COM1 file; the former harness then timed out despite a working guest.
# TCP capture also makes absent UART data distinguishable from a failed boot.
$serial=@{Listener=$null; Client=$null; Stream=$null; Log=$null; Input=$null;
          Buffer=(New-Object byte[] 4096); Text=(New-Object Text.StringBuilder)}
$serial.Listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
$serial.Listener.Start(1)
$port=$serial.Listener.LocalEndpoint.Port
$serial.Log=[IO.File]::Open("$dir\com1.log",'Create','Write','ReadWrite')
if ($Shell) {
    $serial.Input=[IO.File]::Open("$dir\com1-input.bin",'Create','Write','ReadWrite')
}
# VBox 7.1 tcpclient requires an active listener before startvm.
VBox modifyvm $vm --uart-mode1 tcpclient "127.0.0.1:$port"
VBox storagectl $vm --name SATA --add sata --controller IntelAhci
VBox storageattach $vm --storagectl SATA --port 0 --device 0 --type hdd --medium "$dir\esp.vdi"
VBox modifynvram $vm inituefivarstore
# Seed the db variable (including UEFI attributes), then replace its contents in this new VM.
VBox modifynvram $vm enrollmssignatures
VBox modifynvram $vm changevar --name=db "--filename=$root\build\db.esl"
VBox modifynvram $vm enrollorclpk
VBox modifynvram $vm secureboot --enable
$runSucceeded=$false
$shutdownSucceeded=$false
try {
    VBox startvm $vm --type headless
    $timer=[Diagnostics.Stopwatch]::StartNew()
    # Connect before examining guest output, regardless of interactive mode.
    do {
        Receive-Serial $serial
        if ($null -ne $serial.Client) { break }
        Start-Sleep -Milliseconds 25
    } while ($timer.Elapsed.TotalSeconds -lt 30)
    if ($null -eq $serial.Client) { throw "COM1 TCP connection missing: $dir" }
    $idleStart=$null
    $found=$false
    do {
        Start-Sleep -Milliseconds 500
        Receive-Serial $serial
        $bootText=$serial.Text.ToString()
        if ($Case -eq 'signed' -and $null -eq $idleStart -and
            $bootText.Contains('AGENTOS IDLE BEGIN')) {
            $idleStart=$timer.Elapsed.TotalSeconds
        }
        $found=$bootText.Contains('AGENTOS KERNEL OK STAGE 1')
        if ($Case -eq 'signed' -and $bootText -match 'SMP FAILED|FATAL VECTOR|ACPI DISCOVERY FAILED') {
            throw "Guest reported a boot failure: $dir"
        }
        if ($found -and $Case -eq 'signed') {
            if ($null -eq $idleStart) { throw "Kernel marker preceded idle marker: $dir" }
            $hostIdleSeconds=$timer.Elapsed.TotalSeconds-$idleStart
            break
        }
        if ($found -and $Case -ne 'signed') { throw 'Firmware accepted a modified boot image' }
        if ($Case -ne 'signed' -and $bootText -match 'Security Violation|Access Denied') { break }
    } while (($null -eq $idleStart -and $timer.Elapsed.TotalSeconds -lt 120) -or
             ($null -ne $idleStart -and ($timer.Elapsed.TotalSeconds - $idleStart) -lt 60))
    if ($Case -eq 'signed' -and !$found) {
        throw "Kernel marker missing in COM1 TCP capture (received $($serial.Text.Length) characters): $dir"
    }
    if ($Case -eq 'signed') {
        # The guest always enters its operational TTY. Capture its explicit
        # readiness state, with a preserved boot header, rather than racing
        # the old framebuffer clear one second after the raw boot marker.
        $readyTimer=[Diagnostics.Stopwatch]::StartNew()
        do {
            Receive-Serial $serial
            $readyText=[IO.File]::ReadAllText("$dir\com1.log")
            if ($readyText -match 'AGENTOS SHELL READY\r\nagentos> ') { break }
            if ($readyText -match 'SMP FAILED|FATAL VECTOR|SHELL FAILED') { throw 'Guest failed before shell readiness' }
            Start-Sleep -Milliseconds 25
        } while ($readyTimer.Elapsed.TotalSeconds -lt 30)
        if ($readyText -notmatch 'AGENTOS SHELL READY\r\nagentos> ') { throw 'Operational shell did not become ready' }
    }
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
        Verify-Console "$dir\display.png"
        if (!(Select-String -LiteralPath "$dir\com1.log" -SimpleMatch 'AGENTOS KERNEL STACK GUARD OK' -Quiet)) {
            throw "Kernel stack guard fault probes missing: $dir"
        }
        & python "$PSScriptRoot/verify-boot-log.py" --log "$dir\com1.log" --level $LogLevel --output $LogOutput
        if ($LASTEXITCODE -ne 0) { throw "BOOT.LOG sink/severity verification failed: $dir" }
        & "$PSScriptRoot/verify-processes.ps1" -Log "$dir\com1.log" -ApicIds $ids
        & python "$PSScriptRoot/verify-supervisor.py" --log "$dir\com1.log" --cpus $Cpus
        if ($LASTEXITCODE -ne 0) { throw "Service supervision verification failed: $dir" }
        & python "$PSScriptRoot/verify-orphans.py" --log "$dir\com1.log" --cpus $Cpus
        if ($LASTEXITCODE -ne 0) { throw "Orphan reparenting verification failed: $dir" }
        & python "$PSScriptRoot/verify-cow.py" --log "$dir\com1.log" --cpus $Cpus
        if ($LASTEXITCODE -ne 0) { throw "Fork/COW page isolation failed: $dir" }
        & python "$PSScriptRoot/verify-demand-paging.py" --log "$dir\com1.log" --cpus $Cpus
        if ($LASTEXITCODE -ne 0) { throw "Demand paging and lazy syscall isolation failed: $dir" }
        & python "$PSScriptRoot/verify-migration.py" --log "$dir\com1.log" --cpus $Cpus
        if ($LASTEXITCODE -ne 0) { throw "Actual process migration and cross-CPU state preservation failed: $dir" }
        & python "$PSScriptRoot/verify-service-manager.py" --log "$dir\com1.log"
        if ($LASTEXITCODE -ne 0) { throw "Persistent service registry readiness/restart evidence failed: $dir" }
        & "$PSScriptRoot/verify-idle.ps1" -RunDir $dir -ApicIds $ids -HostSeconds $hostIdleSeconds
        if ($Shell) {
            $match=[regex]::Match($serial.Text.ToString(),'(?m)^AGENTOS SHELL START PID=([0-9a-f]{16})\r\n')
            if (!$match.Success) { throw 'Managed shell identity missing' }
            $shellPid=[Convert]::ToUInt64($match.Groups[1].Value,16)
            $planArgs=@('--plan-pid',[string]$shellPid)
            if ($Keyboard) { $planArgs+='--keyboard' }
            $planJson=& python "$PSScriptRoot/verify-stage3-session.py" @planArgs
            if ($LASTEXITCODE -ne 0) { throw 'Could not load the shared stage-3 input plan' }
            $sessionPlan=$planJson | ConvertFrom-Json
            VBox controlvm $vm screenshotpng "$dir\shell-before.png"
            Verify-Console "$dir\shell-before.png"
            foreach ($step in $sessionPlan.steps) {
                if ($step.screenshot) { VBox controlvm $vm screenshotpng "$dir\shell-before.png" }
                $offset=$serial.Text.Length
                if ($step.transport -eq 'keyboard') { Send-Keyboard $step.command }
                else { Send-Serial $serial $step.command }
                Wait-Serial $serial $step.pattern $offset 20
                if ($step.wait_exits -gt 0) { Wait-WorkerExits $serial $offset $step.wait_exits }
                if ($step.screenshot) {
                    VBox controlvm $vm screenshotpng "$dir\shell-keyboard.png"
                    Verify-Console "$dir\shell-keyboard.png" "$dir\shell-before.png"
                }
            }
            Wait-Serial $serial $sessionPlan.stop_pattern 0 15
            if ($LogLevel -in @('info','debug') -and $LogOutput -in @('serial','both')) {
                # This structured write follows the native stop record.
                # Drain it completely before hashing or powering off; a TCP
                # read can otherwise end halfway through the final line.
                Wait-Serial $serial '\[INFO\] INTERACTIVE SHELL STOPPED\r\n$' 0 15
            }
            $verifyArgs=@('--log',"$dir\com1.log",'--input',"$dir\com1-input.bin",'--cpus',[string]$Cpus)
            if ($Keyboard) { $verifyArgs+='--keyboard' }
            & python "$PSScriptRoot/verify-stage3-session.py" @verifyArgs
            if ($LASTEXITCODE -ne 0) { throw "Stage-3 interactive verification failed: $dir" }
            & python "$PSScriptRoot/verify-boot-log.py" --log "$dir\com1.log" --level $LogLevel --output $LogOutput
            if ($LASTEXITCODE -ne 0) { throw 'BOOT.LOG policy violated during interactive session' }
        }
    } elseif ($serial.Text.ToString() -notmatch 'BdsDxe: failed to load [^\r\n]*HARDDISK[^\r\n]*(Access Denied|Security Violation)') {
        throw "Missing firmware rejection in COM1 TCP capture; timeout is inconclusive: $dir"
    }
    $runSucceeded=$true
} finally {
    # Preserve what the UEFI firmware actually displayed during a failed first boot.
    # COM1 can be absent until our loader runs; capture before powering off.
    if (!$runSucceeded) {
        try {
            VBox controlvm $vm screenshotpng "$dir\failure.png"
            Write-Warning "Captured failed VM screen before power-off: $dir\failure.png"
        } catch {
            Write-Warning "Could not capture failed VM screen: $_"
        }
    }
    try { VBox controlvm $vm poweroff; $shutdownSucceeded=$true } catch {
        if ($runSucceeded) { throw }
        Write-Warning "VM power-off after a failed run also failed: $_"
    }
}
} catch {
    $runError=$_.Exception.Message
    throw
} finally {
    # Close and flush host-owned COM1 capture before measuring hashes.
    try {
        if ($null -ne $serial) {
            foreach ($handle in @($serial.Stream,$serial.Client,$serial.Log,$serial.Input)) {
                if ($null -ne $handle) {
                    try { $handle.Dispose() } catch { Write-Warning "COM1 cleanup failed: $_" }
                }
            }
            if ($null -ne $serial.Listener) { $serial.Listener.Stop() }
        }
    } finally {
        try {
            $artifactHashes=@{}
            foreach ($name in @('esp.raw','esp.vdi','changed.efi','com1.log',
                                'com1-input.bin','display.png','shell-before.png',
                                'shell-keyboard.png','failure.png')) {
                $file=Join-Path $dir $name
                if (Test-Path -LiteralPath $file -PathType Leaf) {
                    $artifactHashes[$name]=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
            $elapsed=if ($null -ne $timer) { [math]::Round($timer.Elapsed.TotalSeconds,3) } else { 0.0 }
            $receiptStatus='fail'
            if ($runSucceeded -and $shutdownSucceeded) { $receiptStatus='pass' }
            $receipt=[ordered]@{
                schema=1
                result=$receiptStatus
                source_commit=$sourceCommit
                build_provenance_sha256=$buildReceiptHash
                harness_sha256=$harnessHash
                virtualbox_version=$vboxVersion
                vm=$vm
                case=$Case
                cpus=$Cpus
                shell=[bool]$Shell
                keyboard=[bool]$Keyboard
                boot_log_level=$LogLevel
                boot_log_output=$LogOutput
                host_elapsed_seconds=$elapsed
                boot_image_sha256=$bootImageHash
                failure_message=$runError
                artifacts=$artifactHashes
            }
            $receiptFile=Join-Path $dir 'acceptance.json'
            $tempReceipt="$receiptFile.tmp"
            $json=$receipt | ConvertTo-Json -Depth 6
            [IO.File]::WriteAllText($tempReceipt,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
            Move-Item -LiteralPath $tempReceipt -Destination $receiptFile -Force
            if ($receipt.result -eq 'pass') {
                # Validate the completed receipt before reporting success.
                & python "$PSScriptRoot/verify-vm-evidence.py" --root $root --run-dir $dir
                if ($LASTEXITCODE -ne 0) {
                    $receipt.result='fail'
                    $receipt.failure_message='VM evidence receipt failed independent validation'
                    [IO.File]::WriteAllText($tempReceipt,($receipt | ConvertTo-Json -Depth 6)+[Environment]::NewLine,
                                            [Text.UTF8Encoding]::new($false))
                    Move-Item -LiteralPath $tempReceipt -Destination $receiptFile -Force
                    throw 'VM evidence validation failed; acceptance was not recorded'
                }
            }
        } catch {
            if ($runSucceeded) { throw }
            Write-Warning "Unable to write failure evidence receipt: $_"
        } finally {
            $lock.Dispose()
        }
    }
}
Write-Output "Verified $Case ($Cpus vCPUs): $dir"
Write-Output "VM_ACCEPTANCE_JSON=$dir\acceptance.json"
