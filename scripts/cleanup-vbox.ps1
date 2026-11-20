param()
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
$runs=Join-Path $root 'build\runs'
$vbox=Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
$lock=[IO.File]::Open((Join-Path $root 'build/test.lock'),'OpenOrCreate','ReadWrite','None')
try {
    $machines=& $vbox list vms
    if ($LASTEXITCODE) { throw 'Cannot enumerate VirtualBox machines' }
    foreach ($record in $machines) {
        if ($record -notmatch '^"(AgentOS-(?:signed|kernel|loader|initrd)-[0-9a-f]{10})" \{([0-9a-f-]{36})\}$') { continue }
        $name=$Matches[1]; $uuid=$Matches[2]
        $info=& $vbox showvminfo $uuid --machinereadable
        if ($LASTEXITCODE) { throw "Cannot inspect $uuid" }
        $config=(Join-Path $runs "$name\$name\$name.vbox").Replace('\','\\')
        if ($info -notcontains "CfgFile=`"$config`"" -or
            ($info -notcontains 'VMState="poweroff"' -and $info -notcontains 'VMState="aborted"')) { continue }
        & $vbox unregistervm $uuid
        if ($LASTEXITCODE) { throw "Cannot unregister $name" }
        Write-Output "Unregistered $name"
    }
} finally { $lock.Dispose() }
