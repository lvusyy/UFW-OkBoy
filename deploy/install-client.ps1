<#
.SYNOPSIS
    UFW OkBoy - one-click Windows client install (Windows PowerShell 5.1+ or PowerShell 7).

.DESCRIPTION
    The Windows counterpart of install-client.sh. Run it from an elevated
    PowerShell ("Run as administrator"). It installs client\knock.ps1 plus a
    scheduled task that knocks every configured server every -IntervalMinutes
    as SYSTEM, so it keeps working after reboots with nobody logged in.

    Each server gets its own config file (named after its host and port). Run
    the installer again with another -Server to add a second server, or with
    the same -Server to change its user / secret. -Uninstall removes the task
    and all files.

    When -Secret is omitted it is prompted for without echo, which also keeps
    it out of the PowerShell history.

    One-liner (elevated PowerShell; add -NoVerifySsl for a self-signed server):
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
      & ([scriptblock]::Create((irm https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.ps1))) -Server https://your-server:8443 -User alice

.PARAMETER GhMirror
    GitHub proxy prefix for downloading knock.ps1 when GitHub is blocked, e.g.
    https://ghfast.top (find a current one at https://ghproxy.link/). Also read
    from the UFW_OKBOY_GH_MIRROR environment variable.
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$User,
    [string]$Secret,
    [ValidateRange(1, 1440)]
    [int]$IntervalMinutes = 1,
    [switch]$NoVerifySsl,
    [string]$GhMirror = $env:UFW_OKBOY_GH_MIRROR,
    [switch]$Uninstall
)

# The one-liner runs this as a script block inside the caller's session, so
# stop with throw / return, never exit (exit would close their window).
$ErrorActionPreference = 'Stop'

$GhRaw       = 'https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master'
$InstallDir  = Join-Path $env:ProgramFiles 'UFW-OkBoy'
$ServersDir  = Join-Path $InstallDir 'servers'
$KnockScript = Join-Path $InstallDir 'knock.ps1'
$LogFile     = Join-Path $InstallDir 'last-run.log'
$TaskName    = 'UFW-OkBoy Knock'
$PowerShell  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell ("Run as administrator"): the knock task runs as SYSTEM.'
}

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    # A knock that is still finishing keeps last-run.log open for a little while.
    for ($i = 1; Test-Path -LiteralPath $InstallDir; $i++) {
        try {
            Remove-Item -LiteralPath $InstallDir -Recurse -Force
        } catch {
            if ($i -ge 120) { throw }
            if ($i -eq 1) { Write-Host '[INFO] Waiting for a running knock to finish...' }
            Start-Sleep -Seconds 1
        }
    }
    Write-Host '[INFO] UFW OkBoy client removed (scheduled task and files).'
    return
}

# Interactive prompts for missing values (the secret without echo).
if (-not $Server) { $Server = Read-Host 'Server URL (https://...)' }
if (-not $User)   { $User = Read-Host 'Username' }
if (-not $Secret) { $Secret = [Net.NetworkCredential]::new('', (Read-Host 'Secret' -AsSecureString)).Password }

$uri = $null
if (-not [Uri]::TryCreate($Server, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin 'https', 'http') {
    throw "Invalid -Server '$Server': expected https://host[:port]"
}
if ($User -notmatch '^[A-Za-z0-9_.-]{1,64}$') { throw "Invalid -User '$User'" }
if ($Secret -notmatch '^[^\s"'']+$') { throw 'Invalid -Secret: empty, or contains spaces or quotes' }

$serverUrl = $uri.AbsoluteUri.TrimEnd('/')
$name = $uri.Host
if (-not $uri.IsDefaultPort) { $name = '{0}_{1}' -f $name, $uri.Port }
$configName = ($name -replace '[^A-Za-z0-9.-]', '_') + '.yaml'
$configFile = Join-Path $ServersDir $configName

# Everything in the install directory runs as SYSTEM or holds secrets, so only
# SYSTEM and Administrators may access it. A new directory is locked before
# anything is written into it; an existing one must still carry that lock (and
# be a real directory: the ACL of a junction says nothing about its target).
$trusted = 'S-1-5-18', 'S-1-5-32-544'  # LocalSystem, BUILTIN\Administrators
if (Test-Path -LiteralPath $InstallDir) {
    $item = Get-Item -LiteralPath $InstallDir -Force
    $acl = Get-Acl -LiteralPath $InstallDir
    $others = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -notin $trusted })
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            -not $acl.AreAccessRulesProtected -or $others.Count -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw "$InstallDir has permissions this installer did not set. Remove it and run again: Remove-Item -LiteralPath '$InstallDir' -Recurse -Force"
    }
} else {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
    try {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in $trusted) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
                'ContainerInherit, ObjectInherit', 'None', 'Allow'))
        }
        # Replaces owner and the whole DACL in one call (Set-Acl would also try to write the SACL).
        $dir = [IO.DirectoryInfo]::new($InstallDir)
        if ($PSVersionTable.PSEdition -eq 'Core') {
            [IO.FileSystemAclExtensions]::SetAccessControl($dir, $acl)
        } else {
            $dir.SetAccessControl($acl)
        }
    } catch {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force  # never leave an unlocked directory behind
        throw
    }
}

if ($PSVersionTable.PSEdition -ne 'Core' -and [int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

function Move-IntoPlace([string]$Source, [string]$Destination) {
    # Move-Item -Force deletes the destination before moving, so keep the old
    # file aside until the new one is in place, and put it back on failure.
    $backup = "$Destination.old"
    if (Test-Path -LiteralPath $Destination) { Move-Item -LiteralPath $Destination -Destination $backup -Force }
    try {
        Move-Item -LiteralPath $Source -Destination $Destination
    } catch {
        if (Test-Path -LiteralPath $backup) { Move-Item -LiteralPath $backup -Destination $Destination }
        throw
    }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
}

# Prepare knock.ps1 and every server config in a staging directory inside the
# locked one, so each file is created fresh and inherits the lock (a file that
# is overwritten in place keeps its own ACL), then move them into place. A
# failure before the moves leaves the current install and its task untouched.
$stage = Join-Path $InstallDir ('staging-' + [Guid]::NewGuid().ToString('N'))
$stageServers = Join-Path $stage 'servers'
New-Item -ItemType Directory -Path $stageServers | Out-Null
try {
    # knock.ps1: the local copy from a repo checkout / release package, else GitHub.
    $localKnock = if ($PSScriptRoot) { Join-Path $PSScriptRoot '..\client\knock.ps1' }
    if ($localKnock -and (Test-Path -LiteralPath $localKnock)) {
        Copy-Item -LiteralPath $localKnock -Destination (Join-Path $stage 'knock.ps1')
    } else {
        $url = "$GhRaw/client/knock.ps1"
        if ($GhMirror) { $url = '{0}/{1}' -f $GhMirror.TrimEnd('/'), $url }
        Write-Host "[INFO] Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile (Join-Path $stage 'knock.ps1') -UseBasicParsing
    }

    # Configs of servers added earlier (regular files only), then this server's
    # in the same format as knock.py (server_url / username / secret / verify_ssl).
    if (Test-Path -LiteralPath $ServersDir) {
        $item = Get-Item -LiteralPath $ServersDir -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "$ServersDir is a link or not a directory; this installer only writes into plain directories."
        }
        foreach ($file in Get-ChildItem -LiteralPath $ServersDir -Filter '*.yaml' -File) {
            if (-not ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                [IO.File]::WriteAllText((Join-Path $stageServers $file.Name), [IO.File]::ReadAllText($file.FullName))
            }
        }
    }
    $verify = if ($NoVerifySsl) { 'false' } else { 'true' }
    [IO.File]::WriteAllText((Join-Path $stageServers $configName),
        "server_url: `"$serverUrl`"`nusername: `"$User`"`nsecret: `"$Secret`"`nverify_ssl: $verify`n")

    Move-IntoPlace (Join-Path $stage 'knock.ps1') $KnockScript
    New-Item -ItemType Directory -Force -Path $ServersDir | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $stageServers -File) {
        Move-IntoPlace $file.FullName (Join-Path $ServersDir $file.Name)
    }
} finally {
    # Leftovers are copies inside the locked directory; warn rather than fail the install.
    try { Remove-Item -LiteralPath $stage -Recurse -Force } catch { Write-Warning "Could not remove ${stage}: $($_.Exception.Message)" }
}
Write-Host "[INFO] Config written to $configFile"

Write-Host '[INFO] Testing connection...'
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $KnockScript -Config $configFile
if ($LASTEXITCODE -eq 0) {
    Write-Host '[INFO] Knock successful! Your IP is now allowlisted.'
} else {
    Write-Warning 'Initial knock failed. Check the server URL, user, secret and network (see the line above).'
}

# One task knocks every config in the servers directory; each run overwrites last-run.log.
$argument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ''{0}'' *> ''{1}''"' -f $KnockScript, $LogFile
$action   = New-ScheduledTaskAction -Execute $PowerShell -Argument $argument
$trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
$system   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $system `
    -Description 'UFW OkBoy: keeps this machine''s public IP on the servers'' firewall allowlists.' -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ''
Write-Host '=== Client Setup Complete ==='
Write-Host "  Config:   $configFile"
Write-Host "  Script:   $KnockScript"
Write-Host "  Task:     $TaskName (every $IntervalMinutes min, as SYSTEM)"
Write-Host "  TLS:      verify_ssl=$verify"
Write-Host ''
Write-Host '  Manual commands (elevated PowerShell):'
Write-Host "    Get-Content '$LogFile'    # result of the last scheduled knock"
Write-Host "    powershell -ExecutionPolicy Bypass -File '$KnockScript'    # knock all servers now"
Write-Host "    powershell -ExecutionPolicy Bypass -File '$KnockScript' status"
Write-Host '  Add a server: run the installer again with its -Server. Remove everything: -Uninstall'
