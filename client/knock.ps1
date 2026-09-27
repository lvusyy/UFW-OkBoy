<#
.SYNOPSIS
    UFW OkBoy - Windows client (Windows PowerShell 5.1+ or PowerShell 7, no dependencies).

.DESCRIPTION
    Registers this machine's public IP with UFW OkBoy servers: the Windows
    counterpart of knock.py / knock.sh. Reads the same config format as
    knock.py (server_url / username / secret / verify_ssl, see
    config.example.yaml).

    -Config is a config file or a directory. For a directory, every *.yaml in
    it is used, one file per server. The default is the "servers" directory
    next to this script, where install-client.ps1 keeps its configs.

.EXAMPLE
    .\knock.ps1 -Config .\config.yaml             # knock once
    .\knock.ps1 status -Config .\config.yaml      # show registration status
    .\knock.ps1                                   # knock every server set up by install-client.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('knock', 'status')]
    [string]$Action = 'knock',

    [string]$Config,

    # Skip TLS verification (self-signed server), like knock.py --no-verify-ssl.
    # The HMAC secret is never sent, so this drops only transport verification.
    [switch]$Insecure
)

$ErrorActionPreference = 'Stop'

if (-not $Config) { $Config = Join-Path $PSScriptRoot 'servers' }

# Windows PowerShell 5.1 may still default to TLS 1.0 on older systems. Add TLS
# 1.2 unless the OS default (SystemDefault = 0) is already in effect.
if ($PSVersionTable.PSEdition -ne 'Core' -and [int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

function Read-KnockConfig([string]$Path) {
    # Flat "key: value" lines as in config.example.yaml. A value may be quoted and
    # followed by a "# comment"; no nesting, multi-line values or escape sequences.
    $cfg = @{}
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$') { continue }
        $key, $value = $Matches[1], $Matches[2]
        if ($value -match '^"([^"]*)"' -or $value -match "^'([^']*)'") {
            $value = $Matches[1]
        } else {
            $value = ($value -replace '(^|\s)#.*$', '').Trim()
        }
        $cfg[$key] = $value
    }
    foreach ($key in 'server_url', 'username', 'secret') {
        if (-not $cfg[$key]) { throw "${Path}: '$key' is required" }
    }
    $cfg
}

function Get-AuthHeader([string]$User, [string]$Secret) {
    # signature = HMAC-SHA256(secret, "<username>:<timestamp>"); the secret itself is never sent.
    $message = '{0}:{1}' -f $User, [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $hmac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Secret))
    try {
        $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
    } finally {
        $hmac.Dispose()
    }
    'HMAC-SHA256 {0}:{1}' -f $message, (-join ($hash | ForEach-Object { $_.ToString('x2') }))
}

function Get-AcceptAnyCertCallback {
    # Windows PowerShell 5.1 runs the TLS handshake on another thread, where a
    # script-block callback fails ("no Runspace available"), so compile one.
    if (-not ('OkBoyAcceptAnyCert' -as [type])) {
        Add-Type -TypeDefinition @'
public static class OkBoyAcceptAnyCert {
    public static readonly System.Net.Security.RemoteCertificateValidationCallback Callback =
        delegate { return true; };
}
'@
    }
    [OkBoyAcceptAnyCert]::Callback
}

function ConvertFrom-JsonOrNull([string]$Text) {
    if (-not $Text) { return $null }
    try { $Text | ConvertFrom-Json } catch { $null }  # not JSON, e.g. an HTML error page from a proxy
}

function Invoke-OkBoy([hashtable]$Cfg, [string]$Action, [bool]$Verify) {
    $request = @{
        Uri              = $Cfg.server_url.TrimEnd('/') + "/api/$Action"
        Method           = $(if ($Action -eq 'knock') { 'Post' } else { 'Get' })
        Headers          = @{ Authorization = (Get-AuthHeader $Cfg.username $Cfg.secret) }
        ContentType      = 'application/json'
        TimeoutSec       = 15
        UseBasicParsing  = $true
        DisableKeepAlive = $true
    }
    $callback = [Net.ServicePointManager]::ServerCertificateValidationCallback
    if (-not $Verify) {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            $request.SkipCertificateCheck = $true
        } else {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = Get-AcceptAnyCertCallback
        }
    }
    try {
        $response = Invoke-RestMethod @request
        if ($response -is [string]) { throw 'Unexpected non-JSON response (wrong server URL?)' }
        $response
    } catch {
        # Non-2xx answers still carry the server's JSON {"ok": false, "error": "..."}.
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $body = ConvertFrom-JsonOrNull $_.ErrorDetails.Message
        $message = if ($body -and $body.error) { $body.error } else { $_.Exception.Message }
        if (-not $body -and $_.Exception.InnerException) { $message += " ($($_.Exception.InnerException.Message))" }
        if ($status) { $message = "HTTP ${status}: $message" }
        [pscustomobject]@{ ok = $false; error = $message }
    } finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $callback
    }
}

if (Test-Path -LiteralPath $Config -PathType Container) {
    $files = @(Get-ChildItem -LiteralPath $Config -Filter '*.yaml' -File | Sort-Object Name | ForEach-Object { $_.FullName })
    if (-not $files) { throw "No *.yaml config found in $Config" }
} else {
    $files = @($Config)
}

$failed = 0
foreach ($file in $files) {
    $server = $file
    try {
        $cfg = Read-KnockConfig $file
        $server = $cfg.server_url
        $verify = -not $Insecure -and $cfg.verify_ssl -notin 'false', '0', 'no', 'off'
        $result = Invoke-OkBoy $cfg $Action $verify
    } catch {
        $result = [pscustomobject]@{ ok = $false; error = $_.Exception.Message }
    }

    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    if (-not $result.ok) {
        $failed++
        "[$stamp] [FAIL] $server - $($result.error)"
    } elseif ($Action -eq 'status') {
        "[$stamp] [OK] $server"
        $result | ConvertTo-Json -Depth 5
    } else {
        $line = "[$stamp] [OK] $server $($result.ip) - $($result.message)"
        if ($result.warning) { $line += " (warning: $($result.warning))" }
        $line
    }
}

exit ([int]($failed -gt 0))
