<#
.SYNOPSIS
    UFW OkBoy - Windows client (Windows PowerShell 5.1+ or PowerShell 7, no dependencies).

.DESCRIPTION
    Registers this machine's public IP with UFW OkBoy servers: the Windows
    counterpart of knock.py / knock.sh. Reads the same config format as
    knock.py (server_url / username / secret / pin_sha256 / verify_ssl, see
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

    # Skip TLS verification, like knock.py --no-verify-ssl. For a self-signed
    # server prefer pin_sha256 in its config (it then decides and this switch
    # is not used): without verification a man in the middle can replay a knock.
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

function Initialize-OkBoyPin {
    # pin_sha256 = base64(SHA-256(SubjectPublicKeyInfo)), checked in a compiled
    # validation callback (it runs on another thread, see above). Each request
    # gets its own OkBoyPinCheck, so nothing is shared between requests.
    if ('OkBoyPinCheck' -as [type]) { return }
    $source = @'
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public sealed class OkBoyPinCheck {
    readonly string expected;
    // The key the server presented, for the error message.
    public string Seen;

    public OkBoyPinCheck(string expected) { this.expected = expected; }

    public RemoteCertificateValidationCallback Callback { get { return Validate; } }

    bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        return Matches(cert);
    }

    public bool Matches(X509Certificate cert) {
        Seen = cert == null ? null : SpkiSha256(cert.GetRawCertData());
        return Seen != null && Seen == expected;
    }

    public static string SpkiSha256(byte[] der) {
        int pos = Value(der, 0);                            // Certificate -> tbsCertificate
        pos = Value(der, pos);                              // first field of tbsCertificate
        if (der[pos] == 0xA0) pos = Next(der, pos);         // [0] version (absent in v1)
        for (int i = 0; i < 5; i++) pos = Next(der, pos);   // serial, signature, issuer, validity, subject
        int end = Next(der, pos);                           // subjectPublicKeyInfo
        using (SHA256 sha = SHA256.Create()) {
            return Convert.ToBase64String(sha.ComputeHash(der, pos, end - pos));
        }
    }

    static int Value(byte[] der, int pos) { int len; return Header(der, pos, out len); }
    static int Next(byte[] der, int pos) { int len; int start = Header(der, pos, out len); return start + len; }
    static int Header(byte[] der, int pos, out int len) {
        len = der[pos + 1];
        pos += 2;
        if ((len & 0x80) != 0) {
            int size = len & 0x7F;
            len = 0;
            for (int i = 0; i < size; i++) len = (len << 8) | der[pos++];
        }
        if (len < 0 || pos + len > der.Length) throw new FormatException("truncated certificate");
        return pos;
    }
}
'@
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $source += @'

public static class OkBoyPinHttp {
    public static Func<System.Net.Http.HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> Callback(OkBoyPinCheck check) {
        return (request, cert, chain, errors) => check.Matches(cert);
    }
}
'@
    } else {
        Add-Type -AssemblyName System.Net.Http, System.Net.Http.WebRequest
    }
    Add-Type -TypeDefinition $source
}

function Invoke-OkBoyPinned([hashtable]$Cfg, [string]$Action, [string]$Pin) {
    # The server key is checked on the connection that then carries the request,
    # before anything is sent. HttpClient gives each handler its own connections
    # and callback: WebRequestHandler under Windows PowerShell, HttpClientHandler
    # under PowerShell 7 (whose Invoke-RestMethod cannot check a key).
    $uri = [Uri]($Cfg.server_url.TrimEnd('/') + "/api/$Action")
    if ($uri.Scheme -ne 'https') { throw 'pin_sha256 needs an https:// server_url' }
    Initialize-OkBoyPin
    $check = [OkBoyPinCheck]::new($Pin)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.ServerCertificateCustomValidationCallback = [OkBoyPinHttp]::Callback($check)
    } else {
        $handler = [Net.Http.WebRequestHandler]::new()
        $handler.ServerCertificateValidationCallback = $check.Callback
    }
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(15)
    try {
        $method = if ($Action -eq 'knock') { [Net.Http.HttpMethod]::Post } else { [Net.Http.HttpMethod]::Get }
        $request = [Net.Http.HttpRequestMessage]::new($method, $uri)
        [void]$request.Headers.TryAddWithoutValidation('Authorization', (Get-AuthHeader $Cfg.username $Cfg.secret))
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $body = ConvertFrom-JsonOrNull $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ($response.IsSuccessStatusCode -and $body) { return $body }
        $message = if ($body -and $body.error) { $body.error } else { 'Unexpected non-JSON response (wrong server URL?)' }
        [pscustomobject]@{ ok = $false; error = "HTTP $([int]$response.StatusCode): $message" }
    } catch {
        if ($check.Seen -and $check.Seen -ne $Pin) {
            $message = "Server public key does not match pin_sha256 (the server presented $($check.Seen)); nothing was sent"
        } else {
            $e = $_.Exception
            while ($e.InnerException) { $e = $e.InnerException }
            $message = $e.Message
        }
        [pscustomobject]@{ ok = $false; error = $message }
    } finally {
        $client.Dispose()
    }
}

function ConvertFrom-JsonOrNull([string]$Text) {
    if (-not $Text) { return $null }
    try { $Text | ConvertFrom-Json } catch { $null }  # not JSON, e.g. an HTML error page from a proxy
}

function Invoke-OkBoy([hashtable]$Cfg, [string]$Action, [bool]$Verify, [string]$Pin) {
    if ($Pin) { return Invoke-OkBoyPinned $Cfg $Action $Pin }
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
        $pin = "$($cfg.pin_sha256)".Trim()
        if ($pin -and $pin -cnotmatch '^[A-Za-z0-9+/]{43}=$') {
            throw "'pin_sha256' must be the base64 SHA-256 of the server's public key (44 characters ending in '=')"
        }
        $verify = -not $Insecure -and $cfg.verify_ssl -notin 'false', '0', 'no', 'off'
        $result = Invoke-OkBoy $cfg $Action $verify $pin
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
