param(
    [string]$IPv4Address = '1.1.1.1',
    [int]$Port = 443,
    [string]$IPv6Address = '2606:4700:4700::1111',
    [string]$CurlUrl = 'https://example.com/'
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Administrator privileges are required. Start this PowerShell session elevated and rerun the script.'
    exit 1
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$buildDirectory = Join-Path $repoRoot 'build\Release'
$controller = Join-Path $buildDirectory 'WfpProcessSandbox.exe'
$client = Join-Path $buildDirectory 'WfpTestClient.exe'
if (-not (Test-Path -LiteralPath $controller -PathType Leaf) -or
    -not (Test-Path -LiteralPath $client -PathType Leaf)) {
    Write-Error "Build outputs not found under '$buildDirectory'. Configure and build the project first."
    exit 1
}

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $lines = & $Executable @Arguments 2>&1
    $code = $LASTEXITCODE
    foreach ($line in $lines) {
        Write-Host $line
    }
    return [pscustomobject]@{
        ExitCode = $code
        Output = ($lines -join "`n")
    }
}

Write-Host '=== Baseline IPv4 TCP ==='
$baseline4 = Invoke-CapturedCommand -Executable $client -Arguments @('tcp', $IPv4Address, [string]$Port)
if ($baseline4.Output -match 'CONNECT_SUCCESS') {
    Write-Host '=== Blocked IPv4 TCP ==='
    $null = Invoke-CapturedCommand -Executable $controller -Arguments @('run', '--app', $client, '--', 'tcp', $IPv4Address, [string]$Port)
} else {
    Write-Host 'SKIPPED: blocked IPv4 TCP was not classified because baseline connectivity failed (environment/network condition).'
}

Write-Host '=== Baseline IPv6 TCP ==='
$baseline6 = Invoke-CapturedCommand -Executable $client -Arguments @('tcp', $IPv6Address, [string]$Port)
if ($baseline6.Output -match 'CONNECT_SUCCESS') {
    Write-Host '=== Blocked IPv6 TCP ==='
    $null = Invoke-CapturedCommand -Executable $controller -Arguments @('run', '--app', $client, '--', 'tcp', $IPv6Address, [string]$Port)
} else {
    Write-Host 'SKIPPED: no usable external IPv6 connectivity'
}

Write-Host '=== IPv4 loopback with filter ==='
$null = Invoke-CapturedCommand -Executable $controller -Arguments @('run', '--app', $client, '--', 'loopback4')

Write-Host '=== IPv6 loopback with filter ==='
$null = Invoke-CapturedCommand -Executable $controller -Arguments @('run', '--app', $client, '--', 'loopback6')

Write-Host '=== Child-process escape (curl.exe is not the filter target) ==='
$null = Invoke-CapturedCommand -Executable $controller -Arguments @('run', '--app', $client, '--', 'spawn-curl', $CurlUrl)

Write-Host '=== Unrelated process check ==='
Write-Host 'Run curl.exe in a second terminal while this is active: WfpProcessSandbox.exe hold --app <full path to WfpTestClient.exe>'
