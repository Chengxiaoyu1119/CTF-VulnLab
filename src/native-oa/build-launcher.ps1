$ErrorActionPreference = 'Stop'

$appRoot = Split-Path -Parent $PSScriptRoot
$source = Join-Path $PSScriptRoot 'appcontainer-launcher.cs'
$outputDir = Join-Path $appRoot 'assets\native-oa'
$output = Join-Path $outputDir 'appcontainer-launcher-sandbox.exe'
$contract = Join-Path $appRoot 'oa\sandbox.ts'
$compilerPaths = @(
  (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
  (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$compiler = $compilerPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $compiler) { throw 'Windows .NET Framework C# compiler was not found.' }

New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
& $compiler /nologo /target:exe /optimize+ "/out:$output" /reference:System.dll /reference:System.Core.dll /reference:System.Security.dll $source
if ($LASTEXITCODE -ne 0) { throw "AppContainer launcher compilation failed: $LASTEXITCODE" }

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hash = ([System.BitConverter]::ToString($sha256.ComputeHash([System.IO.File]::ReadAllBytes($output)))).Replace('-', '').ToLowerInvariant()
$sha256.Dispose()
$content = [System.IO.File]::ReadAllText($contract)
$pattern = "(?<=OA_LAUNCHER_SHA256 = ')[0-9a-f]{64}(?=')"
if (-not [System.Text.RegularExpressions.Regex]::IsMatch($content, $pattern)) { throw 'OA launcher SHA-256 constant is invalid.' }
$content = [System.Text.RegularExpressions.Regex]::Replace($content, $pattern, $hash)
$encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
[System.IO.File]::WriteAllText($contract, $content, $encoding)
Write-Output "OA AppContainer launcher SHA-256: $hash"
