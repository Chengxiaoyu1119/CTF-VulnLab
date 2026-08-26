$ErrorActionPreference = 'Stop'

$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$app = Join-Path $root 'src\VulnLab'
$runtime = Join-Path $app 'data\runtime'
$version = '22.23.1'
$platform = 'win32-x64'
$sourceUrl = "https://nodejs.org/dist/v$version/node-v$version-win-x64.zip"
$sha256 = '7df0bc9375723f4a86b3aa1b7cc73342423d9677a8df4538aca31a049e309c29'
$nodeRoot = Join-Path $runtime "toolchains\node\$version\$platform"
$nodeBinary = Join-Path $nodeRoot 'node.exe'
$npmBinary = Join-Path $nodeRoot 'npm.cmd'
$manifestPath = Join-Path $runtime "manifests\node-$version-win32-x64.json"

function Test-ProjectNode {
  if (-not (Test-Path -LiteralPath $nodeBinary -PathType Leaf) -or -not (Test-Path -LiteralPath $npmBinary -PathType Leaf) -or -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return $false }
  try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    return $manifest.id -eq 'node' -and $manifest.version -eq $version -and $manifest.platform -eq 'win32' -and $manifest.arch -eq 'x64' -and $manifest.archiveSha256 -eq $sha256
  } catch {
    return $false
  }
}

function Install-ProjectNode {
  $nodeParent = Split-Path -Parent $nodeRoot
  $staging = Join-Path $nodeParent ".staging-node-$([guid]::NewGuid().ToString('N'))"
  $archive = Join-Path ([System.IO.Path]::GetTempPath()) "vulnlab-node-$([guid]::NewGuid().ToString('N')).zip"
  try {
    New-Item -ItemType Directory -Force -Path $nodeParent, (Split-Path -Parent $manifestPath), $staging | Out-Null
    Invoke-WebRequest -UseBasicParsing -Uri $sourceUrl -OutFile $archive
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $sha256) { throw 'Node.js 下载校验失败，安装已停止。' }
    Expand-Archive -LiteralPath $archive -DestinationPath $staging -Force
    $payload = Join-Path $staging "node-v$version-win-x64"
    if (-not (Test-Path -LiteralPath (Join-Path $payload 'node.exe') -PathType Leaf) -or -not (Test-Path -LiteralPath (Join-Path $payload 'npm.cmd') -PathType Leaf)) { throw 'Node.js 发行包缺少启动文件。' }
    if (Test-Path -LiteralPath $nodeRoot) { Remove-Item -LiteralPath $nodeRoot -Recurse -Force }
    Move-Item -LiteralPath $payload -Destination $nodeRoot
    [ordered]@{
      id = 'node'; version = $version; platform = 'win32'; arch = 'x64'; sourceUrl = $sourceUrl
      archiveSha256 = $sha256; installedPath = $nodeRoot; installedBytes = 0; fileCount = 0
      executables = [ordered]@{ node = 'node.exe' }; installedAt = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding utf8
  } finally {
    Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
  }
}

if (-not (Test-ProjectNode)) { Install-ProjectNode }
if (-not (Test-Path -LiteralPath $nodeBinary -PathType Leaf) -or -not (Test-Path -LiteralPath $npmBinary -PathType Leaf)) { throw '项目内 Node.js 准备失败。' }
if (-not (Test-Path -LiteralPath (Join-Path $app 'node_modules') -PathType Container)) {
  & $npmBinary --prefix $app ci
  if ($LASTEXITCODE -ne 0) { throw "依赖安装失败（退出码 $LASTEXITCODE）。" }
}
& $npmBinary --prefix $app run dev
exit $LASTEXITCODE
