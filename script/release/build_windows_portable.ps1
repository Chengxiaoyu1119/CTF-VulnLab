$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$src = Join-Path $root 'src'
$releaseScript = Join-Path $root 'script\run_vulnlab.ps1'
$launcherSource = Join-Path $PSScriptRoot 'launcher.cs'
$releaseNotes = Join-Path $PSScriptRoot 'RELEASE_NOTES.zh-CN.md'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$output = Join-Path $root 'output\release'
$zipPath = Join-Path $output 'CTF-VulnLab.zip'
$hashPath = Join-Path $output 'CTF-VulnLab.zip.sha256'
$tempRoot = Join-Path $env:TEMP "CTF-VulnLab-release-$([guid]::NewGuid().ToString('N'))"
$stageRoot = Join-Path $tempRoot 'stage'
$packageRoot = Join-Path $stageRoot 'CTF-VulnLab'
$appStage = Join-Path $packageRoot 'app'
$nodeStage = Join-Path $packageRoot 'node'
$temporaryZip = Join-Path $output 'CTF-VulnLab.tmp.zip'
$oldPath = $env:PATH

try {
  if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw '未找到 Windows .NET Framework C# 编译器。' }
  if (-not (Test-Path -LiteralPath (Join-Path $src 'package-lock.json') -PathType Leaf)) { throw 'src/package-lock.json 不存在。' }
  if (-not (Test-Path -LiteralPath $releaseNotes -PathType Leaf)) { throw '中文发行说明文件不存在。' }

  $runScriptText = Get-Content -LiteralPath $releaseScript -Raw
  $versionMatch = [regex]::Match($runScriptText, '\$version\s*=\s*''([^'']+)''')
  if (-not $versionMatch.Success) { throw '无法从 script/run_vulnlab.ps1 读取 Node.js 固定版本。' }
  $nodeVersion = $versionMatch.Groups[1].Value
  $hashMatch = [regex]::Match($runScriptText, '\$sha256\s*=\s*''([a-f0-9]{64})''')
  if (-not $hashMatch.Success) { throw '无法从启动脚本读取 Node.js SHA-256。' }
  $nodeSha256 = $hashMatch.Groups[1].Value
  $nodeRoot = Join-Path $src "data\runtime\toolchains\node\$nodeVersion\win32-x64"
  $manifestPath = Join-Path $src "data\runtime\manifests\node-$nodeVersion-win32-x64.json"
  $nodeSource = $null

  if ((Test-Path -LiteralPath (Join-Path $nodeRoot 'node.exe') -PathType Leaf) -and
      (Test-Path -LiteralPath (Join-Path $nodeRoot 'npm.cmd') -PathType Leaf) -and
      (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $nodeOutput = (& (Join-Path $nodeRoot 'node.exe') --version | Out-String).Trim()
    if ($manifest.version -eq $nodeVersion -and $manifest.platform -eq 'win32' -and $manifest.arch -eq 'x64' -and
        $manifest.archiveSha256 -eq $nodeSha256 -and $nodeOutput -eq "v$nodeVersion") {
      $nodeSource = $nodeRoot
    }
  }

  New-Item -ItemType Directory -Force -Path $output, $tempRoot, $stageRoot, $packageRoot, $appStage, $nodeStage | Out-Null
  if (-not $nodeSource) {
    $nodeArchive = Join-Path $tempRoot "node-v$nodeVersion-win-x64.zip"
    $nodeExtract = Join-Path $tempRoot 'node-extracted'
    New-Item -ItemType Directory -Force -Path $nodeExtract | Out-Null
    $nodeUrl = "https://nodejs.org/dist/v$nodeVersion/node-v$nodeVersion-win-x64.zip"
    Invoke-WebRequest -UseBasicParsing -Uri $nodeUrl -OutFile $nodeArchive
    $downloadHash = (Get-FileHash -LiteralPath $nodeArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($downloadHash -ne $nodeSha256) { throw 'Node.js 官方压缩包 SHA-256 校验失败。' }
    Expand-Archive -LiteralPath $nodeArchive -DestinationPath $nodeExtract
    $nodeSource = Join-Path $nodeExtract "node-v$nodeVersion-win-x64"
  }

  $nodeBinary = Join-Path $nodeSource 'node.exe'
  $npmBinary = Join-Path $nodeSource 'npm.cmd'
  if (-not (Test-Path -LiteralPath $nodeBinary -PathType Leaf) -or -not (Test-Path -LiteralPath $npmBinary -PathType Leaf)) { throw 'Node.js 发行目录缺少 node.exe 或 npm.cmd。' }
  $env:PATH = "$nodeSource;$oldPath"
  $nodeOutput = (& $nodeBinary --version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $nodeOutput -ne "v$nodeVersion") { throw "Node.js 版本不匹配：$nodeOutput" }

  Write-Host '构建 TypeScript 应用……'
  & $npmBinary --prefix $src run build
  if ($LASTEXITCODE -ne 0) { throw "TypeScript 构建失败（退出码 $LASTEXITCODE）。" }

  foreach ($name in @('dist', 'public', 'assets')) {
    $source = Join-Path $src $name
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw "发行输入目录不存在：src/$name" }
    Copy-Item -LiteralPath $source -Destination $appStage -Recurse -Force
  }
  Copy-Item -LiteralPath (Join-Path $src 'package.json') -Destination $appStage -Force
  Copy-Item -LiteralPath (Join-Path $src 'package-lock.json') -Destination $appStage -Force
  Copy-Item -LiteralPath $releaseNotes -Destination (Join-Path $packageRoot '发行说明.md') -Force
  foreach ($file in @('node.exe', 'LICENSE')) {
    $source = Join-Path $nodeSource $file
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Node.js 发行目录缺少 $file。" }
    Copy-Item -LiteralPath $source -Destination $nodeStage -Force
  }

  Write-Host '按锁文件安装生产依赖……'
  & $npmBinary --prefix $appStage ci --omit=dev --no-audit --no-fund
  if ($LASTEXITCODE -ne 0) { throw "生产依赖安装失败（退出码 $LASTEXITCODE）。" }

  Write-Host '编译 Windows 启动器……'
  $launcher = Join-Path $packageRoot 'CTF-VulnLab.exe'
  & $compiler /nologo /target:exe "/out:$launcher" $launcherSource
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw 'CTF-VulnLab.exe 编译失败。' }

  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  if (Test-Path -LiteralPath $temporaryZip) { Remove-Item -LiteralPath $temporaryZip -Force }
  $links = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force -Attributes ReparsePoint)
  if ($links.Count) { throw '发行目录包含重解析点，停止打包以避免写入目录外文件。' }
  $zipStream = [System.IO.File]::Open($temporaryZip, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  $zipArchive = [System.IO.Compression.ZipArchive]::new($zipStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
  try {
    $files = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File -Force)
    foreach ($file in $files) {
      $relativePath = $file.FullName.Substring($packageRoot.Length + 1).Replace('\', '/')
      $entry = $zipArchive.CreateEntry("CTF-VulnLab/$relativePath", [System.IO.Compression.CompressionLevel]::Optimal)
      $sourceStream = [System.IO.File]::OpenRead($file.FullName)
      $entryStream = $entry.Open()
      try { $sourceStream.CopyTo($entryStream) }
      finally { $entryStream.Dispose(); $sourceStream.Dispose() }
    }
  }
  finally { $zipArchive.Dispose(); $zipStream.Dispose() }
  $archive = [System.IO.Compression.ZipFile]::OpenRead($temporaryZip)
  try {
    $entries = @($archive.Entries | ForEach-Object { $_.FullName })
    $required = @('CTF-VulnLab/CTF-VulnLab.exe', 'CTF-VulnLab/发行说明.md', 'CTF-VulnLab/node/node.exe', 'CTF-VulnLab/node/LICENSE', 'CTF-VulnLab/app/dist/server.js', 'CTF-VulnLab/app/public/index.html', 'CTF-VulnLab/app/assets/labs/oa-vuln-labs/1.0.0-beta/source.zip')
    $entryExamples = ($entries | Select-Object -First 8) -join ', '
    if ($entries | Where-Object { $_.Contains('\') }) { throw 'ZIP 内路径必须使用标准正斜杠。' }
    foreach ($path in $required) { if ($entries -notcontains $path) { throw "ZIP 缺少必要文件：$path；归档首项：$entryExamples" } }
    if ($entries | Where-Object { $_ -match '^CTF-VulnLab/(data/|app/data/|app/\.env($|\.)|app/[^/]+\.sqlite($|[-.]))' }) { throw '发行 ZIP 意外包含项目运行数据或根级环境配置文件。' }
  }
  finally { $archive.Dispose() }

  Move-Item -LiteralPath $temporaryZip -Destination $zipPath -Force
  $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
  [System.IO.File]::WriteAllText($hashPath, "$hash  CTF-VulnLab.zip`n", [System.Text.UTF8Encoding]::new($false))
  $zipSize = (Get-Item -LiteralPath $zipPath).Length
  $finalArchive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
  try { $uncompressedSize = ($finalArchive.Entries | Measure-Object -Property Length -Sum).Sum }
  finally { $finalArchive.Dispose() }
  Write-Host "发行包：$zipPath"
  Write-Host ('ZIP 大小：{0:N2} MiB；解压后：{1:N2} MiB' -f ($zipSize / 1MB), ($uncompressedSize / 1MB))
  Write-Host "SHA-256：$hash"
  Write-Host "校验文件：$hashPath"
}
finally {
  $env:PATH = $oldPath
  Remove-Item -LiteralPath $temporaryZip -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
