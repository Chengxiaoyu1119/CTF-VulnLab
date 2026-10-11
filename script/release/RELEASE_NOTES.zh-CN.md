# CTF-VulnLab Windows 便携版

## 发行包

- 文件名：`CTF-VulnLab.zip`
- 平台：Windows 10/11 x64；启动器依赖系统 .NET Framework 4.x
- 形式：解压即用，无需安装 Node.js、npm 或项目源码
- 内容：VulnLab 服务、生产依赖、固定靶场资源、Node.js 运行时和 `CTF-VulnLab.exe` 启动器

## 启动

1. 将 ZIP 解压到有写入权限的目录。
2. 双击 `CTF-VulnLab\CTF-VulnLab.exe`。
3. 启动器等待本地服务就绪后打开浏览器；默认地址为 `http://127.0.0.1:6710/`。如果该端口已被其他程序占用，启动器会选择可用端口并显示实际地址。
4. 使用默认工作台账号 `vulnlab`、密码 `vulnlab` 登录。
5. 在控制台窗口按 `Enter` 或 `Ctrl+C` 正常关闭服务并回收运行资源。

## 运行条件

- 基础服务和内置固定资源已放入 ZIP。
- 各靶场的运行时及上游资源按需准备并进行哈希校验；首次使用相应靶场通常需要网络连接。
- OA-Vuln-Labs 的 Docker 原版模式需要另外安装并启动 Docker Engine；本 ZIP 不包含 Docker。
- 服务默认只监听本机回环地址，不作为公网部署包使用。

## 数据与更新

数据库、账号、导入内容、下载缓存、已准备的运行时和日志保存在 `%LOCALAPPDATA%\CTF-VulnLab\data`。程序目录可单独替换或删除；保留用户数据时，更新前不要删除上述数据目录。可通过已有环境变量 `VULNLAB_DATA_DIR` 指定其他数据位置。

## 校验

发行目录旁提供 `CTF-VulnLab.zip.sha256`。可在 PowerShell 中运行：

```powershell
Get-FileHash .\CTF-VulnLab.zip -Algorithm SHA256
```
