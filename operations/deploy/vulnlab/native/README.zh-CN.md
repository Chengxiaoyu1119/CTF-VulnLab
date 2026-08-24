# VulnLab 原生单机部署

这套入口使用 Node.js 22+、Fastify 和 SQLite，内置 PHP、Node.js、Java、Python、QEMU 五类 Provider，适合本地电脑或单台 Linux 云服务器。默认服务不依赖 Docker。

## Linux 单服务器

准备 Node.js 22+、npm、systemd 和可选的 Caddy。复制并填写配置：

```bash
cp operations/deploy/vulnlab/native/.env.example \
  operations/deploy/vulnlab/native/.env
```

至少修改两个密码和 Cookie secret。按需要安装 PHP、MySQL/MariaDB、Java、Python 或 QEMU；Juice Shop 直接使用主服务的 Node.js。DVWA、Pikachu、SQLi-Labs、Mutillidae 需要 PHP `mysqli` 和可通过 TCP 访问的 MySQL 管理账号，然后安装：

```bash
sudo bash operations/deploy/vulnlab/native/install.sh \
  operations/deploy/vulnlab/native/.env
```

通过域名或 Caddy 访问时，把 `VULNLAB_PUBLIC_URL` 填成完整的 HTTPS 地址，例如 `https://lab.example.com`，这样运行实例返回的入口会使用远程可访问地址。

服务安装到 `/opt/vulnlab/app`，数据位于 `/opt/vulnlab/data`，配置位于 `/etc/vulnlab/vulnlab.env`。安装过程会执行 `npm ci`、TypeScript 构建和生产依赖裁剪。

原生 PHP 推荐配置：

```text
VULNLAB_PHP_BIN=/usr/bin/php
VULNLAB_RUNTIME_HOST=127.0.0.1
VULNLAB_RUNTIME_PORT_START=6800
VULNLAB_RUNTIME_PORT_END=6899
```

WebGoat 与 PyGoat 使用以下可选路径，未配置时从系统 `PATH` 查找：

```text
VULNLAB_JAVA_BIN=/usr/bin/java
VULNLAB_PYTHON_BIN=/usr/bin/python3
```

DVWA、Pikachu、SQLi-Labs、Mutillidae 的 MySQL 配置示例：

```text
VULNLAB_MYSQL_BIN=/usr/bin/mysql
VULNLAB_MYSQL_HOST=127.0.0.1
VULNLAB_MYSQL_PORT=3306
VULNLAB_MYSQL_ADMIN_USER=vulnlab-admin
VULNLAB_MYSQL_ADMIN_PASSWORD=替换为真实密码
VULNLAB_MYSQL_APP_HOST=127.0.0.1
```

管理账号只用于创建和清理每实例数据库、账号及授权；靶场 PHP 进程使用 Provider 生成的独立应用账号。PHP 配置至少应启用 `mysqli`、`pdo_mysql` 和 `mbstring`。Windows 大小写不敏感文件系统上的路径冲突会在导入阶段被拒绝。

PHP 与 QEMU 入口通过 VulnLab 的 `/lab-runtime/<实例 ID>/` 路径转发。Juice Shop、WebGoat、PyGoat 使用直接运行端口；远程访问时把 `VULNLAB_RUNTIME_HOST` 设置为服务器监听地址，并配置 `VULNLAB_RUNTIME_PUBLIC_ORIGIN=http://SERVER_IP:{port}`，只向可信来源开放 `6800-6899`。原生进程与 VulnLab 使用同一个系统账号，适合单用户或可信小团队；需要更强操作系统隔离时优先选择 QEMU。

VulnHub 镜像默认最多下载 20 GiB，可在环境文件中用 `VULNLAB_VM_MAX_BYTES` 调整到 1 MiB–100 GiB。下载只由管理员在页面中显式触发。安装 `qemu-system-x86_64` 后，机器详情可启动已校验的 OVA（自动提取 VMDK）、qcow2、raw/img、vdi 或 vmdk；单独的 OVF 仍需要配套磁盘。Provider 由靶场自动选择。

QEMU 相关配置：

```text
VULNLAB_QEMU_BIN=/usr/bin/qemu-system-x86_64
VULNLAB_VM_PORT_START=6900
VULNLAB_VM_PORT_END=6999
VULNLAB_VM_GUEST_PORT=80
VULNLAB_VM_MEMORY_MB=2048
VULNLAB_VM_CPUS=2
VULNLAB_VM_BOOT_TIMEOUT_MS=120000
```

## 本地运行

Windows：

```powershell
powershell -ExecutionPolicy Bypass -File script/run_vulnlab.ps1
```

Linux/macOS：

```bash
bash script/run_vulnlab.sh
```

打开 `http://127.0.0.1:6710/`，开发账号为 `vulnlab-admin / VulnLabAdmin123!`。

## 备份和恢复

停止服务后备份：

```bash
sudo systemctl stop vulnlab
bash operations/deploy/vulnlab/native/backup.sh
sudo systemctl start vulnlab
```

恢复前先停止服务，脚本要求显式传入 `--yes`：

```bash
sudo systemctl stop vulnlab
bash operations/deploy/vulnlab/native/restore.sh \
  --yes operations/deploy/backups/vulnlab-native/ARCHIVE.tar.gz
sudo systemctl start vulnlab
```

## 当前边界

当前定位是单机或可信小团队。Node.js、Java、Python 和 PHP 靶场使用独立运行副本与进程生命周期回收，但仍共享宿主操作系统账号；VulnHub 使用 QEMU 临时快照。不同 VulnHub 机器的架构和服务端口仍需逐台验证。
