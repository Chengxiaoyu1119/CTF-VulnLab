# VulnLab 原生单机部署

这套入口使用 Node.js 22+、Fastify、SQLite 和 `simulated` Provider，已额外支持需要 PHP CLI 的 `native-php` Provider；配置 MySQL 后可以运行 DVWA、Pikachu 和 SQLi-Labs，适合本地电脑或单台 Linux 云服务器。默认服务不依赖 Docker。

## Linux 单服务器

准备 Node.js 22+、npm、systemd 和可选的 Caddy。复制并填写配置：

```bash
cp operations/deploy/vulnlab/native/.env.example \
  operations/deploy/vulnlab/native/.env
```

至少修改两个密码和 Cookie secret；如果要运行 Upload-Labs、DVWA、Pikachu 或 SQLi-Labs，还要安装 PHP CLI 和对应扩展。DVWA/Pikachu/SQLi-Labs 还需要一个可通过 TCP 访问的 MySQL 管理账号，然后安装：

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

DVWA/Pikachu/SQLi-Labs 的 MySQL 配置示例：

```text
VULNLAB_MYSQL_BIN=/usr/bin/mysql
VULNLAB_MYSQL_HOST=127.0.0.1
VULNLAB_MYSQL_PORT=3306
VULNLAB_MYSQL_ADMIN_USER=vulnlab-admin
VULNLAB_MYSQL_ADMIN_PASSWORD=替换为真实密码
VULNLAB_MYSQL_APP_HOST=127.0.0.1
```

管理账号只用于创建和清理每实例数据库、账号及授权；靶场 PHP 进程使用 Provider 生成的独立应用账号。PHP 配置至少应启用 `mysqli`、`pdo_mysql` 和 `mbstring`。Windows 大小写不敏感文件系统上的路径冲突会在导入阶段被拒绝。

如果前面使用 HTTPS 反向代理，靶场入口通过 VulnLab 的同源 `/lab-runtime/<实例 ID>/` 路径转发，不需要把 PHP 端口直接暴露到公网。`native-php` 进程与 VulnLab 使用同一个系统账号，适合单用户或可信小团队的学习机；需要更强隔离时，应等容器或虚拟机 Provider 接入后再对公网开放。

VulnHub 镜像默认最多下载 20 GiB，可在环境文件中用 `VULNLAB_VM_MAX_BYTES` 调整到 1 MiB–100 GiB。下载只由管理员在页面中显式触发，服务会把任务和校验结果写入数据目录。需要运行时，将页面 Provider 设置为 `qemu-vm`，安装 `qemu-system-x86_64`，然后在机器详情中启动已完成校验的 OVA（自动提取 VMDK）、qcow2、raw/img、vdi 或 vmdk 镜像；单独的 OVF 文件仍需要配套磁盘。QEMU 使用用户态网络，宿主端口只绑定回环地址，再由 VulnLab 同源代理转发。

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

当前 `simulated` Provider 负责框架预览；`native-php` Provider 已验证 Upload-Labs 的导入、首页、Pass-01 上传页、续期、结束和服务关闭回收，也已验证 DVWA/Pikachu/SQLi-Labs 的 PHP + MySQL 初始化和实例清理回归；`qemu-vm` Provider 已接入 QEMU 命令构造、回环端口转发、启动探测、续期、结束和服务恢复边界，真实启动仍需目标主机安装 QEMU、准备可启动镜像并按机器实际服务端口配置。GitHub、GitLab 和 VulnHub 来源适配器已接入；真实容器运行时、更强隔离和集群调度属于后续 Provider 范围。
