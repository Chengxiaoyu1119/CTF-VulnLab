# VulnLab 原生单机部署

这套入口使用 Node.js 22+、Fastify 和 SQLite，内置 PHP、Node.js、Java、Python 四类 Provider，适合本地电脑或单台 Linux 云服务器。默认服务不依赖 Docker。主服务安装脚本会先在数据目录准备固定版本的项目内 Node.js，再用它构建和启动 VulnLab。

## Linux 单服务器

准备 Linux x86_64、systemd、`tar`、`curl` 或 `wget`、`sha256sum` 或 `shasum`、PHP 8.3（启用 `mysqli`、`pdo_mysql`）和可选的 Caddy。安装脚本会从 Node.js 官方源下载固定版本 Node.js 22.23.1；Java、Python、MariaDB 由项目按需准备。复制并填写配置：

```bash
cp operations/deploy/vulnlab/native/.env.example \
  operations/deploy/vulnlab/native/.env
```

至少修改管理员密码和 Cookie secret；如果启用外部 MySQL，再填写对应的数据库管理密码。Juice Shop 直接使用主服务的 Node.js。安装服务：

```bash
sudo bash operations/deploy/vulnlab/native/install.sh \
  operations/deploy/vulnlab/native/.env
```

通过域名或 Caddy 访问时，把 `VULNLAB_PUBLIC_URL` 填成完整的 HTTPS 地址，例如 `https://lab.example.com`，这样运行实例返回的入口会使用远程可访问地址。

服务安装到 `/opt/vulnlab/app`，数据位于 `/opt/vulnlab/data`，配置位于 `/etc/vulnlab/vulnlab.env`。安装过程会校验 Node.js 归档 SHA-256，执行项目内 `npm ci`、TypeScript 构建和生产依赖裁剪；服务单元直接调用项目内 Node.js。

首次启动对应靶场时，服务会按需准备固定版本 MariaDB、Eclipse Temurin JRE 和 Python standalone，执行 SHA-256 校验和受限解压，然后统一放在 `/opt/vulnlab/data/runtime`；项目内 Node.js 已由安装脚本准备好。MariaDB 只监听 `127.0.0.1`；运行时不会进入应用源码或 Git，下载失败时会保留原因。

原生 PHP 推荐配置：

```text
VULNLAB_PHP_BIN=/usr/bin/php
VULNLAB_RUNTIME_HOST=127.0.0.1
VULNLAB_RUNTIME_PORT_START=6800
VULNLAB_RUNTIME_PORT_END=6899
```

WebGoat 与 PyGoat 默认使用项目下载的 Java/Python；以下路径只在需要覆盖项目运行时时设置：

```text
VULNLAB_JAVA_BIN=/usr/bin/java
VULNLAB_PYTHON_BIN=/usr/bin/python3
```

默认项目内 MariaDB 已满足 DVWA、Pikachu、SQLi-Labs、XVWA、Mutillidae。已有独立数据库服务时，也可以用以下配置覆盖项目实例：

```text
VULNLAB_MYSQL_BIN=/usr/bin/mysql
VULNLAB_MYSQL_HOST=127.0.0.1
VULNLAB_MYSQL_PORT=3306
VULNLAB_MYSQL_ADMIN_USER=替换为 MySQL 管理账号
VULNLAB_MYSQL_ADMIN_PASSWORD=替换为真实密码
VULNLAB_MYSQL_APP_HOST=127.0.0.1
```

外部管理账号只用于创建和清理每实例数据库、账号及授权；靶场 PHP 进程使用 Provider 生成的独立应用账号。项目内 MariaDB 和外部连接不会同时启用。PHP 配置至少应启用 `mysqli`、`pdo_mysql` 和 `mbstring`。Windows 大小写不敏感文件系统上的路径冲突会在导入阶段被拒绝。

PHP 入口通过 VulnLab 的 `/lab-runtime/<实例 ID>/` 路径转发。Juice Shop、WebGoat、PyGoat 使用直接运行端口；远程访问时把 `VULNLAB_RUNTIME_HOST` 设置为服务器监听地址，并配置 `VULNLAB_RUNTIME_PUBLIC_ORIGIN=http://SERVER_IP:{port}`，只向可信来源开放 `6800-6899`。原生进程与 VulnLab 使用同一个系统账号，适合单用户或可信小团队。

XVWA 与 DVWA、Pikachu、SQLi-Labs、Mutillidae 一样由 `native-php` Provider 管理。每次启动创建独立 MySQL 资源和运行副本，初始化成功后从实例入口进入 `/xvwa/`，不依赖宿主机预先放置靶场源码。

## 本地运行

Windows：

```powershell
powershell -ExecutionPolicy Bypass -File script/run_vulnlab.ps1
```

Linux/macOS：

```bash
bash script/run_vulnlab.sh
```

打开 `http://127.0.0.1:6710/`，本地默认管理员账号为 `vulnlab / vulnlab`；生产服务使用 `.env` 中设置的 `VULNLAB_ADMIN_PASSWORD`。

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

当前定位是单机或可信小团队。Node.js、Java、Python 和 PHP 靶场使用独立运行副本与进程生命周期回收，但仍共享宿主操作系统账号；需要更强隔离时应在宿主机层增加独立用户或虚拟机边界。
