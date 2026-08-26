# VulnLab Node 应用

这是 VulnLab 0.3.0 的 Node.js / TypeScript 单机应用入口。

## 模块边界

- `server.ts`：Fastify 服务、认证、API、运行入口与静态资源。
- `db.ts`：SQLite schema、内置靶场、安装任务、实例、设置与审计。
- `builtin-assets.ts`：Juice Shop、WebGoat 官方发行包下载、校验和安全解包。
- `importer.ts`：GitHub / GitLab 固定版本下载、归档哈希、路径检查和清单生成。
- `providers.ts`：`native-php`、`native-node`、`native-java`、`native-python`、`qemu-vm` 生命周期。
- `runtime-prep.ts`：PyGoat 私有 Python 环境与依赖准备。
- `runtime-status.ts`：PHP、mysqli、MySQL、Node.js、Java、Python、QEMU 检测和按靶场启动条件。
- `runtime-toolchains.ts`：按平台选择官方 Node.js、PHP、MariaDB、Java、Python 包，执行限量下载、SHA-256、安全解压、原子安装和清单复用。
- `project-environment.ts`：项目内 PHP 配置、私有 MariaDB/MySQL 初始化、启动与回收；外部配置可覆盖。
- `mysql.ts`：每实例数据库与应用账号的创建、验证和清理。
- `vulnhub.ts`、`vm-download.ts`：VulnHub 机器目录、镜像下载、磁盘检查和校验。
- `seed.ts`：九个固定靶场的版本、Provider 与自动安装策略。
- `public/`：原生 JavaScript / CSS 工作台；所有页面共用运行状态区和顶部导航。
- `data/`：SQLite、下载资源、靶场源码、Python 环境与运行副本；整个目录被 Git 忽略。

## 开发

```powershell
npm ci
npm run check
npm test
npm run dev
```

默认地址是 `http://127.0.0.1:6710`。`VULNLAB_HOST`、`VULNLAB_PORT` 和 `VULNLAB_DATA_DIR` 可以覆盖服务参数。

## 安装模型

`seed.ts` 保存九个项目的固定版本声明，管理员从页面按需安装时，安装器把资源下载到 `data/labs/<slug>/<version>`，同时生成 `vulnlab.manifest.json`。安装过程限制下载与解压体积，检查路径穿越、Windows 不可移植路径和归档完整性，并在任务结束后清理下载缓存。设置 `VULNLAB_AUTO_INSTALL_BUILTINS=1` 可以批量准备全部内置靶场。

Juice Shop 使用官方预构建发行包；WebGoat 使用适配 Java 17/21 的 2023.8 JAR；PyGoat 安装后创建 `.vulnlab-venv`，运行副本复用该环境并在启动前执行 Django migration。

## 运行模型

每个 Lab 通过自己的 `providerId` 自动选择运行实现。

- PHP：复制独立运行目录，按需创建 MySQL 资源，启动 PHP 内置服务器。
- Node.js：复制可变文件并链接只读依赖目录，减少 Juice Shop 启动复制量。
- Java：为 WebGoat 与 WebWolf 分配两个端口，并把数据目录限制在实例副本。
- Python：复制源码、复用项目私有解释器、迁移 SQLite 后启动 Django。
- QEMU：校验镜像后使用临时快照和端口转发启动。

进程状态写入运行目录；正常停止、过期回收、服务关闭和服务重启都执行资源回收。实例 API 在调用 Provider 前执行依赖检查，缺失项以 `RUNTIME_DEPENDENCY_MISSING` 返回。

服务运行后，`npm run smoke:runtimes` 会依次启动 Upload-Labs、Juice Shop、WebGoat 和 PyGoat，检查真实页面后停止实例。

## 项目运行环境

启动时，VulnLab 会在 `data/runtime/` 创建运行状态。管理员点击环境页的“下载并准备环境”后，Windows x64 会下载 Node.js 22.23.1、PHP 8.3.33 NTS、MariaDB 11.4.10、Eclipse Temurin JRE 21.0.12.1 和 Python 3.11.16；Linux x64 下载 Node.js、MariaDB、Java 和 Python。下载文件必须匹配仓库固定的 SHA-256，解压路径和体积受限，安装通过临时目录原子切换；成功后压缩包立即清理。

运行时目录结构为 `toolchains/`、`manifests/`、`downloads/`、`php/` 和 `mysql/`。PHP 使用项目生成的 `php.ini`；Windows 会启用发行包内存在的 `mysqli`、`pdo_mysql`、`mbstring`、`gd`、`curl`、`openssl` 扩展。MariaDB 只绑定 `127.0.0.1`，默认端口 `7330`，数据、日志、PID 和随机管理凭据均留在项目数据目录，服务关闭时回收进程。

运行时二进制不提交进 Git。已下载的项目包优先级高于系统 `PATH`；显式环境变量和外部 MySQL 连接仍可覆盖。Juice Shop 使用项目 Node.js，PyGoat 直接用项目 Python 创建 `venv`，WebGoat 直接用项目 JRE 启动。环境页显示平台、版本、来源、官方源入口、SHA-256 结果、磁盘占用和失败原因。

## 外部 MySQL 配置

DVWA、Pikachu、SQLi-Labs 和 Mutillidae 需要 PHP `mysqli` 与 MySQL / MariaDB：

```text
VULNLAB_MYSQL_HOST
VULNLAB_MYSQL_PORT
VULNLAB_MYSQL_ADMIN_USER
VULNLAB_MYSQL_ADMIN_PASSWORD
VULNLAB_MYSQL_APP_HOST
VULNLAB_MYSQL_BIN
```

设置 `VULNLAB_MYSQL_ADMIN_USER` 后，外部 MySQL 配置优先于项目内实例。启动时创建确定性数据库名、随机应用密码和最小权限账号。管理密码只通过 `MYSQL_PWD` 传给 MySQL 客户端，不进入靶场进程环境。

项目内实例端口可以通过 `VULNLAB_PROJECT_MYSQL_PORT` 调整；需要手动指定服务端二进制时使用 `VULNLAB_MYSQLD_BIN`。这两个设置只影响项目运行目录，不会修改系统 MySQL 服务。

真实运行时链路回归：

```powershell
npm run build
npm run smoke:toolchains
```

该回归在全新临时目录完成“官方下载 → SHA-256 → 安全解压 → Node.js → PHP mysqli → MariaDB 连接 → Java 启动 → Python venv/pip → 停止回收”，随后删除临时目录。`npm test` 另外覆盖 Linux TAR.XZ 解压 fixture 和原生 systemd 部署文件契约。

## 生产配置

生产环境必须显式设置管理员密码和至少 32 字符的 `VULNLAB_COOKIE_SECRET`。VulnLab 只保留一个最高权限管理员账号，会话保存在 SQLite；Cookie 使用签名 HttpOnly，写操作要求 CSRF token，登录失败有持久化速率限制。

部署说明见 [`operations/deploy/vulnlab/native/README.zh-CN.md`](../../operations/deploy/vulnlab/native/README.zh-CN.md)。
