<!-- markdownlint-disable MD013 MD033 MD041 -->

<div align="center">
  <img src="src/VulnLab/public/favicon.svg" width="88" alt="VulnLab Logo">
  <h1>VulnLab</h1>
  <p><strong>把主流开源靶场装进一个真正可启动的单机工作台。</strong></p>
  <p>固定版本资源 · 一键启动 · 原生进程运行 · 生命周期管理 · 单服务器部署</p>

  [![VulnLab CI](https://github.com/Chengxiaoyu1119/CTF-VulnLab/actions/workflows/vulnlab-ci.yml/badge.svg)](https://github.com/Chengxiaoyu1119/CTF-VulnLab/actions/workflows/vulnlab-ci.yml)
  [![Node.js](https://img.shields.io/badge/Node.js-22%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
  [![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
  [![Fastify](https://img.shields.io/badge/Fastify-5-111111?logo=fastify&logoColor=white)](https://fastify.dev/)
  [![SQLite](https://img.shields.io/badge/SQLite-单文件-003B57?logo=sqlite&logoColor=white)](https://sqlite.org/)
  [![License](https://img.shields.io/badge/License-Apache--2.0-D22128)](LICENSE)
</div>

<p align="center">
  <a href="#项目是什么">项目是什么</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#内置靶场">内置靶场</a> ·
  <a href="#运行原理">运行原理</a> ·
  <a href="#测试">测试</a> ·
  <a href="#单服务器部署">部署</a>
</p>

![VulnLab 靶场工作台](.github/assets/vulnlab-workspace.png)

## 项目是什么

VulnLab 是面向个人学习和小团队训练的开源靶场工作台。桌面端以固定 3×3 目录呈现九个主流靶场，用户从详情弹窗点击“启动环境”即可完成准备、启动、访问和停止。

当前版本为 `0.3.0`。主服务采用 Node.js 原生运行，Windows、Linux、macOS 本地和单台 Linux 云服务器使用同一套代码。

大型上游资源和运行时二进制不会提交进 Git 历史。仓库只保存固定版本、官方地址、SHA-256 和安装逻辑；靶场资源进入 `src/VulnLab/data/labs`，PHP/MariaDB 运行时进入 `src/VulnLab/data/runtime/toolchains`。整个数据目录已被 Git 忽略，既能随项目统一管理，也不会让仓库永久膨胀。

## 快速开始

### 1. 准备基础环境

- Windows 启动脚本和 Linux 原生部署会从 Node.js 官方源下载并校验固定版本 Node.js 22.23.1 到项目数据目录，再用它启动或构建 VulnLab；macOS 仍使用系统 Node.js 22+ 启动脚本。
- Windows x64 首次启动对应靶场时会自动准备固定版本 Node.js 22、PHP 8.3、MariaDB 11.4、Java 21 和 Python 3.11，不需要单独安装数据库、Java 或 Python。
- Linux x64 可下载项目内 Node.js、MariaDB、Java 和 Python；PHP 仍使用系统安装，并套用项目生成的 `php.ini`。

### 2. 启动

Windows：

```powershell
git clone https://github.com/Chengxiaoyu1119/CTF-VulnLab.git
cd CTF-VulnLab
powershell -ExecutionPolicy Bypass -File script/run_vulnlab.ps1
```

Linux / macOS：

```bash
git clone https://github.com/Chengxiaoyu1119/CTF-VulnLab.git
cd CTF-VulnLab
bash script/run_vulnlab.sh
```

打开 `http://127.0.0.1:6710/`。点击靶场封面进入详情弹窗，再点击“启动环境”；首次启动由服务自动准备该靶场所需资源和运行时，完成后即可打开页面。服务监听地址、端口和并发参数通过部署配置或环境变量维护，不设置独立的环境页面。

### 3. 登录

本地默认只有一个最高权限管理员账号：

| 账号 | 密码 |
| --- | --- |
| `vulnlab` | `vulnlab` |

生产部署仍需通过 `VULNLAB_ADMIN_PASSWORD` 设置独立管理员密码，并设置 Cookie secret；生产环境不使用本地默认密码。

## 内置靶场

| 靶场 | 固定来源 | 启动前准备 | 运行方式 |
| --- | --- | --- | --- |
| DVWA | 官方 Git 仓库 commit | 页面按需下载与安全解包 | PHP + MySQL |
| Pikachu | 官方 Git 仓库 commit | 页面按需下载与安全解包 | PHP + MySQL |
| SQLi-Labs | 官方 Git 仓库 commit | 页面按需下载与安全解包 | PHP + MySQL |
| Upload-Labs | 官方 Git 仓库 commit | 页面按需下载与安全解包 | PHP |
| XVWA | 官方 Git 仓库 commit | 页面按需下载与安全解包 | PHP + MySQL |
| OWASP Juice Shop | 官方发行包 `20.2.0` | 页面按需校验后解包 | Node.js |
| OWASP WebGoat | 官方发行包 `2023.8` | 页面按需校验后安装 | Java |
| OWASP Mutillidae II | 官方 Git 仓库 commit | 页面按需下载与安全解包 | PHP + MySQL |
| OWASP PyGoat | 官方 Git 仓库 commit | 页面按需下载并建立独立 Python 环境 | Python / Django |

九个靶场的目录、版本和运行方式内置在 VulnLab 中。源码和发行包在首次启动时由服务自动下载、校验并保存到项目数据目录；也可以设置 `VULNLAB_AUTO_INSTALL_BUILTINS=1` 在服务启动时批量准备全部资源。

## 运行依赖

| 依赖 | 影响范围 | VulnLab 的处理方式 |
| --- | --- | --- |
| PHP CLI | PHP 靶场 | Windows x64 下载官方 PHP 8.3 到 `data/runtime/toolchains`；Linux 使用系统 PHP 和项目配置 |
| PHP `mysqli`、`pdo_mysql` + MySQL/MariaDB | DVWA、Pikachu、SQLi-Labs、XVWA、Mutillidae | Windows/Linux x64 可下载项目内 MariaDB 11.4；每次启动创建独立数据库和最小权限账号 |
| Node.js 22+ | VulnLab 主服务、Juice Shop | Windows/Linux 启动器与原生部署使用项目内 Node.js 22；macOS 启动脚本使用系统 Node.js，Juice Shop优先复用已准备的项目版本 |
| Java 17+ | WebGoat | Windows/Linux x64 下载项目内 Eclipse Temurin JRE 21，独立端口启动 WebGoat 与 WebWolf |
| Python 3.10 / 3.11 | PyGoat | Windows/Linux x64 下载项目内 Python 3.11，再创建项目私有虚拟环境并执行迁移 |

详情弹窗只提供“启动环境”主动作。运行依赖由服务在启动过程中自动检查和准备，失败原因通过操作提示反馈；用户不需要理解、选择或手动准备 Provider。

## 运行原理

```mermaid
flowchart LR
    UI[原生 JavaScript / CSS 工作台] --> API[Fastify API]
    API --> DB[(SQLite)]
    API --> INSTALL[内置安装器 / Source Adapter]
    API --> RUN[Provider Registry]
    API --> TOOLCHAIN[运行时下载 / SHA-256]
    INSTALL --> FIXED[固定版本与完整性清单]
    FIXED --> DATA[data/labs]
    TOOLCHAIN --> RUNTIME[data/runtime/toolchains]
    RUN --> PHP[native-php]
    RUN --> NODE[native-node]
    RUN --> JAVA[native-java]
    RUN --> PY[native-python]
    PHP --> MYSQL[(每实例 MySQL 资源)]
```

- 后端：Node.js 22、TypeScript、Fastify。
- 数据：SQLite 单文件数据库。
- 前端：原生 JavaScript + CSS 工作区。
- 安装：固定上游版本、下载大小限制、路径检查、校验记录、失败清理。
- 运行：每个靶场声明 Provider；启动、续期、停止、过期回收采用统一生命周期。
- 隔离：原生靶场使用独立运行副本；PHP 数据库靶场使用每实例数据库和最小权限账号。

## 项目结构

```text
CTF-VulnLab/
├─ src/VulnLab/
│  ├─ public/                 页面、样式与封面
│  ├─ builtin-assets.ts       官方发行包安装器
│  ├─ importer.ts             GitHub / GitLab 下载与安全解包
│  ├─ providers.ts            PHP / Node / Java / Python Provider
│  ├─ runtime-prep.ts         PyGoat 私有运行环境准备
│  ├─ runtime-status.ts       本机运行依赖检测与启动前校验
│  ├─ runtime-toolchains.ts   Node.js / PHP / MariaDB / Java / Python 官方运行时下载、校验、安全解压与清单
│  ├─ project-environment.ts  项目内 PHP 配置与 MariaDB 生命周期
│  ├─ db.ts                   SQLite 数据层
│  └─ data/                   本地资源与状态，Git 忽略
├─ script/                    启动、单元测试、冒烟与浏览器回归
├─ operations/deploy/vulnlab/ 原生单机部署、备份与恢复
└─ .github/workflows/         持续集成
```

## 测试

```powershell
cd src/VulnLab
npm ci
npm run check
npm test
cd ../..
node script/check_vulnlab_node.mjs
```

Windows x64 可额外验证真实官方下载链路；测试会下载约 230 MiB，完成后自动清理临时目录：

```powershell
cd src/VulnLab
npm run smoke:toolchains
```

测试覆盖固定版本导入、安全解包、官方发行包、ZIP/TAR.XZ 下载校验、SQLite 生命周期、MySQL 资源、Provider 契约、部署契约和按靶场依赖判断。

服务启动后执行浏览器回归：

```powershell
node script/smoke_vulnlab.mjs
node script/smoke_vulnlab_builtin_runtimes.mjs
python script/browser_check_vulnlab.py
```

运行冒烟会真实启动并停止 Upload-Labs、Juice Shop、WebGoat 和 PyGoat。浏览器回归检查桌面 3×3、移动端双列、九个固定卡片、靶场详情、启动状态、触控尺寸、横向溢出和控制台错误。

## 单服务器部署

仓库提供 Linux 原生部署入口，包括 systemd、Caddy、环境变量模板、备份和恢复脚本。完整步骤见 [原生单机部署指南](operations/deploy/vulnlab/native/README.zh-CN.md)。

云服务器需要按实际靶场开放或反向代理运行端口；仅供本机使用时保持默认 `127.0.0.1` 即可。

## 当前边界

- 当前定位是单机和可信小团队，不是多租户集群调度平台。
- Windows x64 已具备 Node.js、PHP、MariaDB、Java、Python 的项目内下载、校验和运行链路；Linux x64 已具备 Node.js、MariaDB、Java、Python 链路，PHP 仍来自系统包管理器。
- XVWA 使用官方固定 commit 导入，启动时在独立 PHP 副本内完成数据库初始化，并通过 `/xvwa/` 入口访问。
- 原生进程提供练习副本和生命周期回收，但操作系统级隔离弱于虚拟机。

## 许可证

项目自有代码采用 [Apache License 2.0](LICENSE)。上游靶场、Logo 和界面截图分别遵循对应项目的许可证、版权与品牌要求，封面来源见 [素材说明](src/VulnLab/public/covers/README.md)。固定资源清单记录各项目许可证；SQLi-Labs 与 Upload-Labs 的当前固定版本记录为“上游未声明”。

安全问题请通过 [GitHub Private Vulnerability Reporting](SECURITY.md) 提交。
