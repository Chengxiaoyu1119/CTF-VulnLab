# VulnLab · 攻防控制台（Node 应用）

这是 VulnLab 当前开发基线的 Node.js / TypeScript 单机应用入口，暂未形成正式发行版。

## 模块边界

启动入口、包配置和跨模块核心文件保留在根目录；独立功能组按领域放入一级目录，运行数据、依赖和构建产物不纳入源码整理。

- `server.ts`：Fastify 服务、认证、API、运行入口与静态资源。
- `db.ts`：SQLite schema、内置靶场、安装任务、实例、设置与审计。
- `builtin-assets.ts`：Juice Shop、WebGoat 官方发行包下载、校验和安全解包。
- `importer.ts`：GitHub / GitLab 固定版本下载、归档哈希、路径检查和清单生成。
- `providers.ts`：`native-php`、`native-node`、`native-java`、`native-python`、`native-oa` 生命周期；OA 支持本地 AppContainer 与 Docker Compose 两种 Provider；XVWA 与其他 PHP 靶场共用 `native-php`。
- `oa/`：OA 专属 API、IPC、Docker、网络隔离与 AppContainer 模块。
- `native-oa/`：OA 启动器源码和 Docker 构建文件；生成的启动器二进制放在 `assets/native-oa/`。
- `runtime/prep.ts`：PyGoat 私有 Python 环境与依赖准备。
- `runtime/status.ts`：PHP、mysqli、PDO MySQL、MySQL、Node.js、Java、Python 检测和按靶场启动前校验。
- `runtime/toolchains.ts`：选择 Windows x64 官方 Node.js、PHP、MariaDB、Java、Python 包，执行限量下载、SHA-256、安全解压、原子安装和清单复用。
- `project-environment.ts`：项目内 PHP 配置、私有 MariaDB/MySQL 初始化、启动与回收；外部配置可覆盖。
- `mysql.ts`：每实例数据库与应用账号的创建、验证和清理。
- `seed.ts`：十一个内置靶场的版本、Provider 与自动安装策略（十个常规靶场及 OA Beta）。
- `assets/labs/oa-vuln-labs/1.0.0-beta/`：随仓库发布的 OA `source.zip` 与 `docker.zip` 靶场资源。
- `assets/`：固定输入资源；用途、版本、校验和生成方式见 [`assets/README.md`](assets/README.md)。
- `public/`：原生 JavaScript / CSS 工作台；主界面呈现内置与自定义靶场卡片，管理中心弹窗承载个人中心、系统数据、靶场管理、账号、审计和邀请管理，详情弹窗承载实例操作。
- `paths.ts`：统一生成 SQLite、靶场资源、下载缓存、运行实例和导入任务路径。
- `data/`：SQLite、下载资源、靶场源码、Python 环境与运行副本；整个目录被 Git 忽略。
- `bundle/`：可选的本地发行包目录，不提交到 Git；用于半联网或完全离线准备。

## 开发

```powershell
npm ci
npm run check
npm test
npm run dev
```

默认地址是 `http://127.0.0.1:6710`。`VULNLAB_HOST`、`VULNLAB_PORT`、`VULNLAB_PUBLIC_URL`、`VULNLAB_DATA_DIR`、`VULNLAB_BUNDLE_DIR` 和 `VULNLAB_OFFLINE=1` 可以覆盖服务参数；监听 `0.0.0.0` 或 `::` 时必须显式设置 `VULNLAB_PUBLIC_URL`。

## 内置资源与启动模型

`seed.ts` 保存十一个内置靶场，其中十个常规靶场使用固定版本，OA Beta 使用仓库内的 `source.zip` / `docker.zip`。用户不需要执行安装动作；点击“启动环境”后，服务按“本地 bundle → 已有 data 缓存 → 官方网络来源”的顺序准备常规靶场资源，完成体积、路径和固定 SHA-256 校验后再安装。设置 `VULNLAB_OFFLINE=1` 后只使用 bundle 和已有缓存；设置 `VULNLAB_AUTO_INSTALL_BUILTINS=1` 可以在服务启动时批量准备全部资源。

离线发行包使用固定目录约定：`<bundle>/runtime/<运行时文件名>` 放 PHP、MariaDB、Node.js、Java、Python 压缩包；Git 仓库靶场放在 `<bundle>/labs/<slug>/<version>/source.zip`；Juice Shop 和 WebGoat 使用各自固定发行包文件名。XSS-Labs 使用固定上游提交及 SHA-256；上游未声明许可证，第 17–20 关依赖现代浏览器已移除的 Flash。`VULNLAB_BUNDLE_DIR` 未设置时不启用本地发行包目录。

管理员可以通过管理中心添加自定义靶场。来源支持公开 GitHub/GitLab 仓库和本地 ZIP；运行配置使用静态 PHP、PHP + MySQL、Node.js、Java JAR、Python 文件或 PyGoat Django 这几类固定模板。上传包先写入 `data/lab-uploads`，导入成功后再复制到 `data/labs`，SQLite 保存运行模板和永久路径，服务重启时会做路径对账。Node 项目必须带锁文件；带 `requirements.txt` 的自定义 Python 项目必须配置离线 wheelhouse；不符合模板的入口、路径或 ZIP 安全检查会直接拒绝。

Juice Shop 使用官方预构建发行包；WebGoat 使用适配 Java 17/21 的 2023.8 JAR；PyGoat 安装后创建 `.vulnlab-venv`，运行副本复用该环境并在启动前执行 Django migration。PyGoat 默认使用 `assets/python/pygoat` 内的哈希锁定依赖和离线 wheelhouse，适配 Windows x64 上的 Python 3.10/3.11；安装过程不访问包索引。`VULNLAB_PYTHON_REQUIREMENTS_FILE` 与 `VULNLAB_PYTHON_WHEELHOUSE` 可覆盖默认资源路径。

## 运行模型

每个 Lab 通过自己的 `providerId` 自动选择运行实现。

- PHP：复制独立运行目录，按需创建 MySQL 资源，启动 PHP 内置服务器。
- Node.js：复制可变文件并链接只读依赖目录，减少 Juice Shop 启动复制量。
- Java：为 WebGoat 与 WebWolf 分配两个端口，并把数据目录限制在实例副本。
- Python：复制源码、复用项目私有解释器、迁移 SQLite 后启动 Django。
- XVWA：启动时创建独立 MySQL 资源，修正上游初始化脚本后通过 PHP 内置服务器提供 `/xvwa/`。
- OA-Vuln-Labs：初始靶场账号为 `admin / ZSD@admin2025!`，无需先找漏洞获得账号；本地模式依赖 Windows AppContainer，Docker 模式依赖可用的本机 Docker Engine。

进程状态写入运行目录；正常停止、过期回收、服务关闭和服务重启都执行资源回收。点击“启动环境”时，实例 API 会先准备资源和项目运行时，再调用 Provider；确实无法满足的依赖以 `RUNTIME_DEPENDENCY_MISSING` 返回。

## 管理中心与账号行为

管理员从工作台左上角的 `VulnLab` 入口打开管理中心。栏目包括个人中心、系统数据、账号管理、审计记录和邀请管理；弹窗内栏目切换保留筛选，关闭或退出登录会清空临时选择状态。

管理员还可以在“靶场管理”栏目创建自定义靶场。添加任务使用管理员 CSRF 会话，任务完成后靶场会进入主目录并出现在工作台；导入期间的状态和错误保存在导入任务中，不会显示为可启动的假就绪状态。

| 接口 | 契约 |
| --- | --- |
| `GET /api/overview` | 管理员可读；返回靶场就绪/运行概况、最近 365 天成功启动活动和靶场排行。活动数据来自保留的启动审计记录，清理审计会同步改变统计。 |
| `GET /api/auth/users` | 管理员分页读取账号；首屏附带 `kind: "system"` 的默认管理员展示行，它不是注册用户数据库记录，不可选择或删除。注册账号仍按游标分页。 |
| `GET /api/audit` | 管理员分页读取审计记录；可选 `date=YYYY-MM-DD` 与 `action` 在数据库分页前筛选。日期按服务器本地自然日解释。 |
| `GET /api/auth/invitations` | 管理员分页读取邀请码状态、创建信息、使用账号快照与时间；已使用记录只读保留。 |

邀请码通过 `POST /api/auth/invitations` 创建，有效期 24 小时、单次使用；明文只在创建响应中返回，数据库只保存 SHA-256 哈希。注册与邀请码消费在同一 SQLite 事务中完成，注册成功后保存使用者账号快照，因此之后删除注册账号仍能追溯邀请码。旧记录没有使用者快照时，界面会明确标记为“历史记录未记录使用者”，不会猜测回填。注册账号当前统一为管理员；默认管理员 `vulnlab` 是独立配置账号，不伪装成注册账号。

服务运行后，`npm run smoke:runtimes` 会依次验证十个常规内置靶场；OA 有独立的 `npm run smoke:oa`、`npm run smoke:oa:docker` 与 `npm run smoke:oa:mysql` 回归入口。MariaDB smoke 需要预先准备项目私有 MariaDB 运行时，不会自动下载运行时。

`/api/settings` 保存的监听地址和端口在下次服务启动时生效；监听 `0.0.0.0` 或 `::` 时必须同时设置可信的 `VULNLAB_PUBLIC_URL`，运行时入口不会使用请求头 `Host` 推导公共地址。

## 项目运行环境

启动时，VulnLab 会在 `data/runtime/` 创建运行状态。用户点击“启动环境”后，Windows x64 会自动准备当前靶场需要的 Node.js 22.23.1、PHP 8.3.33 NTS、MariaDB 11.4.10、Eclipse Temurin JRE 21.0.12.1 或 Python 3.11.16。下载文件必须匹配仓库固定的 SHA-256，解压路径和体积受限，准备通过 `data/runtime/.staging` 原子切换；成功后压缩包立即清理。

运行时目录结构为 `toolchains/`、`manifests/`、`.staging/`、`php/` 和 `mysql/`。原始发行包只在准备阶段进入项目内 `.staging/`，校验和安装完成后清理，不作为运行时持久目录。PHP 使用项目生成的 `php.ini`；Windows 会启用发行包内存在的 `mysqli`、`pdo_mysql`、`mbstring`、`gd`、`curl`、`openssl` 扩展。MariaDB 只绑定 `127.0.0.1`，默认端口 `7330`，数据、日志、PID 和随机管理凭据均留在项目数据目录，服务关闭时回收进程。

运行时二进制不提交进 Git；固定输入资源按 [`assets/README.md`](assets/README.md) 登记。`data/`、`dist/`、`node_modules/` 与 `bundle/` 分别用于运行状态、构建输出、依赖和可选离线包，不提交进 Git。已下载的项目包优先级高于系统 `PATH`；显式环境变量和外部 MySQL 连接仍可覆盖。Juice Shop 使用项目 Node.js，PyGoat 直接用项目 Python 创建 `venv`，WebGoat 直接用项目 JRE 启动。用户点击“启动环境”后，服务自动完成依赖检查；失败原因通过启动操作提示返回。

## 外部 MySQL 配置

DVWA、Pikachu、SQLi-Labs、XVWA 和 Mutillidae 需要 PHP `mysqli`、`pdo_mysql` 与 MySQL / MariaDB：

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

Windows x64 真实运行时链路回归：

```powershell
npm run build
npm run smoke:toolchains
```

该回归在全新临时目录完成“官方下载 → SHA-256 → 安全解压 → Node.js → PHP mysqli → MariaDB 连接 → Java 启动 → Python venv/pip → 停止回收”，随后删除临时目录。PyGoat 运行回归需要预先提供哈希锁定依赖文件和离线 wheelhouse。`npm test` 使用 Windows ZIP/TGZ fixture 和 Provider 契约完成快速回归。

## 生产配置

生产环境必须显式设置至少 12 字符的 `VULNLAB_ADMIN_PASSWORD` 和至少 32 字符的 `VULNLAB_COOKIE_SECRET`。本地开发保留默认管理员账号 `vulnlab`；注册账号必须使用管理员在管理中心生成的 24 小时一次性邀请码，且当前统一为管理员。注册账号和邀请码状态保存在 SQLite，密码只保存 scrypt 哈希，邀请码只保存 SHA-256 哈希；Cookie 使用签名 HttpOnly，写操作要求 CSRF token，登录和注册失败有持久化速率限制。对外监听 `0.0.0.0` 或 `::` 时，还必须设置可信的 `VULNLAB_PUBLIC_URL`。

当前仅维护 Windows x64 本地启动流程，不提供独立服务器部署入口。

## 构建与发行边界

`npm run build` 仅执行 TypeScript 编译并生成 `dist/`，不生成 EXE。当前阶段继续使用 Git 仓库中的源码运行；便携式 Windows 发行版应作为后续独立阶段，随发行目录提供启动器、Node/runtime、前端资源和可写 `data/`，避免每次启动执行 `npm ci` 或重新下载依赖。
