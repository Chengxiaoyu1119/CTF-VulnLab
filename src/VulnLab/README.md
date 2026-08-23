# VulnLab Node 应用

这是 VulnLab 0.2.0 的 Node.js/TypeScript 单机应用入口。

## 技术边界

- `server.ts`：Fastify 服务、认证、API 和 Web 静态资源入口；
- `db.ts`：SQLite schema、种子目录、导入任务、实例、设置和审计；
- `providers.ts`：Provider 生命周期契约、注册表、`simulated`、`native-php` 和可选 `qemu-vm` 实现；原生 PHP 适配 Upload-Labs、DVWA、Pikachu 和 SQLi-Labs，未注册的 container 运行类型不会回退到模拟实例；
- `mysql.ts`：通过本机 `mysql` 客户端创建、验证和清理每实例数据库与应用账号；
- `vm-download.ts`：VulnHub 镜像显式下载、磁盘/大小限制、临时文件和校验；
- `importers.ts`：GitHub、GitLab、VulnHub 来源适配器注册边界；
- `vulnhub.ts`：VulnHub 机器目录、详情、下载地址和校验元数据导入；
- `importer.ts`：GitHub/GitLab 固定版本下载、哈希记录、安全解包和导入清单；
- `seed.ts`：首批主流靶场来源目录；
- `public/`：无组件库的 VulnLab 页面应用；靶场主页面按已确认的运行状态面板 + 3×3 题目工作区实现，卡片封面使用 `public/covers/` 中的上游 Logo 或实际界面截图，其他管理功能保持独立工作页；
- `data/`：运行时 SQLite 数据，进入 Git 忽略范围。

导入 VulnHub 目录后，认证用户可以通过 `GET /api/labs/:id/catalog` 读取经过 manifest SHA-256 校验的 `catalog.json`；页面在“导入”工作页提供机器列表和单台机器详情。该接口只读取目录元数据，不下载虚拟机镜像。

管理员可以通过 `POST /api/labs/:id/catalog/entries/:index/download` 显式创建镜像下载任务，任务状态会写入 SQLite；下载器检查官方域名、响应大小、运行数据目录磁盘空间、临时文件和 MD5/SHA1/SHA-256，服务重启时未完成任务会重新排队。镜像下载完成后，若环境 Provider 设置为 `qemu-vm`，可以在机器详情中启动已校验的 OVA（自动提取 VMDK）、qcow2、raw、vdi 或 vmdk 镜像；单独的 OVF 文件仍需要配套磁盘。

## 开发

```powershell
npm ci
npm run check
npm run build
npm run dev
```

服务默认监听 `http://127.0.0.1:6710`。可以使用 `VULNLAB_PORT`、`VULNLAB_HOST` 和 `VULNLAB_DATA_DIR` 覆盖默认配置。

实例 API 通过 `providerRegistry` 选择 Provider：Provider 生成入口、续期时间和运行日志，数据库只保存实例状态。`simulated` Provider 只返回明确标记的 `/lab-preview/:slug` 框架预览；`native-php` Provider 为每个实例复制独立工作目录、分配内部端口、启动 PHP 子进程，并由服务端 `/lab-runtime/:id/` 同源代理转发请求；`qemu-vm` Provider 为每台已校验磁盘镜像分配宿主端口，通过 QEMU 用户态网络转发到虚拟机端口，并以临时快照启动，再由同源代理暴露入口。DVWA、Pikachu 和 SQLi-Labs 启动时还会创建独立 MySQL 数据库和应用账号，在实例副本中完成初始化；管理账号密码只进入 `mysql` 子进程的 `MYSQL_PWD` 环境变量。过期实例会由服务层调用 Provider 停止并回收资源。导入完成但尚未有匹配 Provider 的靶场仍可在目录中查看，启动接口会返回明确的运行适配错误。

开发环境使用内置账号，生产环境必须显式设置管理员密码、学员密码和至少 32 个字符的 `VULNLAB_COOKIE_SECRET`；生产环境不会接受开发默认凭据。会话存放在 SQLite，Cookie 使用签名 HttpOnly 形式，服务重启后仍可恢复未过期会话。

## 导入适配器原则

GitHub/GitLab 适配器已经完成来源解析、默认分支和 commit 固定、下载校验、解包目录安全检查、许可证文件发现和失败清理；GitLab 支持命名空间项目路径、API 限流时的分支压缩包哈希回退，以及针对归档 CDN 兼容性的内置 HTTPS 下载。VulnHub 适配器会读取目录和详情页，把机器下载地址、文件名、大小、MD5/SHA1 和页面读取警告写入 `catalog.json`。适配器只下载和解析页面或文件，不执行外部安装脚本。

Upload-Labs 的真实运行需要 PHP CLI。Provider 会使用 `VULNLAB_PHP_BIN` 指定的 PHP，可选使用 `VULNLAB_PHP_INI` 加载扩展配置；运行进程默认绑定 `VULNLAB_RUNTIME_HOST`，端口从 `VULNLAB_RUNTIME_PORT_START` 到 `VULNLAB_RUNTIME_PORT_END` 中分配。服务关闭时回收子进程，下一次启动会把上次遗留的原生 PHP 实例标记为已结束。

DVWA、Pikachu 和 SQLi-Labs 使用 `native-php` Provider 时额外需要 MySQL 配置：`VULNLAB_MYSQL_HOST`、`VULNLAB_MYSQL_PORT`、`VULNLAB_MYSQL_ADMIN_USER`、`VULNLAB_MYSQL_ADMIN_PASSWORD`、`VULNLAB_MYSQL_APP_HOST` 和可选的 `VULNLAB_MYSQL_BIN`。启动实例时，Provider 创建形如 `vulnlab_<靶场>_<实例摘要>` 的独立数据库和 `vl_<靶场>_<实例摘要>` 的独立账号；管理密码只放在 `mysql` 子进程的 `MYSQL_PWD` 环境变量中，停止、服务重启恢复和异常退出都会按确定性名称清理资源。DVWA/Pikachu 初始化脚本和 SQLi-Labs 的 `mysql_*` 兼容层都只写入实例副本，不修改导入源目录。

导入任务采用 SQLite 原子抢占：同一任务只能由一个请求启动。服务重启时未完成任务会回到排队状态，避免把半完成的导入误标记为可运行。

导入下载具有 30 秒请求超时和进程关闭取消机制；关闭服务时任务保留在 `importing` 状态，由下一次启动的恢复逻辑重新排队。HTTP 请求体默认限制为 64 KiB，防止管理接口被超大 JSON 占用。
