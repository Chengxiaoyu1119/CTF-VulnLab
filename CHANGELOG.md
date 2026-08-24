# Changelog

## 0.3.0 — 内置靶场与真实运行

- 固定 3×3 九靶场工作区：DVWA、Pikachu、SQLi-Labs、Upload-Labs、VulnHub、Juice Shop、WebGoat、Mutillidae、PyGoat；
- 接入 Juice Shop 与 WebGoat 官方发行包安装器，增加 MD5/SHA-256、下载上限、ZIP/TAR.GZ 安全解包和缓存回收；
- 把四个 PHP 靶场、Mutillidae 和 PyGoat 固定到官方 commit，并在首次启动时自动准备；
- 增加 `native-node`、`native-java`、`native-python` Provider，真实启动 Juice Shop、WebGoat 和 PyGoat；
- 增加 PyGoat 私有 Python 环境、依赖安装、Django 设置适配和启动迁移；
- 增加 Mutillidae 每实例 MySQL 配置与初始化适配；
- 靶场按自身 `providerId` 自动选择运行实现；
- 增加 PHP、mysqli、MySQL、Node.js、Java、Python、QEMU 自动检测和按靶场启动条件；
- 一级工作区聚焦靶场、运行和环境三个入口，安装进度直接呈现在靶场卡片；
- 卡片操作统一为安装、启动环境、打开页面和停止；
- 使用上游封面或项目内真实资源补齐九个靶场封面，桌面保持 3×3，移动端保持双列；
- 增加固定版本发行包、依赖判断与多 Provider 回归测试，完成 PHP/MySQL 四靶场和 Node/Java/Python 靶场真实启动验证；
- 增加原生进程 PID 状态、服务重启资源回收、旧版本目录清理和 PHP 重定向启动探测；
- WebGoat 固定为 Java 17/21 兼容的 `2023.8`，Juice Shop 固定为 `20.2.0`，两者均使用固定哈希校验。

## 0.2.0 — Node 单机框架

- 后端迁移为 Node.js 22 + TypeScript + Fastify；
- 数据状态迁移为 SQLite 单文件；
- 建立靶场来源、导入任务、实例生命周期、环境设置和审计 API；
- 建立 DVWA、Pikachu、SQLi-Labs、Upload-Labs、VulnHub、Vulhub、OWASP Juice Shop、OWASP WebGoat 种子目录；
- 建立 GitHub、GitLab、VulnHub Source Adapter 注册边界；
- 完成 GitHub 仓库导入：固定 commit、SHA-256、大小限制、路径穿越防护、许可证发现和 `manifest.json`；
- 增加 SQLite 会话持久化、签名 Cookie、CSRF 校验、登录限速和生产默认凭据校验；
- 增加导入任务原子抢占、服务重启恢复和 GitHub `main` / `master` 默认分支回退；
- 增加 SQLite 持久化登录限速、实例容量事务、下载超时、导入取消、请求体上限和可信代理配置；
- 增加云服务器公开入口配置 `VULNLAB_PUBLIC_URL`，并清理浏览器与 Python 测试缓存；
- 抽出 `LabProvider` 契约、Provider 注册表和 `simulated` 生命周期实现，实例 API 保持原有返回结构；
- 增加 `native-php Provider`：Upload-Labs、DVWA、Pikachu 和 SQLi-Labs 可通过独立 PHP 进程、同源运行时代理和实例目录运行；
- 增加每实例 MySQL 资源管理：DVWA/Pikachu 使用独立数据库、独立应用账号和启动初始化，管理账号密码不进入 PHP 子进程；
- 增加 Windows 可移植路径审查：拒绝大小写冲突、文件/目录冲突、保留设备名和 NTFS 不可用文件名；
- Web 工作台保留桌面 3×3 靶场展示、移动端 2 列布局和独立环境设置页；
- 靶场卡片改用各上游项目的 Logo 或实际界面截图作为封面，移除无实际操作价值的状态说明行和封面叠加标签；
- 清理旧后端、旧客户端、旧品牌资源和旧部署入口，仓库主线统一为 VulnLab Node 应用；
- 增加 Node 结构检查、类型检查、构建和 API 冒烟测试。
- 修正运行资格边界：导入完成不再把 container/vm 靶场降级为 simulated 实例；未完成导入或缺少匹配 Provider 时，接口明确拒绝启动。
- 增加 VulnHub 目录元数据导入：保存机器详情、下载地址、文件大小、MD5/SHA1 和页面读取警告；虚拟机镜像下载与 VM Provider 仍保持独立阶段。
- 增加 VulnHub `catalog.json` 认证查看、SHA-256 完整性复核和单台机器选择界面；管理员可显式创建镜像下载任务，下载器具备官方域名限制、大小上限、磁盘空间检查、临时文件、服务重启重排队和 MD5/SHA1/SHA-256 校验。
- 增加可选 `qemu-vm Provider`：支持已校验 OVA 中的 VMDK、qcow2、raw、vdi 和 vmdk 镜像，使用回环端口转发、启动探测、续期、停止、服务重启回收和 OVA 路径安全检查；主服务仍不依赖 Docker。
- 修正 GitLab 归档下载在 Node/undici 请求下可能返回 HTTP 406 的兼容问题，默认使用内置 HTTPS 传输并保留可注入的测试请求实现。
- 加强导入、VulnHub 页面和虚拟机下载的响应流回收，超过大小上限或请求失败时主动取消读取，避免无效下载继续占用资源。
- 收紧来源登记边界：未匹配 Source Adapter 的 GitLab 压缩包或直接虚拟机地址会在登记阶段明确返回适配器错误；过期实例缺少 Provider 时保留运行记录，等待恢复处理。

详细说明见 [`README.md`](./README.md) 和 [`src/VulnLab/README.md`](./src/VulnLab/README.md)。
