# Changelog

## 未发布 — 当前开发基线

当前代码仍处于持续开发阶段，尚未形成正式发行版；首个公开版本号另行确定。

- 固定 3×3 九靶场工作区：DVWA、Pikachu、SQLi-Labs、Upload-Labs、XVWA、OWASP Juice Shop、OWASP WebGoat、OWASP Mutillidae II、OWASP PyGoat；
- 使用固定版本来源、下载大小限制、SHA-256 校验、安全解包和失败清理，首次使用时将资源保存到本地数据目录；
- 使用 `native-php`、`native-node`、`native-java`、`native-python` Provider 运行对应靶场，不依赖 Docker；
- PHP 数据库靶场按实例创建独立数据库与应用账号，运行副本和实例资源在停止或过期后回收；
- 详情弹窗统一承载启动、打开、续期和停止操作，运行时检查与资源准备属于服务内部流程；
- 桌面端保持 3×3，移动端保持双列，靶场卡片只展示官方封面和名称；
- 提供 SQLite 状态管理、签名 Cookie、CSRF 校验、登录限速、请求体限制、审计记录和服务重启回收；
- 提供 Windows 本地启动脚本、Linux 原生单机部署、systemd、Caddy、备份恢复与 GitHub Actions 检查。

详细说明见 [`README.md`](./README.md) 和 [`src/VulnLab/README.md`](./src/VulnLab/README.md)。
