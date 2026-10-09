# 自动化脚本索引

## 目录职责

| 目录/文件 | 用途 | 入口 |
| --- | --- | --- |
| `tests/` | Node.js 回归、接口、清理队列与 Compose Provider 测试 | `cd src; npm test` |
| `smoke/` | 需要运行时或服务状态的集成检查 | `cd src; npm run smoke:<name>` |
| `browser/` | Playwright 浏览器检查及其 Node.js 启动器 | `cd src; npm run test:browser` |
| `tools/` | 不启动服务的结构、文档和资源清单契约检查 | CI 自动执行 `check_vulnlab_node.mjs` |
| `run_vulnlab.ps1` | 本地启动入口，保持根 README 中的路径稳定 | `powershell -ExecutionPolicy Bypass -File script/run_vulnlab.ps1` |

## Smoke 命令

| 命令 | 用途 |
| --- | --- |
| `npm run smoke` | 当前运行服务 API 检查 |
| `npm run smoke:native-php` | PHP 内置靶场检查 |
| `npm run smoke:native-php:mysql` | PHP 与 MySQL 集成检查 |
| `npm run smoke:toolchains` | 项目运行时工具链端到端检查 |
| `npm run smoke:runtimes` | 十个常规内置靶场运行检查 |
| `npm run smoke:operational` | 服务运行与数据隔离检查 |
| `npm run smoke:oa` | OA 本地 Provider 检查 |
| `npm run smoke:oa:docker` | OA Docker Provider 检查 |
| `npm run smoke:oa:mysql` | OA MariaDB 初始化检查；要求项目私有 MariaDB 已预先准备 |
| `npm run smoke:compose` | 需要可用 Docker Engine 和 `nginx:1.27-alpine`、`redis:8-alpine` 镜像；验证多服务入口与资源回收 |
| `npm run smoke:xss-ruffle` | 需要固定版 XSS-Labs 本地资源、PHP 与 Playwright Chromium；检查第 17–20 关 |
