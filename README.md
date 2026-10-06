<!-- markdownlint-disable MD013 MD033 MD041 -->

<div align="center">
  <img src="src/public/favicon.png" width="88" alt="VulnLab Logo">
  <h1>VulnLab</h1>
  <p><strong>一台电脑，启动九类 Web 安全靶场。</strong></p>
  <p>固定版本 · 一键启动 · 独立实例 · 到期回收</p>

  <a href="https://github.com/Chengxiaoyu1119/CTF-VulnLab/actions/workflows/vulnlab-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Chengxiaoyu1119/CTF-VulnLab/vulnlab-ci.yml?style=for-the-badge&logo=githubactions&label=CI" alt="VulnLab CI"></a>
  <img src="https://img.shields.io/badge/Windows-x64-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows x64">
  <img src="https://img.shields.io/badge/Node.js-22%2B-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js 22+">
  <a href="https://github.com/Chengxiaoyu1119/CTF-VulnLab/stargazers"><img src="https://img.shields.io/github/stars/Chengxiaoyu1119/CTF-VulnLab?style=for-the-badge&logo=github&label=Stars" alt="GitHub stars"></a>
</div>

<p align="center">
  <a href="#核心能力">核心能力</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#内置靶场">内置靶场</a> ·
  <a href="#文档">文档</a> ·
  <a href="#架构时序">架构时序</a>
</p>

<p align="center">
  <img src=".github/assets/vulnlab-workspace.png" alt="VulnLab 工作台：品牌区与九个安全训练环境" width="100%">
</p>

> [!NOTE]
> 当前以 Windows x64 本地运行链路为主。源码启动、按需准备运行时和靶场资源；尚未提供独立安装包。

## 核心能力

<table>
  <tr>
    <td width="33%" valign="top"><strong>固定版本</strong><br>锁定上游来源与版本，下载、解包和目录进入运行区前均执行校验。</td>
    <td width="33%" valign="top"><strong>一键启动</strong><br>按靶场按需准备 Node.js、PHP、MariaDB、Java 或 Python，不要求预先配置整套环境。</td>
    <td width="33%" valign="top"><strong>可回收实例</strong><br>每次练习使用独立运行副本，支持打开、续期、停止与过期回收。</td>
  </tr>
</table>

## 快速开始

```powershell
git clone https://github.com/Chengxiaoyu1119/CTF-VulnLab.git
cd CTF-VulnLab
powershell -ExecutionPolicy Bypass -File script/run_vulnlab.ps1
```

打开 `http://127.0.0.1:6710/`，使用本地默认账号 `vulnlab / vulnlab` 登录，选择靶场后点击“启动环境”。首次启动只准备当前靶场需要的资源。

## 内置靶场

| PHP | PHP / MySQL | Node.js | Java | Python |
| --- | --- | --- | --- | --- |
| Upload-Labs | DVWA · Pikachu · SQLi-Labs · XVWA · Mutillidae II | OWASP Juice Shop | OWASP WebGoat | OWASP PyGoat |

共 `9` 个固定版本训练环境。资源和对应运行时在首次启动时按需准备。

<details>
  <summary><strong>开发与验证</strong></summary>

  ```powershell
  cd src
  npm ci
  npm run check
  npm test
  npm run test:browser
  ```

  完整运行时、离线 bundle、外部 MySQL 与发布边界见开发运行手册。
</details>

## 文档

| 文档 | 用途 |
| --- | --- |
| [开发与运行手册](src/README.md) | 模块、配置、运行时、Provider 与验证命令 |
| [设计说明](DESIGN.md) | 页面契约、视觉规则与响应式验收 |
| [靶场封面来源](src/public/covers/README.md) | 上游图片、标识与来源链接 |

## 架构时序

```mermaid
sequenceDiagram
    autonumber
    actor Learner as 练习者
    participant UI as VulnLab 工作台
    participant API as 本地服务
    participant Lab as 靶场实例
    Learner->>UI: 选择靶场并启动
    UI->>API: 请求启动实例
    API->>API: 检查依赖并准备资源
    API->>Lab: 创建独立副本并启动进程
    Lab-->>API: 返回入口与运行状态
    API-->>UI: 更新实例状态
    UI-->>Learner: 打开练习页面
    Learner->>UI: 停止实例
    UI->>API: 请求结束实例
    API->>Lab: 停止进程并回收资源
    API-->>UI: 更新实例状态
```

<p align="center">
  <strong>如果这个项目对你有帮助，欢迎点亮一个标星 ⭐</strong><br>
  <a href="https://github.com/Chengxiaoyu1119/CTF-VulnLab/stargazers">⭐ Star VulnLab</a>
</p>
