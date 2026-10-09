# 固定输入资源

`assets/` 只存放随项目版本固定、供构建或运行使用的输入资源；SQLite、下载缓存、靶场运行副本、日志、临时文件和可重建输出放在 `data/`、`bundle/` 或系统临时目录，不放入此目录。

| 路径 | 用途与维护依据 |
| --- | --- |
| `labs/oa-vuln-labs/` | 项目维护的 OA-Vuln-Labs `source.zip` 与 `docker.zip`；安装和运行副本由 `src/builtin-assets.ts`、`src/labs/oa-vuln-labs/docker-assets.ts` 校验。对外显示版本为 `1.0.0`，内部资源缓存沿用既有目录。 |
| `python/pygoat/requirements.in`、`requirements.txt`、`wheelhouse/` | PyGoat 离线依赖输入；锁文件要求哈希，`src/runtime/prep.ts` 按离线 wheelhouse 安装，CI 通过 `pip-audit` 审计锁文件。修改时需同步验证锁文件、wheel 文件和 PyGoat 运行时测试。 |
| `labs/oa-vuln-labs/native/appcontainer-launcher-sandbox.exe` | OA AppContainer 启动器；由 `src/labs/oa-vuln-labs/native/build-launcher.ps1` 生成，`src/labs/oa-vuln-labs/sandbox.ts` 保存校验哈希，回归测试会校验该文件。 |
| `../public/ruffle/` | Ruffle `nightly-2026-10-06` 自托管 Web 文件及 MIT/Apache-2.0 许可文本；第 17–20 关运行副本使用这些本地文件。

新增或更新固定资源时，必须同时记录用途、来源/版本、哈希校验位置、更新或再生成步骤以及许可状态。运行期生成物不因体积小或方便测试而提交到 Git。

已提交固定资源及依赖的许可、来源和哈希记录见根目录 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)。
