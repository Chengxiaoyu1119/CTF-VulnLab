# 固定输入资源

`assets/` 只存放随项目版本固定、供构建或运行使用的输入资源；SQLite、下载缓存、靶场运行副本、日志、临时文件和可重建输出放在 `data/`、`bundle/` 或系统临时目录，不放入此目录。

| 路径 | 用途与维护依据 |
| --- | --- |
| `labs/oa-vuln-labs/1.0.0-beta/source.zip`、`docker.zip` | OA Beta 固定靶场资源；版本与哈希校验由 `src/builtin-assets.ts`、`src/oa/docker-assets.ts` 维护。上游许可尚未声明，资源登记不代表许可状态已解决。 |
| `python/pygoat/requirements.in`、`requirements.txt`、`wheelhouse/` | PyGoat 离线依赖输入；锁文件要求哈希，`src/runtime/prep.ts` 按离线 wheelhouse 安装，CI 通过 `pip-audit` 审计锁文件。修改时需同步验证锁文件、wheel 文件和 PyGoat 运行时测试。 |
| `native-oa/appcontainer-launcher-sandbox.exe` | OA AppContainer 启动器；由 `src/native-oa/build-launcher.ps1` 生成，`src/oa/sandbox.ts` 保存校验哈希，回归测试会校验该文件。 |

新增或更新固定资源时，必须同时记录用途、来源/版本、哈希校验位置、更新或再生成步骤以及许可状态。运行期生成物不因体积小或方便测试而提交到 Git。
