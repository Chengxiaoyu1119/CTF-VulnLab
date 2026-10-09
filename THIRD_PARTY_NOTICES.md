# 第三方资源与许可

根目录 [LICENSE](LICENSE) 适用于本项目原创代码和原创文档。第三方内容保留各自许可；本清单记录仓库固定资源及锁定依赖的来源、版本、校验值和许可依据，不代表未声明许可的素材已获再发布授权。

## 固定靶场

靶场版本、来源提交和许可声明以 [`src/seed.ts`](src/seed.ts) 为准。除 OA 资源包外，靶场源码由工作台按固定提交从上游获取，不随本仓库打包发布。

| 靶场 | 固定来源 | 许可声明 |
| --- | --- | --- |
| DVWA | `digininja/DVWA@5d5c76cced604e54462b13723f5c69af58e78748` | GPL-3.0 |
| Pikachu | `zhuifengshaonianhanlu/pikachu@5e1e8d9d14a3ba61d62f28cf35531c4df4dd24fc` | Apache-2.0 |
| XSS-Labs | `do0dl3/xss-labs@c97bed6e6dd850d486e0fcaac177b13117b1052d` | 上游未声明 |
| SQLi-Labs | `Audi-1/sqli-labs@e96f21776372c8613a7e565106e62bc01a59355e` | 上游未声明 |
| Upload-Labs | `c0ny1/upload-labs@3a0ff865d41d93ea7d57a91e837f084d9d2318e5` | 上游未声明 |
| XVWA | `s4n7h0/xvwa@fb30fa517d288e618b521d252f61107ef6a24797` | GPL-3.0 |
| OWASP Juice Shop | `juice-shop/juice-shop@5658473cf8814459bf89000ce373b20ed0b4eb37` | MIT |
| OWASP WebGoat | `WebGoat/WebGoat@5357a65e054976cd7d79b81ef3906ded050ed921` | GPL-2.0 |
| OWASP Mutillidae II | `webpwnized/mutillidae@84f2c00d9141dbb9e26a448c8288e651e0b5bb04` | GPL-3.0 |
| OWASP PyGoat | `adeyosemanputra/pygoat@19d17cc8874861142b330636d068bbde54e86b85` | MIT |

## 随仓库发布的资源

| 资源 | 来源、版本与 SHA-256 | 许可与再发布依据 |
| --- | --- | --- |
| OA-Vuln-Labs `source.zip` | 项目固定资源 `1.0.0`；`99d7d57daad5f68474a6a2a0c04be5959bae4543a9ed31a10cfc6249ebc57e64` | Apache-2.0；项目原创资源按根目录 LICENSE 发布 |
| OA-Vuln-Labs `docker.zip` | 项目固定资源 `1.0.0`；`6402789609f547668c9c1d41a5aded1ef3dd644a7657ef414b53db2a55e46dcb` | Apache-2.0；项目原创资源按根目录 LICENSE 发布 |
| Ruffle Web | `ruffle-rs/ruffle`, `nightly-2026-10-06`；文件 SHA-256 见下表 | MIT 或 Apache-2.0；随资源保留 `LICENSE.md`、`LICENSE_MIT`、`LICENSE_APACHE` |
| PyGoat wheelhouse | 30 个 Windows wheel；版本及每个发行包 SHA-256 见 [`requirements.txt`](src/assets/python/pygoat/requirements.txt) | 遵循各 wheel 的发行许可；包名、版本及许可元数据位于 wheel 的 `.dist-info/METADATA`。缺失或 `UNKNOWN` 字段不由本项目重新声明 |
| npm 依赖 | 版本、registry 来源、integrity 与许可元数据见 [`package-lock.json`](src/package-lock.json) | 遵循各依赖的许可；依赖通过 `npm ci` 获取，不作为源码副本提交 |

OA-Vuln-Labs `source.zip` SHA-256 `99d7d57daad5f68474a6a2a0c04be5959bae4543a9ed31a10cfc6249ebc57e64`。导入归档 SHA-256 写入本地清单并在安装时校验；Ruffle 与封面哈希由 `script/tools/check_vulnlab_node.mjs` 校验。

### Ruffle Web 文件

| 文件 | SHA-256 |
| --- | --- |
| `ruffle.js` | `ef588353471686368e505f1fbf8b29fbba2f762be5dc527d7cfcd84973ab8911` |
| `core.ruffle.3063d6eba6e1517a4f98.js` | `6edbdcc314eb9a4328b96a8885d7ebfde766dad233d8aa08e32eded0bf6605e7` |
| `core.ruffle.40449116850a3e651e6c.js` | `651cbe7f490f0e1a8e5997ab68a15afc1dd2c8ece5ff7c6ff05921c9658d334e` |
| `6bd0bf4499a1d6ead2fc.wasm` | `3461c15a73e7ce00f2c836bf9474e5150b73039d1b058e803ac31af2ec887b7d` |
| `9b62d11991d757a71e0f.wasm` | `4230b8c58c9265430b396c55afb2c55ba8e53130cf6585924a2b8b5e265f22a6` |
| `LICENSE_MIT` | `4de9338a7879c68e911742a7d691f0797ff1ef8d8a6fb978b0c711e258fe959c` |
| `LICENSE_APACHE` | `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a` |
| `LICENSE.md` | `e39a2fa3dfd7238f0924f568fabb659ee1a9d95ea6460dbae4bc9b67017a1c71` |

### 靶场卡片封面

封面来源与固定上游提交见 [`src/public/covers/README.md`](src/public/covers/README.md)。

| 文件 | SHA-256 | 许可状态 |
| --- | --- | --- |
| `dvwa.png` | `a440db6f754d51e5e5a57aad08d4b1be90a47f3f6eb63be907519e71b62a8fb8` | GPL-3.0 |
| `pikachu.png` | `390c98333dc945eaae0383017142142dc880ebe603ddc695aaecf59d6dc008f3` | Apache-2.0 |
| `xss-labs.png` | `00f0f2188ec6255b1a734b57f33dd52cab555d01e607ffe590f2812f3247a3fd` | 基于上游页面的截图；上游未声明许可 |
| `sqli-labs.jpg` | `997f27b253c2b62be209ea6e446436ca6b8c97d27b9c5dfce5b9d29abcea1559` | 上游未声明 |
| `upload-labs.jpg` | `cfebcea3f40d7dcf1b54092b4ab971520c7e159248ad986bd290b2139b49f97c` | 上游未声明 |
| `xvwa.png` | `50b29ba51dfd410c044438c60c496701e1d21fb9165b9021efafbbbbe2aaa391` | GPL-3.0 |
| `juice-shop.png` | `28392cb221e29d5fdd31853151b02c50eabf27348564381143445f0ace67fe18` | MIT |
| `webgoat.png` | `5d3ca2eda0c49cbda4de57fbd03ed832cc73865756982dcbf074bb702d5f8505` | GPL-2.0 |
| `pygoat.svg` | `b094b484fc7a06989976afc1c94703b956ca49716852d086be3575bd8940c8b4` | MIT |
| `mutillidae.svg` | `7a0432e774ea1217a48df36b3f9f338a5a94512ef5d212ae73586c336eaee375` | 本项目原创；Apache-2.0 |
| `oa-vuln-labs.svg` | `f5ae41a654970e9dd226ccd7bf026d23a9f4210f54180742546f95083570f2d3` | 本项目原创；Apache-2.0 |
