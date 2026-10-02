# 发版候选包工作流

`.github/workflows/release.yml` 只接受手动运行。输入必须是已存在、版本号一致、指向已审查提交的 `v*` tag。`target` 默认 `windows`，还可选 `mac-arm`、`mac-intel`、`windows-intel`；最后一项只在 Windows 和 Intel Mac 上分别原生构建，适合复用已经在本机验证的 Apple 芯片候选包。只有显式选择 `all` 才会构建三个平台并建立草稿 Release。推送 tag 不触发构建。

运行前先检查本月 Actions 额度、预算、进行中与排队任务，估算本次所选 runner 的分钟数。本机能完成的检查应先通过；公共问题先在本机解决，再按需运行单平台。完整 `all` 矩阵只用于准备好公开发行的最终候选版本。此文档描述流程，不代表平台验收已经通过。

日常原生检查可手动运行 `Checks` 工作流，选择一个 `platform`。`include_source` 默认开启，同时运行 Linux 源码检查；仅当已有通过的源码证据、后续差异已审查且本地回归通过时，才可关闭它以单独验证失败的平台。普通 push 和 PR 仍执行源码检查。原生测试保留成功用例的输出，以区分实际执行的系统检查和环境限制导致的跳过；这不代替安装包与升级验收。

## 每次运行的检查

准备任务检出 tag 的完整历史，核对 tag 对应提交与版本，并执行代码、前端、工具和私有词表隐私检查。后续构建任务固定检出同一个 SHA。每个原生 runner 都重新执行 Rust 格式检查、测试和 Clippy，再构建带 Tauri 更新签名的安装包。Windows 仅构建和发布 NSIS 安装包；macOS 构建应用及 DMG。

构建后只在对应的 GitHub 托管原生 runner 安装并启动候选包：macOS 以只读方式挂载 DMG、复制应用、核对架构和完整包签名，然后观察应用进程稳定运行；Windows 将 NSIS 安装包静默安装到 runner 临时目录，核对 x64 可执行文件和应用窗口，并只结束这次启动的测试进程。启动检查不导入账号、不输入凭据、不发起 Cloudflare 操作，也不证明业务网络功能、最低系统版本兼容性或 Windows Authenticode/macOS 公证。macOS 启动检查只观察应用进程，不宣称自动验证了窗口内容。

每个原生候选包在启动前，先用正式更新公钥对更新包和签名做密码学验证，同时检查包签名、签名说明和密钥标识。失败时不启动候选包。候选包随后经过解包隐私扫描；构建成功且任务未取消时，原生验收失败仍执行隐私扫描，但只有原生验收与隐私扫描都通过才上传 artifact。每个平台的证据记录 tag、来源 SHA、安装包、更新包和签名文件的 SHA-256、更新公钥散列、原生架构与启动结果；不包含 runner 路径或用户数据。临时 Actions artifact 只保留 1 天，应及时下载或汇总。

三个平台齐备时，汇总脚本再次核对来源 SHA、原生证据和文件散列，并对每个更新包用正式公钥重新验签，再生成 `latest.json`、`SHA256SUMS` 和草稿资源。缺少公钥、签名损坏、签名公钥不匹配或更新包被替换都会拒绝汇总。校验和覆盖安装包、更新包及 `latest.json`。

## 复用三次单平台运行

单平台运行不会建立草稿。可以在一个检出同一 tag 的本地工作目录中，把三个成功运行的 `candidate-<target>` artifact 分别下载到 `candidates/candidate-<target>/`。先将 `SLG_UPDATER_PUBLIC_KEY` 环境变量设置为与客户端构建一致的正式更新公钥。示例中的 run ID 应替换为实际成功运行的编号：

```sh
gh run download <mac-arm-run-id> -n candidate-aarch64-apple-darwin -D candidates/candidate-aarch64-apple-darwin
gh run download <mac-intel-run-id> -n candidate-x86_64-apple-darwin -D candidates/candidate-x86_64-apple-darwin
gh run download <windows-run-id> -n candidate-x86_64-pc-windows-msvc -D candidates/candidate-x86_64-pc-windows-msvc
GITHUB_REPOSITORY="xiaogan123/short-link-generator" RELEASE_TAG="v$(node -p 'require("./package.json").version')" RELEASE_SHA="$(git rev-parse HEAD)" node scripts/release-manifest.mjs candidates --require-evidence
```

使用 `windows-intel` 时，Windows 与 Intel Mac 的两个 artifact 来自同一次运行，各自保留原生证据和隐私检查；不会构建 Apple 芯片包，也不会创建草稿。仍须补齐符合下述要求的本机 Apple 芯片候选包，再通过相同的三平台严格汇总。任何平台失败后先定位，只重新执行需要修复的平台。

`release-manifest.mjs` 遇到不同提交、缺少原生启动证据、更新签名无效、公钥不匹配或文件散列不符时会拒绝汇总。检查 `release-assets/`、`latest.json`、`SHA256SUMS` 和发版说明后，再决定是否建立或公开 Release；本地汇总命令本身不会上传或发布。本机若自行重建同一候选包，构建进程还须显式导出与正式渠道一致的 `SLG_UPDATER_PUBLIC_KEY` 和 `SLG_UPDATER_ENDPOINT`，并使用 `release-config.json`；仅有配置文件不足以设置编译时环境变量。

本机 Apple 芯片候选包可以使用 `schema: 2`、`method: "manual-local"` 的人工验收记录复用。记录分别保留实际构建提交 `buildSha` 和最终 tag 提交 `reviewedSha`，必须按实际构建记录填写；直接从最终提交构建时，两者相同。运行 `node scripts/release-app-inputs.mjs <buildSha> <reviewedSha>` 得到应用输入清单的 SHA-256 与文件数；汇总时会从两个 Git 提交重新生成并逐项比较。清单默认包含全部已跟踪文件，包括 `src/`、`src-tauri/`、`edge/`、`public/`、`.cargo/`、构建配置与工具链配置；只排除已明确列出的发版工作流、脚本、说明和生成物。未提交的应用文件、应用目录内被忽略的文件及本机 `.env*` 文件会拒绝复用。此证明只比较仓库输入，不证明外部工具链或本机环境完全一致。

人工记录还需包含实际系统版本、GUI 与进程观察结果、安装包和更新包散列、架构及签名检查结果、生成的 `release-config.json` 散列、更新公钥散列与发布地址、原始构建参数的散列及不含本机路径的参数类别。`osVersion` 填实际测试系统版本，不固定为某次本机快照。本机候选证据不能用于 Intel Mac 或 Windows 平台。

本机候选作为正式发行物复用前，最低系统、原生签名及公证状态、本机环境差异都必须完成核实。`manual-local` 记录还必须具备下列字段；缺失或仍为旧记录中的 `minimumSystemRuntimeTested: false` 时，严格汇总会拒绝该候选：

| 字段 | 必须据实记录的内容 |
| --- | --- |
| `minimumSystemVersionMetadata` | 候选包实际元数据中的最低系统版本，须与已审查 Git 提交的 `src-tauri/tauri.conf.json` 一致；当前为 `11.0`。 |
| `minimumSystemRuntimeTested` | 只有同一候选确实在声明最低版本上完成原生启动和 GUI 验证，才能填 `true`。 |
| `minimumSystemRuntime` | 实际 `osVersion`、`host: "darwin-arm64"`、均为 `true` 的 `architectureVerified` / `processAlive` / `guiObserved`、与外层一致的 `installerSha256` / `updaterSha256`，以及私有验证报告的 `reportSha256`。 |
| `nativeSigning` | 当前候选必须为实际核实的固定证书 `self-signed`，`identityVerified: true`、`notarization: "not-notarized"`，并包含下述证书和 DR 验证字段；人工本机证据还须保留私有签名核查报告的 `reportSha256`。历史 `ad-hoc` 或其他身份记录不能代替当前固定身份闸。 |
| `environmentVerification` | `differencesReviewed: true`、`compatibleWithRelease: true` 以及私有环境核查报告的 `reportSha256`。报告应绑定本次构建提交及候选散列，核对实际 Node / Rust / Xcode / SDK、依赖和构建参数与发行流程的差异，说明相关差异为何不影响本次制品。 |

最低版本比较允许等价的零补丁写法，如 `11.0` 与 `11.0.0`；在更高版本（包括更高补丁版本）启动不构成最低版本运行证据。包内最低版本元数据、较新 macOS 上的成功启动、Git 输入一致，都不能代替该验证。缺少能运行声明最低版本的原生或已验证等价环境时，保留缺口，本机包只能作为候选，不能填造验证记录或通过调高最低系统需求逃避验证。

历史发行曾允许临时签名且未公证的 macOS 包；当前候选改为下述固定证书自签身份，旧 `ad-hoc` 记录不再满足当前汇总闸。仍不要求购买 Developer ID 或 Apple 公证。`signatureVerified: true` 必须来自实际候选应用的完整性验签；独立的更新签名不证明原生签名或公证。将来更换为 Developer ID 或声明公证通过，须单独审查身份迁移并更新策略与真实证据。

填写者应依据私有实际记录填写，原始日志、路径、截图和环境报告留在私有位置，候选 JSON 只保存上述结果与报告散列。汇总器核对 Git 输入、声明的最低版本、字段约束与制品散列，并重新验证更新签名；报告散列不是运行测试或身份核验的替代品，仍须审查其对应记录。托管 runner 保留 `schema: 1` 并补充实际自签名核查证据；启动结果同样不能被表述为最低系统运行或 Apple 公证已通过。三平台汇总成功只说明已通过脚本规定的证据检查，公开发行仍须完成当前候选的其他验收与隐私检查。

## 稳定的 macOS 自签身份

后续正式 macOS 构建使用 `scripts/stable-macos-sign.mjs` 包装构建命令；开发配置仍可使用 `signingIdentity: "-"`。发行 wrapper 缺证书、口令或预期指纹即失败，不退回临时签名。现有临时签名记录仍只能据实标注；不能拿它证明稳定身份。自签名保持未经过 Apple 公证的发行政策，不要求购买 Developer ID，也不使 Gatekeeper 自动认可发布者。

长期使用同一份加密 P12 和私钥，固定应用标识 `org.shortlink.generator`。加密 P12、独立口令文件及离线备份保存在仓库和应用用户数据之外的私有目录；输入文件权限必须为仅所有者可读写。证书公开 SHA-256 指纹单独固定，名称相同不能替代指纹匹配。不要每次构建重新生成证书。

macOS 凭据 helper 的两个已签名归档固定放在 `src-tauri/native/credential-helper-archives/aarch64-apple-darwin.zip` 和 `src-tauri/native/credential-helper-archives/x86_64-apple-darwin.zip`。构建任务先核对批准记录、归档 SHA-256、签名证书、对应架构 CDHash、完整目录字节和 Info.plist，再按目标架构暂存 helper，随后才打包应用；缺项或不匹配即停止。每次界面更新复用同一份已审查归档，不重编译或重签 helper，也不从未批准路径自动下载。归档 ZIP 及其解包内容须检查本机 UID/GID、所有者名、扩展属性和其他元数据，不得携带本机账户或私有数据。

| 构建输入 | 用途 |
| --- | --- |
| `SLG_MACOS_SIGNING_P12_PATH` 或 `SLG_MACOS_SIGNING_P12_BASE64` | 本地加密 P12 的绝对私有路径，或 CI 进程中的 base64；二选一。 |
| `SLG_MACOS_SIGNING_P12_PASSWORD_FILE` 或 `SLG_MACOS_SIGNING_P12_PASSWORD` | 私有口令文件或进程环境；二选一，不把口令写进命令行。 |
| `SLG_MACOS_CERT_SHA256` | 预期公开证书 DER 的 SHA-256；本地、原生验收和汇总必须相同。 |
| `SLG_RCODESIGN_PATH` | 已验证的原生 `rcodesign` 0.29.0 绝对路径；取得工具时不加载任何发行秘密。 |

设置好这些进程输入后，本地构建命令为：

```sh
ulimit -S -c 0
ulimit -H -c 0
node scripts/stable-macos-sign.mjs -- npm run tauri -- build --config release-config.json --bundles app,dmg
```

`scripts/rcodesign-tool.mjs` 固定上游版本及 ARM、Intel 各自的压缩包和可执行文件 SHA-256，只提取已知普通文件，并用 macOS 检查架构与上游签名。CI 在取得签名秘密之前下载工具；本地可通过同一模块准备工具。构建入口再次核验实际文件，拒绝自动升级、未知工具和架构不匹配。固定哈希与上游签名不等于可复现构建证明，更新工具版本需重新审查。

wrapper 在进程内核对 P12 口令、证书自签名、用途、私钥匹配及公开指纹，再用一次性随机口令重封装到仅所有者可访问的临时目录。未加密私钥不落盘，长期及临时口令均不进入 argv。签名器从权限受限的临时文件读取输入，禁止网络请求和隐式配置；原生验签仍由 Apple 工具完成。签名子进程不继承更新私钥、加载器选项或任意签名配置。JavaScript 字符串及第三方进程内存不能保证安全擦除，关闭 core dump 也不替代主机安全。

签名 shim 对外层应用嵌入“固定 identifier 且固定证书指纹”的 designated requirement（DR），按 Tauri 的顺序处理内部代码。整个签名流程不创建签名钥匙串、不导入私钥、不修改系统信任或真实凭据 ACL，也不需要构建者确认钥匙串授权。构建前后只读比较搜索列表与默认库，若出现差异则失败，不整表覆盖恢复。正常完成、构建失败和可处理的中断都会清理临时文件；清理失败会拒绝候选。强制终止或断电可能留下私有临时目录，需确认相关进程退出后单独清理，不能宣称所有异常均已清理。

GitHub 的 `release` 环境需新增 `MACOS_SIGNING_P12_BASE64`、`MACOS_SIGNING_P12_PASSWORD` 两个 secret，以及公开变量 `MACOS_SIGNING_CERT_SHA256`。只有 macOS 打包和隐私扫描步骤取得签名秘密；Windows 构建保持原方式。隐私扫描在内存中比较加密容器、口令以及实际解密私钥的 PKCS1/PKCS8 DER、PEM 和常见编码，扫描结束清理可写缓冲区，公开证书不当作秘密。解包和验签子进程不继承这些输入。不新增 Apple ID 或公证秘密；先完成本机验证，再按既有额度纪律估算所选原生 runner 消耗，此流程本身不授权触发 CI。

原生验收从实际候选应用导出公开证书，核实自签名与预期 SHA-256，执行完整性验签，并检查与求值实际 DR。`nativeSigning` 记录 `identity: "self-signed"`、`notarization: "not-notarized"`、证书 `certificateSha256` / `certificateSha1`、固定 `identifier`、`designatedRequirement` 及其 SHA-256，并记录均为 `true` 的 `identityVerified` / `signatureVerified` / `requirementVerified` / `certificateSelfSignatureVerified`。汇总提供相同 `SLG_MACOS_CERT_SHA256`，才接受这些记录；只有 identifier、CN、cdhash 或替代证书的记录均拒绝。安装包和更新包仍须各自绑定实际散列与独立更新签名。

当前 macOS 候选还必须提供 `macArtifacts`（`schema: 1`）：`updaterBundleVerified`、`contentMatchVerified`、`modesMatchVerified` 均为 `true`，`bundleManifestSha256`、`entryCount`、`fileCount` 绑定包内完整目录、文件字节与 SHA-256、权限和链接目标。原生检查安全解包更新 tar，分别对 DMG、tar 和构建目录中的 app 核实固定证书与实际 DR，并比较三者清单；`updaterSigning` 和 `buildSigning` 保存对应的真实签名结果。托管 runner 必须记录 `buildBundleCompared: true`；人工本机核查若已无构建目录，可记录 `false` 并省略 `buildSigning`，仍须完成 DMG 与 tar 比较。清单不包含本机绝对路径。汇总器重新读取实际 tar、重算清单并核对以上证据；缺失稳定证书指纹、旧临时签名记录、缺少比较记录、字节或权限不一致均拒绝当前候选。历史临时签名记录只能作为历史证据，不能代替此闸。

归档解析先验证整个路径与链接图，再写入新的私有目录；支持普通 USTAR、GNU 长名称、受限 PAX 元数据和应用内部链接，拒绝路径穿越、大小写/Unicode 重复路径、链接父目录、越界或循环链接、硬链接、设备、稀疏文件及不支持的扩展元数据。压缩输入最多 256 MiB、展开数据最多 512 MiB、头记录最多 20,000 条；超过限制须调整并重新审查，不能跳过检查。隐私检查使用同一解包器，并在提取前扫描完整展开字节，覆盖不进入文件清单的头部、元数据和填充区；原始字节不写入公开证据。每次发行还须检查源码、安装包、更新包、发版说明、公开仓库和发布后的匿名下载资源；任一私有路径、账户、凭据或用户数据泄露未关闭时不得公开。外层 Minisign 验签本身不证明内部原生签名。

固定主应用证书是 helper 身份绑定的一部分；每次完整升级仍须用真实旧版、候选版和安装路径做原生凭据连续性验收。首次采用该身份前，必须用同一证书签两个确实不同的二进制，确认代码哈希不同、固定 DR 一致，并让 A 满足 B 的 DR、B 满足 A 的 DR。这仅验证签名要求的连续性，不证明钥匙串跨版本授权连续性。macOS 在普通 ACL 之外还验证 partition；自签代码可能使用随二进制变化的 CDHash。即使证书和 identifier 不变，升级后也可能再次要求授权。

自动工具测试、mock OS 命令以及新建自定义钥匙串的成功结果，均不能代替真实登录钥匙串的升级验收；不同库的格式和 partition 行为可能不同。发布前须以实际旧版与候选版、真实安装路径和原有条目验证升级后读取，分别记录首次授权、同版冷启动和跨版本结果。不得以同 DR、同版重启成功或新库夹具成功宣称跨版本免授权。当前跨版本授权故障未关闭前不得发布本候选。

旧临时签名迁移到自签名、证书丢失或轮换、将来换成 Developer ID，都需要单独处理迁移。尊重系统提示与用户选择，不静默改 ACL、删除重建条目或承诺所有弹框消失。系统锁定和自定义访问限制仍可能要求授权。

签名要求的依据见 [Apple TN2206](https://developer.apple.com/library/archive/technotes/tn2206/_index.html) 和 [Apple Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)。额外的 partition 分类与验证见 Apple Security 源码中的 [clientid.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/securityd/src/clientid.cpp#L187) 和 [acls.cpp](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/securityd/src/acls.cpp#L119)。

GitHub 的手动触发输入、原生 runner 标签与 artifact 保留期以 [workflow_dispatch 文档](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)、[runner 参考](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)和[artifact 文档](https://docs.github.com/en/actions/tutorials/store-and-share-data)为准。Windows 静默安装使用 Tauri 所述的 NSIS `/S` 参数；见 [Tauri Windows 安装包说明](https://v2.tauri.app/distribute/windows-installer/)。
