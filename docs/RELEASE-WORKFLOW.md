# 发版候选包工作流

`.github/workflows/release.yml` 只接受手动运行。输入必须是已存在、版本号一致、指向已审查提交的 `v*` tag。`target` 默认 `windows`，还可选 `mac-arm`、`mac-intel`；只有显式选择 `all` 才会构建三个平台并建立草稿 Release。推送 tag 不触发构建。

运行前先检查本月 Actions 额度、预算、进行中与排队任务，估算本次所选 runner 的分钟数。本机能完成的检查应先通过；公共问题先在本机解决，再按需运行单平台。完整 `all` 矩阵只用于准备好公开发行的最终候选版本。此文档描述流程，不代表平台验收已经通过。

## 每次运行的检查

准备任务检出 tag 的完整历史，核对 tag 对应提交与版本，并执行代码、前端、工具和私有词表隐私检查。后续构建任务固定检出同一个 SHA。每个原生 runner 都重新执行 Rust 格式检查、测试和 Clippy，再构建带 Tauri 更新签名的安装包。Windows 仅构建和发布 NSIS 安装包；macOS 构建应用及 DMG。

构建后只在对应的 GitHub 托管原生 runner 安装并启动候选包：macOS 以只读方式挂载 DMG、复制应用、核对架构和完整包签名，然后观察应用进程稳定运行；Windows 将 NSIS 安装包静默安装到 runner 临时目录，核对 x64 可执行文件和应用窗口，并只结束这次启动的测试进程。启动检查不导入账号、不输入凭据、不发起 Cloudflare 操作，也不证明业务网络功能、最低系统版本兼容性或 Windows Authenticode/macOS 公证。macOS 启动检查只观察应用进程，不宣称自动验证了窗口内容。

候选包和启动证据随后一起经过上传前的解包隐私扫描。每个平台的证据记录 tag、来源 SHA、安装包和更新包的 SHA-256、原生架构与启动结果；记录不包含 runner 路径或用户数据。临时 Actions artifact 只保留 1 天，应及时下载或汇总。三个平台齐备时，汇总脚本再次验证来源 SHA、原生证据、更新签名文件存在且非空以及文件散列，然后产生 `latest.json`、`SHA256SUMS` 和草稿资源；校验和覆盖安装包、更新包及 `latest.json`。签名文件存在不等于密码学验签，公开发布前还须用真实公钥独立验签。

## 复用三次单平台运行

单平台运行不会建立草稿。可以在一个检出同一 tag 的本地工作目录中，把三个成功运行的 `candidate-<target>` artifact 分别下载到 `candidates/candidate-<target>/`。示例中的 run ID 应替换为实际成功运行的编号：

```sh
gh run download <mac-arm-run-id> -n candidate-aarch64-apple-darwin -D candidates/candidate-aarch64-apple-darwin
gh run download <mac-intel-run-id> -n candidate-x86_64-apple-darwin -D candidates/candidate-x86_64-apple-darwin
gh run download <windows-run-id> -n candidate-x86_64-pc-windows-msvc -D candidates/candidate-x86_64-pc-windows-msvc
GITHUB_REPOSITORY="xiaogan123/short-link-generator" RELEASE_TAG="v$(node -p 'require("./package.json").version')" RELEASE_SHA="$(git rev-parse HEAD)" node scripts/release-manifest.mjs candidates --require-evidence
```

`release-manifest.mjs` 遇到不同提交、缺少原生启动证据、更新签名文件或文件散列不符时会拒绝汇总。检查 `release-assets/`、`latest.json`、`SHA256SUMS` 和发版说明后，再决定是否建立或公开 Release；本地汇总命令本身不会上传或发布。本机若自行重建同一候选包，构建进程还须显式导出与正式渠道一致的 `SLG_UPDATER_PUBLIC_KEY` 和 `SLG_UPDATER_ENDPOINT`，并使用 `release-config.json`；仅有配置文件不足以设置编译时环境变量。

本机 Apple 芯片候选包可以使用 `schema: 2`、`method: "manual-local"` 的人工验收记录复用。记录分别保留实际构建提交 `buildSha` 和最终 tag 提交 `reviewedSha`，必须按实际构建记录填写；直接从最终提交构建时，两者相同。运行 `node scripts/release-app-inputs.mjs <buildSha> <reviewedSha>` 得到应用输入清单的 SHA-256 与文件数；汇总时会从两个 Git 提交重新生成并逐项比较。清单默认包含全部已跟踪文件，包括 `src/`、`src-tauri/`、`edge/`、`public/`、`.cargo/`、构建配置与工具链配置；只排除已明确列出的发版工作流、脚本、说明和生成物。未提交的应用文件、应用目录内被忽略的文件及本机 `.env*` 文件会拒绝复用。此证明只比较仓库输入，不证明外部工具链或本机环境完全一致。

人工记录还需包含实际系统版本、GUI 与进程观察结果、安装包和更新包散列、架构及签名检查结果、生成的 `release-config.json` 散列、更新公钥散列与发布地址、原始构建参数的散列及不含本机路径的参数类别。填写者应依据私有的实际验证记录填写；汇总器只能核对 Git 输入、字段格式和制品散列，不能替代人工 GUI 观察或独立的更新签名验签。最低系统版本 `11.0` 是包内元数据，不能写成在 macOS 11 上实际启动过。本机候选证据不能用于 Intel Mac 或 Windows 平台。

GitHub 的手动触发输入、原生 runner 标签与 artifact 保留期以 [workflow_dispatch 文档](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)、[runner 参考](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)和[artifact 文档](https://docs.github.com/en/actions/tutorials/store-and-share-data)为准。Windows 静默安装使用 Tauri 所述的 NSIS `/S` 参数；见 [Tauri Windows 安装包说明](https://v2.tauri.app/distribute/windows-installer/)。
