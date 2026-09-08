# Security Policy

## Supported Versions

本仓库是**数据快照仓库**：`advisories/` 是只读数据产物，`scripts/` 是轻量工具。
我们仅对最新 `main` 分支提供安全支持。

| 组件 | 支持策略 |
|---|---|
| scripts/ 工具代码 | 最新 main 分支 |
| advisories/ 数据 | 快照性质，随上游 GitHub Advisory 更新 |

## 数据本身的漏洞？

本仓库**不负责**漏洞信息的真伪判定——每条公告的权威来源是
[GitHub Advisory Database](https://github.com/advisory-database/advisories)。
如发现某条公告内容有误，请直接向**上游**提交修正。

## 报告代码问题

如发现 `scripts/` 或 `.github/` 中的安全问题（如命令注入、路径穿越、
凭据泄漏等），请**不要**公开开 issue，直接发邮件到维护者邮箱：

- 邮箱: xwikex@users.noreply.github.com
- 请在主题注明 `[vulnknowledge-security]`

我们会尽快确认并修复。修复发布前请勿公开细节。

## 安全设计说明

- `sync_advisories.py` 只读公开数据，不使用任何写入凭据；
  GitHub Actions 中仅使用最低权限的 `GITHUB_TOKEN`（contents: write）
- 仓库不含任何硬编码密钥；如需调用 API 请用环境变量 `GITHUB_TOKEN`
- 数据文件全部来自公共 API，无用户可控输入路径，攻击面极小
