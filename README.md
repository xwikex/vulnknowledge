# vulnknowledge — 面向安全 Agent 的 GHSA 漏洞知识库

> **GitHub Advisory (GHSA) 漏洞公告的自动化知识库**：每日自动同步 → 结构化清洗 →
> JSON 分片存储 → SQLite/FTS5 本地索引。数据可直接喂给安全 Agent（AI 助手、
> MCP、自动化扫描工具），也可用 jq / sqlite3 人肉查询。
> 全仓**纯标准库、零第三方依赖**，clone 下来 5 分钟即可投入使用。

```
GitHub Advisory API
        ↓  scripts/sync_advisories.py   （自动同步，本仓库核心）
   清洗 / 去重 / 标准化
        ↓
   advisories/*.json                    （按年份分片，单文件 ≤40MB）
        ↓                              stats.json（每次运行自动重建）
   scripts/import_to_sqlite.py
        ↓
   vulnerabilities.db                    （SQLite + 可选 FTS5 全文索引）
        ↓
   安全 Agent / 分析师查询
```

## 它是什么 / 不是什么

| ✅ 是 | ❌ 不是 |
|---|---|
| GHSA 全球安全公告的**离线镜像 + 检索层** | 漏洞扫描器（不做资产发现/验证） |
| 面向 AI Agent 的结构化漏洞语料 | CVE 全量库（仅 GitHub 收录范围） |
| 自动更新的数据管道（GitHub Actions） | 实时情报推送（数据源本身有延迟） |

- **数据量**: 34,989 条公告（2017–2026），含 63,409 条受影响软件包记录、CVSS 分数、CVE 关联与完整原始 JSON
- **更新方式**: 每日自动（本仓库 Actions）+ 本地一键（见下文）
- **精确定位**: 让 Agent/工具在几毫秒内回答"哪些版本受 CVE-2024-xxx 影响？修复版本是多少？"

## 快速上手（5 分钟）

```bash
# 0) 零依赖。Python ≥3.9 即可。

# 1) 直接查 JSON（不用导入，jq 就行）
jq '.advisories[] | select(.severity=="critical") | {ghsa_id, cve_id, summary}' advisories/2026.json | head

# 2) 导入 SQLite（含 FTS5 全文索引，推荐给 Agent/高频查询）
python3 scripts/import_to_sqlite.py --fts
sqlite3 vulnerabilities.db "SELECT COUNT(*) FROM advisories;"            # → 34989

# 3) 跑测试（验证代码与数据自洽）
python3 -m unittest discover -s tests -v
```

### SQLite 查询示例

```bash
# 按 CVE 查
sqlite3 vulnerabilities.db "SELECT ghsa_id, severity, summary FROM advisories WHERE cve_id='CVE-2024-0001';"

# 按受影响包查（含修复版本）
sqlite3 vulnerabilities.db "SELECT ghsa_id, version_range, fixed_version FROM affected_packages WHERE package_name LIKE 'ghost' AND fixed_version IS NOT NULL LIMIT 10;"

# FTS5 全文搜索（summary + description，毫秒级）
sqlite3 vulnerabilities.db "SELECT ghsa_id, summary FROM advisories WHERE rowid IN
  (SELECT rowid FROM advisories_fts WHERE advisories_fts MATCH '\"command\" \"injection\"');"
```

## 仓库结构

```
vulnknowledge/
├── advisories/            # 数据（按 published_at 年份分片；>40MB 自动切 -partN）
│   ├── 2017.json ... 2026.json
├── scripts/
│   ├── sync_advisories.py      # API → JSON 同步/清洗（--full 全量 / --days N 增量）
│   └── import_to_sqlite.py     # JSON → SQLite（可选 FTS5）
├── tests/
│   ├── test_import.py          # 导入/幂等/FTS5 命中
│   └── test_sync.py            # 清洗兼容/去重/分片/确定性输出
├── .github/workflows/update.yml  # 每日自动同步 + 自动提交
├── skills/vuln-search/SKILL.md   # Agent Skill（可直接复制给 Claude Code/Hermes 等）
├── stats.json                 # 全库统计（总条数/年份/严重级别/生态分布）
├── pyproject.toml             # 项目元数据（零第三方依赖）
├── requirements.txt           # 依赖说明（纯标准库，无 pip 依赖）
├── LICENSE                    # MIT（代码）+ CC BY 4.0（数据声明）
├── README.md  CHANGELOG.md  CONTRIBUTING.md  SECURITY.md
└── .gitignore
```

## 数据格式

每个 `advisories/<年份>.json` 是一个对象：

```json
{
  "schema_version": 1,
  "year": "2026",
  "count": 9481,
  "advisories": [
    {
      "ghsa_id": "GHSA-xxxx-xxxx-xxxx",   // 主键（同步去重依据）
      "cve_id": "CVE-2026-0001",          // 关联 CVE，可能为 null
      "state": "published",               // published / withdrawn
      "severity": "critical",             // critical/high/medium/low/unknown
      "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/...",
      "summary": "标题", "description": "漏洞描述",
      "published_at": "2026-01-01T00:00:00Z",   // 决定文件归属年份
      "updated_at": "2026-01-02T00:00:00Z",
      "withdrawn_at": null,
      "source": "github_api",
      "packages": [                        // 受影响软件包
        {"ecosystem": "npm", "name": "ghost", "version_range": ">= 6.27.0, < 6.44.0",
         "introduced": null, "fixed_version": "6.44.0"}
      ],
      "raw": { ... }                       // GitHub API 完整原始报文（信息零丢失）
    }
  ]
}
```

## 统计（详见 `stats.json`）

```json
{
  "schema_version": 1,
  "total": 34989,
  "source": "GitHub Advisory Database",
  "by_year": {"2017": 221, "2018": 785, "...": "...", "2026": 9481},
  "by_severity": {"high": ..., "medium": ..., "critical": ..., ...},
  "by_ecosystem": {"npm": ..., "pip": ..., "maven": ..., ...}
}
```

## 自动维护

| 途径 | 何时 | 说明 |
|---|---|---|
| **GitHub Actions**（推荐） | 每日 UTC 04:17（北京 12:17） | 推送后自动生效：增量同步 → 测试 → 数据有变即提交回仓库；Actions 页面可手动触发 |
| 本地一键 | 任意时间 | 见下 |

```bash
# 本地更新（需 GITHUB_TOKEN 环境变量，匿名限 60 次/小时）
GITHUB_TOKEN=xxx python3 scripts/sync_advisories.py --days 7   # 增量（默认 7 天）
GITHUB_TOKEN=xxx python3 scripts/sync_advisories.py --full     # 首次/全量重建

# 手动触发 GitHub Actions 增量更新（免本地环境）：
#   repo → Actions → update-knowledge → Run workflow
```

> 增量同步按 `updated_at` 回看 N 天拉取，按 `ghsa_id` 幂等合并——重复运行安全，
> 数据无变化时不会产生 git 提交（文件确定性输出，字节级稳定）。

## 面向安全 Agent 接入

本库设计目标之一是作为 **Agent 的漏洞知识库**。三种接入方式：

**① 本地 SQLite 文件（推荐 Agent/工具直连）** — 导入一次后，让 Agent 用 sqlite3 查询：

```bash
python3 scripts/import_to_sqlite.py --fts
```

**② 复制 `skills/vuln-search/SKILL.md`**（已内置本仓库）— 支持 skills 的 Agent
（Claude Code / Hermes / 等）可直接引用：

```bash
# 把技能文件放进 Agent 的 skills 目录即可，例如:
cp -r skills/vuln-search ~/.hermes/skills/        # Hermes
cp -r skills/vuln-search .claude/skills/          # Claude Code
```

技能内含 SQL 查询配方（按 CVE/包名/全文/严重级别）与输出规范，Agent 加载后即可回答
"哪个版本受 CVE-xxx 影响？修复版本是多少？" 这类问题。

**③ REST 化** — 若需跨机/多 Agent 共享，可基于 SQLite 包一层 FastAPI 只读接口
（生产环境建议加 Bearer Token；本仓库刻意保持零依赖，故不内置服务端）。

## 许可与致谢

- **代码**（scripts/ tests/ .github/）：MIT License，Copyright (c) 2026 xwikex
- **数据**（advisories/ stats.json）：源自 [GitHub Advisory Database](https://github.com/advisory-database/advisories)，
  CC BY 4.0，分发须保留署名并附上游许可链接（详见 [LICENSE](LICENSE)）
- 数据版权归各安全公告作者及 GitHub 所有
