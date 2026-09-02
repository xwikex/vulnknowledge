# vulnerability-knowledge-base

GitHub Advisory (GHSA) 漏洞知识库离线数据包 —— 由 vuln-sync 同步生成。

- **数据源**: GitHub Advisory Database（[api.github.com/advisories](https://docs.github.com/rest/security-advisories/global-advisories)）
- **数据量**: 34989 条公告（2017~2018~2019~2020~2021~2022~2023~2024~2025~2026），本快照生成于 2026-09-02T15:13:53Z
- **格式**: 每文件为一个 JSON 数组对象，按公告发布时间年份分片，见下方字段说明

## 目录结构

```
├── advisories/          # 数据分片（按年份）
│   ├── 2017.json
│   └── ...
├── stats.json           # 全库统计
└── import_to_sqlite.py  # 一键还原为 SQLite 数据库（纯标准库，无需 pip）
```

## 单条公告字段

| 字段 | 类型 | 说明 |
|---|---|---|
| ghsa_id | string | GitHub 安全公告唯一编号（主键） |
| cve_id | string\|null | 关联 CVE 编号 |
| state | string | `published` / `withdrawn` |
| severity | string | critical/high/medium/low/none/unknown |
| cvss_score | number\|null | CVSS v3 分数 |
| cvss_vector | string\|null | CVSS 向量串 |
| summary | string | 公告标题 |
| description | string | 漏洞描述 |
| published_at / updated_at / withdrawn_at | string\|null | ISO 8601 UTC 时间戳 |
| source | string | 数据来源（github_api / github_repo） |
| packages | array | 受影响软件包：`ecosystem` `name` `version_range` `introduced` `fixed_version` |
| raw | object | GitHub API 完整原始 JSON（references/cwes 等，信息零丢失） |

## 使用

**还原为 SQLite（可直接查询/建索引）**
```bash
python3 import_to_sqlite.py                # 生成 vulnerabilities.db
python3 import_to_sqlite.py -o my.db       # 指定输出文件
python3 import_to_sqlite.py --fts          # 同时创建 FTS5 全文索引
sqlite3 vulnerabilities.db "SELECT COUNT(*) FROM advisories;"
```

**直接用 jq 查询 JSON**
```bash
jq -r '.advisories[] | select(.severity=="critical") | .ghsa_id' advisories/2026.json | head
```

## 字段统计

```json
{
  "total": 34989,
  "generated_at": "2026-09-02T15:13:53Z",
  "source": "GitHub Advisory Database",
  "by_year": {
    "2017": 221,
    "2018": 785,
    "2019": 745,
    "2020": 1398,
    "2021": 2610,
    "2022": 8767,
    "2023": 3377,
    "2024": 3705,
    "2025": 3900,
    "2026": 9481
  },
  "by_severity": {
    "medium": 15126,
    "high": 12622,
    "critical": 4627,
    "low": 2584,
    "unknown": 30
  },
  "by_ecosystem": {
    "composer": 12451,
    "maven": 12280,
    "pip": 10879,
    "npm": 9450,
    "go": 7471,
    "nuget": 6320,
    "rust": 2395,
    "rubygems": 1878,
    "erlang": 137,
    "swift": 72,
    "actions": 63,
    "pub": 13
  }
}
```

## 许可与致谢

- 数据版权归各公告作者/GitHub 所有，分发前请自行确认符合
  [GitHub 安全公告条款](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)
  与各 CVE 条目作者的许可要求。
- 本项目仅为数据的本地化整理与再分发示例。
