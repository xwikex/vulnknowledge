---
name: vuln-search
description: 查询本地 GHSA 漏洞知识库（vulnknowledge）。当用户询问某个 CVE、软件包、
  版本的漏洞影响、修复版本，或按关键词/严重级别检索漏洞时使用。数据源为 GitHub
  Advisory Database，仅覆盖其收录范围。
---

# vuln-search

本地知识库: `<REPO>/vulnerabilities.db`
由以下命令生成（生成后任何目录都可查询）:

```bash
python3 <REPO>/scripts/import_to_sqlite.py --fts
```

## 查询配方

按 CVE 精确查:

```sql
SELECT ghsa_id, severity, summary, published_at, updated_at
FROM advisories WHERE cve_id = '<CVE>';
```

按受影响包名查（含受影响区间与修复版本，最常用）:

```sql
SELECT a.ghsa_id, a.severity, a.summary,
       p.ecosystem, p.package_name, p.version_range, p.fixed_version
FROM affected_packages p
JOIN advisories a ON a.ghsa_id = p.ghsa_id
WHERE p.package_name LIKE '%<pkg>%'
  AND p.fixed_version IS NOT NULL
ORDER BY a.severity DESC
LIMIT 20;
```

全文搜索（summary + description，FTS5 毫秒级; 多词默认 AND）:

```sql
SELECT ghsa_id, summary, severity
FROM advisories
WHERE rowid IN (
  SELECT rowid FROM advisories_fts
  WHERE advisories_fts MATCH '"<word1>" "<word2>"'
)
LIMIT 20;
```

按严重级别 + 时间窗口统计:

```sql
SELECT severity, COUNT(*) FROM advisories
WHERE published_at >= '2026-01-01'
GROUP BY severity;
```

## 输出规范

- 每次给出结果时附 `ghsa_id`（可溯源: https://github.com/advisories/<ghsa_id>）
- 区分"无此包记录"与"包存在但无已修复版本"两种空结果
- 明确说明: 数据覆盖范围为 GitHub Advisory，非全量 CVE；withdrawn 公告 state='withdrawn'，查询时可过滤
