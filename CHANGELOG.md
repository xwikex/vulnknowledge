# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格。
数据快照的自动更新提交见 git 历史（由 GitHub Actions `update` 工作流产生）。

## [Unreleased]

### 新增
- `pyproject.toml`：项目元数据（零第三方依赖，`license` 注明 MIT(代码)/CC BY 4.0(数据)）
- `requirements.txt`：依赖说明（纯标准库，占位说明）
- `skills/vuln-search/SKILL.md`：Agent Skill 落地为仓库文件（SQL 查询配方 + 输出规范）

## [1.0.0] - 2026-09-02

### 新增
- 初始发布：34,989 条 GitHub Advisory (GHSA) 漏洞公告（2017–2026）
- `scripts/sync_advisories.py`：GitHub Advisory API 自动同步
  - 清洗/去重/标准化（ghsa_id 主键幂等合并，raw 全量留档）
  - 全量（`--full`）与增量（`--days N`，默认 7 天回看）两种模式
  - 按年份分片输出 `advisories/*.json`，单文件超 40MB 自动切 `-partN`
  - 自动重建 `stats.json`；纯标准库、确定性输出（数据不变则 git 零 diff）
- `scripts/import_to_sqlite.py`：JSON 分片 → SQLite（含可选 FTS5 全文索引，
  触发器自动同步），纯标准库
- `tests/`：`test_import.py`（导入/幂等/FTS5 命中）、`test_sync.py`
  （清洗形态兼容/去重/分片/确定性）
- `.github/workflows/update.yml`：每日自动同步（UTC 04:17 / 北京 12:17），
  数据有变即提交回仓库；支持手动触发
- 社区文档：`README.md`、`CONTRIBUTING.md`、`SECURITY.md`、`LICENSE`
  （MIT + CC BY 4.0 数据声明）
