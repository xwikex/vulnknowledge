#!/usr/bin/env python3
"""GitHub Advisory API 同步脚本 —— 面向安全 Agent 的漏洞知识库自动维护核心。

数据流水线:
    GitHub Advisory REST API
        ↓  本脚本 (--full 全量 / --days N 增量)
    清洗 / 去重 / 标准化 (normalize_item)
        ↓
    advisories/<年份>.json      (按 published_at 年份分片, >40MB 自动切 -partN)
        ↓
    stats.json                  (每次运行后自动重新生成)

设计要点:
- 纯标准库 (urllib/json/sqlite3)，无第三方依赖，可在任意 Python ≥3.9 环境运行
- 支持 GitHub Actions 定时执行；认证走 GITHUB_TOKEN 环境变量（可选，匿名限 60 次/h）
- 幂等：按 ghsa_id 去重合并，重复运行不产生脏数据
- 确定性输出：文件内按 (published_at, ghsa_id) 排序，数据未变时 git 零 diff

用法:
    python3 scripts/sync_advisories.py --full              # 全量拉取（需要 Token，约 350 页）
    python3 scripts/sync_advisories.py --days 7            # 增量：拉最近 7 天更新（默认）
    GITHUB_TOKEN=xxx python3 scripts/sync_advisories.py --full
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

API_URL = "https://api.github.com/advisories"
PER_PAGE = 100
CHUNK_TARGET_MB = 40          # 单数据文件目标上限（GitHub 单文件硬限制 100MB，留余量）
SCHEMA_VERSION = 1
USER_AGENT = "vulnknowledge-sync/1.0"
DEFAULT_DATA_DIR = "advisories"
DEFAULT_STATS = "stats.json"


class SyncError(Exception):
    """同步失败（限流/网络/认证）"""


# ---------------------------------------------------------------------------
# HTTP / GitHub API
# ---------------------------------------------------------------------------

def _request(url: str, token: str | None) -> tuple[list, str | None]:
    """GET 一页；返回 (items, next_url)。限流/认证失败抛 SyncError。"""
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    })
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            items = json.loads(resp.read().decode("utf-8"))
            next_url = None
            for part in resp.headers.get("Link", "").split(","):
                if 'rel="next"' in part:
                    next_url = part[part.find("<") + 1:part.find(">")]
            return items, next_url
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            retry = e.headers.get("Retry-After")
            raise SyncError(f"GitHub API 限流 (HTTP {e.code})，请稍后重试"
                            + (f"，Retry-After={retry}s" if retry else "")
                            + "；或设置 GITHUB_TOKEN 提高配额") from e
        if e.code == 401:
            raise SyncError("GitHub API 认证失败 (HTTP 401)，请检查 GITHUB_TOKEN") from e
        raise SyncError(f"GitHub API 请求失败: HTTP {e.code} ({url})") from e
    except urllib.error.URLError as e:
        raise SyncError(f"网络错误: {e.reason}") from e


def fetch_advisories(since_date: str | None, token: str | None,
                     max_pages: int) -> list[dict]:
    """分页拉取公告（2026 版 API 使用 Link 头 after 游标翻页）。

    since_date: 'YYYY-MM-DD'，只拉 updated_at 晚于该日期的公告；None=全量。
    """
    url = f"{API_URL}?per_page={PER_PAGE}"
    if since_date:
        url += f"&updated={since_date}"
    items: list[dict] = []
    pages = 0
    while url and pages < max_pages:
        page_items, url = _request(url, token)
        items.extend(page_items)
        pages += 1
    if url:
        raise SyncError(f"超过最大页数限制 ({max_pages})，数据可能不完整，请用 --max-pages 调大后重跑")
    return items


# ---------------------------------------------------------------------------
# 清洗 / 标准化
# ---------------------------------------------------------------------------

def _parse_first_patched(raw: object) -> str | None:
    """兼容 GitHub API 两种形态: "6.44.0" 或 {"name": "6.44.0", ...}"""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        return raw.get("name")
    return None


def normalize_item(raw: dict) -> dict:
    """把 GitHub API 原始公告清洗/标准化为仓库统一 schema（与 advisories/*.json 一致）。

    去重键: ghsa_id（主键）。原始报文完整保留在 raw 字段，保证信息零丢失。
    """
    withdrawn_at = raw.get("withdrawn_at")
    state = "withdrawn" if withdrawn_at else "published"
    cvss = raw.get("cvss") or {}
    severity = raw.get("severity") or (
        "unknown" if state == "withdrawn" else "unknown")
    packages = []
    for vuln in raw.get("vulnerabilities") or []:
        packages.append({
            "ecosystem": vuln.get("package", {}).get("ecosystem"),
            "name": vuln.get("package", {}).get("name"),
            "version_range": vuln.get("vulnerable_version_range"),
            "introduced": None,  # API 不提供精确引入版本，统一置空保持 schema 稳定
            "fixed_version": _parse_first_patched(vuln.get("first_patched_version")),
        })
    try:
        cvss_score = float(cvss.get("score")) if cvss.get("score") is not None else None
    except (TypeError, ValueError):
        cvss_score = None
    return {
        "ghsa_id": raw["ghsa_id"],
        "cve_id": raw.get("cve_id"),
        "state": state,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss.get("vector_string"),
        "summary": raw.get("summary"),
        "description": raw.get("description"),
        "published_at": raw.get("published_at"),
        "updated_at": raw.get("updated_at"),
        "withdrawn_at": withdrawn_at,
        "source": "github_api",
        "packages": packages,
        "raw": raw,
    }


def dedupe(items: list[dict]) -> dict[str, dict]:
    """按 ghsa_id 去重（后到覆盖先到），返回 {ghsa_id: item}"""
    out: dict[str, dict] = {}
    for it in items:
        out[it["ghsa_id"]] = it
    return out


# ---------------------------------------------------------------------------
# 本地文件读写（advisories/*.json 与 stats.json）
# ---------------------------------------------------------------------------

def _year_of(item: dict) -> str:
    return (item.get("published_at") or "")[:4] or "unknown"


def load_existing(data_dir: Path) -> dict[str, dict]:
    """读取现有 advisories/*.json（含 -partN 分片），返回 {ghsa_id: item}"""
    out: dict[str, dict] = {}
    for f in sorted(data_dir.glob("*.json")):
        obj = json.loads(f.read_text(encoding="utf-8"))
        for it in obj.get("advisories", []):
            out[it["ghsa_id"]] = it
    return out


def write_year_files(data_dir: Path, data: dict[str, dict], chunk_mb: int = CHUNK_TARGET_MB) -> int:
    """把 {ghsa_id: item} 写回按年份分片文件（确定性排序 + 自动切分）。

    chunk_mb 可注入小阈值便于测试分片逻辑。
    """
    by_year: dict[str, list] = {}
    for it in data.values():
        by_year.setdefault(_year_of(it), []).append(it)
    files_written = 0
    for year in sorted(by_year):
        items = sorted(by_year[year], key=lambda x: (x.get("published_at") or "", x["ghsa_id"]))
        files_written += _write_year_chunks(data_dir, year, items, chunk_mb)
    return files_written


def _write_year_chunks(data_dir: Path, year: str, items: list, chunk_mb: int = CHUNK_TARGET_MB) -> int:
    """单年数据按体积切分写入，返回写出的文件数（数据无变化时保持字节级稳定）。"""
    if not items:
        return 0
    chunks: list[list] = []
    sizes: list[int] = []
    cur: list = []
    cur_bytes = 0
    limit = chunk_mb * 1024 * 1024
    for it in items:
        size = len(json.dumps(it, ensure_ascii=False, separators=(",", ":")))
        if cur and cur_bytes + size > limit:
            chunks.append(cur)
            sizes.append(cur_bytes)
            cur, cur_bytes = [], 0
        cur.append(it)
        cur_bytes += size
    if cur:
        chunks.append(cur)
        sizes.append(cur_bytes)
    # 尾部小块按体积判断并入前一片（<5% 阈值），避免碎片分片；
    # 但体积达标的大记录独自分片不合并
    if len(chunks) > 1 and sizes[-1] < max(limit // 20, 1):
        chunks[-2].extend(chunks.pop())
    for idx, chunk in enumerate(chunks, 1):
        suffix = "" if len(chunks) == 1 else f"-part{idx}"
        payload = {"schema_version": SCHEMA_VERSION, "year": year,
                   "count": len(chunk), "advisories": chunk}
        (data_dir / f"{year}{suffix}.json").write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return len(chunks)


def build_stats(data: dict[str, dict], generated_at: str) -> dict:
    by_year: Counter = Counter()
    by_severity: Counter = Counter()
    by_ecosystem: Counter = Counter()
    for it in data.values():
        by_year[_year_of(it)] += 1
        by_severity[it.get("severity") or "unknown"] += 1
        for pk in it.get("packages", []):
            by_ecosystem[pk.get("ecosystem") or "unknown"] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "total": len(data),
        "generated_at": generated_at,
        "source": "GitHub Advisory Database",
        "by_year": {y: by_year[y] for y in sorted(by_year)},
        "by_severity": dict(by_severity.most_common()),
        "by_ecosystem": dict(by_ecosystem.most_common()),
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def run(data_dir: Path, stats_path: Path, full: bool, days: int,
        token: str | None, max_pages: int) -> dict:
    data_dir.mkdir(parents=True, exist_ok=True)
    existing = load_existing(data_dir)

    if full or not existing:
        print(f"[sync] 全量模式：拉取全部公告 ...", file=sys.stderr)
        raws = fetch_advisories(None, token, max_pages)
    else:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        print(f"[sync] 增量模式：拉取 {since} 以来的更新 ...", file=sys.stderr)
        raws = fetch_advisories(since, token, max_pages)

    data = dict(existing)                      # 保留旧数据
    data.update(dedupe(normalize_item(r) for r in raws))   # 新增/更新按 ghsa_id 合并

    files = write_year_files(data_dir, data)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = build_stats(data, now)
    stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
    print(json.dumps({
        "ok": True, "mode": "full" if full else "incremental",
        "total": len(data), "fetched": len(raws),
        "added_or_updated": len(dedupe(normalize_item(r) for r in raws)),
        "year_files": files, "stats": stats_path.name,
    }, ensure_ascii=False))
    return stats


def main() -> int:
    p = argparse.ArgumentParser(description="GitHub Advisory API → advisories/*.json 同步")
    p.add_argument("--full", action="store_true", help="全量拉取（默认增量）")
    p.add_argument("--days", type=int, default=7, help="增量回看天数（默认 7）")
    p.add_argument("--max-pages", type=int, default=2000, help="最大翻页数（默认 2000）")
    p.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="数据目录（默认 advisories/）")
    p.add_argument("--stats", default=DEFAULT_STATS, help="统计输出文件（默认 stats.json）")
    args = p.parse_args()
    try:
        run(Path(args.data_dir), Path(args.stats), args.full, args.days,
            os.environ.get("GITHUB_TOKEN"), args.max_pages)
    except SyncError as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
