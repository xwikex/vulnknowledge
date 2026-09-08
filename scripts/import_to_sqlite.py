#!/usr/bin/env python3
"""把 advisories/*.json 分片数据还原为 SQLite 数据库（纯标准库，无第三方依赖）。

用法:
    python3 scripts/import_to_sqlite.py                  # 生成 vulnerabilities.db
    python3 scripts/import_to_sqlite.py -o my.db         # 指定输出文件
    python3 scripts/import_to_sqlite.py --fts            # 额外创建 FTS5 全文索引

提供函数式接口便于测试/二次开发:
    import_files(con, data_dir, with_fts=False) -> int   # 返回导入条数
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    ghsa_id        TEXT PRIMARY KEY,
    cve_id         TEXT,
    state          TEXT NOT NULL DEFAULT 'published',
    summary        TEXT,
    description    TEXT,
    severity       TEXT,
    cvss_score     REAL,
    cvss_vector    TEXT,
    published_at   TEXT,
    updated_at     TEXT,
    withdrawn_at   TEXT,
    source         TEXT,
    raw_json       TEXT,
    first_seen_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_synced_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_advisories_cve      ON advisories(cve_id);
CREATE INDEX IF NOT EXISTS idx_advisories_severity ON advisories(severity);
CREATE INDEX IF NOT EXISTS idx_advisories_updated  ON advisories(updated_at);
CREATE TABLE IF NOT EXISTS affected_packages (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ghsa_id        TEXT NOT NULL REFERENCES advisories(ghsa_id) ON DELETE CASCADE,
    ecosystem      TEXT,
    package_name   TEXT,
    version_range  TEXT,
    introduced     TEXT,
    fixed_version  TEXT
);
CREATE INDEX IF NOT EXISTS idx_affected_eco   ON affected_packages(ecosystem);
CREATE INDEX IF NOT EXISTS idx_affected_name  ON affected_packages(package_name);
CREATE INDEX IF NOT EXISTS idx_affected_ghsa  ON affected_packages(ghsa_id);
"""

FTS_DDL = """
CREATE VIRTUAL TABLE IF NOT EXISTS advisories_fts USING fts5(
    summary, description, content='advisories', content_rowid='rowid', tokenize='unicode61');
CREATE TRIGGER IF NOT EXISTS advisories_ai AFTER INSERT ON advisories BEGIN
    INSERT INTO advisories_fts(rowid, summary, description)
    VALUES (new.rowid, new.summary, new.description);
END;
CREATE TRIGGER IF NOT EXISTS advisories_ad AFTER DELETE ON advisories BEGIN
    INSERT INTO advisories_fts(advisories_fts, rowid, summary, description)
    VALUES('delete', old.rowid, old.summary, old.description);
END;
CREATE TRIGGER IF NOT EXISTS advisories_au AFTER UPDATE ON advisories BEGIN
    INSERT INTO advisories_fts(advisories_fts, rowid, summary, description)
    VALUES('delete', old.rowid, old.summary, old.description);
    INSERT INTO advisories_fts(rowid, summary, description)
    VALUES (new.rowid, new.summary, new.description);
END;
"""


def import_files(con: sqlite3.Connection, data_dir: Path, with_fts: bool = False) -> int:
    """把 data_dir 下全部 advisories 分片导入给定连接，返回导入条数。"""
    con.executescript(SCHEMA)
    files = sorted(Path(data_dir).glob("*.json"))
    if not files:
        raise FileNotFoundError(f"未找到任何 JSON 分片: {data_dir}")
    total = 0
    for f in files:
        obj = json.loads(f.read_text(encoding="utf-8"))
        items = obj.get("advisories", obj if isinstance(obj, list) else [])
        for a in items:
            raw = a.get("raw") or {}
            con.execute(
                """INSERT OR REPLACE INTO advisories
                   (ghsa_id,cve_id,state,summary,description,severity,cvss_score,cvss_vector,
                    published_at,updated_at,withdrawn_at,source,raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (a.get("ghsa_id"), a.get("cve_id"), a.get("state", "published"),
                 a.get("summary"), a.get("description"), a.get("severity"),
                 a.get("cvss_score"), a.get("cvss_vector"), a.get("published_at"),
                 a.get("updated_at"), a.get("withdrawn_at"), a.get("source"),
                 json.dumps(raw, ensure_ascii=False)),
            )
            con.execute("DELETE FROM affected_packages WHERE ghsa_id=?", (a.get("ghsa_id"),))
            for pk in a.get("packages", []):
                con.execute(
                    """INSERT INTO affected_packages
                       (ghsa_id,ecosystem,package_name,version_range,introduced,fixed_version)
                       VALUES (?,?,?,?,?,?)""",
                    (a.get("ghsa_id"), pk.get("ecosystem"), pk.get("name"),
                     pk.get("version_range"), pk.get("introduced"), pk.get("fixed_version")),
                )
            total += 1
    if with_fts:
        con.executescript(FTS_DDL)
        con.execute("INSERT INTO advisories_fts(advisories_fts) VALUES('delete-all')")
        rows = [tuple(r) for r in con.execute(
            "SELECT rowid, summary, description FROM advisories")]
        con.executemany(
            "INSERT INTO advisories_fts(rowid, summary, description) VALUES (?,?,?)", rows)
    con.commit()
    return total


def main() -> int:
    p = argparse.ArgumentParser(description="vulnknowledge JSON 数据包 → SQLite")
    p.add_argument("-o", "--output", default="vulnerabilities.db")
    p.add_argument("--fts", action="store_true", help="创建 FTS5 全文索引")
    p.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "advisories"),
                   help="JSON 分片目录（默认仓库 advisories/）")
    args = p.parse_args()

    con = sqlite3.connect(args.output)
    try:
        total = import_files(con, Path(args.data), with_fts=args.fts)
    except (FileNotFoundError, sqlite3.OperationalError) as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1
    finally:
        con.close()
    print(f"完成: {total} 条公告已导入 {args.output}"
          + ("（含 FTS5 全文索引）" if args.fts else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
