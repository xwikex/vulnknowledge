#!/usr/bin/env python3
"""把 advisories/*.json 分片数据还原为 SQLite 数据库（纯标准库，无第三方依赖）。

用法:
    python3 import_to_sqlite.py [-o vulnerabilities.db] [--fts]
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


def main() -> int:
    p = argparse.ArgumentParser(description="vuln-sync JSON 数据包 → SQLite")
    p.add_argument("-o", "--output", default="vulnerabilities.db")
    p.add_argument("--fts", action="store_true", help="创建 FTS5 全文索引")
    p.add_argument("--data", default="advisories", help="JSON 分片目录")
    args = p.parse_args()

    con = sqlite3.connect(args.output)
    con.executescript(SCHEMA)
    files = sorted(Path(args.data).glob("*.json"))
    if not files:
        print("错误: 未找到任何 JSON 分片", file=sys.stderr)
        return 1

    total = 0
    for f in files:
        with open(f, encoding="utf-8") as fh:
            obj = json.load(fh)
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
    if args.fts:
        try:
            con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS advisories_fts USING fts5("
                        "summary, description, content='advisories', content_rowid='rowid', tokenize='unicode61')")
            con.executescript(
                """CREATE TRIGGER IF NOT EXISTS advisories_ai AFTER INSERT ON advisories BEGIN
                       INSERT INTO advisories_fts(rowid, summary, description)
                       VALUES (new.rowid, new.summary, new.description);
                   END;""")
            con.execute("INSERT INTO advisories_fts(advisories_fts) VALUES('delete-all')")
            rows = [tuple(r) for r in con.execute("SELECT rowid, summary, description FROM advisories")]
            con.executemany("INSERT INTO advisories_fts(rowid, summary, description) VALUES (?,?,?)", rows)
        except sqlite3.OperationalError as e:
            print(f"警告: FTS5 不可用（{e}），跳过全文索引", file=sys.stderr)
    con.commit()
    con.close()
    print(f"完成: {total} 条公告已导入 {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
