#!/usr/bin/env python3
"""import_to_sqlite 的单元测试（纯标准库 unittest，无网络依赖）。

运行: python3 -m unittest discover -s tests -v
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from import_to_sqlite import import_files  # noqa: E402

SAMPLE_ADVISORY = {
    "ghsa_id": "GHSA-xxxx-1111-2222",
    "cve_id": "CVE-2024-0001",
    "state": "published",
    "severity": "high",
    "cvss_score": 8.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "summary": "Example command injection in demo-pkg",
    "description": "A vulnerability allows command injection.",
    "published_at": "2024-01-15T10:00:00Z",
    "updated_at": "2024-02-01T10:00:00Z",
    "withdrawn_at": None,
    "source": "github_api",
    "packages": [
        {"ecosystem": "npm", "name": "demo-pkg",
         "version_range": ">= 1.0.0, < 1.2.0", "introduced": None, "fixed_version": "1.2.0"}
    ],
    "raw": {"ghsa_id": "GHSA-xxxx-1111-2222"},
}


def make_year_file(data_dir: Path, year: str, advisories: list) -> Path:
    f = data_dir / f"{year}.json"
    f.write_text(json.dumps({"schema_version": 1, "year": year,
                             "count": len(advisories), "advisories": advisories},
                            ensure_ascii=False), encoding="utf-8")
    return f


class ImportTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "advisories"
        self.data_dir.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _db(self, path):
        con = sqlite3.connect(path)
        return con

    def test_import_counts(self):
        make_year_file(self.data_dir, "2024", [SAMPLE_ADVISORY])
        adv2 = dict(SAMPLE_ADVISORY, ghsa_id="GHSA-yyyy-3333-4444",
                    summary="Second issue", packages=[])
        make_year_file(self.data_dir, "2023", [adv2])   # 不同年份文件，避免互相覆盖
        db = Path(self._tmp.name) / "t.db"
        con = self._db(db)
        try:
            n = import_files(con, self.data_dir)
        finally:
            con.close()
        self.assertEqual(n, 2)
        con = sqlite3.connect(db)
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM advisories").fetchone()[0], 2)
            self.assertEqual(
                con.execute("SELECT COUNT(*) FROM affected_packages").fetchone()[0], 1)
            row = con.execute(
                "SELECT summary, severity, cvss_score, fixed_version FROM advisories a "
                "JOIN affected_packages p ON p.ghsa_id=a.ghsa_id WHERE a.ghsa_id=?",
                (SAMPLE_ADVISORY["ghsa_id"],)).fetchone()
            self.assertEqual(tuple(row), ("Example command injection in demo-pkg",
                                          "high", 8.1, "1.2.0"))
        finally:
            con.close()

    def test_import_idempotent(self):
        make_year_file(self.data_dir, "2024", [SAMPLE_ADVISORY])
        con = sqlite3.connect(Path(self._tmp.name) / "t.db")
        try:
            self.assertEqual(import_files(con, self.data_dir), 1)
            self.assertEqual(import_files(con, self.data_dir), 1)  # 重复导入不翻倍
        finally:
            con.close()

    def test_import_with_fts(self):
        make_year_file(self.data_dir, "2024", [SAMPLE_ADVISORY])
        con = sqlite3.connect(Path(self._tmp.name) / "t.db")
        try:
            import_files(con, self.data_dir, with_fts=True)
            hit = con.execute(
                "SELECT COUNT(*) FROM advisories WHERE rowid IN "
                "(SELECT rowid FROM advisories_fts WHERE advisories_fts MATCH ?)",
                ('"command"',)).fetchone()[0]
            self.assertEqual(hit, 1)
            hit2 = con.execute(
                "SELECT COUNT(*) FROM advisories WHERE rowid IN "
                "(SELECT rowid FROM advisories_fts WHERE advisories_fts MATCH ?)",
                ('"nonexistent-term"',)).fetchone()[0]
            self.assertEqual(hit2, 0)
        finally:
            con.close()

    def test_empty_dir_raises(self):
        con = sqlite3.connect(Path(self._tmp.name) / "t.db")
        try:
            with self.assertRaises(FileNotFoundError):
                import_files(con, self.data_dir)
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
