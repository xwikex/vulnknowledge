#!/usr/bin/env python3
"""sync_advisories 清洗/去重/分片逻辑的单元测试（纯标准库，无网络依赖）。

运行: python3 -m unittest discover -s tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sync_advisories import (build_stats, dedupe, load_existing,  # noqa: E402
                             normalize_item, write_year_files)

RAW_API_ITEM = {
    "ghsa_id": "GHSA-x", "cve_id": "CVE-2025-0001",
    "summary": "Legacy record hello", "description": "desc",
    "published_at": "2025-03-01T00:00:00Z",
    "updated_at": "2026-08-01T00:00:00Z",
    "withdrawn_at": None,
    "severity": "high",
    "cvss": {"score": "8.1", "vector_string": "CVSS:3.1/AV:N"},
    "vulnerabilities": [{
        "package": {"ecosystem": "npm", "name": "ghost"},
        "vulnerable_version_range": ">= 6.27.0, < 6.44.0",
        "first_patched_version": "6.44.0",      # 字符串形态
    }],
}

RAW_STRING_VERSION = json.loads(json.dumps(RAW_API_ITEM))   # 深拷贝，避免共享 vulnerabilities 列表
RAW_STRING_VERSION["ghsa_id"] = "GHSA-y"
RAW_STRING_VERSION["vulnerabilities"][0]["first_patched_version"] = {"name": "1.2.3"}  # 对象形态


class NormalizeTest(unittest.TestCase):

    def test_normalize_basic(self):
        it = normalize_item(RAW_API_ITEM)
        self.assertEqual(it["ghsa_id"], "GHSA-x")
        self.assertEqual(it["state"], "published")
        self.assertEqual(it["severity"], "high")
        self.assertEqual(it["cvss_score"], 8.1)
        self.assertEqual(it["packages"][0]["fixed_version"], "6.44.0")
        self.assertEqual(it["raw"], RAW_API_ITEM)

    def test_normalize_first_patched_object_form(self):
        it = normalize_item(RAW_STRING_VERSION)
        self.assertEqual(it["packages"][0]["fixed_version"], "1.2.3")

    def test_normalize_withdrawn(self):
        raw = dict(RAW_API_ITEM, withdrawn_at="2026-01-01T00:00:00Z")
        it = normalize_item(raw)
        self.assertEqual(it["state"], "withdrawn")
        self.assertEqual(it["withdrawn_at"], "2026-01-01T00:00:00Z")

    def test_normalize_missing_cvss(self):
        raw = {k: v for k, v in RAW_API_ITEM.items() if k != "cvss"}
        it = normalize_item(raw)
        self.assertIsNone(it["cvss_score"])
        self.assertIsNone(it["cvss_vector"])

    def test_dedupe_last_wins(self):
        a = normalize_item(RAW_API_ITEM)
        b = dict(a, summary="Updated summary")
        out = dedupe([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(out["GHSA-x"]["summary"], "Updated summary")

    def test_normalize_object_form_does_not_leak(self):
        # 深拷贝隔离：改对象形态样例不得污染字符串形态样例
        self.assertEqual(normalize_item(RAW_API_ITEM)["packages"][0]["fixed_version"], "6.44.0")
        self.assertEqual(normalize_item(RAW_STRING_VERSION)["packages"][0]["fixed_version"], "1.2.3")


class FileIOTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "advisories"
        self.data_dir.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_roundtrip_and_stats(self):
        data = dedupe([normalize_item(RAW_API_ITEM), normalize_item(RAW_STRING_VERSION)])
        self.assertEqual(set(data), {"GHSA-x", "GHSA-y"})
        write_year_files(self.data_dir, data)
        files = sorted(self.data_dir.glob("*.json"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, "2025.json")
        loaded = load_existing(self.data_dir)
        self.assertEqual(set(loaded), {"GHSA-x", "GHSA-y"})
        stats = build_stats(loaded, "2026-09-02T00:00:00Z")
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["by_year"]["2025"], 2)
        self.assertEqual(stats["by_severity"]["high"], 2)

    def test_write_is_deterministic(self):
        data = {f"GHSA-{i:04d}": normalize_item(
            dict(RAW_API_ITEM, ghsa_id=f"GHSA-{i:04d}",
                 published_at=f"2026-01-{(i % 28) + 1:02d}T00:00:00Z"))
            for i in range(50)}
        write_year_files(self.data_dir, data)
        first = {f.name: f.read_bytes() for f in self.data_dir.glob("*.json")}
        write_year_files(self.data_dir, data)   # 重写
        second = {f.name: f.read_bytes() for f in self.data_dir.glob("*.json")}
        self.assertEqual(first, second)          # 数据未变 → 字节级一致

    def test_chunk_splitting(self):
        # 小阈值分片：30 条小记录 ≈25KB + 1 条 1MB 大记录
        # 用 0.05MB(≈52KB) 阈值 → 必然多片；尾片 25KB > 阈值5%(≈2.6KB) 不会被尾部合并
        big = normalize_item(dict(RAW_API_ITEM, ghsa_id="GHSA-big",
                                  published_at="2026-01-01T00:00:00Z"))
        big["description"] = "x" * (1024 * 1024)      # 1MB
        data = {f"GHSA-{i:04d}": normalize_item(
            dict(RAW_API_ITEM, ghsa_id=f"GHSA-{i:04d}",
                 published_at="2026-01-01T00:00:00Z"))
            for i in range(30)}
        data["GHSA-big"] = big
        write_year_files(self.data_dir, data, chunk_mb=0.05)
        parts = sorted(self.data_dir.glob("2026*.json"))
        self.assertGreater(len(parts), 1)
        total = sum(json.loads(p.read_text(encoding="utf-8"))["count"] for p in parts)
        self.assertEqual(total, 31)


if __name__ == "__main__":
    unittest.main()
