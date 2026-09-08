# Contributing

感谢你对本漏洞知识库的关注！本项目由数据 + 代码两部分组成，欢迎任何形式的贡献。

## 快速开始

```bash
# 克隆
git clone <your-fork-url>
cd vulnknowledge

# 查看数据（无需任何依赖）
jq '.advisories[] | select(.severity=="critical") | .ghsa_id' advisories/2026.json | head

# 导入 SQLite（纯标准库）
python3 scripts/import_to_sqlite.py --fts

# 跑测试
python3 -m unittest discover -s tests -v
```

## 数据类贡献

- **修数据**：直接改 `advisories/<年份>.json` 并提交 PR。文件 schema 见 README
  "数据格式"一节。注意保持 `count` 字段与实际 `advisories` 数组长度一致
  （提交前可运行 `python3 -m unittest discover -s tests -v` 自检）。
- **新增数据源字段**：同步修改 `scripts/sync_advisories.py` 的
  `normalize_item()` 与 `scripts/import_to_sqlite.py` 的 `SCHEMA`，并补充测试。

## 代码类贡献

1. Fork 并创建特性分支：`git checkout -b feat/my-change`
2. 修改代码，**必须**为新增行为补充 `tests/` 下的单元测试
3. 本地验证：
   ```bash
   python3 -m unittest discover -s tests -v   # 全绿
   ```
4. 提交 PR，说明改动动机与验证结果。

## 代码风格

- Python ≥3.9，纯标准库（禁止引入第三方依赖，保证任何人可运行）
- 中文注释；公共函数带 docstring
- 保持"确定性输出"原则：同输入必须产生字节级相同的输出文件

## 发布流程（维护者）

数据自动更新由 GitHub Actions（`.github/workflows/update.yml`）完成，无需手动。
版本发布时更新 `CHANGELOG.md`。
