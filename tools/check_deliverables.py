"""交付检查：文档本地链接、必需材料和原始结果一致性。"""

import csv
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def main():
    documents = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    problems, links = [], 0
    for path in documents:
        for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if urlsplit(target).scheme or target.startswith("#"):
                continue
            destination = path.parent / unquote(target.split("#", 1)[0])
            links += 1
            if not destination.exists():
                problems.append(f"{path.relative_to(ROOT)}: {target}")
    summary = json.loads((ROOT / "docs/evidence/results/summary.json").read_text(encoding="utf-8"))
    assert summary["tests"]["failures"] == summary["tests"]["errors"] == 0
    assert summary["members"] == []
    assert summary["cross_group_testing"] == "deferred_by_user"
    pdf = ROOT / "docs/reference/附录D 简化AES.pdf"
    if pdf.exists() and summary.get("source_pdf_sha256"):
        assert hashlib.sha256(pdf.read_bytes()).hexdigest() == summary["source_pdf_sha256"]
    assert not {"executable", "processor", "hostname", "username"}.intersection(summary["environment"])
    for attack in summary["mitm"]:
        path = ROOT / "docs/evidence/results" / attack["candidate_csv"]
        with path.open(encoding="utf-8-sig", newline="") as stream:
            count = sum(1 for _ in csv.DictReader(stream))
        assert count == attack["candidate_count"], path
    for name in ("user-guide.md", "developer-guide.md", "test-report.md", "通关说明.md", "cross-test-record.md", "ui-design.md", "demo-recording.md"):
        assert (ROOT / "docs" / name).stat().st_size > 200
    if problems:
        raise RuntimeError("文档链接失效：\n" + "\n".join(problems))
    print(f"checked {len(documents)} documents, {links} local links; evidence consistent; environment metadata minimized")


if __name__ == "__main__":
    main()
