"""检查提交文档的表述、本地链接、实验材料和原始结果。"""

import csv
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from verify_cross_test import read_source_bytes

ROOT = Path(__file__).resolve().parents[1]


def main():
    documents = [ROOT / "README.md", *sorted(path for path in (ROOT / "docs").rglob("*.md") if "peer-original" not in path.parts)]
    problems, links = [], 0
    draft_wording = re.compile(r"待处理|待完善|待补充|待填写|待确认|待互测|TODO|TBD|PENDING|用户(?:转交|要求|提供)|本轮|交付|成员留空|未制作|尚未|回执|不代填|线上提交另行", re.IGNORECASE)
    for path in documents:
        content = path.read_text(encoding="utf-8")
        if draft_wording.search(content):
            problems.append(f"{path.relative_to(ROOT)}: 存在草稿或对话式表述")
        for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", content):
            if urlsplit(target).scheme or target.startswith("#"):
                continue
            destination = path.parent / unquote(target.split("#", 1)[0])
            links += 1
            if not destination.exists():
                problems.append(f"{path.relative_to(ROOT)}: {target}")
    summary = json.loads((ROOT / "docs/evidence/results/summary.json").read_text(encoding="utf-8"))
    assert summary["tests"]["failures"] == summary["tests"]["errors"] == 0
    assert summary["cross_group_testing"] == "passed_peer_dataset"
    cross = ROOT / "docs/evidence/cross-test"
    peer = json.loads((cross / "cross-test-summary.json").read_text(encoding="utf-8"))
    assert peer["result_rows"] == peer["passed"] == 220 and peer["failed"] == peer["not_run"] == 0
    assert peer["basic_vectors"] == peer["basic_passed"] == 64
    for name, digest in peer["source_file_sha256"].items():
        assert hashlib.sha256(read_source_bytes(cross / "peer-original", name)).hexdigest() == digest
    assert hashlib.sha256((cross / peer["source_archive"]).read_bytes()).hexdigest() == peer["source_archive_sha256"]
    with (cross / "cross-test-results.csv").open(encoding="utf-8-sig", newline="") as stream:
        results = list(csv.DictReader(stream))
    assert len(results) == 220 and all(row["status"] == "PASS" for row in results)
    for case_id, result in peer["mitm"].items():
        assert hashlib.sha256((cross / f"{case_id}-candidates.txt").read_bytes()).hexdigest() == result["candidate_set_sha256"]
    ui = json.loads((cross / "ui-evidence.json").read_text(encoding="utf-8"))
    assert ui["rows"] == ui["encrypt_passed"] == ui["decrypt_passed"] == 64 and ui["all_passed"]
    assert all((ROOT / image).is_file() for image in ui["screenshots"])
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
        raise RuntimeError("提交材料检查失败：\n" + "\n".join(problems))
    print(f"checked {len(documents)} submission documents, {links} local links; wording and evidence verified")


if __name__ == "__main__":
    main()
