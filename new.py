#!/usr/bin/env python3
"""
새 페이지 만들기.

사용법:
    python new.py windows/prefetch                 # 기본 템플릿(concept)
    python new.py windows/prefetch -t artifact     # 아티팩트 템플릿
    python new.py tools/kape -t tool
    python new.py adversary/pass-the-hash -t technique
    python new.py playbooks/ransomware -t playbook
    python new.py network/zeek/conn-log -t artifact --title "Zeek conn.log"

템플릿 종류: concept(기본) / artifact / tool / technique / playbook
폴더가 없으면 자동으로 만들고, 그 폴더용 index.md도 같이 만들어 줍니다.
"""
import argparse
import datetime as dt
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).parent
DOCS = ROOT / "docs"
TEMPLATES = ROOT / "templates"


def slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9/._-]+", "-", s)
    return re.sub(r"-{2,}", "-", s).strip("-")


def pretty(slug: str) -> str:
    return slug.replace("-", " ").replace("_", " ").title()


def ensure_index(folder: pathlib.Path) -> None:
    """폴더에 index.md가 없으면 만들어 준다 (섹션 첫 페이지)."""
    idx = folder / "index.md"
    if idx.exists():
        return
    name = pretty(folder.name)
    idx.write_text(
        f"# {name}\n\n"
        f"Pages in this section are listed in the sidebar.\n",
        encoding="utf-8",
    )
    pages = folder / ".pages"
    if not pages.exists():
        pages.write_text("nav:\n  - index.md\n  - ...\n", encoding="utf-8")
    print(f"  + {idx.relative_to(ROOT)}  (section index)")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", help="docs/ 아래 경로 (확장자 없이). 예: windows/prefetch")
    p.add_argument("-t", "--template", default="concept",
                   choices=[t.stem for t in TEMPLATES.glob("*.md")])
    p.add_argument("--title", help="페이지 제목 (생략하면 파일명에서 자동 생성)")
    p.add_argument("-f", "--force", action="store_true", help="이미 있어도 덮어쓰기")
    a = p.parse_args()

    rel = slugify(a.path.removesuffix(".md"))
    if not rel or "/" not in rel:
        sys.exit("경로는 '섹션/이름' 형태여야 해요. 예: windows/prefetch")

    target = DOCS / f"{rel}.md"
    if target.exists() and not a.force:
        sys.exit(f"이미 있어요: {target.relative_to(ROOT)}  (덮어쓰려면 -f)")

    parts = target.relative_to(DOCS).parts
    section = parts[0]
    title = a.title or pretty(target.stem)

    # 중간 폴더들 모두 만들고 index.md 채우기
    folder = DOCS
    for part in parts[:-1]:
        folder = folder / part
        folder.mkdir(exist_ok=True)
        ensure_index(folder)

    body = (TEMPLATES / f"{a.template}.md").read_text(encoding="utf-8")
    body = (body.replace("{{TITLE}}", title)
                .replace("{{SECTION}}", section)
                .replace("{{DATE}}", dt.date.today().isoformat()))
    target.write_text(body, encoding="utf-8")
    print(f"  + {target.relative_to(ROOT)}  ({a.template} template)")
    print("\n이제 그 파일을 열어 내용을 채우고, git add/commit/push 하면 배포돼요.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
