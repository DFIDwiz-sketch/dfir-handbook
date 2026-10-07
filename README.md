# DFIR Handbook

개인 DFIR / IR 레퍼런스 사이트. [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)로 만들고 GitHub Pages에 자동 배포됩니다.

## 처음 한 번만 (셋업)

```bash
# 1. 가상환경 + 패키지
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt

# 2. mkdocs.yml 맨 위 두 줄에서 YOUR-GITHUB-USERNAME 을 본인 아이디로 변경

# 3. GitHub 저장소 설정
#    Settings → Pages → Source: "Deploy from a branch" → Branch: gh-pages / (root)
#    (첫 push 후 Actions가 gh-pages 브랜치를 만들어 줍니다. 그 다음에 설정하세요.)
```

## 평소에 글 쓰기 — 3단계

```bash
# 1. 새 페이지 만들기  (섹션/이름  -t 템플릿)
python new.py windows/prefetch -t artifact
python new.py tools/kape -t tool
python new.py adversary/pass-the-hash -t technique
python new.py playbooks/ransomware -t playbook
python new.py basics/base64 -t concept        # -t 생략하면 concept

# 2. 생긴 파일을 열어서 내용 채우기 (docs/windows/prefetch.md)
#    로컬에서 미리보기: mkdocs serve  →  http://127.0.0.1:8000

# 3. 올리기
git add -A && git commit -m "Add prefetch" && git push
```

push 하면 1~2분 뒤 사이트에 반영됩니다 (영어 사이트와 한국어 사이트 둘 다 자동으로 빌드돼요). **mkdocs.yml 은 건드릴 필요 없어요** — 폴더 구조가 곧 메뉴입니다.

### 더 쉬운 방법: 컴퓨터 없이 수정하기

사이트의 아무 페이지에서 오른쪽 위 ✏️ 아이콘 → GitHub 편집기에서 바로 수정 → "Commit changes" → 자동 배포.
새 페이지도 GitHub 웹에서 `docs/섹션/이름.md` 로 "Add file" 하면 됩니다 (템플릿은 `templates/` 폴더에서 복사).

## 영어 / 한국어 두 언어

사이트 상단의 🌐 버튼으로 **English ↔ 한국어**를 바꿀 수 있어요. 영어가 기본이고, 한국어는 `/ko/` 주소 아래에 있습니다.
버튼을 누르면 **지금 보고 있는 같은 페이지**의 다른 언어 버전으로 이동합니다 (`assets/lang-switch.js`).

| | 영어 | 한국어 |
|---|---|---|
| 글 폴더 | `docs/` | `docs-ko/` (구조·파일명이 똑같음) |
| 설정 파일 | `mkdocs.yml` | `mkdocs.ko.yml` (mkdocs.yml 을 물려받고 다른 부분만 덮어씀) |
| 로컬 미리보기 | `mkdocs serve` → http://127.0.0.1:8001/dfir-handbook/ | `mkdocs serve -f mkdocs.ko.yml` → http://127.0.0.1:8002/dfir-handbook/ko/ |
| 배포 주소 | `.../dfir-handbook/` | `.../dfir-handbook/ko/` |

**규칙: 페이지는 항상 두 폴더에 같은 경로로 있어야 해요.** 한쪽에만 있으면 언어 버튼을 눌렀을 때 404가 나거나, `.pages` 에 적힌 파일이 없어서 빌드가 실패합니다.
`new.py` 는 `docs/` 와 `docs-ko/` 양쪽에 파일을 만들어 주고, 한국어 쪽에는 "번역 예정" 박스를 붙여 둡니다.

번역할 때 지키는 것:

- 코드 블록, SPL 쿼리, 명령어, 이벤트 ID, 필드 이름, mermaid 다이어그램은 **영어 그대로** 둡니다.
- 제목·본문·표만 번역합니다.
- 한국어 제목 뒤에 `{ #영어-앵커 }` 를 붙이면 영어 페이지와 같은 링크(`페이지.md#detection` 등)가 그대로 동작해요. 예: `## 탐지 { #detection }`
- `.pages` 에 메뉴 순서를 바꿨다면 `docs-ko/` 쪽 `.pages` 도 똑같이 바꿉니다 (최상위 `docs-ko/.pages` 는 탭 이름만 한국어).

## 폴더 구조

```
docs/                 ← 영어 글
  index.md            ← 홈 (카드 그리드)
  .pages              ← 최상위 탭 순서 (awesome-pages)
  basics/             ← 각 폴더 = 상단 탭 하나
    index.md          ←   섹션 첫 페이지
    .pages            ←   "index.md 먼저, 나머지는 알파벳순"
    *.md              ←   페이지들
  windows/  linux/  network/  memory/  splunk/  adversary/  tools/  playbooks/
  assets/             ← CSS, 아이콘, 이미지, lang-switch.js
docs-ko/              ← 한국어 글 (docs/ 와 같은 구조)
templates/            ← new.py 가 쓰는 페이지 템플릿 5종
new.py                ← 새 페이지 생성 스크립트
mkdocs.yml            ← 사이트 설정 (거의 안 건드림)
mkdocs.ko.yml         ← 한국어 사이트 설정 (mkdocs.yml 상속)
.github/workflows/deploy.yml  ← push 시 자동 배포
```

### 새 섹션(탭) 추가하고 싶으면

`docs/새폴더/` 와 `docs-ko/새폴더/` 를 만들고, `docs/.pages` 와 `docs-ko/.pages` 의 `nav:` 에 각각 한 줄 추가. `new.py 새폴더/페이지` 로 만들면 폴더와 index.md 는 자동 생성됩니다.

### 페이지 순서 바꾸고 싶으면

그 폴더의 `.pages` 파일에 파일명을 원하는 순서로 나열. `...` 은 "나머지 전부".

## 자주 쓰는 마크다운 (Material 확장)

```markdown
!!! note "제목"           ← 파란 박스   (note / tip / warning / danger / abstract / info / quote)
    내용 (4칸 들여쓰기)

??? note "접힌 박스"       ← 클릭하면 펼쳐짐

=== "Tab 1"               ← 탭 UI
    내용
=== "Tab 2"
    내용

++ctrl+shift+esc++        ← 키보드 키 표시

```spl / ```powershell / ```bash / ```yaml   ← 코드 하이라이트

- [ ] 할 일 / - [x] 완료   ← 체크박스
```

Mermaid 다이어그램은 ` ```mermaid ` 블록 안에 쓰면 그대로 렌더링됩니다.
