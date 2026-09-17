# DFIR Handbook — Git & GitHub 사용 가이드

> 이 문서는 `dfir-handbook` 사이트(Material for MkDocs + GitHub Pages)를 관리하면서 쓰는 Git 명령어를 한곳에 정리한 것입니다. Windows + VS Code + PowerShell 기준이며, 명령은 항상 **저장소 폴더 안**(`C:\Users\sung\Project\dfir-handbook`)에서 실행합니다.

## 0. 핵심 개념 30초 정리

Git은 폴더의 "스냅샷"을 기록하는 도구이고, GitHub는 그 기록을 올려두는 서버입니다. 흐름은 항상 같습니다.

```
내 컴퓨터 폴더 ──(add)──▶ 스테이지 ──(commit)──▶ 로컬 기록 ──(push)──▶ GitHub
                                                              ◀──(pull)──
```

용어를 한 줄씩만 알면 됩니다. **저장소(repository)**는 Git이 관리하는 폴더이고, 안에 숨김 폴더 `.git`이 기록을 담고 있습니다. **add**는 "이번 스냅샷에 넣을 파일 고르기", **commit**은 "메시지를 붙여 스냅샷 찍기", **push**는 "GitHub에 올리기", **pull**은 "GitHub에서 최신 내용 받아오기", **clone**은 "GitHub의 저장소를 새 컴퓨터에 통째로 복사", **remote**는 GitHub 주소의 별명(보통 `origin`), **branch**는 작업 줄기(우리는 `main` 하나만 씁니다)입니다.

GitHub에 `push`가 되면 GitHub Actions가 자동으로 사이트를 빌드해 `gh-pages` 브랜치에 넣고, GitHub Pages가 그것을 `https://DFIDwiz-sketch.github.io/dfir-handbook/` 로 서빙합니다. 즉 **push = 배포**입니다.

## 1. 처음 한 번만 — 컴퓨터 준비

터미널(VS Code에서 `Ctrl + \``)을 열고 세 가지가 설치되어 있는지 확인합니다.

```powershell
# 3.10 이상
python --version
# 아무 버전이든 OK
git --version
# VS Code (선택)
code --version
```

없으면 python.org, git-scm.com 에서 설치한 뒤 VS Code를 다시 켭니다. Git에 내 이름과 이메일을 등록합니다(commit에 기록되는 정보이며, 컴퓨터마다 한 번).

```powershell
git config --global user.name "Sung Lee"
git config --global user.email "sungkwangleeusa@gmail.com"
```

PowerShell에서 가상환경 활성화 스크립트가 막히면 이 한 줄을 먼저 실행합니다.

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 2. 처음 한 번만 — 새 저장소 만들어 올리기 (이미 완료한 절차)

이미 끝낸 과정이지만, 새 프로젝트를 시작할 때 그대로 재사용할 수 있습니다.

GitHub에서 **+ → New repository**, 이름 `dfir-handbook`, Public, "Add README / .gitignore / license"는 모두 **체크 해제**하고 Create. 그런 다음 로컬 폴더에서:

```powershell
cd C:\Users\sung\Project\dfir-handbook

# 이 폴더를 Git 저장소로 만들기
git init
# 기본 브랜치 이름을 main으로
git branch -M main
# 모든 파일을 스테이지에
git add -A
# 첫 스냅샷
git commit -m "Initial DFIR handbook skeleton"
# GitHub 주소 등록
git remote add origin https://github.com/DFIDwiz-sketch/dfir-handbook.git
# 올리기 (-u: 앞으로 git push만 쳐도 되게 연결)
git push -u origin main
```

첫 push에서 로그인 창이 뜨면 브라우저로 GitHub 로그인합니다.

이어서 GitHub 저장소 페이지에서 두 가지를 설정합니다. **Actions** 탭에서 "Deploy DFIR Handbook"이 초록 체크가 될 때까지 기다린 뒤(1~2분), **Settings → Pages**에서 Source를 *Deploy from a branch*, Branch를 `gh-pages` / `/ (root)`로 지정하고 Save. 잠시 후 "Your site is live at …" 가 나타나면 완료입니다.

Actions가 빨간 X면 대부분 권한 문제입니다. **Settings → Actions → General → Workflow permissions**를 *Read and write permissions*로 바꾸고, 실패한 실행에서 *Re-run jobs*.

## 3. 처음 한 번만 — 다른 컴퓨터에서 이어서 작업하기

원드라이브는 필요 없습니다. GitHub가 이미 원본 저장소 역할을 하고, 각 컴퓨터의 폴더는 작업용 복사본입니다. 오히려 Git 저장소를 원드라이브 폴더 안에 두면 `.git` 내부 파일 동기화 충돌로 저장소가 깨질 수 있으니 **원드라이브 밖**(예: `C:\Users\<이름>\Project\`)에 둡니다.

```powershell
mkdir C:\Users\<이름>\Project
cd C:\Users\<이름>\Project
# 저장소 통째로 받기
git clone https://github.com/DFIDwiz-sketch/dfir-handbook.git
cd dfir-handbook

# 가상환경은 컴퓨터마다 따로 (GitHub에 안 올라감)
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

git config --global user.name "Sung Lee"
git config --global user.email "sungkwangleeusa@gmail.com"

# http://127.0.0.1:8001 에서 미리보기 확인
mkdocs serve
```

여러 컴퓨터를 오갈 때 습관 하나만 지키면 됩니다. **작업 시작 전 `git pull`, 작업 끝나면 `git push`.**

## 4. 평소 작업 — 매번 하는 것

VS Code로 저장소 폴더를 열고 터미널에서:

```powershell
# (터미널을 새로 열 때마다) 가상환경 켜기
.venv\Scripts\activate
# 다른 컴퓨터에서 작업했다면 최신 상태로
git pull

# 새 페이지 만들기 (템플릿: concept/artifact/tool/technique/playbook)
python new.py windows/amcache -t artifact
# 미리보기 (끄기: Ctrl + C)
mkdocs serve
```

`docs/windows/amcache.md` 를 열어 내용을 채운 뒤:

```powershell
# 무엇이 바뀌었는지 확인 (빨간 글씨 = 아직 add 안 됨)
git status
# 바뀐 것 전부 스테이지에 (특정 파일만: git add docs/windows/amcache.md)
git add -A
# 스냅샷 + 메시지
git commit -m "Add amcache page"
# GitHub로 → 1~2분 뒤 사이트 반영
git push
```

commit 메시지는 영어 한 줄, 동사로 시작하는 습관이 좋습니다: `Add …`, `Update …`, `Fix …`, `Remove …`.

명령어 대신 VS Code 왼쪽 **Source Control**(가지 모양 아이콘)에서 메시지 입력 → ✓ Commit → *Sync Changes* 버튼을 눌러도 똑같습니다.

## 5. 이미 push한 뒤 파일을 고쳤을 때

Git은 "바뀐 것만" 다시 올립니다. 파일을 덮어쓰거나 수정한 뒤 같은 3단계를 반복하면 됩니다.

```powershell
# modified: mkdocs.yml 처럼 표시됨
git status
git add mkdocs.yml
git commit -m "Set GitHub username and dev port"
git push
```

## 6. 컴퓨터 없이 고치기 (GitHub 웹)

사이트의 아무 페이지 오른쪽 위 연필(편집) 아이콘을 누르면 GitHub 편집기가 열립니다. 고친 뒤 초록색 **Commit changes** → 자동 배포. 새 페이지는 GitHub에서 `docs/<섹션>/` 폴더로 들어가 **Add file → Create new file**, `templates/` 폴더의 템플릿 내용을 복사해 붙이면 됩니다.

웹에서 고친 뒤 컴퓨터로 돌아오면 반드시 `git pull` 을 먼저 하세요. 안 하면 다음 push 때 충돌이 납니다.

## 7. 자주 보는 상황과 해결

**`git push` 가 rejected 되면서 "fetch first" 라고 나올 때** — GitHub에 내 컴퓨터에 없는 변경(웹 편집, 다른 PC)이 있는 것입니다.

```powershell
# 먼저 받아서 합치기
git pull
# 다시 올리기
git push
```

**pull 하다가 CONFLICT 가 났을 때** — 같은 파일의 같은 부분을 양쪽에서 고친 경우입니다. VS Code가 해당 파일에 `<<<<<<<`, `=======`, `>>>>>>>` 표시와 함께 *Accept Current / Incoming / Both* 버튼을 보여줍니다. 원하는 쪽을 선택하고 저장한 뒤:

```powershell
git add -A
git commit -m "Resolve merge conflict"
git push
```

**실수로 고친 파일을 마지막 commit 상태로 되돌리기** (아직 add/commit 안 했을 때)

```powershell
# 파일 하나
git restore docs/windows/amcache.md
# 전부 (주의: 저장 안 한 작업 사라짐)
git restore .
```

**add 는 했는데 commit 전에 빼고 싶을 때**

```powershell
git restore --staged docs/windows/amcache.md
```

**마지막 commit 메시지 오타 고치기** (push 전)

```powershell
git commit --amend -m "Add amcache page"
```

**어떤 파일이 왜 바뀌었는지 보기**

```powershell
# add 전 변경 내용
git diff
# add 후, commit 전 변경 내용
git diff --staged
# 최근 commit 10개 한 줄씩
git log --oneline -10
git log --oneline -- docs/windows/amcache.md # 특정 파일의 이력
```

**예전 버전 내용을 잠깐 보고 싶을 때**

```powershell
# 한 commit 전의 파일 내용 출력
git show HEAD~1:docs/windows/amcache.md
git show <commit id>:docs/windows/amcache.md
```

**로그인/인증이 계속 물어볼 때** — Git Credential Manager가 보통 자동 저장합니다. 안 되면 `git config --global credential.helper manager` 실행 후 다시 push.

**`.venv` 나 `site/` 폴더가 status 에 뜰 때** — `.gitignore` 에 이미 들어 있어야 합니다. 뜬다면 `.gitignore` 파일에 `.venv/` 와 `site/` 줄이 있는지 확인하세요.

**`mkdocs serve` 가 포트 에러(WinError 10013)를 낼 때** — Git 문제가 아니라 8000번 포트가 막힌 것입니다. `mkdocs.yml` 맨 아래 `dev_addr: 127.0.0.1:8001` 이 있으면 8001로 열리고, 그것도 막히면 `mkdocs serve -a 127.0.0.1:8080` 처럼 다른 포트를 지정합니다.

## 8. 명령어 한 장 요약

| 하고 싶은 것 | 명령 |
|---|---|
| 저장소 새로 받기 | `git clone https://github.com/DFIDwiz-sketch/dfir-handbook.git` |
| 최신 내용 받기 | `git pull` |
| 바뀐 것 확인 | `git status` / `git diff` |
| 전부 스테이지 | `git add -A` |
| 스냅샷 | `git commit -m "메시지"` |
| 올리기(=배포) | `git push` |
| 이력 보기 | `git log --oneline -10` |
| 파일 되돌리기 | `git restore <파일>` |
| 스테이지 취소 | `git restore --staged <파일>` |
| 마지막 메시지 수정 | `git commit --amend -m "새 메시지"` |
| 새 페이지 | `python new.py <섹션>/<이름> -t <템플릿>` |
| 미리보기 | `mkdocs serve` |

## 9. 폴더 구조 참고

```
dfir-handbook/
  mkdocs.yml                   사이트 설정 (거의 안 건드림)
  requirements.txt             파이썬 패키지 목록
  new.py                       새 페이지 생성 스크립트
  templates/                   페이지 템플릿 5종
  docs/                        ← 여기 .md 파일이 곧 사이트 페이지
    .pages                     최상위 탭 순서
    index.md                   홈
    basics/ windows/ linux/ network/ memory/ splunk/ adversary/ tools/ playbooks/
      index.md                 섹션 첫 페이지
      .pages                   섹션 안 순서
  .github/workflows/deploy.yml push 시 자동 배포
  .gitignore                   .venv/, site/ 등 올리지 않을 것
  .venv/                       (컴퓨터마다 로컬, GitHub에 안 올라감)
  site/                        (mkdocs build 결과, 안 올라감)
```

---

저장소: https://github.com/DFIDwiz-sketch/dfir-handbook · 사이트: https://DFIDwiz-sketch.github.io/dfir-handbook/
