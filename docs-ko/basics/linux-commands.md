---
title: 필수 Linux 명령어
tags:
  - concept
  - basics
  - linux
---

# 필수 Linux 명령어 { #essential-linux-commands }

<div class="dfir-meta" markdown>
**분류:** 기초 · **초점:** DFIR 분석가가 매일 쓰는 명령어 · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    정말 기초인 파일·폴더 만들기, 복사, 이동, 삭제, 편집, 리다이렉션부터 조사 중에 계속 쓰는 명령어(이동, 검색, 파이프, 프로세스·네트워크 확인, 증거를 안전하게 다루기)까지 정리했습니다. 각각 실제 예시와 중요한 옵션을 붙였습니다. 이 명령어들을 *조사에* 어떻게 쓰는지(어떤 로그가 어떤 질문에 답하는지)는 [Linux 포렌식 섹션](../linux/index.md)을 보세요.

## 명령어의 구조 { #command-anatomy }

명령어는 `program [options] [arguments]` 형태입니다. 옵션(플래그)은 `-`(짧은 형태, `-l`)나 `--`(긴 형태, `--all`)로 시작하고, 짧은 플래그는 합쳐 쓸 수 있습니다(`ls -la` = `ls -l -a`). 어떤 옵션은 값을 받습니다(`-p 2222`, `--output=file`). 인수(argument)는 명령이 작업할 대상(파일, 경로)입니다.

```bash
ls -la /var/log        # program=ls, options=-la, argument=/var/log
```

자주 쓰는 키: ++tab++ 이름 자동 완성, ++ctrl+c++ 실행 중인 명령 중지, ++ctrl+r++ 명령 기록 검색, ++up++/++down++ 이전 명령 넘기기, `clear`(또는 ++ctrl+l++) 화면 지우기. `history`는 입력했던 명령 목록을 보여 주고, `!!`는 마지막 명령을 다시 실행합니다(`sudo !!`는 root로 다시 실행).

경로: `/`는 루트, `.`는 현재 위치, `..`는 상위 폴더, `~`는 홈 폴더입니다. 맨 앞에 `/`가 있으면 절대 경로(`/etc/passwd`), 없으면 상대 경로(`logs/auth.log`)입니다.

## 이동하고 둘러보기 { #navigating-looking-around }

| 명령어 | 하는 일 | 예시 |
|---|---|---|
| `pwd` | 현재 폴더 출력 | `pwd` → `/var/log` |
| `ls` | 파일 목록 | `ls -la` (전부, 자세히) · `ls -lat` (최신순) · `ls -laR` (하위 폴더까지) · `ls -li` (inode) |
| `cd` | 폴더 이동 | `cd /var/log` · `cd -` (직전 폴더) · `cd` (홈) |
| `tree` | 폴더를 트리로 보기 | `tree -a -L 2 /etc` (모든 파일, 2단계 깊이) |
| `stat` | 파일 메타데이터와 타임스탬프 | `stat auth.log` (M/A/C, 지원하면 Birth도 표시) |
| `file` | 내용으로 파일 종류 판별 | `file /tmp/x` → `ELF 64-bit executable` (사실은 ELF인 "PNG" = 수상함) |
| `du` / `df` | 파일별 / 파일시스템별 사용량 | `du -sh /var/log/*` (항목별 크기) · `df -h` (남은 공간) |

```bash
# Newest files in a directory (recently touched = interesting during an incident)
ls -lat --time-style=full-iso /tmp | head
# Long listing explained: -l long, -a hidden(dot) files, -t sort by mtime, --time-style full timestamp
```

`ls -la`가 가장 많이 치게 될 명령입니다. 열 순서: 권한, 링크 수, 소유자, 그룹, 크기, mtime, 이름. 이름이 `.`로 시작하면 숨김 파일입니다(공격자는 `.` 이름을 좋아합니다).

## 파일과 폴더 만들기 { #creating-files-folders }

| 명령어 | 하는 일 | 예시 |
|---|---|---|
| `mkdir` | 폴더 만들기 | `mkdir cases` · `mkdir -p cases/2026/incident1` (`-p`는 상위 폴더도 같이 만듦) |
| `touch` | 빈 파일 만들기, 또는 타임스탬프 갱신 | `touch notes.txt` · `touch a.txt b.txt c.txt` (한 번에 여러 개) |
| `echo >` | 새 파일에 텍스트 쓰기 | `echo "first line" > notes.txt` |
| `printf >` | echo와 비슷하지만 형식을 정확히 지정 | `printf "a\nb\n" > list.txt` |
| `cat >` | 파일에 직접 내용 입력 (++ctrl+d++로 끝냄) | `cat > notes.txt` 입력 후 ++ctrl+d++ |
| `tee` | 파일**과** 화면에 동시에 쓰기 | `echo hi \| tee notes.txt` |

```bash
# Make a nested folder structure in one go
mkdir -p cases/incident-2026-0917/{collected,parsed,report}
#   -p creates every level; {a,b,c} expands to three siblings → creates all four dirs at once

# Create an empty file (or refresh its modification time if it exists)
touch cases/incident-2026-0917/report/notes.md

# Create a file with initial content
echo "# Incident notes" > cases/incident-2026-0917/report/notes.md
```

!!! warning "`>`는 덮어쓰고, `>>`는 덧붙입니다"
    `echo "x" > file`은 파일 내용 전체를 **바꿉니다**(없으면 새로 만듦). `echo "x" >> file`은 끝에 **추가**합니다. 둘을 헷갈리면 파일이 조용히 지워집니다 — 확실하지 않으면 `>>`를 쓰세요.

## 복사, 이동, 이름 바꾸기, 삭제 { #copying-moving-renaming-deleting }

| 명령어 | 하는 일 | 예시 |
|---|---|---|
| `cp` | 파일 복사 | `cp a.txt b.txt` · `cp -r dir/ backup/` (폴더는 재귀) · `cp -a` (메타데이터 모두 보존) |
| `mv` | 이동 **또는** 이름 변경 (같은 명령) | `mv old.txt new.txt` (이름 변경) · `mv file.txt /tmp/` (이동) |
| `rm` | 파일 삭제 | `rm file.txt` · `rm -r dir/` (재귀) · `rm -i file` (먼저 물어봄) |
| `rmdir` | **빈** 폴더 삭제 | `rmdir emptydir` |
| `ln -s` | 심볼릭 링크(바로가기) 만들기 | `ln -s /var/log/auth.log here.log` |

```bash
# Copy a whole folder, keeping timestamps/permissions (use -a for evidence)
cp -a /var/log/ ./log-backup/

# Rename is just "move to a new name in the same folder"
mv report-draft.md report-final.md

# Move several files into a directory
mv *.log logs/

# Delete — there is no recycle bin, deletion is immediate
rm scratch.txt
rm -r old-case/          # -r removes a directory and everything inside
```

!!! danger "`rm`은 영구 삭제입니다 — 되돌리기도, 휴지통도 없습니다"
    명령줄에는 휴지통이 없습니다. `rm -rf`는 폴더 트리를 즉시, 되돌릴 수 없게 지우고, `rm -rf /`(또는 공백 하나 실수한 `rm -rf / tmp`)는 시스템 전체를 지울 수 있습니다. 도움이 되는 습관: `rm -i`(삭제 전마다 물어봄)를 쓰고, ++enter++ 전에 경로를 다시 확인하고, 변수가 들어간 경로(`rm -rf "$DIR/"`)는 `$DIR`가 설정됐는지 확인하기 전에 절대 실행하지 마세요. 증거는 지우지 말고 격리 폴더로 **옮기세요**(`mv suspect /quarantine/`).

## 파일 편집하기 { #editing-files }

거의 모든 시스템에 편집기 두 개가 있습니다. **nano**가 초보자에게 쉽습니다:

```bash
nano notes.txt
#   Ctrl+O then Enter = save (write Out) ; Ctrl+X = exit ; Ctrl+W = search ; Ctrl+K = cut line
```

**vim**은 어디에나 있으니 살아남는 데 필요한 정도는 알아 두세요(실수로 들어가게 될 일이 *반드시* 생깁니다):

```bash
vim notes.txt
#   i        enter insert mode (now you can type)
#   Esc      leave insert mode (back to command mode)
#   :w       save        :q   quit        :wq  save & quit        :q!  quit WITHOUT saving
#   /word    search      dd   delete line      u   undo
```

편집기를 열지 않고 빠르게 고칠 때는 `sed`가 파일 안에서 바로 찾아 바꾸기를 합니다:

```bash
sed -i 's/old/new/g' file.txt      # -i edits the file directly; s/old/new/g replaces all occurrences
```

## 파일 읽기 { #reading-files }

| 명령어 | 하는 일 | 예시 |
|---|---|---|
| `cat` | 파일 전체 출력 | `cat /etc/passwd` |
| `less` | 페이지 단위로 보기 (검색 가능) | `less /var/log/auth.log` — `/pattern` 검색, `q` 종료, `G` 끝, `g` 처음 |
| `head` / `tail` | 처음 / 마지막 N줄 | `head -50 file` · `tail -100 file` · `tail -f file` (실시간 따라가기) |
| `nl` | 줄 번호 붙이기 | `nl script.sh` |
| `strings` | 바이너리에서 출력 가능한 문자열 추출 | `strings -a malware.bin \| grep -iE "http\|cmd\|\.dll"` |
| `xxd` / `hexdump` | 16진수 보기 | `xxd file \| head` · `xxd -s 0 -l 64 file` (오프셋 0부터 64바이트) |
| `zcat` / `zless` / `zgrep` | gzip 로그를 압축 풀지 않고 읽기 | `zgrep "Failed" /var/log/auth.log.*.gz` |

```bash
# Follow a log live during response (Ctrl+C to stop)
tail -f /var/log/auth.log
# Read a rotated, compressed log
zcat /var/log/syslog.2.gz | tail -50
```

!!! tip "증거에는 읽기 전용 도구를 쓰세요"
    `cat`/`less`/`grep`은 내용을 바꾸지 않지만, 라이브 시스템에서는 파일의 **atime**(접근 시간)을 갱신합니다. 증거를 볼 때는 **복사본**이나 **읽기 전용 마운트**에서 작업해 타임스탬프를 건드리지 마세요 — 그리고 `atime`은 원래 꺼져 있는 경우가 많다는 점도 기억하세요([타임스탬프](../linux/filesystem-timestamps.md)).

## 검색 — grep, find와 친구들 { #searching-grep-find-and-friends }

`grep`(텍스트 검색)과 `find`(파일시스템 검색)는 없으면 일을 못 하는 두 명령입니다.

```bash
# grep: search inside files
grep "Failed password" auth.log            # lines containing the phrase
grep -i "error" log                         # -i case-insensitive
grep -r "password" /etc/                     # -r recursive through a directory
grep -n "root" /etc/passwd                   # -n show line numbers
grep -v "^#" sshd_config                     # -v invert: lines NOT matching (drop comments)
grep -c "Accepted" auth.log                  # -c count matches
grep -E "Failed|Invalid" auth.log            # -E extended regex (OR)
grep -A3 -B1 "segfault" kern.log             # -A/-B lines After/Before context
grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" access.log   # -o only the match (extract IPs)
```

```bash
# find: locate files by criteria
find /home -name "*.sh"                       # by name
find / -type f -newermt "2026-08-20" 2>/dev/null   # modified after a date
find / -perm -4000 -type f 2>/dev/null        # setuid binaries (privilege persistence)
find /tmp -type f -mmin -60                    # modified in the last 60 minutes
find / -user www-data -type f 2>/dev/null      # owned by a user
find . -size +100M                             # larger than 100 MB (staged archives?)
find / -xdev -name ".*" -type f 2>/dev/null    # hidden files, stay on one filesystem
```

`2>/dev/null`은 "permission denied" 잡음을 버려서 결과만 보이게 합니다. `-xdev`는 `find`가 `/proc`, `/sys`, 네트워크 마운트로 헤매지 않게 합니다.

관련 명령: `awk`(필드 처리), `sed`(스트림 편집), `sort`, `uniq`, `cut`, `wc` — 아래 파이프 부분에서 다룹니다.

## 리다이렉션과 명령 연결 { #redirection-chaining }

모든 명령에는 스트림이 세 개 있습니다: **stdin**(입력), **stdout**(정상 출력), **stderr**(오류). 아래 연산자로 방향을 바꿉니다:

| 연산자 | 하는 일 | 예시 |
|---|---|---|
| `>` | stdout → 파일 (**덮어쓰기**) | `ls > files.txt` |
| `>>` | stdout → 파일 (**덧붙이기**) | `echo done >> log.txt` |
| `2>` | stderr → 파일 | `find / 2> errors.txt` |
| `2>/dev/null` | 오류 버리기 | `find / -name x 2>/dev/null` ("permission denied" 숨기기) |
| `&>` | stdout+stderr 둘 다 → 파일 | `command &> all.txt` |
| `<` | 파일 → stdin | `sort < names.txt` |
| `\|` | 앞 명령의 stdout → 다음 명령의 stdin ("파이프") | `ps aux \| grep ssh` |

한 줄에서 명령 연결하기:

| 연산자 | 하는 일 | 예시 |
|---|---|---|
| `;` | 결과와 상관없이 순서대로 실행 | `cd /tmp ; ls` |
| `&&` | 앞 명령이 성공했을 **때만** 다음 실행 | `mkdir out && cd out` |
| `\|\|` | 앞 명령이 실패했을 **때만** 다음 실행 | `ping -c1 host \|\| echo "down"` |
| `&` | 백그라운드 실행 | `long-job &` |

```bash
# Save results and errors separately
find / -name "*.conf" > found.txt 2> denied.txt
# Only continue if the first step worked
tar czf backup.tgz /data && echo "backup ok"
```

## 파이프와 텍스트 처리 — 진짜 힘 { #pipes-text-processing-the-real-power }

파이프 `|`는 한 명령의 출력을 다음 명령으로 보냅니다. 원시 로그를 답으로 바꾸는 방법이 바로 이것입니다.

```bash
# Top 10 source IPs of failed SSH logins
grep "Failed password" auth.log \
  | grep -oE "from [0-9.]+" \
  | awk '{print $2}' \
  | sort | uniq -c | sort -rn | head
```

읽는 법: `grep`이 실패 줄을 찾고 → `grep -oE`가 `from <IP>`를 뽑고 → `awk '{print $2}'`가 두 번째 단어(IP)를 출력하고 → `sort`가 같은 IP끼리 모으고 → `uniq -c`가 중복을 합치며 **개수를 세고** → `sort -rn`이 그 개수로 큰 순서대로 정렬하고 → `head`가 상위 10개를 보여 줍니다. 결과는 무차별 대입 출발지 순위표입니다.

기본 블록:

| 명령어 | 하는 일 | 예시 |
|---|---|---|
| `awk` | 필드 기반 처리 | `awk -F: '{print $1}' /etc/passwd` (`:`로 나눈 첫 번째 필드) |
| `sed` | 찾아 바꾸기, 스트림 편집 | `sed 's/old/new/g' file` · `sed -n '10,20p' file` (10–20번째 줄) |
| `sort` | 줄 정렬 | `sort -rn` (숫자 역순) · `sort -u` (중복 제거) · `sort -t: -k3 -n` (`:` 기준 3번째 필드로) |
| `uniq` | 붙어 있는 중복 합치기 | `uniq -c` (개수) — **먼저 `sort` 필수** |
| `cut` | 열 추출 | `cut -d: -f1,3 /etc/passwd` (1, 3번째 필드) |
| `wc` | 세기 | `wc -l file` (줄 수) · `wc -c` (바이트) |
| `tr` | 문자 바꾸기/지우기 | `tr 'A-Z' 'a-z'` · `tr -d '\0'` (널 제거) · `tr '\0' '\n'` |
| `tee` | 파일**과** 화면에 쓰기 | `... | tee out.txt` |
| `xargs` | 입력을 인수로 바꾸기 | `find . -name "*.log" | xargs grep "error"` |

```bash
# awk is a mini-language: filter + compute
awk -F: '$3 == 0 {print $1}' /etc/passwd        # users with UID 0 (should be only root)
awk -F: '$3 >= 1000 {print $1}' /etc/passwd      # regular (human) accounts
awk '{sum+=$1} END {print sum}' numbers          # sum a column
awk '$9 == 404 {print $7}' access.log            # requested paths that returned 404

# Unique-and-count pattern (memorise this one)
cut -d' ' -f1 access.log | sort | uniq -c | sort -rn | head   # top client IPs in a web log
```

## 프로세스와 네트워크 { #processes-the-network }

| 명령어 | 하는 일 | 예시 |
|---|---|---|
| `ps` | 프로세스 스냅샷 | `ps auxfww` (전부, 전체, 트리) · `ps -eo pid,ppid,user,cmd` |
| `top` / `htop` | 실시간 프로세스 보기 | `top` — `P` CPU순, `M` 메모리순, `q` 종료 |
| `ss` | 소켓/연결 | `ss -tunap` (TCP+UDP, 숫자, 전부, 프로세스) · `ss -tlnp` (리스닝) |
| `lsof` | 열린 파일/소켓 | `lsof -nP -iTCP -sTCP:LISTEN` (리스닝 포트) · `lsof +L1` (삭제됐지만 열려 있는 파일) |
| `kill` | 프로세스에 시그널 보내기 | `kill -9 <pid>` (강제) — **증거부터 수집할 것** |
| `pgrep` / `pkill` | 이름으로 찾기/종료 | `pgrep -a nginx` (인수와 함께 목록) |

```bash
# Full process tree with command lines (read this to spot bad parent→child)
ps auxfww
# Network connections with the owning process — the key pivot in live response
ss -tunap
# What is listening (backdoor listeners show here)
ss -tlnp
# A process's details via /proc
cat /proc/<pid>/cmdline | tr '\0' ' '; echo      # full command line
readlink /proc/<pid>/exe                          # the actual binary (may say "(deleted)")
```

사고 중에 이것들을 어떻게 읽는지는 [Linux 로그와 트리아지](../linux/logs-and-triage.md)를 보세요.

## 권한과 소유권 { #permissions-ownership }

```bash
ls -l file            # -rwxr-xr-- : owner rwx, group r-x, others r--
chmod 640 file        # rw- r-- --- (owner read/write, group read, others none)
chmod +x script.sh    # add execute
chown user:group file # change owner and group
id                    # your uid/gid/groups
sudo -l               # what you're allowed to run as root
lsattr file           # extended attrs — 'i' = immutable (attacker anti-delete trick)
chattr -i file        # remove immutable so you can delete/quarantine
```

권한 표기: `rwx` 세 묶음(소유자, 그룹, 그 외). 숫자로는 `r=4, w=2, x=1`을 묶음마다 더해서 `750` = `rwxr-x---`입니다. 누구나 쓸 수 있는 파일(`chmod 777`)이나 예상치 못한 setuid 비트(소유자 실행 자리에 `s`)는 다시 볼 가치가 있습니다.

## 증거를 안전하게 다루기 { #handling-evidence-safely }

```bash
# Hash a file (integrity — do this to every piece of evidence)
sha256sum evidence.raw > evidence.raw.sha256
sha256sum -c evidence.raw.sha256                  # verify later (prints OK/FAILED)
md5sum file                                        # legacy tools still want md5

# Copy preserving all metadata (timestamps, perms, owner)
cp -a source dest                                  # -a = archive (preserve everything)
rsync -a --progress src/ dest/                     # large trees, resumable

# Mount a disk image read-only (never write to evidence)
mount -o ro,loop,noexec image.dd /mnt/evidence
mount -o ro,loop,offset=$((2048*512)) image.dd /mnt/evidence   # partition at sector 2048

# Compress/extract collections
tar czf triage.tar.gz /path/to/collect            # create gzip archive
tar xzf triage.tar.gz                              # extract
gzip -d file.gz ; zcat file.gz                     # single-file gzip
```

!!! warning "전후로 해시하고, 읽기 전용으로 마운트하세요"
    모든 증거 파일은 **손대기 전에 SHA-256**을 구하고 작업 후에 다시 구해서 일치해야 합니다 — 그래야 바뀌지 않았다는 걸 증명할 수 있습니다([이미징과 수집](../tools/imaging-collection.md)). 이미지는 항상 **`ro`**(읽기 전용)로 마운트하세요. 실수로 한 번 쓰면 증거가 훼손되고 해시가 깨집니다.

## SSH와 원격 작업 { #ssh-remote-work }

```bash
ssh user@host                                      # connect
ssh -i key.pem user@host                            # with a specific key
ssh -p 2222 user@host                               # non-standard port
scp file user@host:/path/                           # copy a file over SSH
scp -r dir user@host:/path/                          # recursive
scp user@host:/var/log/auth.log ./                  # pull a log from a remote box
sftp user@host                                       # interactive file transfer
# Check what keys grant access to an account you're investigating
cat ~/.ssh/authorized_keys
```

## 도움말 보기 { #getting-help }

```bash
man ss              # full manual (q to quit, /pattern to search)
ss --help           # quick option summary
tldr find           # community examples (if tldr installed) — faster than man
which volatility3   # where is this binary?
apropos network     # find commands related to a keyword
type -a ls          # is it a binary, alias, or function?
```

## 실제로 가장 먼저 쓰게 되는 명령들 { #the-commands-youll-actually-reach-for-first }

라이브 대응 순간에는 이 몇 개로 대부분 해결됩니다:

```bash
w; who -a                                    # who's logged in now
ps auxfww                                     # what's running
ss -tunap                                     # what's connected / listening
ls -lat /tmp /dev/shm /var/tmp | head         # recent drops
grep -Ei "accepted|failed|sudo" /var/log/auth.log | tail   # recent auth
find / -xdev -mmin -120 -type f 2>/dev/null | head    # changed in last 2 hours
```

## 참고 자료 { #references }

- [The Linux Command Line (무료 책, W. Shotts)](https://linuxcommand.org/tlcl.php)
- [explainshell.com — 명령을 붙여 넣으면 플래그마다 설명](https://explainshell.com/)
- [GTFOBins — Unix 바이너리가 LOLBin처럼 악용되는 방법](https://gtfobins.github.io/)
- 관련 페이지: [Linux 포렌식](../linux/index.md) — 이 명령어들의 조사 활용 · [잘 알려진 포트](well-known-ports.md)
