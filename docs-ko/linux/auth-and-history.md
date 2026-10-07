---
title: 인증과 셸 히스토리
tags:
  - artifact
  - linux
  - logs
---

# 인증과 셸 히스토리 { #authentication-shell-history }

<div class="dfir-meta" markdown>
**분류:** Linux · **출처:** 인증 로그, wtmp/btmp, 셸 히스토리 · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    Linux에서 "누가 들어왔고 무엇을 입력했나"는 몇 개의 텍스트 로그(`/var/log/auth.log` 또는 `secure`, journald), 바이너리 로그인 데이터베이스(`wtmp`/`btmp`/`lastlog`), 사용자별 셸 히스토리 파일에 있습니다. 모두 읽기 쉽지만 공격자가 변조하기도 쉬우므로, 서로 대조하고 파일시스템 타임라인과도 대조해야 합니다.

## 인증 로그 { #authentication-logs }

| 파일 | 배포판 | 내용 |
|---|---|---|
| `/var/log/auth.log` | Debian/Ubuntu | SSH, sudo, su, PAM, cron 인증, 로그인 |
| `/var/log/secure` | RHEL/CentOS/Fedora | 같은 내용, RHEL 계열 |
| `journalctl` (systemd 저널) | 모든 systemd | 인증을 포함한 구조화된 로그 (`_SYSTEMD_UNIT=sshd.service`) — 텍스트 로깅이 꺼져 있으면 *유일한* 사본일 수 있음 |
| `/var/log/audit/audit.log` | auditd 설치 시 | 커널 수준 인증, execve, 파일 접근 — 있다면 가장 풍부한 출처 |

여기서 읽어 낼 것:

```bash
# Successful SSH logins: user, source IP, method (password/publickey)
grep -E "sshd.*Accepted" /var/log/auth.log
#   "Accepted publickey for root from 203.0.113.7 port 5123 ssh2: RSA SHA256:..."

# Failed SSH (brute force) — count by source IP
grep -E "sshd.*Failed password" /var/log/auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn | head

# sudo usage: who ran what as whom
grep -E "sudo:.*COMMAND" /var/log/auth.log
#   "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"

# su / new sessions / user & group changes
grep -E "su\[|session opened|useradd|usermod|groupadd|passwd" /var/log/auth.log

# From the journal instead (survives text-log deletion)
journalctl -u ssh -o short-iso | grep -Ei "accepted|failed|invalid user"
journalctl _COMM=sudo -o short-iso
```

신호: `Accepted publickey for root` (root 직접 로그인은 보통 꺼져 있어야 함), `Failed password`가 몰려 나온 뒤 `Accepted` (성공), `Invalid user` 훑기 (사용자명 열거), 예상 밖의 국가/ASN에서 `Accepted`, 평소 그러지 않는 사용자의 root sudo, 새 계정/그룹 이벤트 (`useradd`, `sudo`/`wheel`에 추가).

## 로그인 데이터베이스 (바이너리) { #login-databases-binary }

| 파일 | 읽는 명령 | 내용 |
|---|---|---|
| `/var/log/wtmp` | `last` | 성공한 로그인/로그아웃 + 재부팅, 출발지와 시간 포함 |
| `/var/log/btmp` | `lastb` (root) | **실패한** 로그인 시도 |
| `/var/run/utmp` | `who`, `w` | **현재** 로그인한 사용자 |
| `/var/log/lastlog` | `lastlog` | 계정별 마지막 로그인 시각 |

```bash
last -Faiw                 # full timestamps, IPs, no truncation
last -f /path/to/wtmp      # a wtmp pulled from an image
lastb -Fai                 # failed logins (brute-force sources)
who -a ; w                 # live sessions right now (do this during live response)
```

!!! warning "변조 대상입니다"
    `wtmp`/`btmp`/`utmp`는 바이너리이고, 공격자는 도구로 특정 항목을 0으로 지웁니다 (`utmpdump`로 편집 후 다시 가져오기, 또는 전용 클리너). `auth.log`에는 있는데 `last`에는 없는 로그인(또는 그 반대), 바쁜 서버인데 지나치게 깨끗한 `wtmp`는 그 자체로 발견 사항입니다. `journalctl`과 `audit.log`는 별도의 사본이니 비교하세요.

## 셸 히스토리 { #shell-history }

| 파일 | 메모 |
|---|---|
| `~/.bash_history` | Bash — **정상 로그아웃 시에만 기록**, `HISTTIMEFORMAT`을 설정하지 않았으면 타임스탬프 없음; 크기는 `HISTSIZE`로 제한 |
| `~/.zsh_history` | Zsh — epoch 타임스탬프가 있는 경우가 많음 (`: 1699999999:0;command`) |
| `~/.local/share/fish/fish_history`, `~/.python_history`, `~/.mysql_history`, `~/.psql_history`, `~/.rediscli_history`, `~/.lesshst` | 그 밖의 대화형 도구 |
| `/root/.bash_history` | root의 히스토리 — 항상 확인 |

```bash
# Every user's bash history in one pass
for h in /home/*/.bash_history /root/.bash_history; do echo "== $h =="; cat "$h" 2>/dev/null; done

# Zsh with timestamps decoded
awk -F';' '/^: [0-9]/{ "date -d @"substr($1,3,10) | getline d; print d" | "$0 }' ~/.zsh_history
```

!!! tip "히스토리가 없다는 건 이상 없음이 아니라 신호입니다"
    공격자는 히스토리를 습관적으로 끄거나 지웁니다: `unset HISTFILE`, `export HISTSIZE=0`, `ln -sf /dev/null ~/.bash_history`, `history -c`, 또는 기록이 남지 않는 셸에서 실행. 활발히 쓰이는 계정의 히스토리가 비어 있거나 `/dev/null`로 심볼릭 링크돼 있다면 수상합니다. 그럴 땐 **auditd**(`execve`가 모든 명령을 인수와 함께 기록), `journald`, 프로세스 회계(`acct`가 켜져 있다면 `lastcomm`/`sa`), 네트워크/호스트 텔레메트리로 넘어가세요.

## 모든 것을 교차 확인하기 { #cross-check-everything }

로그 하나는 거짓말을 할 수 있지만, 교집합은 그러지 않습니다. 모든 출처로 그림을 그리고 서로 다른 점을 기록하세요:

- `auth.log`가 사용자 X가 시각 T에 IP에서 로그인했다고 말하면 → `last`/`wtmp`도 동의하나? 셸 히스토리에 T 직후 명령이 있나? 파일시스템의 `$MFT`에 해당하는 것([타임스탬프](filesystem-timestamps.md))에 그때 생성된 파일이 있나?
- `auth.log`에 root로의 sudo가 있으면 → 무엇을 실행했나(`COMMAND=`), bash 히스토리 / auditd가 확인해 주나?
- SSH `Accepted publickey` → 누구의 키인가? 사용자가 추가하지 않은 키가 `~/.ssh/authorized_keys`에 있는지 확인 ([지속성](persistence.md)).

## 라이브 대응 빠른 세트 { #live-response-quick-set }

```bash
w ; who -a                                  # who's on now
last -Faiw | head -40                       # recent logins
lastb -Fai | head                           # recent failures
ss -tunap                                    # current connections + owning process
grep -E "Accepted|sudo.*COMMAND|useradd" /var/log/auth.log | tail -50
for h in /home/*/.bash_history /root/.bash_history; do echo "== $h =="; tail -50 "$h"; done
```

## 참고 자료 { #references }

- [Linux auth logging — man sshd, PAM](https://man7.org/linux/man-pages/man8/sshd.8.html)
- [`last`, `lastb`, `utmp` formats](https://man7.org/linux/man-pages/man1/last.1.html)
- [Linux auditd](https://man7.org/linux/man-pages/man8/auditd.8.html)
- 관련 페이지: [지속성](persistence.md) · [파일시스템과 타임스탬프](filesystem-timestamps.md) · [로그와 트리아지](logs-and-triage.md)
