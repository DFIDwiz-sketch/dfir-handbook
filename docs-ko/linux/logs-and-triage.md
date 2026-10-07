---
title: 로그, 프로세스, 라이브 트리아지
tags:
  - artifact
  - linux
  - logs
  - triage
---

# 로그, 프로세스, 라이브 트리아지 { #logs-processes-live-triage }

<div class="dfir-meta" markdown>
**분류:** Linux · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    라이브 상태이거나 막 이미징한 Linux 호스트에서 빨리 성과를 내는 방법: **로그**(syslog, journald, audit)를 정리하고, **실행 상태**(프로세스, 네트워크, 열린 파일)가 바뀌기 전에 스냅샷을 뜨고, 어떤 로그가 어떤 질문에 답하는지 아는 것 — 이 페이지는 그 지도와 바로 복사해 쓸 수 있는 트리아지 스크립트입니다.

## 로그 위치 { #log-locations }

| 로그 | 경로 | 답하는 질문 |
|---|---|---|
| 시스템 메시지 | `/var/log/syslog` (Debian), `/var/log/messages` (RHEL) | 일반 데몬/커널 메시지 |
| 인증 | `/var/log/auth.log` / `secure` | 로그인, sudo — [인증과 히스토리](auth-and-history.md) 참고 |
| 커널 | `/var/log/kern.log`, `dmesg` | 드라이버/모듈 로드, OOM, USB, segfault |
| systemd 저널 | `journalctl` (바이너리, 영구 저장이면 `/var/log/journal/`) | 모든 것, 구조화됨; **유일한** 사본인 경우가 많음 |
| auditd | `/var/log/audit/audit.log` | execve, 파일 접근, 시스템 콜 — 켜져 있다면 가장 풍부 |
| 패키지 관리자 | `/var/log/dpkg.log`, `/var/log/apt/history.log`, `/var/log/yum.log`/`dnf.rpm.log` | 무엇이 언제 설치/제거됐나 |
| Cron | `/var/log/cron` (RHEL), syslog (Debian) | cron 작업 실행 |
| 웹/앱 | `/var/log/apache2/`, `/var/log/nginx/`, 앱 폴더 | [웹셸 플레이북](../playbooks/webshell-server.md) 참고 |
| Wtmp/btmp/lastlog | `/var/log/wtmp` 등 | 로그인 데이터베이스 — [인증과 히스토리](auth-and-history.md) |
| 방화벽 | `journalctl -u firewalld` / `ufw.log` / `iptables` syslog | 차단/허용된 연결 |

```bash
# journald is the safety net when text logs are deleted or rotated
journalctl --list-boots                    # boot sessions
journalctl -b -1 -p err -o short-iso       # errors from the previous boot
journalctl -S "2026-08-20 00:00" -U "2026-08-21 00:00" -o short-iso   # a time window
journalctl _COMM=sshd + _COMM=sudo -o short-iso   # combine matches (auth events)
journalctl -k | grep -iE "module|segfault|oom|usb"

# What was installed around the incident
grep -E " install " /var/log/dpkg.log
awk '/Commandline:/{print}' /var/log/apt/history.log
```

!!! warning "auditd가 판을 바꿉니다"
    `auditd`가 실행 중이라면 `execve` 레코드가 **모든 명령을 전체 인수와 실행한 사용자와 함께** 알려 줍니다 — Sysmon 1 / 프로세스 명령줄 로깅에 해당하는 Linux 기능이고, 셸 히스토리를 지워도 남습니다. 규칙은 `auditctl -l`로 확인하고 `ausearch -m EXECVE -ts today` / `aureport -x`로 검색하세요. 켜져 *있지 않다면* 보고서에 그 공백을 적고 journald + bash 히스토리 + 네트워크 텔레메트리에 기대세요.

## 실행 상태 스냅샷 (라이브 대응 — 가장 먼저 수집) { #running-state-snapshot-live-response-capture-first }

휘발성 상태는 재부팅하거나 공격자가 정리하면 사라집니다. 다른 무엇보다 먼저 확보하세요 (메모리 이미지를 뜬다면 그보다도 먼저 — [이미징](../tools/imaging-collection.md) 참고):

```bash
# Processes — full tree, with command lines
ps auxfww                                   # forest view, full args
ps -eo pid,ppid,user,etimes,cmd --sort=start_time | tail -40   # newest processes

# Network — connections with owning process (the key pivot)
ss -tunap                                    # TCP/UDP, numeric, all, process
ss -tlnp                                     # listening ports + process (backdoor listeners)
# Old school if ss unavailable:
netstat -tunap

# Open files & deleted-but-running binaries
lsof -nP | grep -iE "LISTEN|ESTABLISHED"     # network file handles
ls -l /proc/*/exe 2>/dev/null | grep -i deleted   # self-deleting malware
lsof +L1                                      # deleted files still open

# Loaded kernel modules (rootkits)
lsmod ; cat /proc/modules

# Scheduled / persistence quick look — see Persistence page for the full sweep
systemctl list-timers --all ; crontab -l 2>/dev/null
```

## 프로세스 트리아지 — 무엇이 수상한가 { #process-triage-whats-suspicious }

| 찾을 것 | 이유 |
|---|---|
| `exe`가 `(deleted)`인 프로세스 | 자기 삭제 악성코드가 아직 실행 중 |
| `/tmp`, `/dev/shm`, `/var/tmp`, 홈 폴더에서 실행 중인 바이너리 | 정상 데몬은 `/usr`/`/sbin`에서 실행 |
| 디스크에 대응하는 바이너리가 없거나 / 패키지 소유가 아닌 프로세스 | 주입됐거나 떨어뜨린 것 |
| 이상한 포트에 이상한 소유자의 리스닝 소켓 | 백도어 / 리버스 셸 리스너 |
| 커널 스레드가 **아닌데** "커널" 이름(`[kworker/…]`)인 것 (실제 `exe`, 네트워크 소켓이 있음) | 위장 — 진짜 kthread는 PPID가 2이고 `/proc/<pid>/exe`가 없음 |
| CPU 사용량 높음 + 한 IP로의 아웃바운드 연결 | 암호화폐 채굴기 / 비콘 |
| `bash -i`, `nc`, `socat`, `python -c '...socket...'`, `/dev/tcp/` 리다이렉션 | 리버스 셸 |

```bash
# Processes running from suspicious paths
ls -l /proc/*/exe 2>/dev/null | grep -E "/tmp/|/dev/shm/|/var/tmp/|/home/"
# A process's full context
cat /proc/<pid>/cmdline | tr '\0' ' '; echo
readlink /proc/<pid>/cwd ; readlink /proc/<pid>/exe
cat /proc/<pid>/environ | tr '\0' '\n'      # env vars (LD_PRELOAD? proxy?)
ls -l /proc/<pid>/fd                          # open files/sockets
```

## 한 번에 돌리는 트리아지 스크립트 { #one-shot-triage-script }

```bash
#!/bin/sh
# Minimal live-response collector — redirect to a file on removable/network storage
OUT=/mnt/evidence/$(hostname)_$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUT"; exec > "$OUT/triage.txt" 2>&1
echo "=== date/uptime ==="; date -u; uptime
echo "=== who ==="; w; who -a; last -Faiw | head -40
echo "=== processes ==="; ps auxfww
echo "=== newest procs ==="; ps -eo pid,ppid,user,etimes,cmd --sort=start_time | tail -40
echo "=== network ==="; ss -tunap; echo "-- listening --"; ss -tlnp
echo "=== deleted-but-open ==="; ls -l /proc/*/exe 2>/dev/null | grep -i deleted; lsof +L1 2>/dev/null
echo "=== modules ==="; lsmod
echo "=== cron/timers ==="; for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done; cat /etc/crontab /etc/cron.d/* 2>/dev/null; systemctl list-timers --all
echo "=== authorized_keys ==="; for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do echo "-- $f --"; cat "$f" 2>/dev/null; done
echo "=== recent auth ==="; grep -Ei "accepted|failed|sudo.*command|useradd" /var/log/auth.log /var/log/secure 2>/dev/null | tail -80
echo "=== UID0 accounts ==="; awk -F: '$3==0{print $1}' /etc/passwd
echo "=== package integrity (sample) ==="; command -v rpm >/dev/null && rpm -Va 2>/dev/null | grep -E "^..5|missing" | head; command -v dpkg >/dev/null && dpkg --verify 2>/dev/null | head
```

철저하고 방어 가능한 수집에는 전용 수집기를 쓰세요: **UAC**(Unix-like Artifacts Collector)와 **CatScale**은 위의 모든 것을 구조화된 압축 파일로 모으고, **Velociraptor**는 여러 호스트에 원격으로 같은 일을 합니다 ([도구](../tools/velociraptor.md)).

## 참고 자료 { #references }

- [systemd journalctl](https://www.freedesktop.org/software/systemd/man/journalctl.html) · [auditd / ausearch / aureport](https://man7.org/linux/man-pages/man8/auditd.8.html)
- [UAC](https://github.com/tclahr/uac) · [CatScale](https://github.com/WithSecureLabs/LinuxCatScale)
- 관련 페이지: [인증과 히스토리](auth-and-history.md) · [지속성](persistence.md) · [파일시스템과 타임스탬프](filesystem-timestamps.md) · [이미징](../tools/imaging-collection.md)
