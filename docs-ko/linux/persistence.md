---
title: Linux 지속성
tags:
  - artifact
  - linux
  - persistence
---

# Linux 지속성 { #linux-persistence }

<div class="dfir-meta" markdown>
**분류:** Linux · **전술:** 지속성 (ATT&CK T1053/T1543/T1546/T1098) · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    Linux에는 코드를 자동 실행할 곳이 수십 군데 있습니다 — cron, systemd, 셸 프로필, SSH 키, PAM, 커널 모듈 등. 공격자는 하나만 있으면 됩니다. 이 페이지는 체크리스트입니다: 각각 어디 있는지, "정상"은 어떤 모습인지, 심어 둔 것을 어떻게 찾는지.

## 예약 작업 (cron과 친구들) { #scheduled-tasks-cron-friends }

| 위치 | 메모 |
|---|---|
| `/etc/crontab`, `/etc/cron.d/*` | 시스템 전체; 각 줄에 실행할 사용자가 적혀 있음 |
| `/etc/cron.{hourly,daily,weekly,monthly}/` | 그 주기로 실행되는 스크립트 |
| `/var/spool/cron/crontabs/<user>` (Debian) · `/var/spool/cron/<user>` (RHEL) | 사용자별 crontab — `crontab -l -u <user>`로 읽기 |
| `/etc/anacrontab` | Anacron (항상 켜져 있지 않은 머신용) |
| `at` 작업: `/var/spool/at/` , `atq` | 한 번만 실행되는 예약 작업 |
| systemd 타이머 | 아래 참고 — cron의 최신 대체재 |

```bash
# Dump every crontab on the box
for u in $(cut -f1 -d: /etc/passwd); do echo "== $u =="; crontab -l -u "$u" 2>/dev/null; done
cat /etc/crontab /etc/cron.d/* 2>/dev/null
ls -la /etc/cron.{hourly,daily,weekly,monthly}/ /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null
```

신호: `/tmp`, `/dev/shm`, `/var/tmp`, 사용자 홈의 스크립트를 실행하거나 base64/`curl|bash` 한 줄짜리를 실행하는 cron 줄; 매분 실행되는 작업 (비콘); `cron.d` 안의 이상한 파일 이름.

## systemd (서비스와 타이머) { #systemd-services-timers }

```bash
# Services & timers, including recently changed unit files
systemctl list-unit-files --type=service --state=enabled
systemctl list-timers --all
# Unit files sorted by modification time — recently added = suspicious
ls -lat /etc/systemd/system/ /usr/lib/systemd/system/ /run/systemd/system/ ~/.config/systemd/user/ 2>/dev/null | head -40
# Read a suspicious unit
systemctl cat suspicious.service
```

신호: `ExecStart=`가 `/tmp`/홈/이상한 경로나 다운로드 후 실행하는 스크립트를 가리키는 `.service`; `~/.config/systemd/user/` 아래의 **사용자** 유닛 (그 사용자 로그인 시 실행, 놓치기 쉬움); 악성 `.service`와 짝지어진 `.timer`; 오래된 파일들 사이에서 mtime이 최근인 유닛 파일. `systemd-run`으로 임시 유닛도 만들 수 있으니 `journalctl`에서 생성 기록을 확인하세요.

## 셸과 로그인 프로필 { #shell-login-profiles }

모든 대화형 셸(과 일부 비대화형 셸)이 이 파일들을 불러옵니다 — 고전적이고 조용한 지속성:

```bash
ls -la /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc ~/.bashrc ~/.bash_profile ~/.profile ~/.bash_login ~/.zshrc /etc/zsh/* 2>/dev/null
grep -REn "curl|wget|base64|/tmp/|/dev/shm|nc |ncat|bash -i|python -c|eval" /etc/profile.d/ ~/.bashrc ~/.profile 2>/dev/null
```

`~/.ssh/rc`와 `/etc/ssh/sshrc`(SSH 로그인마다 실행), `~/.config/environment.d/`도 확인하세요.

## SSH 키와 설정 { #ssh-keys-config }

```bash
# Unauthorised authorized_keys entries (the #1 Linux backdoor)
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do echo "== $f =="; cat "$f" 2>/dev/null; done
# Odd SSHD config: forced commands, alternate authorized_keys paths, PermitRootLogin
grep -Ev "^#|^$" /etc/ssh/sshd_config | grep -Ei "AuthorizedKeysFile|ForceCommand|PermitRootLogin|Match|PermitUserEnvironment"
```

신호: 사용자가 추가하지 않은 `authorized_keys`의 키 (주석/날짜를 `$MFT`에 해당하는 mtime과 비교); 공격자가 쓸 수 있는 경로를 가리키는 `AuthorizedKeysFile`; `ForceCommand`; `PermitUserEnvironment yes` (`~/.ssh/environment`로 변수 주입 가능).

## 계정과 권한 { #accounts-privileges }

```bash
# UID 0 accounts other than root (backdoor superusers)
awk -F: '$3==0 {print $1}' /etc/passwd
# Accounts with a login shell / recently added; empty-password accounts
awk -F: '$7 ~ /(bash|sh|zsh)$/ {print $1":"$7}' /etc/passwd
awk -F: '($2=="" ){print $1" has EMPTY password"}' /etc/shadow 2>/dev/null
# Sudoers changes
cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -Ev "^#|^$"
# passwd/shadow/group modification times vs other /etc files
ls -la --time-style=full-iso /etc/passwd /etc/shadow /etc/group /etc/sudoers
```

신호: 두 번째 UID 0 계정; 셸이 부여된 서비스 계정; NOPASSWD를 주는 `sudoers.d/`의 새 항목; 알려진 변경과 맞지 않는 `passwd`/`shadow` mtime.

## PAM, LD_PRELOAD, 더 낮은 수준의 기법 { #pam-ld_preload-and-lower-level-tricks }

| 벡터 | 위치 | 확인할 것 |
|---|---|---|
| 악성 PAM 모듈 | `/etc/pam.d/*`, `/lib*/security/` | 패키지에서 온 게 아닌 `pam_*.so` (`rpm -Vf` / `dpkg -V`); 이상한 모듈을 호출하는 줄 (자격증명을 훔치는 PAM 백도어) |
| `LD_PRELOAD` / `ld.so.preload` | `/etc/ld.so.preload`, 프로필/유닛의 `LD_PRELOAD` | `/etc/ld.so.preload`에 내용이 있으면 무엇이든 자세히 볼 것 (유저랜드 루트킷 훅) |
| 로드 가능한 커널 모듈 | `lsmod`, `/etc/modules`, `/etc/modules-load.d/` | 서명 없는/알 수 없는 모듈 (커널 루트킷); `lsmod`를 패키지 소유 모듈과 비교 |
| 초기화 스크립트 (SysV) | `/etc/init.d/`, `/etc/rc.local`, `/etc/rc*.d/` | `rc.local`은 고전적인 투하 장소 |
| 오늘의 메시지 (MOTD) | `/etc/update-motd.d/` | 이곳의 스크립트는 로그인 시 root로 실행 |
| Udev 규칙 | `/etc/udev/rules.d/` | 장치 이벤트 때 실행되는 `RUN+=` |
| Git 훅 / 앱 수준 | 저장소 `.git/hooks/`, 웹 앱 설정 | 앱별 자동 실행 |
| Xorg/데스크톱 자동 시작 | `~/.config/autostart/`, `/etc/xdg/autostart/` | 워크스테이션에서 |

```bash
grep -R "" /etc/ld.so.preload 2>/dev/null            # should be empty on most systems
lsmod | tail -n +2 | awk '{print $1}'                 # compare against known-good
cat /etc/rc.local /etc/update-motd.d/* 2>/dev/null
```

## 무결성 검사 — 패키지 관리자에게 변조를 찾게 하기 { #integrity-check-let-the-package-manager-find-tampering }

바뀐 시스템 바이너리와 설정을 찾는 가장 빠른 방법은 패키지 데이터베이스에 무엇이 바뀌었는지 물어보는 것입니다:

```bash
# Debian/Ubuntu — files whose checksum no longer matches the package
dpkg --verify 2>/dev/null           # lines starting with "??5" = content changed
# RHEL/CentOS — S(size) M(mode) 5(md5) T(mtime) etc. flags per changed file
rpm -Va 2>/dev/null | grep -vE "^\.{8}" | grep -E "^..5|missing"
```

내용이 바뀌었다고 표시된 시스템 바이너리(`/bin/ls`, `sshd`, `/usr/bin/passwd`)는 트로이 목마화된 바이너리나 루트킷입니다 — 매우 강한 신호입니다.

## 훑기 도구 { #sweep-tools }

`chkrootkit`와 `rkhunter`가 이 검사 상당수를 자동화하고, `Linux Forensics` 류 스크립트(`UAC`, `CatScale`, 공격자 관점은 `LinPEAS`)가 전부 수집합니다. 이미지라면 `Velociraptor` Linux 아티팩트가 같은 일을 원격으로 합니다 — [도구](../tools/velociraptor.md) 참고.

## 참고 자료 { #references }

- [MITRE ATT&CK — Persistence (Linux)](https://attack.mitre.org/tactics/TA0003/) — T1053.003 (cron), T1543.002 (systemd), T1546.004 (셸 설정), T1098.004 (SSH 키)
- [chkrootkit](http://www.chkrootkit.org/) · [rkhunter](https://rkhunter.sourceforge.net/) · [UAC — Unix-like Artifacts Collector](https://github.com/tclahr/uac)
- 관련 페이지: [인증과 히스토리](auth-and-history.md) · [파일시스템과 타임스탬프](filesystem-timestamps.md) · [로그와 트리아지](logs-and-triage.md)
