---
title: 파일시스템과 타임스탬프
tags:
  - artifact
  - linux
  - filesystem
---

# 파일시스템과 타임스탬프 { #filesystem-timestamps }

<div class="dfir-meta" markdown>
**분류:** Linux · **파일시스템:** ext4, xfs · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    Linux 파일에는 타임스탬프가 네 개(MACB) 있지만 — NTFS와 달리 — **crtime(생성 시각)**은 숨겨져 있고 `$FILE_NAME` 같은 두 번째 세트가 없어서 타임스톰핑을 잡기가 더 어렵습니다. 대신 **변경 시각(ctime)**, 저널, inode/링크 이상에 기대야 합니다.

## 네 가지 타임스탬프 (MACB) { #the-four-timestamps-macb }

| 타임스탬프 | `stat` 표시 이름 | 설정되는 때 | 공격자 조작 가능성 |
|---|---|---|---|
| **M** — 수정 | `Modify` (mtime) | 파일 **내용**이 바뀔 때 | `touch -m -d`, `touch -r` — 쉽게 위조 |
| **A** — 접근 | `Access` (atime) | 파일을 **읽을** 때 | 성능 때문에 꺼져 있는 경우가 많음 (`relatime`/`noatime`); 믿기 어려움 |
| **C** — 변경 | `Change` (ctime) | **inode 메타데이터**가 바뀔 때 (권한, 소유자, 링크, *또는* mtime 설정) | 시계를 바꾸지 않는 한 **`touch`로 설정 불가** — 타임스톰핑의 단서 |
| **B** — 생성 | `Birth` (crtime) | 파일이 **생성**될 때 | ext4/xfs inode에 저장되지만 **기본으로 안 보임** — `debugfs`/`xfs_db` 또는 최신 커널의 `stat` 필요 |

```bash
stat file                          # M, A, C shown; Birth shown if kernel/fs supports it
# ext4 birth time when stat won't show it:
debugfs -R "stat <inode>" /dev/sda1 2>/dev/null | grep -i crtime
# get inode first:
ls -i file
```

!!! tip "ctime이 타임스톰핑을 잡아냅니다"
    `touch -d "2020-01-01" evil`은 **mtime과 atime**을 과거로 설정하지만 — **ctime은 현재로 갱신**됩니다(inode를 바꿨으니까요). 그래서 `mtime`은 한참 과거인데 `ctime`이 최근이면 = 파일이 타임스톰핑됐다는 뜻입니다(또는 메타데이터가 정상적으로 바뀌었거나). `stat`의 Modify와 Change를 비교하세요. ctime까지 고치려는 공격자는 시스템 시계를 바꾸거나 장치에 원시 쓰기를 해야 하는데 — 훨씬 어렵고 그 자체로 탐지됩니다.

## 최근 바뀐 파일 찾기 { #finding-recently-changed-files }

```bash
# Files with content changed in the incident window (mtime)
find / -xdev -type f -newermt "2026-08-20 00:00" ! -newermt "2026-08-21 00:00" 2>/dev/null

# Files whose inode changed recently (ctime) — catches perms/owner/link changes and timestomps
find / -xdev -type f -cnewer /etc/hostname 2>/dev/null      # changed more recently than a reference file

# Suspicious locations first
find /tmp /var/tmp /dev/shm /run -type f 2>/dev/null | xargs ls -la --time-style=full-iso 2>/dev/null
```

`-xdev`는 `find`가 한 파일시스템에만 머물게 합니다(`/proc`, `/sys`, 네트워크 마운트로 헤매지 않게). `/dev/shm`(RAM 기반)은 재부팅하면 사라지고 "디스크"가 아니라서 즐겨 쓰이는 투하 장소입니다.

## 숨기거나 위장한 파일 { #hidden-disguised-files }

```bash
# Dotfiles and dot-dir tricks (". " , ".. ", "..." names)
find / -xdev -name ".*" -type f 2>/dev/null | grep -vE "/(\.bashrc|\.profile|\.ssh|\.config)"
find / -xdev -name "* *" 2>/dev/null            # names with spaces
# setuid/setgid binaries (privilege persistence) — compare to a known-good baseline
find / -xdev -perm -4000 -o -perm -2000 -type f 2>/dev/null | xargs ls -la 2>/dev/null

# Files masquerading by extension vs actual type
file /tmp/*                                       # "PNG" that is really an ELF
```

신호: `/tmp`에 있는 `.systemd`라는 이름의 ELF 바이너리; 어느 패키지에도 속하지 않는 setuid root 바이너리 (`dpkg -S`/`rpm -qf`가 아무것도 돌려주지 않음); `file`이 실행 파일이라고 말하는 "로그" 파일; 지우지 못하게 공격자가 설정한 불변 파일 (`lsattr`에 `i` 표시, 제거는 `chattr -i`).

## 삭제됐지만 열려 있는 파일 (라이브 시스템) { #deleted-but-open-files-live-systems }

프로세스는 디스크에서 링크가 끊긴 뒤에도 파일을 열어 둘 수 있습니다 — 악성코드가 자기 자신을 지우고도 계속 실행되는 방법:

```bash
# Files that are deleted but still held open by a running process
ls -l /proc/*/exe 2>/dev/null | grep -i deleted          # deleted binaries still executing
lsof +L1 2>/dev/null                                       # files with link count 0 (deleted, still open)
# Recover the content while the process lives:
cp /proc/<pid>/exe /evidence/recovered_binary
cat /proc/<pid>/maps                                       # memory-mapped files
```

`(deleted)`를 가리키는 `/proc/<pid>/exe`는 자기 삭제 악성코드의 강한 지표입니다 — 분석용으로 `/proc`에서 실행 중인 바이너리를 여전히 복사해 낼 수 있습니다.

## ext4 저널과 inode 재사용 { #the-ext4-journal-inode-reuse }

ext4 저널(`$journal`, inode 8)은 최근 메타데이터 트랜잭션을 기록하며, `ext4magic`/`extundelete`/`debugfs`로 최근 삭제된 파일을 복구하거나 이전 inode 상태를 보는 데 도움이 됩니다 — NTFS `$LogFile`을 읽는 것과 가장 비슷한 ext4의 방법입니다. xfs에서는 `xfs_db`로 메타데이터를 봅니다. 이것들은 이미지 수준의 기법입니다:

```bash
# On a mounted-read-only image or raw device
debugfs -R "ls -d /tmp" /dev/sda1                          # deleted entries in a directory
ext4magic /dev/sda1 -a <start_epoch> -b <end_epoch> -j /dev/sda1   # recover in a time window
extundelete /dev/sda1 --restore-directory /home/user
```

## Linux 타임라인 만들기 { #building-a-linux-timeline }

Windows 슈퍼 타임라인에 해당하는 Sleuth Kit / Plaso 방법:

```bash
# Sleuth Kit: body file (MAC times per file) → mactime timeline
fls -r -m / /dev/sda1 > body.txt          # on an image; -m prefixes the mount point
mactime -b body.txt -d 2026-08-20 > timeline.csv

# Plaso covers Linux too (syslog, bash history, ext4, systemd, audit…)
log2timeline.py --parsers linux case.plaso /evidence/
psort.py -o l2tcsv -w timeline.csv case.plaso "date > '2026-08-20' AND date < '2026-08-21'"
```

필터링은 [Plaso와 타임라인](../tools/plaso-timelines.md)을 보세요. "알려진 사건에 기준점을 두고 ±1시간 창" 방법이 그대로 적용됩니다.

## 참고 자료 { #references }

- [ext4 disk layout & timestamps (kernel docs)](https://www.kernel.org/doc/html/latest/filesystems/ext4/)
- [The Sleuth Kit — fls / mactime](https://www.sleuthkit.org/sleuthkit/man/)
- [debugfs / extundelete / ext4magic](https://linux.die.net/man/8/debugfs)
- 관련 페이지: [인증과 히스토리](auth-and-history.md) · [지속성](persistence.md) · [Plaso와 타임라인](../tools/plaso-timelines.md)
