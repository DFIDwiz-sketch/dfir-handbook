---
title: "Linux 로그 파일과 systemd 저널 — 전통적인 로그 경로, 수집할 파일, journalctl, 명령줄 로깅, 섹션 정리"
tags:
  - training
  - blue-team
  - linux
  - logging
  - journald
  - auditd
---

# Linux 로그 파일과 systemd 저널 — 전통적인 로그 경로, 수집할 파일, journalctl, 명령줄 로깅, 섹션 정리 { #log-files-journal }

!!! abstract "이 페이지에서 다루는 것"
    Linux 로그 메시지 하나가 지나가는 길. 프로그램에서 `/dev/log` 소켓과 syslog 데몬을 거쳐 `/var/log` 아래 평범한 텍스트 파일과 네트워크로 가는 길, 그리고 요즘은 그 길 한가운데에 journald가 서 있다는 점. 가장 수집할 가치가 있는 로그 파일들(`auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron`, `audit.log`, `ufw.log`, 웹 서버·데이터베이스 로그, 그리고 이진 파일인 `wtmp`/`btmp`/`lastlog` 로그인 기록), Debian 계열과 Red Hat 계열에서 무엇이 다른지, 로그 순환(rotation)이 수집과 변조에 어떤 영향을 주는지. systemd 저널: 어디에 있는지, 왜 구조화된 이진 데이터베이스인지, `journalctl`로 어떻게 찾는지, 그리고 텍스트 파일이라면 그냥 받아들였을 위조 메시지를 **신뢰 칸(trusted fields)** 이 어떻게 드러내는지. auditd, Sysmon for Linux, Snoopy, `logger`로 명령줄 기록을 더하는 법. 마지막으로 Linux 로그 섹션 전체 정리와 확인 문제·해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 전통적인 길은 **프로그램 → `/dev/log` 소켓 → syslog 데몬 → `/var/log`의 텍스트 파일**(필요하면 → 원격 수집기)입니다. 데몬이 메시지마다 표준 헤더를 앞에 붙이고, **facility와 severity**를 보고 어느 파일에 쓸지 정합니다.
2. systemd를 쓰는 시스템에서는 **journald가 `/dev/log`를 차지합니다.** 메시지는 먼저 저널에 들어가고, rsyslog가 (깔려 있다면) journald에서 받아 익숙한 텍스트 파일을 씁니다. rsyslog가 없으면 **`/var/log/auth.log`도 없습니다** — 저널뿐입니다.
3. 파일 이름은 계열마다 다릅니다. 인증 기록은 **`/var/log/auth.log`**(Debian/Ubuntu) 또는 **`/var/log/secure`**(Red Hat 계열), 일반 로그는 **`/var/log/syslog`** 또는 **`/var/log/messages`**. 짐작하지 말고 배포판마다 확인합니다.
4. 보안에 가장 값진 파일은 인증 로그, 일반 시스템 로그, `audit.log`, cron 로그, 방화벽 로그, 그리고 그 서버의 웹·DB 로그입니다. **`kern.log`** 는 대부분 잡음이지만 USB와 방화벽 메시지가 들어 있습니다.
5. 로그인 기록은 **이진 파일**에도 남습니다. `wtmp`(로그인), `btmp`(로그인 실패), `lastlog`. `cat`이 아니라 `last`, `lastb`, `lastlog`로 읽습니다. 최근 배포판은 2038년 문제가 없는 데이터베이스(`wtmpdb`, `lastlog2`)로 바꾸는 중입니다.
6. **systemd 저널**(`/var/log/journal/<machine-id>/`, 영구 저장이 아니면 `/run/log/journal`)은 이름 있는 칸을 가진 **구조화된 이진 로그**라 Windows EVTX에 훨씬 가깝습니다. **`journalctl`** 로 읽습니다. 서비스는 `-u`, 그 밖에 `--since`, `-p`, `-o json`.
7. 밑줄로 시작하는 저널 칸(`_PID`, `_UID`, `_COMM`, `_EXE`, `_SYSTEMD_UNIT`)은 프로그램이 적는 게 아니라 **journald가 커널에게 물어서 붙입니다.** 그래서 누가 진짜 메시지를 썼는지 보여 줍니다 — `logger` 위조에 대한 답입니다.
8. 기본 로그는 모든 명령을 기록하지 않습니다. **auditd**(내장), **Sysmon for Linux**(무료 외부 도구), **Snoopy**를 더하고, 직접 만든 스크립트에는 **`logger`** 를 씁니다. 그리고 더한 로그가 실제로 파싱되고 전달되는지 확인합니다. 파싱 못 하는 로그로는 경보를 만들 수 없습니다.

## 전통적인 Linux 로그 경로 { #log-path }

### 프로그램에서 파일까지 { #program-to-file }

회사 우편실을 떠올려 보세요. 모든 부서(프로그램)가 벽에 난 투입구 하나(`/dev/log`)에 봉투를 넣습니다. 벽 뒤에서 직원 한 명(syslog 데몬)이 봉투마다 날짜와 보낸 사람 이름 도장을 찍고, 부서·긴급도 라벨(facility와 severity)을 읽어서 알맞은 칸(`/var/log`의 텍스트 파일)에 꽂습니다. 본사에 사본을 한 부 보내기도 하고요(원격 수집기).

기술적인 실제 모습으로 돌아오면 이렇습니다.

1. 프로그램이 C 라이브러리 함수 `syslog()`(또는 같은 일을 하는 로깅 라이브러리)를 부릅니다. 메시지, facility, severity, 프로그램 태그가 Unix 도메인 소켓 **`/dev/log`** 로 들어갑니다.
2. 커널은 자기 메시지를 링 버퍼(`dmesg`가 보여 주는 것)에 쓰고, 데몬이 그걸 따로 읽어 갑니다.
3. **syslog 데몬**(rsyslog, syslog-ng)이 메시지를 받아 헤더(시각, 호스트, 태그, PID)를 붙이고, facility와 severity를 규칙과 맞춰 봅니다.
4. 줄을 하나 이상의 **평범한 텍스트 파일**(보통 **`/var/log`** 아래) 끝에 덧붙이고, **원격 수집기**에 사본을 보낼 수도 있습니다.

가상의 Ubuntu 호스트 `web-01`의 파일에 실제로 찍히는 모습입니다.

```
/var/log/auth.log:
Nov 20 14:25:01 web-01 CRON[4295]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Nov 20 14:25:01 web-01 CRON[4295]: pam_unix(cron:session): session closed for user root

/var/log/syslog:
Nov 20 14:13:51 web-01 NetworkManager[574]: <info>  [1795144431.5264] dhcp4 (eth0): activation: beginning transaction (timeout in 45 seconds)
Nov 20 14:13:51 web-01 dhclient[4231]: DHCPDISCOVER on eth0 to 255.255.255.255 port 67 interval 3 (xid=0x5a1c2e7d)
```

한 줄씩:

- `CRON[4295]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)` — cron 데몬(프로세스 4295)이 예약 작업을 `root`로 실행하려는 참입니다. cron은 PAM(플러그형 인증 모듈, Pluggable Authentication Modules)을 거치고, PAM 모듈 `pam_unix`가 세션 시작을 알립니다. 작업 예약기가 **인증** 로그에 나오는 이유가 이겁니다.
- `session closed for user root` — 작업이 끝났습니다. 몇 분마다 이런 한 쌍이 나오는 건 평범한 배경 잡음입니다. 중요한 건 **새로운** 패턴입니다. 평소와 다른 사용자나 다른 간격의 cron 세션은 지속성(persistence) 작업일 수 있습니다(MITRE ATT&CK **T1053.003**, Scheduled Task/Job: Cron).
- `NetworkManager[574]: <info>  [1795144431.5264] dhcp4 (eth0): ...` — NetworkManager가 메시지 안에 자기 수준(`<info>`)과 Unix 시각을 직접 적었습니다. syslog PRI가 아니라 그냥 프로그램이 넣기로 한 글자입니다. 자유 형식 메시지에는 개발자가 정한 무엇이든 들어갑니다.
- `dhclient[4231]: DHCPDISCOVER on eth0 to 255.255.255.255 port 67 ...` — DHCP 클라이언트가 주소를 달라고 방송하고 있습니다. 뒤이은 `DHCPACK` 줄과 합치면 이 호스트가 언제 어떤 IP였는지 알 수 있습니다.

파일 하나하나가 그냥 텍스트라는 점에 주목하세요. SIEM 에이전트든, `grep`이든, `less`든 어떤 프로그램이나 읽을 수 있습니다. 이 설계의 장점이죠. 그리고 한 파일에 여러 프로그램이 섞여 있고, facility·severity 규칙으로만 나뉩니다. 이게 약점입니다.

### 요즘은 journald가 어디에 끼는가 { #journald-in-path }

지금 쓰이는 거의 모든 배포판에서 systemd의 로그 서비스 **journald**가 `/dev/log`를 차지합니다. 길은 이렇게 바뀌었습니다.

```
program (syslog())       ──> /dev/log ──┐
program (native API)     ───────────────┤
kernel (/dev/kmsg)       ───────────────┼──> journald ──> journal files
service stdout/stderr    ───────────────┘        │       (/var/log/journal or /run/log/journal)
                                                 │
                                                 └──> rsyslog (imjournal or imuxsock)
                                                        ├──> /var/log/auth.log, /var/log/syslog, ...
                                                        └──> remote collector
```

- journald는 네 곳에서 모읍니다. syslog 소켓, 자체 API, 커널, 그리고 systemd가 띄운 **모든 서비스의 표준 출력과 표준 오류**. 마지막이 중요합니다. 그냥 화면(stdout)에 찍기만 하는 서비스도, syslog 의미로는 "로그를 남긴" 적이 없는데 저널에는 들어갑니다.
- rsyslog는 자기 몫을 journald에서 받습니다. Red Hat 계열은 `imjournal` 입력 모듈로, Debian/Ubuntu는 journald가 넘겨주는 소켓(`imuxsock`)으로요. 그다음 예전처럼 텍스트 파일을 쓰고 전달합니다.
- rsyslog가 설치돼 있지 않으면(Debian 12 이후 기본값) 텍스트 파일은 **아예 만들어지지 않습니다.** 저널이 유일한 로컬 저장소입니다.

**[보충] 수집에서 이게 중요한 이유.** SIEM 에이전트가 `/var/log/auth.log`를 따라 읽는데(tail) 그 파일이 없으면, 에이전트는 아무것도 보내지 않고 불평도 하지 않습니다. 조직의 Linux 빌드마다 진짜 원본이 저널인지, 텍스트 파일인지, 둘 다인지 확인하고, 에이전트가 맞는 쪽을 읽게 설정합니다.

## 수집할 흔한 Linux 로그 파일 { #log-files }

### 파일 지도 { #file-map }

배포판마다 로그를 조금씩 다르게 남기니, 출발점이 되는 지도로 보고 실제 빌드에서 확인하세요.

| 무엇 | Debian / Ubuntu | Red Hat / Fedora / Rocky / Alma | 보안 가치 |
| --- | --- | --- | --- |
| 인증(sshd, sudo, su, PAM, cron 세션) | `/var/log/auth.log` | `/var/log/secure` | 아주 높음 |
| 일반 시스템 메시지 | `/var/log/syslog` | `/var/log/messages` | 높음 — 대부분의 일을 처음 찾아보는 곳, Windows System 로그와 비슷 |
| 커널 | `/var/log/kern.log` | (`messages` 안에) | 낮음/중간 — 시끄럽지만 USB 장치, 방화벽 차단, 모듈 로드 |
| Cron | (`syslog` 안에) | `/var/log/cron` | 중간 — 예약 작업을 이용한 지속성 |
| 감사 프레임워크 | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` | 규칙을 걸어 두면 아주 높음 |
| UFW 방화벽 | `/var/log/ufw.log` | (firewalld는 `messages`/저널에) | 중간/높음 |
| Apache 웹 서버 | `/var/log/apache2/access.log`, `error.log` | `/var/log/httpd/access_log`, `error_log` | 웹 서버라면 높음 |
| Nginx | `/var/log/nginx/access.log`, `error.log` | 같음 | 웹 서버라면 높음 |
| MySQL / MariaDB | `/var/log/mysql/error.log` | `/var/log/mysqld.log` 또는 `/var/log/mariadb/mariadb.log` | 중간 — 로그인과 오류. 쿼리 기록은 보통 꺼져 있음 |
| 패키지 설치 | `/var/log/dpkg.log`, `/var/log/apt/history.log` | `/var/log/dnf.log`(그리고 `dnf history`) | 중간 — 침입자가 설치한 도구 |
| 로그인(이진) | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | 같음 | 높음 |

**[정정]** `kern.log`와 `ufw.log`를 `/var/log/audit/` 아래에 적어 둔 목록을 가끔 봅니다. 거기 있지 않습니다. `/var/log/audit/`는 auditd 전용이고, `kern.log`와 `ufw.log`는 `/var/log/` 바로 아래에 있습니다. MySQL 로그 위치도 패키지와 배포판에 따라 다르니, 목록을 믿지 말고 데이터베이스 설정(`log_error`)에서 실제 경로를 찾으세요.

### 인증 로그 읽기 { #auth-log }

SSH 침입이 처음 눈에 띄는 곳이 인증 로그입니다. `web-01`의 `/var/log/auth.log`에서 그럴듯하게 잘라 온 부분입니다.

```
Nov 20 14:31:07 web-01 sshd[5011]: Invalid user admin from 203.0.113.45 port 40122
Nov 20 14:31:09 web-01 sshd[5011]: Failed password for invalid user admin from 203.0.113.45 port 40122 ssh2
Nov 20 14:33:40 web-01 sshd[5032]: Accepted publickey for deploy from 198.51.100.61 port 50544 ssh2: ED25519 SHA256:kq3V0bXa1nYv7k0Lr2Wc9mT4Jt8sQ1eZpHfUo6dNgAs
Nov 20 14:33:40 web-01 sshd[5032]: pam_unix(sshd:session): session opened for user deploy(uid=1003) by deploy(uid=0)
Nov 20 14:35:02 web-01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt install -y socat
Nov 20 14:35:02 web-01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1003)
Nov 20 14:36:18 web-01 su[5101]: (to backup) deploy on pts/1
Nov 20 14:36:18 web-01 su[5101]: pam_unix(su-l:session): session opened for user backup(uid=1010) by deploy(uid=1003)
```

한 줄씩:

- `Invalid user admin from 203.0.113.45 port 40122` — 누군가 이 서버에 없는 계정 `admin`으로 로그인하려 했습니다. 보통 추측 공격의 첫 줄입니다.
- `Failed password for invalid user admin ...` — 비밀번호 시도 자체가 실패했습니다. 한 출발지에서 사용자 이름을 바꿔 가며 이런 줄이 많이 나오면 비밀번호 추측(**T1110.001**), 비밀번호 하나를 여러 계정에 돌리면 스프레이(**T1110.003**)입니다.
- `Accepted publickey for deploy from 198.51.100.61 ... ED25519 SHA256:kq3V...` — SSH 키로 로그인에 **성공**했습니다. 키의 **지문(fingerprint)** 이 아주 값집니다. 어느 키를 썼는지 알려 주니, `~deploy/.ssh/authorized_keys`에서 그 키를 찾아 우리가 발급한 키인지 확인할 수 있습니다. 거기에 모르는 키가 추가돼 있다면 지속성입니다(**T1098.004**, SSH Authorized Keys).
- `pam_unix(sshd:session): session opened for user deploy(uid=1003)` — 세션이 실제로 시작됐습니다.
- `sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt install -y socat` — `deploy`가 sudo로 **root 권한으로** 명령을 실행했습니다. 네트워크 중계 도구 `socat` 설치입니다. sudo는 세미콜론으로 나눈 칸(`TTY`, `PWD`, `USER`, `COMMAND`)을 써서 파싱하기 쉽고, Linux 호스트에서 가장 좋은 소스 중 하나입니다. 원격 로그인 직후 터널링 도구를 설치했다면 꼼꼼히 봐야 합니다(도구 반입과 프로토콜 터널링, **T1105**, **T1572**).
- `su[5101]: (to backup) deploy on pts/1` — `deploy`가 `su`로 `backup` 계정으로 바꿨습니다. 다음 줄이 세션 시작을 확인해 줍니다. 침입자는 이렇게 계정을 옮겨 다니며 권한 수준을 오갑니다.

**[변경됨] `sshd`가 이제 `sshd-session`일 수 있습니다.** OpenSSH 9.8(2024)부터 접속 하나하나를 처리하는 일이 `sshd-session`이라는 별도 프로그램으로 옮겨졌습니다. 이 버전을 쓰는 배포판에서는 위 줄들 상당수가 `sshd[5032]:`가 아니라 `sshd-session[5032]:` 태그를 달고 나옵니다. 잘 알려진 로그 도구 여러 개가 패턴을 고쳐야 했고, 글자 그대로 `sshd[`에 맞추는 SIEM 규칙은 이 줄들을 조용히 놓칩니다. 가장 최신 빌드가 무엇을 쓰는지 확인하고 둘 다 잡게 하세요.

### 다른 파일들, 하나씩 예시 { #other-files }

`/var/log/ufw.log`의 UFW 방화벽 차단(커널 메시지에서 옴):

```
Nov 20 14:40:12 web-01 kernel: [183311.442190] [UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56:52:54:00:ab:cd:ef:08:00 SRC=198.51.100.23 DST=10.20.30.41 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=40122 DF PROTO=TCP SPT=44871 DPT=3306 WINDOW=64240 RES=0x00 SYN URGP=0
```

- `kernel:`과 `[183311.442190]` — 방화벽은 커널 안에 있어서 "프로그램"이 커널이고, 대괄호는 부팅 후 경과 초입니다.
- `[UFW BLOCK]` — UFW가 붙이는 앞머리. 이걸 보고 줄을 `ufw.log`로 보냅니다.
- `IN=eth0 OUT=` — `eth0`으로 들어왔고, 다른 곳으로 넘겨지지 않았습니다(이 호스트가 목적지).
- `SRC=198.51.100.23 DST=10.20.30.41` — 외부 주소에서 이 서버로.
- `PROTO=TCP SPT=44871 DPT=3306` — 출발 포트 44871에서 **3306, 즉 MySQL** 로 가는 TCP. 인터넷에서 누군가 DB 포트를 찔러 보고 있습니다.
- `SYN` — 연결 시도이지, 이미 이어진 통신의 중간이 아닙니다.

방화벽 로그 칸은 뒤 섹션에서 자세히 다룹니다. 지금은 이 파일이 있고 수집할 가치가 있다는 것만 알면 됩니다.

`/var/log/apache2/access.log`의 Apache 접속 로그 한 줄(combined 형식):

```
198.51.100.77 - - [20/Nov/2026:14:42:31 +1100] "GET /wp-login.php HTTP/1.1" 404 492 "-" "python-requests/2.32.3"
```

- `198.51.100.77` — 클라이언트 IP.
- `- -` — `identd` 이름과 인증된 사용자. 대시는 "없음".
- `[20/Nov/2026:14:42:31 +1100]` — syslog 헤더와 달리 **이** 형식에는 연도와 시간대가 들어 있습니다.
- `"GET /wp-login.php HTTP/1.1"` — 요청 줄. 이 서버에는 WordPress가 없으니, WordPress를 찾는 스캐너입니다.
- `404 492` — 상태 코드(없음)와 응답 크기(바이트).
- `"-" "python-requests/2.32.3"` — 리퍼러(없음)와 사용자 에이전트. 브라우저가 아니라 스크립트입니다.

### 이진 로그인 기록 { #wtmp }

**[보충]** 로그인 기록 세 가지는 **이진 파일**이라, `cat`으로 보면 깨진 글자가 나오고 `grep`은 놓칩니다.

- `/var/log/wtmp` — 모든 로그인·로그아웃과 재부팅. `last`로 읽습니다.
- `/var/log/btmp` — 로그인 실패. `sudo lastb`로 읽습니다.
- `/var/log/lastlog` — 계정마다 마지막 로그인. `lastlog`로 읽습니다.

```
$ last -F -n 3
deploy   pts/1        198.51.100.61    Fri Nov 20 14:33:40 2026   still logged in
j.kim    pts/0        10.20.30.15      Fri Nov 20 09:02:11 2026 - Fri Nov 20 11:47:30 2026  (02:45)
reboot   system boot  6.8.0-49-generic Thu Nov 19 22:10:05 2026   still running
```

- `last` — `wtmp`를 읽습니다. `-F`는 연도까지 전체 날짜를 찍고, `-n 3`은 최근 세 개만 보여 줍니다.
- 각 줄: 사용자, 터미널(`pts/1` = 원격 가상 터미널), 출발지 호스트, 로그인 시각, 로그아웃 시각 또는 `still logged in`(아직 접속 중), 세션 길이.
- `reboot system boot` 줄은 부팅 시각입니다. 저널이나 다른 로그가 새로 시작된 경우 쓸모가 있습니다.

**[변경됨]** 옛 형식은 시각을 32비트로 저장해서 2038년에 고장 납니다. Debian 13을 비롯한 일부 최신 배포판은 이걸 SQLite 기반 도구로 바꾸기 시작했습니다. 로그인 기록은 `wtmpdb`, 마지막 로그인은 `lastlog2`. 그래서 이런 시스템에서는 `last`가 `/var/log/wtmp` 대신 데이터베이스를 읽고, `lastlog`가 없을 수도 있습니다. 수집과 포렌식 도구가 호스트마다 어느 쪽인지 알아야 합니다.

### 로그 순환 { #rotation }

텍스트 로그는 그냥 두면 끝없이 커지니, 예약 작업 **logrotate**가 정해진 주기(많은 시스템에서 기본 매주)로 이름을 바꾸고 오래된 사본을 압축합니다.

```
$ ls -l /var/log/auth.log*
-rw-r----- 1 syslog adm  48211 Nov 20 14:36 /var/log/auth.log
-rw-r----- 1 syslog adm 612884 Nov 15 00:00 /var/log/auth.log.1
-rw-r----- 1 syslog adm  71240 Nov  8 00:00 /var/log/auth.log.2.gz
-rw-r----- 1 syslog adm  69915 Nov  1 00:00 /var/log/auth.log.3.gz
```

- `auth.log` — 지금 쓰이고 있는 파일.
- `auth.log.1` — 지난주 것, 아직 압축 안 됨.
- `auth.log.2.gz`, `.3.gz` — 더 오래된 주, gzip 압축. `zgrep "Accepted" /var/log/auth.log.*.gz`로 검색하면 압축을 풀면서 찾아 줍니다.
- `syslog adm`과 `-rw-r-----` — 주인은 `syslog` 사용자와 `adm` 그룹이고, 이들과 root만 읽을 수 있습니다. `adm` 그룹 구성원은 인증 로그를 읽을 수 있으니 누가 그 그룹에 있는지 살펴보세요.

두 가지 결과가 따라옵니다. 에이전트는 이름이 바뀐 파일을 계속 따라가야 하고(제대로 된 에이전트는 다 합니다), **로컬 기록은 짧습니다** — 여기서는 4주. 그리고 root를 가진 침입자는 이 파일들을 지우거나 고칠 수 있습니다(**T1070.002**, Clear Linux or Mac System Logs). 안전한 건 이미 호스트를 떠난 것뿐입니다.

## systemd 저널 { #journal }

### 저널은 무엇이고 왜 생겼나 { #journal-what }

저널은 syslog의 약점 — 구조가 없고, 사용자 정의 칸이 없고, 누가 보냈는지 믿을 만한 정보가 없음 — 을 고치려고 만들어졌습니다. **systemd-journald**는 백그라운드에서 돌며 로그 데이터를 받아 **색인이 붙은 이진 데이터베이스**에 쓰는 서비스입니다. Windows의 `.evtx` 파일과 많이 닮았습니다.

syslog 파일이 엽서 더미라면, 저널은 편지마다 색인 카드가 붙은 서류함입니다. 보낸 사람, 시각, 부서 등 많은 칸이 있고 전부 검색할 수 있죠. 게다가 칸 일부는 우체국이 직접 적어서 보낸 사람이 속일 수 없습니다.

기술적인 사실은 이렇습니다.

- **위치.** 영구 저장소는 `/var/log/journal/<machine-id>/`이고, `<machine-id>`는 `/etc/machine-id`에 있는 값입니다. 이 폴더가 없고 저장 설정이 `auto`이면, journald는 로그를 **`/run/log/journal`** 에만 둡니다. 메모리에 있어서 **재부팅하면 사라집니다.** 어느 쪽인지 꼭 확인하세요. 조사 중에 "재부팅 전 로그가 없어요"는 흔하지만 피할 수 있는 일입니다.
- **형식.** 항목 하나하나가 `FIELD=value` 쌍의 묶음입니다. 값은 대부분 글자지만 이진 값도 되고, 프로그램이 칸을 새로 만들어 넣을 수도 있습니다.
- **호환성.** 항목에는 여전히 syslog식 데이터(`MESSAGE`, `PRIORITY`, `SYSLOG_FACILITY`, `SYSLOG_IDENTIFIER`)가 있고, 전부 평범한 syslog로 전달할 수 있습니다.
- **크기와 보관.** `/etc/systemd/journald.conf`에서 정합니다(`SystemMaxUse=`, `MaxRetentionSec=`, `Storage=`). 한도에 닿으면 가장 오래된 파일부터 지웁니다.

### journalctl로 찾기 { #journalctl }

`journalctl`만 치면 저널 전체를 오래된 것부터 페이지 보기 프로그램으로 보여 줍니다. 실제로는 걸러서 봅니다. 네트워크 IDS 서비스를 예로 들어 보죠.

```
$ journalctl -u suricata --since "2026-11-20 00:00" --no-pager
Nov 20 02:15:09 sensor-01 systemd[1]: Starting suricata.service - Suricata IDS/IDP daemon...
Nov 20 02:15:10 sensor-01 suricata[34399]: Notice: suricata: This is Suricata version 7.0.7 RELEASE running in SYSTEM mode
Nov 20 02:15:11 sensor-01 systemd[1]: Started suricata.service - Suricata IDS/IDP daemon.
Nov 20 13:52:44 sensor-01 systemd[1]: Stopping suricata.service - Suricata IDS/IDP daemon...
Nov 20 13:52:45 sensor-01 systemd[1]: suricata.service: Deactivated successfully.
```

- `journalctl` — 저널 검색 도구.
- `-u suricata` — systemd **유닛(unit)**, 즉 등록된 서비스 `suricata.service`의 항목만. 그 유닛에 대한 systemd 자신의 시작·중지 메시지와 서비스가 쓴 것 전부가 들어갑니다.
- `--since "2026-11-20 00:00"` — 자정 이후만(`--until`로 끝을 정함).
- `--no-pager` — `less`를 열지 말고 화면에 바로 찍기.
- 출력은 syslog처럼 생겼습니다. 시각, 호스트, 태그[PID], 메시지. 저널은 언제든 이 익숙한 모습으로 보여 줄 수 있습니다.
- 흥미로운 건 마지막 두 줄입니다. IDS 센서가 13:52에 **멈췄습니다.** 계획된 일이 아니라면, 멈춘 센서는 방어 회피입니다(**T1562.001**, Disable or Modify Tools).

자주 쓰게 될 다른 옵션들:

| 명령 | 하는 일 |
| --- | --- |
| `journalctl -p warning` | severity `warning`과 그보다 심각한 것만(syslog와 같은 0~7 척도) |
| `journalctl -k` | 커널 메시지만(`dmesg`와 비슷하지만 지난 것도 남아 있음) |
| `journalctl -b` / `-b -1` | 이번 부팅 / 이전 부팅 |
| `journalctl --list-boots` | 저널이 기억하는 모든 부팅과 시간 범위 |
| `journalctl _COMM=sudo` | 아무 칸으로나 거르기, 여기서는 프로세스 이름 |
| `journalctl -f` | `tail -f`처럼 실시간으로 따라 보기 |
| `journalctl -o json-pretty -n 1` | 가장 최근 항목을 **모든** 칸과 함께 보기 |
| `journalctl --disk-usage` | 저널이 쓰는 디스크 공간 |
| `journalctl --verify` | 저널 파일이 깨졌는지(그리고 아래의 봉인) 점검 |

### 신뢰 칸으로 위조 메시지 잡기 { #trusted-fields }

syslog 페이지에서 `logger`로 sshd 줄을 위조해 봤습니다. 텍스트 파일에서는 진짜처럼 보이죠. 저널에서 그 항목의 모든 칸을 보면 이렇습니다.

```
$ journalctl -o json-pretty -n 1 SYSLOG_IDENTIFIER=sshd
{
        "__REALTIME_TIMESTAMP" : "1795143831204871",
        "_HOSTNAME" : "web-01",
        "PRIORITY" : "6",
        "SYSLOG_FACILITY" : "10",
        "SYSLOG_IDENTIFIER" : "sshd",
        "MESSAGE" : "Accepted password for admin from 10.20.30.99 port 40022 ssh2",
        "_TRANSPORT" : "syslog",
        "_PID" : "5120",
        "_UID" : "1004",
        "_GID" : "1004",
        "_COMM" : "logger",
        "_EXE" : "/usr/bin/logger",
        "_CMDLINE" : "logger -t sshd -p authpriv.info Accepted password for admin from 10.20.30.99 port 40022 ssh2",
        "_SYSTEMD_UNIT" : "session-12.scope",
        "_BOOT_ID" : "3f1c0d2e9a8b4c7d8e6f5a4b3c2d1e0f"
}
```

칸별로:

- `__REALTIME_TIMESTAMP` — 1970년부터 센 UTC 마이크로초(여기서는 2026-11-20 03:03:51.204871 UTC). syslog 헤더와 달리 연도, 시간대, 초 이하 단위가 다 있습니다.
- `PRIORITY` `6`과 `SYSLOG_FACILITY` `10` — severity `info`, facility `authpriv`. **보낸 쪽이 적은 값**입니다.
- `SYSLOG_IDENTIFIER` `sshd`와 `MESSAGE` — 이것도 보낸 쪽이 적으니 위조할 수 있습니다.
- `_TRANSPORT` `syslog` — `/dev/log` 소켓으로 들어왔습니다(다른 값: `journal`, `stdout`, `kernel`).
- `_PID`, `_UID`, `_GID` — 보낸 프로세스에 대해 커널이 가진 정보로 **journald가 붙인 값**입니다. 밑줄은 보낸 쪽이 정할 수 없다는 뜻입니다.
- `_COMM` `logger`, `_EXE` `/usr/bin/logger`, `_CMDLINE` — 진짜 프로그램과 전체 명령줄.
- `_SYSTEMD_UNIT` `session-12.scope` — SSH 서비스가 아니라 어떤 사용자의 로그인 세션에서 쓰였습니다.

진짜 sshd 항목이라면 `_COMM=sshd`(또는 `sshd-session`), `_UID=0`, `_SYSTEMD_UNIT=ssh.service`(Debian/Ubuntu) 또는 `sshd.service`(Red Hat)가 보여야 합니다. 여기서는 권한 없는 사용자(UID 1004)가 대화형 세션에서 `logger`를 실행했습니다. 심어 놓은 줄입니다.

여기서 탐지 아이디어가 나옵니다. `SYSLOG_IDENTIFIER`가 민감한 데몬(`sshd`, `sudo`, `su`)인데 `_COMM`이나 `_EXE`가 그와 맞지 않으면 경보. 정직하게 한계도 말하자면, 아주 빨리 끝나는 프로세스는 journald가 제때 정보를 다 읽지 못해서 밑줄 칸 일부가 빠질 때가 있습니다. 신뢰 칸이 없다는 건 더 살펴볼 이유이지, 어느 쪽의 증거도 아닙니다.

또 하나, 신뢰 칸은 **저널 안에만** 있습니다. rsyslog가 메시지를 `auth.log`에 쓰고 평범한 syslog로 전달하면 이 칸들은 떨어져 나갑니다. 에이전트가 저널을 직접 읽게 하거나, 이 칸들을 지키는 구조화 형식으로 전달해야 하는 강한 이유입니다.

### 저널을 호스트 밖으로 보내고 지키기 { #journal-forwarding }

저널 데이터를 SIEM에 보내는 방법:

- **저널을 직접 읽는 에이전트**(대부분의 SIEM·EDR 에이전트와 OpenTelemetry 수집기에 journald 입력이 있음). 모든 칸이 유지됩니다.
- **rsyslog가 저널을 읽어**(`imjournal`) syslog로 전달 — 익숙하지만, 기본으로는 옛 syslog 칸만 살아남습니다.
- **journald 자체의 `ForwardToSyslog=yes`** 로 로컬 syslog 데몬에 넘기기.
- **`systemd-journal-upload`와 `systemd-journal-remote`** — 중앙 저널 서버로 보내는 저널 자체의 HTTP(S) 전송. SOC에서는 덜 쓰이지만 있습니다.

root를 가진 침입자는 저널을 줄이거나 지울 수 있습니다(예: 강제로 순환시킨 뒤 오래된 파일을 정리(vacuum)). 텍스트 로그를 지우는 것과 같은 **T1070.002**입니다. journald에는 **Forward Secure Sealing**(`journalctl --setup-keys`)이 있어서 주기적으로 저널에 서명을 하고, 봉인 이후 항목이 바뀌거나 지워졌는지를 `journalctl --verify`로 보여 줄 수 있습니다. 봉인은 변조가 **있었다는 걸** 알려 줄 뿐 막지는 못합니다. 진짜 보호는 여전히 빠르게 호스트 밖으로 보내는 것입니다.

## 명령줄 로깅 더하기 { #extra-logging }

Linux는 기본으로 "사용자 X가 이런 인자로 명령 Y를 실행했다"를 기록하지 않습니다. 셸 히스토리(`~/.bash_history`)는 로그가 아닙니다. 사용자가 마음대로 끄거나 지울 수 있으니까요(**T1070.003**, Clear Command History). 이 빈자리를 채우는 방법은 세 가지입니다.

### 1. 내장: Linux 감사 하위 시스템(auditd) { #auditd }

커널에는 감사 프레임워크가 있고, **auditd**는 그 기록을 `/var/log/audit/audit.log`에 쓰는 서비스입니다. 거의 모든 배포판에서 쓸 수 있습니다(Red Hat은 기본 설치, Debian/Ubuntu는 패키지 하나만 설치). 장점은 이미 내장돼 있고 아주 자세하다는 것, 단점은 기록이 읽기 어렵고 규칙이 다른 도구보다 덜 직관적이라는 것입니다.

모든 프로그램 실행을 기록하는 규칙으로, `/etc/audit/rules.d/` 아래 파일에 둡니다.

```
-a always,exit -F arch=b64 -S execve -k exec_log
```

- `-a always,exit` — 시스템 콜이 끝날 때 항상 기록을 만듭니다.
- `-F arch=b64` — 64비트 호출에 대해(32비트도 잡으려면 `arch=b32` 줄을 하나 더).
- `-S execve` — 새 프로그램을 시작하는 시스템 콜.
- `-k exec_log` — 맞는 기록에 `exec_log`라는 키를 붙여 나중에 찾기 쉽게.

실행 한 번이 만드는 기록(간단히 줄임):

```
type=SYSCALL msg=audit(1795143831.204:4412): arch=c000003e syscall=59 success=yes exit=0 ppid=5032 pid=5201 auid=1003 uid=1003 euid=1003 tty=pts1 ses=7 comm="curl" exe="/usr/bin/curl" key="exec_log"
type=EXECVE msg=audit(1795143831.204:4412): argc=4 a0="curl" a1="-s" a2="-o" a3="/tmp/.cache-upd"
```

- `msg=audit(1795143831.204:4412)` — epoch 시각과 이벤트 일련번호. 번호가 같은 기록은 한 이벤트입니다.
- `syscall=59` — 64비트 x86에서 `execve`. `success=yes` — 성공.
- `ppid=5032 pid=5201` — 부모와 자식 프로세스 ID. 5032는 위 인증 로그의 SSH 세션이었습니다.
- `auid=1003` — **감사 사용자 ID(audit user ID)**, 처음 로그인한 계정. `sudo`나 `su`를 거쳐도 그대로 남아서, root 명령 뒤에 실제로 누가 있는지 알려 줍니다.
- `comm="curl" exe="/usr/bin/curl"` — 프로그램.
- `EXECVE ... a0= a1= a2= a3=` — 인자 전체: `curl -s -o /tmp/.cache-upd`(URL은 `a4`로 이어지는데 여기선 줄였습니다). `/tmp`의 숨김 파일로 내려받기는 전형적인 도구 반입(**T1105**)입니다.

`ausearch -k exec_log -i`로 이 기록을 찾고 숫자를 이름으로 바꿔 볼 수 있습니다. auditd는 뒤 섹션의 프로세스 생성 부분에서 자세히 다룹니다.

### 2. 외부 도구: Sysmon for Linux { #sysmon-linux }

Microsoft의 인기 있는 무료 Windows 모니터링 도구 Sysmon에는 Linux판도 있습니다. eBPF로 커널을 지켜보며 프로세스 생성, 네트워크 연결, 파일 생성 등을 기록하고, **Windows Sysmon과 같은 이벤트 ID와 XML 배치**를 씁니다. syslog/저널로 쓰기 때문에 `/var/log/syslog`에 이런 줄이 남습니다(줄임).

```
Nov 20 14:35:40 web-01 sysmon: <Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID>...<Computer>web-01</Computer></System><EventData><Data Name="Image">/usr/bin/curl</Data><Data Name="CommandLine">curl -s -o /tmp/.cache-upd ...</Data><Data Name="User">deploy</Data><Data Name="ParentImage">/usr/bin/bash</Data>...</EventData></Event>
```

- `sysmon:` — 태그. 이걸로 경로를 정하고 찾습니다.
- `<EventID>1</EventID>` — Windows와 똑같이 프로세스 생성.
- `Image`, `CommandLine`, `User`, `ParentImage` — Windows에서 아는 이름 그대로의 칸이라, 같은 분석 규칙과 파서를 두 플랫폼에 재사용할 수 있습니다.

약점은 전달 방식입니다. syslog 한 줄 안에 든 XML은, 그걸 꺼낼 줄 아는 파서가 있어야 합니다.

### 3. 직접 만든 스크립트: `logger` { #logger }

어떤 스크립트든 `logger`로 시스템 로그에 쓸 수 있어서, 우리 쪽 점검 결과를 남길 때 편합니다.

```
$ logger -t soc-integrity -p local5.notice "sha256 mismatch on /usr/sbin/sshd"
```

- `-t soc-integrity` — 태그. SIEM이 이 메시지를 찾을 수 있게.
- `-p local5.notice` — 팀이 자기 스크립트용으로 정해 둔 로컬용 facility와 severity `notice`.
- 메시지 — 스크립트가 찾은 것.

침입자가 줄을 위조할 때 쓰는 그 도구로, 우리는 쓸모 있는 줄을 더할 수 있습니다. 팀이 어떤 `local` facility를 쓰는지 적어 두어 SIEM 엔지니어가 대응표를 만들 수 있게 하세요.

**[보충] Snoopy.** Snoopy는 모든 프로그램 실행(사용자, 명령줄, 작업 폴더)을 평범한 syslog 한 줄로 남기는 작은 오픈소스 라이브러리입니다. auditd보다 읽기 쉽지만, root를 가진 침입자가 끄기도 더 쉽습니다. 뒤에서 프로세스 생성과 함께 다룹니다.

## Linux 로그 섹션 정리 { #summary }

Windows와 비교하면 Linux 로그는 완전히 다른 방식입니다. 이해하기는 더 쉽고, 많이 쌓이면 분석하기는 더 괴롭습니다.

- **파일 속 평범한 텍스트.** 어떤 도구로든 읽기 쉽지만, 프로그램마다 자기 문장을 쓰니 칸을 **손으로 파싱**(정규식)해야 하는 경우가 많고, 문구가 바뀌면 파서가 깨집니다. `sshd-session`으로 바뀐 일이 그 예입니다.
- **facility와 severity가 모든 걸 정합니다.** 메시지가 어느 파일에 쓰이고 어느 호스트로 전달될지 정하죠. 사실이 아니라 보낸 쪽의 주장입니다.
- **데몬은 강력합니다.** rsyslog와 syslog-ng는 거르고, 디스크에 쌓아 두고, 형식을 바꾸고(예: JSON), 다른 syslog 중계 서버, Kafka 같은 메시지 브로커, 데이터베이스로 보낼 수 있습니다.
- **저널이 구조를 가져왔습니다.** 이름 있는 칸과 신뢰 칸이 있지만, 이진 형식이고, 휘발성일 수 있고, 평범한 syslog로만 전달하면 추가 칸을 잃습니다.
- **장비 상당수는 속이 Linux입니다.** 방화벽, 프록시, 스토리지 장비가 Linux로 돌아가도 자기만의 로그 형식을 쓸 수 있어서 따로 파서가 필요합니다.

SOC 입장에서 실무 결론은 이겁니다. 어떤 파일과 저널을 모으는지, 어떤 형식으로 도착하는지, 어떤 전송 방식을 쓰는지 검토하고, 악성 행위 탐지에 유리한 설정을 고릅니다. **무엇보다 파싱을 확인하세요. 제대로 파싱되지 않는 로그로는 분석 규칙을 쓰기 어렵습니다.**

## SOC에서 써먹기 { #soc-use }

새 Linux 빌드를 붙이거나 Linux 알림을 받으면:

1. **진짜 원본은 어디인가?** 저널만, 텍스트 파일만, 아니면 둘 다? 저널은 영구 저장인가(`/var/log/journal`이 있나), 재부팅하면 사라지나?
2. **어떤 파일을 모으나?** 최소한 인증 로그(`auth.log`/`secure`), 일반 로그, `audit.log`, cron, 방화벽, 그리고 그 호스트 역할에 맞는 서버 앱 로그. 순환은 처리되나?
3. **중요한 프로그램이 파싱되나?** sshd(그리고 `sshd-session`), sudo, su, cron, auditd, 웹 서버. 현재 버전에서 새로 뽑은 예시 줄로 시험합니다.
4. **명령이 보이나?** auditd(또는 Sysmon for Linux, Snoopy)가 실행을 기록하고, 그 기록이 SIEM까지 오나?
5. **믿을 수 있나?** 저널 신뢰 칸이 유지되나? 로그가 TLS로 빨리 전달되나? 호스트가 조용해지면 경보가 울리나?
6. **사고 대응 중에는** 바뀌기 전에 호스트에서 모읍니다. `/var/log`(순환된 `.gz` 포함), 저널 폴더, `wtmp`/`btmp`/`lastlog`(또는 `wtmpdb`/`lastlog2`), `/var/log/audit/`.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    전통적인 길(프로그램 → syslog 데몬 → `/var/log` 파일과 원격 수집기), `auth.log`/`secure`와 `syslog`/`messages`라는 파일 이름, logrotate, `-u`를 쓰는 `journalctl`, auditd 기록 형식, `logger` 모두 설명한 대로 동작합니다. 이제 주요 배포판 거의 전부에서 저널이 기본 로컬 저장소이고, Sysmon for Linux는 Microsoft가 계속 관리하고 있습니다. 핵심 교훈 — 무엇을 모으는지, 어떻게 파싱되는지, 빠짐없는지 확인하라 — 은 그대로입니다.

!!! info "[변경됨] 바뀐 점"
    - **저널이 먼저, 텍스트 파일은 선택.** Debian 12 이후는 기본으로 rsyslog를 설치하지 않아서, 따로 넣지 않으면 `/var/log/auth.log`와 `/var/log/syslog`가 없습니다. 다른 배포판은 여전히 journald와 rsyslog를 함께 넣으니 빌드마다 확인합니다.
    - **OpenSSH 9.8 이후 sshd가 나뉨.** 세션 메시지가 `sshd-session`에서 나올 수 있어서, `sshd[`에 맞춘 로그 도구와 SIEM 규칙들이 고쳐져야 했습니다.
    - **2038년 문제 없는 로그인 기록.** 일부 최신 배포판(Debian 13부터)에서 `wtmp`/`btmp`/`lastlog`가 `wtmpdb`와 `lastlog2`로 바뀌는 중입니다. 포렌식 도구와 수집 스크립트가 둘 다 다뤄야 합니다.
    - **파일보다 에이전트.** SIEM, EDR, OpenTelemetry 에이전트가 점점 저널을 직접 읽으면서 구조화 칸을 유지합니다. 상용 Linux EDR 센서(보통 eBPF 기반)가 예전엔 auditd나 Snoopy가 필요했던 프로세스·네트워크 활동을 기록하고, 많은 SOC가 EDR 기록을 주된 명령줄 소스로, auditd를 독립된 두 번째 소스로 씁니다.
    - **공통 스키마.** 파이프라인이 Linux 로그를 Elastic Common Schema나 OCSF 같은 스키마로 바꿔서, `user.name`이나 `process.command_line`이 Linux와 Windows에서 같은 뜻이 되게 하는 경우가 많습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **목록에 있다고 파일이 있다고 가정하지 마세요.** 경로는 배포판과 버전마다 다릅니다(`kern.log`와 `ufw.log`를 `/var/log/audit/` 아래에 적은 목록도 있는데 틀렸습니다). 실제 호스트에서 확인하고, 조용한 소스에 경보를 겁니다.
    - **휘발성 저널에 기대지 마세요.** `/var/log/journal`이 없으면 재부팅 때 로그가 사라집니다. 영구 저장으로 바꾸고, 어쨌든 호스트 밖으로 보냅니다.
    - **누가 줄을 썼는지가 중요하다면, 저널을 평범한 syslog로만 전달하지 마세요.** 신뢰 칸(`_UID`, `_COMM`, `_EXE`, `_SYSTEMD_UNIT`)이 사라집니다.
    - **`.bash_history`를 감사 로그로 여기지 마세요.** 사용자가 마음대로 합니다. auditd, Sysmon for Linux, Snoopy, EDR을 씁니다.
    - **`wtmp`/`btmp`를 `cat`이나 `grep`으로 보지 마세요.** 이진 파일입니다. `last`/`lastb`(또는 `wtmpdb` 도구)를 쓰지 않으면 놓치거나 잘못 읽습니다.
    - **탐지에 `sshd[`를 박아 넣지 마세요.** `sshd-session`도 잡고, 큰 OS 업그레이드마다 파서를 시험합니다.

## 확인 문제 { #quiz }

### 문제 1

지난달 새 Debian 13 웹 서버를 SIEM에 붙였습니다. Apache 로그는 보이는데, 관리자가 매일 로그인하는데도 **SSH나 sudo 이벤트가 하나도 없습니다.** 에이전트는 `/var/log/auth.log`를 따라 읽도록 설정돼 있습니다. 가장 그럴듯한 이유는 무엇이고, 각 메시지를 진짜 누가 썼는지 보여 주는 정보까지 지키려면 어떻게 고치겠습니까?

??? success "정답과 해설"
    **가장 그럴듯한 이유:** Debian 12 이후는 기본으로 rsyslog를 설치하지 않습니다. syslog 데몬이 없으니 `/var/log/auth.log`를 만드는 프로그램이 없고, 인증 이벤트는 **systemd 저널에만** 있습니다. 에이전트는 없는 파일을 따라 읽으면서 오류도 없이 아무것도 보내지 않습니다. (Apache는 자기 파일을 직접 쓰니까 그건 들어오는 겁니다.)

    **확인:** `ls /var/log/auth.log`(파일 없음), `systemctl status rsyslog`(설치 안 됨), `journalctl -u ssh --since today`(로그인이 거기 있음). `ls /var/log/journal`도 확인하세요. 없으면 저널이 휘발성이라 재부팅 때마다 사라집니다.

    **고치는 법:** 가장 좋은 건 에이전트가 **저널을 직접 읽게**(journald 입력) 하고, `ssh.service` 같은 유닛과 `sudo`, `su`, `sshd-session` 같은 식별자로 거르는 것입니다. 그래야 신뢰 칸 `_UID`, `_COMM`, `_EXE`, `_SYSTEMD_UNIT`이 유지됩니다. rsyslog를 설치하고 `auth.log`를 따라 읽어도 이벤트는 돌아오지만, 평범한 텍스트 줄에서는 그 칸들이 사라집니다. 저널을 영구 저장으로 바꾸고, `sshd-session`에 맞게 파서를 고치고, 호스트 단위만이 아니라 로그 종류 단위로 "소스가 조용해짐" 경보를 겁니다. 이번 경우는 호스트가 조용했던 게 아니라 로그 한 종류만 조용했으니까요.

### 문제 2

Red Hat 계열 서버의 `/var/log/secure`에서 다음을 찾았습니다. 각 줄을 설명하고, 관련된 ATT&CK 기법을 말하고, 다음에 무엇을 확인할지 적으세요.

```
Nov 20 02:14:09 db-02 sshd[3170]: Accepted password for svc_backup from 198.51.100.61 port 50544 ssh2
Nov 20 02:15:31 db-02 sudo: svc_backup : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab -e
Nov 20 02:17:02 db-02 sudo: svc_backup : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/journalctl --vacuum-time=1s
```

??? success "정답과 해설"
    **한 줄씩:**

    - 02:14:09 — 외부 주소 `198.51.100.61`에서 서비스 계정 `svc_backup`으로 SSH **비밀번호** 로그인. 서비스 계정은 보통 비밀번호로 대화형 로그인을 하면 안 됩니다. 훔치거나 추측한 자격 증명일 수 있습니다(**T1078**, Valid Accounts; 어쩌면 **T1110**).
    - 02:15:31 — `svc_backup`이 sudo로 **root의 crontab**을 편집했습니다. 작업 폴더가 `/tmp`인 것도 이상합니다. root cron 작업 추가는 지속성(**T1053.003**)입니다.
    - 02:17:02 — sudo로 `journalctl --vacuum-time=1s` 실행. 1초보다 오래된 저널 파일을 지우는 명령, 즉 저널 기록을 싹 지운 겁니다. 흔적 지우기(**T1070.002**)입니다. 텍스트 파일 `/var/log/secure`에는 아직 이 줄들이 있다는 점에 주목하세요. 침입자가 저널은 지웠지만 rsyslog 파일은 (아직) 안 지웠습니다. 둘 다 두고, 호스트 밖으로 보내야 하는 이유입니다.

    **다음 확인:**

    1. 지금 증거를 보존합니다. `/var/log/secure*`, `/var/log/cron*`, `/var/log/messages*`, `/var/log/audit/`, 남은 저널, `wtmp`/`btmp`를 호스트 밖으로 복사합니다.
    2. `sudo crontab -l -u root`와 `/var/spool/cron/root` — 어떤 작업이 추가됐나? `/var/log/cron`에서 실행 기록을 봅니다.
    3. SIEM(이미 호스트 밖에 있음)에서 02:17 이전 저널 내용과, `auid`가 `svc_backup`인 auditd 기록으로 실행된 모든 명령을 봅니다.
    4. `last -F` / `lastb`로 `198.51.100.61`의 다른 로그인을 보고, 같은 IP를 다른 서버에서도 찾습니다.
    5. 서비스 계정의 비밀번호 로그인을 막고, 자격 증명을 재설정하고, 저널 봉인과 `journalctl --vacuum`·`--rotate` 명령에 대한 경보를 검토합니다.

### 문제 3

텍스트 파일에 `Nov 20 14:03:51 web-01 sshd[5120]: Accepted password for admin from 10.20.30.99 port 40022 ssh2`가 있는데, `last`에는 맞는 로그인이 없습니다. 저널을 써서 sshd가 정말 이 줄을 썼는지 어떻게 판단하겠습니까? 명령과 비교할 칸을 적고, 텍스트 파일만으로는 왜 답할 수 없는지 설명하세요.

??? success "정답과 해설"
    **텍스트 파일만으로 안 되는 이유:** 태그 `sshd`, PID, facility, 메시지 모두 보낸 쪽이 적는 값입니다. `logger -t sshd -p authpriv.info "..."`로 똑같아 보이는 줄을 만들 수 있으니, 텍스트가 증명하는 건 **뭔가가** 이 글자를 썼다는 것뿐입니다.

    **명령:**

    ```
    journalctl -o json-pretty --since "2026-11-20 14:03:50" --until "2026-11-20 14:03:52" SYSLOG_IDENTIFIER=sshd
    ```

    - `-o json-pretty` — 항목마다 모든 칸을 보여 줍니다.
    - `--since`/`--until` — 그 줄의 1초 앞뒤로 좁힙니다.
    - `SYSLOG_IDENTIFIER=sshd` — 주장된 태그로 거릅니다.

    **신뢰 칸(보낸 쪽이 아니라 journald가 적음)을 비교합니다:**

    - `_COMM` / `_EXE` — 진짜 sshd라면 `sshd`나 `sshd-session`, `/usr/sbin/sshd`(또는 `sshd-session` 경로). `logger`와 `/usr/bin/logger`면 위조입니다.
    - `_UID` — sshd는 root(`0`)로 돕니다. 일반 사용자 UID면 sshd가 아닙니다.
    - `_SYSTEMD_UNIT` — 진짜 sshd는 `ssh.service`/`sshd.service`. `session-N.scope`면 누군가의 로그인 세션에서 나온 겁니다.
    - `_CMDLINE` — `logger ...` 전체 명령이 보일 겁니다.
    - `_PID` — `SYSLOG_PID`, 그리고 텍스트 줄의 PID와 비교합니다.

    `last`에 기록이 없는 것도 위조와 맞아떨어집니다. 진짜 로그인 성공이라면 보통 `wtmp`에도 남으니까요. 신뢰 칸이 `logger`를 가리키면 그 UID와 세션의 주인을 찾고, 심어 놓은 줄을 의도적인 교란일 가능성으로 다룹니다.

## 관련 레퍼런스 { #related }

- [Syslog](syslog.md) — 이 페이지의 바탕인 형식, 전송, 데몬, facility와 severity
- [Windows 로그](../windows-logging/index.md) — 비교 대상인 구조화된, 이벤트 ID 기반 방식
- [Linux 로그, 프로세스, 라이브 트리아지](../../../linux/logs-and-triage.md)
- [Linux 인증과 셸 히스토리](../../../linux/auth-and-history.md)
- [Linux 지속성](../../../linux/persistence.md) — 이 로그들에서 보이는 cron, systemd, SSH 키 지속성
- [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md) — 네트워크 쪽에서 본 SSH 악용
