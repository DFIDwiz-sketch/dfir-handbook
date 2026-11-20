---
title: "Syslog — Linux 로그가 다른 점, “syslog”의 세 가지 뜻, 메시지 형식, 네트워크 전송, 데몬, facility와 severity"
tags:
  - training
  - blue-team
  - linux
  - logging
  - syslog
---

# Syslog — Linux 로그가 다른 점, “syslog”의 세 가지 뜻, 메시지 형식, 네트워크 전송, 데몬, facility와 severity { #syslog }

!!! abstract "이 페이지에서 다루는 것"
    Linux 로그는 Windows보다 단순해 보이는데 왜 검색하기는 더 어려운지, 그리고 왜 기댈 이벤트 ID가 없는지. "syslog"라는 한 단어를 세 가지 뜻 — 메시지 형식, 데몬 프로그램, 네트워크 프로토콜 — 으로 나눠 봅니다. 옛 형식(RFC 3164) 헤더를 칸별로 읽고, 새 형식(RFC 5424) 헤더도 보고, 메시지가 자유 문장이라 왜 정규식에 기댈 수밖에 없는지 봅니다. syslog가 네트워크로 어떻게 가는지(UDP 514, TCP, 6514 포트의 TLS), 크기 제한, 그리고 평범한 UDP syslog가 왜 사라지거나 위조될 수 있는지. 대표 데몬 세 가지 — syslogd, syslog-ng, rsyslog — 와 2023년의 AxoSyslog 포크, Debian 12의 "journald만" 기본값이 여러분에게 무슨 뜻인지. 마지막으로 facility와 severity, 이 둘이 우선순위 값(`<PRI>`)에 어떻게 담기는지, PRI를 머릿속으로 푸는 법, 데몬이 이 값으로 메시지를 어디로 보내는지. 끝에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. Linux(그리고 Unix 계열 시스템 전반)는 운영체제 로그를 **syslog 형식**으로 씁니다. 짧은 표준 헤더(시각, 호스트, 프로그램, 있으면 PID) 뒤에 **자유 형식 메시지**가 붙습니다. **이벤트 ID가 없고**, 메시지 부분에 정해진 구조도 없습니다.
2. "Syslog"는 **세 가지 다른 것**을 뜻합니다. **메시지 형식**, 메시지를 받아서 나눠 보내는 **데몬**(rsyslog, syslog-ng, syslogd), 그리고 메시지를 다른 장비로 보내는 **네트워크 프로토콜**. 누가 "syslog"라고 하면 어느 쪽인지 꼭 물어봅니다.
3. 옛 헤더에는 **연도가 없고 보통 시간대도 없습니다.** 그 빈칸은 SIEM이 채우는데, 새해 무렵, 시간대가 다른 곳, 오래된 파일을 다시 넣을 때 틀리게 채울 수 있습니다.
4. 메시지가 자유 문장이라 칸을 뽑으려면 보통 <strong>정규식(regular expression)</strong>을 써야 하고, 문구가 바뀌면 깨집니다. **key=value나 JSON**으로 로그를 남기는 프로그램이 훨씬 검색하기 쉽습니다.
5. 기본 네트워크 전송은 **암호화도 인증도 없는 UDP 514번 포트**입니다. 메시지가 조용히 **사라질** 수 있고, 패킷을 보낼 수 있는 누구나 **위조**할 수 있습니다. 보안에 중요한 로그는 TCP, 가능하면 **6514 포트의 TLS**로 보냅니다.
6. 모든 메시지에는 **facility**(시스템의 어느 부분에서 왔다고 주장하는지)와 **severity**(얼마나 중요한지, 0 = 비상 … 7 = 디버그)가 붙어 있습니다. 데몬은 이 두 값으로 어느 파일에 쓸지, 어디로 전달할지를 정합니다.
7. 네트워크에서는 둘이 <strong>우선순위(priority)</strong>라는 숫자 하나로 합쳐집니다. `PRI = facility × 8 + severity`이고, 맨 앞에 꺾쇠괄호로 씁니다. 예: `<38>` = `auth.info`. 8로 나눈 몫과 나머지로 풉니다.
8. Facility는 **사실이 아니라 주장**입니다. 많은 프로그램과 장비가 `user`나 `local0`–`local7`로 로그를 남기고, 로컬 사용자 누구나 아무 facility와 프로그램 이름으로 메시지를 쓸 수 있습니다. syslog는 "**누군가 이 문장을 썼다**"는 증거로 보고, 다른 증거로 확인합니다.

## Linux 로그가 다르게 느껴지는 이유 { #why-different }

Windows 이벤트 로그를 막 보고 오셨다면 Linux 로그는 너무 쉬워 보입니다. Windows 이벤트는 공급자, 이벤트 ID, 채널, 이름 붙은 칸이 있는 구조화된 XML 기록이죠. 옛날식 Linux 로그는 평범한 파일 안의 텍스트 한 줄입니다.

```
Nov 20 14:03:51 web-01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2
```

`cat`, `less`, `grep`으로 그냥 읽을 수 있고 특별한 뷰어도 필요 없습니다. 이건 좋은 소식입니다. 나쁜 소식은 빠진 것들입니다. "이건 로그온 실패"라고 말해 주는 이벤트 ID도, `IpAddress`라는 칸도 없고, 다음 OpenSSH 버전에서 문구가 그대로일 거라는 약속도 없습니다. 읽기는 쉬운데, 많이 쌓이면 검색하기 어렵습니다.

두 시스템을 서류에 비유해 보죠. Windows는 관공서 신청서입니다. 칸마다 이름이 있고, "방문 목적" 칸에는 정해진 목록의 코드만 들어갑니다. Linux syslog는 엽서 더미입니다. 엽서마다 구석에 표준 도장(날짜, 보낸 곳, 어느 부서)이 찍혀 있지만, 나머지는 쓴 사람이 마음대로 휘갈긴 글입니다. 엽서 한 장 읽기는 쉽지만, 천만 장 속에서 "지난주 로그온 실패 전부"를 찾으려면 모든 필자의 글씨체를 알아보는 규칙이 필요합니다.

다시 기술적인 얘기로 돌아와, 분석가가 체감하는 차이는 이렇습니다.

| | Windows 이벤트 로그 | Linux syslog(옛 방식) |
| --- | --- | --- |
| 저장 | 채널마다 `.evtx` 파일, 이진 XML | 보통 `/var/log` 아래 평범한 텍스트 파일, 또는 systemd 저널(이진, 구조화) |
| 이벤트 종류 구분 | 공급자 + 이벤트 ID(예: Security 4625) | ID 없음. 프로그램 이름과 메시지 문구로 맞춤 |
| 칸 | 이름 있는 칸(`TargetUserName`, `IpAddress`) | 헤더만 표준이고 메시지는 자유 문장 |
| 분류 | 채널, 수준, 작업 범주, 키워드 | **facility**와 **severity**뿐 |
| 나눠 담기 | 공급자가 정한 채널에 Event Log 서비스가 기록 | syslog 데몬이 설정의 facility/severity 규칙대로 분배 |
| 전달 | 에이전트, Windows 이벤트 전달(WEF) | 데몬에 내장: UDP, TCP, TLS로 수집기에 보냄 |
| SIEM 파싱 | XML에서 대부분 자동 | 프로그램마다 따로 만든 정규식인 경우가 많음 |

표에 두 가지를 덧붙이겠습니다. 첫째, 여기 내용은 Linux만이 아니라 Unix 계열 전반(BSD, 네트워크 장비 등)에 해당합니다. 그래서 방화벽, 스위치, 스토리지 장비가 거의 다 syslog를 말합니다. 둘째, 요즘 배포판에서는 **systemd 저널**(`journald`)이 저장 방식을 바꿉니다. 이름 있는 칸을 가진 이진 구조화 기록이라 Windows에 훨씬 가깝습니다. 저널은 다음 페이지에서 다루고, 이 페이지는 syslog 자체에 집중합니다. 저널을 쓰는 시스템도 여전히 syslog 형식 메시지를 만들고 전달하기 때문입니다.

## "Syslog"의 세 가지 뜻 { #three-meanings }

SOC에서 이런 말을 듣게 됩니다. *"syslog 메시지를 syslog 데몬이 받아서 syslog로 SIEM에 보내요."* 한 단어가 세 가지를 가리킵니다.

1. **Syslog 형식** — 메시지 글자가 어떻게 생겼는가: 헤더 배치와 메시지가 어디서 시작하는지.
2. **Syslog 데몬** — 호스트에서 돌면서 응용 프로그램과 커널이 보낸 메시지를 받아 파일에 쓰거나 다른 곳으로 전달하는 프로그램. 흔한 것은 **rsyslog**, **syslog-ng**, 원조 **syslogd**.
3. **Syslog 네트워크 프로토콜** — 메시지를 장비 사이에서 어떻게 나르는가: 전송 방식(UDP, TCP, TLS), 포트(기본 514), 메시지 구분 방식, 크기 제한.

우편에 비유하면 구분이 쉽습니다. **형식**은 봉투 양식(주소와 우표 자리), **데몬**은 봉투를 칸과 트럭에 나눠 싣는 동네 우체국, **프로토콜**은 도시 사이의 도로와 트럭입니다. 하나만 바꿀 수도 있습니다. 예를 들어 형식은 그대로 두고 트럭만 UDP에서 TLS로 바꾸는 식이죠.

분석가가 왜 신경 써야 할까요? 문제가 생기는 층이 다르기 때문입니다. "방화벽 로그 연도가 틀려요"는 **형식** 문제입니다. "서버 절반의 인증 로그가 안 들어와요"는 흔히 **데몬** 설정 문제입니다. "바쁜 시간에 DMZ 로그가 빠져요"는 대개 **프로토콜** 문제(UDP 유실)입니다. "어느 syslog 말씀이세요?" 한마디가 몇 시간을 아껴 줍니다.

## Syslog 메시지 형식 { #format }

### 옛 헤더(RFC 3164 방식) { #rfc3164 }

Syslog는 1980년대에 Sendmail 프로젝트용으로 만들어졌고, 그 뒤 Unix가 로그를 남기는 표준 방식이 됐습니다. 문서로 정리된 건 나중입니다. **RFC 3164**(2001)가 이미 쓰이던 "BSD syslog" 형식을 정리한 것이죠. 지금 보는 syslog 대부분이 여전히 이렇게 생겼습니다.

```
<time> <hostname> <program>[<PID>]: <message>
```

가상의 Ubuntu 호스트 `web-01.corp.example`의 파일에 실제로 찍히는 모습으로 세 줄을 만들어 봤습니다.

```
Nov 20 14:03:47 web-01 dhclient[812]: DHCPACK of 10.20.30.41 from 10.20.30.1 (xid=0x5a1c2e7d)
Nov 20 14:03:51 web-01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2
Nov 20 14:04:02 web-01 kernel: [183245.117302] usb 2-1: new high-speed USB device number 4 using ehci-pci
```

두 번째 줄을 한 조각씩 뜯어봅니다.

| 조각 | 값 | 뜻 |
| --- | --- | --- |
| 시각 | `Nov 20 14:03:51` | 월, 일, 시각. **연도도, 시간대도, 초 이하 단위도 없습니다.** 시각은 그 호스트의 로컬 시계와 시간대 그대로입니다. |
| 호스트 이름 | `web-01` | 메시지를 쓴 장비 이름(전체 도메인 이름이 아니라 짧은 이름인 경우가 많음). |
| 프로그램("태그") | `sshd` | 로그를 남긴 프로그램. 프로그램이 스스로 적은 글자일 뿐입니다. |
| PID | `[2211]` | 쓴 프로세스의 ID, 대괄호 안. 선택 사항이라 커널 줄에는 없습니다. |
| 구분자 | `:` | 콜론과 공백 뒤가 전부 메시지입니다. |
| 메시지 | `Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2` | 프로그램이 정한 자유 문장. 표준은 여기에 대해 아무 말도 하지 않습니다. |

쉬운 말로 풀면 이렇습니다. 로컬 시각 14:03:51에, `web-01`의 SSH 서버 프로세스 2211이 `oracle`이라는 계정의 비밀번호를 거절했는데, 그 계정은 **이 서버에 존재하지도 않고**("invalid user"), 시도는 `203.0.113.45`에서 왔습니다. 한 IP에서 여러 사용자 이름으로 이런 줄이 줄줄이 나오면 비밀번호 추측입니다. MITRE ATT&CK **T1110.001**(Password Guessing), 비밀번호 하나를 여러 계정에 돌려 보면 **T1110.003**(Password Spraying)입니다.

나머지 두 줄은 "메시지" 부분이 얼마나 제각각인지 보여 줍니다. `dhclient` 줄은 DHCP가 서버 `10.20.30.1`에게서 `10.20.30.41`을 임대받았다는 뜻이라, IP를 장비로 바꿀 때 쓸모가 있습니다. `kernel` 줄은 대괄호 안에 부팅 후 경과 시간(`[183245.117302]`초)을 따로 담고 PID가 없습니다. USB 장치가 꽂혔다는 뜻이라 이동식 저장 매체 조사에서 중요합니다.

**[보충] 연도와 시간대가 없는 건 실제로 문제가 됩니다.** SIEM이 `Nov 20 14:03:51`을 받으면 연도(보통 "올해")와 시간대(보통 자기 시간대나 소스별 설정)를 짐작해야 합니다. 그러다 보면 뻔한 방식으로 틀립니다.

- `Dec 31 23:59:58`에 쓰인 줄이 1월 1일에 처리되면 **새해** 연도가 붙어서, 이벤트가 1년 뒤 미래에 있는 것처럼 보입니다.
- 오래된 파일을 다시 넣으면 이벤트가 올해로 들어갑니다.
- 시드니 서버는 로컬 시각으로, 수집기는 UTC로 기록하면 10~11시간 차이가 나서 타임라인이 밀립니다. SSH 로그인과 방화벽 연결을 맞춰 볼 때 치명적이죠.

해결은 보내는 쪽에서 합니다. 서버를 UTC로 맞추거나, 최소한 데몬이 시간대 오프셋이 붙은 RFC 3339 전체 시각을 쓰게 하고, 바꿀 수 없는 장비는 SIEM에서 소스별 시간대를 설정합니다. 배포판과 버전에 따라 파일에 이미 `2026-11-20T14:03:51.204871+11:00` 같은 긴 형식이 찍혀 있을 수도 있습니다. 짐작하지 말고 플랫폼마다 실제 파일을 열어 확인합니다.

### 자유 문장이 파싱을 괴롭게 만드는 이유 { #parsing }

"출발지 IP별 SSH 로그온 실패"를 검색하려면, SIEM이 문장에서 사용자와 IP를 뽑아내도록 가르쳐야 합니다. 흔히 쓰는 정규식은 이렇습니다.

```
^(?<ts>\w{3}\s+\d+\s[\d:]{8})\s(?<host>\S+)\ssshd\[(?<pid>\d+)\]:\sFailed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>[\d.]+) port (?<src_port>\d+)
```

왼쪽부터 읽어 봅니다.

- `^(?<ts>\w{3}\s+\d+\s[\d:]{8})` — 줄 맨 앞에서, 세 글자 월, 공백 하나 이상(한 자리 날짜는 `Nov  2`처럼 공백이 하나 더 붙음), 날짜, 공백, `hh:mm:ss` 시각을 `ts`라는 칸에 담습니다.
- `\s(?<host>\S+)` — 공백 뒤 호스트 이름(공백 아닌 글자 덩어리).
- `\ssshd\[(?<pid>\d+)\]:` — 글자 그대로의 프로그램 이름 `sshd`, 대괄호 속 PID, 콜론.
- `\sFailed password for (?:invalid user )?` — 고정 문구. `invalid user ` 부분은 계정이 없을 때만 나오니 있어도 되고 없어도 되게(`?`) 합니다.
- `(?<user>\S+) from (?<src_ip>[\d.]+) port (?<src_port>\d+)` — 사용자 이름, IPv4 주소, 포트를 담습니다.

예시 줄에 적용하면 이렇게 나옵니다.

```
ts=Nov 20 14:03:51  host=web-01  pid=2211  user=oracle  src_ip=203.0.113.45  src_port=51122
```

이제 얼마나 깨지기 쉬운지 보세요. IPv6 출발지는 못 잡습니다(`[\d.]+`에 콜론이 없음). 따로 나오는 `Failed publickey for ...`나 `Invalid user oracle from ...` 줄도 놓칩니다. 공백이 든 사용자 이름이나, 문구를 바꾼 OpenSSH 버전 하나면 조용히 깨집니다. 그리고 깨진 파서는 **결과 0건**을 내는데, 그건 "공격 없음"과 똑같아 보입니다. 그래서 SIEM의 Linux 프로그램별 파서는 시험하고 관리해야 합니다.

구조화해서 로그를 남기는 프로그램과 비교해 보죠. key=value 방식:

```
Nov 20 14:05:10 fw-edge-01 filterlog: action=block proto=tcp src=198.51.100.23 sport=44871 dst=192.0.2.10 dport=22
```

메시지 안에 JSON을 담는 방식:

```
Nov 20 14:05:12 app-03 orderapi[4410]: {"event":"login_failed","user":"j.kim","src_ip":"198.51.100.77","reason":"bad_password"}
```

이런 건 SIEM이 범용 key=value나 JSON 파서로 자동으로 쪼갭니다. 메시지마다 정규식을 만들 필요가 없고, 새 칸이 생겨도 누가 패턴을 다시 쓸 필요가 없습니다. 사내 프로그램이 로그를 어떻게 남길지 의견을 낼 수 있다면 구조화된 메시지를 요청하세요. 가장 싼 탐지 공학(Detection Engineering) 성과 중 하나입니다.

**[주의] Syslog 글자만으로는 믿을 수 없습니다.** 로컬 사용자라면 누구나 표준 도구 `logger`로 아무 프로그램 이름, 아무 facility의 메시지를 쓸 수 있습니다.

```
$ logger -t sshd -p authpriv.info "Accepted password for admin from 10.20.30.99 port 40022 ssh2"
```

- `logger` — 로컬 syslog 데몬에 메시지 하나를 보냅니다.
- `-t sshd` — 태그(프로그램 이름)를 `sshd`로 정합니다. sshd가 쓴 게 아닌데도요.
- `-p authpriv.info` — facility `authpriv`, severity `info`로 정합니다.
- 따옴표 안이 메시지입니다.

결과는 auth 로그에서 진짜 sshd 줄과 거의 똑같아 보입니다. 차이는 PID가 `logger` 프로세스 번호이거나(버전과 옵션에 따라 아예 없거나), 저널이 있다면 실제로 보낸 프로세스 정보가 저널에 남는다는 정도입니다. 공격자는 이걸로 잡음이나 가짜 흔적을 심을 수 있고, 평범한 텍스트 파일을 지우거나 고치거나(**T1070.002**, Clear Linux or Mac System Logs), 데몬을 멈출 수도 있습니다(**T1562.006**, Indicator Blocking). 방어: 로그를 빨리 호스트 밖으로 보내고, 호스트가 조용해지면 경보를 울리고, 가능하면 저널의 신뢰할 수 있는 칸이나 auditd로 교차 확인합니다.

### 새 헤더(RFC 5424) { #rfc5424 }

**RFC 5424**(2009)는 서류상으로 RFC 3164를 대체했습니다. "헤더 + 메시지"라는 생각은 그대로 두고 가장 큰 구멍을 메웠죠. 네트워크로 보내는 모습의 예시입니다.

```
<86>1 2026-11-20T03:03:51.204871Z web-01.corp.example sshd 2211 - [origin ip="10.20.30.41"] Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2
```

| 조각 | 값 | 뜻 |
| --- | --- | --- |
| PRI | `<86>` | 우선순위 = facility × 8 + severity(아래에서 풀면 `authpriv.info`). |
| VERSION | `1` | 프로토콜 버전. 이게 있는지로 받는 쪽이 5424인지 3164인지 구분합니다. |
| TIMESTAMP | `2026-11-20T03:03:51.204871Z` | RFC 3339 전체 시각: **연도, 초 이하, 시간대**(`Z` = UTC). |
| HOSTNAME | `web-01.corp.example` | 가급적 전체 도메인 이름(FQDN). |
| APP-NAME | `sshd` | 프로그램. |
| PROCID | `2211` | 프로세스 ID. |
| MSGID | `-` | 선택 사항인 메시지 종류 식별자. `-`는 "없음". |
| STRUCTURED-DATA | `[origin ip="10.20.30.41"]` | 대괄호 안의 이름 있는 key=value 묶음(선택). 없으면 `-`. |
| MSG | `Failed password ...` | 자유 문장 메시지. |

RFC 5424는 메시지 형식과 전송 방식을 나눠서, 전송은 별도 RFC들로 옮겼습니다(다음 절). 실제로는 5424를 제대로 다 쓰는 경우, 특히 **구조화 데이터**와 **MSGID**를 쓰는 경우는 아직 드뭅니다. 대부분의 프로그램은 여전히 평범한 문장을 데몬에 넘기고, 대부분의 수신 쪽도 3164식 줄을 처리합니다. 같은 수집기에서도 둘 다 보게 될 거라고 생각하세요.

## Syslog 네트워크 프로토콜 { #network }

### 전송 방식, 포트, 관련 RFC { #transports }

데몬은 받은 메시지를 수집기 하나 이상에 전달할 수 있습니다. 방법은 별도 문서들에 정해져 있습니다.

| 전송 방식 | 흔한 포트 | 정의 | 메모 |
| --- | --- | --- | --- |
| UDP, 평문 | **514/udp** | RFC 5426(처음엔 RFC 3164에 설명) | 전통적인 기본값. 전달 보장, 암호화, 인증 모두 없음. |
| TCP, 평문 | 실무에선 514/tcp를 흔히 씀 | 메시지 구분 방식은 RFC 6587에 정리 | 전달은 믿을 만하지만 여전히 암호화 없음. 포트는 표준이 아니라 관례. |
| TCP 위의 TLS | **6514/tcp** | RFC 5425, 암호 스위트는 RFC 9662(2024)로 갱신 | 암호화되고, 인증서를 쓰면 상대 확인까지. 권장 방식. |
| UDP 위의 DTLS | 6514/udp | RFC 6012 | 암호화된 UDP. 지원이 덜 널리 됨. |
| BEEP("신뢰성 syslog") | 601/tcp | RFC 3195 | 요즘은 거의 안 보임. |
| 서명된 메시지 | — | RFC 5848 | 메시지에 서명을 붙임. 실무에선 드묾. |

**[정정]** RFC 3195를 "TCP로 보내는 syslog"라고 설명하는 걸 자주 봅니다. 정확히는 BEEP라는 틀 위에서 전달하는 방식을 정한 것이고, syslog에 BEEP를 쓰는 곳은 거의 없습니다. 평범한 TCP syslog는 관행으로 퍼졌고 나중에 문서화됐습니다(RFC 6587). 그리고 서명된 syslog는 **RFC 5848**입니다. 번호를 잘못 적는 경우가 있습니다.

### 크기 제한과 메시지 구분 { #size }

RFC 3164는 메시지가 **1024바이트를 넘으면 안 된다**고 했습니다. 이후 RFC들은 이를 풀어서, 받는 쪽은 최소 480바이트를 받아야 하고 2048바이트는 받는 게 좋다고 했고, UDP 데이터그램은 이론상 약 64KB까지 됩니다. TCP에서는 메시지를 줄바꿈으로 나누거나, 앞에 "바이트 수"(길이)를 붙여 나눕니다. 옛 자료에 자주 나오는 "UDP 1KB, TCP 4KB"는 엄격한 한계가 아니라 옛날 기준 정도로 보세요. 여러분에게 중요한 건 이겁니다.

- **긴 메시지는 잘립니다.** 보내는 쪽이나 받는 쪽의 한도가 낮으면요. rsyslog의 기본 최대 메시지 크기는 8KB이고, 많은 장비는 더 짧게 자릅니다. 긴 명령줄이나 큰 JSON은 끝부분이 날아갈 수 있는데, 흥미로운 부분이 바로 거기 있는 경우가 많습니다.
- **줄바꿈으로 나누면 여러 줄짜리 메시지가 깨집니다**(스택 트레이스, 일부 앱 로그). 줄마다 따로 "이벤트"로 도착합니다.

어느 소스 하나의 파서가 갑자기 실패하면, 정규식을 탓하기 전에 잘림부터 확인합니다.

### 네트워크에서 실제로 보이는 모습 { #wire }

수집기(`192.0.2.10`)에서 평문 UDP syslog를 잡아 봅니다.

```
$ sudo tcpdump -i eth0 -nn -A -c 2 udp port 514
14:03:51.205113 IP 10.20.30.41.48211 > 192.0.2.10.514: SYSLOG authpriv.info, length: 112
E.....@.@......)........u.<86>Nov 20 14:03:51 web-01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2
14:03:52.031876 IP 10.20.30.1.514 > 192.0.2.10.514: SYSLOG local4.warning, length: 97
E..}..@.@.......<164>Nov 20 14:03:52 fw-edge-01 filterlog: action=block proto=tcp src=198.51.100.23 dst=192.0.2.10 dport=22
```

한 줄씩:

- `sudo tcpdump` — 패킷 캡처 도구를 필요한 권한으로 실행합니다.
- `-i eth0` — `eth0` 인터페이스에서 듣습니다.
- `-nn` — IP를 이름으로, 포트를 서비스 이름으로 바꾸지 않습니다(빠르고, 원래 값이 보임).
- `-A` — 패킷 내용을 ASCII 글자로 찍습니다.
- `-c 2` — 패킷 두 개를 잡고 멈춥니다.
- `udp port 514` — 캡처 필터: UDP syslog만.
- 출력의 `10.20.30.41.48211 > 192.0.2.10.514`는 출발지 IP와 포트 → 목적지 IP와 포트입니다. tcpdump가 프로토콜을 알아보고 PRI를 풀어서 `SYSLOG authpriv.info`로 보여 줍니다. `E.....@.@...` 같은 쓰레기 글자는 IP/UDP 헤더 바이트를 글자로 찍은 것이고, 읽을 수 있는 부분은 `<86>`부터 시작합니다.
- 두 번째 패킷은 방화벽 `10.20.30.1`에서 온 `<164>`이고, tcpdump는 `local4.warning`으로 보여 줍니다.

네트워크 형식이 무엇을 더하는지 보세요. **`<PRI>` 앞머리**입니다. 데몬이 같은 메시지를 로컬 파일에 쓸 때는 보통 PRI를 빼서, 파일 줄은 날짜로 시작합니다. 네트워크에서는 받는 쪽이 facility와 severity를 알아야 하니 맨 앞에 붙여 보냅니다. Wireshark에서는 같은 패킷이 **Syslog** 프로토콜로 보이고, 상세 창에 Facility, Level, Message가 나뉘어 나옵니다. 표시 필터 `syslog`나 `udp.port == 514`로 찾습니다.

이 캡처의 모든 내용은 경로에 있는 누구나 읽을 수 있습니다. 로그인 사용자 이름, 내부 IP, 때로는 훨씬 나쁜 것(실수로 토큰이나 비밀번호를 로그에 남기는 프로그램)까지 평문으로 네트워크를 지나갑니다.

### 평범한 UDP syslog가 보안 문제인 이유 { #udp-risk }

- **조용한 유실.** UDP에는 받았다는 확인이 없습니다. 수집기가 바쁘거나, 재시작 중이거나, 네트워크가 막히면 메시지가 사라지고 아무도 모릅니다. 바쁜 사고 대응 중 로그 공백 — 바로 로그가 가장 필요한 때입니다.
- **위조.** 수집기는 514로 온 UDP 패킷을 다 받습니다. 닿을 수만 있으면 누구나 출발지 IP를 속여 `<86>Nov 20 14:03:51 web-01 sshd[2211]: Accepted password for root ...`를 보낼 수 있습니다. "호스트 이름" 칸은 그냥 글자입니다.
- **엿듣기.** 위에서 본 대로 암호화가 없습니다.

그래서 믿을 만한 전달은 TCP로, 기밀성과 상대 확인은 <strong>인증서를 쓴 TLS(6514)</strong>로 하고, 수집기에서는 보낼 수 있는 상대를 제한합니다. TCP로도 부족하면 rsyslog의 **RELP** 프로토콜이 응용 계층에서 받았다는 확인을 더해, 연결이 끊겨도 메시지를 잃지 않게 해 줍니다. UDP밖에 못 하는 소스(많은 장비)는 수집기를 가까이, 보호된 네트워크 구간에 둡니다.

## Syslog 데몬 { #daemons }

### 대표 데몬 세 가지 { #three-daemons }

- **syslogd** — 1980년대 초의 원조. BSD 계열 일부에서는 지금도 기본입니다. 설정이 아주 단순하고, UDP 전달 정도의 기능만 있습니다.
- **syslog-ng** — syslogd를 개선하려고 **1998년**에 나왔고, 필터링과 경로 설정을 훨씬 읽기 쉬운 설정으로 할 수 있습니다. Balabit이 만들었고, Balabit은 **One Identity**에 인수됐습니다. 오픈소스판과 상용 "프리미엄"판이 있습니다. **[변경됨]** 2023년에 원래 개발자가 Axoflow라는 회사에서 관리하는 포크 **AxoSyslog**를 시작했고, 보안 데이터 파이프라인을 겨냥합니다. 두 이름 다 만날 수 있습니다.
- **rsyslog** — syslog-ng의 대안으로 **2004년**에 시작됐습니다. 옛 syslogd 설정 문법을 그대로 받아서(옮기기 쉬움) 자기만의 더 풍부한 문법("RainerScript")을 더했고, 아주 빠르며, 많은 배포판(예: Red Hat 계열, Ubuntu)의 기본 syslog 데몬입니다. Linux판은 무료이고, 같은 개발자의 Windows 이벤트를 syslog로 보내는 상용 Windows 에이전트도 있습니다.

syslog-ng와 rsyslog는 "파일 쓰고 UDP로 전달" 수준을 훨씬 넘습니다. 어떤 칸으로든 필터링하고, 메시지를 고쳐 쓰거나 형식을 바꾸고(예: JSON으로), 메시지를 칸으로 파싱하고, 수집기가 죽으면 디스크에 쌓아 두고, 여러 곳으로 보냅니다. UDP/TCP/TLS/RELP로 다른 syslog 서버에, **Kafka**나 RabbitMQ 같은 메시지 브로커에, 데이터베이스에, Elasticsearch/OpenSearch에, 파일에 등등. 많은 SOC에서 SIEM 앞의 "syslog 수집기"가 바로 이런 일을 하는 rsyslog나 syslog-ng 서버입니다.

**[변경됨]** **Debian 12** 이후로는 rsyslog가 **기본으로 설치되지 않습니다.** rsyslog를 따로 설치하지 않으면 로컬 로그 저장소는 systemd 저널뿐이라, 새로 설치한 시스템에는 `/var/log/syslog`와 `/var/log/auth.log`가 아예 없습니다. 이 파일들을 따라 읽는(tail) 방식으로 수집하고 있다면 그 호스트들은 아무것도 보내지 않습니다. 저널과 저널에서 전달하는 법은 다음 페이지에서 다룹니다.

### rsyslog 설정 읽기 { #rsyslog-config }

경로 규칙은 `/etc/rsyslog.conf`와 `/etc/rsyslog.d/` 아래 파일들에 있습니다(Ubuntu는 기본 규칙이 `/etc/rsyslog.d/50-default.conf`에 있음). 옛 규칙 형식은 `선택자    동작`이고, 선택자는 `facility.severity`입니다.

```
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
kern.*                          -/var/log/kern.log
mail.err                        /var/log/mail.err
*.emerg                         :omusrmsg:*
*.*                             @192.0.2.10:514
authpriv.*                      @@192.0.2.10:514
```

한 줄씩:

- `auth,authpriv.*  /var/log/auth.log` — facility `auth`와 `authpriv`의 **모든** severity(`*`)를 auth 로그로. Debian/Ubuntu에서 sshd, sudo, PAM 메시지가 여기 떨어집니다.
- `*.*;auth,authpriv.none  -/var/log/syslog` — 모든 facility와 severity를, auth와 authpriv는 **빼고**(`.none`) 일반 syslog 파일로. 앞의 `-`는 줄마다 디스크에 바로 쓰지 말라는 옛 힌트입니다(빠르지만, 충돌 시 마지막 몇 줄을 잃을 수 있음).
- `kern.*  -/var/log/kern.log` — 커널 메시지 전부.
- `mail.err  /var/log/mail.err` — 메일 메시지 중 severity `err` **이상**(`err`, `crit`, `alert`, `emerg`). 선택자의 severity는 "이 수준과 그보다 심각한 것"을 뜻합니다. 딱 한 수준만이면 `mail.=err`, 그 수준을 빼려면 `mail.!err`.
- `*.emerg  :omusrmsg:*` — 비상 메시지는 로그인한 모든 사용자의 터미널에 띄웁니다.
- `*.*  @192.0.2.10:514` — 전부 수집기로 **UDP**(`@` 하나) 전달.
- `authpriv.*  @@192.0.2.10:514` — authpriv는 **TCP**(`@@` 둘)로 전달.

TLS 전달용 `/etc/rsyslog.d/` 파일은 새 문법을 씁니다.

```
global(DefaultNetstreamDriverCAFile="/etc/pki/rsyslog/ca.pem")

action(type="omfwd"
       target="siem-col-01.corp.example" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1"
       StreamDriverAuthMode="x509/name"
       StreamDriverPermittedPeers="siem-col-01.corp.example"
       queue.type="LinkedList" queue.filename="fwd_siem"
       queue.saveOnShutdown="on" action.resumeRetryCount="-1")
```

- `global(DefaultNetstreamDriverCAFile=...)` — 수집기 인증서를 확인할 때 쓰는 CA 인증서.
- `action(type="omfwd" ...)` — 전달용 출력 모듈을 씁니다.
- `target=... port="6514" protocol="tcp"` — 보낼 곳. TLS syslog 표준 포트입니다.
- `StreamDriver="gtls" StreamDriverMode="1"` — GnuTLS 드라이버를 쓰고 TLS를 필수로 합니다.
- `StreamDriverAuthMode="x509/name"`과 `StreamDriverPermittedPeers=...` — 인증서 이름이 맞는 수집기만 받아들입니다. 이게 없으면 TLS가 암호화는 하지만 상대가 누구인지는 증명하지 못합니다.
- `queue.type="LinkedList" queue.filename=...`와 `queue.saveOnShutdown="on"` — 메시지를 메모리에 쌓아 두고, 수집기에 못 닿으면 디스크로 넘겨 재시작 후에도 유지합니다.
- `action.resumeRetryCount="-1"` — 포기하고 메시지를 버리는 대신 끝없이 재시도합니다.

재시작 전에 `rsyslogd -N1`로 설정을 점검하고(오류를 출력하거나, 깨끗하면 `End of config validation run. Bye.`), 끝에서 끝까지 시험합니다.

```
$ logger -p local3.warning -t soc-test "forwarding test 7f3a"
```

그리고 SIEM에서 `soc-test`와 `7f3a`를 검색합니다. facility `local3`, severity `warning`으로 도착하면 경로가 살아 있는 겁니다.

syslog-ng로는 이름 붙은 블록 — `source`, `destination`, `filter`, 그리고 이들을 잇는 `log` — 으로 같은 일을 합니다.

```
source s_local { system(); internal(); };
destination d_siem { syslog("siem-col-01.corp.example" transport("tls") port(6514)
                     tls(ca-file("/etc/syslog-ng/ca.pem") peer-verify(required-trusted))); };
filter f_auth { facility(auth, authpriv); };
log { source(s_local); filter(f_auth); destination(d_siem); };
```

- `source s_local { system(); internal(); };` — 플랫폼의 로컬 로그 소스와 syslog-ng 자신의 메시지를 모읍니다.
- `destination d_siem { syslog(... transport("tls") port(6514) tls(...)) };` — RFC 5424식 syslog를 TLS로 보내고, 상대에게 믿을 수 있는 인증서를 요구합니다.
- `filter f_auth { facility(auth, authpriv); };` — 이 facility들만 고릅니다.
- `log { ... };` — 이 소스에서, 이 필터를 거쳐, 이 목적지로 연결합니다.

**[보충] 분석가가 이 파일을 읽는 이유.** SIEM에 어떤 로그 종류가 없을 때, 이 경로 규칙을 보면 호스트가 애초에 보냈는지 알 수 있습니다. `*.*;auth,authpriv.none @192.0.2.10:514` 같은 규칙은 인증만 **빼고** 전부 보냅니다. 복사해 붙이다 흔히 생기는 사고인데, 중앙에서 SSH 무차별 대입이 안 보이게 됩니다. 침해가 의심되는 호스트에서 `/etc/rsyslog.d/`에 생긴 낯선 파일이 `authpriv`를 `/dev/null`로 보내거나 전달을 멈춘다면 방어 회피(**T1562.006**)입니다.

## Facility와 severity { #facility-severity }

### 모든 메시지에 붙는 두 라벨 { #labels }

모든 syslog 메시지에는 작은 숫자 두 개가 붙고, 그 뜻은 **RFC 5427**(그리고 RFC 5424의 표)에 정리돼 있습니다.

- **Facility** — 메시지가 시스템의 어느 부분에서 왔다고 말하는지. 프로그램 이름이 아니라 **하위 시스템** 라벨입니다. sshd와 sudo는 둘 다 `auth`/`authpriv`로 남깁니다.
- **Severity** — 얼마나 중요한지. 0(시스템 사용 불가)부터 7(디버그)까지. **숫자가 낮을수록 심각합니다.**

Facility 목록:

| 코드 | 키워드 | 뜻 |
| --- | --- | --- |
| 0 | `kern` | 커널 메시지 |
| 1 | `user` | 사용자 수준 메시지(프로그램이 정하지 않으면 기본값) |
| 2 | `mail` | 메일 시스템 |
| 3 | `daemon` | 자기 facility가 없는 시스템 데몬 |
| 4 | `auth` | 보안/권한 메시지 |
| 5 | `syslog` | syslog 데몬이 스스로 만든 메시지 |
| 6 | `lpr` | 라인 프린터 하위 시스템 |
| 7 | `news` | 네트워크 뉴스 하위 시스템 |
| 8 | `uucp` | UUCP 하위 시스템 |
| 9 | `cron` | 시계 데몬(cron) |
| 10 | `authpriv` | 비공개 보안/권한 메시지 |
| 11 | `ftp` | FTP 데몬 |
| 12 | `ntp` | NTP 하위 시스템 |
| 13 | — | 로그 감사(RFC 5424) |
| 14 | — | 로그 경고(RFC 5424) |
| 15 | — | 시계 데몬(두 번째 자리) |
| 16–23 | `local0`–`local7` | 자유롭게 쓰는 로컬용 |

Severity 목록:

| 코드 | 키워드 | 뜻 |
| --- | --- | --- |
| 0 | `emerg` | 시스템을 쓸 수 없음 |
| 1 | `alert` | 즉시 조치 필요 |
| 2 | `crit` | 치명적 상태 |
| 3 | `err` | 오류 |
| 4 | `warning` | 경고 |
| 5 | `notice` | 정상이지만 눈여겨볼 일 |
| 6 | `info` | 정보 |
| 7 | `debug` | 디버그 |

12~15번은 구현마다 다릅니다. RFC는 13을 "로그 감사", 14를 "로그 경고"로 적지만, 어떤 시스템은 13을 `security`, 14를 `console`이라 부르고, Linux 도구에는 12~15번 키워드가 아예 없는 경우가 많습니다. 13이나 14의 이름을 두고 도구들이 엇갈리면 숫자를 믿으세요.

`auth`와 `authpriv`가 나뉜 이유는, 예전에 `auth` 메시지는 더 많은 사용자가 읽을 수 있었기 때문입니다. 그래서 민감한 내용(어느 계정에 비밀번호를 시도했는지 등)은 root만 읽을 수 있는 파일에 쓰는 `authpriv`로 갑니다. 요즘 Linux에서 sshd는 기본으로 `authpriv`에 남기고, Debian/Ubuntu는 둘 다 `auth.log`에, Red Hat 계열은 authpriv를 `/var/log/secure`에 씁니다.

### 우선순위: 숫자 둘을 하나로 { #pri }

네트워크에서는 facility와 severity가 <strong>우선순위(PRI)</strong>라는 숫자 하나로 합쳐져서, 메시지 맨 앞 꺾쇠괄호 안에 들어갑니다.

```
PRI = facility × 8 + severity
```

8을 곱하는 이유는 severity가 0~7뿐이라 맨 아래 3비트에 딱 들어가고 facility와 겹치지 않기 때문입니다. 8진법 두 자리 숫자처럼 생각하면 됩니다. facility가 "십의 자리", severity가 "일의 자리"죠.

풀 때는 8로 나눕니다. **몫이 facility**, **나머지가 severity**입니다. 셸에게 시킬 수도 있습니다.

```
$ p=86; echo "facility=$((p / 8)) severity=$((p % 8))"
facility=10 severity=6
```

- `p=86` — PRI 값을 셸 변수에 담습니다.
- `$((p / 8))` — 셸 정수 계산: 86 ÷ 8 = 10(소수점 버림).
- `$((p % 8))` — `%`는 나머지: 86 − 80 = 6.
- facility 10은 `authpriv`, severity 6은 `info` → `authpriv.info`, 전형적인 sshd 메시지입니다.

머릿속으로 할 수 있어야 하는 예들입니다.

| PRI | ÷ 8 | 나머지 | 뜻 | 흔한 출처 |
| --- | --- | --- | --- | --- |
| `<0>` | 0 | 0 | `kern.emerg` | 커널이 시스템을 쓸 수 없다고 함 — 가장 심각한 값 |
| `<13>` | 1 | 5 | `user.notice` | `-p` 없이 쓴 `logger`의 기본값 |
| `<38>` | 4 | 6 | `auth.info` | 인증 관련 정보 메시지 |
| `<86>` | 10 | 6 | `authpriv.info` | sshd 로그인 성공/실패 메시지 |
| `<164>` | 20 | 4 | `local4.warning` | `local4`로 남기도록 설정한 방화벽 |
| `<191>` | 23 | 7 | `local7.debug` | 가능한 가장 큰 PRI: 가장 덜 중요한 조합 |

반대로 해 보면, `cron.err` = 9 × 8 + 3 = **75**, 즉 `<75>`입니다.

### Facility를 곧이곧대로 믿지 말 것 { #facility-trust }

Facility 목록은 1980년대 Unix 장비의 하위 시스템에 맞춰 만들었습니다. 웹 서버, 데이터베이스, EDR 에이전트, VPN 장비용 facility는 없습니다. 그래서 실제로는:

- 응용 프로그램은 `user`, `daemon`, 아니면 `local0`–`local7` 중 하나를 고릅니다.
- 네트워크·보안 장비는 관리자가 고르게 하고, 흔히 장비 종류별로 `local0`–`local7`을 씁니다(예: 방화벽은 전부 `local4`, 스위치는 전부 `local6`).
- 어떤 프로그램은 하는 일과 안 맞는 "공식" facility를 씁니다.

그러니 받는 쪽은 소스마다 각 facility가 무슨 뜻인지 **알려 줘야** 합니다. SIEM 엔지니어가 관리하는 대응표죠. 분석가라면 메시지가 `auth`/`authpriv`가 아니라는 이유만으로 "보안과 상관없다"고 결론 내리면 안 됩니다. 그리고 `logger`에서 봤듯이, facility는 쓴 쪽이 고른 값일 뿐입니다.

Severity도 비슷하게 개발자의 의견입니다. SSH 비밀번호 실패는 `warning`이 아니라 `info`입니다. SIEM 라이선스를 아끼려고 `warning` 아래를 다 버리면, 가장 필요한 인증 로그를 버리게 됩니다. severity만으로 거르지 말고 소스와 내용으로 거릅니다.

### 데몬이 이 값을 쓰는 방법 { #routing }

호스트에서 데몬은 facility와 severity를 규칙(앞에서 본 선택자)에 맞춰 보고, 각 메시지를 어느 **파일**에 쓰고 어느 **수집기**에 보낼지 정합니다. 예를 들어 커널 메시지는 전부 `/var/log/kern.log`로, auth 메시지는 전부 `/var/log/auth.log`로 보내되 `auth.debug`만은 따로 디버그 파일로, 그리고 `warning` 이상은 SIEM에도 전달 — 이런 식입니다. 파일 이름을 적는 그 자리에 원격 주소를 적으면 전달이 켜집니다. 다음 페이지에서 이 길을 따라 `/var/log` 아래 실제 파일들과 systemd 저널로 들어갑니다.

## SOC에서 써먹기 { #soc-use }

새 Linux 소스를 붙이거나, Linux 알림이 들어오면 이렇게 확인합니다.

1. **어느 syslog?** 호스트에 어떤 데몬이 있나(아니면 journald뿐인가)? 수집기까지 어떤 전송 방식과 포트를 쓰나? 어떤 형식(3164 또는 5424)으로 도착하나?
2. **시각.** 이벤트에 연도와 시간대가 있나? SIEM에 그 소스의 시간대가 설정돼 있나? 아는 이벤트 하나(예: 내 SSH 로그인)를 호스트와 SIEM에서 비교해 봅니다.
3. **빠짐없이 오는가.** `auth`/`authpriv`가 실제로 전달되나? "호스트가 보내기를 멈춤" 경보가 있나? 이 경로에서 UDP 유실이 생길 수 있나?
4. **파싱.** 핵심 프로그램(sshd, sudo, su, cron, 웹 서버)의 칸이 뽑히나? 지금 버전의 문구로 파서를 시험해 봤나?
5. **믿을 수 있나.** 증거가 syslog 한 줄뿐인가, 아니면 저널의 신뢰 칸, auditd, EDR, 네트워크 로그로 교차 확인할 수 있나?

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    syslog 헤더, facility와 severity 표, PRI 공식, "syslog"의 세 가지 뜻은 바뀌지 않았고 여전히 어디에나 있습니다. Linux 서버, 방화벽, 스위치, 로드 밸런서, 스토리지, 대부분의 보안 장비가 syslog를 보냅니다. SIEM 앞의 표준 수집기는 여전히 rsyslog와 syslog-ng이고, 자유 문장 메시지와 프로그램별 파서는 지금도 일상입니다.

!!! info "[변경됨] 바뀐 점"
    - **저널 우선 배포판.** Debian 12 이후는 기본으로 syslog 데몬을 설치하지 않습니다. rsyslog를 더하거나 저널에서 전달하지 않으면 로그는 systemd 저널에만 있습니다. 다른 배포판은 여전히 journald와 rsyslog를 함께 넣지만, `/var/log/auth.log`가 있다고 가정하지 마세요.
    - **syslog-ng와 AxoSyslog.** syslog-ng는 One Identity 아래에서 계속되고, 2023년부터 원래 개발자의 포크 AxoSyslog가 보안 데이터 파이프라인을 겨냥한 또 하나의 갈래가 됐습니다.
    - **TLS 지침 갱신.** RFC 9662(2024)가 TLS·DTLS syslog의 필수 암호 스위트를 요즘 TLS 관행에 맞게 갱신했습니다. 민감한 로그는 인증서 확인을 켠 6514 TLS가 기본 기대치입니다.
    - **파이프라인과 스키마.** 많은 SOC가 소스와 SIEM 사이에 파이프라인 층(syslog 수집기, Kafka, 업체의 "데이터 파이프라인" 제품)을 두고, Elastic Common Schema나 OCSF 같은 공통 스키마로 정규화합니다. 그래도 파서가 틀렸을 때는 원본 syslog 줄이 중요합니다.
    - **원시 syslog 대신 에이전트.** 서버에서는 저널이나 파일을 직접 읽는 SIEM·EDR 에이전트(또는 OpenTelemetry 수집기)가 데몬 대 데몬 syslog를 점점 대신하고 있습니다. 장비 쪽은 여전히 원시 syslog가 표준입니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **보안 로그를 믿을 수 없는 네트워크 너머로 평문 UDP 514로 보내지 마세요.** 사라지고, 읽히고, 위조될 수 있습니다. 인증서 확인을 켠 TLS over TCP와 디스크 큐를 씁니다.
    - **facility, severity, 호스트 이름, 프로그램 이름을 증거로 믿지 마세요.** 보낸 쪽이 고른 글자입니다. 다른 소스로 확인합니다.
    - **양을 줄이려고 Linux 로그를 severity로 거르지 마세요.** 인증 이벤트는 `info`입니다. 소스와 내용으로 거릅니다.
    - **작년에 되던 정규식이 아직 된다고 가정하지 마세요.** 프로그램 업그레이드가 문구를 바꿉니다. 파서를 시험하고, 파싱 비율이 떨어지는 소스에 경보를 겁니다.
    - **서버를 로컬 시각 + 3164 시각으로 두지 마세요.** UTC나 오프셋이 붙은 RFC 3339 전체 시각을 쓰고, 바꿀 수 없는 건 SIEM에 소스별 시간대를 설정합니다.
    - **`/var/log/*.log`가 있다고 믿지 마세요.** 저널만 있는 호스트에서는 파일을 따라 읽는 수집기가 아무것도 보내지 않고, 조용한 소스를 감시하지 않으면 아무도 알려 주지 않습니다.

## 확인 문제 { #quiz }

### 문제 1

동료가 "우리 Linux 서버는 괜찮아요, syslog로 SIEM에 보내거든요"라고 말합니다. 이 문장의 "syslog"가 뜻할 수 있는 세 가지를 적고, 각각에 대해 로그가 정말 빠짐없고 믿을 만한지 확인하려면 어떤 질문을 하겠는지 적으세요.

??? success "정답과 해설"
    **세 가지 뜻:**

    1. **형식** — 메시지가 어떻게 생겼나. *질문:* 연도와 시간대가 없는 RFC 3164 줄인가, RFC 5424/RFC 3339 시각인가? SIEM에 소스별 시간대가 맞게 설정돼 있나? sshd, sudo 같은 핵심 프로그램의 칸이 실제로 파싱되나?
    2. **데몬** — 각 서버의 프로그램. *질문:* 어떤 데몬이 깔려 있나(rsyslog, syslog-ng — 아니면 기본 설치 Debian 12처럼 journald만 있어서 아무것도 없나)? 규칙이 `auth`/`authpriv`를 전달하나, 아니면 `*.*;auth,authpriv.none` 같은 규칙이 빼 버리나? 수집기가 죽었을 때를 위한 디스크 큐가 있나?
    3. **네트워크 프로토콜** — 메시지가 어떻게 가나. *질문:* UDP 514인가, TCP인가, 인증서 확인을 켠 6514 TLS인가? UDP라면 메시지가 조용히 사라질 수 있고, 수집기에 닿는 누구나 위조할 수 있고, 전부 평문으로 지나갑니다.

    셋 모두에 덧붙일 좋은 질문: 서버가 보내기를 멈추면 경보가 울리나?

### 문제 2

다음 PRI 값을 facility와 severity로 풀고, 각각 어떤 소스가 보낼 법한지 말하세요: `<86>`, `<164>`, `<13>`, `<3>`. 그리고 `cron.err`의 PRI를 적으세요.

??? success "정답과 해설"
    8로 나눕니다. 몫 = facility, 나머지 = severity.

    - `<86>` → 86 ÷ 8 = 10, 나머지 6 → **`authpriv.info`**. sshd 로그인 성공/실패 메시지가 전형적입니다.
    - `<164>` → 20, 나머지 4 → **`local4.warning`**. 로컬용 facility라, 관리자가 `local4`로 남기도록 설정한 방화벽 같은 장비일 가능성이 큽니다. 정체는 소스 대응표를 봐야 압니다.
    - `<13>` → 1, 나머지 5 → **`user.notice`**. `-p` 없는 `logger`의 기본값, 또는 facility를 고르지 않은 프로그램. 보안 도구에서 왔다고 주장한다면 들여다볼 만합니다.
    - `<3>` → 0, 나머지 3 → **`kern.err`**. 커널 오류, 예를 들어 드라이버나 하드웨어 문제.
    - `cron.err` = 9 × 8 + 3 = **75**, `<75>`로 씁니다.

    facility와 severity는 보낸 쪽이 고른 라벨이라는 걸 기억하세요. `<86>`이 증명하는 건 보낸 쪽이 `authpriv.info`라고 주장했다는 것뿐입니다.

### 문제 3

`web-01`의 `/var/log/auth.log`에서 아래 줄들을 찾았는데, SIEM에는 지난 사흘간 이 호스트에서 비슷한 게 하나도 없습니다.

```
Nov 20 02:14:09 web-01 sshd[3170]: Accepted password for deploy from 198.51.100.61 port 50544 ssh2
Nov 20 02:14:09 web-01 sshd[3170]: pam_unix(sshd:session): session opened for user deploy(uid=1003) by (uid=0)
Nov 20 02:16:40 web-01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/vi /etc/rsyslog.d/50-default.conf
```

이 줄들이 무슨 뜻인지, SIEM 데이터가 없는 이유로 무엇이 의심되는지, 다음에 무엇을 확인할지 설명하세요.

??? success "정답과 해설"
    **줄의 뜻:**

    - 02:14:09 — sshd 프로세스 3170이 외부 IP `198.51.100.61`에서 온 `deploy` 계정의 **비밀번호** 로그온을 받아들였고, PAM이 `deploy`(uid 1003)의 세션을 열었습니다.
    - 02:16:40 — `deploy`가 **sudo**로 **root 권한으로** `vi`를 실행해 `/etc/rsyslog.d/50-default.conf`, 즉 rsyslog의 경로·전달 규칙 파일을 열었습니다. sudo 줄은 자기만의 key=value 비슷한 배치(`TTY=`, `PWD=`, `USER=`, `COMMAND=`)라 파싱하기 쉽고, 아주 값집니다.

    **SIEM이 빈 이유:** 새벽 2시, 외부에서 비밀번호로 로그인한 지 2분 만에 root로 rsyslog 규칙을 고친 건 **방어 회피**(**T1562.006**, Indicator Blocking)의 강한 신호입니다. 전달 줄이 지워졌거나 다른 곳으로 돌려져서 호스트가 보내기를 멈췄을 수 있습니다. 원래 있던 UDP 유실이나 파서 문제일 수도 있지만, 시점으로 보아 변조가 1순위 가설입니다. 로컬 파일에는 아직 이 줄들이 남아 있다는 점도 주목하세요. 공격자가 나중에 지울 수 있습니다(**T1070.002**).

    **다음 확인:**

    1. 지금 증거를 보존합니다. `/var/log/auth.log*`, 저널, `/etc/rsyslog.conf`와 `/etc/rsyslog.d/`(시각 정보 포함)를 호스트 밖으로 복사합니다.
    2. 현재 rsyslog 파일을 정상본(구성 관리, 백업, 다른 서버)과 비교합니다. 무엇이 바뀌었나?
    3. 같은 시간대의 저널(`journalctl`)과 auditd를 봅니다. 파일과 SIEM에 없는 것, 예를 들어 `logger` 사용이나 서비스 중지 흔적이 있을 수 있습니다.
    4. `198.51.100.61`과 `deploy`를 조사합니다. 다른 어디에 로그인했나, 이 계정에 비밀번호 로그인이 허용돼야 하나 — 그리고 자격 증명을 재설정합니다.
    5. "소스가 조용해짐" 경보를 만들거나 확인해서 다음 공백은 며칠이 아니라 몇 분 안에 알아채게 하고, 전달을 인증서 확인을 켠 TLS로 옮깁니다.

## 관련 레퍼런스 { #related }

- [Windows 로그](../windows-logging/index.md) — 비교 대상인 구조화된, 이벤트 ID 기반 방식
- [Linux 로그, 프로세스, 라이브 트리아지](../../../linux/logs-and-triage.md)
- [Linux 인증과 셸 히스토리](../../../linux/auth-and-history.md)
- [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md) — 네트워크 쪽에서 본 SSH 악용과 `auth.log`
- [DHCP](../other-protocols/dhcp.md) — 로그 줄의 IP를 장비로 바꾸기
