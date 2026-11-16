---
title: Arkime로 PCAP 분석하기 — 초보자 가이드
tags:
  - tool
  - network
  - arkime
  - pcap
  - training
---

# Arkime로 PCAP 분석하기 — 초보자 가이드 { #offline-pcap-guide }

!!! abstract "이 페이지는"
    Zeek로 풀던 PCAP 침해사고 질문을 Arkime로 푸는 방법입니다. PCAP을 넣고, 검색하고, 웹 화면에서 답을 읽습니다. Arkime는 PCAP을 **세션(연결) 단위로 색인**하므로 `zeek-cut | grep | awk` 대신 **검색창 + 클릭**으로 같은 답에 도달합니다. 필드 이름과 `capture` 옵션은 Arkime 소스 코드(`capture/parsers/*.c`, `capture/main.c`)에서 확인했습니다.

따라 하기 예제는 Zeek로 먼저 풀었던 [PCAP 실습 06](../../blueteam/investigations/pcap-lab-06-invoice-macro-c2.md)과 [PCAP 실습 07](../../blueteam/investigations/pcap-lab-07-autoit-downloader-multi-c2.md)을 다시 풉니다.

## Arkime와 Zeek 비교 { #vs-zeek }

| 비교 | Zeek | Arkime |
|---|---|---|
| 결과물 | 프로토콜별 텍스트 로그 (`conn.log`, `http.log` …) | 세션 색인 + 원본 패킷, 웹 화면 |
| 찾는 방법 | `zeek-cut`, `grep`, `awk` | 검색창에 검색식 + 클릭 |
| 단위 | 로그마다 다름 (연결, 요청, 파일) | 연결 하나 = 세션 하나, 그 안에 HTTP·DNS·TLS 필드가 들어 있음 |
| 패킷 보기 | 없음 (tshark/Wireshark로) | 세션 상세에서 바로 봄 |
| 집계 | <code>sort &#124; uniq -c</code> | **SPI View**가 필드별 값과 개수를 바로 보여 줌 |
| 잘하는 것 | 파일 추출, 해시, 정확한 필드, 스크립트 | 많은 세션을 빠르게 훑기, 피벗하기, 원본 패킷 확인 |

실무 순서는 보통 이렇습니다. Arkime로 **전체를 훑어 수상한 세션을 찾고**, 더 자세히 봐야 하는 세션은 **PCAP으로 내보내 Zeek·tshark**로 봅니다.

## 0단계 — PCAP을 Arkime에 넣기 { #import }

Arkime가 이미 설치돼 있다면 **PCAP을 색인하고 시간 범위를 맞추는 것**이 준비의 전부입니다. 경로는 기본 설치 위치(`/opt/arkime`) 기준입니다.

### 1. 서비스가 살아 있는지 확인 { #services }

```bash
systemctl status arkimeviewer arkimecapture --no-pager   # 웹 화면(viewer)과 수집기(capture)
curl -s http://localhost:9200/_cluster/health?pretty     # 색인 저장소(OpenSearch/Elasticsearch)
```

- `arkimeviewer`가 웹 화면입니다. 브라우저로 `http://<분석서버>:8005`에 접속해 로그인합니다.
- `status`가 `green`이나 `yellow`면 색인 저장소는 정상입니다. 단일 서버 랩은 보통 `yellow`입니다.
- 서비스 이름과 포트는 랩 구성에 따라 다를 수 있습니다.

### 2. PCAP 색인하기 { #capture }

```bash
sudo /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini \
     -r ~/Investigation_7/Phase1_PCAP_7.pcap -t lab7 --copy
```

| 옵션 | 뜻 |
|---|---|
| `-c` | 설정 파일. 기본값이 `/opt/arkime/etc/config.ini`라서 보통 생략 가능 |
| `-r <파일>` | 오프라인 PCAP 파일을 읽음 |
| `-R <폴더>` | 폴더 안의 `*.pcap`을 모두 읽음 |
| `-t <태그>` | 이 PCAP의 모든 세션에 태그를 붙임. 나중에 `tags == lab7`로 이 실습만 골라 봅니다 |
| `--copy` | PCAP을 Arkime 저장 폴더(`pcapDir`)로 **복사**. 없으면 원본 위치를 기억하므로, 원본을 옮기거나 지우면 패킷을 못 봅니다 |
| `-n <노드>` | 노드 이름. viewer와 **같아야** 패킷을 열 수 있음(기본값은 호스트 이름이라 보통 생략) |
| `--flush` | 여러 파일을 읽을 때 파일마다 세션을 끊어 줌 |
| `--dryrun` | 아무것도 저장하지 않고 시험만 함 |

명령이 끝나면 1분 정도 기다렸다가 화면을 새로 고칩니다. 상단 **Files** 탭에 PCAP 이름이 보이면 색인이 끝난 것입니다.

### 3. 가장 흔한 함정: 시간 범위 { #time-range }

Arkime는 패킷의 **원래 시각**으로 색인합니다. 실습 PCAP은 2017~2018년 트래픽이라, 화면 기본값인 "최근 1시간"으로는 **세션이 하나도 안 나옵니다**.

1. 검색창 옆 시간 선택에서 **All**을 고릅니다. 또는 Start/End에 캡처 시각을 직접 넣습니다.
2. 검색창에 `tags == lab7`을 넣고 Search를 누릅니다.
3. 세션이 보이면 준비 끝입니다.

화면 시각은 브라우저의 현지 시간대로 표시될 수 있습니다. 보고서는 UTC로 쓰므로, 사용자 설정(Settings)에서 시간대를 **UTC**로 바꾸어 두는 것이 안전합니다.

## 화면 둘러보기와 검색 문법 기초 { #ui }

분석에 쓰는 화면은 다섯 개입니다. 모두 같은 검색창과 시간 범위를 공유하므로, 한 화면에서 걸러 둔 조건이 다른 화면에도 그대로 적용됩니다.

| 화면 | 무엇을 보여 주나 | Zeek로 치면 |
|---|---|---|
| **Sessions** | 세션 목록(시각, 출발·목적 IP/포트, 패킷 수, 바이트, 요약). 줄 앞의 `+`를 누르면 **세션 상세** | `conn.log` + 해당 프로토콜 로그 |
| **SPI View** | 필드별 **값과 개수** (예: User-Agent별 세션 수) | <code>zeek-cut 필드 &#124; sort &#124; uniq -c</code> |
| **SPI Graph** | 한 필드의 값마다 **시간에 따른 그래프** | 비콘 간격 계산 |
| **Connections** | 출발지 → 목적지를 선으로 잇는 그림 | 내부 ↔ 외부 관계 파악 |
| **Help → Fields** | 이 버전에서 쓸 수 있는 **모든 필드 이름** | 로그 헤더(`#fields`) |

### 세션 상세 읽는 법 { #session-detail }

- 위쪽에는 프로토콜별 필드가 나옵니다(예: HTTP의 Host, URI, User-Agent, 응답 코드, 본문 MD5).
- 아래쪽에는 **실제 패킷 내용**이 나옵니다. 요청과 응답이 색으로 구분됩니다. Wireshark의 Follow Stream과 비슷합니다.
- 필드 값을 누르면 메뉴가 뜨고, **and** / **and not**을 고르면 그 값이 검색창에 자동으로 추가됩니다. 검색식을 직접 치지 않아도 됩니다.

### 검색 문법 기초 { #search-basics }

검색식은 `필드 연산자 값` 모양입니다.

```text
ip.src == 10.192.1.157                       # 같다
port.dst != 443                              # 다르다
ip.src == 10.0.0.0/8                         # IP 대역(CIDR)
host.http == *.yahoo.com                     # * = 아무 글자
http.user-agent == "Mozilla/4.08 (Charon; Inferno)"   # 띄어쓰기·괄호가 있으면 큰따옴표
port.dst == [465,587,25]                     # [ ] = 여러 값 중 하나
http.uri == /forum\.php/                     # / / = 정규식
ip.src == 10.192.1.157 && protocols == http  # && = 그리고
protocols == dns || protocols == dhcp        # || = 또는
!(port.dst == 443)                           # ! = 아닌 것
```

- 여러 조건을 섞을 때는 괄호로 묶습니다. 예: `tags == lab7 && (port.dst == 80 || port.dst == 443)`.
- 필드 이름이 기억나지 않으면 검색창에 몇 글자만 쳐도 **자동완성 목록**이 나옵니다.
- 모든 검색식 앞에 `tags == lab7 &&`를 붙이면, 여러 실습을 넣어 둔 Arkime에서도 이 실습만 봅니다. 아래 예시에서는 짧게 쓰려고 생략합니다.

## 질문별 방법 { #by-question }

각 항목은 **검색식 → 볼 화면 → 읽는 법** 순서입니다.

### 1. 감염 후보 호스트 찾기 { #infected-host }

```text
ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16
```

**SPI View → General → Src IP**를 엽니다. 내부 IP별 세션 수가 나옵니다. 연결을 많이 시작한 내부 IP가 첫 후보입니다. (Zeek: `zeek-cut id.orig_h < conn.log | sort | uniq -c`)

### 2. IP, MAC, 호스트 이름 (DHCP) { #dhcp }

```text
protocols == dhcp
```

- **SPI View → DHCP**에서 `dhcp.host`(호스트 이름), `dhcp.mac`(클라이언트 MAC), `dhcp.classId`(벤더 클래스)를 봅니다.
- 세션을 하나 열면 IP, MAC, 이름이 한곳에 보입니다.
- 같은 IP의 MAC을 다른 방법으로도 확인하려면: `ip.src == <감염IP>` 후 SPI View의 `mac.src`.

### 3. 사용자 계정, 도메인, DC (Kerberos) { #kerberos }

```text
protocols == krb5
```

| 필드 | 무엇을 보나 |
|---|---|
| `krb5.cname` | 계정 이름. `$`로 끝나면 컴퓨터 계정, 없으면 사람 계정 |
| `krb5.realm` | AD 도메인 이름 |
| `krb5.sname` | 요청한 서비스. `ldap/<이름>`, `cifs/<이름>`의 `<이름>`이 DC |
| `ip.dst` | Kerberos를 받는 서버 = DC의 IP |

DNS로도 DC 이름을 확인할 수 있습니다: `host.dns == _ldap._tcp.dc._msdcs.*`. **Kerberos 세션이 하나도 없으면** 도메인에 속하지 않은 PC일 가능성이 큽니다(실습 07).

### 4. 운영체제 { #os }

| 단서 | 검색식 / 필드 | 읽는 법 |
|---|---|---|
| User-Agent | `ip.src == <감염IP> && protocols == http` → SPI View `http.user-agent` | `Windows NT 6.1` = 윈도우 7, `NT 10.0` = 윈도우 10/11 |
| DHCP 벤더 클래스 | `dhcp.classId` | `MSFT 5.0` = 윈도우 |
| TTL | `ip.src == <감염IP>` → SPI View `ttl.src` | 128 = 윈도우, 64 = 리눅스·맥·안드로이드 |

Zeek에서는 TTL과 벤더 클래스를 보려면 tshark가 필요했지만, Arkime는 둘 다 색인합니다.

### 5. 다운로드된 파일, URL, 크기 { #downloads }

```text
http.bodymagic == application/x-dosexec       # EXE/DLL
http.bodymagic == application/msword          # 예전 .doc
http.bodymagic == *zip*                       # zip, docx/xlsx(내부가 zip)
```

- `http.bodymagic`은 본문 **내용(매직 바이트)**으로 알아낸 파일 종류입니다. Zeek의 `mime_type`과 같은 역할입니다.
- 전체 URL = 세션 상세의 `host.http` + `http.uri`.
- **크기**: 세션 상세 아래 패킷 영역의 응답 헤더에서 `Content-Length`를 읽습니다. 목록의 바이트 수(`databytes.dst`)는 헤더까지 포함한 값이라 파일 크기와 조금 다릅니다.

### 6. 해시 { #hashes }

- 세션 상세의 HTTP 부분에 본문 해시 `http.md5`가 나옵니다. `http.sha256`은 설정(`supportSha256=true`)이 켜져 있을 때만 있습니다.
- 해시로 거꾸로 찾기: `http.md5 == <md5>` → 같은 파일을 받은 모든 세션.
- **주의**: 캡처에서 패킷이 빠지면 이 해시는 진짜 파일의 해시가 아닙니다. 실습 07처럼 손실이 있을 때는 아래 [한계와 함정](#limits)을 보세요.

### 7. 브라우저가 받았나, 프로그램이 받았나 { #user-agent }

```text
ip.src == <감염IP> && protocols == http
```

**SPI View → HTTP**에서 `http.user-agent`의 값과 개수를 봅니다. 값을 눌러 **and**를 고르면 그 User-Agent가 어디로 갔는지 Sessions에서 바로 보입니다. `AutoIt`, `Charon; Inferno`, 오래된 IE 7 같은 값은 브라우저가 아닙니다. User-Agent가 아예 없는 요청은 세션 상세 패킷 영역의 요청 헤더에서 확인합니다.

### 8. 공인 IP { #public-ip }

```text
host.http == [api.ipify.org, icanhazip.com, checkip.amazonaws.com, ipinfo.io]
```

세션 상세를 열고 아래 패킷 영역에서 **응답 본문**을 읽습니다. 본문에 나온 IP가 공인 IP입니다. Zeek처럼 fuid로 파일을 찾을 필요가 없습니다.

### 9. C2와 비콘 { #c2 }

```text
ip.src == <감염IP> && http.method == POST
```

1. **SPI View → `host.http`**: POST를 받은 서버와 횟수.
2. **Sessions**를 시작 시각으로 정렬: 같은 서버에 일정한 간격으로 가는지 봅니다.
3. **SPI Graph**에서 필드를 `host.http`로 고르면, 서버별 접속이 시간 위에 막대로 나타납니다. 막대가 일정한 간격으로 찍히면 비콘입니다.

### 10. HTTPS 목적지와 인증서 { #tls }

```text
ip.src == <감염IP> && protocols == tls
```

- HTTPS의 서버 이름(SNI)도 `host.http` 필드에 들어갑니다. SPI View에서 `host.http`를 보면 접속한 HTTPS 사이트 목록이 나옵니다.
- 세션 상세의 인증서 부분에서 `cert.issuer.cn`(발급자), `cert.subject.cn`, `cert.notafter`(만료일)를 봅니다. 만료일이 캡처 시각보다 앞이면 **만료된 인증서**입니다.
- `tls.ja3`는 TLS 클라이언트 지문입니다. 같은 값이 여러 수상한 서버에 나오면 같은 프로그램일 가능성이 있습니다.

### 11. 실패한 연결 (Zeek의 S0, REJ) { #failed }

```text
ip.src == <감염IP> && tcpflags.syn-ack == 0       # 핸드셰이크가 한 번도 성공 못 함
ip.src == <감염IP> && tcpflags.rst > 0            # 연결이 리셋됨 (거부 포함)
```

SPI View에서 `ip.dst`와 `port.dst`를 보면 같은 곳에 몇 번이나 실패했는지 한눈에 보입니다. Arkime에는 Zeek의 `conn_state` 같은 한 칸이 없으므로 TCP 플래그로 대신합니다.

### 12. 메일(SMTP) { #smtp }

```text
ip.src == <감염IP> && port.dst == [25,465,587]
```

- **25 / 587 평문 SMTP**면 `email.src`(보낸 사람), `email.dst`(받는 사람), `email.subject`, `email.fn`(첨부 파일 이름)까지 보입니다.
- **465는 처음부터 TLS**라 내용은 안 보입니다. 보낸 양은 목록의 `databytes.src`로 봅니다.

## 따라 하기: 실습 06과 07을 Arkime로 { #worked }

아래 "기대 결과"는 Zeek로 확인한 답입니다. Arkime에서도 같은 값이 나와야 합니다. 다르게 나오면 시간 범위(All)와 태그부터 확인하세요. 검색식마다 앞에 `tags == lab6 &&`(또는 `lab7`)을 붙입니다.

### 실습 06 — 청구서 Word 매크로 { #lab-06 }

색인: `sudo /opt/arkime/bin/capture -r ~/Investigation_6/Phase1_PCAP_6.pcap -t lab6 --copy`

| # | 검색식 | 볼 곳 | 기대 결과 |
|---|---|---|---|
| 1 | `ip.src == 172.16.0.0/12` | SPI View `ip.src` | 내부 호스트는 172.16.1.125 하나 |
| 2 | `protocols == dhcp` | SPI View `dhcp.host`, `dhcp.mac` | Anatoliy-PC, b8:97:fa:74:de:c0 |
| 3 | `protocols == krb5` | SPI View `krb5.cname`, `krb5.realm`, `krb5.sname`, `ip.dst` | anatoliy.demchuk, MARICHEIKA.NET, DC 172.16.1.3 (Maricheika-DC) |
| 4 | `http.bodymagic == application/msword` | 세션 상세 | 2018-10-01 18:38:00 UTC, `pitchbocaraton.com/?82a1=APYBKsCs3LUw`, IE 11 User-Agent, `http.md5` = 41a3101af94fca79bbdb0db2a52994c0 |
| 5 | `host.http == api.ipify.org` | 세션 상세 → 응답 본문 | 31.44.188.95 |
| 6 | `http.method == POST` | SPI View `host.http`, SPI Graph | perranrowsin.com으로 `/4/forum.php` 약 2분 간격, `/mlu/forum.php`, `/d2/about.php` |
| 7 | `ip.src == 172.16.1.125 && protocols == http` | SPI View `http.user-agent` | 문서는 `WOW64` IE, C2는 `Win64; x64`와 `MSIE 7.0` → 서로 다른 프로그램 |

Arkime만으로 안 되는 것이 두 가지 있습니다.

- **매크로 확인(7번)**: 문서 파일을 꺼내서 `strings`나 `olevba`로 봐야 합니다.
- **서브넷 마스크와 게이트웨이(9번)**: Arkime의 DHCP 필드에는 없습니다. tshark 한 줄(`-e dhcp.option.subnet_mask -e dhcp.option.router`)이 가장 쉽습니다.

### 실습 07 — AutoIt 다운로더와 여러 C2 { #lab-07 }

색인: `sudo /opt/arkime/bin/capture -r ~/Investigation_7/Phase1_PCAP_7.pcap -t lab7 --copy`

| # | 검색식 | 볼 곳 | 기대 결과 |
|---|---|---|---|
| 1 | `ip.src == 10.0.0.0/8` | SPI View `ip.src` | 내부 호스트는 10.192.1.157 하나 |
| 2 | `protocols == dhcp` | SPI View `dhcp.host`, `dhcp.mac`, `dhcp.classId` | WIN-D5243B, 50:46:5d:d5:24:3b, `MSFT 5.0` |
| 3 | `protocols == krb5` | Sessions | **0개** → 도메인 없는 단독 PC |
| 4 | `ip.src == 10.192.1.157` | SPI View `ttl.src`, `http.user-agent` | TTL 128, `Windows NT 6.1` → 윈도우 7 |
| 5 | `host.http == api.bing.com` | Sessions → `http.uri` | `query=m`, `ma` … `mail.yahoo.com`: 사용자가 Yahoo 메일 주소를 입력 |
| 6 | `http.bodymagic == application/x-dosexec` | 세션 상세 | `jjjj.exe`(lucrecianos.com.ar, User-Agent 없음), `zugu.exe`(virtualsmsonline.site, `AutoIt`). 응답 `Content-Length` 3,061,200 / 5,895,226 |
| 7 | `host.http == icanhazip.com` | 응답 본문 | 공인 IP 확인 (User-Agent `AutoIt`) |
| 8 | `http.method == POST` | SPI View `host.http`, `http.user-agent` | tcoolonline.mobi (`Charon; Inferno`), harddomainname.biz (`MSIE 7.0`) |
| 9 | `protocols == tls` | SPI View `host.http`, 세션 상세 인증서 | idea.bsit.pk — `cert.notafter`가 캡처보다 앞(만료) |
| 10 | `tcpflags.syn-ack == 0` | SPI View `ip.dst`, `port.dst` | 213.183.58.34:5552에 수백 번 실패 |
| 11 | `port.dst == 465` | Sessions `databytes.src` | smtp.aol.com(152.163.0.69)으로 수 KB 전송, 내용은 암호화 |

6번에서 Arkime가 `http.md5`를 보여 주더라도 **그 값을 답으로 쓰면 안 됩니다.** 이 캡처는 두 파일 모두 일부 바이트가 빠져 있어서, 본 바이트만으로 만든 해시는 진짜 파일의 해시와 다릅니다(추정: Arkime는 빈틈을 표시하지 않음).

## 한계와 함정, Zeek·tshark로 넘기기 { #limits }

Arkime는 **찾기**에 강하고, 파일을 꺼내거나 정확히 재는 일은 Zeek·tshark가 더 낫습니다. 두 도구를 이어 쓰는 방법은 **걸러 둔 세션을 PCAP으로 내보내기**입니다.

### Arkime만으로 부족한 것 { #cannot }

| 하고 싶은 일 | Arkime에서는 | 대신 |
|---|---|---|
| 파일 꺼내기, 매크로 보기 | 본문을 패킷 영역에서 볼 수는 있지만 분석 도구가 아님 | PCAP 내보내기 → Zeek `extract-all-files` 또는 `tshark --export-objects` → `strings`, `olevba` |
| 캡처 손실 확인 | 빠진 바이트를 따로 표시하지 않음 | Zeek `files.log`의 `missing_bytes`, tshark `tcp.analysis.lost_segment` |
| DHCP 마스크·게이트웨이 | 색인 필드에 없음 | tshark `dhcp.option.subnet_mask`, `dhcp.option.router` |
| 연결 상태(S0, REJ) | 한 칸으로 안 나옴 | `tcpflags.syn-ack == 0`, `tcpflags.rst > 0`로 대신, 또는 Zeek `conn_state` |
| 간격 계산(초 단위) | SPI Graph로 눈으로 봄 | Zeek `ts` + `awk` 빼기 |

### PCAP 내보내기 { #export }

1. Sessions에서 검색식으로 필요한 세션만 남깁니다. 예: `tags == lab7 && http.bodymagic == application/x-dosexec`.
2. 세션 목록 위의 **액션 메뉴**에서 **Export PCAP**을 고릅니다. 검색에 맞는 세션 전체(matching)를 고르고 파일 이름을 정합니다.
3. 받은 작은 PCAP을 평소처럼 분석합니다.

```bash
mkdir exe_check && cd exe_check
zeek -C -r ../exported.pcap local frameworks/files/extract-all-files 2>/dev/null
zeek-cut fuid mime_type seen_bytes total_bytes missing_bytes md5 sha1 < files.log
```

같은 메뉴의 **Export CSV**는 세션 목록(보이는 열)을 표로 내보냅니다. 보고서의 타임라인을 만들 때 씁니다.

### 초보자가 자주 빠지는 함정 { #traps }

- **세션이 하나도 안 보인다**: 시간 범위가 "최근 1시간"입니다. **All**로 바꿉니다.
- **세션은 보이는데 패킷이 안 열린다**: `--copy` 없이 넣은 원본 PCAP을 옮겼거나, capture와 viewer의 노드 이름(`-n`)이 다릅니다.
- **개수가 두 배로 나온다**: 같은 PCAP을 두 번 넣었을 가능성이 큽니다. 태그로 나눠 보거나 한 번만 넣습니다.
- **다른 실습 세션이 섞인다**: 모든 검색에 `tags == labN &&`를 붙입니다.
- **시각이 보고서와 안 맞는다**: 화면이 브라우저 현지 시간입니다. Settings에서 UTC로 바꿉니다.
- **필드 이름이 안 맞는다**: 버전마다 다를 수 있습니다. **Help → Fields**에서 확인하거나 검색창 자동완성을 씁니다.

## 검색식 치트시트 { #cheat-sheet }

앞에 `tags == labN &&`를 붙여 씁니다. `<감염IP>`는 실제 IP로 바꿉니다.

| 목적 | 검색식 | 볼 필드 (SPI View) |
|---|---|---|
| 내부 호스트 | <code>ip.src == 10.0.0.0/8 &#124;&#124; ip.src == 172.16.0.0/12 &#124;&#124; ip.src == 192.168.0.0/16</code> | `ip.src` |
| IP·MAC·호스트 이름 | `protocols == dhcp` | `dhcp.host`, `dhcp.mac`, `dhcp.classId` |
| 계정·도메인·DC | `protocols == krb5` | `krb5.cname`, `krb5.realm`, `krb5.sname`, `ip.dst` |
| DC 이름 (DNS) | `host.dns == _ldap._tcp.dc._msdcs.*` | 세션 상세의 DNS 응답 |
| 운영체제 | `ip.src == <감염IP>` | `ttl.src`, `http.user-agent`, `dhcp.classId` |
| 실행 파일 다운로드 | `http.bodymagic == application/x-dosexec` | `host.http`, `http.uri`, `http.md5` |
| Word 문서 | `http.bodymagic == application/msword` | `host.http`, `http.uri` |
| 압축·Office 2007+ | `http.bodymagic == *zip*` | `host.http`, `http.uri` |
| 같은 파일 거꾸로 찾기 | `http.md5 == <md5>` | `ip.src`, `host.http` |
| User-Agent 비교 | `ip.src == <감염IP> && protocols == http` | `http.user-agent` |
| 특정 User-Agent | `http.user-agent == "AutoIt"` | `host.http`, `http.uri` |
| 공인 IP 확인 | `host.http == [api.ipify.org, icanhazip.com, checkip.amazonaws.com]` | 세션 상세 응답 본문 |
| C2 POST | `ip.src == <감염IP> && http.method == POST` | `host.http`, `http.uri` + SPI Graph |
| HTTPS 목적지 | `ip.src == <감염IP> && protocols == tls` | `host.http`(SNI), `tls.ja3` |
| 인증서 | `protocols == tls` | `cert.issuer.cn`, `cert.subject.cn`, `cert.notafter` |
| 실패한 연결 | `tcpflags.syn-ack == 0` | `ip.dst`, `port.dst` |
| 리셋된 연결 | `tcpflags.rst > 0` | `ip.dst`, `port.dst` |
| 메일 보내기 | `port.dst == [25,465,587]` | `databytes.src`, 평문이면 `email.src`, `email.dst`, `email.subject`, `email.fn` |
| 특이한 포트 | `ip.src == <감염IP> && !(port.dst == [53,80,443])` | `ip.dst`, `port.dst` |

!!! note "확인한 것과 시험하지 못한 것"
    필드 이름과 `capture` 옵션은 Arkime 소스 코드에서 확인했습니다. TLS SNI가 `host.http`에 들어간다는 것도 포함입니다. 메뉴 이름과 위치(Export PCAP이 있는 액션 메뉴, 시간 범위 All), 서비스 이름, 포트 8005는 랩의 Arkime 버전에서 직접 시험하지 못했습니다. 다르면 viewer의 **Help → Fields**를 기준으로 삼으세요.
