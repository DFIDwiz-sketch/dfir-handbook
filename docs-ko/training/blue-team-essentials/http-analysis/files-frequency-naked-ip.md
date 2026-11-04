---
title: "정상 사이트의 악성 파일, 파일 추출, 잦은 요청, IP 직접 접속"
tags:
  - training
  - blue-team
  - http
  - analysis
---

# 정상 사이트의 악성 파일, 파일 추출, 잦은 요청, IP 직접 접속 { #files-frequency-naked-ip }

!!! abstract "이 페이지에서 다루는 것"
    평판 좋은 클라우드 공유 서비스로 악성 파일을 퍼뜨리는 수법과 그때 남는 유일한 단서(파일 자체), Wireshark·tshark·Zeek로 HTTP 트래픽에서 파일을 안전하게 꺼내는 법, C2가 만드는 **잦고 규칙적인 GET·POST**를 찾는 규칙과 도구, 그리고 **도메인 없이 IP로 직접** 접속하는 요청과 사이트 루트(`/`)로 가는 POST가 왜 수상한지. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 비콘 간격 분석은 [Beaconing & C2 탐지](../../../network/beaconing-c2.md), 파일 기록은 [Zeek files.log](../../../network/zeek/files-log.md)에 자세히 있습니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 공격자는 Dropbox·OneDrive·Google Drive 같은 **평판 좋은 서비스**에 악성 파일을 올려 링크를 보낸다. Host, User-Agent, 메서드가 모두 정상이라 **파일 자체**만 남는다.
2. 암호화되지 않은 HTTP 캡처라면 Wireshark의 **File → Export Objects → HTTP**로 파일을 꺼낼 수 있다.
3. 꺼낸 실행 파일·스크립트는 **더블클릭해도 실행되지 않는 환경**(리눅스 분석 PC)에서만 다룬다.
4. HTTP C2는 명령을 받으려면 **계속 체크인**해야 한다. 그래서 반복되는 GET·POST가 남는다.
5. 특히 수상한 조합: **많다 + 규칙적이다 + 처음 보는 도메인 + 사이트 루트(`/`)로 간다 + 본문이 인코딩돼 있다**.
6. "인기 사이트가 아닌 곳으로 1시간에 POST 100번 이상" 같은 규칙은 쉽고 효과적이지만, 느린 비콘은 놓친다. 주기를 찾는 도구(RITA 등)로 보완한다.
7. 정상 인터넷 통신은 대부분 **호스트 이름**을 쓴다. Host 헤더에 **IP 주소**가 들어 있으면 의심한다.
8. POST는 보통 스크립트(`.php`)나 API 경로로 간다. **루트 `/`로 바로 가는 POST**는 어색하다.

## 정상 사이트에서 내려오는 악성 파일 { #malicious-files-on-good-sites }

**왜 위험한가.** HTTP는 거의 모든 조직이 허용하므로 악성 파일을 전달하기 좋은 통로입니다. 특히 공격자는 **누구나 파일을 올릴 수 있는 평판 좋은 클라우드 서비스**(Dropbox, OneDrive, Google Drive 등)를 즐겨 씁니다. 실제로 2018년 Lazarus 그룹은 Dropbox 공유 링크로 표적 피싱을 했습니다.

이때 분석가가 볼 수 있는 것을 정리하면 이렇습니다.

| 칸 | 상태 |
| --- | --- |
| Host | `www.dropbox.com` 같은 "알려진 정상" 서비스(정책상 허용 여부는 따로) |
| User-Agent | 사용자의 진짜 브라우저 |
| Referer | 메일 링크로 열면 없거나 웹메일 |
| 메서드·경로 | 평범한 다운로드 GET |
| **파일** | **유일하게 남은 단서** |

[좋은 도메인 ≠ 안전한 URL](evil-http-and-reputation.md#domain-vs-url) 원칙이 그대로 적용됩니다. 헤더로는 판단할 수 없으니 **파일을 꺼내서** 확인해야 합니다. 다행히 연결이 해독돼 있다면 네트워크 흐름에서 파일을 직접 꺼내거나, 도구가 자동으로 꺼내 두게 할 수 있습니다.

## HTTP 트래픽에서 파일 꺼내기 { #file-extraction }

### Wireshark { #wireshark-export }

1. 캡처 파일을 엽니다.
2. 메뉴 **File → Export Objects → HTTP**를 고릅니다(같은 메뉴에 TFTP, SMB, IMF(이메일), DICOM도 있습니다).
3. 목록에서 다운로드 거래를 고릅니다.

```
Packet  Hostname                     Content Type               Size        Filename
1482    docs-share-cloud.example     application/octet-stream   1,245 kB    Remittance_2026-11.zip
1530    docs-share-cloud.example     text/html                  18 kB       view
```

- `Packet` — 그 파일이 끝난 패킷 번호(그 번호로 가면 해당 거래를 볼 수 있음)
- `Hostname` — Host 헤더 값
- `Content Type` — 서버가 **주장**한 종류([진짜 종류는 매직 바이트로](../http/responses.md#content-type))
- `Size` — 크기
- `Filename` — URL 경로 끝이나 Content-Disposition에서 가져온 이름

4. **Save**로 저장합니다. 그다음 해시 계산, 서명 확인, 백신 검사를 하고 해시로 평판을 조회합니다.

### tshark(명령줄) { #tshark-export }

캡처가 크거나 여러 개면 명령줄이 편합니다.

```
$ mkdir -p /cases/2026-1104/objects
$ tshark -r capture.pcap --export-objects http,/cases/2026-1104/objects
$ sha256sum /cases/2026-1104/objects/*
9b2f...e41a  /cases/2026-1104/objects/Remittance_2026-11.zip
```

- `mkdir -p ...` — 꺼낸 파일을 둘 폴더를 만듦(`-p`: 중간 폴더까지 한 번에)
- `tshark -r capture.pcap` — 캡처 파일을 읽음(`-r` = read)
- `--export-objects http,<폴더>` — HTTP 객체를 전부 그 폴더로 꺼냄
- `sha256sum ...` — 꺼낸 파일마다 SHA-256 해시를 계산. 이 값으로 평판 조회

### Zeek로 자동 추출 { #zeek-extraction }

Zeek는 설정하면 지나가는 파일을 **자동으로 해시 계산하고 꺼내 둡니다.** 그러면 나중에 캡처를 다시 뒤질 필요 없이 `files.log`에서 바로 찾을 수 있습니다. 필드와 설정 방법은 [Zeek files.log](../../../network/zeek/files-log.md)에 정리돼 있습니다.

!!! warning "[주의] 꺼낸 파일은 터지지 않는 곳에서"
    꺼낸 파일이 윈도우 실행 파일이라면 <strong>윈도우가 아닌 분석 PC(리눅스 등)</strong>에 저장해서, 실수로 더블클릭해도 실행되지 않게 합니다. 윈도우가 더블클릭으로 실행하는 스크립트(`.js`, `.vbs`, `.ps1`, `.hta`, `.bat` 등)도 똑같이 조심합니다. "나는 절대 실수 안 한다"고 생각하기 쉽지만, 한 번 실수하면 그 PC를 믿을 수 없게 되어 새로 설치해야 합니다. 분석용 기기를 따로 두는 것이 훨씬 쌉니다. 파일을 남에게 넘길 때는 암호 걸린 ZIP(관례적으로 비밀번호 `infected`)으로 묶어 백신이 지우거나 누가 실수로 열지 않게 합니다.

**[보충] 암호화된 트래픽이라면.** 위 방법은 **해독된(또는 원래 평문인) HTTP**에서만 됩니다. HTTPS는 TLS 검사 프록시의 저장 기능, 엔드포인트(EDR이 다운로드 파일을 수집), 메일 게이트웨이의 첨부 보관 기능이 현실적인 대안입니다. HTTP/2 거래는 도구와 버전에 따라 객체 내보내기가 안 될 수 있으니, 그럴 땐 [Follow → HTTP/2 Stream](../http/new-standards.md#http2-wireshark)으로 DATA 프레임을 확인하거나 Zeek 추출을 씁니다.

## 잦고 규칙적인 GET·POST { #high-frequency }

**왜 생기나.** HTTP를 C2로 쓰는 악성코드는 공격자의 명령을 받으려면 **계속 서버에 물어봐야** 합니다(체크인). 원격 셸처럼 빠르게 반응하게 하려면 1초에 여러 번 묻고, 조용히 숨으려면 하루에 한 번만 묻기도 합니다. 어느 쪽이든 **반복되는 요청**이 남습니다.

특히 수상한 조합:

| 신호 | 왜 |
| --- | --- |
| 많다 | 사람이 하루에 같은 주소로 수백·수천 번 요청하지 않음 |
| 규칙적이다 | 사람은 불규칙, 프로그램은 일정한 간격 |
| 처음 보는·믿기 어려운 도메인 | 인기 사이트 목록에 없는 곳 |
| 사이트 루트(`/`)로 간다 | 정상 요청은 보통 구체적인 경로나 API로 감 |
| 요청·응답 본문이 인코딩돼 있다 | [Base64](base64.md) 등 |

**간단한 규칙 예.** "인기 순위 상위 1,000개가 아닌 사이트로 1시간 안에 POST 100번 이상이면 알림"처럼 만들 수 있습니다. Zeek 로그로 비슷하게 세어 보면 이렇습니다.

```
$ cat http.log | zeek-cut id.orig_h host method | awk '$3=="POST"' | sort | uniq -c | sort -rn | head -5
   1440 10.1.5.77    sync-metrics-api.example   POST
    212 10.1.5.23    graph.microsoft.com        POST
     96 10.1.5.40    login.microsoftonline.com  POST
     41 10.1.5.12    collector.analytics.example POST
     12 10.1.5.31    forms.office.com           POST
```

- `zeek-cut id.orig_h host method` — 출발지 IP, Host, 메서드 세 칸만 잘라냄
- `awk '$3=="POST"'` — 셋째 칸(메서드)이 POST인 줄만 남김
- `sort | uniq -c` — 같은 (PC, 호스트, 메서드) 조합끼리 세어 합침
- `sort -rn` — 횟수가 큰 것부터(`-r` 역순, `-n` 숫자)
- `head -5` — 위 5개만

결과 읽기:

- **1줄** — 한 PC가 처음 보는 `sync-metrics-api.example`로 하루 1,440번 POST = **정확히 1분에 한 번**(24시간 × 60분). 비콘 의심 1순위
- **2~3줄** — 마이크로소프트 서비스. 인기 사이트 목록과 기준선으로 걸러냄
- **4줄** — 분석 수집기. 웹사이트 추적 스크립트일 수 있으니 확인

**[보충] 느린 비콘도 잡을 수 있다.** 위 같은 횟수 규칙은 하루 한 번 연락하는 느린 비콘을 놓칩니다. 그래서 **간격의 규칙성**을 직접 재는 도구를 씁니다. 예를 들어 오픈소스 RITA(Real Intelligence Threat Analytics)는 Zeek 로그에서 연결 간격과 데이터 크기가 얼마나 일정한지 점수를 매겨, 간격이 길어도 주기적인 신호를 찾아 줍니다. 원리와 직접 계산하는 법은 [Beaconing & C2 탐지](../../../network/beaconing-c2.md#interval-analysis-the-core-technique)에 있습니다.

## 도메인 없이 IP로 직접: Naked IP { #naked-ip }

**왜 수상한가.** 정상 인터넷 통신은 거의 다 **호스트 이름**을 씁니다. 사람이 기억하기 쉽고, 프로그램도 서버 IP가 바뀌어도 계속 작동하기 때문입니다. 그래서 이름 없이 **IP 주소로 바로** 접속하는 요청은 눈여겨봐야 합니다. 이걸 알려 주는 곳이 Host 헤더입니다.

```
POST / HTTP/1.1
Host: 203.0.113.58
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/octet-stream
Content-Length: 344

(binary data)
```

- `Host: 203.0.113.58` — 이름이 아니라 **IP 주소**. 호스트 이름으로 접속했다면 여기에 이름이 들어 있어야 함
- `POST /` — 데이터를 서버의 **루트(맨 위 폴더)로 바로** 보냄. 보통 POST는 `login.php` 같은 서버 스크립트나 `/api/v2/...` 같은 API로 가는데, 루트로 바로 보내는 건 어색함
- User-Agent는 브라우저 이름 없이 플랫폼만 있는 짧은 가짜 값
- 본문은 정체 모를 바이너리

**[보충] HTTPS에서 IP 직접 접속 알아보기.** TLS에서는 사이트 이름을 SNI로 밝히는데, 표준상 **IP 주소는 SNI에 넣지 않습니다.** 그래서 IP로 직접 HTTPS 접속하면 Zeek `ssl.log`의 `server_name`이 **비어** 있고, 서버 인증서도 그 IP와 맞지 않는 경우가 많습니다(`validation_status`에 오류). "SNI 없음 + 처음 보는 외부 IP + 일정한 간격"은 강한 C2 신호입니다.

**정상인 예외도 있습니다.** 장비 업체의 원격 관리, IoT 기기, 오래된 사내 앱, 클라우드 VM의 메타데이터 주소(`169.254.169.254`, 클라우드 안에서만 쓰는 정상 주소)는 IP로 통신할 수 있습니다. 그래서 "IP 직접 접속 = 악성"이 아니라 <strong>"설명이 필요한 통신"</strong>으로 보고, 어떤 장비·프로세스인지 확인합니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    "평판 좋은 서비스가 악성 파일을 나른다", "해독되면 파일을 꺼내 직접 확인", "C2는 반복을 남긴다", "IP 직접 접속과 루트 POST는 수상하다"는 모두 그대로입니다.

!!! info "[변경됨] 바뀐 것"
    - **인기 사이트 순위 목록이 바뀌었습니다.** 예전에 많이 쓰던 Alexa 순위는 2022년에 서비스가 끝났습니다. 지금은 Tranco 목록, Cisco Umbrella 인기 목록, Cloudflare Radar 순위 등을 씁니다. 다만 **인기 순위 = 안전**은 아닙니다(인기 클라우드 서비스가 악용됨).
    - **악용되는 "정상 서비스"가 넓어졌습니다.** 클라우드 저장소 외에 GitHub, Discord·Telegram의 파일 공유, 협업 도구 링크, 그리고 [Cloudflare Workers나 터널 같은 무료 서브도메인](../http/post-methods-headers.md#domain-fronting)이 흔합니다.
    - **파일 확보는 엔드포인트 쪽이 중심입니다.** 대부분 HTTPS라 네트워크에서 파일을 꺼내기 어려워, EDR이 다운로드 파일을 수집하거나 브라우저 다운로드 기록과 MotW(Mark of the Web, 인터넷에서 받은 파일에 붙는 표시) 정보로 출처를 확인합니다.
    - **C2 프레임워크는 지터(Jitter)로 간격을 흔듭니다.** Cobalt Strike, Sliver 등은 기본으로 간격을 무작위로 흔들어 "정확히 60초"를 피합니다. 그래서 간격의 평균·편차, 데이터 크기의 일정함까지 함께 보는 통계 기반 탐지(RITA, NDR 제품)가 중요해졌습니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **인기 사이트로 가는 반복 요청을 무조건 제외하지 않습니다.** 공격자가 클라우드 API(예: 협업 도구, 저장소 API)를 C2로 쓰면 인기 목록 필터를 그대로 통과합니다. 제외 목록은 "도메인 전체"보다 좁게 둡니다.
    - **꺼낸 파일을 분석가의 업무용 윈도우 PC에 저장하지 않습니다.**
    - **IP 직접 접속을 전부 차단·경보하면 업무 장비 통신이 깨집니다.** 장비 목록과 기준선으로 예외를 관리합니다.

## 확인 문제 { #quiz }

### 문제 1

직원이 메일 링크로 `docs-share-cloud.example`에서 `Remittance_2026-11.zip`(1.2MB)을 받았습니다. 평문 HTTP 캡처가 있습니다. Host, User-Agent, 메서드는 모두 평범해 보입니다. 파일을 어떻게 꺼내고, 꺼낸 뒤 무엇을 해야 합니까?

??? success "정답과 해설"
    **꺼내기:** Wireshark **File → Export Objects → HTTP**에서 그 거래를 골라 Save. 또는 명령줄로 `tshark -r capture.pcap --export-objects http,<폴더>`. **리눅스 분석 PC 같은 안전한 곳**에 저장합니다.

    **꺼낸 뒤:**

    1. `sha256sum`으로 해시를 계산해 평판 조회(파일을 공개 서비스에 올리기 전에 해시부터)
    2. ZIP 안을 **풀지 말고 목록만** 확인(`unzip -l` 등): 안에 `.exe`, `.js`, `.lnk`, `.iso` 같은 실행 가능한 파일이 있는지
    3. 매직 바이트로 실제 종류 확인 — 이름과 Content-Type은 거짓일 수 있음
    4. 필요하면 격리된 샌드박스에서 동작 확인
    5. 그 직원 PC에서 ZIP이 풀렸는지, 안의 파일이 실행됐는지(Sysmon Event ID 11 파일 생성, Sysmon 1 / 4688 프로세스 생성) 확인
    6. 같은 링크를 받은 다른 직원 찾기

    헤더가 다 정상인 이유는 공격자가 평판 좋은 공유 서비스를 썼거나 그렇게 보이게 했기 때문입니다. 이럴 때 남는 단서는 **파일 자체**뿐입니다.

### 문제 2

다음은 하루치 Zeek `http.log`에서 POST를 (PC, 호스트)별로 센 결과입니다. 무엇을 먼저 조사하고, 무엇은 정상일 가능성이 높습니까?

```
   1440 10.1.5.77    sync-metrics-api.example    POST
    212 10.1.5.23    graph.microsoft.com         POST
     24 10.1.5.88    203.0.113.58                POST
     12 10.1.5.31    forms.office.com            POST
```

??? success "정답과 해설"
    **먼저 조사:**

    - **1줄** — 처음 보는 도메인으로 하루 1,440번 = **정확히 1분에 한 번**. 비콘 1순위
    - **3줄** — 횟수는 적지만(24번 = 1시간에 한 번) Host가 **IP 주소**. 하루 24번이라 횟수 규칙엔 안 걸리지만, IP 직접 접속 + 규칙적 간격(1시간)은 느린 비콘의 모양. 경로가 `/`인지, 본문이 인코딩됐는지도 확인

    **정상 가능성 높음:**

    - **2줄** — Microsoft Graph API. 오피스 앱들이 많이 씀(단, Graph API를 C2로 악용한 사례도 있으니 출발 프로세스가 정상 오피스 앱인지는 확인할 가치가 있음)
    - **4줄** — Microsoft Forms 제출

    교훈: **횟수 순위만 보면 3줄 같은 느린 비콘을 놓칩니다.** IP 직접 접속, 간격의 규칙성을 함께 봅니다.

### 문제 3

다음 두 요청 중 어느 쪽이 더 수상하고, 그 이유는 무엇입니까? 각각 무엇을 확인해야 합니까?

```
A: POST / HTTP/1.1
   Host: 203.0.113.58:8443
   Content-Type: application/octet-stream

B: GET /api/v1/status HTTP/1.1
   Host: 10.20.0.15
   User-Agent: PrinterAgent/3.2
```

??? success "정답과 해설"
    **A가 훨씬 수상합니다.**

    - 외부 IP(`203.0.113.58`)에 **이름 없이 직접**, 비표준 포트 8443
    - **루트 `/`로 바로 POST** — 서버 스크립트나 API 경로가 아님
    - 정체 모를 바이너리 본문

    확인할 것: 연결을 만든 프로세스(Sysmon Event ID 3), 같은 IP로의 반복 간격, IP의 평판과 소속(어느 호스팅 업체·국가), 본문 내용(Base64인지, 매직 바이트), 그 PC의 지속성 장치.

    **B는 설명 가능한 예외일 가능성이 큽니다.**

    - 목적지가 **사내 IP**(`10.20.0.15`)이고, 경로가 구체적인 상태 확인 API
    - User-Agent가 프린터 관리 에이전트로 보임

    확인할 것: `10.20.0.15`가 실제로 프린터(또는 관리 서버)인지 자산 목록과 대조, 그 에이전트가 회사가 설치한 소프트웨어인지. 확인되면 기준선(정상 예외 목록)에 올려 다음부터 잡음을 줄입니다.
