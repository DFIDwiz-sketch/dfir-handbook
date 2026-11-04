---
title: "새 HTTP 표준 — HTTP/2, HTTP/3·QUIC, 웹소켓, 그리고 HTTP 정리"
tags:
  - training
  - blue-team
  - http
  - concept
---

# 새 HTTP 표준 — HTTP/2, HTTP/3·QUIC, 웹소켓, 그리고 HTTP 정리 { #new-standards }

!!! abstract "이 페이지에서 다루는 것"
    HTTP/2가 왜 생겼고 무엇이 바뀌었는지(한 연결 안의 번호 붙은 스트림, HEADERS·DATA 프레임, 이진 형식, HPACK 헤더 압축, 사실상 필수가 된 암호화, 서버 푸시), Wireshark에서 HTTP/2 거래 하나를 따라가는 법, HTTP/3과 QUIC(UDP 위의 TCP+TLS), Zeek `quic.log` 읽기, 회사가 QUIC을 다루는 방법, 웹소켓 핸드셰이크와 탐지, 그리고 HTTP 섹션 전체 정리. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 앞 페이지들은 [HTTP 개요](index.md)에 정리돼 있습니다.

## 한눈에 보는 핵심 10가지 { #key-points }

1. HTTP/2와 HTTP/3은 **말의 뜻(메서드·경로·헤더·응답 코드)은 그대로**이고 **전달 방식**만 바뀌었다.
2. HTTP/2는 TCP 연결 **하나** 안에 번호 붙은 **스트림** 여러 개를 섞어 보낸다. 거래 하나 = IP + TCP 연결 + **스트림 ID**.
3. 요청·응답 헤더는 **HEADERS 프레임**, 본문은 **DATA 프레임**에 따로 담긴다. 헤더는 이진 형식에 HPACK으로 압축돼 "Follow TCP Stream"으로는 못 읽는다.
4. HTTP/2 헤더 이름은 **소문자**이고, 첫 줄과 Host는 `:method`, `:path`, `:authority`, `:scheme`, `:status` 같은 특수 칸이 된다.
5. 브라우저는 HTTP/2를 **암호화된 연결에서만** 쓴다. 내용을 보려면 TLS 검사나 세션 키가 필요하다.
6. 서버 푸시(요청 없이 파일 보내기)는 브라우저들이 꺼서 사실상 사라졌다.
7. HTTP/3은 **UDP 443** 위의 QUIC으로 간다. 암호화가 프로토콜 안에 들어 있어 TCP·TLS를 따로 볼 수 없다.
8. 그래도 QUIC의 첫 패킷(Initial)에서 **SNI**는 읽을 수 있다(ECH가 아니라면). Zeek `quic.log`의 `server_name`.
9. 많은 조직이 **외부 UDP 443을 막아** 브라우저를 TCP+TLS로 되돌리고 기존 검사 장비로 본다.
10. 웹소켓은 `101 Switching Protocols` 뒤로 **오래 열린 양방향 통로**가 된다. 핸드셰이크 뒤의 대화는 HTTP 로그에 거의 안 남는다.

## HTTP/2 { #http2 }

### 왜 생겼나 { #why-http2 }

HTTP/1.1은 한 연결에서 **한 번에 하나씩** 주고받습니다. 앞의 응답이 끝나야 다음 요청의 답이 옵니다. 식당 창구가 하나인데 손님이 줄을 선 것과 같습니다. 그래서 브라우저는 사이트마다 연결을 여러 개(보통 6개 안팎) 열어 버텼고, 웹 페이지에 그림·스크립트가 수십 개씩 들어가면서 느려졌습니다.

구글이 이를 고치려고 만든 실험 프로토콜이 **SPDY**("스피디")였고, 이것이 다듬어져 **HTTP/2**가 되었습니다(2015년 표준화, 2022년 RFC 9113으로 개정). 목표는 두 가지, **더 빠르게**와 **기본적으로 암호화**입니다. 사용자에게는 좋은 일이지만, 글자로 쉽게 읽던 분석가에게는 어려워졌습니다.

### 무엇이 바뀌었나 { #what-changed }

비유하면 HTTP/1.1이 "창구 하나에 한 줄 서기"라면, HTTP/2는 <strong>"컨베이어 벨트 하나에 번호표 붙은 상자를 섞어 올리기"</strong>입니다.

| 바뀐 점 | HTTP/1.1 | HTTP/2 |
| --- | --- | --- |
| 연결 | 사이트당 여러 TCP 연결 | 보통 **TCP 연결 하나** |
| 동시 처리 | 한 연결에 하나씩 차례로 | 번호 붙은 **스트림(Stream)** 여러 개를 섞어서 |
| 단위 | 글자로 된 요청·응답 | **프레임(Frame)**: 헤더는 HEADERS, 본문은 DATA |
| 형식 | 사람이 읽는 글자 | **이진(Binary)** |
| 헤더 | 그대로 | **HPACK**으로 압축(반복되는 헤더는 번호만 보냄) |
| 암호화 | 선택 | 표준은 선택이지만 **브라우저는 TLS에서만** 사용 |
| 서버 푸시 | 없음 | 요청 없이 서버가 먼저 파일을 보낼 수 있음(지금은 사실상 폐지) |

**스트림과 프레임.** 연결 하나 안에서 요청마다 **스트림 ID**라는 번호표가 붙습니다(클라이언트가 여는 스트림은 1, 3, 5…처럼 홀수). 요청 헤더는 그 번호의 HEADERS 프레임으로, 응답 헤더와 본문은 같은 번호의 HEADERS·DATA 프레임으로 돌아옵니다. 여러 스트림의 프레임이 **뒤섞여** 오가므로, 거래 하나를 찾으려면 **IP + TCP 연결 + 스트림 ID** 세 가지로 좁혀야 합니다.

자주 보는 프레임 종류:

| 프레임 | 하는 일 |
| --- | --- |
| `HEADERS` | 요청·응답 헤더 |
| `DATA` | 본문(파일 내용) |
| `SETTINGS` | 연결 설정 교환(연결 시작 때) |
| `WINDOW_UPDATE` | "더 보내도 돼" 흐름 조절 |
| `PING` | 연결이 살아 있는지 확인 |
| `RST_STREAM` | 스트림 하나 취소 |
| `GOAWAY` | 연결 종료 예고 |
| `PUSH_PROMISE` | 서버 푸시 예고 |

### 글자 대신 특수 칸: 의사 헤더 { #pseudo-headers }

HTTP/1.1의 첫 줄(`GET /path HTTP/1.1`)과 Host는 HTTP/2에서 **콜론(`:`)으로 시작하는 특수 칸**(Pseudo-header)이 됩니다.

```
HTTP/1.1                              HTTP/2 (decoded)
GET /images/logo.png HTTP/1.1         :method: GET
Host: www.example.com                 :path: /images/logo.png
                                      :authority: www.example.com
                                      :scheme: https
User-Agent: Mozilla/5.0 ...           user-agent: Mozilla/5.0 ...

HTTP/1.1 200 OK                       :status: 200
Content-Type: image/png               content-type: image/png
```

- `:method` = 메서드, `:path` = 경로, `:authority` = Host에 해당, `:scheme` = http·https
- 응답의 첫 줄은 `:status` 하나 — **"OK" 같은 설명 글자가 없음**
- 일반 헤더 이름은 **모두 소문자**(`user-agent`, `content-type`)

**[보충] 탐지 규칙이 깨지는 지점.** "`User-Agent:`"처럼 대문자를 그대로 찾는 탐지 규칙이나 정규식은 HTTP/2 트래픽을 해석한 결과에서 놓칠 수 있습니다. 헤더 이름은 **대소문자를 구분하지 않고** 비교하도록 만들어야 합니다.

### 실제 모양: 평문 HTTP/2로 올라타기 { #h2c-upgrade }

브라우저는 HTTP/2를 TLS 안에서만 쓰지만, 암호화 없는 HTTP/2(`h2c`)도 표준에 있습니다. HTTP/1.1로 시작해서 "HTTP/2로 바꾸자"고 올라타는 모습이 응답 코드 101의 대표 예입니다.

```
No.  Info
1    GET / HTTP/1.1   (Upgrade: h2c, HTTP2-Settings: ...)
2    HTTP/1.1 101 Switching Protocols
3    Magic, SETTINGS[0]
4    SETTINGS[0], WINDOW_UPDATE[0]
5    HEADERS[1]: 200 OK
6    DATA[1]
7    HEADERS[3]: GET /style.css
8    HEADERS[5]: GET /logo.png
9    HEADERS[3]: 200 OK, DATA[3]
10   HEADERS[5]: 200 OK, DATA[5]
```

1. 클라이언트가 HTTP/1.1로 첫 페이지를 요청하며 `Upgrade: h2c`로 "HTTP/2로 바꿔도 돼?"라고 물음
2. 서버가 `101 Switching Protocols`로 승낙
3. 클라이언트가 HTTP/2 시작 신호(Magic)와 설정(SETTINGS, 스트림 0 = 연결 전체)을 보냄
4. 서버도 설정을 보내고 흐름 조절 값을 알림
5~6. 첫 요청의 답은 **스트림 1**의 HEADERS·DATA로 옴
7~8. 다음 요청 두 개가 스트림 3, 5로 **한꺼번에** 나감
9~10. 답도 번호표별로 돌아옴(순서가 섞일 수 있음)

예전처럼 "200 OK" 한 줄이 아니라, 프레임 이름과 스트림 번호를 따라가야 읽힙니다.

### Wireshark에서 HTTP/2 거래 하나 따라가기 { #http2-wireshark }

해독된(또는 평문) HTTP/2 캡처라면 이렇게 따라갑니다.

```
http2
http2.type == 1
http2.streamid == 19
tcp.stream == 4 && http2.streamid == 19
```

- 1줄: HTTP/2 패킷만 보기
- 2줄: HEADERS 프레임만(프레임 종류 번호: DATA = 0, HEADERS = 1) → 요청·응답 헤더 목록
- 3줄: 스트림 19번만
- 4줄: **4번 TCP 연결의 19번 스트림만** → 거래 하나로 좁히기(다른 연결에도 19번 스트림이 있을 수 있어서 연결 번호까지 함께 지정)

HEADERS 프레임을 펼치면 패킷 상세 창에 이렇게 보입니다.

```
HyperText Transfer Protocol 2
  Stream: HEADERS, Stream ID: 19, Length 52, GET /images/logo.png
    Header: :method: GET
    Header: :path: /images/logo.png
    Header: :authority: www.example.com
    Header: :scheme: https
    Header: user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
```

HPACK 압축 때문에 "Follow TCP Stream"을 하면 깨진 바이트만 보입니다. 대신 Wireshark의 **Follow → HTTP/2 Stream**으로 스트림 하나의 헤더와 본문을 읽을 수 있습니다.

**[보충] 암호화된 HTTP/2를 실습에서 보려면.** 브라우저는 환경 변수 `SSLKEYLOGFILE`이 설정돼 있으면 TLS 세션 키를 그 파일에 적습니다. Wireshark의 Preferences → Protocols → TLS → "(Pre)-Master-Secret log filename"에 그 파일을 지정하면 캡처가 해독되어 HTTP/2가 보입니다. 이 키 파일은 그 시간의 모든 암호화 통신을 풀 수 있는 열쇠이므로 **실습 환경에서만** 쓰고 안전하게 지웁니다. 회사 규모에서는 TLS 검사 프록시가 같은 역할을 합니다.

### 서버 푸시 { #server-push }

서버가 "이 페이지를 보면 이 CSS도 필요하겠지" 하고 **요청 없이 먼저** 파일을 보내는 기능입니다. 분석가에게는 "요청 기록 없이 들어온 파일"이 생긴다는 뜻이라 추적이 어려워질 수 있었습니다.

**[변경됨]** 효과가 기대보다 작고 문제가 많아, 크롬이 2022년에 기본으로 끄고 다른 브라우저들도 뒤따라 **사실상 사라졌습니다.** 대신 `103 Early Hints`(본 응답 전에 "이 파일들 미리 받아 둬" 하고 힌트만 주는 응답)가 쓰입니다. 이 경우에도 실제 파일은 **브라우저의 요청**으로 받아 가므로 요청 기록이 남습니다.

## HTTP/3과 QUIC { #http3 }

### 무엇인가 { #what-is-quic }

HTTP/2도 TCP 연결 하나에 모든 걸 실어 보내다 보니, 패킷 하나가 사라지면 TCP가 그걸 다시 받을 때까지 **모든 스트림이 같이 멈추는** 문제가 남았습니다. 그래서 구글이 TCP 대신 **UDP 위에 새 전송 방식**을 만들었고, 이것이 **QUIC**(Quick UDP Internet Connections, 지금은 그냥 이름)입니다. 구글의 설계 문서는 QUIC을 "TCP+TLS+HTTP/2와 아주 비슷하지만 UDP 위에 구현한 것"이라고 설명합니다. 2021년 RFC 9000으로 표준이 됐고, QUIC 위에서 도는 HTTP가 **HTTP/3**(2022년 RFC 9114)입니다.

| 층 | HTTP/1.1·HTTP/2 | HTTP/3 |
| --- | --- | --- |
| 응용 | HTTP | HTTP/3 |
| 보안 | TLS(별도 층) | **QUIC 안에 TLS 1.3이 들어 있음** |
| 전송 | TCP | **QUIC** |
| 그 아래 | IP | **UDP**(보통 443번) → IP |

HTTP의 "말"을 바꾼 게 아니라 **4계층(전송 계층)을 다시 만든 것**에 가깝습니다. 그래서 TCP 3-way handshake, TCP 재전송, 평문 TLS 핸드셰이크 같은 익숙한 흔적이 안 보입니다.

### 브라우저는 HTTP/3을 어떻게 알고 쓰나 { #h3-discovery }

브라우저는 처음부터 UDP로 가지 않습니다. 보통 두 가지 방법으로 "이 사이트는 HTTP/3도 된다"는 걸 압니다.

```
Alt-Svc: h3=":443"; ma=86400
```

- 첫 접속(TCP+TLS, HTTP/2) 응답에 붙는 `Alt-Svc` 헤더: "같은 곳의 UDP 443에서 HTTP/3(`h3`)도 됩니다. 86,400초(하루) 동안 기억하세요"
- 또는 DNS의 [HTTPS 레코드(타입 65)](../dns/understanding-dns.md#records)가 처음부터 `alpn="h3,h2"`를 알려 줌

그리고 UDP가 막혀 있으면 브라우저는 **조용히 TCP+TLS로 되돌아갑니다.** 이 성질이 아래의 회사 대응 방법으로 이어집니다.

### 그래도 보이는 것: QUIC의 첫 패킷과 Zeek quic.log { #quic-visibility }

QUIC은 패킷 머리 부분까지 대부분 암호화합니다. 다만 연결을 시작하는 **Initial 패킷**은 누구나 풀 수 있는 키(연결 번호에서 계산)로만 보호되어서, 그 안의 TLS ClientHello, 즉 <strong>SNI(사이트 이름)</strong>를 네트워크 장비가 읽을 수 있습니다(ECH를 쓰지 않는다면). Zeek 6.1부터 들어간 QUIC 분석기는 이를 `quic.log`에 남깁니다.

```json
{
  "ts": "2026-11-04T13:40:12.502Z",
  "uid": "CQx9aW2Z7mL1kd3Fe",
  "id.orig_h": "10.1.5.23",
  "id.orig_p": 53727,
  "id.resp_h": "203.0.113.44",
  "id.resp_p": 443,
  "version": "1",
  "client_initial_dcid": "95412c47018cdfe8",
  "server_scid": "d5412c47018cdfe8",
  "server_name": "media.example.com",
  "client_protocol": "h3",
  "history": "ISisH"
}
```

| 필드 | 의미 |
| --- | --- |
| `id.orig_h` / `id.resp_h` / `id.resp_p` | 우리 PC / 서버 IP / 포트(UDP 443) |
| `version` | QUIC 버전(`1` = RFC 9000, `quicv2` = 버전 2) |
| `client_initial_dcid` | 클라이언트가 처음 무작위로 만든 연결 번호 |
| `server_scid` | 서버가 정한 연결 번호 |
| `server_name` | **SNI — 접속한 사이트 이름.** 이 로그에서 가장 쓸모 있는 칸 |
| `client_protocol` | ClientHello의 첫 ALPN 값. `h3` = HTTP/3 |
| `history` | QUIC 패킷 흐름을 글자로 요약(`conn.log`의 history와 비슷) |

경로, 헤더, 응답 코드는 보이지 않습니다. HTTP/3 분석은 <strong>"어느 사이트에 얼마나, 얼마나 자주"</strong>까지가 네트워크 한계이고, 나머지는 해독 장비나 엔드포인트에서 얻습니다.

### 회사는 QUIC을 어떻게 다루나 { #quic-policy }

많은 조직이 이렇게 합니다.

1. **방화벽에서 외부로 나가는 UDP 443을 막습니다.** 브라우저는 HTTP/3을 포기하고 TCP+TLS(HTTP/2)로 되돌아가므로, 기존 TLS 검사 프록시와 로그가 그대로 통합니다. 사용자 영향은 약간 느려지는 정도입니다.
2. **브라우저 정책으로 QUIC을 끕니다**(예: 크롬·엣지 정책 `QuicAllowed`).
3. 그 뒤에도 **UDP 443으로 나가는 시도**가 보이면, 브라우저가 아닌 무언가(QUIC을 쓰는 다른 앱, 원격 접속 도구, 악성코드)가 보내는 것이므로 확인 대상이 됩니다.

### QUIC은 HTTP만 나르지 않는다 { #smb-over-quic }

QUIC은 웹 전용이 아닙니다. 윈도우의 **SMB over QUIC**은 파일 공유(SMB)를 VPN 없이 인터넷 너머로 UDP 443에 실어 보냅니다. 2022년에는 윈도우 11과 Windows Server 2022 Azure Edition에서만 됐지만, **Windows Server 2025부터는 일반 에디션에서도** 쓸 수 있게 되었습니다. 그래서 "UDP 443 = 웹"이라는 가정은 틀릴 수 있고, 회사 밖으로 나가는 QUIC 안에 파일 공유가 들어 있을 수도 있습니다.

**[보충]** 공격 도구 쪽에서도 일부 오픈소스 C2 프레임워크(예: Merlin)가 HTTP/2·HTTP/3 통신을 지원합니다. UDP 443을 열어 둔 환경이라면 C2가 TCP 기반 검사를 피해 나갈 통로가 될 수 있습니다.

## [보충] 웹소켓(WebSocket) { #websocket }

**무엇인가.** HTTP는 원래 "손님이 묻고 주방이 답하는" 방식이라 서버가 먼저 말을 걸 수 없습니다. 채팅, 실시간 알림, 주식 시세처럼 **양쪽이 수시로 말을 주고받아야** 하는 서비스를 위해 만든 것이 웹소켓입니다. HTTP로 시작해서 "이제부터 전화 통화처럼 계속 연결해 두자"고 올라타는 방식입니다. 주소는 `ws://`(암호화 없음), `wss://`(TLS)로 씁니다.

```
GET /chat HTTP/1.1
Host: chat.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

- `Upgrade: websocket` + `Connection: Upgrade` — "웹소켓으로 바꾸자"
- `Sec-WebSocket-Key` — 클라이언트가 만든 무작위 값(Base64). 보안용 암호가 아니라 "진짜 웹소켓 서버인지" 확인하는 인사말
- `Sec-WebSocket-Version: 13` — 현재 표준(RFC 6455) 버전
- `101 Switching Protocols` — 승낙
- `Sec-WebSocket-Accept` — 서버가 Key에 정해진 값을 붙여 계산한 답. 맞으면 연결 성립

**SOC 관점.** 101 이후의 대화는 HTTP 요청·응답이 아니라 **웹소켓 프레임**으로 오가서, 프록시·웹 로그에는 보통 **처음 핸드셰이크 한 줄만** 남습니다. 그 뒤로 연결이 몇 시간씩 열려 있어도 HTTP 로그에는 아무것도 없습니다. 그래서 공격자에게는 C2 통로로 매력적입니다. 탐지는 이렇게 합니다.

- `conn.log` 같은 연결 기록에서 **아주 오래 열린 연결**(몇 시간)과 그 목적지 평판
- 처음 보는 도메인, 등록된 지 얼마 안 된 도메인으로 가는 웹소켓 핸드셰이크
- 연결을 만든 프로세스가 브라우저인지(Sysmon Event ID 3)

## HTTP 섹션 정리 { #summary }

HTTP는 웹 페이지, 메일, 메신저, SNS, 일정 관리, 그리고 악성코드까지 거의 모든 것이 쓰는 프로토콜입니다. 그래서 요청과 응답을 읽고 해석하는 일은 분석가의 일상 업무가 됩니다. 이 섹션에서 다룬 핵심을 다시 묶으면 이렇습니다.

| 해야 하는 것 | 다룬 페이지 |
| --- | --- |
| URL을 프로토콜·호스트·경로·파라미터로 쪼개 읽기 | [웹 서버, URL, GET 요청](web-servers-urls-get.md#url) |
| 서버 쪽 스크립트가 응답을 바꾸는 원리(웹셸 포함) | [웹 서버, URL, GET 요청](web-servers-urls-get.md#web-servers) |
| GET·POST와 나머지 메서드 | [POST, 그 밖의 메서드, 요청 헤더](post-methods-headers.md) |
| 응답 코드 해석 | [응답 헤더와 응답 코드](responses.md#status-codes) |
| 중요한 요청·응답 헤더(Host, User-Agent, Referer, 메서드, MIME 타입) | [요청 헤더](post-methods-headers.md#headers), [응답 헤더](responses.md#response-headers) |
| 헤더를 보고 바로 이상한 점 찾기 | [요청 판정 연습](reading-requests.md), [헤더 판독 실전 연습](header-practice.md) |
| 새 표준의 영향(웹소켓, HTTP/2, HTTP/3·QUIC) | 이 페이지 |

마지막으로, 많은 악성코드가 "규칙을 지키는 평범한 HTTP"인 척 숨어 다닙니다. 그래서 헤더를 보고 이상한 점을 바로 알아차리는 능력이 핵심입니다. 동시에 암호화가 기본이 되면서, 해독(TLS 검사)과 엔드포인트 기록 없이는 볼 수 있는 것이 계속 줄어들고 있습니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    "새 표준은 뜻은 그대로, 전달 방식만 바뀌었다", "거래 하나 = IP + 연결 + 스트림 ID", "해독하지 못하면 점점 보이지 않는다"는 핵심은 그대로입니다. 걱정했던 대로 HTTP/2·HTTP/3은 이제 표준이 됐습니다. W3Techs 기준 2026년 11월 웹사이트의 41.2%가 HTTP/3을 지원합니다.

!!! info "[변경됨] 바뀐 것"
    - **도구가 많이 따라왔습니다.** Wireshark는 세션 키만 있으면 QUIC과 HTTP/3을 해독해서 보여 주고, **Follow → HTTP/2 Stream** 기능도 있습니다. Zeek는 6.1부터 `quic.log`를 남깁니다.
    - **서버 푸시는 사실상 사라졌고**, `103 Early Hints`로 대체됐습니다.
    - **HTTP/2 자체가 공격에 쓰였습니다.** 2023년 "Rapid Reset"(CVE-2023-44487)은 스트림을 열자마자 취소(RST_STREAM)하는 일을 아주 빠르게 반복해 사상 최대 규모의 DDoS를 일으켰고, 2024년에는 CONTINUATION 프레임을 끝없이 보내는 공격도 공개됐습니다. 웹 서버와 프록시의 HTTP/2 구현을 패치하는 게 중요해졌습니다.
    - **SMB over QUIC이 Windows Server 2025부터 일반 에디션으로** 넓어졌습니다. UDP 443 안에 웹이 아닌 것이 들어 있을 수 있습니다.
    - **ECH가 표준이 됐습니다**(2026년 3월 RFC 9849). QUIC의 Initial 패킷에서 읽던 SNI도 ECH를 쓰면 가려집니다([도메인 프론팅과 ECH](post-methods-headers.md#domain-fronting)).

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **[정정] "HTTP/2·3에서는 메서드가 크게 다르다"는 오해입니다.** 메서드·경로·응답 코드의 뜻은 같고, 첫 줄과 Host가 의사 헤더로 바뀌었을 뿐입니다.
    - **TCP만 감시하면 QUIC을 통째로 놓칩니다.** 외부 UDP 443 정책을 정하고(막거나, 보고 기록하거나), 그 정책 밖의 UDP 443 시도를 감시합니다.
    - **대문자 헤더 이름을 그대로 찾는 탐지 규칙은 HTTP/2에서 깨질 수 있습니다.** 대소문자 구분 없이 비교합니다.
    - **`SSLKEYLOGFILE`을 운영 PC에 켜 두지 않습니다.** 그 파일 하나로 모든 암호화 통신이 풀립니다. PC를 장악한 공격자가 이 변수를 설정해 키를 빼낼 수도 있으니, 실습 장비가 아닌 PC에 이 환경 변수가 설정돼 있다면 확인할 가치가 있습니다.

## 확인 문제 { #quiz }

### 문제 1

해독된 HTTP/2 캡처에서 같은 TCP 연결 안에 이런 프레임이 차례로 보입니다.

```
HEADERS[7]: GET /report.pdf
HEADERS[9]: GET /update.bin
HEADERS[9]: 200 OK
DATA[9]
HEADERS[7]: 200 OK
DATA[7]
DATA[9]
```

(a) `update.bin`의 내용은 어느 프레임들에 들어 있습니까? (b) 이 거래만 골라 보려면 Wireshark에서 어떻게 좁힙니까?

??? success "정답과 해설"
    **(a)** 스트림 **9번**의 DATA 프레임들, 즉 4번째 줄과 7번째 줄입니다. HTTP/2에서는 여러 스트림의 프레임이 **섞여서** 오므로, 순서가 아니라 **스트림 ID**로 짝을 맞춥니다. `report.pdf`는 스트림 7번(6번째 줄의 DATA)입니다.

    **(b)** 연결 번호와 스트림 번호를 함께 지정합니다.

    ```
    tcp.stream == N && http2.streamid == 9
    ```

    `N`은 이 TCP 연결의 Wireshark 연결 번호입니다. 다른 TCP 연결에도 9번 스트림이 있을 수 있으니 **IP + TCP 연결 + 스트림 ID** 세 가지로 좁혀야 합니다. 그다음 Follow → HTTP/2 Stream으로 헤더와 본문을 보거나, Export Objects로 파일을 꺼냅니다.

### 문제 2

회사가 방화벽에서 외부로 나가는 UDP 443을 막기로 했습니다. (a) 크롬 사용자에게는 무슨 일이 일어나고, 보안팀은 왜 이렇게 합니까? (b) 차단 후에도 어떤 PC가 계속 외부 UDP 443으로 패킷을 보내려 한다면 무엇을 의심해야 합니까?

??? success "정답과 해설"
    **(a)** 크롬은 HTTP/3(QUIC) 연결이 안 되는 걸 알고 **조용히 TCP+TLS(HTTP/2)로 되돌아갑니다.** 사용자는 거의 느끼지 못합니다(아주 약간 느려질 수 있음). 보안팀이 이렇게 하는 이유는, TCP+TLS 트래픽은 기존 **TLS 검사 프록시, 프록시 로그, 웹 필터**가 그대로 다룰 수 있지만 QUIC은 그 장비들을 우회하기 쉽기 때문입니다. 보통 브라우저 정책(`QuicAllowed` 끄기)도 함께 적용합니다.

    **(b)** 브라우저는 이미 TCP로 되돌아갔으므로, 계속 UDP 443을 시도하는 건 **브라우저가 아닌 무언가**입니다.

    - QUIC을 쓰는 다른 정상 앱(일부 화상회의·스트리밍 앱 등)
    - **SMB over QUIC**(회사 밖 파일 서버로의 파일 공유)
    - QUIC·HTTP/3 통신을 지원하는 **C2 악성코드**

    방화벽의 차단 기록과 Zeek `quic.log`의 `server_name`으로 목적지를 보고, Sysmon Event ID 3으로 **어떤 프로세스**가 보냈는지 확인합니다.

### 문제 3

한 PC에서 다음 기록이 보입니다. 해석하고 다음 할 일을 말해 보세요.

```
http.log:  GET /ws  Host: live-feed.example.net  Upgrade: websocket  status=101
conn.log:  10.1.5.88 → 198.51.100.20:443  duration=9h12m  orig_bytes=184,320  resp_bytes=97,280
```

??? success "정답과 해설"
    **해석:** PC가 `live-feed.example.net`에 **웹소켓 연결**을 열었고(`Upgrade: websocket` → `101`), 그 연결이 **9시간 넘게** 열려 있었습니다. 101 이후의 대화는 웹소켓 프레임이라 HTTP 로그에는 처음 한 줄만 남았고, 연결 기록에는 오랜 시간과 비교적 적은 데이터 양만 보입니다. 채팅·실시간 피드 같은 **정상 서비스**일 수도 있고, 오래 열어 두는 **C2 통로**일 수도 있습니다.

    **다음 할 일:**

    1. **목적지 평판** — `live-feed.example.net`과 IP의 평판, 등록일, 회사에서 처음 보는지
    2. **어떤 프로세스인가** — Sysmon Event ID 3. 브라우저의 정상 탭인지, `AppData` 등의 낯선 프로그램인지
    3. **사람 활동과 비교** — 그 9시간 동안 사용자가 실제로 PC를 쓰고 있었나(퇴근 후·밤새 열려 있었다면 더 의심)
    4. **데이터 패턴** — TLS 검사가 가능하다면 웹소켓 프레임 내용, 불가능하면 일정한 간격의 작은 신호(비콘) 모양인지
    5. 같은 목적지로 웹소켓을 여는 다른 PC가 있는지
