---
title: "이메일 전달 구조와 SMTP — MUA·MTA·MDA, 포트, SMTP 대화 읽기"
tags:
  - training
  - blue-team
  - email
  - smtp
---

# 이메일 전달 구조와 SMTP — MUA·MTA·MDA, 포트, SMTP 대화 읽기 { #delivery-smtp }

!!! abstract "이 페이지에서 다루는 것"
    이메일이 보낸 사람의 PC에서 받는 사람의 받은편지함까지 가는 세 단계(제출·중계·받기)와, 각 단계를 맡는 MUA·MSA·MTA·MDA가 무엇인지. 단계마다 쓰는 프로토콜과 포트, MX 레코드로 받는 서버를 찾는 법, 경계 MTA의 IP가 왜 "속일 수 없는 값"인지. 그리고 SMTP 대화를 한 줄씩 읽고, 봉투 주소와 헤더 주소의 차이, 응답 코드, Zeek `smtp.log`, SOC에서 볼 포인트까지. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 도메인과 IP는 모두 설명용 가상 값(`.example`, 문서용 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 이메일 전달은 **제출(Submission) → 중계(Relay) → 받기(Receiving)** 세 단계로 나눠 생각한다.
2. **MUA**(메일 프로그램) → **MSA/MTA**(보내는 서버들) → **MTA**(받는 서버들) → **MDA**(받은편지함에 넣는 서버) → 받는 사람의 **MUA**.
3. 단계마다 프로토콜과 포트가 다르다. **서버끼리 중계는 SMTP 25번**, 사용자 제출은 **587·465**, 읽기는 **IMAP·POP3** 또는 **HTTPS**(웹메일, Exchange·Microsoft 365, Gmail).
4. 받는 쪽 경계 서버는 DNS의 **MX 레코드**로 찾는다.
5. 보내는 쪽 **경계 MTA가 우리에게 연결해 온 IP**는 TCP 연결로 확인된 값이라 **속일 수 없다.** 이메일 출처 판단의 기준점이다.
6. SMTP는 사람이 읽을 수 있는 **평문 명령**(EHLO, MAIL FROM, RCPT TO, DATA)과 **세 자리 응답 코드**로 이루어진다.
7. **봉투 주소(MAIL FROM·RCPT TO)와 헤더 주소(From:·To:)는 서로 다를 수 있다.** 사용자가 보는 건 헤더 주소이고, 이것은 아무렇게나 적을 수 있다.
8. 서버를 하나 지날 때마다 같은 SMTP 대화가 반복되고, 그 흔적이 **Received 헤더**로 쌓인다. 이것이 다음 페이지의 분석 대상이다.

## 왜 이메일을 알아야 하나 { #why-email }

이메일은 지금도 공격자가 회사 안으로 들어오는 **가장 흔한 첫 관문** 중 하나입니다. 악성 첨부 파일, 피싱 링크, 가짜 로그인 페이지로 유도하는 메일, 결제 계좌를 바꿔 달라는 사칭 메일(BEC, Business Email Compromise)이 모두 이메일로 옵니다. 그래서 SOC 분석가는 "이 메일이 정말 그 사람이 보낸 것인가, 어디를 거쳐 왔는가"를 스스로 판단할 수 있어야 합니다.

그 판단의 재료가 **이메일 헤더**입니다. 그런데 헤더를 제대로 읽으려면 먼저 메일이 **어떤 서버들을 거쳐, 어떤 프로토콜로 전달되는지** 알아야 합니다. 서버를 지날 때마다 헤더에 한 줄씩 기록이 붙기 때문입니다. 이 페이지는 그 길을 먼저 그려 봅니다.

## 세 단계: 제출, 중계, 받기 { #three-stages }

비유하면 **우편**입니다. 내가 편지를 써서 동네 우체통에 넣고(제출), 우체국들이 편지를 차례로 넘겨 상대 동네 우체국까지 보내고(중계), 그 우체국이 상대 집 우편함에 넣으면, 상대가 우편함을 열어 꺼내 봅니다(받기).

```
 Sender's org                                           Recipient's org
┌──────────────────────────────────────┐   Internet   ┌──────────────────────────────────────┐
│ MUA ─(1) submit─▶ MSA ─▶ MTA ─▶ Border MTA ═SMTP 25═▶ Border MTA ─▶ MTA ─▶ MDA ─(3) read─▶ MUA │
└──────────────────────────────────────┘  (2) relay   └──────────────────────────────────────┘
                                          found via DNS MX
```

| 이름 | 영어 | 하는 일 | 우편 비유 | 예 |
| --- | --- | --- | --- | --- |
| MUA | Mail User Agent | 사용자가 메일을 쓰고 읽는 프로그램. 쓴 메일을 서버에 제출하고, 받은 메일을 보여 줌 | 나(편지 쓰고 읽는 사람) | Outlook, Thunderbird, Gmail 웹 화면, 휴대폰 메일 앱 |
| MSA | Mail Submission Agent | 사용자의 메일을 처음 받아 주는 제출 전용 서버. 보통 로그인(인증)을 요구 | 동네 우체통 | `smtp.mail.example:587` |
| MTA | Mail Transfer Agent | 메일을 다음 서버로 넘기는 중계 서버. 여러 대를 거칠 수 있음 | 우체국들 | Postfix, Exim, Exchange, 메일 보안 게이트웨이 |
| 경계 MTA | Border MTA | 보내는 회사에서 **마지막으로** 메일을 만지는 서버, 받는 회사에서 **처음으로** 메일을 받는 서버 | 국경 우체국 | 받는 쪽은 MX 레코드에 적힌 서버 |
| MDA | Mail Delivery Agent | 메일을 받는 사람별로 분류해 메일함에 저장 | 집 우편함에 넣는 집배원 | Dovecot, Exchange 메일함 서버 |

표준 문서는 이렇게 역할별로 이름을 나누지만, 실제로는 한 서버가 여러 역할을 겸하는 경우가 많습니다. 웹메일이나 Microsoft 365, Google Workspace 같은 클라우드 메일은 이 경계가 더 흐릿합니다. 그래도 역할을 나눠 생각해야 <strong>"이 구간에서는 어떤 트래픽이, 어떤 로그가 남는가"</strong>를 정확히 말할 수 있습니다.

### 단계별 프로토콜과 포트 { #ports }

| 구간 | 프로토콜 | 포트 | 메모 |
| --- | --- | --- | --- |
| MUA → MSA (제출) | SMTP Submission | **587**(STARTTLS로 암호화 시작) | 로그인 필요. 가장 흔한 제출 포트 |
| MUA → MSA (제출) | SMTP Submission over TLS | **465**(처음부터 TLS) | 한때 폐기됐다가 RFC 8314로 다시 권장됨 |
| MTA → MTA (중계) | SMTP | **25** | 서버끼리. 인증 없이 받는 게 정상(받는 쪽 회사 메일이므로) |
| MDA → MUA (읽기) | IMAP | 143(STARTTLS) / **993**(TLS) | 메일을 서버에 두고 동기화 |
| MDA → MUA (읽기) | POP3 | 110(STARTTLS) / **995**(TLS) | 내려받아 가져가는 방식 |
| 제출·읽기 모두 | HTTPS | **443** | 웹메일, Exchange(MAPI/HTTP, EWS, ActiveSync), Microsoft Graph, Gmail API |

여기서 중요한 사실이 하나 있습니다. **제출(1단계)과 읽기(3단계)는 SMTP가 아닐 수 있지만, 서버끼리 넘기는 중계(2단계)는 모두 SMTP**입니다. 그리고 우리가 분석할 **Received 헤더는 이 SMTP 중계 구간에서 남습니다.** 사용자가 웹메일로 쓰든 Outlook으로 쓰든, 일단 첫 MTA에 들어간 뒤부터 받는 쪽 MDA까지는 SMTP 대화가 이어집니다.

### 받는 서버 찾기: MX 레코드 { #mx }

보내는 쪽 경계 MTA는 "`victim.example` 회사로 가는 메일은 어느 서버에 넘겨야 하나?"를 DNS의 **MX(Mail Exchanger) 레코드**에 묻습니다([DNS 레코드](../dns/understanding-dns.md#records)).

```
$ dig +short MX victim.example
10 mx1.victim.example.
20 mx2.victim.example.
```

- `dig` — DNS를 조회하는 명령
- `+short` — 답만 짧게 출력
- `MX victim.example` — 이 도메인의 메일 서버를 물음
- `10 mx1...` / `20 mx2...` — 앞의 숫자는 **우선순위**입니다. **숫자가 작을수록 먼저** 시도합니다. mx1이 안 되면 mx2로 보냅니다

클라우드 메일을 쓰는 회사라면 MX가 `victim-example.mail.protection.outlook.com`(Microsoft 365)이나 `aspmx.l.google.com`(Google)처럼 클라우드 서비스를 가리킵니다. 메일 보안 게이트웨이를 앞에 둔 회사라면 그 업체의 서버가 MX에 나옵니다. **SOC 입장에서는 "우리 MX가 어디인가"를 알아야** 다음 페이지에서 Received 헤더 중 "우리 쪽이 적은 줄"을 구분할 수 있습니다.

### 경계 MTA의 IP는 속일 수 없다 { #border-ip }

헤더의 많은 내용은 보내는 사람이 마음대로 적을 수 있습니다. 하지만 **보내는 쪽 경계 MTA가 우리 경계 MTA에 연결해 온 IP 주소**만큼은 다릅니다. SMTP는 TCP 위에서 동작하고, TCP 연결은 **3-way handshake**(SYN → SYN-ACK → ACK)를 마쳐야 맺어집니다. 가짜 IP로 SYN을 보내면 우리 서버의 SYN-ACK가 그 가짜 IP로 가 버리므로, 보낸 쪽은 대화를 이어 갈 수 없습니다. 그러니 **실제로 SMTP 대화를 마친 상대의 IP는 진짜**입니다.

그래서 이메일 출처를 판단할 때는 **우리 경계 MTA가 직접 적은 "누구에게서 받았는지(from IP)"** 기록을 기준점으로 삼습니다. 다음 페이지에서 볼 SPF 검사도 바로 이 IP를 가지고 합니다. 반대로 그보다 앞(보내는 쪽 내부)에서 적힌 Received 줄은 **보낸 쪽이 지어낼 수 있습니다.**

## SMTP 대화를 한 줄씩 읽기 { #smtp-conversation }

SMTP는 1982년에 만들어진 아주 단순한 프로토콜입니다. 명령도 응답도 **사람이 읽을 수 있는 ASCII 글자**이고, 서버는 HTTP처럼 **세 자리 응답 코드**로 답합니다. 아래는 `sender.example`의 메일 서버가 `victim.example`의 MX에 메일 한 통을 넘기는 대화입니다. `S:`는 받는 서버(Server), `C:`는 연결한 쪽(Client)입니다.

```
S: 220 mx1.victim.example ESMTP ready
C: EHLO mail.sender.example
S: 250-mx1.victim.example Hello mail.sender.example [198.51.100.25]
S: 250-SIZE 52428800
S: 250-8BITMIME
S: 250-STARTTLS
S: 250 SMTPUTF8
C: MAIL FROM:<alerts@sender.example>
S: 250 2.1.0 Sender OK
C: RCPT TO:<jsmith@victim.example>
S: 250 2.1.5 Recipient OK
C: DATA
S: 354 Start mail input; end with <CRLF>.<CRLF>
C: From: "IT Helpdesk" <helpdesk@victim.example>
C: To: jsmith@victim.example
C: Subject: Password expires today
C: Date: Wed, 18 Nov 2026 09:14:02 +1030
C: Message-ID: <a81f3c@mail.sender.example>
C:
C: Your password expires today. Re-validate here: hxxps://login-victim.example/reset
C: .
S: 250 2.0.0 Ok: queued as 4QzK7m1abc
C: QUIT
S: 221 2.0.0 Bye
```

한 줄씩 봅니다.

- `220 mx1.victim.example ESMTP ready` — 연결하자마자 서버가 먼저 인사합니다(배너). 220 = 서비스 준비됨. ESMTP는 확장 기능을 지원하는 SMTP라는 뜻
- `EHLO mail.sender.example` — 연결한 서버가 **자기 이름을 밝힙니다.** 옛 명령은 `HELO`, 확장 기능을 쓰려면 `EHLO`. **이 이름은 스스로 적는 값이라 거짓일 수 있습니다**
- `250-... Hello mail.sender.example [198.51.100.25]` — 받는 서버가 "당신 이름은 그렇다 치고, **실제로 연결해 온 IP는 198.51.100.25**"라고 기록합니다. 이 IP가 앞에서 말한 속일 수 없는 값입니다. `250-`처럼 숫자 뒤에 `-`가 붙으면 "아직 줄이 더 있다", 마지막 줄은 `250 `(공백)
- `SIZE`, `8BITMIME`, `STARTTLS`, `SMTPUTF8` — 이 서버가 지원하는 확장 기능 목록. `STARTTLS`가 있으면 "원하면 지금부터 암호화로 바꿀 수 있다"는 뜻(아래 [변경됨] 참고). 제출 서버(587)라면 여기에 `AUTH`(로그인 방식)도 나옵니다
- `MAIL FROM:<alerts@sender.example>` — **봉투의 보낸 사람(Envelope From).** 메일이 배달 실패하면 반송 메일이 이 주소로 갑니다. 그래서 Return-Path, bounce 주소라고도 부릅니다
- `250 2.1.0 Sender OK` — 받아들임. `2.1.0`은 더 자세한 확장 상태 코드
- `RCPT TO:<jsmith@victim.example>` — **봉투의 받는 사람(Envelope To).** 실제로 메일이 배달될 곳. 받는 사람이 여럿이면 이 줄이 여러 번 나옵니다
- `DATA` → `354 Start mail input...` — "이제 메일 본체를 보내라. 끝나면 점 하나만 있는 줄을 보내라"
- `From: "IT Helpdesk" <helpdesk@victim.example>` — 여기서부터는 <strong>메일 본체(메시지)</strong>입니다. 이 `From:`은 <strong>헤더의 보낸 사람(Header From)</strong>으로, 받는 사람의 메일 화면에 표시되는 주소입니다. 봉투의 `alerts@sender.example`과 **다릅니다.** 게다가 받는 회사 자신의 도메인(`victim.example`)을 사칭하고 있습니다
- `To:`, `Subject:`, `Date:`, `Message-ID:` — 화면에 보이는 받는 사람, 제목, 날짜, 메일 고유 번호. 모두 **보내는 쪽이 적는 값**입니다
- 빈 줄 — 헤더가 끝나고 본문이 시작된다는 표시
- 본문 — 실제 내용. 여기서는 가짜 비밀번호 재설정 링크(기록할 때는 `hxxps`로 디팽)
- `.` — 점 하나만 있는 줄 = 메일 끝
- `250 2.0.0 Ok: queued as 4QzK7m1abc` — 받아서 대기열에 넣었다. **`4QzK7m1abc`는 이 서버의 대기열 ID**로, 메일 서버 로그에서 이 메일을 찾는 열쇠가 됩니다
- `QUIT` → `221 Bye` — 연결 종료

이 메일이 다음 서버로 넘어가면, **같은 대화가 그 서버와 다시 반복됩니다.** 받는 쪽 내부에 서버가 셋 있으면 대화도 세 번, Received 헤더도 세 줄이 붙습니다.

### 봉투 주소와 헤더 주소 { #envelope-vs-header }

이 구분은 이메일 분석에서 가장 중요한 개념 중 하나입니다.

| 구분 | 어디에 | SMTP에서 | 누가 보나 | 비유 |
| --- | --- | --- | --- | --- |
| 봉투(Envelope) | SMTP 명령 | `MAIL FROM`, `RCPT TO` | 서버들(배달에 씀). 헤더에는 `Return-Path:`로 남음 | 편지봉투에 적힌 주소 |
| 헤더(Header) | DATA 안의 메시지 | `From:`, `To:`, `Cc:` | **받는 사람이 화면에서 봄** | 편지지 맨 위에 적은 "보내는 이" |

우체국은 **봉투**만 보고 배달합니다. 편지지 안에 "대통령 올림"이라고 써도 우체국은 상관하지 않습니다. 이메일도 똑같습니다. 서버는 `RCPT TO`대로 배달하고, 사용자는 `From:`을 보고 "누가 보냈는지" 판단합니다. 그런데 **원래 SMTP에는 이 둘이 같아야 한다는 규칙도, 확인하는 장치도 없습니다.** 그래서 공격자는 봉투는 자기 도메인으로 두고, 헤더 `From:`만 은행이나 우리 회사 사람으로 적을 수 있습니다. 이 빈틈을 메우려고 나중에 만들어진 것이 SPF, DKIM, DMARC입니다(이후 페이지에서 다룸).

같은 원리로 <strong>숨은 참조(Bcc)</strong>가 동작합니다. Bcc 받는 사람은 `RCPT TO`에만 들어가고 헤더에는 적히지 않으므로, 다른 받는 사람에게 보이지 않습니다.

### 응답 코드 읽기 { #reply-codes }

| 코드 | 뜻 | 자주 보는 예 |
| --- | --- | --- |
| 2xx | 성공 | `220` 준비됨, `250` OK, `221` 종료 |
| 3xx | 계속 입력하라 | `354` 본문 보내라, `334` 인증 정보 보내라 |
| 4xx | **일시적** 실패, 나중에 다시 시도 | `421` 서비스 불가, `450`/`451` 그레이리스트·잠시 거부 |
| 5xx | **영구** 실패 | `550` 받는 사람 없음·정책 거부, `530` 인증 필요, `535` 인증 실패, `554` 거래 실패(스팸 등) |

확장 상태 코드(`5.7.1` 같은 세 숫자)의 가운데 숫자 `7`은 **보안·정책** 문제입니다. 반송 메일에 `550 5.7.1`이 보이면 "정책상 거부"(SPF 실패, 차단 목록 등)라는 뜻이라, 사칭 메일이 막혔는지 확인할 때 유용합니다.

**[정정] 대소문자 규칙.** SMTP 명령(`EHLO`, `MAIL FROM` 등)과 도메인 이름은 대소문자를 구분하지 않습니다. 메일 주소의 `@` 앞부분(로컬 부분)은 SMTP 표준(RFC 5321)상 **받는 서버가 구분해도 되는** 부분이지만, 실제로 대부분의 메일 서비스는 구분하지 않습니다. 참고로 SMTP 대화 규칙은 RFC 5321, 메일 메시지(헤더·본문) 형식은 RFC 5322로, 서로 다른 문서입니다.

### 실습: 직접 SMTP 대화해 보기 { #smtp-lab }

예전에는 `telnet mail.example 25`로 접속해 위 명령을 손으로 쳐 보는 게 흔한 실습이었습니다. 지금은 대부분의 서버가 암호화를 요구하거나 낯선 연결을 거부하므로, <strong>자기 실습용 메일 서버(예: 랩의 Postfix, MailHog·Mailpit 같은 테스트 서버)</strong>에서 해 봅니다.

```
$ openssl s_client -starttls smtp -connect mail.lab.example:587 -crlf -quiet
```

- `openssl s_client` — TLS 클라이언트로 서버에 연결
- `-starttls smtp` — 먼저 평문 SMTP로 연결한 뒤 `STARTTLS` 명령으로 암호화를 시작
- `-connect mail.lab.example:587` — 실습 서버의 제출 포트
- `-crlf` — 줄 끝을 SMTP가 요구하는 CRLF(`\r\n`)로 보냄
- `-quiet` — 인증서 정보 출력을 줄임. 이후 `EHLO`, `MAIL FROM`… 을 직접 입력

명령을 일일이 치기 귀찮으면 `swaks`(Swiss Army Knife for SMTP)를 씁니다.

```
$ swaks --server mail.lab.example:25 --from alerts@sender.example \
        --to jsmith@lab.example --header "Subject: test" --body "hello"
```

- `--server` — 연결할 서버와 포트
- `--from` — **봉투** 보낸 사람(MAIL FROM)
- `--to` — 봉투 받는 사람(RCPT TO)
- `--header "Subject: test"` — 메시지 헤더 추가
- 출력에 위와 같은 `<-`(서버 응답)와 ` ->`(보낸 명령) 대화가 그대로 찍혀서 공부하기 좋습니다

**[주의]** 남의 메일 서버나 회사 운영 메일 서버에 이런 테스트 메일을 보내지 않습니다. 사칭 메일 발송으로 오해받거나 차단 목록에 오를 수 있습니다.

## SOC에서 보는 법 { #soc-view }

### Zeek `smtp.log` { #zeek-smtp }

네트워크 센서가 **평문 SMTP**(또는 해독된 SMTP)를 보면 Zeek은 `smtp.log`를 남깁니다. 위 대화라면 대략 이렇습니다.

```
ts=2026-11-17T22:44:02Z  uid=CmXv2k3  id.orig_h=198.51.100.25  id.resp_h=203.0.113.10  id.resp_p=25
helo=mail.sender.example
mailfrom=alerts@sender.example
rcptto=jsmith@victim.example
from="IT Helpdesk" <helpdesk@victim.example>
to=jsmith@victim.example
subject=Password expires today
msg_id=<a81f3c@mail.sender.example>
last_reply=250 2.0.0 Ok: queued as 4QzK7m1abc
path=203.0.113.10,198.51.100.25
tls=F  fuids=-  is_webmail=F
```

- `id.orig_h` / `id.resp_h` — 연결한 쪽(보내는 경계 MTA)과 받은 쪽(우리 MX)의 IP. **`id.orig_h`가 속일 수 없는 값**
- `helo` — EHLO에 적힌 이름(스스로 적은 값)
- `mailfrom` / `rcptto` — **봉투** 주소
- `from` / `to` — **헤더** 주소. `mailfrom`의 도메인(`sender.example`)과 `from`의 도메인(`victim.example`)이 다르고, 게다가 `from`이 우리 회사 도메인 → 사칭 의심
- `subject`, `msg_id` — 제목과 메일 고유 번호(같은 캠페인 메일을 묶을 때 씀)
- `last_reply` — 서버의 마지막 응답. 250이면 받아들였다는 뜻
- `path` — 메일이 거쳐 온 IP 경로(헤더의 Received에서 뽑음)
- `tls=F` — 암호화 없이 오갔다. `T`라면 STARTTLS로 암호화돼서 **내용이 보이지 않고**, 이 로그 대부분이 비어 있게 됩니다
- `fuids` — 첨부 파일이 있으면 `files.log`의 파일 ID([Zeek files.log](../../../network/zeek/files-log.md))

**[주의] 요즘 서버 간 SMTP는 대부분 STARTTLS로 암호화됩니다.** 그래서 인터넷에서 들어오는 메일을 네트워크 센서로 보는 경우는 줄었고, 메일 내용은 주로 **메일 서버·메일 보안 게이트웨이의 로그**, Microsoft 365의 **메시지 추적(Message Trace)**·Defender for Office 365의 메일 기록, Google Workspace의 **이메일 로그 검색**에서 봅니다. 네트워크 센서는 "누가 누구와 25번으로 연결했나"(`conn.log`) 수준의 신호에 더 쓰입니다.

### 네트워크에서 찾을 신호 { #network-signals }

| 보이는 것 | 왜 수상한가 | 확인할 것 |
| --- | --- | --- |
| **내부 PC가 외부의 25번 포트로 직접 연결** | 일반 PC는 회사 메일 서버(또는 클라우드 메일, 443)를 통해 보냄. 직접 25번으로 나간다면 스팸봇·악성코드의 메일 발송, 또는 유출 | 어떤 프로세스인지(Sysmon Event ID 3 — 네트워크 연결 기록), 연결 수와 목적지 수 |
| 외부에서 우리 MX가 아닌 서버의 25번으로 들어오는 연결 | MX와 메일 보안 게이트웨이를 **우회**해 검사를 피하려는 시도 | 그 서버가 왜 인터넷에 25번을 열어 두었는지 |
| 587·465·IMAP 로그인 실패가 많은 IP·계정에서 반복 | 비밀번호 대입(password spraying·brute force) | 실패 후 성공이 있었는지, 성공한 계정의 이후 활동 |
| 회사 안에 처음 보는 SMTP 서버 | 공격자가 세운 중계 서버, 설정이 잘못된 장비(복합기 등) | 누가 그 서버를 통해 보내는지, 열린 중계(open relay)인지 |
| EHLO 이름이 IP의 역방향 DNS(PTR)와 전혀 맞지 않음 | 정상 메일 서버는 보통 맞춰 둠. 스팸·악성 발송지는 대충 적는 경우가 많음 | 약한 신호. 다른 신호와 함께 판단 |

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    MUA·MSA·MTA·MDA 구조, 서버 간 중계는 SMTP 25번, MX로 받는 서버 찾기, 경계 MTA의 연결 IP가 기준점, 봉투와 헤더 주소의 차이, 서버마다 대화가 반복되며 헤더가 쌓인다는 점은 그대로입니다.

!!! info "[변경됨] 바뀐 것"
    - **서버 간 암호화가 기본이 됐습니다.** STARTTLS는 "가능하면 암호화"라서, 중간자가 `STARTTLS` 줄을 지우면 평문으로 떨어질 수 있었습니다. 이를 막으려고 **MTA-STS**(RFC 8461, "우리 서버는 반드시 TLS로만 받는다"를 HTTPS로 공개)와 **TLS-RPT**(RFC 8460, TLS 실패 보고), DNSSEC 기반의 **DANE**이 쓰입니다. 큰 메일 서비스 대부분이 이를 지원합니다.
    - **메일은 대부분 클라우드로 옮겨 갔습니다.** Microsoft 365, Google Workspace를 쓰면 제출과 읽기가 HTTPS(Graph API, MAPI/HTTP, Gmail API)로 이뤄지고, 분석은 네트워크 센서보다 **클라우드 메일 로그와 메시지 추적**이 중심입니다. 온프레미스 Exchange 2016·2019는 2025년 10월에 지원이 끝났습니다.
    - **SMTP AUTH의 기본 인증(아이디·비밀번호)이 퇴출 중입니다.** Exchange Online은 2026년 1월 갱신된 일정에서, 2026년 12월 말부터 기존 테넌트의 SMTP AUTH 기본 인증을 **기본값으로 끄고**(관리자가 다시 켤 수는 있음), 최종 제거 날짜는 2027년 하반기에 발표하기로 했습니다. OAuth가 표준입니다. 오래된 복합기·업무 앱이 비밀번호로 587에 로그인하는 구성은 공격자의 비밀번호 대입 표적이기도 합니다.
    - **SMTP 스머글링(SMTP Smuggling, 2023).** 서버마다 "메일 끝" 표시(`<CR><LF>.<CR><LF>`)를 조금씩 다르게 해석하는 점을 악용해, 메일 한 통 안에 **두 번째 가짜 메일을 숨겨** 다음 서버가 그것을 별도 메일로 받아들이게 하는 기법입니다. 정상 발송 서버를 거쳐 나가므로 SPF·DMARC를 통과한 사칭 메일을 만들 수 있었습니다. Postfix, Exim, Sendmail 등이 패치했으므로 메일 서버를 최신으로 유지하고 비표준 줄 끝을 거부하도록 설정합니다.
    - **클라우드 메일의 "내부 발송" 기능 악용.** 예를 들어 Microsoft 365의 Direct Send(인증 없이 MX로 바로 넣는 기능)를 악용해 회사 내부 사람인 척 보내는 피싱이 2025년에 보고됐고, 이를 거부하는 설정이 추가됐습니다. 쓰지 않는 무인증 경로는 닫습니다.
    - **메일로 오는 공격 모양이 바뀌었습니다.** 링크 대신 **QR 코드**(휴대폰으로 찍게 해 회사 보안 장비를 피함), 정상 클라우드 서비스의 공유 링크, 로그인 세션을 가로채는 AiTM 피싱, "명령어를 복사해 실행하라"는 ClickFix 미끼, 생성형 AI로 다듬은 자연스러운 문장의 BEC가 흔합니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **헤더의 `From:`이나 EHLO 이름을 보낸 사람의 증거로 믿지 않습니다.** 둘 다 보내는 쪽이 적는 값입니다. 기준은 우리 경계 MTA가 기록한 연결 IP와 인증 결과(SPF·DKIM·DMARC)입니다.
    - **회사 PC의 외부 25번 출구를 열어 두지 않습니다.** 메일 서버 외에는 25번 아웃바운드를 막는 것이 기본입니다.
    - **남의 서버에 telnet·swaks로 시험 메일을 보내지 않습니다.**
    - **"네트워크에 smtp.log가 없다 = 메일이 없다"로 보지 않습니다.** 암호화와 클라우드 때문에 안 보일 뿐입니다. 메일 플랫폼 로그를 SIEM에 넣어야 합니다.

## 확인 문제 { #quiz }

### 문제 1

다음 Zeek `smtp.log`에서 무엇이 수상합니까? 어떤 값은 믿을 수 있고, 어떤 값은 믿을 수 없습니까?

```
id.orig_h=198.51.100.25  id.resp_h=203.0.113.10  id.resp_p=25
helo=mail.victim.example
mailfrom=billing@pay-notice.example
rcptto=finance@victim.example
from="CFO Office" <cfo@victim.example>
subject=Urgent: updated bank details for invoice 2219
tls=F
```

??? success "정답과 해설"
    **믿을 수 있는 값:** `id.orig_h=198.51.100.25` — TCP 연결을 마친 실제 상대 IP. 이 IP가 `victim.example`(우리 회사)의 메일 서버인지 확인하면 됩니다. 우리 서버가 아니라면, 우리 회사 이름으로 외부에서 들어온 메일입니다.

    **믿을 수 없는 값(보내는 쪽이 적음):**

    - `helo=mail.victim.example` — 우리 회사 메일 서버인 척하는 이름. 연결 IP와 맞지 않음
    - `from="CFO Office" <cfo@victim.example>` — 화면에 보이는 보낸 사람. 우리 회사 CFO를 사칭
    - `subject` — 급하게, 계좌 변경을 요구하는 전형적인 BEC 문구

    **수상한 점 정리:** 봉투 보낸 사람(`pay-notice.example`)과 헤더 보낸 사람(`victim.example`)의 도메인이 다르고, 외부 IP가 우리 회사 이름(HELO와 From)을 쓰며, 내용은 계좌 변경 요청입니다. **BEC 사칭 메일로 판단**하고, 같은 `mailfrom`·연결 IP·제목으로 다른 받는 사람에게 간 메일을 찾고, 재무팀에 확인 절차(알려진 전화번호로 직접 확인)를 안내합니다. 다음 페이지들에서 볼 SPF·DMARC 결과도 확인합니다.

### 문제 2

방화벽 로그에서 업무용 PC `10.1.20.55`가 지난 1시간 동안 서로 다른 외부 IP 수백 곳의 **TCP 25번**으로 연결한 기록이 나왔습니다. 무엇을 의심하고, 무엇을 확인해야 합니까?

??? success "정답과 해설"
    **의심:** 일반 PC는 메일을 회사 메일 서버(또는 클라우드 메일의 443)를 통해 보냅니다. **외부 여러 곳의 25번으로 직접** 나간다는 것은, PC가 직접 MTA 노릇을 하며 메일을 뿌린다는 뜻입니다. 스팸봇(봇넷에 감염돼 스팸·피싱 발송)이나 메일을 이용한 정보 유출 악성코드를 의심합니다.

    **확인:**

    1. 어떤 프로세스가 연결했는지 — Sysmon Event ID 3(네트워크 연결: 어떤 프로그램이 어느 IP·포트로 연결했는지 기록)이나 EDR
    2. 그 프로세스의 실행 경로와 부모 프로세스(Sysmon Event ID 1, Windows Event ID 4688 — 새 프로세스 생성)
    3. 목적지 IP들이 각 도메인의 MX인지(스팸 발송 패턴)
    4. 방화벽이 실제로 허용했는지, 막혔는지. **원칙적으로 메일 서버가 아닌 장비의 25번 아웃바운드는 막아야** 하므로, 허용됐다면 정책 자체도 고칩니다
    5. PC 격리 후 조사, 회사 IP가 스팸 차단 목록에 올랐는지 확인

### 문제 3

동료가 "이 피싱 메일은 `From:`이 `notice@bank.example`이니까 그 은행 서버에서 온 게 맞다"고 합니다. SMTP 대화 구조를 근거로 왜 그렇게 말할 수 없는지 설명하고, 무엇을 봐야 하는지 말해 보세요.

??? success "정답과 해설"
    **근거:** `From:`은 SMTP의 `DATA` 명령 뒤, **메일 본체 안에** 보내는 쪽이 적는 헤더입니다. 서버는 배달에 봉투 주소(`MAIL FROM`, `RCPT TO`)만 쓰고, 원래의 SMTP에는 `From:`이 진짜인지 확인하는 장치가 없습니다. 그래서 누구든 `From: notice@bank.example`이라고 적어 보낼 수 있습니다. 편지지에 "은행 올림"이라고 쓰는 것과 같습니다.

    **봐야 할 것:**

    1. **우리 경계 MTA가 기록한 연결 IP** — 그 메일을 실제로 넘겨준 서버의 IP. 이 IP가 그 은행의 메일 서버인지(ASN, 역방향 DNS, 평판)
    2. **봉투 보낸 사람(Return-Path)** — `From:`과 도메인이 같은지
    3. **인증 결과(Authentication-Results 헤더)** — SPF, DKIM, DMARC가 통과했는지, 그리고 통과한 도메인이 `From:`의 도메인과 일치하는지(이후 페이지에서 자세히 다룸)
    4. 링크·첨부의 목적지와 평판
