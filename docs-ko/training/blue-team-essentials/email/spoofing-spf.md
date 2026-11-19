---
title: "이메일 위조와 SPF — SMTP가 아무나 믿는 이유, 위조 메일 주입, 세 가지 방어, SPF 동작 원리"
tags:
  - training
  - blue-team
  - email
  - smtp
  - spf
---

# 이메일 위조와 SPF — SMTP가 아무나 믿는 이유, 위조 메일 주입, 세 가지 방어, SPF 동작 원리 { #spoofing-spf }

!!! abstract "이 페이지에서 다루는 것"
    처음 만들어진 SMTP가 왜 보낸 사람 주소를 아무 확인 없이 받아 주는지, 그리고 위조 메일이 SMTP 대화에서 실제로 어떻게 생겼는지. 정상 사용자는 거쳐야 하는 로그인 단계를, 공격자가 받는 쪽 경계 MTA에 바로 연결해서 건너뛰는 방법(위조 메일 주입). 이 빈틈을 막으려고 만든 세 가지 표준 SPF·DKIM·DMARC가 각각 무엇을 확인하는지. 이어서 SPF를 자세히 봅니다. 받는 서버가 무엇과 무엇을 비교하는지, 왜 연결 IP가 기준점인지, `dig`로 SPF 레코드를 항목별로 읽는 법, 판정을 한 단계씩 따라가는 법, DNS 조회 10회 제한과 빈 조회(void lookup) 제한, 그리고 SPF가 **막지 못하는 것**. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 도메인과 IP는 모두 설명용 가상 값입니다. 앞 페이지 [이메일 헤더 읽기](email-headers.md)에 이어집니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. SMTP는 악용을 생각하지 않던 시절에 만들어져서, **보낸 사람이 정말 그 사람인지 확인하지 않는다.** 어느 서버든 `MAIL FROM`과 `From:`에 아무 주소나 적을 수 있다.
2. 정상 사용자는 보내기 전에 자기 회사 제출 서버에 **로그인(SMTP AUTH)** 해야 한다. 공격자는 **그 단계를 건너뛰고 받는 쪽 경계 MTA의 25번 포트에 바로 연결**한다. 받는 쪽은 인터넷 전체에서 오는 메일을 로그인 없이 받아야 하니 막을 수가 없다.
3. 빈틈을 메우는 세 가지 표준: **SPF**(도메인이 허락한 서버에서 보냈나?), **DKIM**(도메인이 서명했고 내용이 바뀌지 않았나?), **DMARC**(화면에 보이는 `From:` 도메인이 SPF나 DKIM을 통과한 도메인과 같은가, 아니면 어떻게 처리할까?).
4. SPF는 **경로 기반(path-based)** 이다. 받는 MTA가 **연결해 온 IP**를, 도메인이 **DNS TXT 레코드에 공개한 허용 발송지 목록**과 비교한다.
5. 연결 IP가 기준점인 이유: **위조한 IP로는 TCP 연결을 끝까지 맺을 수 없다.** 핸드셰이크 응답이 그 IP의 진짜 주인에게 가 버리기 때문이다.
6. **[정정]** SPF가 확인하는 것은 **봉투 보낸 사람(`MAIL FROM` / Return-Path)** 과 `HELO` 이름이지, **사용자가 보는 `From:` 헤더가 아니다.** 바로 이 틈을 DMARC가 막는다.
7. SPF 레코드는 **왼쪽부터 읽고, 처음 맞는 항목이 결과를 정한다.** 앞에 붙은 기호(`+ - ~ ?`)가 pass·fail·softfail·neutral을 뜻하고, 맨 끝 `all`이 나머지 전부를 받는다.
8. SPF 판정 한 번에 DNS 조회는 **최대 10번**(`include`, `a`, `mx`, `ptr`, `exists`, `redirect`), 빈 조회는 **최대 2번**. 넘으면 **permerror**가 되고 SPF가 조용히 무너진다.

## SMTP는 왜 이렇게 위조하기 쉬운가 { #why-spoofable }

SMTP의 첫 규격은 1982년에 나왔습니다. 그때 인터넷은 대학과 연구소 몇 곳을 잇는 작은 네트워크였고, 관리자들끼리 대부분 서로 아는 사이였습니다. 누군가 자기 정체를 속일 거라고는 생각하지 않았기 때문에, 이 프로토콜에는 **받는 서버가 "이 주소로 보낼 자격이 있는지 증명해 봐"라고 묻는 단계가 아예 없습니다.** 서버는 들은 대로 적어 둘 뿐입니다.

**옛날 우편**을 떠올려 보세요. 봉투 뒷면에 보내는 사람 주소를 아무렇게나 적어도 우체국은 그냥 배달해 줍니다. 그 주소에 정말 사는지 확인하는 직원은 없습니다. SMTP도 똑같습니다. "보내는 사람 주소"(`MAIL FROM`)도, "편지지 맨 위의 이름"(헤더의 `From:`)도 그냥 보내는 쪽이 타이핑한 글자입니다.

실제로 어떻게 생겼는지 봅시다. 공격자가 빌린 서버 `203.0.113.66`에서 `victim.example`의 메일 서버에 연결해, 그 회사 사장인 척합니다.

```
$ nc mx1.victim.example 25
220 mx1.victim.example ESMTP Postfix
EHLO mail.victim.example
250-mx1.victim.example
250-PIPELINING
250-SIZE 52428800
250-STARTTLS
250 8BITMIME
MAIL FROM:<ceo@victim.example>
250 2.1.0 Ok
RCPT TO:<finance@victim.example>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
From: "Jane Park (CEO)" <ceo@victim.example>
To: finance@victim.example
Subject: Urgent - payment needed today

Please process the vendor payment I sent earlier before 3pm. I'm in meetings, reply by email only.
.
250 2.0.0 Ok: queued as 4QzK7m2XyZ
QUIT
221 2.0.0 Bye
```

한 줄씩 봅니다.

- `nc mx1.victim.example 25` — 받는 회사의 MX에 서버끼리 쓰는 SMTP 포트(25번)로 TCP 연결을 엽니다. 메일 프로그램이 없어도 됩니다. SMTP는 그냥 글자로 주고받는 프로토콜이니까요.
- `220 ... ESMTP Postfix` — 서버가 인사하며 자기 소프트웨어를 밝힙니다.
- `EHLO mail.victim.example` — 공격자가 **자기를 피해 회사의 메일 서버라고 소개**합니다. 그냥 문자열이라 아무도 확인하지 않습니다.
- `250-...` 줄들 — 서버가 지원하는 확장 기능 목록입니다. 여기에 **`AUTH`(로그인)가 없다**는 점을 보세요. 받는 쪽 MX는 바깥 서버에게 로그인을 요구하지 않습니다.
- `MAIL FROM:<ceo@victim.example>` — **봉투 보낸 사람**을 사장으로 적습니다. 서버는 `250 Ok`, 아무 질문 없이 받아 줍니다.
- `RCPT TO:<finance@victim.example>` — 봉투 받는 사람, 재무팀. 역시 통과.
- `DATA` / `354` — 이제 메일 내용을 보내라는 뜻입니다.
- `From: "Jane Park (CEO)" <ceo@victim.example>` — 사용자가 **실제로 화면에서 볼 헤더 From**입니다. 이것도 그냥 글자입니다.
- `.` 한 글자만 있는 줄이 메일의 끝입니다. `250 2.0.0 Ok: queued as 4QzK7m2XyZ`는 **메일을 받아서 배달 대기열에 넣었다**는 뜻입니다.

이 대화 전체에서 정직한 정보는 딱 하나, 공격자가 타이핑하지 않은 것입니다. 바로 **TCP 연결이 들어온 IP 주소**이고, `mx1`은 이것을 Received 줄에 적습니다.

```
Received: from mail.victim.example (unknown [203.0.113.66])
        by mx1.victim.example (Postfix) with ESMTP id 4QzK7m2XyZ
        for <finance@victim.example>; Thu, 19 Nov 2026 01:12:40 +0000 (UTC)
```

앞 페이지에서 배운 대로 읽으면, EHLO 이름은 `mail.victim.example`이라고 주장하지만 역방향 DNS는 `unknown`이고 괄호 안 IP는 바깥 주소입니다. 하지만 별도의 확인 장치가 없으면, 재무팀 메일 화면에는 그냥 "Jane Park (CEO)"라고만 보입니다.

**[보충]** 요즘 메일 서버와 클라우드 메일 서비스 상당수는 이 공격이 너무 쉬워서 "인터넷에서 들어왔는데 우리 회사 도메인이라고 주장하는 메일은 거부하거나 격리"하는 규칙을 따로 둡니다. SMTP 자체에 그런 규칙이 없으니 **나중에 덧붙인** 것입니다.

## 위조 메일 주입: 로그인을 건너뛰는 법 { #injection }

정직한 직원은 메일을 어떻게 보낼까요? 메일 프로그램(MUA)이 회사의 **제출 서버**에 587번 포트로 연결하고, 그 서버는 무엇이든 받기 전에 **로그인을 요구**합니다.

```
$ openssl s_client -starttls smtp -connect smtp.victim.example:587 -quiet
250 smtp.victim.example
EHLO laptop-7q2
250-smtp.victim.example
250-AUTH LOGIN PLAIN
250-SIZE 52428800
250 8BITMIME
AUTH LOGIN
334 VXNlcm5hbWU6
amFuZUB2aWN0aW0uZXhhbXBsZQ==
334 UGFzc3dvcmQ6
************************
235 2.7.0 Authentication successful
MAIL FROM:<jane@victim.example>
250 2.1.0 Ok
```

- `openssl s_client -starttls smtp -connect ...:587` — 제출 포트에 연결하고 STARTTLS로 암호화를 켭니다(아래 로그인 정보가 네트워크에서 암호화되도록). `-quiet`은 인증서 출력을 숨깁니다.
- `250-AUTH LOGIN PLAIN` — 이 서버가 **로그인 기능(ESMTP AUTH 확장)을 제공**한다는 뜻입니다. 제출 서버에서는 필수입니다.
- `AUTH LOGIN` — 클라이언트가 로그인을 시작합니다.
- `334 VXNlcm5hbWU6` — 서버의 질문이 Base64로 와 있습니다. 풀면 `Username:`입니다([Base64](../http-analysis/base64.md)). Base64는 **암호화가 아니라 인코딩**일 뿐이라, 그래서 TLS를 먼저 켜야 합니다.
- `amFuZUB2aWN0aW0uZXhhbXBsZQ==` — Base64로 적은 사용자 이름(`jane@victim.example`).
- `334 UGFzc3dvcmQ6` — `Password:`. 클라이언트가 Base64로 비밀번호를 보냅니다(여기서는 가림).
- `235 2.7.0 Authentication successful` — 로그인 성공. 이제야 서버가 `MAIL FROM`을 받아 주고, 잘 설정된 서버라면 Jane이 그 보내는 사람 주소를 써도 되는지까지 확인합니다.

즉 **보내는 쪽**은 자기 사용자를 확인합니다. 문제는 **받는 쪽**입니다.

```
 정상 경로                                              공격자 경로
┌───────────┐ 로그인(AUTH) ┌───────────────┐          ┌───────────────┐
│ Jane의 MUA│─────────────▶│ victim.example│          │ 공격자 서버   │
└───────────┘   587번      │ 제출 서버/MTA │          │ 203.0.113.66  │
                           └──────┬────────┘          └──────┬────────┘
                                  │ SMTP 25                   │ SMTP 25 (로그인 없음)
                                  ▼ (로그인 없음)              │
                           ┌─────────────────────────────────────────┐
                           │  받는 회사의 경계 MTA (MX)              │
                           │  "우리 직원에게 오는 메일은 누구든 OK"  │
                           └─────────────────────────────────────────┘
```

받는 회사의 경계 MTA는 인터넷의 **어느 서버에게서든 로그인 없이 메일을 받아야만** 합니다. 그렇지 않으면 아무도 그 회사에 메일을 보낼 수 없으니까요. 그래서 이 서버는 "보내는 쪽에서 로그인 확인을 거친 메일"과 "공격자가 직접 들고 온 메일"을 구별하지 못합니다. 둘 다 똑같이 25번 포트로, 어떤 IP에서, 주장하는 보낸 사람을 달고 도착합니다. 받는 MTA에 그 주장을 확인할 방법이 없으면, 헤더에 적힌 대로 믿어 버립니다. 꽤 오랫동안 이메일은 정말로 이렇게 동작했습니다.

비유하면, 정직한 편지는 보내는 사람 동네 우체국을 거치고 거기서 직원이 신분증을 확인합니다. 위조 편지는 **받는 사람 동네 우체국까지 직접 들고 가서 투입구에 넣어 버립니다.** 받는 쪽 우체국은 신분증 확인 단계를 본 적도 없고, 건너뛰었다는 사실도 모릅니다.

## 출처를 확인하는 세 가지 방법 { #three-defences }

빈틈을 막는 아이디어는 단순하고, 각각 하나씩 표준이 되었습니다.

1. **보낸 서버가 그 도메인에게 미리 허락받았는지 확인** → **SPF**(Sender Policy Framework)
2. **보내는 쪽 게이트웨이가 개인 키로 메일에 서명**하고, 누구나 확인할 수 있게 공개 키를 공개 → **DKIM**(DomainKeys Identified Mail)
3. **사용자가 보는 주소가 속임수가 아닌지 확인** — 화면의 `From:` 도메인을 실제로 확인을 통과한 도메인과 묶고, 실패하면 어떻게 할지 도메인 주인이 정함 → **DMARC**(Domain-based Message Authentication, Reporting and Conformance)

| | SPF | DKIM | DMARC |
| --- | --- | --- | --- |
| 방식 | **경로 기반**(어디서 왔나?) | **서명 기반**(누가 서명했고 그대로인가?) | **정책 + 일치(alignment)**(사용자가 보는 것과 맞나?) |
| 확인하는 것 | 연결 IP vs 허용 목록 | 고른 헤더와 본문에 대한 서명 | SPF나 DKIM이 **`From:`과 같은 도메인으로** 통과했는지 |
| 확인 대상 신원 | 봉투 `MAIL FROM`(와 `HELO`) | 서명 안의 `d=` 도메인 | 헤더 `From:` 도메인 |
| 공개 위치 | 도메인의 TXT 레코드 | `selector._domainkey.도메인`의 TXT | `_dmarc.도메인`의 TXT |
| 전달(forwarding)을 거치면? | 대개 **깨짐**(IP가 바뀜) | 내용이 안 바뀌면 대개 **살아남음** | 둘 중 무엇이 살아남느냐에 달림 |
| 다루는 곳 | 이 페이지 | 다음 페이지 | 그 뒤 페이지 |

받는 서버는 세 가지 결과를 **`Authentication-Results:`** 트레이스 헤더에 적습니다. 이 형식은 2009년(RFC 5451)에 처음 표준이 됐고 몇 번 개정되어 지금은 RFC 8601이 현행입니다. 보통 이렇게 생겼고, 다음 페이지들에서 칸별로 뜯어봅니다.

```
Authentication-Results: mx1.victim.example;
       spf=fail smtp.mailfrom=victim.example;
       dkim=none;
       dmarc=fail (p=reject) header.from=victim.example
```

## SPF 한눈에 보기 { #spf-nutshell }

### 받는 MTA는 무엇과 무엇을 비교하나 { #what-is-compared }

받는 경계 MTA는 연결이 들어올 때마다 두 가지를 손에 쥡니다.

- **주장하는 도메인** — 봉투의 `MAIL FROM`에서 가져옵니다(`ceo@victim.example`이면 `victim.example`). 또는 `HELO`/`EHLO` 이름.
- **진짜 연결 IP** — TCP 연결 반대편의 주소.

그리고 DNS에 묻습니다. "`victim.example`은 어떤 서버가 자기 메일을 보내도 된다고 했지?" 그 답을 연결 IP와 비교합니다.

```
 공격자 203.0.113.66 ────┐                      ┌── victim.example의 DNS TXT:
                         │                      │   "v=spf1 ip4:198.51.100.0/28 ... -all"
 victim.example의 MTA ───┼──▶ 받는 쪽 MX ───────┤
 198.51.100.5            │     1. 누가 연결했나? (IP)
                         │     2. 누구라고 주장하나? (MAIL FROM 도메인)
                         │     3. 그 IP가 도메인의 목록에 있나?
                         └──▶  198.51.100.5 → 목록에 있음 → spf=pass
                               203.0.113.66 → 목록에 없음 → spf=fail
```

비유하면, 받는 우체국이 이제 회사마다 **"우리 편지는 이 우체국들에서만 나갑니다"라는 공인 목록**을 갖게 된 것입니다. 목록은 회사가 직접 공개합니다. victim.example에서 왔다는 편지가 목록에 없는 우체국에서 도착하면 표시를 해 둡니다.

### 왜 연결 IP는 믿을 수 있나 { #why-ip }

SMTP 대화의 나머지는 전부 보내는 쪽이 고른 글자입니다. 연결 IP만 다른 이유는, SMTP가 **TCP** 위에서 돌고 TCP는 3단계 핸드셰이크(three-way handshake) 없이는 연결을 열어 주지 않기 때문입니다.

```
공격자 (진짜 IP 203.0.113.66, 198.51.100.5인 척)
  1. SYN      src=198.51.100.5  →  mx1
  2. SYN-ACK  mx1  →  dst=198.51.100.5     ← 공격자가 아니라 진짜 198.51.100.5에게 감
  3. ACK      (공격자는 2단계의 순서 번호를 못 봤으니 올바르게 답할 수 없음)
  → 연결이 안 열림, 그러니 SMTP 대화도 못 함
```

공격자가 패킷 하나의 출발지 주소를 가짜로 적을 수는 있습니다. 하지만 답장은 그 주소의 진짜 주인에게 갑니다. 답장을 못 받으면 핸드셰이크를 끝낼 수 없고, `MAIL FROM`까지 갈 수도 없습니다. 그래서 `mx1`이 적은 IP는 진짜입니다.

**[보충]** "진짜"가 "무죄"라는 뜻은 아닙니다. 그 IP가 메일을 건넨 기계인 것은 확실하지만, 그 기계가 공격자가 빌린 저가 VPS일 수도, **공격자가 장악한 정상 서버**일 수도, **공격자가 계정을 만든 정상 메일 플랫폼**일 수도 있습니다. 뒤의 두 경우에는 SPF가 기꺼이 통과시킵니다. SPF가 답하는 질문은 "허락받은 서버가 건넸나?"이지 "이 메일이 안전한가?"가 아닙니다.

### [정정] SPF가 실제로 보는 "보낸 사람" { #which-from }

"SPF는 From 줄을 본다"는 설명을 흔히 보는데, SPF는 사용자가 보는 **헤더** `From:`을 보지 않습니다. RFC 7208은 SPF가 확인하는 신원을 두 가지로 정합니다.

| 신원 | 어디서 오나 | 언제 쓰나 |
| --- | --- | --- |
| `MAIL FROM` | SMTP 대화의 봉투 보낸 사람. 나중에 `Return-Path:`로 복사됨 | 일반 메일에서는 항상 |
| `HELO` | `HELO`/`EHLO`에 적은 이름 | 함께 확인하는 것이 권장됨. `MAIL FROM:<>`이 비어 있는 반송 메일(bounce)에서는 이것만 확인 |

이 차이는 아주 중요합니다. 공격자는 이렇게 할 수 있습니다.

```
MAIL FROM:<bounce@mailer.lookalike-pay.example>     ← 공격자 자신의 도메인, SPF 레코드도 정상
...
From: "Jane Park (CEO)" <ceo@victim.example>        ← 사용자가 보는 주소
```

SPF는 `lookalike-pay.example`을 확인하고, 공격자 자신의 목록에서 공격자 IP를 찾아 **pass**를 줍니다. 사용자는 여전히 `ceo@victim.example`을 봅니다. **SPF 혼자서는 화면에 보이는 주소에 대해 아무것도 해 주지 않습니다.** "SPF를 통과한 도메인이 `From:` 도메인과 같아야 한다"는 DMARC의 일치(alignment) 조건이 이 틈을 막습니다.

## SPF 레코드 읽기 { #reading-spf }

### dig로 찾아보기 { #dig }

SPF 레코드는 도메인 자체에 걸린 평범한 DNS **TXT** 레코드이고 `v=spf1`로 시작합니다([DNS 레코드](../dns/understanding-dns.md#records)).

```
$ dig +short TXT victim.example
"site-verification=Xa91kPq2v0m"
"v=spf1 ip4:198.51.100.0/28 ip6:2001:db8:25::/48 a:mail.victim.example mx include:_spf.mailvendor.example include:spf.crm-cloud.example -all"
```

- `dig` — DNS 조회 도구
- `+short` — 답만 짧게 출력
- `TXT victim.example` — 이 도메인의 TXT 레코드를 모두 요청. 도메인에는 TXT가 여러 개 있는 경우가 많습니다(사이트 소유 확인용 문자열 등). **그중 `v=spf1`로 시작하는 것만 SPF**이고, **딱 하나만** 있어야 합니다. `v=spf1`이 두 개면 **permerror**입니다.

### 레코드를 항목별로 { #mechanisms }

| 항목 | 뜻 | 드는 DNS 조회 수 |
| --- | --- | --- |
| `v=spf1` | 버전 표시. 맨 앞에 있어야 하고, 이것으로 이 TXT가 SPF임을 알림 | — |
| `ip4:198.51.100.0/28` | 이 범위(198.51.100.0~15)의 IPv4면 일치 | 0 |
| `ip6:2001:db8:25::/48` | 이 범위의 IPv6면 일치 | 0 |
| `a:mail.victim.example` | 그 호스트의 A/AAAA 레코드를 조회해서 연결 IP가 그중 하나면 일치. 그냥 `a`만 쓰면 "도메인 자신의 A 레코드" | 1 |
| `mx` | 도메인의 MX 서버들을 조회하고 그 주소까지 찾아서, 연결 IP가 메일 서버 중 하나면 일치 | 1 (+ MX 호스트 최대 10개의 주소 조회) |
| `include:_spf.mailvendor.example` | **다른 도메인의 SPF 레코드를 평가**해서, 그 결과가 pass면 이 항목이 일치. 메일 서비스 업체를 허락할 때 쓰는 방법 | 1 + 포함된 레코드가 쓰는 만큼 |
| `include:spf.crm-cloud.example` | 같은 방식으로 두 번째 서비스(회사 대신 메일을 보내는 CRM 플랫폼)를 허락 | 1 + 그만큼 |
| `-all` | `all`은 **모든 것**과 일치. 앞에 `-`가 붙었으니, 앞에서 안 맞은 건 전부 **fail** | 0 |

그 밖에 보게 될 것들:

- `exists:<도메인>` — 그 도메인에 A 레코드가 하나라도 있으면 일치. 매크로와 함께 고급 설정에 씁니다. 조회 1회.
- `ptr` — 역방향 DNS로 일치 판단. RFC 7208에서 **쓰지 말라고(deprecated)** 한 항목입니다(느리고 믿을 수 없음). 보이면 오래된 레코드라는 신호입니다.
- `redirect=<도메인>` — 항목(mechanism)이 아니라 **수정자(modifier)** 입니다. "여기서 아무것도 안 맞으면 저 도메인의 레코드를 대신 써라." 도메인을 많이 가진 조직이 한곳에서 관리할 때 흔합니다. 조회 1회.
- `exp=<도메인>` — 거부할 때 보여 줄 설명 문구를 가리키는 수정자. 드뭅니다.

### 앞에 붙는 기호: 일치하면 무슨 뜻인가 { #qualifiers }

항목마다 앞에 기호(qualifier)를 붙일 수 있고, 안 붙이면 `+`로 칩니다.

| 기호 | 일치했을 때 결과 | 받는 쪽에게 주는 뜻 |
| --- | --- | --- |
| `+` (기본) | **pass** | 허락됨 |
| `-` | **fail** | 분명히 허락 안 됨 — "하드 페일" |
| `~` | **softfail** | 아마 허락 안 됨. 받긴 하되 의심 |
| `?` | **neutral** | 도메인이 아무 말도 하지 않음 |

그래서 레코드 끝부분은 도메인 주인의 자신감을 보여 줍니다. `-all`("나머지는 확실히 우리 아님"), `~all`("나머지는 아마 우리 아님"), `?all`("말 안 할게요"), 그리고 위험한 `+all`("**세상 누구나 우리 이름으로 보내도 됨**" — SPF가 없는 것과 같고, 설정 실수나 레코드 변조의 신호일 때도 있음).

### include 따라가기 { #include }

`include`는 다른 목록을 가리키는 화살표라서, 받는 쪽은 그 목록도 가져옵니다.

```
$ dig +short TXT _spf.mailvendor.example
"v=spf1 ip4:192.0.2.0/25 include:_spf2.mailvendor.example ~all"

$ dig +short TXT _spf2.mailvendor.example
"v=spf1 ip6:2001:db8:ee::/48 ~all"

$ dig +short TXT spf.crm-cloud.example
"v=spf1 ip4:198.51.100.128/25 -all"
```

- 메일 업체의 목록에는 IPv4 범위가 있고, **또** 다른 목록을 include합니다. include는 겹겹이 들어갈 수 있습니다.
- 중요한 점: `include` 안쪽 레코드의 `~all`/`-all`은 "**여기서는 안 맞았음**"이라는 뜻일 뿐, 바깥 판정을 끝내지 않습니다. 바깥 레코드는 다음 항목으로 계속 갑니다.

### 판정을 한 단계씩 따라가기 { #walkthrough }

페이지 맨 위의 위조 메일을 넣어 봅시다. `MAIL FROM:<ceo@victim.example>`, 연결 IP `203.0.113.66`.

```
v=spf1                                   시작
ip4:198.51.100.0/28           203.0.113.66이 198.51.100.0-15 안에?         아니오
ip6:2001:db8:25::/48          IPv4 주소인데 IPv6 범위                     아니오
a:mail.victim.example         mail.victim.example → 198.51.100.5          아니오 (조회 1)
mx                            MX → mx1, mx2 → 198.51.100.2, .3            아니오 (조회 2)
include:_spf.mailvendor...    192.0.2.0/25 안에?                          아니오 (조회 3)
   include:_spf2.mailvendor   2001:db8:ee::/48 안에?                      아니오 (조회 4)
   ~all                       → 안쪽은 "안 맞음", 바깥으로 돌아감
include:spf.crm-cloud...      198.51.100.128/25 안에?                     아니오 (조회 5)
-all                          모든 것과 일치                              → FAIL
```

결과는 **`spf=fail`** 입니다. 받는 쪽은 이제 "victim.example이 이 IP는 자기 발송지가 아니라고 했다"는 것을 압니다. 그다음에 거부할지, 스팸함에 넣을지, 기록만 할지는 받는 쪽의 정책이고, 나중에 DMARC로 도메인 주인이 원하는 처리를 알려 줄 수 있습니다.

이번엔 회사 서버 `198.51.100.5`를 통해 보낸 Jane의 정상 메일입니다. 첫 항목 `ip4:198.51.100.0/28`에서 바로 일치하고, 기호가 없으니 `+`, **거기서 판정이 끝나** **`spf=pass`** 가 됩니다. 순서가 중요합니다. 처음 맞는 것이 이기므로 그 뒤는 조회조차 하지 않습니다.

### 조회 10회 제한과 빈 조회 { #limits }

SPF 확인 한 번에 받는 서버가 DNS를 너무 많이 조회하게 만들 수 있다면, 이를 악용해 메일 서버들이 DNS 서버를 공격하게 만들 수도 있습니다. 그래서 RFC 7208은 딱 정해 둡니다.

- 판정 한 번에 **DNS를 조회하는 항목은 최대 10개**. `include`, `a`, `mx`, `ptr`, `exists`, `redirect`가 각 1회이고, **겹쳐 들어간 include 안의 것도 모두 셉니다.** `ip4`, `ip6`, `all`은 0회.
- **빈 조회(void lookup)는 최대 2번** — 답이 없거나 NXDOMAIN이 돌아온 조회(예: 이미 없어진 도메인을 가리키는 `include`).
- 하나라도 넘으면 **`permerror`**("레코드가 고장 남").

예제를 세어 보면 `a`(1) + `mx`(1) + mailvendor `include`(1) + 그 안의 `include`(1) + crm-cloud `include`(1) = **10개 중 5개**. 괜찮습니다. 그런데 회사가 커지면서 메일 서비스, 마케팅 플랫폼, CRM, 고객지원, 인사 시스템을 하나씩 추가하고 각자 안에 include를 겹겹이 갖고 있으면 어느새 10을 넘습니다. 그러면 모든 받는 쪽이 `permerror`를 받고, 정책에 따라 그 도메인의 메일을 인증 안 된 메일로 다룹니다. **현실에서 가장 흔한 SPF 고장 원인 중 하나**이고, 대개 아무 문제 없어 보이는 작은 변경 뒤에 생깁니다.

**[보충]** 그 밖에 흔한 레코드 실수: `v=spf1` 레코드가 두 개(permerror), `ip4:198.51.100.0/33`이나 `inculde:` 같은 오타(permerror), 255자 넘는 레코드를 따옴표 묶음으로 나누지 않음, 몇 년 전에 끊은 서비스를 아직 `include` 중(그 서비스 도메인이 만료되어 **남이 등록**하면 자기 서버를 허락 목록에 넣을 수 있음).

## SOC에서 SPF를 쓰는 법 { #soc-use }

- **의심 메일 확인.** [경계 Received 줄](email-headers.md#trust-boundary)에서 연결 IP를, 봉투(`Return-Path:`)에서 도메인을 꺼냅니다. 받는 서버가 남긴 `Received-SPF:`/`Authentication-Results:` 결과를 읽고, 필요하면 직접 `dig TXT`로 왜 그런 결과가 나왔는지 봅니다. 은행이라고 주장하는데 은행 레코드에 없는 VPS IP에서 온 메일은 강한 신호입니다.
- **"거래처가 우리가 안 보낸 메일을 받았대요."** 먼저 우리 레코드를 봅니다. 있는지, `-all`이나 `~all`로 끝나는지, 조회가 10회 이하인지. SPF(와 DKIM·DMARC)가 없으면 다른 회사는 우리 진짜 메일과 위조 메일을 구별할 방법이 없습니다.
- **Return-Path와 From 비교.** `From:` 도메인과 전혀 상관없는 Return-Path 도메인으로 SPF가 pass된 것은, SPF는 만족됐는데 사용자는 속은 전형적인 모습입니다.
- **[보충] 정찰은 양쪽 모두 한다.** SPF 레코드는 한 회사를 대신해 메일을 보내도 되는 모든 서비스(메일 서비스, 마케팅 도구, CRM)를 보여 줍니다. 공격자는 이걸 읽고 어떤 플랫폼을 흉내 내거나 악용할지 정하고, 방어자는 잊혀진 서비스가 없는지 점검해야 합니다.
- **레코드 변경 감시.** 우리 SPF 레코드가 갑자기 바뀌면(특히 새 `include`나 `+all`) 경보를 울릴 만합니다. DNS 관리 계정이 털렸다는 뜻일 수 있습니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    SMTP 자체에는 여전히 보낸 사람 인증이 없고, 지금도 누구나 MX의 25번에 연결해 `MAIL FROM`과 `From:`을 아무렇게나 적을 수 있습니다. 세 겹의 해답(경로는 SPF, 서명은 DKIM, 일치와 정책은 DMARC)도 그대로입니다. SPF는 여전히 RFC 7208이 정의하고, 항목·기호·조회 10회 제한·빈 조회 2회 제한도 같습니다. 연결 IP가 보내는 쪽이 속일 수 없는 유일한 사실이라는 점도 변함없습니다.

!!! info "[변경됨] 바뀐 것"
    - **대형 메일 서비스가 인증을 의무로 만들었습니다.** 2024년 2월부터 Gmail과 Yahoo는 모든 발송자에게 SPF 또는 DKIM을, 대량 발송자(그 서비스 사용자에게 하루 약 5,000통 이상)에게는 SPF **와** DKIM **과** DMARC 레코드, 그리고 `From:` 도메인 일치를 요구합니다. Microsoft도 2025년 5월부터 Outlook.com·Hotmail·Live 주소로 대량 발송하는 쪽에 비슷한 규칙을 적용해, 지키지 않은 메일을 `550 5.7.515`로 거부합니다. 그래서 정상 발송자가 SPF조차 없는 경우는 드물어졌고, "SPF가 아예 없음"은 예전보다 더 강한 경고 신호가 됐습니다.
    - **`Authentication-Results:` 표준이 갱신됐습니다.** 예전 자료가 가리키던 버전은 대체되었고 지금은 RFC 8601이 현행 정의입니다. 분석가 눈에 보이는 헤더 모양은 같습니다.
    - **DMARC가 정식 표준 궤도(Proposed Standard)에 올랐습니다.** 오래 논의되던 "DMARCbis" 개정판이 2026년에 RFC 9989~9991로 발행되어, 정보성 문서였던 RFC 7489를 대체했습니다. SPF 자체는 그대로지만 DMARC의 일부 태그와 동작이 바뀌었고, DMARC 페이지에서 다룹니다.
    - **공용 클라우드 플랫폼 때문에 "pass"의 의미가 달라졌습니다.** 대부분의 조직이 대형 업체의 범위 전체를 넣습니다(클라우드 메일이나 마케팅 플랫폼의 `include:`). 그래서 SPF pass가 "그 플랫폼에서 왔다"는 것 정도만 증명하는 경우가 많고, 정상 플랫폼 악용과 탈취된 계정이 SPF를 통과하는 피싱의 큰 출처가 됐습니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **SPF pass를 "진짜 메일"로 읽지 않습니다.** 봉투 도메인이 그 IP를 허락했다는 뜻일 뿐입니다. 공격자는 SPF가 완벽한 비슷한 도메인을 등록하거나, 탈취한 계정으로 보냅니다. 항상 화면의 `From:`과 일치하는지(DMARC) 봅니다.
    - **SPF가 `From:` 헤더를 확인한다고 믿지 않습니다.** `MAIL FROM`/`HELO`를 확인합니다.
    - **`+all`을 공개하거나 `ptr`을 쓰지 않습니다.** `+all`은 인터넷 전체를 허락하고, `ptr`은 폐기 권고된 항목입니다.
    - **레코드가 조회 10회를 넘지 않게 합니다.** 우리 쪽에서는 아무 오류도 안 보인 채 `permerror`로 실패합니다. 새 서비스를 추가할 때마다 확인합니다.
    - **전달(forwarding)을 생각하지 않고 SPF fail만으로 메일을 거부하지 않습니다.** 전달된 메일은 전달 서버의 IP에서 오기 때문에 정당하게도 SPF에 실패합니다. 요즘은 (DKIM에 기댈 수 있는) DMARC가 판단하게 하는 것이 일반적입니다.

## 확인 문제 { #quiz }

### 문제 1

`payroll-portal.example`이 아래 레코드를 공개했습니다. `MAIL FROM:<notify@payroll-portal.example>`인 메일이 `192.0.2.140`에서 왔습니다. SPF 결과는 무엇이고, 판정은 어느 항목에서 끝납니까? `198.51.100.9`에서 왔다면요?

```
"v=spf1 ip4:192.0.2.128/26 include:_spf.sendgrid-like.example ~all"
```

(`_spf.sendgrid-like.example`에는 `"v=spf1 ip4:203.0.113.0/24 -all"`이 들어 있습니다.)

??? success "정답과 해설"
    **`192.0.2.140`에서 왔다면: `pass`, 첫 항목에서 끝납니다.** `192.0.2.128/26`은 192.0.2.128~191을 덮으니 .140이 일치합니다. 기호가 없으니 `+`(pass)이고, 판정은 바로 거기서 끝나서 `include`는 조회조차 하지 않습니다.

    **`198.51.100.9`에서 왔다면: `softfail`.** `192.0.2.128/26`에 없습니다. `include`를 평가하면 `203.0.113.0/24`에도 없으니 안쪽 레코드의 `-all`이 일치하지만, include 안에서는 이것이 "여기서는 안 맞음"이라는 뜻일 뿐 전체 fail이 아닙니다. 바깥 레코드로 돌아와 `~all`이 모든 것과 일치 → **softfail**("아마 허락 안 됨"). 안쪽 레코드의 `-all`이 결과를 하드 페일로 만들지 **않았다**는 점이 핵심입니다.

### 문제 2

이 레코드의 DNS 조회 수를 세어 보세요. 모든 받는 쪽은 어떤 결과를 받게 되고, 회사는 왜 눈치채지 못할 수 있습니까?

```
"v=spf1 a mx include:_spf.mailsuite.example include:mkt.example include:crm.example include:helpdesk.example include:hr-system.example include:billing.example ~all"
```

`_spf.mailsuite.example` 안에는 include가 3개 더 들어 있고, 나머지에는 없다고 가정합니다.

??? success "정답과 해설"
    `a` = 1, `mx` = 1, `include` 6개 = 6, 메일 서비스 레코드 안의 include 3개 = 3. **합계 11 — 제한 10을 넘습니다.**

    결과: 어느 IP에서 보냈든, 모든 메일에 대해 모든 받는 쪽이 **`permerror`**. 받는 쪽은 이 도메인의 SPF가 고장 났다고 보고, DMARC가 있다면 이제 DKIM 하나에만 기대게 됩니다. DKIM이 없는 발송 흐름은 스팸함이나 거부로 갈 수 있습니다.

    **왜 아무도 모르나:** 회사가 보내는 메일은 우리 쪽에서 아무 오류 없이 잘 나갑니다. 고장은 받는 쪽에서만 보입니다(그쪽 `Authentication-Results`, 또는 회사가 DMARC 집계 보고서를 읽는다면 거기서). 원인은 대개 서비스 하나를 무심코 추가한 것입니다. 해결: 안 쓰는 서비스 빼기, 바뀌지 않는 서버는 `a`/`mx` 대신 `ip4`/`ip6` 범위로 바꾸기, 일부 서비스를 자기 레코드를 가진 서브도메인으로 옮기기.

### 문제 3

재무팀 직원이 메일 하나를 신고했습니다. 헤더는 아래와 같고 SPF는 통과했습니다. 이 메일은 회사의 진짜 사장이 보낸 것입니까? 이것으로 SPF의 한계에 대해 무엇을 알 수 있습니까?

```
Return-Path: <bounce-7731@mail.lookalike-pay.example>
Received: from out-3.lookalike-pay.example (out-3.lookalike-pay.example [203.0.113.81])
        by mx1.victim.example with ESMTPS id 9Rt2Lq; Thu, 19 Nov 2026 02:41:10 +0000
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=mail.lookalike-pay.example
From: "Jane Park (CEO)" <ceo@victim.example>
Subject: Confidential - change of supplier bank details
```

??? success "정답과 해설"
    **거의 확실히 아닙니다.** 증거를 순서대로 읽어 봅니다.

    - `Received ... by mx1.victim.example` — 우리 경계 줄입니다. 메일은 우리 메일 서버가 아니라 스스로를 `out-3.lookalike-pay.example`이라고 부르는 `203.0.113.81`에서 왔습니다.
    - `spf=pass smtp.mailfrom=mail.lookalike-pay.example` — SPF는 봉투(`Return-Path`)의 도메인인 **`lookalike-pay.example`에 대해** 통과했습니다. 그 도메인은 공격자 것이고, 자기 SPF 레코드에 자기 서버를 넣어 두었습니다.
    - `From: ... <ceo@victim.example>` — 직원이 보는 주소는 **우리** 회사, 완전히 다른 도메인입니다. SPF는 이것을 보지도 않았습니다.

    **교훈:** SPF는 봉투 도메인만 인증합니다. 화면의 `From:`이 남의 도메인인 메일은 막지 못합니다. 그건 **DMARC 일치(alignment)** 의 몫입니다. `victim.example`이 DMARC 정책을 공개해 두면, `From: ...@victim.example`로 보이는 메일은 **victim.example 자신에 대해** SPF나 DKIM을 통과해야 하는데 이 메일은 그럴 수 없습니다. 또 하나, "우리 사장"이라는 메일이 우리 서버가 아닌 바깥에서 들어왔다면 내부 사칭 규칙으로도 막거나 표시해야 합니다. 다음 조치: 그 도메인과 IP 차단, 같은 Return-Path 도메인을 다른 메일함에서 검색, 재무팀에 계좌 변경 요청에 응하지 말라고 경고.
