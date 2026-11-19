---
title: "이메일 헤더 읽기 — 트레이스 헤더, 메시지 헤더, 본문, Received 줄 해석"
tags:
  - training
  - blue-team
  - email
  - smtp
---

# 이메일 헤더 읽기 — 트레이스 헤더, 메시지 헤더, 본문, Received 줄 해석 { #email-headers }

!!! abstract "이 페이지에서 다루는 것"
    받은 메일의 원문(source)이 어떤 세 부분(트레이스 헤더·메시지 헤더·본문)으로 되어 있는지, 각 부분을 누가 쓰는지, 그래서 어디까지 믿을 수 있는지. 메일 프로그램별로 원문과 헤더를 꺼내는 법과 안전하게 다루는 법. 그리고 Received 헤더를 아래에서 위로 읽어 메일의 길을 되짚고, Received 한 줄을 칸별로 해석하고, **우리 경계 서버가 쓴 줄**을 찾아 신뢰의 경계를 긋는 방법. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 도메인과 IP는 모두 설명용 가상 값입니다. 앞 페이지 [이메일 전달 구조와 SMTP](delivery-smtp.md)에 이어집니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 메일 원문은 위에서부터 **트레이스 헤더 → 메시지 헤더 → 본문** 순서다.
2. **트레이스 헤더**(Received 등)는 메일을 만진 **서버들이 하나씩 위에 덧붙인다.** 메시지 헤더와 본문은 **보낸 사람의 메일 프로그램(또는 제출 서버)이 쓴다.**
3. Received 줄은 **최신이 맨 위**다. 길을 따라가려면 **아래에서 위로** 읽는다.
4. Received 한 줄 = `from <EHLO 이름> (<PTR 이름> [<연결 IP>]) by <이 줄을 쓴 서버> with <프로토콜> id <ID> for <받는 사람>; <날짜>`.
5. 이 중 **괄호 안의 IP는 받는 서버가 직접 본 값**이라 그 서버를 믿는 한 진짜다. EHLO 이름은 보낸 쪽이 적은 값이다.
6. **우리 경계 MTA가 쓴 Received 줄**이 신뢰의 경계다. 그 줄의 `from` IP까지는 믿고, **그보다 아래 줄은 보낸 쪽이 지어낼 수 있다.**
7. 정상 메일은 아래에서 위로 **`by` → 다음 줄의 `from`이 이어지는 사슬**이 된다. 끊김, 시간 역행, 엉뚱한 서버가 단서다.
8. 의심 메일을 받을 때는 <strong>첨부 파일로 전달(.eml/.msg)</strong>받아야 헤더가 살아 있다. 일반 전달은 헤더를 잃는다.

## 왜 헤더를 읽어야 하나 { #why }

사용자가 메일 화면에서 보는 건 보낸 사람 이름, 제목, 본문 정도입니다. 그런데 앞 페이지에서 본 것처럼 이것들은 **모두 보내는 쪽이 마음대로 적을 수 있는 값**입니다. "이 메일이 정말 어디서 왔는가"를 판단하려면 화면 뒤에 숨은 <strong>원문(source)</strong>을 열어서, 서버들이 남긴 기록을 읽어야 합니다.

비유하면 **택배 송장의 배송 조회 기록**입니다. 상자에 붙은 "보내는 사람" 스티커는 아무나 쓸 수 있지만, 물류센터마다 찍힌 "○○ 터미널 입고, 14:02" 기록은 각 터미널이 직접 남긴 것입니다. 이메일의 Received 헤더가 바로 이 터미널 기록입니다. 다만 한 가지 함정이 있습니다. **우리 쪽 터미널에 도착하기 전의 기록은 보내는 쪽이 송장에 미리 적어 놓을 수도 있습니다.** 그래서 어디까지 믿을지 선을 긋는 법이 이 페이지의 핵심입니다.

## 메일 원문의 세 부분 { #three-parts }

아래는 가상의 회사 `victim.example`의 직원이 받은 메일의 원문입니다. 실제로 "원본 보기"를 누르면 이런 텍스트가 나옵니다.

```
Return-Path: <user1@freemail.example>
Received: from mx1.victim.example (10.0.5.20) by mbx01.victim.example with ESMTPS
        id 7Hq2; Wed, 18 Nov 2026 22:41:07 +0000
Received: from out-7.freemail.example (out-7.freemail.example [198.51.100.71])
        by mx1.victim.example with ESMTPS id 4QzK7m1abc
        for <jsmith@victim.example>; Wed, 18 Nov 2026 22:41:05 +0000
Received: from LAPTOP-7Q2 (static-25-113-0-203.isp.example [203.0.113.25])
        by smtp.freemail.example with ESMTPSA id e5so1909
        for <jsmith@victim.example>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);
        Wed, 18 Nov 2026 14:41:02 -0800 (PST)
Authentication-Results: mx1.victim.example; spf=pass smtp.mailfrom=freemail.example;
        dkim=pass header.d=freemail.example; dmarc=pass header.from=freemail.example
From: "Kim User" <user1@freemail.example>
To: <jsmith@victim.example>
Subject: Meeting notes
Date: Wed, 18 Nov 2026 17:41:00 -0500
Message-ID: <013501d48651$07300ed0$15902c70$@freemail.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_8812"
X-Mailer: Microsoft Outlook 16.0

------=_Part_8812
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Notes from today attached.

------=_Part_8812
Content-Type: application/pdf; name="notes.pdf"
Content-Disposition: attachment; filename="notes.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjcKJeLjz9MKMSAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMiAwIFI+Pgpl
------=_Part_8812--
```

| 부분 | 어디 | 누가 쓰나 | 무엇이 들어 있나 |
| --- | --- | --- | --- |
| **트레이스 헤더(Trace Headers)** | 맨 위 | 메일을 거쳐 간 **각 서버**가 자기 줄을 맨 위에 덧붙임 | `Received:`, `Return-Path:`, 인증 결과(`Authentication-Results:`), 서버·보안 제품이 붙이는 `X-...` 헤더 |
| **메시지 헤더(Message Headers)** | 그 아래 | **보낸 사람의 메일 프로그램**(MUA) 또는 제출 서버 | `From:`, `To:`, `Subject:`, `Date:`, `Message-ID:`, `MIME-Version:`, `Content-Type:`, `X-Mailer:` |
| **본문(Body)** | 빈 줄 다음, 맨 아래 | 보낸 사람 | 텍스트, HTML, 그림, 첨부 파일(대개 Base64) |

이 표의 "누가 쓰나" 칸이 곧 <strong>"얼마나 믿을 수 있나"</strong>입니다. 메시지 헤더와 본문은 보낸 사람이 쓴 것이라 거짓일 수 있고, 트레이스 헤더는 서버가 쓴 것이라 **그 서버를 믿는 만큼만** 믿을 수 있습니다.

### 트레이스 헤더 한 줄씩 { #trace-lines }

- `Return-Path: <user1@freemail.example>` — 앞 페이지의 **봉투 보낸 사람(MAIL FROM)**. 마지막으로 배달한 서버가 적어 넣습니다. `From:`과 도메인이 다르면 눈여겨봅니다
- 맨 위 `Received: from mx1.victim.example (10.0.5.20) by mbx01.victim.example` — 가장 최근 기록. 우리 회사 MX가 우리 메일함 서버(MDA)로 넘긴 내부 구간
- 가운데 `Received: from out-7.freemail.example (...[198.51.100.71]) by mx1.victim.example` — **우리 경계 MTA(mx1)가 쓴 줄.** 외부 서버 198.51.100.71이 우리에게 연결해 왔다는 기록. 이 줄이 신뢰의 경계입니다(아래에서 자세히)
- 맨 아래 `Received: from LAPTOP-7Q2 (...[203.0.113.25]) by smtp.freemail.example with ESMTPSA` — 가장 오래된 기록. 보낸 사람의 PC(`LAPTOP-7Q2`, IP 203.0.113.25)가 메일 서비스의 제출 서버에 로그인해서 보냈다는 기록. **이 줄은 freemail.example 쪽이 쓴 것이라, 우리는 freemail.example을 믿는 만큼만 믿을 수 있습니다**
- `Authentication-Results:` — 우리 mx1이 SPF·DKIM·DMARC를 검사한 결과(이후 페이지에서 자세히)

### 메시지 헤더 한 줄씩 { #message-lines }

- `From:` / `To:` / `Subject:` — 화면에 보이는 값. 보낸 쪽이 적음
- `Date: Wed, 18 Nov 2026 17:41:00 -0500` — 보낸 사람 **PC의 시계와 시간대**로 적힌 시간. -0500은 UTC보다 5시간 늦은 시간대. 보낸 사람이 사는 지역의 단서가 될 수 있지만 PC 설정일 뿐이라 바꿀 수 있습니다
- `Message-ID:` — 메일마다 붙는 고유 번호. `@` 뒤 도메인과 앞부분 모양은 **메일 프로그램마다 버릇**이 있습니다(이 예의 `$...$...$@` 모양은 Outlook의 버릇). `From:`은 Gmail인데 Message-ID 모양이 전혀 다른 프로그램의 것이면 단서가 됩니다
- `MIME-Version: 1.0` — 본문에 여러 종류(텍스트, HTML, 첨부)를 담는 MIME 형식을 쓴다는 표시
- `Content-Type: multipart/mixed; boundary="----=_Part_8812"` — "본문이 여러 조각으로 되어 있고, 조각 사이는 `------=_Part_8812` 줄로 나뉜다"
- `X-Mailer: Microsoft Outlook 16.0` — 보낸 메일 프로그램. `X-`로 시작하는 헤더는 표준이 아닌 추가 정보. 피싱 도구나 대량 발송 스크립트는 여기에 특이한 값을 남기거나 아예 빼기도 합니다

### 본문과 첨부 { #body }

- 빈 줄 — 헤더 끝, 본문 시작
- `------=_Part_8812` — 첫 조각 시작. `Content-Type: text/plain` = 평문 텍스트 조각
- 두 번째 조각 `Content-Type: application/pdf; name="notes.pdf"`와 `Content-Disposition: attachment` — **첨부 파일**이라는 뜻
- `Content-Transfer-Encoding: base64` — 파일이 **Base64로 바뀌어** 글자로 들어 있음. SMTP는 원래 글자만 나르는 프로토콜이라, 파일 같은 바이너리는 Base64로 바꿔서 실어 보냅니다
- `JVBERi0x...` — Base64 데이터. 앞부분 `JVBERi0`는 디코딩하면 `%PDF-`이므로 실제로 PDF임을 알 수 있습니다([Base64 앞글자로 파일 종류 짐작하기](../http-analysis/base64.md))
- `------=_Part_8812--` — 끝에 `--`가 붙으면 마지막 조각 끝

**[보충]** 본문에 `Content-Transfer-Encoding: quoted-printable`이 보이면 `=3D`(= 기호), `=20`(공백)처럼 바뀐 글자가 섞여 있습니다. 피싱 메일은 이 인코딩이나 Base64로 본문 HTML을 감싸서 단순한 키워드 검사를 피하기도 합니다. HTML 본문이 `text/plain`과 함께 오는 `multipart/alternative`라면, 두 버전의 내용이 서로 다른지(평문에는 정상 문장, HTML에는 피싱 링크)도 확인합니다.

## 원문과 헤더를 보는 법 { #how-to-view }

| 환경 | 방법 |
| --- | --- |
| Outlook(클래식 데스크톱) | 메일을 **별도 창으로 열고** → 파일(File) → 속성(Properties) → "인터넷 헤더(Internet headers)" 칸. 창이 작으니 `Ctrl+A`, 복사해서 편집기에 붙여 넣어 봄 |
| 새 Outlook·Outlook on the web | 메일의 `...` → 보기(View) → 메시지 세부 정보 보기(View message details) |
| Gmail | 메일 오른쪽 위 `⋮` → **원본 보기(Show original)**. 헤더·본문 전체가 평문으로 나오고 SPF·DKIM·DMARC 요약도 보임. "원본 다운로드"로 `.eml` 저장 가능 |
| Thunderbird 등 | 보기 → 메시지 소스(`Ctrl+U`) |
| 헤더 해석 도구 | Microsoft **Message Header Analyzer**(MHA), Google Admin Toolbox **Messageheader** — 헤더를 붙여 넣으면 Received 순서와 지연 시간을 표로 보여 줌 |

**[주의] 안전하게 다루는 법.**

- **사용자에게 "일반 전달"이 아니라 "첨부 파일로 전달"을 요청합니다.** 일반 전달(Forward)을 하면 원래 메일의 트레이스 헤더가 사라지고, 전달한 사람이 보낸 새 메일이 됩니다. Outlook의 "첨부 파일로 전달", Gmail의 "첨부파일로 전달", 또는 `.eml`/`.msg` 파일로 받습니다. 많은 회사는 "피싱 신고" 버튼이 이 일을 대신합니다
- 원문(평문) 보기는 비교적 안전하지만, **HTML로 렌더링하면 원격 이미지(추적 픽셀)가 불려 와 "이 주소는 살아 있고 열어 봤다"는 신호가 공격자에게 갈 수 있습니다.** 분석용 환경에서는 원격 콘텐츠 불러오기를 끕니다
- 링크는 누르지 않고 기록할 때 디팽(`hxxps`, `[.]`)합니다. 첨부는 격리된 환경이나 샌드박스에서만 엽니다
- 메일 원문에는 받는 사람의 개인정보가 들어 있으니, 공개 해석 사이트에 붙여 넣기 전에 조직 규정을 확인합니다

## Received 헤더로 메일의 길 되짚기 { #tracing }

### 아래에서 위로 읽는다 { #bottom-to-top }

서버는 메일을 받을 때마다 **자기 기록을 맨 위에 덧붙입니다.** 그래서 Received 줄은 **최신이 맨 위, 가장 오래된 것이 맨 아래**인 역순입니다. 메일이 실제로 지나간 순서대로 따라가려면 **맨 아래에서 시작해 위로** 올라갑니다.

다음은 외부 메일 서비스 사용자가 Microsoft 365를 쓰는 회사로 보낸 메일의 Received 줄만 뽑은 것입니다(설명을 위해 줄였습니다). 아래에서부터 번호를 붙였습니다.

```
[6] Received: from AM9PR01MB7421.eurprd01.prod.outlook.example by AM9PR01MB7421.eurprd01.prod.outlook.example; Wed, 18 Nov 2026 22:41:09 +0000
[5] Received: from DB8PR04CA0012.eurprd04.prod.outlook.example (2603:10a6:10:12a::22) by AM9PR01MB7421.eurprd01.prod.outlook.example; Wed, 18 Nov 2026 22:41:08 +0000
[4] Received: from DB1EUR03FT041.eop-EUR03.prod.protection.outlook.example (2603:10a6:10:12a:cafe::5) by DB8PR04CA0012.outlook.office365.example; Wed, 18 Nov 2026 22:41:07 +0000
[3] Received: from out-7.freemail.example (out-7.freemail.example [198.51.100.71]) by DB1EUR03FT041.mail.protection.outlook.example; Wed, 18 Nov 2026 22:41:06 +0000
[2] Received: by out-7.freemail.example with SMTP id e5so1909 for <jsmith@victim.example>; Wed, 18 Nov 2026 14:41:05 -0800 (PST)
[1] Received: from LAPTOP-7Q2 (static-25-113-0-203.isp.example [203.0.113.25]) by smtp.freemail.example with ESMTPSA; Wed, 18 Nov 2026 14:41:03 -0800 (PST)
```

아래에서 위로 이야기를 만들어 봅니다.

- **[1]** 보낸 사람의 노트북 `LAPTOP-7Q2`(IP 203.0.113.25, 역방향 DNS로는 어느 인터넷 회사의 고정 IP)가 메일 서비스의 제출 서버 `smtp.freemail.example`에 **로그인해서(ESMTPSA의 A)** 메일을 냈습니다. 메일 프로그램(Outlook, Thunderbird 등)으로 보냈기 때문에 PC 이름과 IP가 남았습니다. **웹메일로 보냈다면** 이 줄에는 대개 메일 서비스 자기 서버만 나오고, 사용자의 IP는 남지 않습니다
- **[2]** freemail.example 안의 다른 서버 `out-7`이 받았습니다. 이 줄에는 `from`이 없는데, 같은 회사 내부 서버 사이에서는 이렇게 생략되는 경우가 있고 걱정할 일은 아닙니다
- **[3]** **여기가 회사 경계를 넘는 곳입니다.** freemail.example의 경계 서버 `out-7`(IP 198.51.100.71)이 받는 회사의 Microsoft 365 입구(`...mail.protection.outlook...`, 받는 회사의 MX)에 연결했습니다. **이 줄은 받는 쪽(Microsoft 365)이 쓴 줄**이라, 198.51.100.71이 실제로 연결해 왔다는 것은 믿을 수 있습니다
- **[4]~[6]** Microsoft 365 내부 서버들이 차례로 넘겨 마지막 메일함 서버까지 갔습니다(내부 구간은 IPv6 주소가 흔합니다)

**정상 사슬 확인:** [3]의 `by DB1EUR03FT041`이 [4]의 `from DB1EUR03FT041`로 이어지고, [4]의 `by DB8PR04CA0012`이 [5]의 `from`으로 이어집니다. 이렇게 **아래 줄의 `by`가 바로 위 줄의 `from`이 되는 사슬**이 이어지면 자연스러운 경로입니다.

**시간 확인:** 각 줄 끝의 시간을 **UTC로 바꿔** 비교합니다. [1] `14:41:03 -0800` = UTC 22:41:03, [2] = 22:41:05, [3] 22:41:06, … [6] 22:41:09. 시간이 **아래에서 위로 갈수록 늘어나야** 정상입니다. 시간이 거꾸로 가거나, 한 구간에서 몇 시간씩 지체되거나(대기열·그레이리스트일 수도 있음), 시간대 표기가 이상하면 눈여겨봅니다. 서버마다 시간대가 달라서 UTC 변환 없이 비교하면 착각하기 쉽습니다.

### 어디까지 믿을 수 있나: 신뢰의 경계 { #trust-boundary }

여기가 이 페이지에서 가장 중요한 부분입니다.

- SMTP는 TCP라서, 어떤 서버가 "누가 나에게 연결해 왔다"고 적은 IP는 **그 서버가 정직하다면** 진짜입니다
- 우리는 **우리 경계 MTA**(또는 우리가 쓰는 클라우드 메일 서비스의 입구)는 정직하다고 믿습니다. 그러므로 **우리 경계 MTA가 쓴 줄의 `from` IP는 진짜**입니다. 위 예에서는 [3]
- 그런데 [1], [2]는 **보내는 쪽 서버가 쓴 줄**입니다. 보내는 쪽이 정상적인 대형 메일 서비스라면 그 기록도 대체로 믿을 만하지만, **보내는 쪽이 공격자라면 [1], [2] 같은 줄을 통째로 지어내서 메일에 미리 넣어 보낼 수 있습니다.** 우리 서버는 받은 메일 위에 자기 줄을 덧붙일 뿐, 아래 줄을 검사하지 않기 때문입니다

```
  ┌──────────── written by our side: trust ────────────┐
  [6] [5] [4]   internal hops (our servers / our cloud tenant)
  [3]  from ... [198.51.100.71]  by OUR border MTA   ← trust boundary: this IP is real
  └─────────────────────────────────────────────────────┘
  [2] [1]       written by the sender's side: claims only
```

그래서 분석 순서는 이렇습니다.

1. **우리 MX(경계)의 이름을 안다** — 앞 페이지의 MX 조회, 또는 회사가 쓰는 메일 서비스·보안 게이트웨이 이름
2. **위에서부터 내려가며 "우리 쪽 서버가 by에 있는 마지막 줄"을 찾는다** — 그 줄이 경계
3. **그 줄의 `from` IP를 조사한다** — 이 IP가 메일의 진짜 출처(적어도 우리에게 넘겨준 서버). ASN, 역방향 DNS, 평판, 그리고 이 IP가 `From:` 도메인의 정당한 발송 서버인지(SPF로 확인, 다음 페이지)
4. **그 아래 줄들은 "주장"으로만 본다** — 정상 대형 서비스면 참고로 쓰고, 이상한 서버면 의심

**[보충] 위조 Received 줄의 예.** 공격자가 아래처럼 보내면, 대충 보면 "은행 내부 서버에서 출발했다"는 이야기가 만들어집니다.

```
Received: from mail.bank.example (unknown [203.0.113.77]) by mx1.victim.example with ESMTP; Wed, 18 Nov 2026 22:50:12 +0000
Received: from internal-relay.bank.example ([10.40.1.12]) by mail.bank.example with ESMTP; Wed, 18 Nov 2026 22:50:10 +0000
Received: from ops-pc17.bank.example ([10.40.8.33]) by internal-relay.bank.example; Wed, 18 Nov 2026 22:50:09 +0000
```

하지만 맨 위 줄, 즉 **우리 mx1이 쓴 줄**을 보면 연결해 온 IP 203.0.113.77은 역방향 DNS가 없고(`unknown`), EHLO만 `mail.bank.example`이라고 주장합니다. 203.0.113.77이 실제로 bank.example의 메일 서버인지(그 도메인의 MX·SPF에 있는지, ASN이 그 은행 것인지) 확인하면 거짓이 드러납니다. **아래 두 줄은 공격자가 미리 써 넣은 장식일 수 있습니다.**

### Received 한 줄을 칸별로 읽기 { #anatomy }

경계에서 우리 서버가 쓴 줄 하나를 칸별로 나눠 봅니다.

```
Received: from mailer.promo-deals.example (unknown [203.0.113.149])
        by mx1.victim.example with ESMTP id 922034ljg
        for <jsmith@victim.example>; Wed, 18 Nov 2026 22:26:53 +0000
```

| 칸 | 값 | 누가 정했나 | 뜻 |
| --- | --- | --- | --- |
| `from` 바로 뒤 | `mailer.promo-deals.example` | **보낸 쪽**(EHLO/HELO로 스스로 밝힌 이름) | 거짓일 수 있음 |
| 괄호 안 앞쪽 | `unknown` | 받은 서버(연결 IP로 **PTR 조회한 결과**) | 역방향 DNS 결과. 없으면 `unknown`. EHLO 이름과 같을 수도 다를 수도 |
| 괄호 안 `[ ]` | `203.0.113.149` | 받은 서버(TCP 연결에서 **직접 본 값**) | **속일 수 없는 연결 IP** |
| `by` | `mx1.victim.example` | 받은 서버 | **이 줄을 쓴 서버.** 방금 메일을 넘겨받은 쪽 |
| `with` | `ESMTP` | 받은 서버 | 쓰인 프로토콜(아래 표) |
| `id` | `922034ljg` | 받은 서버 | 그 서버의 대기열 ID. 서버 로그와 맞춰 볼 때 쓰는 열쇠 |
| `for` | `<jsmith@victim.example>` | 받은 서버 | 봉투 받는 사람(RCPT TO). 선택 항목 |
| `;` 뒤 | 날짜·시간 | 받은 서버 | 받은 시각 |

이 예를 해석하면: **스스로를 `mailer.promo-deals.example`이라고 밝힌 IP 203.0.113.149가, 역방향 DNS도 없이, 우리 mx1에 암호화 없이(ESMTP, S 없음) 연결해 메일을 넘겼다.** EHLO 이름과 PTR이 맞지 않는 것(여기서는 PTR 자체가 없음)은 스팸·악성 발송지에서 흔한 모습이라 약한 신호가 됩니다.

`with` 칸의 프로토콜 표기는 이렇게 읽습니다(RFC 3848).

| 표기 | 뜻 |
| --- | --- |
| `SMTP` | 확장 없는 옛 SMTP(HELO) |
| `ESMTP` | 확장 SMTP(EHLO), 암호화 없음 |
| `ESMTPS` | ESMTP + **TLS 암호화**(STARTTLS) |
| `ESMTPA` | ESMTP + **로그인 인증**(사용자가 제출 서버에 로그인) |
| `ESMTPSA` | TLS + 로그인 인증. 사용자가 메일 프로그램으로 보낼 때 흔함 |
| `LMTP` | 메일함 서버로 넘기는 내부 전달용 |

**[보충] Received 말고도 볼 만한 트레이스 헤더.**

- `X-Originating-IP:` — 일부 웹메일 서비스가 붙였던 "사용자가 접속한 IP". 대형 서비스 다수는 개인정보 보호 때문에 지금은 붙이지 않습니다
- Microsoft 365의 `X-Forefront-Antispam-Report:` — `CIP:`(연결 IP), `SFV:`(스팸 판정 결과), `SCL:`(스팸 점수) 등이 들어 있어 경계 IP를 빠르게 찾는 데 유용합니다. `X-MS-Exchange-Organization-AuthAs: Anonymous`면 외부에서 인증 없이 들어온 메일, `Internal`이면 회사 내부에서 인증된 메일입니다
- `ARC-Seal:`, `ARC-Message-Signature:`, `ARC-Authentication-Results:` — 메일이 전달·메일링 리스트를 거치며 원래 인증 결과가 깨질 때, 중간 서버가 "내가 받았을 때는 인증이 통과했다"고 서명해 남기는 기록(ARC, 이후 페이지에서 설명)

### Zeek와 명령줄에서 보기 { #tools }

Zeek `smtp.log`는 Received 줄 일부를 따로 뽑아 둡니다.

```
first_received=from LAPTOP-7Q2 (static-25-113-0-203.isp.example [203.0.113.25]) by smtp.freemail.example ...
second_received=by out-7.freemail.example with SMTP id e5so1909 ...
path=203.0.113.10,198.51.100.71,203.0.113.25
```

- `first_received` / `second_received` — 헤더의 **맨 위** Received 줄 두 개(Zeek이 보는 시점에 가장 최근 것)
- `path` — Received 줄들에서 뽑은 IP 경로. 앞쪽이 최근

`.eml` 파일이 있다면 Python 표준 라이브러리로 Received 줄을 **실제 지나간 순서**로 뽑을 수 있습니다.

```
$ python3 -c '
import email, sys
msg = email.message_from_binary_file(open(sys.argv[1], "rb"))
for n, h in enumerate(reversed(msg.get_all("Received", [])), 1):
    print(n, " ".join(h.split()))
' suspicious.eml
```

- `import email, sys` — 메일 해석용 표준 모듈과 명령줄 인자용 모듈
- `email.message_from_binary_file(open(..., "rb"))` — `.eml` 파일을 바이너리로 열어 메일 객체로 해석
- `msg.get_all("Received", [])` — Received 헤더를 <strong>원문 순서(최신이 먼저)</strong>로 모두 가져옴. 없으면 빈 목록
- `reversed(...)` — 순서를 뒤집어 **가장 오래된 것부터**
- `" ".join(h.split())` — 여러 줄로 접힌 헤더를 한 줄로 펴서 출력
- `suspicious.eml` — 분석할 파일(`sys.argv[1]`로 전달)

결과는 이렇게 나옵니다.

```
1 from LAPTOP-7Q2 (static-25-113-0-203.isp.example [203.0.113.25]) by smtp.freemail.example with ESMTPSA id e5so1909 for <jsmith@victim.example> (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384); Wed, 18 Nov 2026 14:41:02 -0800 (PST)
2 from out-7.freemail.example (out-7.freemail.example [198.51.100.71]) by mx1.victim.example with ESMTPS id 4QzK7m1abc for <jsmith@victim.example>; Wed, 18 Nov 2026 22:41:05 +0000
3 from mx1.victim.example (10.0.5.20) by mbx01.victim.example with ESMTPS id 7Hq2; Wed, 18 Nov 2026 22:41:07 +0000
```

1번이 출발, 2번이 **우리 경계(mx1이 쓴 줄)**, 3번이 우리 내부 구간입니다. 2번의 `[198.51.100.71]`이 조사할 IP입니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    트레이스 헤더·메시지 헤더·본문의 세 부분, Received는 역순이고 아래에서 위로 읽는다는 점, `from EHLO (PTR [IP]) by ...` 형식, 연결 IP는 받는 서버가 직접 본 값이라는 점, **우리 경계 MTA가 쓴 줄이 신뢰의 경계**라는 원칙은 그대로입니다.

!!! info "[변경됨] 바뀐 것"
    - **클라우드 메일이 헤더를 길게 만듭니다.** Microsoft 365나 Google Workspace를 거치면 내부 Received 줄이 많고(IPv6 내부 주소가 흔함), 서비스별 `X-` 헤더(`X-Forefront-Antispam-Report`, `X-MS-Exchange-*`, `X-Google-*`)가 수십 줄 붙습니다. 사람이 다 읽기보다 MHA 같은 해석 도구로 Received 순서를 펼친 뒤, 경계 줄과 인증 결과에 집중합니다.
    - **보낸 사람 IP가 점점 덜 남습니다.** 대형 웹메일은 사용자의 IP를 헤더에 넣지 않고, 일부 서비스는 메일 프로그램으로 보낸 경우에도 첫 Received 줄에서 사용자 IP를 지웁니다. Apple의 "나의 이메일 가리기"처럼 중계 주소를 쓰는 서비스도 늘었습니다. "첫 Received 줄에 보낸 사람 IP가 있다"는 기대는 이제 자주 빗나갑니다.
    - **메일 보안 제품이 링크를 바꿔 씁니다.** Microsoft Defender의 Safe Links, 다른 보안 게이트웨이의 URL 재작성 때문에 본문의 링크가 `https://...safelinks.protection.outlook.com/?url=<원래 URL 인코딩>&...` 같은 모양으로 바뀌어 있습니다. 분석할 때는 `url=` 뒤를 URL 디코딩해서 **원래 주소**를 꺼내야 합니다.
    - **헤더 분석이 자동화되었습니다.** 사용자의 "피싱 신고" 버튼 → 메일 플랫폼(Defender for Office 365, Google Workspace)이 원본을 보존 → SOAR가 헤더·링크·첨부를 자동 추출해 평판 조회하는 흐름이 흔합니다. 그래도 자동 결과가 애매할 때 판단하는 것은 결국 이 페이지의 읽는 법입니다.
    - **생성형 AI로 본문이 자연스러워졌습니다.** 맞춤법 실수나 어색한 번역투로 피싱을 가려내는 방법은 약해졌습니다. 그럴수록 사람이 고칠 수 없는 **헤더의 기술적 기록**(경계 IP, 인증 결과, 사슬의 일관성)의 비중이 커집니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **맨 아래 Received 줄(가장 오래된 줄)을 "진짜 출발지"로 단정하지 않습니다.** 공격자가 써 넣을 수 있는 줄입니다. 기준은 우리 경계 MTA가 쓴 줄입니다.
    - **EHLO 이름을 출처로 믿지 않습니다.** 괄호 안의 `[IP]`를 봅니다.
    - **의심 메일을 일반 전달로 받지 않습니다.** 헤더가 사라집니다. 첨부로 전달받거나 메일 플랫폼에서 원본을 꺼냅니다.
    - **시간대를 맞추지 않고 시간을 비교하지 않습니다.** 모두 UTC로 바꿔서 봅니다.
    - **HTML 본문을 원격 콘텐츠가 켜진 상태로 열어 보지 않습니다.** 추적 픽셀이 공격자에게 신호를 보냅니다.

## 확인 문제 { #quiz }

### 문제 1

회사 `victim.example`의 MX는 `mx1.victim.example`입니다. 다음 Received 줄(원문 순서 그대로)에서 **신뢰의 경계**는 몇 번째 줄이고, 조사해야 할 IP는 무엇입니까? 그 아래 줄들은 어떻게 다뤄야 합니까?

```
Received: from mx1.victim.example (10.0.5.20) by mbx01.victim.example with ESMTPS; Wed, 18 Nov 2026 23:05:44 +0000
Received: from relay.payroll-portal.example (unknown [203.0.113.201]) by mx1.victim.example with ESMTP; Wed, 18 Nov 2026 23:05:42 +0000
Received: from hr-gw.victim.example ([10.0.9.4]) by relay.payroll-portal.example with ESMTP; Wed, 18 Nov 2026 23:05:40 +0000
Received: from HR-PC03.victim.example ([10.0.9.77]) by hr-gw.victim.example with ESMTPSA; Wed, 18 Nov 2026 23:05:39 +0000
```

??? success "정답과 해설"
    **경계는 두 번째 줄**입니다. 위에서부터 내려가며 `by`에 우리 서버가 있는 마지막 줄을 찾으면, 첫 줄(`by mbx01`, 우리 내부)과 두 번째 줄(`by mx1`, **우리 경계 MTA**)입니다. 세 번째 줄부터는 `by relay.payroll-portal.example` — 외부 서버가 쓴 줄입니다.

    **조사할 IP: `203.0.113.201`.** 우리 mx1이 직접 본 연결 IP입니다. 역방향 DNS도 없고(`unknown`), 암호화도 없습니다(ESMTP).

    **아래 두 줄**은 메일이 마치 **우리 회사 인사팀 PC(HR-PC03)와 내부 게이트웨이(hr-gw.victim.example)에서 출발한 것처럼** 보이게 만듭니다. 하지만 이 줄들은 외부의 `relay.payroll-portal.example` 쪽이 쓴 것이고, 우리 내부 서버가 외부 중계 서버를 거쳐 다시 우리에게 메일을 보낼 이유도 없습니다. **우리 회사 내부에서 보낸 것처럼 꾸민 위조 줄일 가능성이 높습니다.** 실제로 확인하려면 우리 hr-gw 서버 로그에 그 시각의 그 메일 기록이 있는지 찾아보면 됩니다(없으면 위조 확정).

### 문제 2

다음 Received 줄 하나를 칸별로 해석하고, 수상한 점을 말해 보세요.

```
Received: from mail.securebank.example (static-77-113-0-203.cheap-vps.example [203.0.113.77])
        by mx1.victim.example with ESMTP id 8Kd2Q
        for <finance@victim.example>; Wed, 18 Nov 2026 01:14:09 +0000
```

??? success "정답과 해설"
    - `from mail.securebank.example` — 보낸 쪽이 EHLO로 **스스로 밝힌 이름**. 은행 메일 서버라고 주장
    - `static-77-113-0-203.cheap-vps.example` — 우리 mx1이 연결 IP로 조회한 **역방향 DNS(PTR)**. 저가 VPS 업체의 이름
    - `[203.0.113.77]` — 우리 mx1이 **직접 본 연결 IP**(속일 수 없음)
    - `by mx1.victim.example` — 이 줄을 쓴 서버 = **우리 경계 MTA**. 그러므로 이 줄이 신뢰의 경계
    - `with ESMTP` — 암호화 없이(S 없음), 로그인 없이 연결
    - `id 8Kd2Q` — mx1의 대기열 ID. mx1 로그에서 이 메일을 찾는 열쇠
    - `for <finance@victim.example>` — 봉투 받는 사람. 재무팀
    - 시간 — UTC 01:14

    **수상한 점:** 은행이라고 주장하는 이름(EHLO)과 실제 연결 IP의 역방향 DNS(저가 VPS)가 맞지 않습니다. 진짜 은행이라면 보통 자기 회사나 대형 메일 서비스의 IP에서 보내고, 암호화(ESMTPS)도 씁니다. 받는 사람은 재무팀이라 BEC 사칭일 가능성이 있습니다. 다음 단계: 203.0.113.77의 ASN·평판 조회, 은행 도메인의 SPF에 이 IP가 있는지 확인, `Authentication-Results` 확인, 같은 IP에서 온 다른 메일 찾기.

### 문제 3

한 직원이 의심스러운 메일을 받았다며 <strong>일반 "전달"</strong>로 SOC 메일함에 보냈습니다. 받은 메일의 헤더를 열어 보니 Received 줄이 전부 회사 내부 서버뿐이고, 보낸 사람은 그 직원입니다. 왜 이렇게 됐고, 어떻게 해야 원래 메일을 분석할 수 있습니까?

??? success "정답과 해설"
    **이유:** 일반 전달은 원래 메일의 내용을 **새 메일에 복사해서 그 직원이 다시 보내는 것**입니다. 새 메일의 트레이스 헤더는 "직원 PC → 회사 메일 서버 → SOC 메일함" 경로만 남고, 원래 메일의 Received 줄, Return-Path, Authentication-Results는 사라집니다. 본문 안 링크도 메일 프로그램이 바꿔 버렸을 수 있습니다.

    **해결:**

    1. 직원에게 <strong>"첨부 파일로 전달"</strong>하거나 `.eml`/`.msg` 파일로 저장해 보내 달라고 요청(또는 회사의 "피싱 신고" 버튼 사용 안내)
    2. 관리자 권한이 있다면 메일 플랫폼에서 원본을 직접 꺼냄 — 예: Microsoft 365의 메시지 추적·Defender의 탐색기(Explorer)에서 메일 다운로드, Google Workspace의 조사 도구
    3. 원본의 Received 줄에서 우리 경계 MTA가 쓴 줄을 찾아 `from` IP를 조사하고, 같은 메일이 다른 직원에게도 갔는지 검색
    4. 직원 안내: 앞으로는 일반 전달 대신 신고 버튼이나 첨부 전달을 쓰도록
