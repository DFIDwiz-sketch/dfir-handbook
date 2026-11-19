---
title: "DMARC와 이메일 정리 — From 주소는 몇 개인가, 일치(alignment), 정책과 보고서, 인증이 증명하는 것"
tags:
  - training
  - blue-team
  - email
  - dmarc
---

# DMARC와 이메일 정리 — From 주소는 몇 개인가, 일치(alignment), 정책과 보고서, 인증이 증명하는 것 { #dmarc-summary }

!!! abstract "이 페이지에서 다루는 것"
    SPF와 DKIM이 남겨 둔 마지막 빈틈부터 봅니다. 메일에는 **"보낸 사람" 주소가 하나가 아니고**, 검사가 보는 주소와 사용자가 보는 주소가 서로 다릅니다. 엉뚱한 도메인으로 SPF와 DKIM을 둘 다 통과하는 위조 대화를 한 줄씩 따라가 봅니다. 이어서 DMARC입니다. 도메인 주인이 무엇을 공개하는지, **일치(alignment)** 가 무슨 뜻인지(SPF 일치, DKIM 일치, 느슨한(relaxed) 방식과 엄격한(strict) 방식), `_dmarc` 레코드를 태그별로(2026년 개정에서 새로 생기고 빠진 태그 포함), 받는 서버가 한 단계씩 어떻게 판정하는지, 결과가 `Authentication-Results:`에 어떻게 남는지, 그리고 **집계 보고서(aggregate report)** 읽는 법. 그다음 DMARC로도 못 막는 함정들(비슷한 도메인, 표시 이름, `Reply-To:`, 탈취된 계정)과 이메일 섹션 전체 정리, 분석 체크리스트를 다룹니다. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 도메인·IP·키·보고서 값은 모두 설명용 가상 값입니다. 앞 페이지 [SPF 결과와 DKIM](spf-results-dkim.md)에 이어지고, 이 페이지로 이메일 섹션이 끝납니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 메일에는 "보낸 사람" 주소가 (적어도) **두 개** 있다. **봉투(envelope)** 의 보낸 사람 `MAIL FROM`(RFC 5321, 나중에 `Return-Path:`가 됨)과 **헤더(header)** 의 `From:`(RFC 5322, 메일 프로그램이 화면에 보여 주는 것). 둘은 완전히 다를 수 있다.
2. **SPF는 봉투 도메인을, DKIM은 `d=` 도메인을 확인하고, 사용자는 `From:` 도메인을 본다.** 이 셋을 이어 주는 장치가 없으면, 공격자는 *자기* 도메인으로 두 검사를 통과하면서 화면에는 *우리* 도메인을 띄울 수 있다.
3. 이 셋을 이어 주는 것이 **DMARC**다. **SPF가 통과하고 일치하거나, DKIM이 통과하고 일치하면** DMARC를 통과한다. 둘 중 하나면 된다.
4. **일치(aligned)** 란 인증된 도메인이 `From:` 도메인과 맞는다는 뜻이다. **느슨한 방식(relaxed, 기본값)** = 같은 조직 도메인이면 됨(`mail.victim.example` ≈ `victim.example`), **엄격한 방식(strict)** = 이름이 정확히 같아야 함.
5. 도메인 주인은 **`_dmarc.<도메인>`** 에 TXT 레코드를 올려서, 실패하면 어떻게 할지(`p=none`, `quarantine`, `reject`)와 **보고서(report)** 를 어디로 보낼지(`rua=`)를 알린다.
6. **집계 보고서**가 DMARC가 준 가장 큰 선물이다. 주요 받는 업체들이 매일, 어떤 IP가 우리 이름으로 메일을 보냈고 통과했는지를 알려 준다. DMARC 전에는 도메인 주인이 누가 자기를 사칭하는지 볼 방법이 없었다.
7. SPF, DKIM, DMARC를 **모두** 통과했다는 것은 **"정말 그 도메인에서 왔다"** 는 증명이다. 내용이 안전하다는 증명은 **아니다.** 탈취된 계정, 비슷하게 만든 도메인, 악의적인 `Reply-To:`는 모두 통과한다.
8. 이메일 정리: SMTP는 처음부터 인증이 없다. 헤더는 우리 경계 MTA부터 안쪽만 믿는다. SPF/DKIM/DMARC를 **공개하면** 우리 이름으로 위조된 메일에서 **남을** 지켜 주고, 들어오는 메일에서 그것들을 **검사하면** **우리**를 지킨다. 어느 것도 내용은 보증하지 않는다.

## 마지막 문제: "From" 주소는 몇 개인가? { #how-many-from }

종이 편지를 떠올려 보세요. **봉투** 바깥에는 보내는 사람 주소가 적혀 있고, 우체국은 편지를 배달할 수 없을 때 그 주소로 돌려보냅니다. 봉투 **안의** 편지지에는 회사 로고가 박힌 머리글과 맨 아래 이름, 서명이 있습니다. 둘이 같아야 한다는 규칙은 어디에도 없습니다. 봉투에는 "시골읍 사서함 12호"라고 적고, 편지지 머리글에는 "대형은행 대표이사실"이라고 적어서 부칠 수 있습니다. 받는 사람은 봉투를 뜯어서 버리고, 편지지 머리글만 읽습니다.

이메일이 정확히 이렇게 생겼습니다. 서로 다른 표준 두 개에서 자라났기 때문입니다.

- **RFC 5321**은 **운반(transport)**, 즉 서버끼리 나누는 SMTP 대화를 정합니다. `MAIL FROM:` 뒤에 적는 주소가 **봉투 보낸 사람(envelope sender)** 이고, 정식 이름은 **RFC5321.MailFrom**입니다. 받는 서버는 배달할 때 이 주소를 `Return-Path:` 헤더로 저장하고, 반송 메일은 여기로 갑니다. ([봉투 주소와 헤더 주소](delivery-smtp.md#envelope-vs-header))
- **RFC 5322**는 **메일 형식(message format)**, 즉 `DATA` 안에 들어가는 내용을 정합니다. 거기 있는 `From:` 헤더가 **RFC5322.From**입니다. Outlook이든 Gmail이든 휴대폰 앱이든, 사용자에게 보여 주는 건 이쪽입니다.

그런데 SPF가 확인하는 건... 봉투입니다([SPF가 확인하는 "from"](spoofing-spf.md#which-from)). 검사하는 곳과 화면에 보여 주는 곳이 서로 다른 겁니다.

### 검사를 통과하는 위조 대화 { #spoofed-pass }

SPF와 DKIM이 있다는 걸 알게 된 공격자가 있다고 합시다. 이 공격자는 검사에 걸리는 대신 검사를 *통과하기로* 마음먹었습니다. 싸구려 도메인 `cheap-hosting.example`을 등록하고, 자기 서버 `203.0.113.66`을 적은 SPF 레코드를 올리고, DKIM 키도 만들어 두었습니다. 그리고 피해 회사의 MX에 연결합니다.

```
S: 220 mx1.victim.example ESMTP
C: EHLO mail.cheap-hosting.example
S: 250-mx1.victim.example Hello [203.0.113.66]
C: MAIL FROM:<bounce@cheap-hosting.example>
S: 250 2.1.0 Ok
C: RCPT TO:<accounts@victim.example>
S: 250 2.1.5 Ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: From: "Payroll Team" <payroll@victim.example>
C: To: accounts@victim.example
C: Subject: Updated bank details for November salary run
C: Date: Thu, 19 Nov 2026 08:12:40 +0000
C:
C: Please use the attached details from today.
C: .
S: 250 2.0.0 Ok: queued as 4QvX2m
```

중요한 줄만 하나씩 봅니다.

- `EHLO mail.cheap-hosting.example` — 공격자 서버가 자기 이름을 솔직하게 댑니다. 여기서는 숨길 게 없거든요.
- `MAIL FROM:<bounce@cheap-hosting.example>` — **봉투**에는 공격자 자기 도메인을 씁니다. SPF는 바로 이걸 확인하는데, 공격자의 SPF 레코드에 `203.0.113.66`이 들어 있으니 SPF는 **pass**가 됩니다.
- `From: "Payroll Team" <payroll@victim.example>` — `DATA` 안에서 공격자가 직접 타이핑한 **헤더** `From:`입니다. 피해 회사 자기 급여팀이라고 주장합니다. 이 줄은 아무도 확인하지 않았습니다.
- 공격자 서버는 보내기 전에 `d=cheap-hosting.example`로 서명도 붙입니다(대화에는 안 보이지만 `DATA` 안의 헤더로 들어갑니다). 그래서 DKIM도 **pass**입니다.

받는 서버가 SPF와 DKIM만 검사하고 DMARC는 **검사하지 않는다면**, 이렇게 적습니다.

```
Return-Path: <bounce@cheap-hosting.example>
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=cheap-hosting.example;
       dkim=pass header.d=cheap-hosting.example header.s=k1 header.b=Qm7Lx2Ra
From: "Payroll Team" <payroll@victim.example>
Subject: Updated bank details for November salary run
```

- `Return-Path:` — 우리 서버가 기록한 봉투 보낸 사람. 공격자 도메인입니다.
- `spf=pass smtp.mailfrom=cheap-hosting.example` — 진짜 pass입니다. 다만 **`cheap-hosting.example`에 대한** pass입니다.
- `dkim=pass header.d=cheap-hosting.example` — 이것도 진짜 pass, 역시 **`cheap-hosting.example`에 대한** 것입니다.
- `From: ... <payroll@victim.example>` — 사용자가 보는 것. 이 도메인에 대해서는 **어느 검사도** 아무 말을 하지 않았습니다.

사용자 화면에는 "Payroll Team, payroll@victim.example"이 뜹니다. 메일 프로그램이 SPF/DKIM만 보고 "확인됨" 표시를 띄운다면 오히려 믿음직해 보일 수도 있습니다. SPF나 DKIM의 버그가 아닙니다. 둘 다 자기 일은 정확히 했습니다. 빠진 건 **"인증한 도메인이 곧 화면에 보여 주는 도메인이어야 한다"** 는 규칙입니다.

**[보충]** "보낸 사람"처럼 생긴 칸은 이 둘보다 더 많고, 공격자는 전부 써먹습니다.

| 칸 | 누가 정하나 | 무엇에 쓰나 | 무엇이 확인하나 |
| --- | --- | --- | --- |
| `MAIL FROM` → `Return-Path:` | 보내는 서버(봉투) | 반송 | SPF |
| `HELO`/`EHLO` 이름 | 보내는 서버 | 서버 이름 | SPF(HELO 검사) |
| `DKIM-Signature:`의 `d=` | 서명하는 서버 | 누가 책임지는지 | DKIM |
| `From:` 주소 | 보내는 사람(헤더) | **사용자가 보낸 사람으로 보는 것** | DMARC(일치) |
| `From:` 표시 이름(`"Payroll Team"`) | 보내는 사람 | 주소 대신 보여 주는 친근한 이름 | **아무것도 없음** |
| `Reply-To:` | 보내는 사람 | 답장이 갈 곳 | **아무것도 없음** |
| `Sender:` | 보내는 사람 | "대신 보냄" 표시 | 없음(화면에 거의 안 나옴) |

## DMARC: 검사 결과를 화면의 From에 묶기 { #dmarc }

**DMARC**(Domain-based Message Authentication, Reporting and Conformance)는 SPF와 DKIM 위에 올라가는 규칙입니다. 새 암호 기술도, 새 경로 검사도 넣지 않습니다. 대신 도메인 주인이 DNS로 세 가지를 말할 수 있게 해 줍니다.

1. **"우리 도메인이라고 주장하는 메일은 일치 여부로 판단해 달라."** SPF와 DKIM 결과를 쓰되, **우리** 도메인, 즉 `From:`에 적힌 도메인에 대한 pass만 쳐 달라는 것.
2. **"실패하면 이렇게 해 달라."** 아무것도 안 함(`none`), 스팸함으로(`quarantine`), 받지 않음(`reject`).
3. **"보고서를 보내 달라."** 누가 우리 이름으로 메일을 보내고 있는지, 통과했는지 알려 달라는 것.

편지 비유로 돌아가면, DMARC는 은행이 공개적으로 이렇게 발표하는 것입니다. "우리가 보내는 진짜 편지는 모두 우리 우편실에서 부치거나 **또는** 우리 밀랍 봉인이 찍혀 있고, *그리고* 편지지 머리글에 우리 이름이 있습니다. 머리글은 우리 이름인데 둘 다 없는 편지는 버려 주시고, 그런 편지가 왔다고 저희에게 알려 주세요."

### 일치(alignment) { #alignment }

DMARC를 통과하려면 다음 중 **최소 하나**가 필요합니다.

- **SPF 일치 통과(SPF aligned pass)** — SPF 결과가 `pass`**이고**, SPF가 확인한 도메인(RFC5321.MailFrom)이 RFC5322.From 도메인과 맞는다.
- **DKIM 일치 통과(DKIM aligned pass)** — DKIM 서명 하나가 `pass`**이고**, 그 서명의 `d=` 도메인이 RFC5322.From 도메인과 맞는다.

왜 "그리고"가 아니라 "또는"일까요? 두 검사가 깨지는 평범한 상황이 서로 다르기 때문입니다. SPF는 메일이 **전달(forwarding)** 되면 깨지고(IP가 바뀌니까), DKIM은 메일링 리스트가 메일을 **고치면** 깨집니다. 둘 다 요구하면 정상 메일을 너무 많이 버리게 됩니다. 하나만 요구하면, 예를 들어 DKIM을 제대로 설정한 발송자는 전달을 거쳐도 살아남습니다.

"맞는다"는 얼마나 정확해야 할까요? 도메인 주인이 SPF(`aspf=`)와 DKIM(`adkim=`)에 대해 따로 고릅니다.

- **느슨한 방식(relaxed, `r`, 기본값)**: 두 도메인의 **조직 도메인(organizational domain)** 이 같으면 됩니다. 조직 도메인이란 등록된 도메인, 즉 누군가 실제로 돈 내고 산 부분입니다. `bounce.mail.victim.example`과 `victim.example`은 조직 도메인이 둘 다 `victim.example`이니 일치합니다.
- **엄격한 방식(strict, `s`)**: 이름이 **완전히 같아야** 합니다.

| `From:` 도메인 | 인증된 도메인 | 느슨한 방식 | 엄격한 방식 |
| --- | --- | --- | --- |
| `victim.example` | `victim.example` | 일치 | 일치 |
| `victim.example` | `bounce.victim.example`(SPF) | 일치 | **불일치** |
| `news.victim.example` | `victim.example`(DKIM `d=`) | 일치 | **불일치** |
| `victim.example` | `victim-example.example` | **불일치** | 불일치 |
| `victim.example` | `cheap-hosting.example` | **불일치** | 불일치 |

분석가에게는 네 번째 줄이 중요합니다. 비슷하게 생긴 이름은 **다른 조직 도메인**이라서 진짜와는 절대 일치하지 않습니다. (그렇다고 비슷한 도메인이 *자기 자신의* DMARC를 통과하지 못하는 건 아닙니다. [아래](#limits)에서 봅니다.)

받는 서버는 조직 도메인이 어디서 시작하는지 어떻게 알까요? 원래 DMARC는 **공개 접미사 목록(Public Suffix List)** 을 썼습니다. `.com`, `.co.uk`, `.gov.au`처럼 그 아래에 사람들이 이름을 등록하는 접미사를 모아 둔 공동 목록입니다. **[변경됨]** 2026년 개정판은 이걸 **DNS 트리 워크(DNS tree walk)** 로 바꿨습니다. 받는 서버가 이름을 한 칸씩 위로 올라가며 `_dmarc` 레코드를 찾고, 도메인은 새 태그 `psd=`로 "나는 공개 접미사다" 또는 "나는 조직 도메인이다"라고 스스로 표시할 수 있습니다. 분석가 입장에서는 실제 사례 거의 전부에서 답이 똑같습니다.

이제 앞의 위조 대화에 적용해 봅시다.

| 검사 | 결과 | 확인한 도메인 | `From:` 도메인 | 일치? |
| --- | --- | --- | --- | --- |
| SPF | pass | `cheap-hosting.example` | `victim.example` | 아니오 |
| DKIM | pass | `cheap-hosting.example` | `victim.example` | 아니오 |
| **DMARC** | **fail** | | | 일치하는 pass가 하나도 없음 |

### DMARC 레코드 { #dmarc-record }

도메인 주인은 도메인 앞에 `_dmarc.`를 붙인 이름에 TXT 레코드로 정책을 올립니다.

```
$ dig +short TXT _dmarc.victim.example
"v=DMARC1; p=quarantine; sp=reject; np=reject; adkim=r; aspf=r; rua=mailto:dmarc-agg@victim.example,mailto:victim@reports.dmarc-vendor.example; ruf=mailto:dmarc-forensic@victim.example; fo=1"
```

- `dig +short TXT _dmarc.victim.example` — DNS에 `_dmarc.victim.example`의 TXT 레코드를 물어보고, 답만 짧게 출력합니다. 답이 비어 있으면 그 도메인에는 **DMARC 정책이 없는** 것이고, 받는 쪽은 자기 판단에 맡깁니다.

태그별로 봅니다.

| 태그 | 예 | 뜻 |
| --- | --- | --- |
| `v=` | `DMARC1` | 버전. 맨 앞에 와야 함. 2026년 개정 뒤에도 그대로 `DMARC1` |
| `p=` | `quarantine` | DMARC 실패 시 도메인 자체에 대한 **정책**: `none`(지켜보기만), `quarantine`(의심 메일로 취급, 보통 스팸함), `reject`(SMTP 단계에서 거부) |
| `sp=` | `reject` | 자기 레코드가 없는 **서브도메인**(`아무거나.victim.example`)에 대한 정책. 없으면 `p=`를 따름 |
| `np=` | `reject` | **[변경됨] 2026년 개정에서 새로 생김:** **존재하지 않는** 서브도메인(DNS에 아예 없는 이름, 예: `payroll-secure.victim.example`)에 대한 정책. 공격자는 서브도메인을 지어내길 좋아하는데, 이걸로 막습니다 |
| `adkim=` | `r` | DKIM 일치 방식: `r` 느슨(기본) 또는 `s` 엄격 |
| `aspf=` | `r` | SPF 일치 방식: `r` 느슨(기본) 또는 `s` 엄격 |
| `rua=` | `mailto:...` | **집계** 보고서(매일 오는 XML 요약)를 보낼 곳. 쉼표로 여러 주소 가능 |
| `ruf=` | `mailto:...` | **실패** 보고서(실패한 메일 하나하나의 사본이나 일부)를 보낼 곳. 요즘 이걸 보내 주는 곳은 드묾 |
| `fo=` | `1` | 실패 보고서를 언제 만들지: `0`(기본) 전부 실패했을 때만, `1` 하나라도 실패하면, `d`/`s`는 DKIM/SPF 실패 시 |
| `pct=` | `50` | **[변경됨] 2026년 개정에서 빠짐.** "실패한 메일 중 N%에만 정책을 적용"이라는 뜻이었음. 옛 레코드에 아직 보이지만, 갱신된 받는 서버는 무시함 |
| `t=` | `y` | **[변경됨] 2026년 개정에서 새로 생김:** 시험 모드. `t=y`는 "`p=`는 적용하지 말고 보고만 해 달라", `t=n`(기본)은 적용. 흔히 쓰던 `pct=0` 꼼수를 대신함 |
| `psd=` | `n` | **[변경됨] 2026년 개정에서 새로 생김:** 트리 워크에서 이 도메인을 공개 접미사(`y`) 또는 조직 도메인(`n`)으로 표시. 기본값 `u`(지정 안 함) |

보고서 형식과 주기를 정하던 `rf=`와 `ri=` 태그도 개정에서 빠졌습니다. 옛 레코드에서는 아직 보이고, 있어도 해는 없습니다.

**[보충]** 두 번째 `rua` 주소가 **다른 도메인**(`reports.dmarc-vendor.example`, 보고서 분석 업체)에 있다는 점을 보세요. 아무나 남의 메일함으로 보고서를 쏟아붓지 못하게, 받는 서버는 그 도메인이 허락을 공개했을 때만 거기로 보냅니다.

```
$ dig +short TXT victim.example._report._dmarc.reports.dmarc-vendor.example
"v=DMARC1"
```

- 이름은 `<보고서 대상 도메인>._report._dmarc.<보고서를 받는 도메인>` 모양으로 만듭니다.
- `"v=DMARC1"` — "네, victim.example에 대한 보고서를 받겠습니다"라는 뜻. 답이 없으면 받는 서버는 거기로 보내면 안 됩니다.

분석가로서 정책 레코드를 한눈에 읽는 법:

- `p=none` — 주인이 지켜보기만 하는 중. 이 도메인을 쓴 위조 메일은 **어디에서도 DMARC로 막히지 않습니다.** 아주 흔합니다. 대형 업체의 발송 규칙을 맞추려고 `p=none` 레코드만 하나 올려 두고 거기서 멈춘 도메인이 많습니다.
- `p=quarantine` — 실패한 메일은 스팸함으로. 사용자가 스팸함에서 위조 메일을 찾아 받은편지함으로 옮겼다면, 처음에 스팸함에 있던 이유가 이것입니다.
- `p=reject` — 실패한 메일은 거부. 이 도메인 그대로를 쓴 위조 메일이 받은편지함에 왔다면, 받는 쪽이 DMARC를 적용하지 않거나, 메일이 실제로 통과한 것(탈취된 계정, 정상 플랫폼 악용)입니다.
- 레코드 없음 — 공개된 정책이 없음. 자체 규칙을 적용하지 않는 받는 쪽에는 마음대로 위조해 보낼 수 있습니다.

### 받는 서버의 DMARC 판정, 한 단계씩 { #evaluation }

들어오는 메일마다 받는 쪽 경계 MTA는:

1. **`From:` 도메인을 뽑습니다.** `From:`이 없거나, `From:` 헤더가 **두 개 이상**이거나, 한 헤더에 서로 다른 도메인의 주소가 여러 개 있으면, 많은 받는 서버가 거부하거나 실패로 다룹니다. 정상 메일에는 `From:` 헤더가 딱 하나 있습니다.
2. **정책을 찾습니다.** `_dmarc.<From 도메인>`의 TXT. 없으면 조직 도메인의 레코드로 올라가서(거기 있는 `sp=`/`np=`를 씁니다) 찾습니다.
3. 이미 계산해 둔 **SPF 결과**를 가져와, SPF 도메인이 일치하는지 봅니다.
4. **DKIM 결과**를 하나씩 가져와, 통과한 서명 중 `d=`가 일치하는 게 있는지 봅니다.
5. **판정합니다.** 일치하는 pass가 하나라도 있으면 → `dmarc=pass`. 아니면 → `dmarc=fail`.
6. **정책을 적용합니다**(`none`/`quarantine`/`reject`, 또는 자기만의 예외 규칙). 그리고 무엇을 했는지 기록합니다.
7. `rua=`로 보낼 **일일 집계 보고서에 한 줄을 남기고**, 필요하면 `ruf=`로 실패 보고서를 보냅니다.

앞의 위조 메일이라면, `victim.example`이 `p=quarantine`을 공개한 상태에서 트레이스 헤더에 이렇게 남습니다.

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=cheap-hosting.example;
       dkim=pass header.d=cheap-hosting.example header.s=k1 header.b=Qm7Lx2Ra;
       dmarc=fail (p=quarantine dis=quarantine) header.from=victim.example
```

- `dmarc=fail` — 어느 pass도 `victim.example`과 일치하지 않았습니다.
- `p=quarantine` — 주인이 공개한 정책.
- `dis=quarantine` — **처리(disposition)**, 즉 받는 쪽이 실제로 한 일입니다. `p=`와 다를 수 있습니다. 받는 쪽이 자기 예외 규칙을 적용할 수 있기 때문입니다(예: 잘 아는 전달 서버, 또는 옛 `pct=` 표본 적용). `p=reject`인데 `dis=none`이면 왜 그런지 따져 봐야 합니다.
- `header.from=victim.example` — DMARC가 지킨 도메인.

정책이 `p=reject`였다면 메일은 아예 배달되지 않았을 겁니다. 공격자 서버는 `DATA` 끝에서 이런 답을 받았겠죠.

```
S: 550 5.7.1 Unauthenticated email from victim.example is not accepted due to domain's DMARC policy
```

- `550` — 영구 실패. 다시 보내지 말라는 뜻.
- `5.7.1` — "배달 허락 안 됨 / 보안 정책" 계열의 확장 상태 코드(enhanced status code).
- 문구는 업체마다 다르지만, 보내는 쪽은 반송 메일에서 이걸 보고, 우리는 **우리 메일 플랫폼 로그**에서 거부된 수신 시도로 봅니다. 막힌 위조 캠페인의 흔적은 이 로그에만 남는 경우가 많습니다.

비교를 위해, 진짜 급여 시스템이 보낸 메일입니다. 호스팅 플랫폼을 거쳐 보내지만, 자기 도메인으로 DKIM을 설정해 두었습니다.

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=bounce.mailer-hub.example;
       dkim=pass header.d=victim.example header.s=hub2026 header.b=aR5tW0qL;
       dkim=pass header.d=mailer-hub.example header.s=k1 header.b=Zx81PqWe;
       dmarc=pass (p=quarantine dis=none) header.from=victim.example
```

- SPF는 통과했지만 플랫폼의 반송 도메인에 대한 것 → **불일치**.
- **첫 번째** DKIM 서명은 `victim.example`이 했으니 → **일치 통과**. 이것 하나로 DMARC가 통과합니다.
- 두 번째 서명은 플랫폼 자기 것입니다. 문제는 없지만 DMARC와는 상관없습니다.
- `dis=none` — 통과했으니 아무것도 안 함.

"SPF는 불일치, DKIM은 일치" 모양은 외부 플랫폼을 통해 보낸 메일에서 아주 평범합니다. DMARC가 둘 중 하나만 요구하는 이유가 바로 이것입니다.

### 집계 보고서: 누가 우리 이름을 쓰는지 보기 { #reports }

DMARC가 없던 시절, 도메인 주인은 다른 나라 누군가가 자기 이름으로 피싱 메일 백만 통을 보내고 있어도 알 길이 없었습니다. `rua=`를 설정하면, 참여하는 받는 업체마다 매일 **집계 보고서**를 보내 줍니다. `From:`에 우리 도메인을 쓴 메일을 보낸 출발지 IP를 모두 요약한 XML 파일이고, 보통 zip이나 gzip으로 압축해 메일에 첨부해 옵니다.

줄여 놓은 예입니다.

```xml
<feedback>
  <report_metadata>
    <org_name>bigmail.example</org_name>
    <email>noreply-dmarc@bigmail.example</email>
    <report_id>8842137765</report_id>
    <date_range><begin>1795046400</begin><end>1795132799</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>victim.example</domain>
    <adkim>r</adkim><aspf>r</aspf>
    <p>quarantine</p><sp>reject</sp>
  </policy_published>
  <record>
    <row>
      <source_ip>198.51.100.24</source_ip>
      <count>18233</count>
      <policy_evaluated>
        <disposition>none</disposition><dkim>pass</dkim><spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>victim.example</header_from></identifiers>
    <auth_results>
      <dkim><domain>victim.example</domain><selector>hub2026</selector><result>pass</result></dkim>
      <spf><domain>bounce.mailer-hub.example</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.66</source_ip>
      <count>412</count>
      <policy_evaluated>
        <disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>victim.example</header_from></identifiers>
    <auth_results>
      <dkim><domain>cheap-hosting.example</domain><selector>k1</selector><result>pass</result></dkim>
      <spf><domain>cheap-hosting.example</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>
```

읽는 법:

- `<org_name>bigmail.example</org_name>` — 보고서를 **누가** 썼는지. 메일을 받은 업체입니다.
- `<date_range>` — 기간, 유닉스 초 단위. `1795046400` → `2026-11-19 00:00:00 UTC`, `1795132799` → 같은 날 `23:59:59`. `date -u -d @1795046400`으로 바꿔 볼 수 있습니다.
- `<policy_published>` — 받는 업체가 검사할 때 찾아낸 우리 정책. DNS를 바꿨는데 반영이 안 된 걸 알아챌 때 씁니다.
- 첫 번째 `<record>`: `198.51.100.24`가 **18,233**통을 보냈습니다. `policy_evaluated`는 **DMARC 수준의** 결과입니다. `dkim>pass`는 *일치하는* DKIM이 통과했다는 뜻이고, `spf>fail`은 SPF가 일치하지 않았다는 뜻입니다(원래 SPF 자체는 통과했어도요 — `auth_results` 참고). 처리는 `none`. 우리가 쓰는 정상 호스팅 플랫폼입니다.
- 두 번째 `<record>`: `203.0.113.66`이 `victim.example`이라고 주장하는 메일을 **412**통 보냈습니다. 원래 SPF와 DKIM은 둘 다 통과했지만 **`cheap-hosting.example`에 대해서**였고, 그래서 DMARC 수준에서는 둘 다 `fail`입니다. 처리는 `quarantine`. 이게 위조 캠페인입니다.

조심할 함정: `policy_evaluated`와 `auth_results`는 같은 단어를 다른 뜻으로 씁니다. **`policy_evaluated` = 일치 기준 결과(DMARC가 내린 판단), `auth_results` = 무슨 도메인이든 실제로 확인한 도메인에 대한 원래 SPF/DKIM 결과.** `auth_results`에는 pass인데 `policy_evaluated`에는 fail이면, 그게 바로 일치 실패의 모습입니다.

수백 개씩 오는 이 XML을 손으로 읽는 사람은 없습니다. 조직들은 `rua=`를 보고서 분석 업체로 보내거나, SIEM에 넣어서 분석합니다. SOC에서 던질 쓸모 있는 질문은 이런 것들입니다.

- **모르는 출발지가 많은 양으로** 우리 도메인을 주장한다 → 지금 진행 중인 위조, 또는 IT에 알리지 않고 새 메일 서비스를 쓰는 부서(이른바 "그림자" 발송자).
- **아는 출발지가 갑자기 실패한다** → DKIM 키가 고장 났거나 SPF가 바뀐 것. 우리 진짜 메일이 스팸함으로 가게 됩니다.
- **실패 보고서**(`ruf=`)에는 메일 헤더나 내용이 들어 있을 수 있어서 개인정보입니다. 그래서 많은 대형 업체가 개인정보 보호를 이유로 보내지 않습니다. 기대하지 마세요.

### 우리 도메인에 DMARC 적용하기 { #rollout }

보통 거치는 단계와, 단계마다 왜 필요한지:

1. **`p=none`과 `rua=`** — 몇 주 동안 보고서를 모읍니다. 우리 이름으로 메일을 보내는 서비스가 전부 드러납니다(급여, 마케팅, 티켓 시스템, 대표님이 쓰는 뉴스레터 도구까지).
2. **정상 출발지를 하나씩 고쳐서** 일치 통과하게 만듭니다. 보통 그 서비스가 우리 도메인으로 DKIM 서명하게 하거나, SPF용으로 우리 반송 서브도메인을 쓰게 합니다.
3. **`p=quarantine`** — 먼저 `t=y`(시험 모드: 적용했다면 어떻게 됐을지 보고서로만 봄)를 붙였다가, 그다음 떼어 냅니다.
4. **`p=reject`**, 그리고 서브도메인까지 정리되면 `sp=reject`, `np=reject`.
5. **메일을 전혀 안 보내는 도메인**(묵혀 둔 도메인, 방어용으로 사 둔 도메인)은 바로 `v=spf1 -all`과 `v=DMARC1; p=reject;`를 올립니다. 아무도 지켜보지 않기 때문에 오히려 위조 대상으로 인기가 많습니다.

### 전달, 메일링 리스트, ARC { #forwarding }

DMARC는 부품들의 약점을 그대로 물려받습니다. **그냥 전달**(내용을 안 바꾸고 다시 보내는 별칭 주소)은 SPF는 깨지만 DKIM은 살아 있습니다 → DKIM이 일치했다면 여전히 통과. 제목에 꼬리표나 바닥글을 붙이는 **메일링 리스트**는 DKIM까지 깨뜨립니다 → 진짜 메일인데 DMARC 실패, `p=reject`라면 거부될 수도 있습니다.

요즘 쓰는 해결책은 두 가지입니다.

- **From 바꿔 쓰기(From rewriting).** 많은 리스트 서버가 `From:`을 리스트 자기 주소로 바꿉니다. 예: `From: "Kim Lee via Staff List" <staff-list@lists.victim.example>`. 그러면 DMARC는 리스트의 도메인으로 판정되고, 리스트는 그걸 통과할 수 있습니다. 표시 이름에 "via"가 보이면 대개 이 때문입니다.
- **ARC**(Authenticated Received Chain, [앞 페이지에서 소개](spf-results-dkim.md#dkim-limits)). 리스트가 "내가 받았을 때는 DKIM과 DMARC가 통과했다"를 봉인해 두고, 마지막 받는 쪽이 그 리스트를 믿는다면 그 기록을 인정할 수 있습니다. ARC를 인정한 받는 쪽은 결과에 그 사실을 적기도 합니다(예: `dmarc=fail ... arc=pass`, 그리고 `dis=`에 예외 처리).

## DMARC로도 *못* 막는 것 { #limits }

DMARC가 닫는 문은 딱 하나입니다. **내가 갖고 있지 않은 도메인을 `From:` 주소에 쓰는 것.** 나머지 문은 다 열려 있고, 공격자들은 이미 오래전에 그쪽으로 옮겨 갔습니다.

- **비슷한 도메인(look-alike, cousin domain).** `victim-payroll.example`, `vict1m.example`, 또는 [국제화 도메인으로 만든 비슷한 이름](../dns/blockchain-dns-and-idn.md). 공격자가 진짜 주인이니 SPF, DKIM, `p=reject` DMARC까지 완벽하게 올리고 셋 다 통과할 수 있습니다. DMARC는 "그 도메인에서 왔다"를 증명할 뿐, 사용자에게 "엉뚱한 도메인이에요"라고 알려 주지는 않습니다.
- **표시 이름 위조(display-name spoofing).** `From: "Payroll Team - victim.example" <payroll.team.4471@freemail.example>`. DMARC는 주소의 도메인(`freemail.example`)만 확인하고, 그건 통과합니다. 휴대폰 메일 앱 대부분은 표시 이름만 보여 줍니다.
- **`Reply-To:`로 돌리기.** `From:`은 진짜이거나 비슷한 도메인이고, `Reply-To: <payroll@victim-payroll.example>`. 사용자가 답장하면 공격자에게 갑니다. `Reply-To:`를 확인하는 인증 표준은 하나도 없습니다. 비즈니스 이메일 침해(BEC, Business Email Compromise)의 핵심 수법입니다.
- **탈취된 계정.** 공격자가 진짜 직원이나 거래처의 메일함에 로그인했다면, 거기서 보내는 메일은 SPF, DKIM, DMARC를 전부 완벽하게 통과합니다. 그 도메인에서 온 **진짜** 메일이니까요. 정상 클라우드 플랫폼이나 파일 공유 알림을 악용하는 것도 마찬가지입니다.
- **정책이 약한 도메인.** `p=none`이거나 레코드가 없는 도메인은 여전히 대놓고 위조할 수 있습니다.

그래서 규칙은 이것입니다. **인증은 누가 보냈는지 알려 줄 뿐, 그 내용을 믿어도 되는지는 절대 알려 주지 않습니다.**

## 이메일 정리 { #wrap-up }

섹션 전체를 한데 모아 봅니다.

- **헤더로 메일을 출발지까지 추적할 수 *있을 수도* 있지만, 보장은 없습니다.** 웹메일이나 클라우드 앱은 보통 사용자 IP를 아예 남기지 않고, 우리 경계 MTA 이전에 적힌 `Received:` 줄은 모두 우리가 통제하지 못하는 누군가가 쓴 것이라 거짓일 수 있습니다([신뢰 경계](email-headers.md#trust-boundary)). 확실한 사실은 우리 경계 서버가 기록한 연결 IP 하나뿐입니다.
- **SMTP는 태생부터 인증이 없습니다.** 서로 믿는 작은 네트워크를 위해 설계됐고, 보안은 나중에 덧붙였습니다. 그리고 그 대부분은 스스로 설정한 도메인에만 효과가 있습니다.
- **SPF, DKIM, DMARC가 없으면 이메일은 아주 쉽게 위조됩니다.** 봉투, 헤더, 표시 이름, 전부 다요([위조](spoofing-spf.md#why-spoofable)).
- **우리 경계 MTA 바깥의 헤더는 믿지 않습니다.** `Received:`도, `Authentication-Results:`도 마찬가지입니다([위조된 결과 헤더](spf-results-dkim.md#forged-results)).
- **우리 도메인에 SPF, DKIM, DMARC를 공개하면** 공격자가 우리 이름을 단 메일을 보내지 못하게 막습니다. 거래처에게도, 고객에게도, 우리 자신에게도요. 주로 남을 위한 일이라, 다른 도메인에서 우리에게 들어오는 스팸에는 별 효과가 없습니다. 중요한 예외가 **내부 사칭(internal spoofing)** 입니다. 바깥에서 들어오면서 우리 도메인인 척하는 메일은, 우리 `p=reject`(를 우리 받는 서버가 적용하면)로 막힙니다.
- **들어오는 메일에서 SPF, DKIM, DMARC를 검사하면** 누군가 *다른* 도메인을 사칭해 우리 사용자에게 보내는 것을 막아 줍니다. 단, 그 도메인들이 정책을 공개해 둔 만큼만입니다.
- **어느 것도 내용이 괜찮다는 보증은 아닙니다.**

### 신고된 메일 분석 체크리스트 { #triage }

| 단계 | 볼 곳 | 질문 |
| --- | --- | --- |
| 1 | 우리 서버가 쓴 맨 위 `Authentication-Results:`(authserv-id = 우리 서버) | `spf=`, `dkim=`, `dmarc=`가 무엇인가? |
| 2 | `smtp.mailfrom`, `header.d`, `header.from` | 세 도메인이 같은 조직인가? 어느 쪽이 일치했나? |
| 3 | `header.from` 도메인 자체 | *우리* 도메인인가, 거래처의 진짜 도메인인가, 비슷하게 만든 도메인인가? 최근에 등록됐나? |
| 4 | `From:` 표시 이름과 주소, `Reply-To:` | 이름과 주소가 맞나? 답장이 다른 곳으로 가나? |
| 5 | 우리 경계 `Received:` 줄 | 연결 IP와 그 평판. `Received-SPF:`의 `client-ip`와 같은가? |
| 6 | `From:` 도메인의 DMARC 정책(`dig TXT _dmarc.<도메인>`) | `none`, `quarantine`, `reject`? `dis=`가 그에 맞았나? |
| 7 | 내용: 링크, 첨부, 요청 | 전부 통과했더라도, 요청이 이상하지 않나(계좌 변경, 로그인 정보, 다급함)? |
| 8 | 범위 | 같은 발신 IP·제목·URL이 다른 메일함에도 있나? 메일 플랫폼 로그에 거부된 시도가 있나? |

## SOC에서 DMARC를 쓰는 법 { #soc-use }

- **`dmarc=`부터 읽고, 그다음 이유를 설명합니다.** `dmarc=pass`인데 낯선 도메인 → 비슷한 도메인이거나 탈취된 발송자. `dmarc=fail`인데 `From:`이 우리 도메인 → 누군가 우리를 사칭(`dis=`를 확인하고, 왜 배달됐는지 봅니다).
- **우리 도메인들의 정책을 알고 있습니다.** 조직이 가진 도메인 전부, 각각의 `p=`, 메일을 보내는지 여부를 목록으로 관리합니다. `p=none`인 묵혀 둔 도메인은 활짝 열린 위조 대상입니다.
- **집계 보고서를 모니터링에 넣습니다.** 우리 도메인을 주장하는 새로운 대량 출발지는 경보를, 아는 출발지가 갑자기 실패하면 메일 팀에 티켓을 보냅니다.
- **우리 받는 쪽이 DMARC를 적용하는지 확인합니다.** `p=reject`를 공개해도, 우리 게이트웨이가 DMARC를 무시하거나 이를 건너뛰는 허용 목록 규칙이 있으면, 우리 도메인을 사칭해 들어오는 메일에는 아무 효과가 없습니다.
- **인증에서 멈추지 않습니다.** BEC 같은 메일에서 결정적인 증거는 보통 `Reply-To:`, 비슷한 도메인의 등록 날짜, 그리고 요청 내용 자체입니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    "보낸 사람 주소가 두 개" 문제는 그대로입니다. SPF는 여전히 봉투를 확인하고, 사용자는 여전히 헤더 `From:`을 봅니다. DMARC의 핵심 생각 — SPF나 DKIM 통과, 그리고 `From:`과 *일치* — 도 그대로이고, 레코드는 여전히 `v=DMARC1`로 시작하며, `p=none/quarantine/reject`의 뜻도, 느슨한/엄격한 일치도 같습니다. 집계 보고서는 여전히 도메인 주인이 자기 이름이 악용되는 걸 보는 주된 방법입니다. "인증은 출처를 증명할 뿐, 안전을 증명하지 않는다"는 말은 어느 때보다 맞습니다.

!!! info "[변경됨] 바뀐 것"
    - **DMARC가 정식 표준 트랙에 올랐습니다.** 2026년 IETF가 DMARC 개정판을 **RFC 9989**(핵심), **RFC 9990**(집계 보고서), **RFC 9991**(실패 보고서)로 발행해, 정보 문서(informational)였던 옛 RFC 7489를 폐기(obsolete)하고 DMARC를 표준 트랙으로 옮겼습니다. 기존 레코드는 그대로 동작합니다.
    - **태그가 바뀌었습니다.** `pct=`, `rf=`, `ri=`가 빠지고, `np=`(존재하지 않는 서브도메인), `t=`(시험 모드, `pct=0` 꼼수를 대신함), `psd=`가 생겼습니다. 조직 도메인을 찾는 방법도 공개 접미사 목록에서 **DNS 트리 워크**로 바뀌었습니다.
    - **대형 메일 업체가 대량 메일에 DMARC를 의무로 만들었습니다.** Gmail과 Yahoo는 2024년 2월부터(SPF, DKIM, 최소 `p=none`의 DMARC 레코드, `From:` 일치), Gmail은 2025년 11월부터 규칙을 안 지키는 대량 메일을 경고에서 일시·영구 거부로 강화했습니다. Microsoft의 개인용 Outlook.com은 2025년 5월부터 규칙을 안 지키는 대량 발송자(하루 약 5,000통 이상)를 거부합니다. 그 결과 DMARC 레코드는 이제 아주 흔해졌지만, 상당수가 여전히 `p=none`이라 아무도 지켜 주지 못합니다.
    - **옛 도입률 통계는 이제 의미가 없습니다.** 2020년대 초에 나온 "상위 사이트 중 SPF나 DMARC가 있는 곳이 얼마 안 된다"는 숫자는 낡았습니다(그 통계가 쓰던 "상위 사이트" 순위 서비스 자체도 2022년에 문을 닫았습니다). 지금 정확한 숫자는 조사마다 달라서 확실하지 않습니다. 필요하면 최신 자료를 확인하세요.
    - **BIMI**(일부 메일 프로그램에서 인증된 메일 옆에 회사 로고를 보여 주는 것)는 적용 중인 DMARC 정책(`quarantine` 또는 `reject`)을 요구합니다. 그래서 회사들이 `p=none`을 넘어설 마케팅상의 이유가 생겼습니다. 로고는 인증의 표시일 뿐, 내용이 안전하다는 표시가 아닙니다.
    - **공격은 DMARC를 돌아서 갑니다.** 2026년의 피싱은 비슷한 도메인, 탈취된 거래처 계정, 정상 클라우드·전자서명 플랫폼, `Reply-To:` 수법에 기댑니다. 모두 인증을 통과합니다. AI가 쓴 미끼 메일은 분석가가 예전에 기대던 맞춤법 실수를 없애 버려서, 헤더와 도메인 확인이 덜 중요해지기는커녕 더 중요해졌습니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **새 레코드에 `pct=`를 쓰지 않습니다.** 빠진 태그라서 갱신된 받는 서버는 무시합니다. 시험하려면 `t=y`를 씁니다.
    - **도메인을 `p=none`에 영원히 두지 않습니다.** 원래 지켜보는 단계로 만든 것입니다. `p=none` 도메인은 레코드가 없는 도메인만큼 쉽게 위조됩니다.
    - **묵혀 둔 도메인, 메일을 안 보내는 도메인을 잊지 않고,** `sp=`/`np=`도 설정해서 공격자가 서브도메인을 지어내지 못하게 합니다.
    - **`dmarc=pass`를 "안전하다"로 읽지 않습니다.** `From:` 도메인이 진짜라는 뜻일 뿐이고, 그게 공격자가 가진 비슷한 도메인이거나 공격자가 탈취한 진짜 계정일 수 있습니다.
    - **집계 보고서의 `auth_results` pass를 "일치했다"로 읽지 않습니다.** DMARC 수준의 결과는 `policy_evaluated`에만 있습니다.
    - **보고서 없이 바로 `p=reject`로 가지 않습니다.** 우리 급여, 티켓, 마케팅 메일을 우리가 막게 됩니다.

## 확인 문제 { #quiz }

### 문제 1

사용자가 메일을 첨부 파일로 전달해 왔습니다. 아래는 우리 경계 서버가 쓴 것입니다. 사용자는 "payroll@victim.example이라고 되어 있으니 내부 메일이 틀림없다"고 합니다. 무슨 일이 있었고, 왜 배달됐을까요?

```
Return-Path: <bounce@cheap-hosting.example>
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=cheap-hosting.example;
       dkim=pass header.d=cheap-hosting.example header.s=k1 header.b=Qm7Lx2Ra;
       dmarc=fail (p=none dis=none) header.from=victim.example
From: "Payroll Team" <payroll@victim.example>
Reply-To: <payroll-updates@cheap-hosting.example>
Subject: Updated bank details for November salary run
```

??? success "정답과 해설"
    **바깥 발송자가 우리 도메인을 사칭한 것입니다.** SPF와 DKIM은 둘 다 진짜로 통과했지만, `cheap-hosting.example`에 대해서입니다(`smtp.mailfrom`, `header.d`). 화면에 보이는 `From:` 도메인은 `victim.example`이고, 어느 pass도 이것과 **일치하지 않으니** `dmarc=fail`입니다. 사용자가 보는 건 보내는 쪽이 마음대로 쓸 수 있는 RFC 5322 `From:`이고, 봉투(`Return-Path:`)가 진짜 출발 도메인을 보여 줍니다.

    배달된 이유는 우리 도메인의 DMARC 정책이 **`p=none`** 이기 때문입니다(`dis=none`). 우리가 우리 자신을 포함한 모든 받는 쪽에게 "실패해도 아무것도 하지 말라"고 해 둔 셈입니다. 공격자 도메인을 가리키는 `Reply-To:`도 보세요. 답장하면 공격자에게 갑니다.

    조치: 발신 IP와 도메인 차단, 같은 `Return-Path` 도메인과 제목으로 다른 메일함 검색, 급여팀에 경고, 그리고 (집계 보고서로 정상 발송자가 모두 일치 통과하는지 확인한 뒤) `victim.example`을 `p=quarantine`, 이어서 `p=reject`로 올리자고 건의합니다. `From:`에 우리 도메인을 쓴 외부 메일에 표시를 붙이는 게이트웨이 규칙도 검토합니다.

### 문제 2

이 DMARC 레코드를 읽고 답하세요. (a) `victim.example`이라고 주장하면서 DMARC에 실패한 메일은 어떻게 되나? (b) `hr.victim.example`(존재하고, 자기 레코드는 없음)이라면? (c) `payroll-secure.victim.example`(DNS에 존재하지 않음)이라면? (d) 낡은 부분이 있나?

```
"v=DMARC1; p=quarantine; sp=none; np=reject; pct=25; adkim=s; rua=mailto:dmarc-agg@victim.example"
```

??? success "정답과 해설"
    - **(a)** `p=quarantine` → 스팸함으로 갑니다. (옛 규칙이라면 `pct=25` 때문에 실패한 메일의 4분의 1만 격리됐을 겁니다. (d) 참고.)
    - **(b)** `sp=none` → 존재하는 서브도메인에는 **아무 조치 없음.** 공격자는 `hr.victim.example`을 마음대로 위조할 수 있습니다. 약점이고, 인사팀은 그럴듯한 발송자입니다.
    - **(c)** `np=reject` → 존재하지 않는 서브도메인이니 거부됩니다. 다만 아직 2026년 개정을 지원하지 않는 받는 서버는 `np=`를 무시하고 `sp=none`으로 돌아가므로, 이 보호가 아직 어디서나 통하지는 않습니다.
    - **(d)** `pct=`는 2026년 개정에서 **빠졌습니다.** 갱신된 받는 서버는 이걸 무시하고 실패한 메일 전부에 정책을 적용합니다(100과 같음). 옛 서버는 여전히 25%만 적용할 수 있습니다. 지우고, 시험 단계가 필요하면 `t=y`를 씁니다. `adkim=s`(엄격한 DKIM 일치)도 보세요. `d=mail.victim.example`로 서명하고 `From: victim.example`인 메일은 DKIM 일치가 안 됩니다. 모든 발송자가 `From:` 도메인과 정확히 같은 이름으로 서명하게 하거나, 느슨한 방식을 씁니다. `aspf`는 없으니 기본값인 느슨한 방식입니다.

### 문제 3

`victim.example`의 집계 보고서에 아래 기록이 있습니다. 이 출발지는 무엇이고, 무엇이 잘못됐으며, 메일 팀은 무엇을 해야 할까요?

```xml
<row>
  <source_ip>192.0.2.40</source_ip>
  <count>2950</count>
  <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
</row>
<identifiers><header_from>victim.example</header_from></identifiers>
<auth_results>
  <dkim><domain>ticketdesk.example</domain><selector>td1</selector><result>pass</result></dkim>
  <spf><domain>mail.ticketdesk.example</domain><result>pass</result></spf>
</auth_results>
```

??? success "정답과 해설"
    원래 SPF와 DKIM은 둘 다 **통과했지만**, 업체 자기 도메인(`ticketdesk.example`, `mail.ticketdesk.example`)에 대해서입니다. 둘 다 `victim.example`과 일치하지 않으니 DMARC 수준에서는 둘 다 `fail`입니다. 티켓 시스템 업체의 IP에서 하루 3,000통 가까이, 업체 서명은 통과 — 공격자라기보다 **우리 조직이 실제로 쓰는 정상 서비스**(예: IT 헬프데스크의 티켓 알림)인데 우리 도메인으로 인증하도록 설정하지 않은 것으로 보입니다. 그래도 결과는 실제로 문제입니다. 우리 자신의 `p=quarantine` 때문에 그 알림이 사용자 스팸함으로 가고 있습니다.

    고치는 법: 업체가 **`d=victim.example`로 DKIM 서명**하게 설정하거나(업체의 공개 키를 `td1._domainkey.victim.example` 같은 셀렉터로 우리 DNS에 올림), 우리 반송 서브도메인(`tickets.victim.example`)을 봉투 보낸 사람으로 쓰고 그 SPF에 업체를 넣습니다. 둘 중 하나면 일치 통과가 됩니다. 정상이라고 결론 내리기 전에, 실제로 이 업체를 쓰고 있는지 현업에 꼭 확인하세요. 같은 모양의 모르는 출발지라면 누군가 그 업체 플랫폼을 악용하는 것일 수도 있습니다.
