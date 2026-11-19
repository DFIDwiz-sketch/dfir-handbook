---
title: "SPF 결과와 DKIM — 결과 값, Authentication-Results·Received-SPF 읽기, DKIM 서명 동작 원리"
tags:
  - training
  - blue-team
  - email
  - spf
  - dkim
---

# SPF 결과와 DKIM — 결과 값, Authentication-Results·Received-SPF 읽기, DKIM 서명 동작 원리 { #spf-results-dkim }

!!! abstract "이 페이지에서 다루는 것"
    SPF 검사를 마친 받는 서버가 무엇을 적어 두는지 봅니다. 나올 수 있는 결과 일곱 가지(pass, fail, softfail, neutral, none, temperror, permerror)가 각각 정확히 무슨 뜻이고, 받는 서버와 분석가는 어떻게 받아들여야 하는지. 그 결과가 트레이스 헤더 어디에 남는지 — 짧은 요약인 `Authentication-Results:`와 자세한 `Received-SPF:` — 를 칸 하나하나 읽어 보고, 클라우드 메일 플랫폼식 헤더와 공격자가 심어 둔 가짜 헤더도 봅니다. 이어서 DKIM입니다. SPF 위에 왜 서명 기반 검사가 하나 더 필요했는지, 서명과 검증이 실제로 한 단계씩 어떻게 돌아가는지, `DKIM-Signature:` 헤더를 태그별로, `selector._domainkey`에 있는 공개 키 레코드, DKIM 결과 값, 그리고 DKIM pass가 **증명하지 못하는 것**까지. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 도메인·IP·키·서명 값은 모두 설명용 가상 값입니다. 앞 페이지 [이메일 위조와 SPF](spoofing-spf.md)에 이어집니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. SPF 검사는 항상 **일곱 가지 결과 중 하나**로 끝난다: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`. 목록에 없는 발송자가 어떤 결과를 받을지는 도메인 주인이 정하고(`-all`, `~all`, `?all`), 마지막 세 가지는 레코드가 없거나 고장 났거나 DNS에 문제가 있을 때 나온다.
2. `neutral`은 **`none`과 완전히 똑같이 다뤄야** 하고, `softfail`은 그것 **하나만으로 거부하면 안 되지만** 더 의심해 볼 이유는 된다. `fail`을 어떻게 처리할지는 **받는 쪽이 스스로 정할 일(local policy)** 이다.
3. 결과는 두 헤더에 남는다. **`Authentication-Results:`** (SPF·DKIM·DMARC 등을 한 줄로 요약, 지금은 RFC 8601이 정의)와 **`Received-SPF:`** (연결 IP, 봉투 보낸 사람, HELO, 이유까지 SPF의 모든 세부, RFC 7208이 정의).
4. **우리 경계 서버가 직접 쓴 결과 헤더만 믿는다.** 맨 앞에 적힌 이름(authserv-id)으로 누가 썼는지 알 수 있다. 공격자는 보내는 메일 안에 가짜 `Authentication-Results: ... pass` 줄을 얼마든지 넣을 수 있다.
5. DKIM은 **서명 기반(signature-based)** 이다. 보내는 조직의 메일 서버가 고른 헤더와 본문에 **개인 키(private key)** 로 서명하고, **공개 키(public key)** 를 DNS에 올려 두어 누구나 서명을 검증할 수 있게 한다.
6. **[정정]** **셀렉터(selector)** 는 "메일에서 서명할 부분"이 *아니다.* **키의 이름**(`s=`)이고, `<selector>._domainkey.<domain>`에서 공개 키를 찾는 데 쓴다. 무엇을 서명했는지는 `h=`(헤더 목록)와 `bh=`(본문 해시)에 들어 있다.
7. 분석가에게 중요한 DKIM 결과는 셋이다. **`dkim=pass`** (서명이 있고 검증됨), **`dkim=none`** (서명 없음 — 어느 쪽으로도 증거가 아님), **`dkim=fail`** (서명은 있는데 검증 실패 — 가는 길에 바뀌었거나 위조).
8. DKIM pass가 증명하는 것은 **"`d=`의 도메인이 이걸 서명했고, 서명한 부분은 바뀌지 않았다"** 뿐이다. `d=`가 사용자가 보는 `From:`의 도메인과 같다는 것도, 메일이 안전하다는 것도 증명하지 않는다. 둘을 이어 주는 건 DMARC의 몫이다.

## SPF 결과: 받는 서버가 내리는 결론 { #spf-results }

앞 페이지에서 받는 쪽 경계 MTA가 SPF 레코드를 어떻게 평가하는지 따라가 봤습니다. 평가가 끝나면 서버는 **결론을 적어 둬야** 하는데, SPF 표준(RFC 7208의 2.6절과 8절)은 이때 쓸 단어 일곱 개를 정해 두었습니다. 회사 행사장 입구에서 **명단을 들고 있는 경비원**을 떠올려 보세요.

- 명단에 이름이 있다 → *들어오세요* (`pass`)
- 회사가 "명단에 있는 사람 말고는 아무도 안 됨"이라고 했는데 명단에 없다 → *못 들어갑니다* (`fail`)
- 회사가 "아마 명단에 있는 사람만일 텐데, 소란은 피우지 마"라고 했다 → *들여보내되 눈여겨보세요* (`softfail`)
- 회사가 명단은 줬지만 "명단에 없는 사람에 대해서는 할 말 없음"이라고 했다 → *의견 없음* (`neutral`)
- 회사가 명단을 아예 안 줬다 → *정보 없음* (`none`)
- 본사에 확인하는 전화가 지금 안 된다 → *나중에 다시* (`temperror`)
- 명단 자체를 읽을 수가 없다 — 찢어졌거나, 서로 다른 명단이 두 장이거나, 너무 길어서 다 확인할 수 없다 → *명단이 고장 남* (`permerror`)

이제 기술적인 실체로 돌아와, 결과 하나씩 봅니다.

| 결과 | 언제 나오나 | 뜻 | 받는 서버는 어떻게 | 분석가는 이렇게 읽는다 |
| --- | --- | --- | --- | --- |
| `pass` | `+`(또는 기호 없음) 항목이 연결 IP와 일치 | 그 IP는 봉투 도메인을 대신해 **보낼 자격이 있다** | 받음. 이제 그 도메인에 메일의 책임(평판)을 물을 수 있다 | 경로는 괜찮다, **그 도메인에 대해서는**. 이제 사용자가 보는 도메인과 같은지 확인 |
| `fail` | `-` 항목이 일치, 보통 `-all` | 도메인이 **분명하게** "이 IP는 우리 대신 못 보낸다"고 말함 | 받는 쪽 정책: 거부·스팸함·표시. DMARC에 맡기는 경우가 많다 | 강한 위조 신호. 단, 전달(forwarding)된 메일이면 예외 |
| `softfail` | `~` 항목이 일치, 보통 `~all` | "아마 허락 안 됨", 다만 강하게 단정하지는 않음 | **이것만으로 거부하면 안 됨**. 더 꼼꼼히 볼 수는 있다 | 의심스럽다. 레코드를 아직 다듬는 중인 진짜 도메인에서도 아주 흔하다 |
| `neutral` | `?` 항목이 일치, 보통 `?all` | 레코드는 있지만 이 IP에 대해 아무 말도 안 함 | **`none`과 똑같이 다뤄야 한다** | 어느 쪽 증거도 아님 |
| `none` | SPF 레코드가 아예 없거나, 도메인을 알아낼 수 없음(HELO가 빈 경우 등) | 받는 서버에 **정보가 없다** | SPF로는 할 게 없다 | 2026년에 SPF조차 없는 정상 회사 도메인은 드물다. 비슷하게 만든 도메인이나 일회용 도메인일 가능성이 더 크다 |
| `temperror` | 조회 중 DNS 시간 초과나 서버 오류 | **일시적인** 문제, 답을 모름 | 보통 `4xx` 코드로 미뤄서 보내는 쪽이 다시 보내게 한다 | 그 자체로는 의미가 적다. 계속 반복되는지 본다 |
| `permerror` | 문법 오류, `v=spf1` 레코드 두 개, 조회 10회 초과, 빈 조회 2회 초과 | **레코드 자체가 고장**이라 평가할 수 없음 | 대부분 인증 안 된 메일로 취급 | 대개 공격이 아니라 보내는 쪽 실수. 하지만 그 도메인은 이제 위조하기 쉬워졌다 |

`neutral`과 `none`을 똑같이 다뤄야 한다면 왜 굳이 나눠 놨을까요? 순전히 **참고용**입니다. `neutral`은 그 도메인에 SPF 레코드가 *있긴 한데* `?all`을 골랐다는 걸 알려 줍니다. 거래처 메일이 왜 자꾸 스팸함에 가는지 원인을 찾을 때 쓸모가 있죠. 걸러 낼지 말지 판단할 때는 둘이 같습니다.

`softfail` 하나만으로 거부하면 안 되는 이유는? `~all`은 도메인 주인이 "내 목록이 완벽한지 자신이 없다"고 말하는 것이기 때문입니다. 많은 조직이 자기 이름으로 메일을 보내는 서비스를 아직 다 찾아내지 못한 동안 `~all`을 씁니다. 받는 쪽이 softfail을 바로 거부해 버리면 그 조직들은 진짜 메일을 잃게 됩니다. 그래서 RFC는 받는 쪽이 더 꼼꼼히 보는 것(스팸 점수 올리기, 내용 검사 강화)은 허락하지만, 그것만으로 막지는 말라고 합니다.

`fail`의 처리가 "받는 쪽 정책"인 이유는? SPF 표준은 일부러 "거부하라"고 명령하지 않습니다. 받는 조직마다 사정이 다르기 때문입니다. 예를 들어 전달된 메일을 얼마나 받는지가 다릅니다(전달된 메일은 전달 서버의 IP가 원래 도메인 목록에 없으니 정당하게도 SPF에 실패합니다). 요즘 대형 수신 서비스는 대부분 **DMARC** 결과에 최종 판단을 맡깁니다. DMARC는 SPF가 깨져도 DKIM에 기댈 수 있으니까요.

**[보충]** 입문 자료에는 결과가 앞의 다섯 가지만 나오는 경우가 많습니다. 실무에서는 `temperror`와 `permerror`도 중요합니다. 우리 도메인에 `permerror`가 나면 모든 받는 쪽이 우리 메일을 인증 안 된 메일로 취급하고 있다는 뜻인데, 이건 받는 쪽에서만 보입니다.

## 결과가 헤더 어디에 남나 { #where-results }

받는 서버는 결론을 **트레이스 헤더(trace header)** 로 메일 맨 위에 덧붙입니다. 자기 `Received:` 줄을 붙이는 것과 똑같습니다([트레이스 헤더](email-headers.md#three-parts)). SPF 결과는 두 헤더에 남습니다.

### Authentication-Results: 짧은 요약 { #authentication-results }

`Authentication-Results:`는 받는 서버가 돌린 **모든** 인증 검사를 한 헤더에 요약합니다. SPF, DKIM, DMARC, 그리고 가끔 다른 것들(ARC, 역방향 DNS, 메일 업체 자체의 종합 판정)까지요. 지금은 RFC 8601이 정의합니다(예전 자료가 가리키는 RFC 7001은 그 뒤로 두 번 대체됐습니다). 이 헤더는 **답만 적고, 이유는 적지 않습니다.**

직접 운영하는 경계 서버가 쓴 전형적인 예입니다.

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=billing.partner.example;
       dkim=pass header.d=partner.example header.s=s2026 header.b=Kp3vT9xQ;
       dmarc=pass (p=quarantine dis=none) header.from=partner.example
```

한 줄씩 봅니다.

- `Authentication-Results: mx1.victim.example;` — 첫 값은 **authserv-id**, 즉 검사를 한 서버의 이름입니다. 이걸 보고 **이 줄을 누가 썼는지** 압니다. 우리 경계 서버(또는 우리 클라우드 메일 업체)여야 합니다.
- `spf=pass` — SPF 결과. 위의 일곱 단어 중 하나입니다.
- `smtp.mailfrom=billing.partner.example` — SPF가 **어떤 신원을** 확인했는지. 봉투 `MAIL FROM`의 도메인입니다. (HELO 이름을 확인했다면 `smtp.helo=`가 보입니다.) 반송용 **서브도메인**이라는 점에 주목하세요. 청구·마케팅 시스템에서 흔합니다.
- `dkim=pass` — DKIM 결과(아래에서 설명).
- `header.d=partner.example` — 메일에 **서명한** 도메인(서명의 `d=`).
- `header.s=s2026` — 사용한 키의 **셀렉터**.
- `header.b=Kp3vT9xQ` — 서명 값의 앞 몇 글자. 서명이 여러 개 붙은 메일에서 이 결과가 어느 서명 것인지 구분하려고 적습니다.
- `dmarc=pass (p=quarantine dis=none)` — DMARC 결과. 괄호 안 설명은 그 도메인의 정책이 `quarantine`이고, 실제 적용한 처리(disposition)는 `none`(통과했으니 아무것도 안 함)이라는 뜻입니다. 다음 페이지에서 다룹니다.
- `header.from=partner.example` — 화면에 보이는 `From:` 헤더의 도메인. DMARC가 비교한 대상입니다.

클라우드 메일 플랫폼은 자기만의 칸을 더 붙입니다. 대형 호스팅 메일 플랫폼이 받은 메일에는 대략 이런 헤더가 붙습니다(구조는 실제와 같고 이름은 가상입니다).

```
Authentication-Results: spf=pass (sender IP is 198.51.100.24)
 smtp.mailfrom=newsletter.shop.example; dkim=none (message not signed)
 header.d=none;dmarc=bestguesspass action=none
 header.from=newsletter.shop.example;compauth=pass reason=109
```

- `spf=pass (sender IP is 198.51.100.24)` — 괄호 안 설명이 연결 IP를 덧붙여 줍니다. 여기는 맨 앞에 authserv-id가 없습니다. 이런 플랫폼에서는 위치(업체 내부 네트워크에서 붙인, 맨 위 결과 헤더)와 주변 `Received:` 줄로 누가 썼는지 판단합니다.
- `dkim=none (message not signed) header.d=none` — DKIM 서명이 **아예 없습니다.** 실패가 아니라 그냥 증거가 없는 것입니다.
- `dmarc=bestguesspass action=none` — **업체 전용** 값입니다. `From:` 도메인에 **DMARC 레코드가 없어서**, 만약 있었다면 결과가 어땠을지 플랫폼이 추측한 것입니다. 진짜 DMARC pass가 아닙니다.
- `compauth=pass reason=109` — SPF·DKIM·DMARC에 자체 평판 신호까지 합친 업체 자체의 **종합 인증(composite authentication)** 판정입니다. `reason` 코드의 뜻은 업체 문서에 있습니다. 표준이 아니라 참고 힌트로 봅니다.

### Received-SPF: 자세한 내용 { #received-spf }

SPF가 **왜** 그런 결론을 냈는지 알아야 할 때는 `Received-SPF:`를 찾습니다. 형식은 RFC 7208의 9.1절에 정의돼 있고, 평가에 쓰인 모든 재료가 들어 있습니다.

```
Received-SPF: Pass (mx1.victim.example: domain of billing.partner.example
    designates 198.51.100.24 as permitted sender)
    receiver=mx1.victim.example; client-ip=198.51.100.24;
    envelope-from="invoices@billing.partner.example";
    helo=out2.partner.example; identity=mailfrom;
    mechanism="ip4:198.51.100.0/27";
```

- `Pass` — 결과.
- `( ... designates 198.51.100.24 as permitted sender)` — 결과를 사람이 읽을 수 있게 풀어 쓴 설명.
- `receiver=mx1.victim.example` — 검사를 한 서버.
- `client-ip=198.51.100.24` — **연결해 온 IP**. 보내는 쪽이 속일 수 없는 유일한 사실입니다([왜 그런지](spoofing-spf.md#why-ip)). 우리 경계 `Received:` 줄의 대괄호 속 IP와 같아야 합니다.
- `envelope-from="invoices@billing.partner.example"` — `MAIL FROM` 주소.
- `helo=out2.partner.example` — 보내는 서버가 `HELO`/`EHLO`에서 자기를 뭐라고 소개했는지.
- `identity=mailfrom` — 어떤 신원을 확인했는지(`mailfrom` 또는 `helo`).
- `mechanism="ip4:198.51.100.0/27"` — **레코드의 어느 항목이 일치했는지.** 아주 쓸모 있습니다. IP가 허락된 어느 범위, 어느 `include`에서 왔는지 정확히 알려 줍니다.

모든 서버가 선택 칸을 다 쓰지는 않지만, `client-ip`, `envelope-from`, `helo`는 거의 항상 있습니다. 실제와 비슷한 세 가지를 비교해 봅시다.

```
Received-SPF: Softfail (mx1.victim.example: domain of transitioning
    partner.example does not designate 203.0.113.66 as permitted sender)
    client-ip=203.0.113.66; envelope-from="ceo@partner.example";
    helo=mail.partner.example;

Received-SPF: PermError (mx1.victim.example: permanent error in processing
    domain of growing-co.example: too many DNS lookups)
    client-ip=192.0.2.17; envelope-from="hello@growing-co.example";

Received-SPF: None (mx1.victim.example: domain of fresh-login.example
    does not designate permitted sender hosts)
    client-ip=203.0.113.200; envelope-from="security@fresh-login.example";
```

- 첫 번째: IP `203.0.113.66`이 `partner.example`의 목록에 없고, 레코드가 `~all`로 끝남 → `Softfail`. `From:`이 거래처 사장이라고 주장한다면 꼼꼼히 들여다볼 만합니다.
- 두 번째: 레코드가 고장(`too many DNS lookups`, [앞 페이지](spoofing-spf.md#limits)의 조회 10회 제한). 공격이라기보다 보내는 쪽의 설정 실수일 가능성이 큽니다.
- 세 번째: `fresh-login.example`은 SPF를 아예 공개하지 않습니다. 제목이 "보안 경고"라면, 일회용 피싱 도메인의 전형적인 모습입니다.

### 명령줄에서 결과만 뽑아 보기 { #command-line }

저장해 둔 메일(`.eml` 파일, [안전하게 수집](email-headers.md#how-to-view))이 있으면 이 헤더들만 뽑아 볼 수 있습니다. 헤더는 여러 줄로 **접혀(folded)** 있을 수 있어서(이어지는 줄은 공백으로 시작) 그냥 `grep`하면 첫 줄만 보입니다. 아래 짧은 `awk`는 먼저 접힌 줄을 펴 줍니다.

```
$ awk '/^$/{exit} /^[ \t]/{h=h" "$0; next} {if(h)print h; h=$0} END{if(h)print h}' suspicious.eml \
    | grep -iE '^(Authentication-Results|Received-SPF|DKIM-Signature|Return-Path|From):'
```

- `/^$/{exit}` — 처음 나오는 빈 줄에서 멈춥니다. 거기서 헤더가 끝나고 본문이 시작됩니다.
- `/^[ \t]/{h=h" "$0; next}` — 공백이나 탭으로 시작하는 줄은 이어지는 줄이니, 지금 모으는 헤더 `h`에 붙입니다.
- `{if(h)print h; h=$0}` — 새 헤더가 시작되면, 이제 다 모인 이전 헤더를 출력하고 새로 모으기 시작합니다.
- `END{if(h)print h}` — 마지막 헤더를 출력합니다.
- `grep -iE '^(...):'` — 보고 싶은 헤더만, 대소문자 구분 없이 남깁니다.

출력(헤더 하나당 한 줄):

```
Return-Path: <invoices@billing.partner.example>
Authentication-Results: mx1.victim.example; spf=pass smtp.mailfrom=billing.partner.example; dkim=pass header.d=partner.example header.s=s2026 header.b=Kp3vT9xQ; dmarc=pass (p=quarantine dis=none) header.from=partner.example
Received-SPF: Pass (mx1.victim.example: domain of billing.partner.example designates 198.51.100.24 as permitted sender) receiver=mx1.victim.example; client-ip=198.51.100.24; envelope-from="invoices@billing.partner.example"; helo=out2.partner.example; identity=mailfrom; mechanism="ip4:198.51.100.0/27";
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=partner.example; s=s2026; ...
From: "Partner Billing" <billing@partner.example>
```

### [보충] 위조된 결과 헤더 { #forged-results }

공격자는 자기가 넘기는 메일의 모든 것을 마음대로 쓸 수 있습니다. **인증 결과처럼 보이는 헤더까지도요.** 그냥 이렇게 적어서

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=victim.example;
       dkim=pass header.d=victim.example;
       dmarc=pass header.from=victim.example
```

보내기 전에 메일에 넣으면 됩니다. 완벽해 보이고, 심지어 우리 서버 이름까지 씁니다. [헤더 페이지](email-headers.md#trust-boundary)에서 본 위조 `Received:` 줄과 같은 문제이고, 막는 생각도 같습니다.

1. **우리 경계 서버가 붙인 결과 헤더를 찾습니다.** 우리 경계 `Received:` 줄 바로 위나 옆, **맨 위쪽**에 있는 것입니다. 우리 경계 `Received:` 줄보다 **아래**에 있는 것은 바깥에서 메일과 *함께* 들어온 것이고, 남이 쓴 것입니다.
2. RFC 8601은 받는 서버에게, 들어오는 메일에 이미 붙어 있는 `Authentication-Results:` 중 자기 authserv-id를 단 것은 **지우라고** 합니다. 바로 이 속임수를 막으려는 것입니다. 요즘 서버는 대부분 그렇게 하지만, 오래됐거나 설정이 잘못된 서버는 안 할 수도 있습니다. 우리 서버 이름이 달린 결과 헤더가 **두 개** 보이면, 아래쪽 것이 빠져나온 가짜입니다.
3. **다른** 조직이 쓴 결과 헤더(예: 앞서 메일을 처리한 거래처 서버)는 그 조직을 믿는 만큼만 믿을 수 있습니다. 증거가 아니라 참고로 씁니다.

## DKIM: 메일 자체에 서명하기 { #dkim }

### 왜 검사가 하나 더 필요했나 { #why-dkim }

SPF는 **경로**만 봅니다. 어느 IP가 메일을 넘겼는지요. 여기에는 큰 약점이 두 개 있습니다.

- **전달하면 깨집니다.** 대학 별칭 주소나 메일링 리스트가 메일을 전달하면, 메일은 전달 서버의 IP에서 옵니다. 그 IP는 원래 도메인의 목록에 없으니, 진짜 메일인데도 SPF가 실패합니다.
- **내용에 대해서는 아무 말도 못 합니다.** SPF를 통과했어도 가는 길에 내용이 바뀌었을 수 있습니다.

DKIM(DomainKeys Identified Mail, RFC 6376)은 어디서 왔는지에 기대는 대신 **메일 자체에** 증거를 붙여서 두 문제를 다 풉니다. 비유하자면, SPF는 소포를 *어느 우체국 차가* 배달했는지 보는 것입니다. DKIM은 **회사 문장을 찍은 밀랍 봉인**입니다. 누가 소포를 나르든, 차를 몇 번 갈아타든, 받는 사람은 봉인을 보면 됩니다. 봉인이 멀쩡하고 회사가 공개한 문장과 같다면, 그 회사에서 보냈고 아무도 열지 않은 것입니다.

"봉인"의 기술적 실체는 공개 키 암호를 쓰는 **전자 서명(digital signature)** 입니다(RSA, 또는 더 새로운 Ed25519). 보내는 조직은 **개인 키**를 메일 서버에 비밀로 두고, 짝이 되는 **공개 키**를 DNS에 공개합니다. 올바른 서명은 개인 키로만 만들 수 있고, 확인은 공개 키만 있으면 누구나 할 수 있습니다.

### 서명은 이렇게 한다, 한 단계씩 { #signing }

도메인 주인이 한 번만 하는 준비:

1. 키 쌍(key pair)을 만듭니다.
2. **셀렉터**를 정합니다. 그냥 이 키에 붙이는 이름표입니다. `s2026`, `mail1`, 또는 업체 이름 같은 것. 서비스마다 다른 키를 쓸 수 있고, 키마다 셀렉터가 따로 있습니다.
3. 공개 키를 **`<selector>._domainkey.<domain>`** 에 TXT 레코드로 올립니다. 예: `s2026._domainkey.partner.example`.
4. 개인 키를 **나가는 메일 서버나 게이트웨이**에 설치합니다(또는 클라우드 메일 업체가 보관하게 합니다).

메일을 보낼 때마다:

1. 사용자의 메일 프로그램이 아니라 **보내는 메일 서버**가 서명을 준비합니다. 사용자는 키를 보지도, 갖고 있지도 않습니다. 그 발송 흐름의 나가는 메일 전체에 중앙에서 서명합니다.
2. 메일을 **정규화(canonicalization)** 합니다. 중간 서버들이 별 뜻 없이 자주 바꾸는 것들, 예를 들어 남는 공백이나 헤더 이름의 대소문자를 통일하거나(`c=relaxed`), 아무것도 안 바꿉니다(`c=simple`, 엄격).
3. **본문을 해시**(SHA-256)해서 그 값을 `bh=`(body hash)에 넣습니다.
4. **지키기로 고른 헤더들** — `h=`에 적은 것, 예를 들어 `From`, `To`, `Subject`, `Date`, `Message-ID` — 과 새로 만드는 `DKIM-Signature:` 헤더 자신(`b=`는 아직 빈 채로)을 해시하고, **그 해시에 개인 키로 서명**합니다. 결과가 `b=`에 들어갑니다.
5. 완성된 `DKIM-Signature:` 헤더를 메일 맨 위에 붙여서 보냅니다.

메일을 받을 때마다, 검증하는 쪽은:

1. `DKIM-Signature:` 헤더에서 `d=`와 `s=`를 읽습니다.
2. DNS에서 공개 키를 가져옵니다. TXT 레코드 이름은 `s=` + `._domainkey.` + `d=`.
3. 본문을 직접 정규화·해시해서 `bh=`와 비교합니다. **다르면 본문이 바뀐 것 → fail.**
4. `h=`에 적힌 헤더를 정규화·해시하고, `b=`의 서명을 공개 키로 확인합니다. **확인이 안 되면 헤더가 바뀌었거나 그 키로 만든 서명이 아님 → fail.**
5. 둘 다 성공 → **pass**.

**[정정]** 흔히 두 가지가 단순하게 설명됩니다. 첫째, 셀렉터가 "메일의 어느 부분을 서명할지 고른다"는 설명. 아닙니다. 셀렉터는 키에 이름을 붙일 뿐입니다. 어느 부분이 보호되는지는 `h=`(헤더)와 본문 해시 `bh=`(항상 본문, `l=`로 길이를 줄일 수는 있음)가 정합니다. 둘째, "해시를 개인 키로 암호화한다"는 설명. RSA 서명을 느슨하게 말한 것입니다. 개인 키로만 만들 수 있고 공개 키로 누구나 확인할 수 있는 **서명**이라고 생각하는 편이 정확합니다. Ed25519에는 "암호화" 과정 자체가 없습니다.

### DKIM-Signature 헤더, 태그별로 { #dkim-signature }

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=partner.example;
        s=s2026; t=1795047600; x=1795652400;
        h=from:from:to:subject:date:message-id:mime-version:content-type;
        bh=lNXsHoS7vr6QrKDmysIJdvi6qfRmHA6shFtOVsiEKWc=;
        b=Kp3vT9xQm1Lr8bW0zYc4H6s2nDqPfE7uJ0aVxR5tKyM9...(about 340 characters)...
```

| 태그 | 예 | 뜻 |
| --- | --- | --- |
| `v=` | `1` | 버전. 항상 `1` |
| `a=` | `rsa-sha256` | 알고리즘: SHA-256 해시에 RSA 서명. `ed25519-sha256`도 보입니다. `rsa-sha1`은 낡아서 이제 서명에 쓰면 안 됩니다 |
| `c=` | `relaxed/relaxed` | **헤더/본문** 정규화 방식. `relaxed`는 공백·대소문자 변화를 봐주고, `simple`은 하나도 안 봐줍니다 |
| `d=` | `partner.example` | **서명한 도메인** — 책임을 지는 도메인. 분석가에게 가장 중요한 태그 |
| `s=` | `s2026` | **셀렉터** — 키의 이름. 공개 키는 `s2026._domainkey.partner.example`에 있음 |
| `t=` | `1795047600` | 서명 시각, 유닉스 초(여기서는 2026-11-19 00:20 UTC) |
| `x=` | `1795652400` | 만료 시각. 이 뒤로는 서명을 받아 주면 안 됨(여기서는 7일 뒤) |
| `h=` | `from:from:to:...` | **서명한 헤더 목록**, 순서대로. `from`이 일부러 **두 번** 들어 있음 — 아래 설명 |
| `bh=` | `lNXs...KWc=` | 정규화한 본문의 SHA-256 해시를 Base64로 |
| `b=` | `Kp3v...` | 서명 값 자체를 Base64로 |
| `i=` | `@partner.example` | 선택: 누구(사용자나 서브도메인)를 대신해 서명했는지 |
| `l=` | `1250` | 선택: 본문 앞부분 N바이트만 보호. **위험**: 그 뒤에 덧붙인 내용은 보호되지 않음 |

`t=` 값을 바꿔 보면: `date -u -d @1795047600`은 `Thu Nov 19 00:20:00 UTC 2026`을 출력합니다.

`h=`에 `from`이 왜 두 번 있을까요? **오버사이닝(over-signing)** 이라고 합니다. 검증하는 쪽은 `h=`를 헤더 묶음의 아래쪽부터 위로 맞춰 봅니다. `from`을 두 번 적으면 "`From:`은 딱 하나다, 두 번째 `From:`이 *없다는 것*까지 서명한다"는 뜻이 됩니다. 이게 없으면 공격자가 정상 서명된 메일에 **`From:` 헤더를 하나 더 붙일** 수 있고, 어떤 메일 프로그램은 서명이 여전히 검증되는 상태에서 덧붙인 쪽을 화면에 보여 줍니다. 오버사이닝을 하면 `From:`을 더 붙이는 순간 서명이 깨집니다.

본문 해시가 얼마나 예민한지 한 줄로 확인해 볼 수 있습니다. 글자 하나만 다른 본문 두 개입니다.

```
$ printf 'Please find the March invoice attached.\r\n' | openssl dgst -sha256 -binary | base64
lNXsHoS7vr6QrKDmysIJdvi6qfRmHA6shFtOVsiEKWc=

$ printf 'Please find the March invoice attached!\r\n' | openssl dgst -sha256 -binary | base64
dkZtOlxcLddR9/RIEYqlxeE/GcjT4zZZlrPMk+zMuss=
```

- `printf '...\r\n'` — 본문. 이메일이 쓰는 줄바꿈(CR LF)을 붙였습니다.
- `openssl dgst -sha256 -binary` — SHA-256 해시를 바이트 그대로 계산합니다.
- `base64` — DKIM이 `bh=`에 적는 방식으로 인코딩합니다([Base64](../http-analysis/base64.md)).
- `.`을 `!`로 바꿨을 뿐인데 해시가 완전히 달라집니다. 공격자가(또는 바닥글을 붙이는 메일링 리스트가) 본문 한 글자라도 바꾸면 `bh=`가 맞지 않아 DKIM이 "body hash did not verify" 같은 메시지와 함께 실패합니다.

(실제 서명 서버는 먼저 본문 전체를 정규화합니다. 끝에 공백이 없는 한 줄짜리 본문이라면 `simple`이든 `relaxed`든 위와 같은 바이트가 됩니다.)

### DNS에 있는 공개 키 { #dkim-dns }

```
$ dig +short TXT s2026._domainkey.partner.example
"v=DKIM1; k=rsa; " "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx4Lr2Vq9...(about 390 characters)...IDAQAB"
```

- `s2026._domainkey.partner.example` — 셀렉터 + 고정 이름 `_domainkey` + 서명 도메인.
- 답이 **따옴표로 묶인 문자열 두 개**로 옵니다. TXT 문자열 하나는 최대 255자인데 2048비트 RSA 키는 그보다 길어서 나눠 담은 것이고, 받는 쪽이 이어 붙입니다.
- `v=DKIM1` — 키 레코드 버전.
- `k=rsa` — 키 종류(Ed25519 키면 `ed25519`).
- `p=MIIB...IDAQAB` — Base64로 적은 **공개 키**. `MIIB...`는 2048비트 RSA 공개 키의 흔한 시작, `IDAQAB`는 흔한 끝입니다.
- 선택 항목: `t=y`는 "시험 중 — 실패해도 너무 엄하게 다루지 말 것", `t=s`는 `i=`에 서브도메인을 쓰면 안 된다는 뜻, `h=sha256`은 쓸 수 있는 해시 알고리즘 제한.
- **`p=`가 비어 있으면**(`"v=DKIM1; p="`) 그 키는 **폐기(revoke)** 된 것입니다. 그 셀렉터를 쓰는 서명은 모두 실패합니다. 키를 은퇴시킬 때 이렇게 합니다.

셀렉터는 작은 **정찰(recon)** 거리도 됩니다. 흔한 셀렉터 이름을 보면 그 회사가 어떤 메일·마케팅 서비스를 쓰는지 드러납니다. SPF의 `include`와 같은 이치입니다.

### DKIM 결과 값 { #dkim-results }

`Authentication-Results:`는 서명 하나당 DKIM 결과 하나를 적습니다. 메일 하나에 서명이 **여러 개** 붙을 수 있고(예: 회사 서명 하나, 메일 업체 서명 하나), 각각 따로 결과를 받습니다.

| 결과 | 뜻 | 분석가는 이렇게 읽는다 |
| --- | --- | --- |
| `pass` | 서명 있음, 키 찾음, 본문 해시와 서명 모두 검증됨 | `d=` 도메인이 서명했고, 서명한 부분은 바뀌지 않았다 |
| `fail` | 서명은 있는데 검증 실패(본문 변경, 헤더 변경, 키 불일치) | 가는 길에 바뀌었거나(메일링 리스트나 보안 게이트웨이가 내용을 고치는 경우가 많음) **위조** |
| `none` | 서명이 아예 없음 | 증거 없음. 위조의 증거는 아니지만, 이제 정상 대량 발송자는 서명이 의무다 |
| `neutral` | 서명은 있는데 처리할 수 없음(문법 문제 등) | none처럼 다룬다 |
| `policy` | 서명은 맞지만 받는 쪽이 인정하지 않음(예: `l=` 사용, 약한 키) | 이유를 본다. 서명 쪽이 허술하다는 신호일 때가 있다 |
| `temperror` | 키 조회가 일시적으로 실패(DNS 시간 초과) | 나중에 다시 |
| `permerror` | 키 레코드가 없거나 고장, 또는 폐기된 키(`p=` 비어 있음) | 서명 쪽 설정 문제 — 또는 존재한 적 없는 셀렉터를 적은 서명 |

자주 보는 결과 줄과 읽는 법:

```
dkim=pass header.d=partner.example header.s=s2026 header.b=Kp3vT9xQ
dkim=fail (body hash did not verify) header.d=partner.example header.s=s2026 header.b=Kp3vT9xQ
dkim=none (message not signed)
dkim=permerror (no key for signature) header.d=partner.example header.s=old2019
```

- 두 번째 줄: 서명 자체는 멀쩡한데 **본문**이 바뀌었습니다. 리스트 서버가 바닥글을 붙이거나 게이트웨이가 링크를 고쳐 쓴 뒤에 흔히 나옵니다.
- 네 번째 줄: 메일이 DNS에 키가 없는 셀렉터 `old2019`를 적고 있습니다. 회사가 아직 쓰이는 옛 키를 지웠거나, 누군가 서명 헤더를 뜻도 모른 채 베껴 붙인 것입니다.

### DKIM이 증명하지 *못하는* 것 { #dkim-limits }

- **`d=`가 `From:`과 같을 필요가 없습니다.** 어느 도메인이든 어느 메일에든 서명할 수 있습니다. 공격자가 `lookalike-pay.example`을 등록해 `d=lookalike-pay.example`로 완벽하게 서명하고 `From: <ceo@victim.example>`이라고 적으면, 결과는 진짜 `dkim=pass` — 다만 엉뚱한 도메인에 대한 것입니다. `d=` 도메인이 화면의 `From:` 도메인과 같아야 한다고 요구하는 것은 **DMARC 일치(alignment)** (다음 페이지)입니다.
- **pass라고 내용이 안전한 건 아닙니다.** 정상 플랫폼의 탈취된 계정은 서명까지 완벽한 피싱을 보냅니다.
- **재전송(replay).** 서명은 만료될 때까지 유효하기 때문에, 공격자가 평판 좋은 도메인이 정상 서명한 메일을 **딱 한 통** 손에 넣으면(예: 그 서비스에 가입해서, 서명된 헤더와 본문을 그대로 써먹을 수 있는 메일을 받아서) **그 메일을 그대로 수천 명에게 다시 보낼** 수 있습니다. 모든 사본이 검증을 통과합니다. `To:`처럼 서명하지 않은 헤더(`h=`에 없다면)는 바꿔도 서명이 안 깨집니다. 그래서 `x=` 만료를 짧게 두고 `To:`까지 서명하는 것이 중요합니다.
- **아무것도 암호화하지 않습니다.** 메일은 거쳐 가는 모든 서버에서 여전히 읽을 수 있습니다. DKIM은 출처와 무결성만 증명합니다.

**[보충]** 메일을 **고치는** 전달(제목에 꼬리표나 바닥글을 붙이는 메일링 리스트, URL을 고쳐 쓰는 게이트웨이)은 SPF뿐 아니라 DKIM도 깨뜨립니다. 그 해답이 **ARC**(Authenticated Received Chain, RFC 8617)입니다. 중간 서버마다 자기가 본 결과를 기록하고 봉인해서, 마지막 받는 쪽이 "리스트가 받았을 때는 통과했다"는 기록을 믿을지 고를 수 있게 합니다. 이런 메일에는 `ARC-Authentication-Results:`, `ARC-Message-Signature:`, `ARC-Seal:` 헤더가 보입니다.

## SOC에서 SPF 결과와 DKIM을 쓰는 법 { #soc-use }

- **피싱 분석은 늘 우리 결과 헤더에서 시작합니다.** 우리 경계/클라우드 메일 서비스가 쓴 맨 위 `Authentication-Results:`를 찾아, `spf=`, `dkim=`, `dmarc=`를 함께 읽고 `smtp.mailfrom`, `header.d`, `header.from`을 적어 둡니다. 세 도메인이 서로 다르면 왜 그런지 따져 봅니다.
- **설명은 `Received-SPF:`로.** `client-ip`와 `mechanism`을 보면 IP가 허락된 어느 범위, 어느 업체 `include`에서 왔는지 압니다. 큰 공용 플랫폼의 `include`로 얻은 pass는 "그 플랫폼을 통해 보냈다"는 것만 증명합니다.
- **`dkim=fail`은 맥락과 함께 봅니다.** 메일링 리스트를 거친 메일의 본문 해시 실패는 정상이고, 은행에서 바로 온 메일의 실패는 정상이 아닙니다.
- **우리 경계보다 아래에 있는 결과 헤더는 무시합니다.** 메일과 함께 들어온 `Authentication-Results:`는 공격자가 쓸 수 있습니다.
- **우리 도메인은:** 우리 이름으로 보내는 모든 서비스가 (업체 도메인만이 아니라) 우리 도메인으로 서명하는지, 키가 2048비트 RSA나 Ed25519인지, 옛 셀렉터는 폐기했는지, SPF가 조회 10회 아래인지 지켜봅니다. 이걸 보는 도구가 DMARC 집계 보고서(다음 페이지)입니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    SPF 결과 일곱 가지와 받는 쪽의 처리 방식은 그대로입니다. SPF 표준은 여전히 RFC 7208이고 `Received-SPF:` 형식도 같습니다. DKIM도 여전히 RFC 6376이고, 태그도, `selector._domainkey` 키 조회도, pass/fail/none 결과도 같습니다. "`dkim=pass`를 찾고, 그다음 어느 도메인이 통과했는지 본다"는 습관이 지금도 맞습니다. 우리 경계 서버의 `Authentication-Results:`를 먼저 읽는 것이 여전히 이메일 분석의 중심입니다.

!!! info "[변경됨] 바뀐 것"
    - **`Authentication-Results:`는 이제 RFC 8601이 정의합니다.** RFC 7001을 (RFC 7601을 거쳐) 대체했습니다. 분석가 눈에 보이는 헤더 모양은 같습니다.
    - **대량 메일에 DKIM이 의무가 됐습니다.** 2024년부터 Gmail과 Yahoo는 대량 발송자에게 SPF·DKIM·DMARC와 `From:` 도메인 일치를 요구하고, Microsoft도 2025년 5월부터 Outlook.com으로 대량 발송하는 쪽에 비슷한 규칙을 적용했습니다. 그래서 큰 정상 발송자의 메일에 `dkim=none`이 붙는 건 이제 드문 일입니다.
    - **더 강한 키와 새 알고리즘.** RFC 8301(2018)은 `rsa-sha1`을 서명에 쓰면 안 되고, 키는 최소 1024비트, 권장 2048비트라고 정했습니다. RFC 8463은 `ed25519-sha256`을 추가했습니다. 실무에서는 2048비트 RSA가 표준이고, 모든 검증 서버가 Ed25519를 지원하지는 않아서 Ed25519는 RSA를 대신하기보다 함께 올리는 경우가 많습니다.
    - **DMARC가 Proposed Standard가 됐습니다**(RFC 9989~9991, RFC 7489 대체). SPF와 DKIM 결과를 합치는 방식이 일부 바뀌었고, 다음 페이지에서 다룹니다.
    - **DKIM 재전송(replay)이 큰 문제로 떠올랐고**, IETF는 재전송에 강하고 전달에도 살아남도록 다시 설계한 "DKIM2"를 만들고 있습니다. 2026년 말 현재 아직 초안(draft)이지 표준이 아닙니다. 실제 운영 메일 헤더에서 보게 되리라고 기대하지는 마세요.
    - **클라우드 플랫폼이 대세입니다.** 대부분 조직의 메일은 호스팅 메일 업체가 서명하고, 업체들은 표준 결과 옆에 자기만의 종합 판정(`compauth` 같은)을 붙입니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **`dkim=pass`나 `spf=pass` 하나만 믿지 않습니다.** *어느* 도메인이 통과했는지(`header.d`, `smtp.mailfrom`)를 화면의 `From:`과 꼭 비교합니다. 공격자 자기 도메인에 대한 pass는 아무 가치가 없습니다.
    - **누가 썼는지 확인하지 않은 `Authentication-Results:`는 믿지 않습니다.** 우리 경계나 클라우드 메일 서비스가 쓴 헤더만 씁니다.
    - **`dkim=none`을 위조의 증거로, `dkim=fail`을 무조건 공격으로 보지 않습니다.** 맥락(메일링 리스트, 링크를 고쳐 쓰는 게이트웨이)이 중요합니다.
    - **1024비트나 `rsa-sha1` 키를 계속 쓰지 말고, `l=`은 절대 쓰지 말고, 옛 셀렉터는 폐기합니다**(빈 `p=` 공개). 키를 DNS에 영원히 두지 않습니다. 새거나 깨질 수 있는 옛 키가 있으면 누구나 우리 이름으로 서명할 수 있습니다.
    - **셀렉터를 "메일에서 서명하는 부분"이라고 설명하지 않습니다.** 키의 이름입니다. 서명한 부분은 `h=`와 `bh=`에 있습니다.

## 확인 문제 { #quiz }

### 문제 1

사용자가 "검사를 다 통과한" 메일을 신고했습니다. 헤더 묶음 윗부분은 아래와 같습니다(오래된 줄일수록 아래). 무엇이 잘못됐고, 진짜 인증 결과는 무엇입니까?

```
Authentication-Results: mx1.victim.example;
       spf=softfail smtp.mailfrom=victim.example;
       dkim=none;
       dmarc=fail (p=none dis=none) header.from=victim.example
Received: from mail.victim.example (unknown [203.0.113.66])
        by mx1.victim.example (Postfix) with ESMTP id 7HnQ2c; Thu, 19 Nov 2026 03:05:11 +0000
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=victim.example;
       dkim=pass header.d=victim.example;
       dmarc=pass header.from=victim.example
From: "IT Service Desk" <it-support@victim.example>
Subject: Password expires today - confirm here
```

??? success "정답과 해설"
    우리 authserv-id `mx1.victim.example`이 달린 결과 헤더가 **두 개**입니다. 우리 경계 `Received:` 줄 **아래**에 있는 것("전부 통과")은 `203.0.113.66`에서 **메일 안에 담겨** 들어왔습니다. 공격자가 쓴 것입니다. 우리 서버가 이걸 지웠어야 하니(RFC 8601은 들어오는 메일에 붙은, 우리 이름의 결과 헤더를 지우라고 합니다) 고쳐야 할 설정 빈틈도 하나 드러난 셈입니다.

    **진짜** 결과는 `mx1`이 경계 `Received:` 줄 다음에 붙인 맨 위의 것입니다. `spf=softfail`(IP `203.0.113.66`이 `~all`로 끝나는 victim.example의 목록에 없음), `dkim=none`(서명 없음), `dmarc=fail`. 우리 도메인의 DMARC 정책이 `p=none`뿐이라 아무것도 막지 않았습니다. 결론: 바깥 서버가 우리 IT 헬프데스크를 사칭한 것. 다음 조치: IP 차단, 같은 제목·IP로 다른 메일함 검색, 우리 DMARC 정책을 `p=none`보다 강하게 올리는 것 검토.

### 문제 2

메일에 `From: "Partner Billing" <billing@partner.example>`과 아래 결과가 붙어 있습니다. DKIM은 통과했습니다. 이 메일이 `partner.example`에서 왔다는 것이 증명됐습니까?

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=bounce.mailer-hub.example;
       dkim=pass header.d=mailer-hub.example header.s=k1 header.b=Zx81PqWe
```

??? success "정답과 해설"
    **아닙니다.** 두 검사 모두 통과했지만, `partner.example`이 아니라 **`mailer-hub.example`에 대해서**입니다.

    - `smtp.mailfrom=bounce.mailer-hub.example` — SPF는 대량 메일 플랫폼의 서버가 플랫폼 자기 반송 도메인으로 보낼 자격이 있다는 것만 증명했습니다.
    - `header.d=mailer-hub.example` — 서명은 거래처가 아니라 플랫폼의 키로 만들었습니다.
    - 화면에 보이는 `From:` 도메인 `partner.example`은 **어느 검사도** 확인하지 않았습니다.

    그 플랫폼을 쓰면서 자기 도메인 DKIM을 설정하지 않은 진짜 거래처일 수도 있고, 그 플랫폼에 계정이 있는 다른 누군가가 거래처인 척하는 것일 수도 있습니다. DKIM은 "`d=` 도메인이 서명했다"를 증명할 뿐이고, `d=`가 `From:`과 같은지는 DMARC 일치의 몫인데 이 메일은 거기서 실패합니다. 확인 안 된 메일로 다룹니다. 거래처가 예전에 보낸 진짜 메일과 비교하고(`header.d=partner.example`이 붙어 있었나?), 결제 정보 변경은 알고 있는 번호로 전화해 확인합니다.

### 문제 3

`shop.example`의 뉴스레터 두 통이 왔습니다. 하나는 바로, 하나는 제목에 `[staff-list]`를 붙이고 본문에 바닥글을 붙이는 사내 메일링 리스트를 거쳐서. 결과는 이렇습니다.

```
Direct:     dkim=pass header.d=shop.example header.s=s1
Via list:   dkim=fail (body hash did not verify) header.d=shop.example header.s=s1
```

DKIM-Signature에는 `h=from:to:subject:date:message-id`가 있습니다. 리스트를 거친 사본은 왜 실패했고, 어떤 변경 하나만으로도 이미 충분히 깨졌을까요? 이건 공격입니까?

??? success "정답과 해설"
    **"Body hash did not verify"** 는 검증하는 쪽이 계산한 본문 해시가 `bh=`와 더 이상 맞지 않는다는 뜻입니다. 리스트가 본문에 **바닥글**을 붙였으니 본문이 바뀌었고 → 해시 불일치. 이것 하나만으로 실패하기에 충분합니다.

    제목 꼬리표도 **혼자서** 서명을 깨뜨렸을 겁니다. `subject`가 `h=`에 들어 있으니, 서명된 헤더를 바꾸면 `b=`의 서명 확인이 실패합니다. (여기서는 검증 쪽이 본문 해시 문제를 먼저 보고했을 뿐입니다.)

    **공격이 아닙니다.** 메일링 리스트가 메일을 고칠 때 생기는 평범한 부작용이고, 바로 이것 때문에 ARC가 있습니다. 리스트 서버가 "내가 받았을 때는 DKIM이 통과했다"를 ARC 헤더에 기록하면, 마지막 받는 쪽이 그 기록을 믿을지 고를 수 있습니다. 분석가로서는 맥락이 단서입니다. 같은 `d=`와 셀렉터가 바로 온 사본에서는 통과했고, 리스트 사본에는 리스트 자체의 `Received:` 줄과 수정 흔적이 보입니다.
