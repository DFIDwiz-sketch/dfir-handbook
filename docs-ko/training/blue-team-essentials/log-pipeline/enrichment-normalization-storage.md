---
title: "보강·정규화·저장 — 맥락 붙이기, 공통 정보 모델, 분류, Hot/Warm/Cold와 로그 수명 주기"
tags:
  - training
  - blue-team
  - logging
  - siem
---

# 보강·정규화·저장 — 맥락 붙이기, 공통 정보 모델, 분류, Hot/Warm/Cold와 로그 수명 주기 { #enrichment-normalization-storage }

!!! abstract "이 페이지에서 다루는 것"
    로그가 파싱된 **다음에** 무슨 일이 일어나는지, 그리고 그 단계 하나하나가 우리가 보는 것과 찾을 수 있는 것을 어떻게 바꾸는지 봅니다. 먼저 **보강(enrichment)**. SIEM이 로그에 이미 있는 칸을 가지고 다른 곳에서 맥락(자산 주인, 사용자 역할, 도메인 나이, 평판, 패치 상태)을 찾아와 붙이는 일입니다. 맨몸의 DNS 질의 한 줄을 몇 초 만에 판단할 수 있는 이벤트로 바꿔 주지만, 오래됐거나 "그 순간 기준"인 맥락이라는 함정도 있습니다. 다음은 **상관 분석(correlation)**. 로그 하나를 다른 로그(DHCP, 로그온)와 이어서 "어느 기계, 어느 사람"에 답하는 일입니다. 그다음 <strong>필드 정규화(field normalization)</strong>와 **공통 정보 모델(common information model)**(Splunk CIM, Elastic ECS, OCSF, Microsoft ASIM, Google UDM). `src_ip`, `sourceIP`, `source.ip`를 왜 한 칸처럼 검색할 수 있어야 하는지, 하는 방법 세 가지(이름 바꾸기, 복사, 검색할 때 별칭), 그리고 정규화된 이름이 원본 로그에는 없을 수 있는 이유를 봅니다. 그다음 **분류(categorization)**. 4624나 sshd 문구를 몰라도 "mike의 모든 로그인"을 찾는 방법입니다. 마지막으로 **저장(storage)**. 같은 종류끼리 모아 두는 인덱스, 종류별 보관 기간, hot/warm/cold/frozen 계층, 로그 수명 주기, 그게 오래된 사건 조사에 뜻하는 것, SIEM 엔지니어에게 물어볼 질문, 그리고 파이프라인 전체 정리. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. **보강**은 원래 로그에 없던 정보를, 로그에 **있던** 칸으로 찾아와 덧붙이는 일이다(IP → 호스트와 주인, 도메인 → 나이와 순위, 사용자 → 역할). SIEM이 주는 가장 큰 시간 절약 중 하나이고, 파싱이 제대로 됐을 때만 동작한다.
2. 보강은 **사진 한 장**이다. 받을 때 보강은 로그가 도착한 순간의 사실을, 검색할 때 보강은 지금의 사실을 보여 준다. 조사에서 "이 IP가 어느 호스트였나", "이 사람이 어떤 역할이었나"를 물을 때 이 차이가 중요하다.
3. **상관 분석**은 로그 하나를 다른 로그(DHCP 임대, 로그온, DNS 응답)와 이어서, 로그 하나로는 답할 수 없는 질문에 답한다. 예: 03:12에 그 IP 뒤에 있던 사람은 누구인가.
4. 제품마다 같은 것을 다른 이름으로 부른다. **필드 정규화**는 이것들을 이름 하나로 맞춰서 검색 하나로 전부 찾게 한다. 표준 이름 묶음이 **공통 정보 모델**(데이터 모델, 스키마)이다.
5. 정규화는 받을 때 이름을 바꾸거나, 원래 칸 옆에 정규화된 복사본을 더하거나, 검색할 때 별칭을 건다. 우리 SIEM이 어느 방식인지 알아야 한다. 정규화된 칸 이름은 **원본 로그에 없을 수 있다**.
6. 정규화는 **값**(`allow`/`accept`/`permit` → `allowed`, `CORP\mike`/`mike@corp.example` → `mike`)과 **뜻**까지 다룬다. 이름이 같은 칸도 소스마다 뜻이 다를 수 있다.
7. **분류**는 이벤트에 "무슨 종류의 일인가"(인증, 프로세스 시작, 네트워크 연결) 표시를 붙여서, 분석가와 규칙이 모든 소스에 걸쳐 "mike의 실패한 로그인 전부"를 물을 수 있게 한다. 파서가 분류하지 않는 소스는 그런 검색에서 보이지 않는다.
8. 로그는 **같은 종류끼리** 저장되고, 종류마다 **보관 기간**이 있으며, **hot → warm → cold → archive/frozen → 삭제** 순서로 나이 든다. 새 데이터는 빠르고, 오래된 데이터는 느리거나 되살려야 하거나 이미 없다. 이 숫자는 사고가 나기 **전에** 알아 둔다.

## 파이프라인의 어디쯤인가 { #where }

[수집 페이지](collection-methods.md)에서 이벤트가 호스트에서 SIEM까지 왔고, [형식 페이지](formats-structure.md)에서 이름 붙은 칸으로 잘렸습니다. 그 자르기가 이 페이지 모든 내용의 바닥입니다. 보강은 무언가를 찾아보려면 깨끗한 `query`나 `src_ip` 칸이 있어야 합니다. 정규화는 어느 칸이 출발지 IP인지 알아야 이름을 바꿀 수 있습니다. 분류는 이 이벤트가 로그온이라는 걸 알아야 합니다. 파싱이 실패하면 뒤의 단계는 하나도 일어나지 않고, 그 이벤트는 보강도 정규화도 분류도 안 된 덩어리로 SIEM에 앉아 있게 됩니다. 대부분의 규칙과 대시보드는 그걸 보지 못합니다.

우편물 분류 센터를 떠올리면 쉽습니다. 수집은 편지를 실어 오는 차입니다. 파싱은 주소란을 읽는 일입니다. 보강은 직원이 봉투에 정보를 더 찍어 주는 일입니다("보낸 곳은 알려진 회사", "이 우편번호는 새로 생긴 동네"). 정규화는 모든 주소를 한 가지 표준 양식으로 다시 쓰는 일입니다. 분류는 색깔 스티커를 붙이는 일입니다(청구서, 소포, 법원 통지). 저장은 어느 선반에 두고, 얼마나 있다가 지하 창고로 옮기거나 파쇄할지 정하는 일입니다. 단계마다 나중 일을 빠르게 해 주지만, 단계마다 실수가 끼어들 수도 있습니다. 그 실수는 그 단계가 있다는 걸 아는 사람만 알아챕니다.

## 로그 보강 { #enrichment }

### 무엇이고 왜 중요한가 { #enrichment-what }

대부분의 로그 소스는 사건을 설명하는 데 **꼭 필요한 만큼만** 씁니다. DNS 서버는 누가 물었는지, 무엇을 물었는지, 어떤 종류의 레코드인지를 남깁니다. 파싱된 실제 같은 질의 로그 한 줄입니다.

```json
{
  "@timestamp": "2026-11-20T03:12:44.218Z",
  "event.dataset": "dns.query",
  "source.ip": "10.0.10.3",
  "dns.question.name": "invoice-portal-secure.example",
  "dns.question.type": "A",
  "dns.response_code": "NOERROR"
}
```

한 줄씩 보면, 이벤트 시각, 이 로그가 무슨 종류인지(DNS 질의), 물어본 IP, 물어본 이름, 레코드 종류(`A` = IPv4 주소), 결과 코드(`NOERROR` = 이름이 풀렸다)입니다. 이게 나쁜 걸까요? 알 수 없습니다. 다음에 물어볼 질문들 — 어디로 풀렸나, 우리 조직에서 이 도메인을 본 적이 있나, 몇 살짜리 도메인인가, 차단 목록에 있나, 10.0.10.3은 어느 기계인가, 누가 쓰나, 그 사람이 중요한가 — 모두 다른 곳을 찾아봐야 답이 나옵니다. 이 이벤트로 경보가 울리면 분석가는 10분 동안 손으로 그걸 찾아보고, 다음 경보에서 또, 그다음 경보에서 또 합니다.

이제 SIEM이 보강한 뒤의 같은 이벤트입니다.

```json
{
  "@timestamp": "2026-11-20T03:12:44.218Z",
  "event.dataset": "dns.query",
  "source.ip": "10.0.10.3",
  "dns.question.name": "invoice-portal-secure.example",
  "dns.question.type": "A",
  "dns.response_code": "NOERROR",
  "dns.resolved_ip": ["203.0.113.77"],
  "enrich.domain.first_seen_org": "2026-11-20T03:12:44Z",
  "enrich.domain.newly_observed": true,
  "enrich.domain.popularity_rank": null,
  "enrich.domain.registered": "2026-11-17",
  "enrich.domain.age_days": 3,
  "enrich.ti.match": false,
  "host.name": "fin-ws-014",
  "host.patch_status": "missing 2 critical updates",
  "user.name": "kyle.ward",
  "user.roles": ["Domain Admins"],
  "enrich.added_at": "2026-11-20T03:12:46Z"
}
```

앞의 여섯 칸은 그대로이고, 그 뒤는 전부 덧붙은 것입니다. 덧붙은 칸을 읽어 보면:

- `dns.resolved_ip` — 짝이 맞는 DNS 응답 로그에서 가져온 답. 이제 방화벽과 프록시 로그에서 찾아볼 IP가 생겼습니다.
- `first_seen_org` / `newly_observed: true` — 이 순간 전까지 우리 조직의 어떤 기계도 이 도메인을 물어본 적이 없다는 뜻. 정상 도메인은 대부분 계속 반복해서 조회되므로, 처음 보는 조회는 쓸 만한 약한 신호입니다.
- `popularity_rank: null` — 인기 사이트 순위 목록에 없음. 순위에 없다고 나쁜 건 아닙니다(인터넷 대부분이 순위 밖). 다만 크고 정상적인 서비스는 보통 순위에 있습니다.
- `registered` / `age_days: 3` — 사흘 전에 등록된 도메인. 피싱·악성코드 도메인은 등록 후 며칠 안에 쓰이는 일이 많습니다([도메인 나이](../dns/domain-signals.md#age-randomness)). 공격자는 준비 단계에서 도메인을 삽니다(MITRE ATT&CK T1583.001, 인프라 확보: 도메인).
- `ti.match: false` — SIEM이 가진 위협 인텔리전스 목록 어디에도 없음. 새 도메인은 아직 목록에 안 올라간 경우가 많습니다. 그래서 다른 신호들이 중요합니다.
- `host.name`, `host.patch_status` — 10.0.10.3은 `fin-ws-014`, 중요 업데이트 두 개가 빠진 재무팀 PC. 자산 목록이나 취약점 스캐너에서 온 정보입니다.
- `user.name`, `user.roles` — 거기 로그온해 있는 사람은 `kyle.ward`이고 **도메인 관리자**. 디렉터리와 로그온 데이터에서 온 정보입니다.
- `enrich.added_at` — 보강을 붙인 시각. <strong>[보충]</strong> 잘 만든 파이프라인은 이걸 남겨서, 맥락이 얼마나 신선했는지 알 수 있게 합니다.

합쳐 보면 이렇습니다. 패치 안 된 재무팀 PC에 앉은 도메인 관리자가 새벽 3시 12분에, 조직에서 처음으로, 재무 냄새 나는 이름의 사흘짜리 순위 밖 도메인을 조회했습니다. 원래 여섯 칸에는 이 중 아무것도 없었습니다. 이게 보강의 핵심입니다. "DNS 질의가 있었다"를 몇 초 만에 내릴 수 있는 판단으로 바꿔 줍니다. 그리고 바로 이 때문에 파싱이 중요합니다. SIEM이 `dns.question.name`을 뽑아내지 못했다면 그걸로 아무것도 찾아볼 수 없습니다.

### 흔한 보강 출처 { #enrichment-sources }

| 보강 | 무엇으로 찾나 | 답해 주는 것 | 흔한 출처 |
| --- | --- | --- | --- |
| 자산·호스트 | IP, 호스트 이름 | 어느 기계, 주인, 중요도, OS | CMDB, 자산 목록, EDR |
| 신원 | 사용자 이름, IP + 시각 | 어느 사람, 부서, 역할, 특권 계정인지, 계정 활성 여부 | 디렉터리(AD, Entra ID), 인사 데이터, 로그온 이벤트 |
| 네트워크 위치 | IP | 내부 서브넷 이름(DMZ, 서버 VLAN, 손님 Wi-Fi), 사이트 | IPAM, 서브넷 목록 |
| 위치·ASN | 외부 IP | 나라, 네트워크 주인, 호스팅인지 가정용인지 | GeoIP / ASN 데이터베이스 |
| 위협 인텔리전스 | IP, 도메인, URL, 해시 | 알려진 악성인가, 어느 캠페인, 얼마나 확실한가 | TI 플랫폼, 피드 |
| 도메인 정보 | 도메인 | 나이, 등록 기관, 인기 순위, 우리 조직 첫 관측 | WHOIS/RDAP, 순위 목록, 자체 DNS 기록 |
| 취약점 | 호스트 | 빠진 패치, 알려진 취약 소프트웨어 | 취약점 스캐너 |
| 퍼짐 정도 | 해시, 프로세스 이름, 도메인 | 몇 대의 기계가 이걸 봤나 | EDR, 자체 로그 기록 |

### 받을 때인가, 검색할 때인가 { #enrichment-when }

SIEM이 맥락을 붙일 수 있는 순간은 두 번이고, 둘은 다른 답을 줍니다.

<strong>받을 때 보강(ingest-time enrichment)</strong>은 이벤트가 도착하는 순간 찾아보고, 그 결과를 저장되는 이벤트 안에 써 넣습니다. 장점은 **그 순간의 사실**을 기록한다는 것입니다. 03:12에 10.0.10.3이 `fin-ws-014`였고 09:00에 DHCP가 그 주소를 노트북에 줘도, 저장된 이벤트는 여전히 `fin-ws-014`라고 말합니다. 약점은 고칠 수 없다는 것(그날 자산 목록이 틀렸다면 그 이벤트는 영원히 틀림)과, 나중에 알게 된 사실을 쓸 수 없다는 것입니다. 10:00에 차단 목록에 오른 도메인도 03:12 이벤트에는 계속 `ti.match: false`로 남습니다.

<strong>검색할 때 보강(search-time enrichment)</strong>은 검색을 돌리는 순간 찾아봅니다. 장점은 **지금의** 데이터를 쓴다는 것이라, 03:12의 그 도메인이 이제 악성으로 표시됩니다. 약점은 정반대입니다. 오늘 "10.0.10.3은 어느 호스트?"를 물으면 **오늘의** 답이 나오고, 그건 다른 기계일 수 있습니다. 사용자 역할도 마찬가지로, 어젯밤 Domain Admins에 추가된 사람은 지난주 이벤트에서도 도메인 관리자로 보입니다.

대부분의 SOC에서 통하는 대략의 규칙:

- **시간에 따라 바뀌고 과거 기준으로 맞아야 하는 것** — IP → 호스트, IP → 사용자, 그 당시 사용자 역할 — 은 받을 때 보강하거나, 지금의 표 대신 시각이 찍힌 로그(DHCP, 로그온 이벤트)와 상관 분석하는 게 낫습니다.
- **최신 지식이 더 나은 것** — 위협 인텔리전스, 평판 — 은 검색할 때 보강하거나, 새 인텔리전스가 들어오면 과거 데이터를 다시 훑는 게 낫습니다(많은 SIEM이 새 지표로 지난 N일을 다시 헌팅하는 기능을 가지고 있습니다).

<strong>[주의]</strong> 보강 칸을 보고서에 쓰기 전에, 그게 "그 순간 기준"인지 "지금 기준"인지 꼭 확인하세요. "그 호스트는 재무팀 소유였다"는 과거에 대한 주장입니다. 그 칸이 오늘의 CMDB에서 온 거라면 그렇다고 적으세요.

### 검색할 때 하는 간단한 lookup, 풀어서 보기 { #enrichment-spl }

많은 SIEM은 검색문 안에서 보강할 수 있게 해 줍니다. Splunk에서는 **lookup**으로 합니다. SIEM이 이벤트와 맞붙여 볼 수 있는 표(흔히 CSV 파일)입니다. `ip`, `hostname`, `owner`, `criticality` 열을 가진 `asset_inventory`라는 lookup이 있다고 합시다. 위의 DNS 이벤트를 찾는 검색입니다.

```
index=dns query="invoice-portal-secure.example"
| lookup asset_inventory ip AS src_ip OUTPUT hostname owner criticality
| table _time src_ip hostname owner criticality query
```

완전 초보 기준으로 하나씩 보면:

- `index=dns` — DNS 로그가 들어 있는 인덱스(저장 구역)만 검색합니다. 인덱스는 [아래](#storage)에서 더 다룹니다.
- `query="invoice-portal-secure.example"` — `query` 칸이 정확히 그 이름인 이벤트만 남깁니다. 칸 이름은 DNS 파서가 만드는 대로이고, 여기서는 `query`입니다.
- `|` — 파이프. 왼쪽 결과를 오른쪽 명령으로 넘깁니다. 공장의 컨베이어 벨트 같은 것입니다.
- `lookup asset_inventory` — `lookup` 명령. 이벤트마다 `asset_inventory` 표에서 맞는 줄을 찾습니다.
- `ip AS src_ip` — 표의 `ip` 열을 이벤트의 `src_ip` 칸과 맞춰 봅니다.
- `OUTPUT hostname owner criticality` — 맞는 줄의 그 세 열을 새 칸으로 이벤트에 복사합니다. 맞는 줄이 없으면 그 칸은 그냥 비어 있습니다.
- `table _time src_ip hostname owner criticality query` — 결과를 그 열들로, 그 순서대로 표로 보여 줍니다. `_time`은 Splunk의 이벤트 시각입니다.

화면에는 이렇게 나옵니다.

```
_time                    src_ip      hostname     owner        criticality  query
2026-11-20 03:12:44.218  10.0.10.3   fin-ws-014   finance-ops  high         invoice-portal-secure.example
```

기억하세요. 이 lookup은 **검색할 때** 보강이라서, `hostname`은 그 표가 **지금** 말하는 값입니다. 그 표가 DHCP에서 매일 새로 만들어진다면, 3주 전 이벤트는 엉뚱한 기계와 짝지어질 수 있습니다.

### 상관 분석: 로그를 이어서 "누구"에 답하기 { #correlation }

표로 하는 보강이 절반이고, 나머지 절반은 **상관 분석**, 즉 다른 로그를 쓰는 것입니다. DNS 이벤트가 아는 건 IP뿐입니다. 서로 다른 세 시스템이 쓴 세 로그가 그 IP를 사람으로 바꿔 줍니다.

```
# DHCP server log (lease granted)
2026-11-19 18:02:10  ASSIGN  10.0.10.3  mac=00:1a:2b:3c:4d:5e  hostname=fin-ws-014  lease=86400

# Windows Security 4624 on fin-ws-014 (interactive logon)
2026-11-20 02:58:31  EventID=4624  LogonType=2  TargetUserName=kyle.ward  TargetDomainName=CORP  WorkstationName=FIN-WS-014

# DNS query log
2026-11-20 03:12:44  client=10.0.10.3  query=invoice-portal-secure.example  type=A
```

순서대로 읽으면, DHCP 서버가 전날 저녁 18:02에 10.0.10.3을 `fin-ws-014`에게 86,400초(24시간) 동안 빌려줬습니다. 그러니 03:12에도 그 임대는 아직 유효합니다. **4624**는 Windows의 "계정이 로그온에 성공했다" 이벤트이고, 계정이 로그온한 그 기계에 기록됩니다. **LogonType 2**는 누군가 키보드나 콘솔 앞에서 직접 자격 증명을 입력했다는 뜻입니다([로그온](../important-events/logins.md) 참고). 그러니 `kyle.ward`가 02:58에 `fin-ws-014` 앞에 앉았고, 14분 뒤 그 기계가 새 도메인을 조회한 겁니다. 공격자가 4624를 신경 쓰는 이유는 어느 계정이 어디서 쓰였는지 정확히 보여 주기 때문이고, 방어자가 신경 쓰는 이유도 똑같습니다.

조심할 점 두 가지. 첫째, 상관 분석에는 **시간 창**이 필요합니다. 맞는 DHCP 임대는 이벤트 시각에 유효했던 임대이고, 맞는 로그온은 이벤트 전에 그 호스트에서 마지막으로 있었던, 사이에 로그오프가 없는 로그온입니다. 둘째, 여러 사람이 쓰는 기계(터미널 서버, NAT 게이트웨이, 프록시)의 IP는 여러 사용자에게 이어지므로 "그 사용자"는 추측일 수 있습니다. 보고서에 그렇게 적으세요.

## 필드 정규화와 공통 정보 모델 { #normalization }

### 문제 { #normalization-problem }

업체마다 칸 이름을 자기 식으로 짓습니다. 연결의 **출발지 IP**를 다섯 소스가 각각 이렇게 씁니다.

```
Zeek conn.log (JSON):        "id.orig_h": "10.0.10.3"
Windows Firewall log (W3C):  src-ip 10.0.10.3
Palo Alto traffic (CSV):     ...,10.0.10.3,...          (column "Source address")
Sysmon Event ID 3:           <Data Name="SourceIp">10.0.10.3</Data>
Windows 4624:                <Data Name="IpAddress">10.0.10.3</Data>
```

다섯 개 모두 "이 일이 시작된 기계"라는 뜻입니다. 정규화가 없으면 10.0.10.3에서 나간 연결을 전부 찾기 위해 다섯 이름을 다 알고 이렇게 써야 합니다.

```
id.orig_h=10.0.10.3 OR src-ip=10.0.10.3 OR src_addr=10.0.10.3 OR SourceIp=10.0.10.3 OR IpAddress=10.0.10.3
```

누군가 여섯 번째 소스를 추가하고 분석가들에게 말해 주지 않을 때까지는 이게 통합니다. 그때부터 여섯 번째 소스는 모든 검색과 모든 규칙에서 소리 없이 빠집니다. 진짜 비용은 타이핑이 아니라 **아무도 알아채지 못하는 구멍**입니다.

**필드 정규화**는 소스마다의 칸을 합의된 이름 하나로 맞춰서 이걸 해결합니다. 합의된 이름(그리고 합의된 뜻과 값 형식)의 묶음을 제품에 따라 **공통 정보 모델(common information model)**, 공통 이벤트 모델, 데이터 모델, 스키마라고 부릅니다. 정규화가 되면 검색은 이것뿐입니다.

```
source.ip=10.0.10.3        (or src=10.0.10.3, src_endpoint.ip=..., depending on the model)
```

### 만나게 될 공통 모델들 { #models }

| 모델 | 쓰는 곳 | 출발지 IP | 사용자 | 메모 |
| --- | --- | --- | --- | --- |
| Splunk CIM (Common Information Model) | Splunk, Splunk ES | `src` | `user` | 데이터 모델(Authentication, Network Traffic, Endpoint…)로 묶여 있고, 주로 검색할 때 적용 |
| ECS (Elastic Common Schema) | Elastic, 여러 수집기 | `source.ip` | `user.name` | 점으로 이은 중첩 이름. OpenTelemetry 시맨틱 컨벤션과 합쳐지는 중 |
| OCSF (Open Cybersecurity Schema Framework) | AWS Security Lake와 여러 업체 | `src_endpoint.ip` | `user.name` / `actor.user.name` | 업체 중립. 숫자 ID가 붙은 이벤트 클래스로 구성 |
| ASIM (Advanced Security Information Model) | Microsoft Sentinel | `SrcIpAddr` | `TargetUsername` / `ActorUsername` | 주로 검색할 때 동작하는 파서(`_Im_Authentication` 같은 함수) |
| UDM (Unified Data Model) | Google Security Operations | `principal.ip` | `principal.user.userid` / `target.user.userid` | principal / target / src / observer라는 명사로 구성 |

다섯 개를 다 외울 필요는 없습니다. 알아야 할 건 **우리 SIEM이 무엇을 쓰는지**, 그 칸 목록이 어디에 문서로 있는지, 그리고 우리 SIEM의 `src` 같은 칸이 원본 로그에서는 `id.orig_h`였을 수 있다는 점입니다.

### 하는 방법 세 가지 { #normalization-how }

**1. 받을 때 이름 바꾸기.** 파이프라인이 저장 전에 `id.orig_h`를 `source.ip`로 바꿉니다. 검색이 간단하고 빠릅니다. 원래 이름이 사라지므로 Zeek 원본 문서를 보는 사람이 헷갈릴 수 있고, 짝짓기가 틀렸다면 저장된 데이터가 틀립니다.

**2. 받을 때 복사하기.** 파이프라인이 `id.orig_h`를 그대로 두고 같은 값으로 `source.ip`를 더합니다. 두 이름 다 통합니다. 저장 공간이 조금 더 듭니다. 원본 이벤트를 `event.original` 같은 칸에 함께 보관하는 ECS 방식 파이프라인에서 흔합니다.

**3. 검색할 때 별칭 걸기.** 저장된 데이터는 아무것도 안 바뀝니다. 검색할 때 SIEM이 `src`를 Zeek 데이터에서는 `id.orig_h`로, 방화벽 데이터에서는 `src-ip`로 번역해 줍니다. Splunk 필드 별칭과 Sentinel의 ASIM 파서 함수가 이렇게 동작합니다. 원본이 그대로 남고 짝짓기를 나중에 고칠 수 있지만, 검색이 조금 느리고 그 소스용 짝짓기가 설치돼 있어야만 됩니다.

3번의 Splunk 예시를 알아볼 수 있게 보여 드립니다(`props.conf`라는 설정 파일에 들어가고, 보통 SIEM 엔지니어가 관리합니다).

```
[zeek:conn]
FIELDALIAS-cim_src  = "id.orig_h" AS src
FIELDALIAS-cim_dest = "id.resp_h" AS dest
EVAL-action = if(conn_state IN ("REJ","S0"), "blocked", "allowed")
```

한 줄씩 보면, `[zeek:conn]` — 소스 타입(Splunk에서 로그 형식에 붙이는 이름)이 `zeek:conn`인 이벤트에 아래 설정을 적용합니다. `FIELDALIAS-cim_src = "id.orig_h" AS src` — 이 데이터를 검색할 때마다 `id.orig_h` 값을 `src`라는 이름으로도 쓸 수 있게 합니다. `FIELDALIAS-` 뒤의 글자는 그냥 이 설정의 이름입니다. 둘째 줄은 목적지에 대해 같은 일을 합니다. `EVAL-action = ...` — 검색할 때 `action`이라는 새 칸을 계산합니다. Zeek의 연결 상태가 `REJ`(거부됨)나 `S0`(응답 없음)이면 `blocked`, 아니면 `allowed`. 이게 다음 주제인 **값** 정규화입니다. (실제 짝짓기는 이보다 조심스럽습니다. `S0`는 차단이 아니라 패킷이 그냥 버려진 경우일 수도 있습니다.)

### 이름만이 아니라 값과 뜻도 { #normalization-values }

<strong>[보충]</strong> 칸 이름 바꾸기는 일의 절반일 뿐입니다. **값**도 공통 형태가 필요합니다.

- 방화벽 조치: `allow`, `accept`, `permit`, `pass`, `ALLOWED`, `1` → `allowed`.
- 사용자 이름: `CORP\kyle.ward`, `kyle.ward@corp.example`, `KYLE.WARD` → `kyle.ward`, 도메인은 따로 칸에.
- 프로토콜: `6`, `tcp`, `TCP` → `tcp`.
- 시각: 현지 시각 문자열, epoch 초, 시간대가 붙은 ISO 8601 → 한 가지 표준(UTC, ISO 8601).

이게 없으면 `action=allowed`는 한 업체의 이벤트만 찾고 나머지를 놓치며, `user=kyle.ward`는 `CORP\kyle.ward`로 쓴 이벤트를 전부 놓칩니다.

그리고 이름이 같아도 **뜻**은 여전히 다를 수 있습니다. NAT 게이트웨이 뒤에서 방화벽의 `src`는 워크스테이션이 아니라 게이트웨이 주소입니다. 이벤트 4624에서 `IpAddress`는 로그온이 **어디서** 왔는지인데, 로컬 콘솔 로그온이면 `-`나 `127.0.0.1`입니다. 모든 `source.ip`를 "공격자 기계"로 받아들이는 분석가는 틀린 결론을 냅니다. 뭔가 이상해 보이면 원본 이벤트(`event.original`, `_raw`)를 열어서 그 소스가 원래 무슨 뜻으로 썼는지 확인하세요.

### 함정: 원본 로그에 없는 칸 { #normalization-trap }

SIEM에서 `source.ip`를 보고, 센서에 있는 원본 Zeek 파일로 가서 `source.ip`를 찾습니다. 없습니다. 그 칸은 거기 있었던 적이 없고, SIEM이 만든 것입니다. 반대도 생깁니다. 동료가 "Sysmon에서는 그렇게 부르니까" `SourceIp`로 검색하라고 했는데, 우리 SIEM에서는 받을 때 이름이 바뀌어서 아무것도 안 나옵니다. 칸 이름이 사라진 것 같으면 첫 번째 용의자는 정규화입니다. 우리 SIEM의 데이터 모델 문서, 또는 `_raw`/`event.original`과 파싱된 칸을 나란히 놓고 보면 1분 안에 풀립니다.

## 분류 { #categorisation }

### 문제 { #categorisation-problem }

조직 전체에서 `mike`의 로그인 시도를 전부 찾아야 합니다. 분류가 없으면 소스마다 로그인이 어떻게 생겼는지 알아야 합니다.

```
# Windows: success and failure events
index=windows (EventCode=4624 OR EventCode=4625) TargetUserName=mike

# Linux sshd: two different sentences
index=linux process=sshd ("Accepted password for mike" OR "Failed password for mike" OR "Accepted publickey for mike")

# Cloud identity provider sign-in logs, VPN, web applications, network devices ... each with its own wording
```

**4624**는 로그온 성공, **4625**는 로그온 실패입니다. 둘 다 비밀번호를 확인한 기계가 씁니다. 공격자가 비밀번호를 맞히려 할 때는 4625가 쏟아지고(T1110, 무차별 대입), 훔친 자격 증명을 쓸 때는 조용한 4624 하나가 남습니다(T1078, 유효한 계정). Linux 줄들은 SSH 서버가 쓰는 자유 문장입니다. 신입 분석가는 이 중 아무것도 모를 수 있고, 경력자도 VPN은 깜빡합니다.

### 분류가 하는 일 { #categorisation-what }

파서가 자기가 이해하는 이벤트마다 **분류**를 붙여서 무슨 종류의 일이 일어났는지 표시하고, 결과를 나타내는 표준 칸 몇 개도 붙입니다. 그러고 나면 검색 하나로 됩니다.

```
tag=authentication user=mike
```

Splunk CIM에서 `tag=authentication`은 Authentication 데이터 모델에 속하는 이벤트를 표시하고, `action`은 `success`나 `failure`로 정규화됩니다. 아래는 ECS 방식 SIEM에서 분류된 뒤의 SSH 로그인 실패 하나를, 원래 줄과 나란히 놓은 것입니다.

```
Nov 20 03:20:07 web-07 sshd[48211]: Failed password for mike from 198.51.100.23 port 51544 ssh2
```

```json
{
  "event.original": "Nov 20 03:20:07 web-07 sshd[48211]: Failed password for mike from 198.51.100.23 port 51544 ssh2",
  "event.category": ["authentication"],
  "event.type": ["start"],
  "event.outcome": "failure",
  "user.name": "mike",
  "source.ip": "198.51.100.23",
  "source.port": 51544,
  "host.name": "web-07",
  "process.name": "sshd",
  "process.pid": 48211
}
```

한 줄씩 보면, `event.original`은 원래 줄을 보관해서 언제든 원본을 확인할 수 있게 합니다. `event.category: authentication`은 무슨 종류의 이벤트인지, `event.type: start`는 세션을 시작하려는 시도였다는 것, `event.outcome: failure`는 결과입니다. 나머지는 정규화된 사용자, 출발지, 호스트, 프로세스입니다. `mike`에 대한 Windows 4625도 `user.name: mike`와 함께 정확히 같은 `event.category`, `event.type`, `event.outcome`을 만듭니다. 그래서 `event.category:authentication AND event.outcome:failure AND user.name:mike` 검색 하나가 둘 다 찾아냅니다. 누구도 두 형식을 알 필요가 없습니다.

OCSF에서는 같은 생각을 번호 붙은 클래스로 표현합니다. **Authentication** 클래스(`class_uid` 3002, Identity & Access Management 범주)에 로그온이면 `activity_id` 1, 성공·실패는 `status_id` 1 또는 2입니다. Sentinel의 ASIM은 `_Im_Authentication` 파서를 쓰고 `EventResult`를 `Success`나 `Failure`로 둡니다.

### SIEM이 분류를 못 할 때: 태그 { #tags }

어떤 SIEM은 기본으로는 분류를 거의 안 합니다. 간단한 대안은 <strong>태그 붙이기(tagging)</strong>입니다. 알려진 로그인 모양에 맞는 이벤트마다 `login`이라는 단어를 붙이는 규칙을 파이프라인(또는 저장된 검색 정의)에 둡니다. 모두가 그 태그가 있다는 걸 알기만 하면 `tag=login user=mike`로 해결됩니다. 약점은 정규화와 같습니다. 태그는 누군가 써 둔 모양만 덮습니다. 아무도 태그를 걸지 않은 새 VPN 장비의 로그인은 태그 기반 검색과 규칙 모두에서 보이지 않습니다.

<strong>[주의]</strong> 분류 기반 검색을 믿기 전에 물어보세요. 이 분류에는 어떤 소스가 들어오나? 예를 들어 Splunk CIM에서는 어떤 소스 타입이 Authentication 데이터 모델을 채우는지 확인할 수 있습니다. VPN이 목록에 없다면 "mike의 로그인 실패 없음"은 "**분류된 소스에서는** mike의 로그인 실패 없음"이라는 뜻입니다.

## 로그 저장 { #storage }

### 같은 종류끼리 { #storage-indexes }

마지막 단계는 이벤트를 다시 찾을 수 있는 곳에 쓰는 일입니다. 아래의 데이터베이스가 무엇이든 대부분의 SIEM은 **비슷한 로그를 함께 저장**합니다. 방화벽 로그 한 곳, Windows 한 곳, 프록시 한 곳, IDS 한 곳. Splunk는 이 장소를 **인덱스(index)**, Elastic은 인덱스나 **데이터 스트림(data stream)**, Sentinel은 <strong>테이블(table)</strong>이라고 부릅니다. 로그 종류 전체에 적용되는 설정 — 파싱, 접근 권한, 보관 기간 — 도 이 단위에 걸리는 경우가 많습니다.

검색하는 사람 입장에서는, 검색에 **저장 구역 이름을 적어야** 한다는 뜻입니다. `index=proxy`, `index=windows`, 특정 Sentinel 테이블, Elastic 데이터 뷰. 빼도 되지만, 그러면 SIEM이 모든 저장 구역을 뒤지므로 느리고 원하지 않은 로그 종류의 잡음까지 따라옵니다. ([형식 페이지](formats-structure.md#not-google)에서 칸 쪽에서 본 것과 같은 생각입니다.)

### 보관 기간: 종류마다 얼마나 두나 { #retention }

저장 공간은 한정돼 있으니 로그 종류마다 <strong>보관 기간(retention)</strong>이 있습니다. 어느 조직은 방화벽 로그를 30일(양은 엄청나고 가치는 중간), DNS와 프록시를 90일, Windows 보안·인증 로그를 1년, 법무·감사 기록을 7년 둘 수 있습니다. 이 숫자는 세 가지 압력에서 나옵니다. **규정 준수**(어떤 규정과 정부 정책은 최소 기간을 정합니다. 예를 들어 미국 연방 기관의 로깅 정책 M-21-31은 많은 로그 종류에 대해 활성 저장 12개월, 그다음 콜드 저장 18개월을 정합니다), **조사에 필요한 기간**, 그리고 **비용**.

<strong>[보충]</strong> 조사에 필요한 기간은 과소평가하기 쉽습니다. 침해는 시작된 지 몇 주, 몇 달 뒤에 발견되는 일이 많습니다. 프록시 로그를 30일 두는데 첫 비커닝이 45일 전이었다면, 이야기의 시작은 사라진 겁니다. 보관 기간을 정할 때는 "디스크가 얼마나 있나?"만이 아니라 "오늘 침해를 발견하면 얼마나 뒤까지 봐야 하나?"를 물어야 합니다.

### Hot, warm, cold, frozen { #tiers }

대부분의 SIEM은 데이터가 나이 들면서 <strong>저장 계층(storage tier)</strong>을 옮겨 다니게 해서, 검색 속도와 비용을 맞바꿉니다.

| 계층 | 흔한 하드웨어 | 검색 속도 | 흔한 나이 |
| --- | --- | --- | --- |
| Hot | 빠른 SSD, 지금 쓰는 중 | 가장 빠름 | 몇 시간~며칠 |
| Warm | SSD나 빠른 디스크, 읽기 전용 | 빠름 | 며칠~몇 주 |
| Cold | 더 싼 디스크나 오브젝트 스토리지 | 느림 | 몇 주~몇 달 |
| Frozen / archive | 오브젝트 스토리지, 테이프, 오프라인 | 느리거나, 되살리기 전엔 검색 불가 | 몇 달~몇 년 |
| 삭제 | — | 없음 | 보관 기간이 끝난 뒤 |

제품마다 이름이 다릅니다. Splunk는 데이터를 "버킷(bucket)" 단위로 hot → warm → cold → frozen으로 옮기는데, 보관 위치를 따로 설정하지 않으면 frozen은 **기본적으로 삭제**라는 뜻입니다(보관된 버킷은 다시 검색하려면 "thaw", 즉 녹여야 합니다). Elastic의 인덱스 수명 주기 관리(ILM)는 인덱스를 hot → warm → cold → frozen → delete로 옮기고, frozen 데이터는 오브젝트 스토리지의 스냅숏에서 검색합니다. 클라우드 SIEM은 분석 계층에 더해, 보관 기간이 길고 검색이 느리고 기능이 제한된 더 싼 레이크·아카이브 계층을 줍니다.

아래는 Splunk 인덱스 정의입니다. SIEM 엔지니어가 관리하는 종류의 파일이니, 읽을 줄만 알면 됩니다.

```
[proxy]
homePath   = $SPLUNK_DB/proxy/db
coldPath   = $SPLUNK_DB/proxy/colddb
thawedPath = $SPLUNK_DB/proxy/thaweddb
frozenTimePeriodInSecs = 7776000
maxTotalDataSizeMB = 500000
coldToFrozenDir = /archive/splunk/proxy
```

- `[proxy]` — 인덱스 이름. `index=proxy`가 가리키는 게 이것입니다.
- `homePath` — hot과 warm 데이터가 사는 곳(보통 빠른 디스크).
- `coldPath` — cold 데이터가 사는 곳(흔히 느리고 큰 디스크).
- `thawedPath` — 누군가 보관 데이터를 되살리면 다시 올려 두는 곳.
- `frozenTimePeriodInSecs = 7776000` — 7,776,000초보다 오래된 데이터는 인덱스를 떠납니다. 7,776,000 ÷ 하루 86,400초 = **90일**.
- `maxTotalDataSizeMB = 500000` — 인덱스가 약 500 GB를 넘을 수 없습니다. 넘으면 90일이 안 됐어도 **가장 오래된** 데이터가 일찍 frozen 됩니다.
- `coldToFrozenDir` — frozen 데이터를 지우는 대신 이 보관 디렉터리로 복사합니다. 이 줄이 없으면 frozen은 삭제입니다.

<strong>[주의]</strong> 사람들이 잊는 건 크기 제한입니다. 시끄러운 한 주 — 스캔하는 웜, 설정이 잘못된 애플리케이션, 또는 일부러 로그를 쏟아붓는 공격자 — 가 인덱스를 크기 상한 너머로 밀어서, 시간 기준 정책이 지켜 주기로 한 데이터를 조용히 밀어낼 수 있습니다. "90일 보관합니다"는 크기 상한이 가장 바쁜 90일을 담을 만큼 클 때만 참입니다.

### 로그 수명 주기 { #life-cycle }

로그에는 자연스러운 수명 주기가 있고, 저장 계층은 거기에 맞춰 만들어집니다.

1. **기록됨** — 이벤트가 만들어지고 수집됩니다.
2. **새것** — 신선한 데이터. 매일 경보, 분류(트리아지), 헌팅, 사고 대응에 쓰입니다. hot 저장소에 있습니다.
3. **나이 듦** — 며칠~몇 달. 점점 덜 검색됩니다. warm, 그다음 cold로 옮겨 갑니다.
4. **오래됨** — 규정 준수나 오래 끄는 조사가 아니면 거의 필요 없습니다. 보관되고, 오프라인일 수도 있습니다.
5. **삭제** — 보관 기간이 끝났습니다.

실무에서 이게 뜻하는 것:

- 지난 하루, 지난 한 주 검색은 빠릅니다. 몇 달 전까지 가는 검색은 느리거나, 시간 초과가 나거나, 검색이 덮지 않는 계층의 데이터를 건너뛸 수 있습니다.
- 보관된 데이터는 검색 전에 **되살려야**(rehydrate, thaw, 다시 적재) 하는 경우가 많습니다. 몇 시간이 걸리기도 하고 다른 팀에 요청서를 내야 하기도 합니다. 사고에서 오래된 데이터가 필요하겠다 싶으면 일찍 요청하세요.
- hot/warm 기간보다 오래된 시기에 "결과 없음"은 "일어나지 않음"이 아니라 "검색 안 됨"일 수 있습니다. SIEM이 실제로 덮은 시간 범위를 확인하세요.

예를 들어 봅시다. 오늘(11월 20일), 어느 업체의 소프트웨어 업데이트가 8월 2일부터 트로이 목마가 심어져 있었다는 걸 알게 됐습니다. 위 정책이라면 8월 프록시 로그는 frozen 상태입니다. 보관 디렉터리가 있으면 되살릴 수 있고, 없으면 이미 없습니다. 1년 보관하는 Windows 보안 로그는 cold에서 느리게나마 검색됩니다. 30일 보관하는 EDR 기록은 시작 부분을 하나도 덮지 못합니다. "8월이 필요하다"는 이 한 문장 때문에, 사고 전에 이 숫자들을 알아 둬야 합니다.

## SIEM 엔지니어에게 물어볼 질문 { #questions }

이 설정을 여러분이 고르지는 않을 수 있지만, 그 결과는 여러분이 떠안습니다. 에이전트가 애초에 모으지 않아서 없는 로그는, 일어나지 않은 공격과 똑같아 보입니다. 이 질문들의 답을 받아서 팀 위키에 적어 두세요.

**데이터 수집**

- 어느 시스템에서 모으나? 모든 서버와 워크스테이션인가, 일부인가? 어느 클라우드 서비스인가?
- 시스템 종류마다 어느 채널·파일을 모으나(Security만인가, Sysmon, PowerShell, Defender, 작업 스케줄러도인가)?
- 어떤 필터를 어디에 걸었고, 그 설정은 어디에 보관하나?

**데이터 사용**

- 우리 SIEM은 어떤 공통 정보 모델을 쓰고, 그 칸 목록은 어디 있나?
- 각 분류·데이터 모델(Authentication, Network Traffic, Endpoint)에는 어떤 소스가 들어오나?
- 빠른 검색을 위해 어떤 칸이 인덱싱되나(제품에 따라 다름)? 어떤 보강이 있고, 받을 때인가 검색할 때인가?

**데이터 저장**

- 로그 종류마다 보관 기간은 얼마이고, 그걸 줄여 버릴 수 있는 크기 상한이 있나?
- hot/warm(빠름)은 얼마 동안이고 cold/archive(느리거나 되살려야 함)는 얼마 동안인가? 되살리기는 어떻게 요청하나?

<strong>[보충]</strong> 이 중 몇 개는 직접 답을 찾을 수 있습니다. Splunk에서 이 검색은 실제로 무엇이 들어오고 있는지 보여 줍니다.

```
| tstats count latest(_time) AS last_seen WHERE index=* BY index sourcetype
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M")
| sort index sourcetype
```

- `| tstats ...` — 이벤트 전체 대신 인덱스의 메타데이터만 읽는 빠른 명령입니다. 결과를 거르는 게 아니라 만들어 내는 명령(generating command)이라서 파이프로 시작해야 합니다.
- `count latest(_time) AS last_seen` — 묶음마다 이벤트 수를 세고, 가장 최근 이벤트 시각을 찾아 `last_seen`이라고 이름 붙입니다.
- `WHERE index=*` — 볼 권한이 있는 모든 인덱스에서(시간 선택기 범위 안에서).
- `BY index sourcetype` — 인덱스와 소스 타입마다 한 줄.
- `eval last_seen=strftime(...)` — `eval`은 칸을 만들거나 바꿉니다. `strftime`은 epoch 숫자를 읽을 수 있는 날짜로 바꿉니다.
- `sort index sourcetype` — 줄을 정렬합니다.

결과:

```
index     sourcetype              count      last_seen
dns       zeek:dns                18233412   2026-11-20 09:41
linux     linux_secure              912337   2026-11-20 09:41
proxy     squid:access            40117200   2026-11-20 09:41
windows   XmlWinEventLog:Security 25441090   2026-11-20 09:40
windows   XmlWinEventLog:Sysmon      1842   2026-11-12 22:05
```

이 점검이 찾으려고 있는 게 바로 마지막 줄입니다. 지난 30일로 돌렸는데 Sysmon만 이벤트가 몇천 개뿐이고 가장 최근 것이 8일 전입니다. 다른 소스는 전부 지금 시각입니다. Sysmon 데이터는 11월 12일에 끊겼고, 그 뒤로 Sysmon 기반 규칙은 전부 눈을 감고 있었던 겁니다. (`tstats`는 시간 범위 안에 데이터가 있는 것만 줄로 돌려주므로, 범위가 시작되기 전에 끊긴 소스는 목록에서 그냥 사라집니다. 소스마다 마지막으로 보인 때가 들어갈 만큼 넉넉한 범위로 돌리세요.)

## 파이프라인 전체를 한눈에 { #summary }

```
Log generated → Collect → Parse → Normalise → Enrich → Index → Store → Search / Alert
```

| 단계 | 알아야 할 것 | 소리 없이 실패하는 방식 |
| --- | --- | --- |
| 수집 | 에이전트인지 아닌지, 어느 호스트, 어느 채널, 어떤 필터 | 호스트나 채널을 안 모음, 필터가 필요한 걸 버림, 에이전트 멈춤 |
| 파싱 | 형식, 파서, 뽑아내는 칸 | 칸을 못 뽑음, 업그레이드 뒤 열이 밀림 |
| 정규화 | 쓰는 모델, 칸 이름, 값 짝짓기, 어느 소스가 매핑됐나 | 새 소스가 매핑 안 됨, 같은 이름 다른 뜻 |
| 보강 | 무엇을, 어디서, 언제(받을 때/검색할 때) 붙이나 | 오래된 표, 그 순간 기준 vs 지금 기준 혼동 |
| 인덱싱 | 어떤 칸이 인덱싱되나, 검색을 어떻게 좁히나 | 인덱싱 안 된 칸 검색이 느리거나 시간 초과 |
| 저장 | 종류별 보관 기간과 계층, 크기 상한, 되살리는 절차 | 데이터가 기간을 넘겨 사라지거나 frozen, 검색이 그 계층을 덮지 않음 |

목표는 SIEM 엔지니어가 되는 게 아닙니다. 쫓고 있는 어떤 로그든 각 단계에서 무슨 일을 겪었는지 말할 수 있는 것입니다. 그래야 로그가 있을 줄 알았던 곳에 없을 때, "아무 일도 없었다"고 결론 내리는 대신 다음에 어디를 볼지 압니다.

## SOC에서 써먹기 { #soc-use }

경보를 분류할 때, 헌팅할 때, 또는 검색 결과가 하나도 없을 때:

1. **원본 vs 덧붙인 것.** 어느 칸이 소스에서 왔고 어느 칸이 보강이나 정규화로 붙었나? 중요할 때는 원본 이벤트를 여세요.
2. **언제 기준의 사실인가.** 보강마다 그 순간 기준인가, 지금 기준인가? IP → 호스트, IP → 사용자는 이벤트 시각의 DHCP와 로그온 이벤트로 확인하세요.
3. **모델.** 정규화된 칸으로 검색하되, 기대고 있는 소스마다 원래 칸 이름도 알아 두세요.
4. **덮는 범위.** 관련 소스가 전부 검색하는 분류나 데이터 모델에 들어오나? 아니라면 빠진 소스는 원본 검색을 따로 하세요.
5. **저장.** 인덱스·테이블 이름을 적으세요. 시간 범위가 검색 가능한 계층 안인지 확인하고, 되살리기는 일찍 요청하세요.
6. **상태.** "결과 없음"을 믿기 전에 소스마다 아직 데이터가 들어오는지(소스별 최신 이벤트 시각) 확인하세요.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    이 페이지의 내용은 전부 그대로입니다. 보강은 여전히 SIEM이 주는 가장 큰 가치 중 하나이고, 받을 때 vs 검색할 때는 여전히 과거 정확성의 핵심 질문이며, 정규화와 분류는 여전히 검색 하나·규칙 하나로 여러 소스를 덮게 해 주는 장치이고, 종류별 보관 기간과 hot/warm/cold 계층은 여전히 SIEM이 비용을 다스리는 방식입니다. SIEM 엔지니어에게 물어볼 질문도 그대로입니다.

!!! info "[변경됨] 바뀐 점"
    - **열린 스키마.** OCSF는 2023년에 1.0이 나왔고 2024년 말 Linux Foundation에 합류했습니다. 계속 1.x 버전을 내고 있고, AWS Security Lake가 기본 형식으로 쓰며 많은 보안 업체가 지원합니다. Elastic은 2023년에 ECS를 OpenTelemetry에 기여했고, 둘은 OpenTelemetry 시맨틱 컨벤션으로 합쳐지는 중입니다. Splunk CIM, Microsoft ASIM, Google UDM은 각 제품의 모델로 남아 있습니다. 일하면서 이 중 적어도 두 개 사이를 번역하게 될 거라고 보세요.
    - **정규화가 파이프라인 앞쪽으로 옮겨 왔습니다.** 보안 데이터 파이프라인 제품(그리고 SIEM 자체의 파이프라인 기능)이 이제 흔히 데이터가 SIEM에 닿기 **전에** 경로를 정하고, 거르고, 보강하고, OCSF나 ECS 같은 스키마로 바꿉니다. 원본 그대로는 싼 저장소로, 줄인 사본은 SIEM으로 보내는 경우가 많습니다. 그래서 "오는 길에 내 로그에 무슨 일이 있었나"라는 질문이 더 중요해졌습니다.
    - **싼 레이크 계층.** 클라우드 SIEM은 이제 비싼 분석 계층에 훨씬 싼 데이터 레이크 계층을 짝지어 줍니다. Microsoft Sentinel 데이터 레이크는 2025년에 정식 출시됐고 긴 보관(최대 12년)을 지원합니다. 다른 업체도 비슷한 레이크, 연합 검색(federated search), 아카이브 계층을 제공합니다. 이 계층의 데이터는 보통 되살리지 않고도 검색되지만, 질의가 느리고 기능이 적고 질의마다 비용이 들기도 하며, 탐지 규칙이 그 위에서 돌지 않을 수도 있습니다.
    - **AI가 돕는 보강과 요약.** 많은 SIEM·SOAR 제품이 이제 AI가 만든 경보 요약과 보강을 붙여 줍니다. 다른 보강과 똑같이 다루세요. 정보가 어디서 왔는지 알고, 행동하기 전에 원본 이벤트와 대조하세요.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **지금의 lookup 표를 과거 기록처럼 쓰지 마세요.** 오늘의 DHCP나 CMDB 표로 지난달 그 IP가 어느 기계였는지 말하면 엉뚱한 호스트, 엉뚱한 사람을 지목할 수 있습니다.
    - **분류 검색이 모든 소스를 덮는다고 가정하지 마세요.** 어떤 소스가 들어오는지 확인하세요. 새 소스와 클라우드 소스가 흔한 구멍입니다.
    - **SIEM 비용을 아끼려고 가치 낮은 데이터를 파이프라인에서 버리지 마세요(어딘가에 보관하지 않는다면).** 레이크나 아카이브 계층으로 보내세요. 버린 건 보강도 검색도 못 합니다.
    - **크기 상한과 frozen 때 무슨 일이 일어나는지(보관인지 삭제인지) 확인하기 전까지는 "90일 보관"을 믿지 마세요.**
    - **실제로 검색할 수 없었던 기간(frozen, 보관됨, 레이크 질의 범위 밖)에 대해 "활동 없음"이라고 보고하지 마세요.** 무엇을 검색했는지 적으세요.

## 확인 문제 { #quiz }

### 문제 1

경보가 11월 3일에 `10.0.10.3`에서 알려진 악성 IP로 간 연결을 보여 줍니다. SIEM의 검색할 때 lookup은 10.0.10.3이 인사팀 직원의 `hr-lt-201`이라고 말합니다. 그 노트북을 격리하라는 요청을 받았습니다. 먼저 무엇을 확인하고, 왜인가요?

??? success "정답과 해설"
    IP → 호스트 짝이 **그 순간 기준**인지 **지금 기준**인지 확인합니다. 검색할 때 lookup은 오늘의 표를 쓰므로, 11월 3일이 아니라 **지금** 10.0.10.3을 가진 기계를 알려 줍니다. DHCP 임대는 매일 바뀌니, 연결을 만든 기계는 완전히 다른 호스트일 수 있습니다.

    11월 3일의 시각이 찍힌 증거로 확인하세요. 연결 시각에 유효했던(그 전에 주어졌고 아직 만료·반납되지 않은) 10.0.10.3의 DHCP 서버 임대 로그, 그리고 가능하면 그 직전 그 기계의 4624 로그온. 파이프라인이 받을 때 호스트 보강을 한다면, 원래 이벤트에 저장된 `host.name`도 좋은 증거입니다. 그다음에 격리하세요. 그렇지 않으면 진짜 감염된 기계는 계속 돌아가는 동안 죄 없는 인사팀 노트북을 격리할 수 있습니다. 보고서에는 그 짝이 어디서 왔는지 적으세요.

### 문제 2

동료가 지난 7일에 대해 `tag=authentication action=failure user=svc_backup`을 돌리고 아무것도 안 나오자 "서비스 계정의 로그인 실패 없음"이라고 썼습니다. 이 계정은 지난달 추가된 새 VPN 장비 로그인과 Linux 서버 SSH 로그인에도 쓰입니다. 결론의 무엇이 틀렸고, 어떻게 확인하나요?

??? success "정답과 해설"
    이 검색은 파서가 인증으로 **분류**하고 `action`과 `user`를 정규화한 소스의 이벤트만 찾습니다. 지난달 추가된 VPN 장비는 Authentication 모델에 아예 매핑되지 않았을 수 있고, 그러면 그 실패는 이 검색에서 보이지 않습니다. Linux sshd 이벤트는 아마 매핑돼 있겠지만, 그 소스용 애드온·파서가 설치돼 있고 `user` 값이 같은 방식으로 정규화돼 있을 때만입니다.

    덮는 범위를 확인하세요. Authentication 데이터 모델(또는 분류)을 채우는 소스 타입 목록을 뽑아 VPN이 있는지 봅니다. VPN 인덱스에서 `svc_backup`과 그 장비의 실패 문구로 원본 검색을 돌리고, sshd 실패(`Failed password for svc_backup` / `Invalid user`)가 분류되는지 확인합니다. 그때까지 맞는 결론은 "**분류된 소스(목록 적기)에서는** 로그인 실패 없음"입니다. 그다음 SIEM 엔지니어에게 VPN 소스 매핑을 요청하세요.

### 문제 3

Splunk 프록시 인덱스가 `frozenTimePeriodInSecs = 7776000`, `maxTotalDataSizeMB = 300000`이고 `coldToFrozenDir`은 없습니다. 평소 양은 하루 2.5 GB입니다. 지난달 설정이 잘못된 애플리케이션 때문에 30일 동안 프록시 양이 세 배가 됐습니다. 실제 보관 기간은 얼마이고, 가장 오래된 데이터는 어떻게 되나요?

??? success "정답과 해설"
    `7776000`초 = 의도한 보관 90일. 평소 양이면 90일은 약 225 GB로 300 GB 상한 아래라서, 평소에는 정말 90일이 있습니다.

    나쁜 한 달 동안은 하루 약 7.5 GB × 30일 = 225 GB. 나머지 60일을 평소 양(150 GB)으로 더하면 90일 창에 약 375 GB가 필요하고, 300 GB 상한을 넘습니다. Splunk는 상한 아래로 맞추려고 **가장 오래된** 버킷부터 frozen 하므로, 대략 가장 오래된 75 GB, 평소 양으로 약 30일 치를 잃습니다. 실제 보관 기간이 약 60일로 줄어듭니다(정확한 숫자는 압축과 버킷 크기에 따라 다름).

    `coldToFrozenDir`이 없으니 frozen은 **삭제**입니다. 녹여 되살릴 보관본이 없습니다. 해결책: 가장 바쁜 90일이 들어가도록 상한을 올리고, 보관 위치를 추가하고, 인덱스가 상한에 가까워지면 경보를 걸고, 시끄러운 소스를 고치거나 거르세요. 그리고 기억하세요. 로그 양을 만들어 낼 수 있는 공격자는 같은 효과로 증거를 밀어낼 수 있습니다.

## 관련 레퍼런스 { #related }

- [로그 수집](collection-methods.md) — 이벤트가 SIEM에 닿는 방법
- [로그 형식과 구조](formats-structure.md) — 파싱, 인덱싱, 검색 좁히기
- [로그온: 4624, 4625, 4648](../important-events/logins.md) — 분류의 바탕이 되는 인증 이벤트
- [도메인 나이와 평판 신호](../dns/domain-signals.md) — 도메인 보강이 기대는 것
- [Splunk 데이터 탐색](../../../blueteam/splunk/data-discovery.md)
- [로그 집계](../../network-forensics/part-2/log-aggregation.md)
