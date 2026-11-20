---
title: "로그 수집 — 로그 파이프라인, 에이전트 vs 에이전트리스, Windows·Linux 수집 방법"
tags:
  - training
  - blue-team
  - logging
  - siem
  - windows
  - linux
---

# 로그 수집 — 로그 파이프라인, 에이전트 vs 에이전트리스, Windows·Linux 수집 방법 { #collection-methods }

!!! abstract "이 페이지에서 다루는 것"
    SIEM을 직접 만들지 않는 분석가도 로그가 SIEM까지 어떻게 들어오는지 알아야 하는 이유, 그리고 모든 로그가 거쳐 가는 단계: 로그 소스 → 수집 → 집계기 → 파싱·보강 → 인덱싱·저장 → 검색·보고·경보. 각 단계가 이벤트에 무엇을 덧붙이고, 바꾸고, 늦추고, 몰래 버릴 수 있는지 봅니다. 이어서 로그가 호스트를 떠나는 두 가지 방식(**에이전트**, 그리고 **에이전트리스** 밀어 보내기·끌어오기), Windows의 구체적 선택지(SIEM 업체 에이전트, Windows 이벤트 전달, 서드파티 에이전트, PowerShell·WMI·RPC로 끌어오기)와 Linux의 선택지(기본 syslog 데몬, 업체·서드파티 에이전트, 스크립트)를 다룹니다. 설정 예시는 모두 한 줄씩 풀어 읽고, 파이프라인 자체가 고장 났거나 누가 건드렸을 때 알려 주는 이벤트와 시간 필드도 함께 봅니다. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. SIEM에서 보는 이벤트는 호스트가 쓴 이벤트 그대로가 **아니다.** 오는 길에 **형식 변환, 필터링, 파싱, 이름 바꾸기, 보강, 지연**을 겪을 수 있다. 어느 부분이 원본이고 어느 부분이 나중에 붙은 건지 아는 게 조사를 정확하게 지켜 준다.
2. 파이프라인의 기능 블록은 어느 제품이든 같다. **로그 소스 → 수집 → 집계기 → 파싱·보강 → 인덱싱·저장 → 검색·보고와 경보.** 제품마다 다른 건 어느 상자가 어떤 일을 맡느냐지, 해야 할 일 자체가 아니다.
3. <strong>집계기(aggregator)</strong>는 엄청난 양을, 여러 형식으로, 여러 장비에서, 빠르게 받아 내려고 존재한다. 그리고 저장 전에 정리·파싱·필터링·표준화를 한다. 크거나 지역이 흩어진 환경은 여러 대를 둔다.
4. **경보는 정해진 주기로 도는 검색일 뿐이다.** 경보는 수집 지연 + 인덱싱 지연 + 검색 주기보다 빠를 수 없다.
5. 로그가 호스트를 떠나는 길은 두 가지다. **에이전트**(늘 떠 있는 전용 프로세스), 또는 **에이전트리스**(누가 접속해서 **끌어오거나**, 예약된 스크립트가 **밀어 보내거나**). 에이전트는 **필터링, 버퍼링, 압축, 암호화**를 해 주기 때문에 보통 더 선호된다.
6. Windows의 선택지는 **SIEM 업체 에이전트**, 기본 내장 **Windows 이벤트 전달(WEF)**, **서드파티 에이전트**, 그리고 PowerShell·WMI·RPC로 끌어오는 **에이전트리스**다. Windows 이벤트는 구조(XML 또는 **JSON**)를 유지해야 한다. syslog 문장으로 바꾸면 구조가 날아간다.
7. WEF는 여러 호스트의 원본 XML 이벤트를 수집 서버의 **Forwarded Events** 채널로 모으고, 거기서 에이전트 **하나**가 SIEM으로 보낸다. 원래 호스트 이름은 이벤트의 `Computer` 칸에 남아 있으니, SIEM이 그 값을 쓰는지 확인해야 한다.
8. Linux에서는 기본 **rsyslog/syslog-ng** 데몬이 보통 에이전트 역할을 한다. 전달은 한 줄로도 되지만, 믿을 만하게 하려면 TCP/TLS, 디스크 큐, 그리고 "이 호스트가 조용해졌다" 경보가 필요하다.

## 분석가가 파이프라인을 알아야 하는 이유 { #why }

많은 조직에서 SIEM은 다른 팀이 만듭니다. 분석가는 검색창을 열고 치기만 하죠. 그러다 어느 날 말이 안 되는 결과가 나옵니다.

- `src_country`라는 칸에 `RU`라고 적혀 있습니다. 그런데 Windows 이벤트에는 그런 칸이 없습니다. 누가 썼고, 어느 IP를 보고 쓴 걸까요?
- "09:14"에 일어난 로그온이 SIEM에는 09:31에 나타났습니다. 공격자가 시간을 조작했을까요, 아니면 파이프라인이 느렸을까요?
- 어제 도메인 컨트롤러에서 4769 이벤트가 하나도 없습니다. 아무도 Kerberos를 안 썼을까요, DC가 기록을 멈췄을까요, 아니면 수집 서버의 필터가 버렸을까요?
- 전달된 이벤트가 전부 `host=WEC01`이라고 나옵니다. 서버 한 대가 정말 회사 전체에 로그온했을까요?

이 질문들의 답은 전부 공격이 아니라 **파이프라인 안**에 있습니다. 택배를 떠올려 보세요. 보내는 사람이 상자를 쌉니다(호스트가 이벤트를 씀). 트럭이 가져갑니다(수집). 물류 허브(집계기)에서 직원이 무게를 달고, 바코드를 붙이고, 가끔은 다시 포장합니다(파싱, 보강, 형식 변환). 그다음 목록이 있는 창고에 들어가고(인덱싱·저장), 직원이 목록을 검색해서 찾거나(검색) "이 사람이 보낸 상자가 오면 전화 줘"라는 규칙이 울립니다(경보). 상자가 늦게, 찌그러져서, 또는 낯선 스티커를 달고 왔다면 어느 단계에서 그랬는지 알아야 합니다. "취급 주의 — 3번 허브 처리"라는 스티커는 보낸 사람이 붙인 게 아니니까요.

기술 이야기로 돌아오면, 분석가는 어떤 칸이든 <strong>"이건 원본에서 온 값"</strong>인지 <strong>"이건 파이프라인이 덧붙인 값"</strong>인지 말할 수 있어야 하고, 어떤 빈칸이든 <strong>"아무 일도 없어서 데이터가 없다"</strong>와 <strong>"파이프라인이 잃어버려서 데이터가 없다"</strong>를 구별할 수 있어야 합니다. 그게 안 되면 잘못된 결론을 내리기 쉽고, 로그를 더 좋게 만들 기회(뽑아낼 수 있는데 안 뽑은 칸, 아무도 수집하지 않는 채널)도 놓치기 쉽습니다.

## 로그 파이프라인, 상자 하나씩 { #pipeline }

```
 Log sources          Collection         Aggregator(s)            Storage / index          Use
+-------------+     +-----------+     +------------------+     +------------------+     +--------------+
| Windows     | --> | agent     | --> | accept at speed  | --> | parse (if not    | --> | search       |
| Linux       |     | WEF       |     | parse / clean    |     |  done yet)       |     | dashboards   |
| firewalls   |     | syslog    |     | enrich / filter  |     | index            |     | reports      |
| cloud APIs  |     | scripts   |     | buffer / route   |     | store (hot/cold) |     | alerts =     |
+-------------+     +-----------+     +------------------+     +------------------+     | scheduled    |
                                                                                        | searches     |
                                                                                        +--------------+
```

- **로그 소스(log source).** 이벤트를 쓰는 모든 것: Windows 이벤트 로그 서비스, syslog 데몬, 애플리케이션, 네트워크 장비, 클라우드 서비스. 이들이 로그를 만드는 방식은 [Windows 로그](../windows-logging/index.md)와 [Linux 로그](../linux-logging/index.md)에서 다뤘습니다.
- **수집(collection).** 누군가는 이벤트를 호스트 밖으로 옮겨야 합니다. 여기가 **이벤트를 바꿀 수 있는**(예: XML을 JSON으로 형식 변환) 또는 **버릴 수 있는**(필터 규칙) 첫 단계입니다. 아래에서 자세히 봅니다.
- **집계기(aggregator).** 받는 쪽 계층입니다. 첫 번째 일은 그냥 **빠르게 받아 내는 것**입니다. 수천 대의 장비에서 초당 수만 건을, 여러 형식(UDP·TCP syslog, 에이전트 전용 프로토콜, HTTP)으로요. 그다음 제품에 따라 **파싱**(문장을 칸으로 쪼개기), **정리**(시각 고치기, 쓰레기 버리기), <strong>보강(enrichment)</strong>(Geo-IP, 자산 담당자, 위협 인텔리전스 태그 붙이기), **필터링**(시끄러운 이벤트 버리기), **라우팅**(보안 이벤트는 SIEM으로, 디버그 로그는 싼 저장소로)을 하고, 더 표준화된 형식으로 내보냅니다. 집계기는 여러 대일 수 있습니다. 양을 감당하려고, 또는 지역·사이트마다 하나씩 두어 느린 회선에 원본 그대로 흘려보내지 않으려고요.
- **인덱싱·저장(indexing/storage).** 무거운 일을 도맡는 곳입니다. 집계기가 파싱·보강을 안 했다면 여기서 합니다. 이벤트를 영구 저장소에 쓰면서 **동시에** 인덱스를 만듭니다. 인덱스는 책 뒤의 찾아보기처럼 값 → 이벤트를 연결해 주는 데이터베이스 같은 구조라서, 90일 치에서 `TargetUserName=svc-backup`을 찾아도 모든 바이트를 훑지 않고 몇 초 만에 결과가 나옵니다.
- **검색·보고·경보.** 분석가는 검색하고, 대시보드와 보고서는 저장된 검색을 차트로 그린 것이며, **경보는 정해진 주기로 돌다가 결과가 나오면 행동(티켓 생성, 알림)을 하는 저장된 검색**입니다. 결국 데이터 검색이라서 보통 저장 계층에서 돕니다.

### 상자마다 이벤트에 할 수 있는 일 { #what-changes }

| 단계 | 덧붙일 수 있는 것 | 바꿀 수 있는 것 | 늦출 수 있는 것 | 버릴 수 있는 것 |
| --- | --- | --- | --- | --- |
| 수집 | 에이전트 정보(이름·버전, 수집 서버 호스트) | 형식(XML → JSON 또는 문장), 설명문 렌더링 | 묶어 보내기, 폴링 주기 | 설정 안 된 채널, 이벤트 ID 필터, 권한 문제 |
| 집계기 | Geo-IP, 자산·담당자, 위협 인텔 태그, 정규화된 필드 이름 | 시각(시간대 보정), 필드 이름, 긴 값 잘라 내기 | 큐, 역압(back-pressure) | 필터, 파싱 실패분을 따로 버리는 곳, UDP 과부하 |
| 인덱싱·저장 | 인덱스 시각, 추출된 필드 | 필드 타입(문자열 vs 숫자) | 인덱싱 밀림 | 라이선스·용량 한도, 보존 기간 만료 |
| 검색·경보 | 계산 필드, 조회(lookup) | — | 주기(예: 15분마다) | 지연보다 짧은 검색 시간 범위 |

### 이벤트마다 시계가 두 개 { #two-clocks }

SIEM의 이벤트에는 보통 시각이 최소 두 개 있습니다. **호스트에서 일어난 시각**과 **SIEM이 받거나 인덱싱한 시각**입니다. Elastic Common Schema(ECS)에서는 `@timestamp`(이벤트 시각), `event.created`(에이전트·파이프라인이 처음 본 시각), `event.ingested`(중앙 저장소에 도착한 시각)이고, Splunk에서는 `_time`과 `_indextime`입니다. 로그온 실패 하나를 따라가 보죠.

```
09:14:02.311  WS-HR-0231 writes 4625 (TimeCreated SystemTime="2026-11-20T09:14:02.311Z")
09:14:05      agent sends a batch (batch interval 3 s)
09:14:06      aggregator AGG01 receives, parses, adds geo and asset owner
09:14:09      indexer writes it            -> event.ingested = 2026-11-20T09:14:09Z
09:20:00      brute-force rule runs (every 5 min, looks back 10 min) -> alert
```

한 줄씩 읽으면: **이벤트 시각**(09:14:02)은 호스트의 `TimeCreated` 칸에서 온 값이고, 타임라인에 넣는 건 이 값입니다. 에이전트의 3초 묶음과 인덱싱 3초 지연은 정상입니다. **경보**가 09:20에 울린 건 규칙이 5분마다 돌기 때문입니다. 놓친 게 아니라 원래 그렇게 설계된 겁니다. 만약 09:14 이벤트의 `event.ingested`가 11:47이라면, 호스트가 꺼져 있었거나 에이전트가 쌓아 두고 있었던 겁니다. "언제 처음 알 수 있었나?"를 따질 때 중요하죠. 그리고 이벤트 시각이 받은 시각보다 **늦다면** 호스트 시계가 틀린 겁니다. 시각을 근거로 결론을 내리기 전에 두 시계의 차이부터 보세요.

<strong>[보충]</strong> 여기서 실무 규칙 두 가지가 나옵니다. 첫째, 예약된 규칙은 **주기 + 평소 지연보다 더 길게** 뒤를 돌아봐야 합니다. 그렇지 않으면 늦게 도착한 이벤트가 두 번의 실행 사이로 빠져서 영영 검사되지 않습니다. 둘째, 주말 내내 망에 없던 노트북은 토요일 이벤트를 월요일에 올립니다. **받은 시각** 기준 검색에는 잡히지만, **이벤트 시각** 기준 "최근 1시간" 검색에는 안 잡힙니다.

## 로그를 엔드포인트 밖으로: 에이전트 vs 에이전트리스 { #agent-vs-agentless }

```
                 +---------------------+
   pushed by --> |                     |
   an agent      |                     |
                 |   Log aggregator    |
   pushed by --> |                     |
   a script      |                     |
                 |                     |
   pulled by <-- |  (logs in remotely) |
   a tool        +---------------------+
```

<strong>에이전트(agent).</strong> 백그라운드에서 늘 돌아가는 별도 프로세스로, 하는 일은 하나입니다. 로그를 믿을 만하게 집어서 네트워크로 보내는 것. 운영체제에 들어 있는 것일 수도, SIEM 업체 것일 수도, 서드파티 것일 수도 있습니다. 보통 에이전트가 선호되는 이유:

- **여러 소스를 한 번에** — 이벤트 채널, 텍스트 파일, 저널 — 한 곳에서 설정합니다.
- 네트워크를 건너기 전에 **내용으로 필터링**합니다.
- **버퍼링**: 집계기가 죽어 있으면 이벤트를 메모리나 디스크에 쌓아 두었다가 나중에 보냅니다. 잃어버리지 않고요.
- 전송 중 **압축과 암호화**.
- **상태 확인**: 대부분 하트비트를 보내서, 에이전트가 조용해지면 알아챌 수 있습니다.

여기서는 로그 전송만 전담하며 늘 떠 있는 프로세스면 OS에 기본으로 들어 있어도 에이전트로 칩니다.

<strong>에이전트리스(agentless).</strong> 에이전트를 깔 수 없거나 깔면 안 될 때 씁니다(어플라이언스, 오래된 시스템, "에이전트 그만" 정책, 다른 팀 소유 시스템). 모양은 두 가지입니다.

- **끌어오기(pull)**: 수집 서버가 정해진 주기로 **원격 접속**해서 로그를 읽습니다(Windows는 PowerShell 원격이나 RPC, Linux는 SSH, 또는 클라우드 서비스의 API).
- **밀어 보내기(push)**: **호스트에 예약된 스크립트**가 새 로그를 읽어 내보냅니다(예: cron 작업이나 예약 작업이 HTTP 주소로 전송).

비유하면, 에이전트는 건물 안에 상주하는 우편 담당 직원입니다. 하루 종일 나갈 우편을 정리하고, 트럭이 늦으면 잠긴 가방에 보관합니다. 에이전트리스 끌어오기는 몇 시간마다 마스터키를 들고 와서 보낼 우편함에 든 걸 집어 가는 택배 기사이고, 밀어 보내기는 사무실 직원이 한 시간마다 직접 우체국에 들고 가는 겁니다. 둘 다 될 수는 있지만, 방문 사이에 우편함이 넘치면 편지는 사라지고, 택배 기사의 마스터키는 훔치기 좋은 물건입니다.

어떤 방식이든 수집은 **로그를 바꾸거나**(형식 변환) **걸러 버릴 수 있는 첫 단계**입니다. 그래서 뭔가 이상해 보이면 "이 소스는 어떻게 수집되지?"가 첫 질문입니다.

## Windows 로그 수집 방법 { #windows }

| 방법 | 예 | 장점 | 약점 |
| --- | --- | --- | --- |
| SIEM 업체 에이전트 | Splunk Universal Forwarder, Elastic Agent / Winlogbeat, QRadar WinCollect, LogRhythm System Monitor, Microsoft Azure Monitor Agent | 자기 SIEM과 바로 맞고, 설치가 빠르고, 중앙 관리, 필드 파싱이 준비돼 있음 | 모든 PC에 에이전트 하나 더, 한 업체에 묶임 |
| 기본 내장: Windows 이벤트 전달(WEF) | Windows에 기본 내장, 수집 역할 = Windows Event Collector(WEC) | 모든 호스트에 이미 있음, 그룹 정책으로 제어, 밀어 보내기·끌어오기, Kerberos 암호화, 압축, 원본 XML | 설정할 부품이 많음(GPO, WinRM, 구독, 권한), 수집 서버에는 결국 에이전트 필요 |
| 서드파티 에이전트 | NXLog, Fluentd/Fluent Bit, Snare | 필터와 출력 형식이 유연, 보낼 곳이 다양 | 관리·보안을 챙길 제품이 하나 더 |
| 에이전트리스 | PowerShell(`Get-WinEvent`), WMI, MSRPC(원격 이벤트 로그) | 바로 시작, 설치할 것 없음 | 규모가 커지면 버거움, 방화벽 열기와 원격 읽기 계정 필요, 끌어오는 사이에 로그가 덮어써지면 유실 |

### 업체 에이전트와 서드파티 에이전트 { #win-agents }

이런 에이전트는 세 가지를 쉽게 해 줍니다. **채널 고르기**(Security, System, Sysmon, PowerShell…), 이벤트 ID나 내용으로 **필터링**, 그리고 **출력 형식**. 예를 들어 Splunk Universal Forwarder는 짧은 텍스트 파일 두 개로 설정합니다. `inputs.conf`는 무엇을 읽을지 정합니다.

```ini
[WinEventLog://Security]
disabled = 0
renderXml = true
blacklist = 5156,5158

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
```

- `[WinEventLog://Security]` — Windows 이벤트 API로 **Security** 채널을 읽는 구역(stanza)입니다.
- `disabled = 0` — 이 입력을 켭니다(`1`이면 끔 — 누가 몰래 수집을 멈추는 손쉬운 방법이기도 합니다).
- `renderXml = true` — 이벤트를 "고전" 여러 줄 문장이 아니라 **원본 XML** 그대로 보냅니다. XML이면 `EventData`의 모든 칸이 이름과 함께 남습니다.
- `blacklist = 5156,5158` — 이 이벤트 ID(Windows Filtering Platform 연결 허용, 바인드)는 보내지 **않습니다.** 양이 엄청나서 빼면 라이선스와 저장 공간이 줄지만, 그 대신 SIEM에 호스트 단위 연결 기록이 없어집니다. 모든 필터는 탐지에 관한 결정입니다. 꼭 기록해 두세요.
- 두 번째 구역은 Sysmon 채널에 같은 일을 합니다.

`outputs.conf`는 어디로 보낼지 정합니다.

```ini
[tcpout]
defaultGroup = soc_indexers

[tcpout:soc_indexers]
server = 198.51.100.21:9997, 198.51.100.22:9997
useACK = true
clientCert = $SPLUNK_HOME\etc\auth\soc\client.pem
sslVerifyServerCert = true
```

- `defaultGroup = soc_indexers` — 전부 아래 이름의 그룹으로 보냅니다.
- `server = …:9997, …:9997` — 받는 서버가 두 대입니다. 포워더가 둘 사이에 **부하를 나누고**, 하나가 죽으면 다른 쪽으로 넘어갑니다. 9997은 관례적인 수신 포트입니다.
- `useACK = true` — <strong>인덱서 확인 응답(acknowledgement)</strong>: 받는 쪽이 "썼다"고 확인해 줄 때까지 포워더가 데이터를 들고 있습니다. 이게 없으면 장애 순간 전송 중이던 데이터가 소리 없이 사라질 수 있습니다.
- `clientCert` / `sslVerifyServerCert = true` — 클라이언트 인증서로 TLS를 쓰고, 받는 쪽 인증서도 검사합니다. 가짜 수신 서버가 로그를 빼 가지 못하게요.

NXLog 같은 서드파티 에이전트는 모양은 달라도 같은 일을 합니다. 아래 설정은 채널 두 개를 읽어 **JSON**으로 바꾼 뒤 TLS로 보냅니다.

```xml
<Extension _json>
    Module  xm_json
</Extension>

<Input eventlog>
    Module  im_msvistalog
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*</Select>
                <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Output siem>
    Module  om_ssl
    Host    agg01.corp.example
    Port    6514
    CAFile  C:\Program Files\nxlog\cert\soc-ca.pem
    Exec    to_json();
</Output>

<Route r1>
    Path    eventlog => siem
</Route>
```

- `<Extension _json>` / `xm_json` — JSON 모듈을 불러옵니다.
- `<Input eventlog>` / `im_msvistalog` — 최신 Windows 이벤트 로그 API(Vista 이후)용 입력 모듈입니다.
- `<QueryXML>` — 이벤트 뷰어 사용자 지정 보기나 WEF 구독과 같은 `QueryList` 문법의 **XPath 쿼리**입니다. `<Select Path="Security">*</Select>`는 "Security 채널의 모든 이벤트"라는 뜻입니다. `*[System[(EventID=4624 or EventID=4625)]]`처럼 좁힐 수도 있습니다.
- `<Output siem>` / `om_ssl` — `agg01.corp.example`의 6514 포트로 TLS 전송하고, SOC의 CA 파일만 믿습니다. (지시어 이름은 NXLog 판과 버전에 따라 조금씩 다릅니다.)
- `Exec to_json();` — 이벤트마다 칸들을 한 줄짜리 JSON 객체로 바꿉니다.
- `<Route r1>` — 입력과 출력을 연결합니다.

### 왜 syslog 문장이 아니라 JSON인가 { #json-not-syslog }

Windows 이벤트는 이미 **구조가 있습니다.** 이름 붙은 칸이 있는 XML이고, 가끔은 중첩된 데이터와 목록도 들어 있습니다. 가장 안전한 변환은 그 구조를 지키는 변환입니다. 같은 4624가 에이전트 설정에 따라 어떻게 달라지는지 비교해 보세요.

**JSON**으로 바꾼 경우(줄임):

```json
{"EventTime":"2026-11-20T09:12:44.517Z","Hostname":"WS-HR-0231.corp.example","Channel":"Security","EventID":4624,"TargetUserName":"j.park","TargetDomainName":"CORP","LogonType":"3","IpAddress":"10.20.30.52","LogonProcessName":"NtLmSsp ","AuthenticationPackageName":"NTLM","WorkstationName":"LT-FIN-0419"}
```

모든 칸이 이름을 그대로 가지고 있습니다. SIEM은 따로 손대지 않고 파싱할 수 있고, `LogonType`, `IpAddress`, `AuthenticationPackageName`을 바로 검색할 수 있습니다.

**syslog 문장**으로 바꾼 경우("메시지" 렌더링, 원래는 긴 한 줄인데 여기서는 줄을 나눔):

```
<13>Nov 20 09:12:44 WS-HR-0231 MSWinEventLog 1 Security 88213 Fri Nov 20 09:12:44 2026 4624
Microsoft-Windows-Security-Auditing N/A N/A Success Audit WS-HR-0231 Logon An account was
successfully logged on. Subject: Security ID: S-1-0-0 Account Name: - Account Domain: - Logon
ID: 0x0 Logon Information: Logon Type: 3 ... New Logon: Security ID: S-1-5-21-...-1107 Account
Name: j.park Account Domain: CORP ... Network Information: Workstation Name: LT-FIN-0419 Source
Network Address: 10.20.30.52 ...
```

- `<13>`은 syslog PRI(facility 1 = user, severity 5 = notice)입니다. [facility와 severity](../linux-logging/syslog.md#facility-severity) 참고. Windows 이벤트에는 별 의미가 없습니다.
- 헤더에 호스트와 시각은 있지만, 헤더 시각에는 **연도도 시간대도 없고**, 밀리초도 사라졌습니다.
- 본문은 **렌더링된 설명문**입니다. 칸 이름과 값이 문장 속에 섞였습니다. 더 나쁜 건 "Account Name:"이 **두 번** 나온다는 점입니다. Subject에 한 번, New Logon에 한 번. 그래서 단순한 `Account Name: (\S+)` 정규식은 `j.park`이 아니라 Subject 쪽의 `-`를 집어 옵니다.
- 설명문은 언어마다 다릅니다. 표시 언어가 다른 호스트는 다른 문장을 만듭니다.

그래서 규칙은 이겁니다. **Windows 이벤트는 XML이나 JSON으로 유지한다.** 자유 문장으로 바꾸면, 이미 갖고 있던 걸 되찾으려고 깨지기 쉬운 정규식을 짜야 합니다.

### Windows 이벤트 전달(WEF) { #wef }

<strong>WEF(Windows Event Forwarding)</strong>는 Windows에 기본으로 들어 있는 로그 전달 기능입니다. 소스 PC들이 **원본 XML** 이벤트를 <strong>Windows Event Collector(WEC)</strong> 역할을 하는 서버로 보냅니다. 수집 서버에서는 받은 이벤트가 전부 **Forwarded Events** 채널(`ForwardedEvents`)에 쌓이고, 그 서버의 에이전트 하나가 SIEM으로 보냅니다.

```
  WS-HR-0231 ─┐
  WS-HR-0232 ─┤  WinRM (HTTP 5985, Kerberos-encrypted)      +--------------------+     +------+
  SRV-APP-07 ─┼──────────────────────────────────────────►  | WEC01              | --> | SIEM |
  DC01       ─┘  events selected by a subscription (XPath)  | "Forwarded Events" |     +------+
                                                            | + one agent        |
                                                            +--------------------+
```

조직들이 WEF를 고르는 이유: **모든 Windows 호스트에 이미 있고**, 설정 전부를 **그룹 정책**으로 할 수 있고, **밀어 보내기**(소스가 시작, 보통 이쪽)와 **끌어오기**(수집 서버가 시작) 둘 다 되며, 트래픽은 **압축되고 암호화**됩니다(도메인에서는 HTTP 5985의 WinRM도 Kerberos로 암호화되고, 도메인 밖 PC에는 HTTPS 5986을 씁니다). 보안팀이 "모든 PC에 에이전트 하나 더"를 허락받지 못할 때의 답이기도 합니다. 에이전트는 수집 서버에만 있으면 되니까요.

소스가 시작하는 방식의 최소 설정입니다.

```
C:\> wecutil qc
```

- 수집 서버 `WEC01`에서: `wecutil qc`("quick config")는 **Windows Event Collector 서비스**(`Wecsvc`)를 자동 시작으로 바꾸고 WinRM을 준비합니다. 확인(`Y`)을 묻고, 끝나면 프롬프트로 돌아옵니다.

그다음 소스 PC용 그룹 정책을 *컴퓨터 구성 → 관리 템플릿 → Windows 구성 요소 → 이벤트 전달 → 대상 구독 관리자 구성(Configure target Subscription Manager)*에 넣습니다.

```
Server=http://WEC01.corp.example:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

- `Server=http://WEC01.corp.example:5985/wsman/SubscriptionManager/WEC` — 수집 서버 구독 관리자의 WinRM 주소입니다. `http`라고 쓰여 있어도 도메인에서는 내용이 Kerberos로 암호화됩니다.
- `Refresh=60` — 소스가 60초마다 수집 서버에 새 구독이나 바뀐 구독이 있는지 물어봅니다.

수집 서버의 <strong>구독(subscription)</strong>(이벤트 뷰어 → 구독에서 만들거나 `wecutil cs subscription.xml`)에는 무엇을 보낼지 정하는 XPath 쿼리가 들어갑니다. 예:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4732)]]</Select>
    <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4104)]]</Select>
  </Query>
</QueryList>
```

`<Select>` 하나가 채널 하나와, 이벤트 `System` 부분([이벤트 구조](../windows-logging/event-structure-channels.md)에서 본 칸들)에 거는 XPath 필터를 고릅니다. 조건에 맞는 이벤트만 소스를 떠납니다. 구독에서는 **전달 방식**도 고릅니다. 대역폭을 아끼려고 묶어서 보내거나, 지연을 줄이려고 30초 안팎으로 보내거나. 이것도 앞에서 본 "두 시계" 차이를 만드는 원인입니다.

소스들이 실제로 보내고 있는지 확인하기:

```
C:\> wecutil gr SOC-Baseline
Subscription: SOC-Baseline
	RunTimeStatus: Active
	LastError: 0
	EventSources:
		WS-HR-0231.corp.example
			RunTimeStatus: Active
			LastError: 0
			LastHeartbeatTime: 2026-11-20T09:15:31.000
		SRV-APP-0007.corp.example
			RunTimeStatus: Inactive
			LastError: 0
			LastHeartbeatTime: 2026-11-17T22:03:10.000
```

- `wecutil gr <이름>` — 구독 `SOC-Baseline`의 "실행 상태 보기(get runtime status)"입니다.
- `WS-HR-0231 … Active`, 하트비트 1분 전 — 정상입니다.
- `SRV-APP-0007 … Inactive`, 마지막 하트비트가 **사흘 전** — 이 서버는 전달을 멈췄습니다. 폐기됐거나, 고장 났거나, 누가 WinRM을 멈추거나 정책을 바꿨을 수 있습니다. 원인이 뭐든 **사흘 동안 이 호스트에서 SIEM에 들어온 게 없다**는 뜻이고, 이 서버에 기대는 조사에서 "활동 없음"은 아무 의미가 없습니다.

<strong>[보충]</strong> 가장 흔한 WEF 실수: 소스 쪽에서 전달은 **Network Service** 계정으로 도는데, 이 계정은 기본적으로 **Security 채널을 읽지 못합니다.** 다른 건 다 오는데 Security만 소리 없이 안 옵니다. 해결은 읽기 권한을 주는 겁니다(예: 그룹 정책으로 Security 채널 접근 목록에 Network Service `S-1-5-20`을 넣거나, *Event Log Readers* 그룹에 넣기). 소스의 4624가 정말 Forwarded Events에 나타나는지 꼭 시험해 보세요.

수집 서버에서 본 전달된 이벤트(System 부분, 줄임):

```xml
<System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
  <EventID>4625</EventID>
  <TimeCreated SystemTime="2026-11-20T09:14:02.3110000Z" />
  <EventRecordID>1932277</EventRecordID>
  <Channel>Security</Channel>
  <Computer>WS-HR-0231.corp.example</Computer>
</System>
```

- `Channel`은 여전히 **Security**입니다. 이벤트가 지금은 수집 서버의 Forwarded Events 로그에 있어도, 원래 채널 이름이 남습니다.
- `Computer`도 여전히 **WS-HR-0231**, 이벤트를 쓴 PC입니다.
- `EventRecordID`는 **소스 PC에서의** 기록 번호라서, 호스트별로 번호가 비면 잃어버리거나 지워진 이벤트를 알아챌 수 있습니다.

<strong>[주의]</strong> 수집 서버의 에이전트는 이 모든 이벤트를 **한 대**의 서버에서 읽습니다. 에이전트와 애드온 설정에 따라 SIEM의 `host` 칸이 `Computer` 대신 **수집 서버 이름**(`WEC01`)으로 채워질 수 있습니다. 그러면 회사의 모든 로그온이 "WEC01에서 일어난 것"처럼 보입니다. 전달된 이벤트의 host를 SIEM이 `Computer`에서 가져오는지 확인하고, 헷갈리면 그 칸으로 직접 검색하세요.

### Windows의 에이전트리스 수집 { #win-agentless }

가장 가벼운 방법은 수집 서버가 기본 원격 기능으로 이벤트를 끌어오는 겁니다. **PowerShell**(`Get-WinEvent -ComputerName`, 또는 PowerShell 원격), **WMI**, 또는 **MSRPC** 위의 원격 이벤트 로그 인터페이스. 깔 게 없으니 시작은 빠릅니다. 예약해서 끌어오는 예:

```powershell
$since = (Get-Date).AddHours(-1)
Get-WinEvent -ComputerName SRV-APP-0007 -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624, 4625, 4672
    StartTime = $since
} | Select-Object TimeCreated, Id, MachineName, @{n='Xml';e={$_.ToXml()}} |
    ConvertTo-Json -Compress | Out-File \\SRV-LOG-01\drop\SRV-APP-0007.json
```

- 1번 줄: `$since` = 1시간 전. 이번 실행이 모을 시간 범위입니다.
- 2번 줄: `Get-WinEvent -ComputerName SRV-APP-0007`은 **원격** PC의 이벤트 로그를 읽습니다(RPC 사용. 대상의 "원격 이벤트 로그 관리" 방화벽 규칙이 허용돼야 하고, 계정은 거기서 *Event Log Readers*이거나 관리자여야 합니다).
- 3~6번 줄: `-FilterHashtable`은 원격 쪽에서 걸러지므로 맞는 이벤트만 네트워크를 건넙니다. Security 채널, ID 4624/4625/4672, `$since` 이후.
- 7번 줄: 시각, ID, 호스트 이름, 그리고 이벤트마다 전체 XML을 남깁니다.
- 8번 줄: 압축된 JSON으로 바꿔 집계기가 가져갈 공유 폴더에 씁니다.

이 방식이 "덜 쓰이고" 조심해서 설계해야 하는 이유:

1. **규모가 커지면 버겁습니다.** 수집 서버 한 대가 5,000대를 매시간 돌면 느리고, 연결 안 되는 PC는 전부 빈칸이 됩니다.
2. **구멍을 뚫어야 합니다.** 수집 서버에서 모든 곳으로 가는 RPC/WinRM 방화벽 규칙, 그리고 **어디서나 로그를 읽을 수 있는 계정**이 필요합니다. 그 계정은 고가치 표적입니다. "그게 편해서" 도메인 관리자로 만들어 두면, 그 비밀번호(흔히 스크립트나 예약 작업 안에 저장)를 훔친 공격자가 도메인 전체를 얻습니다. *Event Log Readers* 권한만 있는 전용 계정을 쓰세요.
3. **끌어오는 사이에 로그가 덮어써지면 유실됩니다.** 이벤트 로그는 크기가 정해진 파일이라 가득 차면 가장 오래된 이벤트를 덮어씁니다. 크기를 확인해 보죠.

```
C:\> wevtutil gl Security
name: Security
enabled: true
type: Admin
owningPublisher:
isolation: Custom
channelAccess: O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\Security.evtx
  retention: false
  autoBackup: false
  maxSize: 20971520
publishing:
  fileMax: 1
```

- `wevtutil gl Security` — Security 채널의 설정 보기("get log")입니다.
- `channelAccess` — 누가 읽을 수 있는지. SDDL로 `SY`(SYSTEM), `BA`(기본 Administrators), `S-1-5-32-573`(*Event Log Readers*)가 적혀 있습니다. 앞에서 본 WEF Network Service 문제를 고칠 때 손대는 목록이 이겁니다.
- `retention: false` — 가득 차면 가장 오래된 이벤트를 **덮어씀**(기본값). `true`면 가득 찼을 때 기록을 멈추는데, 그게 더 나쁩니다.
- `maxSize: 20971520` — **20 MB**. 대충 계산해 보면, 디스크에서 이벤트 하나가 평균 1 KB쯤이니 약 2만 건입니다. 초당 보안 이벤트 100건을 쓰는 바쁜 서버라면 **3~4분**이면 찹니다. 한 시간에 한 번 끌어오면 거의 다 놓칩니다. 로그 크기를 키우는 것도 도움이 되지만, 진짜 해결은 자주 수집하는 것(또는 에이전트)입니다.

4. **옛 도구가 사라집니다.** `wmic` 명령줄 도구에 기대는 스크립트는 최신 Windows 11에서 깨집니다. 제거됐거든요. WMI 자체는 PowerShell CIM cmdlet으로 계속 쓸 수 있습니다. [변경됨](#trends) 참고.

### 파이프라인 자체를 지켜보기 { #tamper }

공격자도 로그가 밖으로 나간다는 걸 압니다. 수집을 방해하는 건 흔한 방어 회피(defence evasion) 단계라서, SOC는 **수집 상태 자체를 탐지 소스로** 다뤄야 합니다.

| 신호 | 의미 | ATT&CK |
| --- | --- | --- |
| Security **1102** "감사 로그가 지워졌습니다" | 누군가(이벤트의 `SubjectUserName`)가 Security 로그를 지움 | T1070.001 Clear Windows Event Logs |
| System **104** "… 로그 파일이 지워졌습니다" | 다른 채널(System, Application 등)이 지워짐 | T1070.001 |
| Security **1100** "이벤트 로깅 서비스가 종료되었습니다" | 이벤트 로그 서비스가 멈춤 — 정상 종료 때문일 수도, 누가 멈췄을 수도 | T1562.002 Disable Windows Event Logging |
| 에이전트 서비스의 System **7036**/**7040**("중지됨", 시작 유형이 사용 안 함으로 바뀜) | 로그 에이전트가 멈췄거나 꺼짐 | T1562.001 Disable or Modify Tools |
| 에이전트 하트비트 없음 / WEF 소스 `Inactive` / N분 동안 호스트에서 이벤트 없음 | 호스트 꺼짐, 네트워크 고장, 에이전트 강제 종료, 전달 규칙 삭제 | T1562.006 Indicator Blocking |
| 감사 정책 변경(Security **4719** "시스템 감사 정책이 변경되었습니다") | 소스에서 감사 범주가 꺼짐 | T1562.002 |

1102는 한 줄 더 볼 가치가 있습니다. 이 이벤트는 로그를 지운 **다음에**, 막 비워진 로그에 쓰입니다. 그래서 로컬 로그에는 1102 말고는 거의 아무것도 없습니다. 파이프라인이 제대로 돌았다면 SIEM에는 지우기 직전까지가 다 남아 있습니다. 빠르게, 중앙으로 수집해야 하는 가장 강력한 이유입니다.

## Linux 로그 수집 방법 { #linux }

선택지는 Windows와 비슷하지만 큰 차이가 하나 있습니다. Linux에서는 **기본 syslog 데몬이 압도적으로 흔한 에이전트**입니다.

1. **기본 syslog 데몬을 에이전트로** — **rsyslog**, **syslog-ng**(또는 옛 **syslogd**). 대부분 배포판에 이미 깔려 있고, 필터와 출력 형식이 유연합니다.
2. **SIEM 업체나 서드파티 에이전트** — Elastic Agent/Filebeat, Splunk Universal Forwarder, NXLog, Fluentd/Fluent Bit, Apache NiFi 등. 애플리케이션 파일, 저널의 구조화된 칸, 또는 모든 곳에 같은 에이전트를 쓰고 싶을 때 유용합니다.
3. **에이전트리스** — 밀어 보내는 스크립트, 또는 수집 서버가 SSH로 접속해 끌어오기.

Linux에서 syslog 데몬이 이기는 이유: 전달이 설정 파일 **한 줄**이면 되기 때문입니다. WEF는 수집 서버, 구독, WinRM, 그룹 정책이 다 필요하죠. 가장 단순한 전달 규칙([syslog 페이지](../linux-logging/syslog.md#rsyslog-config)에서 다룸)은 이렇습니다.

```
*.*  @@192.0.2.10:514
```

- `*.*` — 모든 facility, 모든 severity.
- `@@` — **TCP**로(`@` 하나면 UDP).
- `192.0.2.10:514` — 집계기와 포트.

이걸로 로그가 흐르기 시작합니다. 하지만 최종 설정으로는 **부족합니다.** 암호화가 없고, 집계기가 죽어 있으면 데몬의 메모리 버퍼가 결국 차서 메시지를 잃습니다. rsyslog와 syslog-ng는 필터, 형식 변환, 다른 인스턴스와 이어 붙이기, 디스크 큐까지 되는 유능한 에이전트이니, 배포판 기본 설정이 어떻게 돼 있는지 확인해 볼 가치가 있습니다. 더 믿을 만한 rsyslog 전달 설정을 `/etc/rsyslog.d/60-siem.conf` 같은 파일에 넣으면:

```
global(DefaultNetstreamDriverCAFile="/etc/ssl/soc/soc-ca.pem")

module(load="imjournal" StateFile="imjournal.state")

action(type="omfwd" target="agg01.corp.example" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1"
       StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="agg01.corp.example"
       queue.type="LinkedList" queue.filename="fwd_agg01"
       queue.maxDiskSpace="1g" queue.saveOnShutdown="on"
       action.resumeRetryCount="-1")
```

- `global(DefaultNetstreamDriverCAFile=…)` — 집계기의 TLS 인증서를 검사할 CA 인증서입니다.
- `module(load="imjournal" …)` — **systemd 저널**에서 메시지를 읽습니다(rsyslog가 `/dev/log` 소켓이 아니라 저널에서 받는 시스템의 경우). `StateFile`이 읽은 위치를 기억해서, 재시작해도 다시 보내거나 건너뛰지 않고 이어서 읽습니다. [systemd 저널](../linux-logging/log-files-journal.md#journal) 참고.
- `action(type="omfwd" …)` — 전달 출력입니다. `agg01.corp.example`의 **6514**(TLS syslog) 포트로, TCP로.
- `StreamDriver="gtls" StreamDriverMode="1"` — GnuTLS 드라이버를 쓰고 TLS를 필수로 합니다.
- `StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers=…` — 인증서 이름이 `agg01.corp.example`인 서버만 받아들입니다. 이게 없으면 TLS가 암호화는 해도 상대가 누군지는 증명하지 못합니다.
- `queue.type="LinkedList" queue.filename="fwd_agg01"` — 이 전달 작업에 전용 큐를 줍니다. 파일 이름을 줬기 때문에 **디스크 보조** 큐가 됩니다. 메모리가 차면 디스크로 넘칩니다.
- `queue.maxDiskSpace="1g"` — 집계기에 닿지 못하는 동안 디스크에 최대 1 GB까지.
- `queue.saveOnShutdown="on"` — 재시작해도 큐에 있던 메시지를 지킵니다.
- `action.resumeRetryCount="-1"` — 포기하고 버리지 않고 계속 재시도합니다.

처음부터 끝까지 시험해 보기:

```
$ logger -p auth.notice -t soc-test "pipeline test 4c1e"
$ ss -tnp | grep 6514
ESTAB 0 0 10.20.40.15:48212 198.51.100.30:6514 users:(("rsyslogd",pid=812,fd=11))
```

- `logger -p auth.notice -t soc-test "…"` — facility `auth`, severity `notice`, 태그 `soc-test`, 그리고 SIEM에서 찾을 고유 문자열로 시험 메시지를 씁니다.
- `ss -tnp | grep 6514` — TCP 소켓을 프로세스와 함께 보여 줍니다. 출력은 이 호스트(`10.20.40.15`)에서 집계기 6514로 가는 **연결 수립(ESTAB)** 상태이고, 주인은 `rsyslogd`입니다. 몇 초 안에 SIEM에 `pipeline test 4c1e`가 보이면 `auth` 메시지 수집이 되는 겁니다.

<strong>[주의]</strong> 배포판마다 다릅니다. 요즘 일부 배포판(예: Debian 12 이후)은 rsyslog를 기본으로 깔지 않아서, syslog 데몬이나 저널을 읽는 에이전트를 추가하기 전까지는 저널만 있습니다. "모든 Linux 서버에서 syslog를 전달한다"는 말이 새로 만든 서버 전부를 조용히 빼먹고 있을 수 있습니다.

### Linux의 에이전트리스, 그리고 스크립트가 어긋나는 이유 { #linux-agentless }

cron으로 예약한 밀어 보내기 스크립트가 대표적인 에이전트리스 설정입니다.

```
*/5 * * * * root journalctl -u ssh -u sshd --cursor-file=/var/lib/soc/ssh.cursor -o json | curl -sS --cacert /etc/ssl/soc/soc-ca.pem -H @/etc/soc/ingest-header --data-binary @- https://agg01.corp.example:8443/ingest
```

- `*/5 * * * * root` — cron: 5분마다, root로.
- `journalctl -u ssh -u sshd` — SSH 서비스의 저널 항목(배포판에 따라 유닛 이름이 `ssh`이기도 `sshd`이기도 해서 둘 다 적음).
- `--cursor-file=/var/lib/soc/ssh.cursor` — 지난번에 저장한 위치 다음부터 읽고, 새 위치를 저장합니다. 스크립트의 고전적인 버그를 피하려는 겁니다. "최근 5분"(`--since "5 min ago"`)으로 하면 cron이 늦게 돌 때 **빈틈**이 생기고, 일찍 돌 때 **중복**이 생깁니다.
- `-o json` — 항목마다 JSON 객체 하나, 저널의 칸들이 그대로 남습니다.
- `curl … --data-binary @-` — 출력(표준 입력으로 받음)을 HTTPS로 수집 주소에 보내고, SOC CA로 서버 인증서를 검사합니다. 인증 헤더는 crontab에 직접 쓰지 않고 root만 읽는 파일에서 가져옵니다.

수집 서버가 SSH로 접속해 끌어오는 방식도 Windows와 같은 약점이 있습니다. 모든 호스트에 접근하는 수집 계정(키를 지켜야 함), 방화벽 열기, 그리고 끌어오는 사이에 파일이 순환되면 생기는 빈틈([로그 순환](../linux-logging/log-files-journal.md#rotation) 참고).

## SOC에서 쓰는 법 { #soc-use }

어떤 소스가 이상하거나 비어 있으면 파이프라인을 처음부터 따라가세요.

1. **소스:** 이벤트가 애초에 만들어지나(감사 정책, 채널 켜짐, 데몬 설치)?
2. **수집:** 이 호스트는 어떤 방식으로 수집되나 — 업체 에이전트, WEF, syslog 데몬, 스크립트? 그 채널이나 파일이 설정에 들어 있나? 이벤트 ID나 내용 필터가 있나? 권한(Network Service와 Security)은?
3. **전송:** 에이전트가 연결돼 있나(하트비트, `wecutil gr`, `ss`)? UDP인가 TCP/TLS인가? 쌓여 있는 큐가 있나?
4. **집계기·파싱:** 이벤트는 왔는데 파싱에 실패했나("unparsed"나 기본 소스 타입을 찾아보기)? 여기서 **덧붙은** 칸은 어떤 것인가?
5. **저장·검색:** 이벤트 시각과 받은 시각의 차이가 평소 수준인가? 검색 시간 범위가 충분히 넓은가? 보존 기간을 넘었나?
6. **조작:** 1102/104/1100/4719, 에이전트 서비스 중지, 또는 수상한 이벤트 직후 조용해진 호스트가 있나?

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    파이프라인 블록(수집, 집계, 파싱·보강, 인덱싱·저장, 검색·경보), 에이전트 vs 에이전트리스 선택과 그 장단점, Forwarded Events 채널을 쓰는 Windows 이벤트 전달, Linux의 보통 에이전트인 rsyslog/syslog-ng, "Windows 이벤트는 syslog 문장이 아니라 XML이나 JSON으로"는 모두 그대로입니다. 경보는 여전히 예약 검색이나 스트리밍 검색이라 지연이 여전히 중요하고, 수집 방해(로그 지우기, 에이전트 멈추기)도 여전히 공격자의 표준 단계입니다.

!!! info "[변경됨] 바뀐 점"
    - **에이전트 판도가 바뀌었습니다.** Elastic은 이제 Beats를 따로 쓰기보다 Fleet으로 관리하는 **Elastic Agent**와 통합(integration)을 쓰도록 이끌고 있습니다(Winlogbeat는 아직 있음). Microsoft는 옛 Log Analytics 에이전트(MMA)를 2024년 8월에 은퇴시켰고, Microsoft Sentinel로 들어가는 길은 데이터 수집 규칙(XPath 필터 사용)을 쓰는 **Azure Monitor Agent**입니다. 업체 주인도 바뀌었습니다. Splunk는 Cisco 소속이 됐고, IBM은 QRadar SaaS 사업을 Palo Alto Networks에 팔았으며(고객에게 Cortex XSIAM 이전이 제안되고, QRadar 소프트웨어와 WinCollect는 IBM에서 계속), LogRhythm은 Exabeam과 합쳤고, McAfee의 SIEM 제품군은 Trellix로 넘어갔습니다. 옛 그림 속 업체 이름은 낡았을 수 있다고 생각하세요.
    - **"파이프라인 계층"이 흔해졌습니다.** 소스와 SIEM 사이에 텔레메트리 파이프라인(Cribl, OpenTelemetry Collector, Fluent Bit, 업체 파이프라인 제품)을 두고 데이터를 거르고, 모양을 바꾸고, 갈 곳을 나누는 SOC가 많습니다. 흔히 전체 데이터는 싼 저장소나 데이터 레이크로, 골라낸 데이터만 비싼 SIEM으로 보냅니다. 이벤트를 바꾸거나 버릴 수 있는 상자가 하나 더 생긴 셈입니다.
    - **에이전트리스는 이제 "덜 쓰이는" 방식이 아닙니다.** 클라우드·SaaS 로그(ID 공급자 로그인, Microsoft 365 감사, AWS CloudTrail, Google Workspace)는 거의 전부 **API로 끌어오거나 클라우드 자체 스트리밍**으로 모으고, 지연과 보존 한도도 서비스마다 다릅니다. EDR 제품도 텔레메트리를 업체 클라우드로 보내고, SIEM은 API나 커넥터로 받습니다.
    - **Sysmon이 Windows의 일부가 되어 가고 있습니다.** Microsoft는 Sysmon을 Windows의 기본 내장 선택 기능으로 내놓고 있습니다(Microsoft Learn에 문서화). 그래도 따로 켜고, 설정 파일을 주고, 다른 채널처럼 수집해야 합니다. 쓸 수 있는지는 Windows 빌드에 따라 다르니 직접 확인하세요.
    - **`wmic`가 사라졌습니다.** 최신 Windows 11(25H2부터)에서 제거됐습니다. WMI 자체는 남아 있으니 에이전트리스 스크립트는 PowerShell CIM cmdlet을 써야 합니다.
    - **스키마와 형식.** HTTPS 위의 JSON(업체 HTTP 수집기, OpenTelemetry)이 syslog와 나란히 평범한 전송 방식이 됐고, ECS와 OCSF 같은 공통 스키마를 파이프라인에서 적용하는 경우가 늘고 있습니다. 다음 페이지들에서 다룹니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **"표준화"한다고 Windows 이벤트를 syslog 문장으로 바꾸지 마세요.** XML이나 JSON으로 보내세요.
    - **라이선스 비용 아끼자고 되찾을 수 없는 걸 버리지 마세요.** 가치 낮은 이벤트는 버리지 말고 싼 저장소로 보내고, 모든 필터를 탐지에 관한 결정으로 기록해 두세요.
    - **에이전트리스 수집을 도메인 관리자 계정으로 돌리거나** 비밀번호를 스크립트에 넣어 두지 마세요. 최소 권한 읽기 전용 계정을 쓰고, Tier 0급 비밀처럼 지키세요.
    - **보안 로그를 UDP나 확인 응답 없는 전송에 맡기지 마세요.** 확인 응답과 디스크 버퍼가 있는 TCP/TLS(또는 에이전트의 암호화 프로토콜)를 쓰세요.
    - **4624가 실제로 도착하는 걸 보기 전에는 WEF가 Security 로그를 보낸다고 가정하지 마세요.** Network Service에 읽기 권한이 필요합니다.
    - **조용한 호스트가 깨끗한 호스트라고 가정하지 마세요.** 하트비트 끊김, 1102/104/1100/4719, 에이전트 서비스 변경에 경보를 거세요.

## 확인 문제 { #quiz }

### 문제 1

새 Windows Event Collector를 배포한 뒤, 동료가 SIEM에서 어제의 4625 실패를 검색하고 이렇게 말합니다. "로그온 실패 3,400건이 전부 `WEC01`에서 일어났어요. 그 서버가 공격받고 있어요!" 더 그럴듯한 설명은 무엇이고, 어떻게 확인하나요? 그리고 어떤 소스에서는 4625가 오는데 다른 소스에서는 **Security 이벤트가 아예 안 오는** 이유는 무엇일 수 있나요?

??? success "정답과 해설"
    **더 그럴듯한 설명:** `WEC01`은 **수집 서버**입니다. 여러 PC의 이벤트가 그 서버의 Forwarded Events 채널로 모이고 에이전트 하나가 보내기 때문에, SIEM의 `host` 칸이 원래 PC가 아니라 **수집 서버 이름**으로 채워진 겁니다. 이벤트는 WEC01에서 쓰인 게 아닙니다.

    **확인 방법:** 원본 이벤트를 보세요. XML의 `System` 부분에서 `<Computer>`에는 진짜 소스(예: `WS-HR-0231.corp.example`)가 있고, `<Channel>`은 여전히 `Security`입니다. 3,400건을 `Computer` 칸으로 묶어 보면 여러 호스트에 흩어져 있을 겁니다. 그다음 전달된 이벤트의 `host`를 `Computer`에서 가져오도록 SIEM/에이전트 설정을 고칩니다.

    **어떤 소스는 Security 이벤트를 안 보내는 이유:** 소스 쪽 WEF는 **Network Service**로 도는데, 이 계정은 기본적으로 Security 채널을 못 읽습니다. 다른 채널(System, PowerShell)은 계속 오니까 WEF가 잘 되는 것처럼 보이죠. 해결은 그룹 정책으로 Security 채널에 Network Service(`S-1-5-20`) 읽기 권한을 주거나 *Event Log Readers*에 넣고, `wecutil gr`과 시험 로그온으로 확인하는 겁니다. 구독의 XPath가 그 ID들을 실제로 고르고 있는지도 확인하세요.

### 문제 2

서버 팀이 에이전트를 거부합니다. 대신 Domain Admins 소속 서비스 계정으로 서버 40대의 Security 로그를 **6시간마다** 끌어오는 에이전트리스 스크립트를 제안합니다. 바쁜 서버에서 `wevtutil gl Security`는 `maxSize: 20971520`, `retention: false`를 보여 줍니다. 문제점을 나열하고, 대신 무엇을 제안할지 말해 보세요.

??? success "정답과 해설"
    **문제점:**

    1. **덮어쓰기로 생기는 빈틈.** `maxSize: 20971520`은 20 MB이고 `retention: false`는 오래된 이벤트를 덮어쓴다는 뜻입니다. 이벤트 하나에 1 KB쯤이면 약 2만 건입니다. 바쁜 서버는 그걸 몇 분이면 채우니, 6시간마다 끌어오면 마지막 몇 분만 모이고 **나머지는 잃습니다.** 조사에 꼭 필요한 바로 그 구간에 구멍이 납니다.
    2. **탐지 지연.** 잃지 않더라도 이벤트가 최대 6시간 늦게 SIEM에 도착하고, 그에 걸린 경보도 그만큼 늦습니다.
    3. **위험한 계정.** 스크립트에서 쓰는(그리고 아마 스크립트나 예약 작업에 저장된) Domain Admin 자격 증명은 공격자에게 선물입니다. 훔치면 도메인을 가집니다. 로그를 읽는 데는 *Event Log Readers*면 충분합니다.
    4. **구멍과 규모.** 수집 서버에서 모든 서버로 원격 RPC/WinRM을 열어야 하고, 끌어오는 순간 연결 안 되는 서버는 빈칸이 됩니다.

    **제안:** **Windows 이벤트 전달**을 쓰세요. Windows에 내장돼 있으니 "에이전트 하나 더"가 아닙니다. 필요한 이벤트를 고르는 구독과 지연 최소화 전달을 쓰고, 에이전트는 수집 서버에만 둡니다. Security 로그 크기도 어쨌든 키웁니다. 꼭 에이전트리스를 유지해야 한다면: 몇 분마다 끌어오기, 최소 권한 읽기 계정, 더 큰 로그, 그리고 호스트별 `EventRecordID` 빈틈 감시.

### 문제 3

02:10에 SIEM이 평소와 다른 출발지에서 `SRV-APP-0007`로 들어온 4624 유형 10(RDP) 로그온을 받습니다. 02:12 이후로는 그 서버에서 아무것도 오지 않습니다. 다음 날 아침 동료가 말합니다. "02:12 이후 이벤트가 없으니 공격자는 로그오프한 거예요." 무엇을 확인하겠습니까? 서버나 파이프라인에서 어떤 이벤트나 신호가 보이면 이 결론이 뒤집힐까요?

??? success "정답과 해설"
    "이벤트 없음"은 "활동 없음"의 증거가 아닙니다. 수상한 로그온 직후의 침묵은 그 자체로 수상합니다. 확인할 것:

    - **파이프라인 상태부터:** 에이전트 하트비트, 또는 그 소스의 `wecutil gr`(02:12부터 `Inactive`인가?), 에이전트 서비스 상태, 그리고 같은 수집 서버의 다른 호스트들은 계속 들어왔는지(수집 서버 장애가 아닌지 가리려고).
    - **조작 이벤트** — 서버 로컬에서, 그리고 침묵 직전 순간을 SIEM에서: **1102**(Security 로그 삭제, 누가 했는지 포함), **104**(다른 채널 삭제), **1100**(이벤트 로그 서비스 종료), **4719**(감사 정책 변경), 에이전트 서비스가 멈추거나 꺼졌다는 **7036/7040**. 각각 T1070.001, T1562.002, T1562.001에 해당합니다.
    - **호스트 위의 공격자가 입막음할 수 없는 다른 소스:** 02:12 이후 그 서버에서 나간 트래픽을 보여 주는 방화벽·네트워크 로그(Zeek `conn.log`), 별도 통로로 가는 EDR 텔레메트리, 그 서버가 요청한 4769 서비스 티켓 같은 도메인 컨트롤러 이벤트.

    02:12에 에이전트가 멈췄거나 로그가 지워졌다면 올바른 결론은 정반대입니다. 공격자가 **수집의 눈을 가리고** 계속 작업했을 가능성이 큽니다. 서버를 격리하고 02:12 이후는 "알 수 없음"으로 다루세요.

## 관련 레퍼런스 { #related }

- [Windows 로그](../windows-logging/index.md) — 이벤트가 만들어지는 방식, 채널, 파이프라인이 실어 나르는 XML 구조
- [Syslog](../linux-logging/syslog.md) · [Linux 로그 파일과 저널](../linux-logging/log-files-journal.md)
- [꼭 알아야 할 이벤트](../important-events/index.md) — 가장 수집할 가치가 있는 이벤트
- [Windows 이벤트 로그(EVTX)](../../../windows/event-logs.md)
- [로그 집계](../../network-forensics/part-2/log-aggregation.md)
- [Splunk 데이터 탐색](../../../blueteam/splunk/data-discovery.md)
