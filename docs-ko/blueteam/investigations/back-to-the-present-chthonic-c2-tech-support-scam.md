---
title: Back to the Present — 네트워크 베이스라이닝부터 .bit C2, 기술지원 사기 팝업, Snort 룰까지 (Arkime + Splunk + Snort)
tags:
  - blue-team
  - pcap
  - baselining
  - arkime
  - splunk
  - zeek
  - snort
  - c2
  - dns
  - tech-support-scam
---

# Back to the Present — 네트워크 베이스라이닝부터 .bit C2, 기술지원 사기 팝업, Snort 룰까지 { #back-to-the-present }

!!! abstract "사례 요약"
    Marty와 Doc의 "스테인리스 타임머신" 안에 있는 **Windows 10 PC 한 대(DELOREAN-PC)**의 12분짜리 캡처입니다. 먼저 **네트워크 베이스라이닝**을 처음부터 합니다. 내부 IP와 대역, 라우터, DNS·DHCP 서버, DC·파일 서버·웹/메일 서버가 있는지, 장치 수, 프로토콜, OS, 외부 통신을 하나씩 찾아요. 그다음 이상한 점을 따라갑니다. Office 활동 직후 PC가 **User-Agent 없이 `.exe`를 내려받았고**, 1분 뒤부터 **회사 DNS를 거치지 않고 외부 DNS 서버들에 TCP로** `.bit` 도메인(`amellet.bit`)을 물었습니다. 그 주소로 **HTTP/1.0 암호화 POST를 39번** 보내 약 **2.3MB**를 받았어요(**Chthonic 유형 C2**와 같은 모양). 마지막에 사용자가 연 웹사이트에 숨어 있던 **팝언더 스크립트**가 **가짜 Windows Defender 경고(기술지원 사기)** 페이지를 띄웠습니다. **Snort 룰 14개를 만들어 PCAP으로 테스트**하고, MC나 다른 헌트 팀에 넘길 **보고서**과 **호스트 오퍼레이터용 단서**를 완성합니다.

| | |
|---|---|
| **증거** | PCAP 1개 `2017-10-21-traffic-analysis-exercise.pcap` — 2017-10-21 04:51:53 – 05:03:52 UTC (11분 59초), 패킷 9,931개, Arkime 세션 505개, Zeek 연결 510개 |
| **출처** | malware-traffic-analysis.net 2017-10-21 실습 "Doc Brown and Marty McFly: Back to the Present" (팀 훈련용으로 Snort 룰 과제가 붙은 버전) |
| **환경** | 폐쇄망(VirusTotal, OSINT 불가). Arkime v5.6.4 웹 화면, Zeek 로그가 들어간 Splunk, 분석 PC의 Snort 2.9 |
| **결과물** | 네트워크 베이스라인, 악성 활동 분석, 트래픽을 다시 찾는 Snort 룰(테스트 완료), 호스트 오퍼레이터용 단서 |
| **관련 페이지** | [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Zeek 로그](../../network/zeek/index.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [비콘과 C2](../../network/beaconing-c2.md) · [앞의 사례: Splunk + Arkime + Snort](phishing-red-herring-ek-driveby-ursnif-c2.md) |

!!! tip "이 페이지 읽는 법"
    완전한 초보자도 첫 클릭부터 보고서 완성까지 따라 할 수 있게 썼습니다. 단계마다 같은 순서로 설명합니다.

    1. **목적** — 이 단계에서 무엇을 알아내려는지
    2. **쿼리 / 명령** — 코드 블록 오른쪽 위 **복사 버튼**으로 복사
    3. **해설** — 한 조각씩 무슨 뜻인지
    4. **결과** — 이 PCAP에서 실제로 나온 값
    5. **결과 읽기** — 그 값이 무슨 뜻이고 왜 중요한지

    **Arkime**와 **Splunk** 쿼리를 단계마다 같이 적었습니다. Arkime는 세션 하나를 깊게 볼 때(패킷 내용, 파일), Splunk(Zeek)는 전체를 세고 묶을 때 좋습니다. 둘 중 하나만 있어도 따라 할 수 있어요.

!!! note "결과 값은 어디서 왔나요?"
    C1~C4단계의 Arkime 결과는 실제 Arkime 화면에서 확인한 값입니다. 나머지 값은 같은 PCAP을 **Zeek 7.0**과 **tshark**로 처리해서 확인했습니다. Arkime 세션 수와 Zeek 연결 수는 세는 규칙이 조금 달라서(예: UDP 세션을 언제 끊는지) 몇 개 차이가 날 수 있습니다. IP, 도메인, 시각, 바이트 수 같은 내용은 같습니다.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인, IP, 해시는 2017년의 실제 악성 트래픽에서 나온 값입니다. 본문과 표에서는 무력화(`hxxp`, `[.]`)해서 적었고, 코드 블록(쿼리, 룰, 원본 출력) 안에서는 입력한 그대로 두었습니다. **절대 접속하지 마세요.** 추출한 `.exe`는 격리된 분석 VM 밖에서 절대 열지 마세요.

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| 내부 네트워크 | **10.0.1.0/24** 하나 (서브넷 마스크 255.255.255.0) | 확인됨 (DHCP) |
| 장치 수 | **2대** — PC 1대 + 라우터 1대 (MAC 주소 2개뿐) | 확인됨 |
| PC | **10.0.1.95 DELOREAN-PC**, MAC `60:a4:4c:6a:b2:1f` (ASUSTek), **Windows 10 64비트**, IE11, 작업 그룹 **DOC-BROWN-GROUP** (도메인 가입 안 됨) | 확인됨 |
| 라우터 / 게이트웨이 | **10.0.1.1**, MAC `00:04:5a:f8:1a:ac` (Linksys) — DNS 서버도 겸함 | 확인됨 |
| DHCP 서버 | **10.0.1.254** — 라우터와 **같은 MAC**, 즉 같은 Linksys 장비의 다른 IP | 확인됨 |
| DNS 서버 | **10.0.1.1** (DHCP가 알려 준 값). DNS 접미사 `localdomain` | 확인됨 |
| DC / 파일 서버 / 웹·메일 서버 | **없음** — Kerberos, LDAP, SMB(445), 메일 포트 연결이 하나도 없음 | 확인됨 |
| 프로토콜 | DNS(UDP·**TCP**), HTTP, TLS, DHCP, NetBIOS(137/138), LLMNR, ICMP | 확인됨 |
| 첫 악성 이벤트 | **04:52:47 UTC** — User-Agent 없이 `hxxp://jgbennett[.]com/3cgconsulting.com/30_723bio_152.exe` 다운로드 (61,440바이트 PE, SHA256 `a56876fd…a490`) | 확인됨 |
| 다운로드 원인 | 바로 전(04:52:40~46) **Microsoft Office**가 통신 시작 → 문서 매크로가 받았을 가능성 | 추정 |
| C2 | `amellet[.]bit` → **35.198.166.240:80**. 외부 DNS 서버 9곳에 **TCP 53**으로 질의. HTTP/1.0 POST `/a/`, `/html/` **39번** (04:54:03 – 05:02:05), User-Agent 없음, 내용 암호화, 받은 양 약 **2.34MB**, 보낸 양 약 **23KB** | 확인됨 |
| 악성코드 계열 | **Chthonic**(Zeus 변종) 유형 — 공개 분석과 일치. 폐쇄망이라 해시 조회 안 함 | 추정 |
| 기술지원 사기 | 05:02:26 `www.singlemoms[.]org`의 **팝언더 스크립트** → 05:03:25 클릭 → `helpcenterforall[.]bid` (302) → `krep2010123[.]tk/?number=888-779-0939` 가짜 "Windows Defender: Zeus Virus Detected" 페이지와 경고음 | 확인됨 |
| 악성 활동 시간 | **2017-10-21 04:52:47 – 05:03:31 UTC** | 확인됨 |
| 측면 이동 | **없음** — 다른 내부 PC 자체가 없음 | 확인됨 |
| Snort | 룰 14개(sid 1000201–1000214), PCAP 테스트에서 모두 예상대로 동작, 정상 트래픽 오탐 0개 | 확인됨 |

---

## A부 — 시나리오와 계획 { #scenario }

### 받은 것 { #given }

과제 설명을 정리하면 이렇습니다.

- 친구 **Marty**와 그의 동료 **Doc**이 "스테인리스 강철 기계" 안에서 돌아가는 **Windows**를 봐 달라고 불렀습니다.
- 미래에서 돌아와 보니 **이상한 트래픽**이 있었고, 그 트래픽을 PCAP으로 녹화해 줬습니다.
- **호스트 오퍼레이터**가 PC에서 조사를 이어갈 수 있는 정보를 넣으세요.
- 그 트래픽을 다시 찾을 수 있는 **Snort 룰**을 만드세요.

"스테인리스 강철 기계"는 영화 *Back to the Future*의 타임머신 자동차 **DeLorean**입니다. 그래서 호스트 이름이 `DELOREAN-PC`, 작업 그룹이 `DOC-BROWN-GROUP`이에요.

---

### 계획 { #plan }

1. **베이스라이닝(B·C부)**: 평소 모습을 먼저 압니다. 정상이 뭔지 알아야 이상한 것이 보이니까요.
2. **악성 행위 찾기(D부)**: 베이스라인에서 벗어난 것을 하나씩 따라갑니다.
3. **Snort 룰(E부)**: 찾은 것을 다시 잡는 룰을 만들고 PCAP으로 테스트합니다.
4. **정리(F부)**: 타임라인, IOC, 호스트 오퍼레이터 단서.

---

## B부 — 준비 { #prep }

### B0단계 — 증거 해시 기록 { #evidence-hash }

**목적:** 분석 전에 증거 파일의 지문(해시)을 남깁니다. 나중에 "분석하는 동안 파일이 바뀌지 않았다"는 것을 증명할 수 있어요.

```bash
sha256sum 2017-10-21-traffic-analysis-exercise.pcap
md5sum 2017-10-21-traffic-analysis-exercise.pcap
```

- `sha256sum 파일` — 파일 내용으로 SHA256 해시(64자리 16진수)를 계산합니다. 내용이 1바이트만 달라도 완전히 다른 값이 나와요.
- `md5sum` — 같은 일을 MD5로 합니다(32자리). 오래된 도구와 비교할 때 씁니다.

**결과:**

```text
a42fd8341966fbf385e54feaf24218eb1df0f408bc060baa5f5c22aeb1318846  2017-10-21-traffic-analysis-exercise.pcap
30d573501a9458f70fb72d991b0db556  2017-10-21-traffic-analysis-exercise.pcap
```

### B1단계 — 시간대와 시간 범위 맞추기 { #timezone }

**목적:** PCAP은 2017년 데이터입니다. 두 도구 모두 기본 검색 범위가 "최근"이라 그대로 두면 **결과가 0건**이에요. 그리고 보고서는 **UTC**로 씁니다.

**Arkime:**

- 상단 시간 범위를 **All**(또는 PCAP 날짜를 포함하는 **Custom**)로 바꿉니다.
- **Settings**에서 시간 표시(Timezone)를 **UTC**로 바꿉니다.

**Splunk:**

- 시간 선택기(Time picker)를 **All time**으로 둡니다.
- 오른쪽 위 계정 이름 → **Preferences → Time zone**을 UTC로 바꿉니다. 안 바뀌는 환경이면 아래 `ts` 필드를 쓰면 됩니다.

!!! warning "Splunk의 `_time` 함정"
    지난 사례에서는 Splunk가 Zeek 로그 안의 시각을 못 읽어서 **모든 이벤트의 `_time`이 로그를 넣은 날**(2026년)로 찍혀 있었습니다. 그래서 이 페이지의 Splunk 쿼리는 시각에 **Zeek의 `ts` 필드**(UTC epoch 초)를 씁니다. `_time`이 2017-10-21로 제대로 나오면 `_time`을 써도 됩니다.

### B2단계 — Splunk에 어떤 Zeek 로그가 있나 { #data-discovery }

**목적:** 쿼리를 쓰기 전에 실제 인덱스와 sourcetype 이름을 확인합니다.

```spl
| tstats count where index=zeek by sourcetype
| sort sourcetype
```

- 맨 앞 `|` — 이벤트 검색이 아니라 **명령으로 시작**한다는 뜻입니다.
- `tstats count` — 이벤트를 하나하나 읽지 않고 색인 정보로 **아주 빨리 셉니다**.
- `where index=zeek` — `zeek` 인덱스만. 회사 지침상 `index=*`는 쓰지 않습니다. 인덱스 이름을 모르면 **Settings → Indexes**에서 확인하세요.
- `by sourcetype` — 로그 종류별로 한 줄씩.
- `sort sourcetype` — 이름순으로 정렬.

**결과 (Zeek가 이 PCAP으로 만든 로그 줄 수):**

| sourcetype | count | 들어 있는 것 |
|---|---|---|
| zeek:conn | 510 | 모든 연결(누가, 누구에게, 포트, 바이트, 상태) |
| zeek:dhcp | 2 | IP 할당(호스트 이름, MAC) |
| zeek:dns | 258 | DNS 질문과 답 (NetBIOS 이름 질의도 섞여 있음) |
| zeek:files | 343 | 주고받은 파일(종류, 크기, 해시) |
| zeek:http | 304 | HTTP 요청과 응답 |
| zeek:pe | 1 | 윈도우 실행 파일 정보 |
| zeek:software | 3 | User-Agent로 알아낸 소프트웨어 |
| zeek:ssl | 87 | TLS 연결(접속한 사이트 이름) |
| zeek:weird | 11 | 규칙에 안 맞는 이상한 통신 |
| zeek:x509 | 21 | 인증서 |

**결과 읽기:** 환경에 따라 sourcetype 이름이 `bro:conn:json`, `zeek_conn`처럼 다를 수 있습니다. 그러면 아래 쿼리의 `sourcetype=zeek:conn`을 실제 이름으로 바꾸세요. **`kerberos`, `smb`, `ntlm`, `smtp` 로그가 아예 없다**는 것도 벌써 단서입니다. 이 캡처에는 윈도우 도메인 로그인도, 파일 공유도, 메일도 없다는 뜻이에요.

**필드 이름 확인:**

```spl
index=zeek sourcetype=zeek:conn
| head 1
```

- `head 1` — 첫 이벤트 1개만 보여 줍니다. 왼쪽 필드 목록에서 이름을 확인하세요.

지난 실습 환경에서는 필드 이름이 **밑줄**이었습니다: `id_orig_h`(출발지 IP), `id_orig_p`(출발지 포트), `id_resp_h`(목적지 IP), `id_resp_p`(목적지 포트), `proto`, `service`, `orig_bytes`, `resp_bytes`, `conn_state`, `ts`. 이 페이지도 그 이름을 씁니다. 필드가 `id.orig_h`처럼 **점**으로 나오면 쿼리의 밑줄을 점으로 바꾸고, `eval`/`where` 안에서는 `'id.orig_h'`처럼 작은따옴표로 감싸세요.

---

## C부 — 네트워크 베이스라이닝 { #baselining }

베이스라이닝은 **"이 네트워크의 평소 모습"을 그리는 일**입니다. 무엇이 있는지 알아야, 없어야 할 것이 눈에 띕니다. 순서는 이렇습니다.

```text
데이터 범위 → 내부 IP와 대역 → 장치(호스트 이름, MAC) → 라우터 → 서버 역할(DNS, DHCP, DC, 파일, 웹, 메일)
→ 프로토콜 → OS → 외부 통신
```

### C1단계 — 데이터 범위: 언제부터 언제까지, 몇 개인가 { #time-range }

**목적:** 분석할 시간 범위를 정하고, 보고서 시각의 기준을 잡습니다.

**Arkime:** 검색창을 **비우고** Search → **Sessions** 탭.

- 목록 위 "Showing 1 - 50 of **N** entries"의 N = 세션 수
- **Start Time** 칸 제목을 눌러 오름차순/내림차순으로 정렬하면 처음과 마지막 세션 시각

**결과 (Arkime 화면):**

```text
Start  2017/10/21 04:51:53     End  2017/10/21 05:03:53     (00:12:00)
Showing 1 - 50 of 505 entries
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:conn
| stats count AS connections min(ts) AS first_seen max(ts) AS last_seen
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

- `stats count AS connections` — 연결 수를 세고 이름을 `connections`로 붙입니다. `AS`는 "이름 붙이기"예요.
- `min(ts) AS first_seen max(ts) AS last_seen` — `ts`는 연결이 **시작된** 시각(UTC epoch 초)입니다. 가장 이른 값과 늦은 값을 구합니다.
- `eval ... strftime(숫자, "형식")` — `1508561513` 같은 숫자를 읽을 수 있는 날짜로 바꿉니다. `%Y`=연, `%m`=월, `%d`=일, `%H:%M:%S`=시:분:초. 쉼표로 두 필드를 한 번에 바꿀 수 있어요.

**결과:**

```text
connections  first_seen           last_seen
510          2017-10-21 04:51:53  2017-10-21 05:03:26
```

**결과 읽기:**

- **12분짜리 짧은 캡처**입니다. 몇 시간짜리 데이터에서 바늘을 찾는 상황이 아니라, 사건 장면을 잘라 온 것이라 세션 상당수가 사건과 관련 있을 수 있어요.
- Splunk의 `last_seen`이 05:03:26인 이유: `ts`는 연결 **시작** 시각입니다. 마지막 연결은 05:03:26에 시작해서 05:03:52까지 이어졌어요.
- Arkime 505개, Zeek 510개 — 세는 규칙이 달라서 생기는 작은 차이입니다. 둘이 **비슷하면** 같은 데이터를 보고 있다는 확인이 됩니다.
- Arkime 막대 그래프의 모양도 메모해 둡니다: 04:52–04:56 꾸준한 활동, 04:57–05:00 거의 조용, 05:00–05:01 다시 몰림, **05:02:30쯤 급증**. 이유는 D부에서 밝혀집니다.

### C2단계 — 내부 IP와 내부 대역 { #internal-ips }

**목적:** "우리 편"이 누구인지 정합니다. 그래야 외부와 내부를 나눌 수 있어요.

사설(내부) IP 대역은 딱 세 가지입니다. 외워 두세요.

```text
10.0.0.0/8       10.x.x.x
172.16.0.0/12    172.16.x.x ~ 172.31.x.x
192.168.0.0/16   192.168.x.x
```

`/8`, `/24` 같은 표기를 **CIDR**이라고 합니다. 앞에서 몇 비트가 네트워크 주소인지 나타내요. `/24`면 앞 세 칸이 같은 주소들(예: 10.0.1.0 ~ 10.0.1.255)이 한 네트워크입니다.

**Arkime:**

```text
ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16
```

- `ip.src` — 출발지 IP. Arkime는 CIDR을 바로 이해합니다.
- `||` — "또는". 세 대역 중 하나라도 맞으면 나옵니다.

→ **SPIView** 탭 → **General** 섹션의 **Src IP**, **Dst IP**, **Protocols**.

**결과 (Arkime 화면):**

```text
Src IP     10.0.1.95 (501)  10.0.1.254 (2)
Dst IP     10.0.1.1 (158)  35.198.166.240 (34)  188.165.200.156 (31)  23.56.3.183 (20)
           13.107.4.52 (19)  198.232.125.32 (18)  52.183.114.173 (17)  13.107.21.200 (11)
           204.79.197.200 (11)  10.0.1.255 (8)  224.0.0.252 (7)  ...  10.0.1.95 (2)  ...
Protocols  tcp (328)  dns (188)  udp (174)  http (166)  tls (87)  http2 (24)  llmnr (7)  dhcp (2)  icmp (1)
```

**Splunk — 내부 IP별 활동량:**

```spl
index=zeek sourcetype=zeek:conn (id_orig_h=10.0.0.0/8 OR id_orig_h=172.16.0.0/12 OR id_orig_h=192.168.0.0/16)
| stats count AS connections dc(id_resp_h) AS unique_destinations BY id_orig_h
| sort - connections
```

- 첫 줄 괄호 — 출발지 IP가 사설 대역인 연결만. Splunk 검색도 `필드=CIDR`을 이해합니다.
- `dc(id_resp_h)` — **distinct count**, 서로 다른 목적지 IP의 개수.
- `BY id_orig_h` — 출발지 IP별로 한 줄씩.
- `sort - connections` — 연결 수가 많은 순(`-` = 큰 것부터).

**결과:**

```text
id_orig_h    connections  unique_destinations
10.0.1.95    508          91
```

**Splunk — 어떤 서브넷이 있나:**

```spl
index=zeek sourcetype=zeek:conn (id_orig_h=10.0.0.0/8 OR id_orig_h=172.16.0.0/12 OR id_orig_h=192.168.0.0/16)
| rex field=id_orig_h "^(?<subnet>\d+\.\d+\.\d+)\.\d+$"
| stats dc(id_orig_h) AS hosts values(id_orig_h) AS ips BY subnet
```

- `rex field=id_orig_h "정규식"` — `rex`는 정규식으로 **글자 일부를 잘라 새 필드를 만드는** 명령입니다.
- `^(?<subnet>\d+\.\d+\.\d+)\.\d+$` — `\d+`는 숫자 여러 개, `\.`은 점입니다. 앞 세 칸(`10.0.1`)을 `subnet`이라는 이름으로 잘라 냅니다. `(?<이름>...)`이 "이 부분에 이름 붙이기"예요.
- `values(id_orig_h)` — 서로 다른 값의 목록.

**결과:**

```text
subnet   hosts  ips
10.0.1   1      10.0.1.95
```

**결과 읽기:**

- **연결을 시작하는 내부 PC는 10.0.1.95 한 대**입니다. 501개(Arkime) / 508개(Zeek) 세션을 모두 이 PC가 시작했어요.
- 내부 대역은 **10.0.1.0/24** 하나입니다. Dst IP의 `10.0.1.255`는 이 /24 네트워크 전체에 외치는 **브로드캐스트 주소**라서 /24라는 것을 뒷받침합니다(C4단계에서 DHCP로 확정).
- **10.0.1.1은 목적지로만 158번** 나옵니다. 스스로 연결을 시작하지 않고 **질문만 받는 장치**, 즉 서버 역할이에요.
- **10.0.1.254는 세션 2개만 시작**했고, Dst IP에 `10.0.1.95 (2)`가 있습니다. 10.0.1.254가 10.0.1.95에게 보낸 것이에요. 무엇인지는 C3단계에서 봅니다.
- 숫자가 2개 빕니다: 전체 505개인데 501 + 2 = **503개**. **출발지가 사설 IP가 아닌 세션이 2개** 있다는 뜻이고, 이것도 C3단계에서 확인합니다.
- `224.0.0.252 (7)`은 **LLMNR**(윈도우가 같은 망에 이름을 묻는 멀티캐스트)이고 `10.0.1.255 (8)`은 **NetBIOS 브로드캐스트**입니다. 윈도우 PC의 평소 잡음이에요.
- **Protocols에 `http (166)`이 `tls (87)`보다 훨씬 많습니다.** 2017년이라도 웹은 이미 상당 부분 암호화였으니, 평문 HTTP가 이렇게 많은 건 메모해 둘 만합니다.

### C3단계 — 출발지가 내부가 아닌 세션 2개와 10.0.1.254 { #non-internal }

**목적:** 비어 있는 2개 세션과 10.0.1.254의 세션 2개가 무엇인지 봅니다. 특히 **외부에서 먼저 들어온 연결**(인바운드)이 있는지 꼭 확인해야 합니다.

**Arkime:**

```text
ip.src != 10.0.0.0/8 || ip.src == 10.0.1.254
```

- `ip.src != 10.0.0.0/8` — 출발지가 10.x.x.x가 **아닌** 세션. `!=`는 "같지 않다"입니다. 이 PCAP에는 172·192 대역이 없어서 10 대역만 빼면 충분해요.
- `ip.src == 10.0.1.254` — 10.0.1.254가 시작한 세션.

→ **Sessions** 탭.

**결과 (Arkime 화면, 4개):**

```text
04:51:53  udp  0.0.0.0:68       -> 255.255.255.255:67   dhcp  313 B
04:51:53  udp  10.0.1.254:67    -> 10.0.1.95:68         dhcp  300 B
04:53:08  udp  0.0.0.0:68       -> 255.255.255.255:67   dhcp  313 B
04:53:08  udp  10.0.1.254:67    -> 10.0.1.95:68         dhcp  300 B
```

**결과 읽기:**

DHCP는 PC가 네트워크에 붙을 때 **"IP 하나 주세요"** 하고 받아 오는 과정입니다. 포트가 정해져 있어요: **67번 = DHCP 서버, 68번 = 클라이언트(PC)**.

- `0.0.0.0` 출발 2개가 비어 있던 2개입니다. PC가 아직 자기 IP를 확정하기 전에는 출발지를 `0.0.0.0`으로 쓰고, 서버 위치를 모르니 `255.255.255.255`(네트워크 전체 브로드캐스트)로 외칩니다. **정상**이에요.
- 그래서 **외부에서 먼저 들어온 연결은 하나도 없습니다.** 505개 세션은 모두 내부에서 시작됐어요. "없다"도 결과라서 보고서에 적습니다.
- **10.0.1.254 = DHCP 서버**입니다(67번 포트에서 답함).
- Splunk(Zeek)에서는 같은 DHCP가 `10.0.1.95 → 10.0.1.254:67`로 보입니다. Zeek는 DHCP 연결을 **클라이언트 → 서버** 방향으로 정리해서 적기 때문이에요. 도구마다 "출발지"를 정하는 규칙이 다르다는 것을 기억해 두세요.
- 같은 일이 **75초 간격으로 두 번**(04:51:53, 04:53:08) 있었습니다. PC가 켜지거나 네트워크에 다시 붙을 때 생기는 일이에요. 두 번째가 왜 있었는지는 D부의 타임라인에서 다시 봅니다.

`Not Found`는 "외부에서 들어온 연결을 찾아봤는데 **없었다**"는 뜻입니다.

### C4단계 — 장치 정보: 호스트 이름, MAC, 네트워크 설정 (DHCP) { #dhcp }

**목적:** DHCP 요청에는 PC가 스스로 밝히는 **호스트 이름**과 **MAC 주소**가 들어 있고, 서버의 답에는 **서브넷 마스크, 게이트웨이, DNS 서버** 같은 네트워크 설정이 들어 있습니다. 베이스라인의 핵심 정보가 한 번에 나와요.

**Arkime:**

```text
protocols == dhcp
```

- `protocols` — Arkime가 알아낸 프로토콜 목록. `== dhcp`면 DHCP 세션만.

→ **SPIView** → **dhcp** 섹션(안 보이면 오른쪽 위 **Load All**).

**결과 (Arkime 화면):**

```text
Client MAC   60:a4:4c:6a:b2:1f (4)        Client MAC Cnt  1
Client OUI   ASUSTek COMPUTER INC. (4)
Host         delorean-pc (2)
Transaction id  15a2b597 (2)  d0ad6ea9 (2)
Type         ACK (2)  REQUEST (2)
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:dhcp
| eval t=strftime(ts, "%H:%M:%S")
| table t client_addr server_addr assigned_addr mac host_name domain lease_time msg_types
```

- `eval t=strftime(ts, "%H:%M:%S")` — 시각만 읽기 좋게 새 필드 `t`로 만듭니다.
- `table 필드 목록` — 원하는 칸만 표로 보여 줍니다.
- `client_addr` / `assigned_addr` — PC의 IP / 서버가 준 IP.
- `server_addr` — DHCP 서버.
- `mac` — 하드웨어 주소. IP보다 훨씬 덜 바뀝니다.
- `host_name` — PC가 밝힌 **컴퓨터 이름**.
- `domain` — 서버가 알려 준 **DNS 접미사**.
- `lease_time` — IP를 빌려 쓰는 시간(초).
- `msg_types` — DHCP 메시지 종류.

**결과:**

```text
t         client_addr  server_addr  assigned_addr  mac                host_name    domain       lease_time  msg_types
04:51:53  10.0.1.95    10.0.1.254   10.0.1.95      60:a4:4c:6a:b2:1f  DELOREAN-PC  localdomain  1800.0      REQUEST ACK
04:53:08  10.0.1.95    10.0.1.254   10.0.1.95      60:a4:4c:6a:b2:1f  DELOREAN-PC  localdomain  1800.0      REQUEST ACK
```

**결과 읽기:**

- **호스트 이름 DELOREAN-PC.** 과제의 "DeLorean"과 맞습니다. Arkime에서 Host가 `(2)`인 이유는 PC가 보낸 REQUEST 2개에만 이름이 들어 있기 때문이에요.
- **MAC `60:a4:4c:6a:b2:1f`.** MAC은 네트워크 카드마다 다른 고유 번호입니다. IP는 바뀔 수 있어도 MAC은 거의 안 바뀌어서, 호스트 오퍼레이터가 **정확히 어느 기계인지** 찾을 때 가장 확실한 단서예요.
- **OUI = ASUSTek.** MAC 앞 6자리(`60:a4:4c`)는 제조사 번호입니다. ASUS 네트워크 카드를 쓰는 일반 PC나 노트북으로 보입니다.
- **DISCOVER, OFFER 없이 REQUEST와 ACK만** 있습니다. DHCP는 원래 4단계예요.

    ```text
    DISCOVER  PC: "DHCP 서버 있나요?"
    OFFER     서버: "이 IP 어때요?"
    REQUEST   PC: "그 IP 쓸게요"
    ACK       서버: "확인, 쓰세요"
    ```

    앞의 두 단계가 없다는 건, PC가 **이미 쓰던 IP(10.0.1.95)를 다시 쓰겠다고 확인만 받은** 것입니다. 재부팅이나 네트워크 재연결 때 이렇게 해요. Transaction id가 두 개라서 **서로 다른 요청 두 번**이었다는 것도 확인됩니다.

- **`domain = localdomain`** — 회사 AD 도메인이 아니라 공유기가 기본으로 주는 이름입니다. 가정이나 작은 사무실 공유기 환경이라는 첫 단서예요.
- **`lease_time = 1800`초 = 30분.**

**DHCP 서버의 답 안에 든 설정 (패킷 세부).** Zeek와 Arkime의 DHCP 칸에는 게이트웨이와 DNS 서버가 나오지 않습니다. 패킷을 직접 열면 보입니다. Arkime에서 `10.0.1.254 -> 10.0.1.95` 세션을 펼치고 패킷을 보거나, 분석 PC에 Wireshark/tshark가 있으면 이렇게 봅니다.

```bash
tshark -r 2017-10-21-traffic-analysis-exercise.pcap -Y "dhcp.option.dhcp == 5" -V | grep -E "^ +(DHCP Server Identifier|Subnet Mask|Router|Domain Name Server|Domain Name|IP Address Lease Time):" | head -6
```

- `-r 파일` — PCAP을 읽습니다.
- `-Y "dhcp.option.dhcp == 5"` — 화면 필터. DHCP 메시지 종류 5번 = **ACK**(서버의 확정 답)만.
- `-V` — 패킷을 층별로 자세히 풀어서 보여 줍니다.
- `| grep -E "^ +(A|B|C):"` — 그중 원하는 줄만 고릅니다. `-E`는 확장 정규식, `^ +`는 "줄 앞이 공백", `(A|B|C)`는 "A 또는 B 또는 C"입니다.
- `| head -6` — 같은 ACK가 두 번 있어서, 앞의 6줄(첫 ACK)만 봅니다.

```text
DHCP Server Identifier: 10.0.1.254
IP Address Lease Time: 30 minutes (1800)
Subnet Mask: 255.255.255.0
Router: 10.0.1.1
Domain Name Server: 10.0.1.1
Domain Name: localdomain
```

→ **서브넷 255.255.255.0 = /24 확정, 게이트웨이(Router) = 10.0.1.1, DNS 서버 = 10.0.1.1.**

- 하나 더: PC의 요청에는 **Vendor class identifier: `MSFT 5.0`**이 들어 있습니다. 윈도우 2000 이후 모든 윈도우가 보내는 값이라 **OS가 윈도우**라는 증거입니다(C8단계).

### C5단계 — 장치는 몇 대이고, 라우터는 누구인가 (MAC) { #devices-router }

**목적:** IP 개수와 실제 장치 수는 다를 수 있습니다. 한 장치가 IP를 여러 개 가질 수도 있고, 고정 IP 장치는 DHCP에 안 나타나요. 그래서 **MAC 주소**로 장치를 셉니다. 같은 방법으로 **라우터**도 찾습니다.

**핵심 원리:** 외부로 나가는 패킷은 상대 서버의 MAC이 아니라 **라우터(게이트웨이)의 MAC**으로 보내집니다. 그래서 외부로 간 패킷의 목적지 MAC은 수백 개 IP에 대해서도 **딱 하나**이고, 그게 라우터예요. MAC은 같은 LAN 안에서만 의미가 있습니다.

**Arkime — 방법 1: MAC 칸 꺼내기**

```text
ip.src == 10.0.1.95 && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && ip.dst != 255.255.255.255
```

- `ip.src == 10.0.1.95` — PC가 보낸 것.
- `ip.dst != 10.0.0.0/8` — 목적지가 내부가 아닌 것.
- `ip.dst != 224.0.0.0/4` — 멀티캐스트(224~239로 시작) 제외.
- `ip.dst != 255.255.255.255` — 전체 브로드캐스트 제외. 즉 **진짜 외부로 나간 세션만** 남습니다.

→ **SPIView** → **General** 섹션의 "Search for fields to display in this category" 칸에 `mac`을 입력 → **Src MAC**, **Dst MAC**을 눌러 불러옵니다. 같은 방법으로 `oui`를 입력해 **Src OUI**, **Dst OUI**도 불러옵니다.

!!! question "질문: SPIView에 ethernet 섹션도 없고 Src MAC도 안 보여요"
    Arkime 버전이나 설정에 따라 MAC 칸(`mac.src`, `mac.dst`)이 **general 섹션 안에 숨어 있거나**, 아예 저장되지 않을 수 있습니다. 먼저 검색창에 `mac.src == 60:a4:4c:6a:b2:1f`를 넣어 보세요. 세션이 나오면 칸은 있는데 화면에 안 보이는 것이고, 0개면 이 Arkime가 MAC을 저장하지 않는 것입니다. 그럴 땐 **방법 2**를 씁니다. (앞의 DHCP Client MAC은 이더넷 헤더가 아니라 **DHCP 메시지 안에 적힌 값**이라서 따로 나왔습니다.)

**Arkime — 방법 2: 패킷의 첫 12바이트 읽기**

MAC 칸이 없어도 패킷 자체에는 MAC이 있습니다. 이더넷 프레임은 항상 이렇게 시작해요.

```text
바이트 0~5    목적지 MAC (6바이트)
바이트 6~11   출발지 MAC (6바이트)
바이트 12~13  다음 층 종류 (08 00 = IPv4)
```

1. 위 쿼리 결과에서 아무 세션(예: 35.198.166.240)의 **+** 를 눌러 세션 상세를 엽니다.
2. 아래 패킷 영역의 옵션에서 **hex**를 고르고, **Show Frames**(프레임 그대로 보기)를 켭니다. 버전에 따라 이름이 조금 다를 수 있어요.
3. PC가 보낸 첫 패킷의 첫 줄을 봅니다.

**결과 (10.0.1.95 → 35.198.166.240 첫 패킷):**

```text
0000  00 04 5a f8 1a ac 60 a4 4c 6a b2 1f 08 00 45 00   ..Z...`.Lj....E.
      └──── 목적지 MAC ────┘└──── 출발지 MAC ────┘└타입┘
```

**같은 방법으로 10.0.1.1의 DNS 응답과 10.0.1.254의 DHCP 응답을 보면:**

```text
10.0.1.1   -> 10.0.1.95 (DNS)   0000  60 a4 4c 6a b2 1f 00 04 5a f8 1a ac 08 00 ...
10.0.1.254 -> 10.0.1.95 (DHCP)  0000  60 a4 4c 6a b2 1f 00 04 5a f8 1a ac 08 00 ...
                                       └ 목적지 = PC ──┘ └ 출발지 = ? ────┘
```

**결과 정리 (PCAP 전체의 MAC):**

```text
출발지 MAC   00:04:5a:f8:1a:ac  The Linksys Group, Inc.   6,046 패킷
             60:a4:4c:6a:b2:1f  ASUSTek COMPUTER INC.     3,885 패킷
목적지 MAC   위 두 개 + ff:ff:ff:ff:ff:ff(브로드캐스트) + 01:00:5e:00:00:fc(LLMNR 멀티캐스트)
```

**결과 읽기:**

- 외부로 나간 패킷의 목적지 MAC은 전부 **`00:04:5a:f8:1a:ac`** 하나입니다. 이게 **라우터의 MAC**이에요. 앞 6자리 `00:04:5a`의 제조사는 **Linksys**(가정·소규모 사무실용 공유기)입니다.
- 10.0.1.1의 DNS 응답도, 10.0.1.254의 DHCP 응답도 **같은 MAC**에서 나왔습니다. 즉 **라우터 한 대가 10.0.1.1(게이트웨이·DNS)과 10.0.1.254(DHCP) 두 IP를 쓰고 있습니다.** C4단계에서 DHCP가 알려 준 "Router: 10.0.1.1"과도 맞아요.
- PCAP 전체에 진짜 장치의 MAC은 **두 개뿐**입니다. **장치는 2대: PC(DELOREAN-PC)와 Linksys 라우터.** `ff:ff:ff:ff:ff:ff`와 `01:00:5e:...`는 장치가 아니라 "모두에게" 보내는 주소예요.
- **IP 3개(10.0.1.95, 10.0.1.1, 10.0.1.254) ≠ 장치 3대.** IP만 세었으면 틀렸을 거예요.

**Splunk:** Zeek의 conn.log는 기본으로 MAC을 남기지 않습니다(센서에 `mac-logging` 스크립트를 켜면 `orig_l2_addr`, `resp_l2_addr` 칸이 생깁니다). 그래서 Splunk에서는 **내부 IP가 몇 개인지**와 **각 IP의 역할**까지만 확인하고, MAC은 Arkime나 DHCP 로그로 봅니다.

```spl
index=zeek sourcetype=zeek:conn
| eval ip=mvappend(id_orig_h, id_resp_h)
| mvexpand ip
| where cidrmatch("10.0.0.0/8", ip) OR cidrmatch("172.16.0.0/12", ip) OR cidrmatch("192.168.0.0/16", ip)
| stats count BY ip
```

- `eval ip=mvappend(id_orig_h, id_resp_h)` — 출발지와 목적지 IP를 한 칸에 **여러 값(multivalue)**으로 모읍니다.
- `mvexpand ip` — 여러 값을 **줄 하나에 하나씩** 펼칩니다. 이제 출발지든 목적지든 모든 IP를 한 번에 셀 수 있어요.
- `where cidrmatch("대역", ip)` — `cidrmatch`는 IP가 그 대역 안에 있으면 참입니다. `where`는 조건이 참인 줄만 남깁니다.
- `stats count BY ip` — IP별 등장 횟수.

**결과:**

```text
ip           count
10.0.1.1     161
10.0.1.254   2
10.0.1.255   6
10.0.1.95    508
```

`10.0.1.255`는 브로드캐스트 주소라서 장치가 아닙니다. **실제 내부 IP는 3개**, MAC으로 보면 **장치는 2대**입니다.

### C6단계 — 서버 역할: DNS, DHCP, DC, 파일·웹·메일 서버 { #server-roles }

**목적:** 내부에 어떤 서버가 있는지 찾습니다. **핵심 원리:** 서버는 **목적지 포트**로 정체가 드러납니다. 여러 PC가 같은 IP의 같은 포트로 접속하면 그 IP가 그 서비스의 서버예요.

포트로 역할 읽기 (외워 두면 좋은 것):

| 포트 | 서비스 | 역할 |
|---|---|---|
| 53 | DNS | DNS 서버 |
| 67/68 | DHCP | DHCP 서버 / 클라이언트 |
| 88, 464 | Kerberos | **DC** (도메인 로그인) |
| 389, 636, 3268 | LDAP, LDAPS, 글로벌 카탈로그 | **DC** |
| 135, 139, 445 | RPC, NetBIOS 세션, SMB | DC 또는 **파일 서버** |
| 80, 443, 8080 | HTTP, HTTPS | 웹 서버 |
| 25, 587, 110, 143, 993, 995 | SMTP, POP3, IMAP | 메일 서버 |
| 123 | NTP | 시간 서버 |
| 3389, 5985 | RDP, WinRM | 원격 관리 |
| 137, 138 | NetBIOS 이름 / 데이터그램 | 윈도우 이름 알리기 (서버 아님) |

**Arkime:**

```text
ip.dst == 10.0.0.0/8
```

→ **SPIView** → General의 **Dst IP**와 **Dst Port**.

- 목적지가 내부인 세션만 봅니다. 내부 서버를 찾으니까요.

**Splunk — 내부 IP가 받은 연결과 포트:**

```spl
index=zeek sourcetype=zeek:conn (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16 OR id_resp_h=224.0.0.0/4 OR id_resp_h=255.255.255.255) id_resp_p<10000
| stats dc(id_orig_h) AS clients count AS connections values(id_resp_p) AS ports values(proto) AS proto BY id_resp_h
| sort - connections
```

- 첫 줄 — 목적지가 내부·멀티캐스트·브로드캐스트인 연결, 그리고 `id_resp_p<10000`(목적지 포트 10000 미만)으로 응답용 임시 포트 잡음을 뺍니다.
- `dc(id_orig_h) AS clients` — 서로 다른 몇 대가 접속했는지.
- `values(id_resp_p) AS ports` — 어떤 포트로 접속받았는지.

**결과:**

```text
id_resp_h        clients  connections  ports         proto
10.0.1.1         1        161          3 53 137      icmp udp
224.0.0.252      1        7            5355          udp
10.0.1.255       1        6            137 138       udp
255.255.255.255  1        2            67            udp
10.0.1.254       1        2            67            udp
```

(`3`은 포트가 아니라 ICMP 종류 3 "Destination unreachable"입니다. Zeek는 ICMP의 종류를 포트 칸에 적어요.)

**DC·파일·메일 서비스가 정말 없는지 한 번 더:**

```spl
index=zeek sourcetype=zeek:conn id_resp_p IN (88, 135, 139, 389, 445, 464, 636, 3268, 3389, 5985, 25, 110, 143, 465, 587, 993, 995)
| stats count BY id_resp_h id_resp_p
```

- `id_resp_p IN (...)` — 목적지 포트가 목록 중 하나. DC(88, 389, 464, 636, 3268), 파일(135, 139, 445), 원격 관리(3389, 5985), 메일(25, 110, 143, 465, 587, 993, 995).

**결과:** `No results found.`

**DNS 서버 확인:**

```spl
index=zeek sourcetype=zeek:dns
| stats count dc(id_orig_h) AS clients values(proto) AS proto BY id_resp_h
| sort - count
```

- dns.log에서 **질문을 받은 쪽**(`id_resp_h`)이 DNS 서버입니다.

**결과:**

```text
id_resp_h        count  clients  proto
10.0.1.1         195    1        udp
188.165.200.156  31     1        tcp      ← !!
224.0.0.252      14     1        udp
10.0.1.255       12     1        udp
144.76.133.38    2      1        tcp      ← !!
130.255.78.223   1      1        tcp      ← !!
31.3.135.232     1      1        tcp      ← !!
62.113.203.99    1      1        tcp      ← !!
93.170.96.235    1      1        tcp      ← !!
```

**결과 읽기:**

- **DNS 서버 = 10.0.1.1** (라우터). DHCP가 알려 준 값과 같습니다.
- **DHCP 서버 = 10.0.1.254** (같은 라우터).
- **DC 없음.** Kerberos(88), LDAP(389) 연결이 하나도 없습니다. PC가 DNS로 `_ldap._tcp.dc._msdcs.DOC-BROWN-GROUP.localdomain`(DC를 찾는 SRV 질의)을 12번 물었지만 **답이 한 번도 없었어요.** 윈도우가 습관적으로 DC를 찾아본 것이고, 찾을 DC가 없습니다.
- **파일 서버 없음.** SMB(445), NetBIOS 세션(139) 연결이 없습니다. 137/138은 이름 알리기용이라 파일 공유가 아닙니다.
- **내부 웹·메일 서버 없음.** 내부 목적지에 80/443/메일 포트가 없습니다.
- **`224.0.0.252`와 `10.0.1.255`는 서버가 아니라** LLMNR 멀티캐스트와 NetBIOS 브로드캐스트입니다. dns.log에 섞여 있는 이유는 Zeek가 NetBIOS 이름 질의(UDP 137)도 DNS 형식으로 읽기 때문이에요. 그 줄의 `qtype_name`이 `NIMLOC`(번호 32)로 나오는데, NetBIOS에서는 이 번호가 "NB(이름)" 질의입니다.
- **!! 표시 — 외부 DNS 서버 6곳에 TCP로 질문했습니다.** 정상 PC는 **DHCP가 알려 준 DNS 서버(10.0.1.1)**에, 보통 **UDP**로 묻습니다. 외부 DNS 서버에 직접, 그것도 TCP로 묻는 건 **베이스라인에서 벗어난 첫 번째 큰 이상**입니다. D3단계에서 파고듭니다.

**NetBIOS로 본 작업 그룹 (Arkime 세션 상세 또는 tshark):** PC가 브로드캐스트로 `DOC-BROWN-GROUP`이라는 **작업 그룹(workgroup)** 이름을 알리고, 스스로 **마스터 브라우저**가 됐습니다. 마스터 브라우저는 같은 망의 윈도우 PC 목록을 관리하는 역할인데, 망에 윈도우가 자기 하나뿐이라 자기가 맡은 거예요. **도메인이 아니라 작업 그룹 = AD 없는 가정·소규모 환경**이라는 것이 다시 확인됩니다.

### C7단계 — 쓰인 프로토콜 { #protocols }

**목적:** 이 네트워크에서 평소 쓰는 프로토콜 목록을 만듭니다. 목록에 없는 게 나오거나, 있어야 할 포트가 아닌 곳에서 나오면 이상 징후예요.

**Arkime:** C2단계의 **Protocols** 목록 그대로입니다.

```text
tcp (328)  dns (188)  udp (174)  http (166)  tls (87)  http2 (24)  llmnr (7)  dhcp (2)  icmp (1)
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:conn
| stats count BY proto service
| sort - count
```

- `proto` — 전송 방식(tcp, udp, icmp).
- `service` — Zeek가 **내용을 보고** 알아낸 프로토콜. 포트가 아니라 내용으로 판단해요.

**결과:**

```text
proto  service  count
udp    dns      169
tcp    http     157
tcp    ssl      87
tcp    -        51
tcp    dns      37     ← TCP 위의 DNS
udp    dhcp     4
udp    -        4
icmp   -        1
```

**결과 읽기:**

- **평소 모습:** DNS(UDP), HTTP, TLS(`ssl`), DHCP, NetBIOS, LLMNR. 공유기에 붙은 윈도우 PC 한 대의 전형적인 모습이에요.
- **`tcp dns 37`** — TCP로 간 DNS 37개. C6단계의 외부 DNS 서버들입니다. DNS는 보통 UDP를 쓰고, TCP는 답이 아주 클 때나 서버끼리 복사할 때 씁니다. PC가 TCP DNS를 쓰는 건 **드문 일**이에요.
- **`tcp - 51`** — Zeek가 프로토콜을 못 알아낸 TCP 연결입니다. 이 PCAP에서는 대부분 **브라우저가 미리 열어 두고 안 쓴 연결**(상태 S1/S3, 데이터 없음)과 **실패한 TCP DNS 연결**(130.255.73.90, 37.187.16.17, 85.159.213.210 — 응답 없음/거절)이었습니다. 이상한 포트의 정체불명 프로토콜은 아니에요.
- **`icmp 1`** — PC가 라우터에게 보낸 "Port unreachable"입니다. DNS 답이 늦게 와서 PC가 이미 닫은 포트로 들어왔을 때 생기는 흔한 잡음이에요.
- Arkime의 `http2 (24)`는 TLS 안에서 협상된 HTTP/2입니다(Zeek에서는 `ssl`로 셉니다).

### C8단계 — OS는 무엇인가 { #os }

**목적:** 어떤 OS인지 알면 호스트 오퍼레이터가 무엇을 볼지(이벤트 로그, 레지스트리 등) 정할 수 있습니다. 단서는 여러 군데에 있어요.

**① User-Agent (가장 쉬움).** 프로그램이 HTTP 요청에 붙이는 자기소개입니다.

**Arkime:**

```text
ip.src == 10.0.1.95 && protocols == http
```

→ **SPIView** → **http** 섹션의 **User-Agent**(`http.user-agent`).

**Splunk:**

```spl
index=zeek sourcetype=zeek:http id_orig_h=10.0.1.95
| fillnull value="(none)" user_agent
| stats count BY user_agent
| sort - count
```

- `fillnull value="(none)" user_agent` — `user_agent` 칸이 **없는** 이벤트에 `(none)`이라는 값을 채웁니다. 이게 없으면 `stats`가 빈 칸을 그냥 빼 버려서, User-Agent 없는 요청이 결과에서 사라져요. (TSV로 넣은 Zeek 로그라면 빈 칸이 `-`로 들어 있습니다.)

**결과:**

```text
user_agent                                                            count
Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko  164
(none)                                                                 123   ← !!
Microsoft-CryptoAPI/10.0                                               9
Microsoft-WNS/10.0                                                     8
```

- `Windows NT 10.0` — **Windows 10** (또는 Server 2016 이후). 참고로 `6.1` = Windows 7, `6.3` = Windows 8.1.
- `WOW64` — 64비트 윈도우에서 **32비트 프로그램**이 돈다는 뜻. 즉 **64비트 Windows 10**.
- `Trident/7.0; rv:11.0` — **Internet Explorer 11**.
- `Microsoft-CryptoAPI/10.0` — 윈도우가 인증서 상태를 확인할 때(OCSP) 쓰는 값.
- `Microsoft-WNS/10.0` — 윈도우 10 시작 메뉴의 **라이브 타일**(뉴스, 날씨)이 쓰는 값.
- **`(none)` 123개 — User-Agent가 아예 없는 요청.** 브라우저와 윈도우 구성 요소는 거의 항상 User-Agent를 보냅니다. 이건 D부에서 가장 중요한 단서가 됩니다.

**② Zeek software.log:**

```spl
index=zeek sourcetype=zeek:software
| table host software_type name unparsed_version
```

- Zeek가 User-Agent 등에서 **알아낸 소프트웨어 목록**입니다.

```text
host       software_type  name                 unparsed_version
10.0.1.95  HTTP::BROWSER  Microsoft-WNS        Microsoft-WNS/10.0
10.0.1.95  HTTP::BROWSER  MSIE                 Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko
10.0.1.95  HTTP::BROWSER  Microsoft-CryptoAPI  Microsoft-CryptoAPI/10.0
```

**③ 다른 단서들 (Arkime 세션 상세 / tshark):**

- **DHCP Vendor class `MSFT 5.0`** (C4단계) — 윈도우.
- **NetBIOS 브라우저 알림의 OS 버전 `10.0`** — PC가 브로드캐스트로 알린 값. 윈도우 10.
- **IP TTL 128** — PC가 보낸 패킷의 TTL(남은 홉 수) 기본값이 128입니다. 윈도우는 128, 리눅스·맥은 보통 64예요. Arkime 패킷 hex에서 IP 헤더의 9번째 바이트(프레임 기준 `0x16` 위치, 위 C5 예시의 두 번째 줄 `80`)입니다.
- **DNS 질의 이름** — `dns.msftncsi.com`(윈도우 인터넷 연결 확인), `win10.ipv6.microsoft.com`, `client.wns.windows.com`, `tile-service.weather.microsoft.com` — 모두 윈도우 10이 켜질 때 하는 질의입니다.
- **Office 도메인** — `officeclient.microsoft.com`, `nexus.officeapps.live.com`, `messaging.office.com` → **Microsoft Office가 설치되어 있고 실행됐습니다.** 이건 D2단계에서 중요해져요.

**결과 읽기:** **DELOREAN-PC = 64비트 Windows 10, IE11, Microsoft Office 설치.** 다른 OS(맥, 리눅스, 안드로이드)의 흔적은 없습니다.

### C9단계 — 외부 통신 개요 { #external }

**목적:** PC가 바깥의 누구와, 얼마나 이야기하는지 큰 그림을 봅니다. 대부분은 Microsoft, Google 같은 정상 서비스이고, 그 속에 섞인 **낯선 것**을 찾습니다.

**Arkime:**

```text
ip.src == 10.0.1.95 && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && ip.dst != 255.255.255.255
```

→ **SPIView** → General의 **Dst IP**, **Dst Port**, 그리고 **dns** 섹션의 **Host**, **tls** 섹션의 **Host**(SNI).

**Splunk — 외부 목적지별 요약:**

```spl
index=zeek sourcetype=zeek:conn id_orig_h=10.0.1.95 NOT (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16 OR id_resp_h=224.0.0.0/4 OR id_resp_h=255.255.255.255)
| stats count AS connections sum(orig_bytes) AS bytes_out sum(resp_bytes) AS bytes_in values(id_resp_p) AS ports values(service) AS service BY id_resp_h
| sort - connections
```

- `NOT (...)` — 목적지가 내부·멀티캐스트·브로드캐스트가 **아닌 것**, 즉 진짜 외부.
- `sum(orig_bytes) AS bytes_out` — PC가 **보낸** 총 바이트(유출을 볼 때 중요).
- `sum(resp_bytes) AS bytes_in` — 상대가 **보낸** 총 바이트(다운로드를 볼 때 중요).

**결과 (상위 15개 / 외부 IP 87개, 연결 332개):**

```text
id_resp_h        connections  bytes_out  bytes_in   ports  service
35.198.166.240   34           25,484     2,350,698  80     http        ← !!
188.165.200.156  31           961        6,231      53     dns         ← !!
23.56.3.183      20           40,742     281,646    80     http -
13.107.4.52      19           6,424      59,933     80     http
198.232.125.32   18           8,798      253,507    80     http -
52.183.114.173   17           108,232    81,852     443    ssl
13.107.21.200    11           19,681     290,534    443    ssl
204.79.197.200   11           22,415     289,096    443    ssl
104.43.139.11    6            7,352      41,922     443    ssl
173.194.206.94   6            4,829      336,724    80     http -
34.206.190.189   6            24,063     10,240     80     http
173.194.206.154  5            7,129      175,185    443    ssl
65.52.108.254    4            9,815      15,568     443    ssl
23.79.207.65     4            852        18,427     80     http
23.73.31.19      4            1,824      27,469     443    ssl
```

**외부로 나간 포트:**

```spl
index=zeek sourcetype=zeek:conn id_orig_h=10.0.1.95 NOT (id_resp_h=10.0.0.0/8 OR id_resp_h=224.0.0.0/4 OR id_resp_h=255.255.255.255)
| stats count BY proto id_resp_p
```

```text
proto  id_resp_p  count
tcp    80         196
tcp    443        90
tcp    53         46     ← !!
```

**접속한 사이트 이름 (TLS SNI):**

```spl
index=zeek sourcetype=zeek:ssl
| stats count BY server_name id_resp_h
| sort - count
```

- `server_name` — TLS 연결을 시작할 때 브라우저가 밝히는 **접속할 사이트 이름**(SNI). 내용은 암호화돼도 이 이름은 보입니다.

**결과 (요약):** `watson.telemetry.microsoft.com`, `www.bing.com`, `messaging.office.com`, `client.wns.windows.com`, `cdn.onenote.net`, `securepubads.g.doubleclick.net`, `nexus.officeapps.live.com`, `login.live.com` … — **모두 Microsoft, Google, 광고 서비스**입니다. 이상한 인증서나 이상한 포트의 TLS는 없습니다.

**결과 읽기:**

- 외부 통신은 **80, 443, 53(TCP)** 세 포트뿐입니다. 80/443은 평범하지만 **TCP 53이 46번**이나 됩니다.
- **35.198.166.240이 연결 수 1위, 받은 양 1위(약 2.35MB)**입니다. 평문 HTTP로 이렇게 많이 받는 곳이 Microsoft나 Google이 아니라면 수상합니다.
- **188.165.200.156**은 C6단계에서 본 외부 DNS 서버입니다. TCP 53으로 31번.
- TLS는 모두 큰 정상 서비스 → 이번 사건의 수상한 통신은 **평문 HTTP와 TCP DNS**에 있습니다.
- Zeek notice.log에 `SSL::Invalid_Server_Cert` 7개가 있지만, 모두 Microsoft/Google 인증서이고 이유는 "unable to get local issuer certificate"(센서에 루트 인증서 목록이 없어서)입니다. 사건과 관계없는 **센서 쪽 잡음**이에요.

**드문 도메인 찾기:**

```spl
index=zeek sourcetype=zeek:dns qtype_name=A
| stats count BY query
| sort count
```

- `qtype_name=A` — IPv4 주소를 묻는 질의만(NetBIOS·SRV 잡음 제외).
- `sort count` — **적은 것부터.** 한두 번만 조회된 도메인이 위로 올라옵니다. 악성 도메인은 보통 여기 숨어 있어요.

**결과 (1번만 조회된 것 중 일부):** `jgbennett.com`, `contentstorage.osi.office.net`, `officeclient.microsoft.com`, `messaging.office.com`, `www.singlemoms.org`, 광고 도메인 수십 개 … 그리고 위로 올라오지는 않지만 **`amellet.bit`가 37번**(모두 TCP, 외부 서버)입니다.

`Further Analysis Required`인 이유: 외부 통신에서 수상한 후보(35.198.166.240, TCP DNS, User-Agent 없는 요청)를 찾았고, D부에서 확인할 거라서요.

### C10단계 — 베이스라인 정리 { #baseline-summary }

| 항목 | 값 |
|---|---|
| 캡처 | 2017-10-21 04:51:53 – 05:03:52 UTC, 세션 505(Arkime) / 연결 510(Zeek) |
| 내부 대역 | 10.0.1.0/24 (마스크 255.255.255.0), 브로드캐스트 10.0.1.255 |
| 장치 | 2대 — PC 1, 라우터 1 |
| PC | 10.0.1.95 DELOREAN-PC, MAC 60:a4:4c:6a:b2:1f (ASUSTek), 64비트 Windows 10, IE11, MS Office, 작업 그룹 DOC-BROWN-GROUP |
| 라우터 / 게이트웨이 | 10.0.1.1, MAC 00:04:5a:f8:1a:ac (Linksys) |
| DNS 서버 | 10.0.1.1 (UDP 53), 접미사 `localdomain` |
| DHCP 서버 | 10.0.1.254 (라우터와 같은 장비), 임대 30분 |
| DC / 파일 / 웹 / 메일 서버 | 없음 (작업 그룹 환경, Kerberos·LDAP·SMB·메일 포트 없음) |
| 다른 장치 (프린터 등) | 없음 |
| 내부 프로토콜 | DHCP, DNS(UDP), NetBIOS 137/138, LLMNR 5355, ICMP |
| 외부 프로토콜 | HTTP 80, TLS 443, **DNS over TCP 53 (비정상)** |
| 외부 통신 | 외부 IP 87개 — 대부분 Microsoft, Google, 광고. 예외: 35.198.166.240(HTTP 2.35MB), 외부 DNS 서버들(TCP 53) |
| 인바운드 | 없음 |

**베이스라인에서 벗어난 것 (D부에서 확인):**

1. User-Agent가 **없는** HTTP 요청 123개
2. **외부 DNS 서버에 TCP로** 질의 (46번 연결)
3. 평문 HTTP로 큰 다운로드를 한 낯선 IP 35.198.166.240
4. 05:02:30쯤 세션 급증

---

## D부 — 악성 행위 찾기 { #malicious }

베이스라인에서 벗어난 것 네 가지를 하나씩 따라갑니다. 순서는 **가장 이상한 것 → 그 앞뒤**입니다.

### D1단계 — User-Agent 없는 HTTP 요청은 누구인가 { #no-ua }

**목적:** C8단계에서 User-Agent가 없는 요청 123개를 찾았습니다. 브라우저도 윈도우 구성 요소도 대부분 User-Agent를 보내니, 없는 쪽은 **직접 만든 프로그램(악성코드 포함)**일 가능성이 큽니다.

**Arkime:**

```text
protocols == http && http.user-agent != EXISTS!
```

- `http.user-agent` — HTTP 요청의 User-Agent 칸.
- `!= EXISTS!` — 그 칸이 **아예 없는** 세션. (`== EXISTS!`는 "있는" 세션입니다.)

→ **SPIView** → **http** 섹션의 **Host**, 그리고 General의 **Dst IP**.

**Splunk:**

```spl
index=zeek sourcetype=zeek:http NOT user_agent=*
| fillnull value="-" host
| stats count AS requests dc(uid) AS connections values(method) AS method values(version) AS http_ver BY host id_resp_h
| sort - requests
```

- `NOT user_agent=*` — `user_agent=*`는 "그 필드에 무슨 값이든 있다"는 뜻입니다. 앞에 `NOT`을 붙이면 **필드가 없는** 이벤트만 남아요. (TSV Zeek 로그라면 `user_agent="-"`로 찾습니다.)
- `fillnull value="-" host` — Host 헤더도 없는 요청에 `-`를 채워서 결과에서 빠지지 않게 합니다.
- `dc(uid)` — Zeek의 `uid`는 **연결 하나의 고유 번호**입니다. 서로 다른 uid 수 = 연결 수.
- `values(version)` — HTTP 버전.

**결과:**

```text
host                     id_resp_h        requests  connections  method  http_ver
www.msftconnecttest.com  13.107.4.52      73        19           GET     1.1
amellet.bit              35.198.166.240   39        34           POST    1.0
-                        (광고 서버 6곳)    8         8            -       1.0
ocsp.digicert.com        72.21.91.29      2         2            POST    1.0
jgbennett.com            107.180.41.148   1         1            GET     1.1
```

**결과 읽기:**

- **`jgbennett.com` 1개** — 파일 하나를 받은 것 같은 GET. D2단계.
- **`amellet.bit` 39개** — 처음 보는 최상위 도메인 `.bit`에 HTTP/1.0 POST만 39번. D3·D4단계.
- **`www.msftconnecttest.com` 73개** — 윈도우가 "인터넷 연결됐나?" 확인하는 주소입니다. 하지만 윈도우의 진짜 확인(NCSI)은 보통 User-Agent `Microsoft NCSI`를 붙이고, 이렇게 몇 초에 수십 번 묻지 않습니다. D6단계.
- **`-` 8개** — Host도 메서드도 없는 줄입니다. 열어 보면 광고 서버들이 **놀고 있는 연결을 끊으면서 보낸 `408 Request Timeout` 응답**뿐이에요. 요청이 없으니 User-Agent도 없는 것 → **정상 잡음**.
- **`ocsp.digicert.com` 2개** — 인증서 폐기 확인(OCSP)을 POST로 한 것. 윈도우가 하는 **정상** 동작입니다.

### D2단계 — 첫 악성 이벤트: User-Agent 없는 `.exe` 다운로드 { #exe-download }

**목적:** `jgbennett.com`에서 무엇을, 언제, 어떻게 받았는지 확인하고 파일 해시를 남깁니다.

**Arkime:**

```text
host.http == jgbennett.com
```

- `host.http` — HTTP 요청의 Host 헤더 값.

→ **Sessions** → 세션의 **+** → 세션 상세. 패킷 영역은 **natural**(사람이 읽는 글자)로 봅니다.

**결과 (세션 상세):**

```text
2017/10/21 04:52:47 UTC  10.0.1.95:49691 -> 107.180.41.148:80

GET /3cgconsulting.com/30_723bio_152.exe HTTP/1.1
Host: jgbennett.com
Connection: Keep-Alive

HTTP/1.1 200 OK
Date: Sat, 21 Oct 2017 04:52:49 GMT
Server: Apache
Last-Modified: Thu, 19 Oct 2017 12:45:16 GMT
Content-Length: 61440
Content-Type: application/x-msdownload

MZ......................@...............!..L.!This program cannot be run in DOS mode.
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:http host="jgbennett.com"
| eval t=strftime(ts, "%Y-%m-%d %H:%M:%S")
| table t uid id_orig_h id_orig_p id_resp_h id_resp_p method host uri user_agent status_code resp_mime_types response_body_len resp_fuids
```

- `resp_fuids` — 응답으로 받은 **파일의 ID**. 이 ID로 files.log와 연결합니다.

```spl
index=zeek sourcetype=zeek:files mime_type="application/x-dosexec"
| eval t=strftime(ts, "%H:%M:%S")
| table t fuid tx_hosts rx_hosts source mime_type seen_bytes total_bytes md5 sha1
```

- `mime_type="application/x-dosexec"` — Zeek가 **내용의 첫 바이트**로 판단한 파일 종류. `x-dosexec`는 윈도우 실행 파일(EXE/DLL)입니다. 확장자를 바꿔도 속지 않아요.
- `tx_hosts` / `rx_hosts` — 파일을 **보낸** 쪽 / **받은** 쪽.
- `seen_bytes` / `total_bytes` — 실제로 본 바이트 / 원래 크기. 같으면 **파일 전체를 캡처**했다는 뜻이고, 그래야 해시를 믿을 수 있습니다.

```spl
index=zeek sourcetype=zeek:pe
| eval compiled=strftime(compile_ts, "%Y-%m-%d %H:%M:%S")
| table id machine compiled os subsystem is_64bit uses_aslr uses_dep has_cert_table section_names
```

- zeek:pe — 윈도우 실행 파일의 머리 부분을 읽은 결과입니다.
- `compile_ts` — 실행 파일 안에 적힌 **컴파일 시각**(조작 가능하지만 참고가 됨).
- `has_cert_table` — **디지털 서명**이 있는지.

**결과:**

```text
t                    id_orig_h  id_orig_p  id_resp_h       method  host           uri                                    user_agent  status_code  resp_mime_types        response_body_len
2017-10-21 04:52:47  10.0.1.95  49691      107.180.41.148  GET     jgbennett.com  /3cgconsulting.com/30_723bio_152.exe   (없음)      200          application/x-dosexec  61440

t         tx_hosts        rx_hosts   mime_type              seen_bytes  total_bytes  md5                               sha1
04:52:47  107.180.41.148  10.0.1.95  application/x-dosexec  61440       61440        658c30fcd1508a65df8b9b9b397a9459  fe4116d0e66350f54042361e3a87c942ee98529d

machine  compiled             os          subsystem    is_64bit  uses_aslr  uses_dep  has_cert_table  section_names
I386     2017-07-16 07:29:21  Windows XP  WINDOWS_GUI  false     false      true      false           .text .data
```

**SHA256 구하기.** Zeek는 기본으로 MD5와 SHA1만 계산합니다. 팀 보고와 위협 정보 공유는 보통 SHA256을 쓰니, 파일을 꺼내서 직접 계산합니다. Arkime 세션 상세에서 파일을 내려받거나, 분석 VM에서 tshark로 HTTP 파일을 모두 꺼냅니다.

```bash
mkdir -p http_objects
tshark -r 2017-10-21-traffic-analysis-exercise.pcap --export-objects http,http_objects
sha256sum http_objects/30_723bio_152.exe
file http_objects/30_723bio_152.exe
```

- `--export-objects http,폴더` — HTTP로 오간 파일을 모두 그 폴더에 저장합니다. **절대 실행하지 마세요.**
- `file 파일` — 내용으로 파일 종류를 알려 줍니다.

```text
a56876fd456d0737eecc4a8bbe3154b35314ab28accb29abf0df7c518c81a490  http_objects/30_723bio_152.exe
http_objects/30_723bio_152.exe: PE32 executable (GUI) Intel 80386, for MS Windows, 2 sections
```

**결과 읽기:**

- **User-Agent가 없습니다.** 요청 헤더가 `Host`와 `Connection` 두 줄뿐이에요. 사람이 브라우저로 받았다면 IE11의 User-Agent가 붙었을 겁니다. **브라우저가 아닌 프로그램**(스크립트, 매크로, 다른 악성코드)이 받은 것입니다.
- **Referer도 없습니다.** 어떤 웹페이지의 링크를 눌러서 받은 게 아니라 **주소를 직접 알고** 받았다는 뜻이에요.
- 경로가 `/3cgconsulting.com/…`처럼 **다른 도메인 이름을 폴더로 쓰고** 있습니다. 해킹된 웹 서버에 악성 파일을 올려 둘 때 흔한 모양입니다.
- 파일은 **완전히 캡처**됐고(`seen_bytes = total_bytes = 61440`), 첫 바이트가 `MZ` = 윈도우 실행 파일입니다. `Content-Type: application/x-msdownload`도 실행 파일 형식이에요.
- **32비트 GUI 프로그램, 서명 없음, 섹션 두 개(`.text`, `.data`)뿐.** 정상 프로그램은 보통 섹션이 더 많고 서명이 있습니다. 섹션이 적고 작은(60KB) 파일은 **진짜 악성코드를 감싸 숨긴 포장(packer)**일 때가 많아요.
- 서버의 `Last-Modified`가 **2017-10-19**(이틀 전) — 최근에 올린 파일입니다.

**바로 직전에 무슨 일이 있었나?** 다운로드 30초 전부터의 DNS 질의를 봅니다.

```spl
index=zeek sourcetype=zeek:dns qtype_name=A ts>=1508561520 ts<=1508561570
| eval t=strftime(ts, "%H:%M:%S")
| table t query answers
| sort t
```

- `ts>=1508561520 ts<=1508561570` — epoch 초로 시간 범위를 정합니다. 1508561520 = 04:52:00, 1508561570 = 04:52:50 (UTC). 시간대 설정과 상관없이 같은 순간이라 정확해요.

**결과:**

```text
t         query                          answers
04:52:01  www.bing.com                   13.107.21.200 204.79.197.200
04:52:02  tile-service.weather...        23.79.207.65
04:52:40  contentstorage.osi.office.net  23.79.196.182
04:52:42  fs.microsoft.com               23.79.211.200
04:52:42  messaging.office.com           104.43.139.11
04:52:46  nexus.officeapps.live.com      104.43.140.223
04:52:46  officeclient.microsoft.com     137.116.74.190
04:52:47  jgbennett.com                  107.180.41.148    ← 1초 뒤 .exe 다운로드
04:52:52  nexus.officeapps.live.com      104.43.140.223
04:52:52  nexusrules.officeapps.live.com 40.117.144.240
```

**결과 읽기:** 04:52:40부터 **Microsoft Office**가 켜지면서 하는 질의(`officeclient`, `nexus.officeapps`, `messaging.office`)가 나오고, **1초 뒤에** `jgbennett.com`을 묻고 `.exe`를 받았습니다. Office 문서를 열었더니 **문서 안의 매크로나 스크립트가 파일을 받은** 흔한 감염 방식과 같은 모양이에요. 다만 문서 자체는 캡처에 없습니다(메일, 웹메일, 파일 다운로드 흔적 없음). 그래서 **"추정"**이고, 호스트 오퍼레이터가 확인할 단서가 됩니다.

### D3단계 — `.bit` 도메인과 외부 DNS 서버, 그리고 TCP DNS { #bit-dns }

**목적:** C6·C9단계의 "외부 DNS 서버에 TCP로 질의"가 무엇을 물었는지 봅니다.

**Arkime:**

```text
port.dst == 53 && ip.protocol == tcp
```

- `port.dst == 53` — 목적지 포트 53(DNS).
- `ip.protocol == tcp` — TCP만. DNS는 보통 UDP라서 TCP만 따로 봅니다.

→ **SPIView** → General의 **Dst IP**, **dns** 섹션의 **Host**.

```text
host.dns == *.bit
```

- `host.dns` — DNS로 물어본 이름. `*`는 "아무 글자나" — `.bit`로 끝나는 모든 이름.

**Splunk — 무엇을 물었나:**

```spl
index=zeek sourcetype=zeek:dns query="*.bit"
| eval t=strftime(ts, "%H:%M:%S")
| table t id_orig_h id_resp_h proto query qtype_name rcode_name answers TTLs
| sort t
```

**결과 (37줄 중 앞부분):**

```text
t         id_resp_h        proto  query        rcode_name  answers         TTLs
04:53:52  130.255.78.223   tcp    amellet.bit  NOERROR     (없음)
04:54:03  188.165.200.156  tcp    amellet.bit  NOERROR     35.198.166.240  400
04:54:44  144.76.133.38    tcp    amellet.bit  NOERROR     35.198.166.240  133
04:54:46  62.113.203.99    tcp    amellet.bit  NOERROR     (없음)
04:54:47  93.170.96.235    tcp    amellet.bit  NOERROR     (없음)
04:54:58  31.3.135.232     tcp    amellet.bit  NOERROR     35.198.166.240  343
04:55:00  188.165.200.156  tcp    amellet.bit  NOERROR     35.198.166.240  342
...       (04:56:11까지 2~3초마다, 대부분 188.165.200.156)
05:00:52  188.165.200.156  tcp    amellet.bit  NOERROR     35.198.166.240
05:02:05  188.165.200.156  tcp    amellet.bit  NOERROR     35.198.166.240
```

**Splunk — 어느 DNS 서버에 연결했고, 성공했나:**

```spl
index=zeek sourcetype=zeek:conn proto=tcp id_resp_p=53
| stats count min(ts) AS first BY id_resp_h conn_state
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `conn_state` — Zeek의 연결 상태. `SF` = 정상으로 열고 닫음, `S0` = SYN을 보냈는데 **응답 없음**, `REJ` = **거절**(RST), `RSTRH` = 응답 쪽이 RST로 끊음.

**결과:**

```text
id_resp_h        conn_state  count  first
130.255.78.223   SF          1      04:53:52
130.255.73.90    S0          2      04:53:53
188.165.200.156  SF          31     04:54:03
144.76.133.38    SF          2      04:54:44
62.113.203.99    SF          1      04:54:46
93.170.96.235    SF          1      04:54:46
85.159.213.210   S0          2      04:54:47
37.187.16.17     REJ         3      04:54:57
31.3.135.232     SF          1      04:54:58
130.255.73.90    RSTRH       1      04:55:08
85.159.213.210   RSTRH       1      04:56:03
```

**결과 읽기:**

- 물어본 이름은 **`amellet.bit` 하나뿐**입니다(37번).
- **`.bit`는 일반 인터넷의 최상위 도메인이 아닙니다.** **Namecoin**이라는 블록체인에 등록하는 이름이라서, 보통 DNS 서버(공유기, 통신사, 구글 DNS)는 답을 못 합니다. 그래서 악성코드가 `.bit`를 아는 **특정 DNS 서버 목록을 직접 들고 다니며** 차례로 묻는 거예요. 실제로 **9곳**에 시도했고, 3곳은 답이 비었고(NOERROR인데 answers 없음), 3곳은 연결도 안 됐고, 3곳이 `35.198.166.240`을 알려 줬습니다.
- **왜 악성코드가 `.bit`를 쓸까?** 일반 도메인은 등록 회사나 당국이 빼앗거나 막을 수 있지만, Namecoin 이름은 그러기 어렵습니다. 공격자가 **C2 주소를 잃지 않으려는** 방법이에요.
- **왜 TCP일까?** 이 악성코드는 그렇게 만들어졌다고 볼 수밖에 없습니다. 결과적으로 공유기의 DNS(10.0.1.1)를 **완전히 우회**했고, 회사 DNS 서버만 감시하는 곳에서는 **이 질의가 아예 안 보입니다.** 그래서 "내부 PC → 외부 TCP 53"은 좋은 탐지 포인트예요(E부 sid 1000204).
- 답은 항상 `35.198.166.240` 하나였습니다. TTL(답을 기억해 둬도 되는 시간)은 처음 400초였고, 그 뒤로는 서버마다 캐시에 남은 시간이라 133, 343, 342…처럼 제각각입니다. 응답에는 `amellet.bit`의 네임서버(`a.dnspod.com` 등) 정보도 함께 있었습니다.
- **매번 새로 묻습니다.** C2 연결(D4) 직전마다 DNS를 다시 물어서, 37번의 질의와 34번의 C2 연결 시각이 거의 겹칩니다.

### D4단계 — C2 통신: `amellet.bit` HTTP POST { #c2 }

**목적:** 35.198.166.240과 무엇을 주고받았는지 봅니다.

**Arkime:**

```text
host.http == amellet.bit
```

→ **Sessions**: **34개**. 아무 세션의 **+** → natural 보기.

**결과 (첫 세션 04:54:03, 10.0.1.95:57622 → 35.198.166.240:80):**

```text
POST /a/ HTTP/1.0
Host: amellet.bit
Content-Length: 1584

`Z8;..QK.:...=.S....*...2n..&......i'..D,h.#..T-L...X....{..kWf9A.r...   (알아볼 수 없는 바이트 1,584개)

HTTP/1.0 200 OK
X-Powered-By: PHP/5.3.3
Content-type: text/html
Content-Length: 158064
Date: Sat, 21 Oct 2017 04:47:14 GMT
Server: lighttpd/1.4.45

.5W..l1..j....t....qy..b..OJT.W.......N...E.c...N....6j.wE+.c)...   (알아볼 수 없는 바이트)
```

**Splunk — 요청 하나하나:**

```spl
index=zeek sourcetype=zeek:http host="amellet.bit"
| sort ts
| streamstats current=f last(ts) AS prev_ts
| eval t=strftime(ts, "%H:%M:%S"), gap=round(ts-prev_ts, 1)
| table t id_orig_p method uri version status_code request_body_len response_body_len gap
```

- `sort ts` — 시간 순서로 정렬합니다. `streamstats`는 **위에서 아래 순서대로** 계산하기 때문에 정렬이 먼저예요.
- `streamstats current=f last(ts) AS prev_ts` — 각 줄에 **바로 앞 줄의 `ts`**를 붙입니다. `current=f`는 "지금 줄은 빼고 계산"이라는 뜻이에요.
- `gap=round(ts-prev_ts, 1)` — 앞 요청과의 **간격(초)**, 소수점 1자리. 비콘(일정한 간격의 신호)을 찾을 때 쓰는 기본 방법입니다.
- `request_body_len` / `response_body_len` — 보낸 / 받은 **본문** 크기(헤더 제외).

**결과 (39줄):**

```text
t         id_orig_p  uri     ver  status  req_len  resp_len  gap
04:54:03  57622      /a/     1.0  200     1584     157261
04:54:44  61982      /a/     1.0  200     1584     132464    41.1
04:54:59  55225      /html/  1.0  200     240      153808    14.6
04:55:01  63017      /html/  1.0  200     240      116737    1.8
04:55:03  54665      /html/  1.0  200     368      1168      2.9
04:55:06  53280      /html/  1.0  200     400      4752      2.7
04:55:08  53132      /html/  1.0  200     400      17248     1.4
04:55:09  60208      /html/  1.0  200     400      256752    1.6
04:55:12  53918      /html/  1.0  200     400      43840     2.5
04:55:14  63963      /html/  1.0  200     400      250688    2.3
04:55:17  51539      /html/  1.0  200     400      17552     2.6
04:55:18  58180      /html/  1.0  200     400      225872    1.7
04:55:33  54278      /html/  1.0  200     384      448       14.5
04:55:35  59593      /html/  1.0  200     400      4592      1.8
04:55:37  64718      /html/  1.0  200     432      1168      2.2
04:55:39  58093      /html/  1.0  200     432      250688    2.2
04:55:42  49338      /html/  1.0  200     432      43840     2.8
04:55:44  59990      /html/  1.0  200     432      4752      2.3
04:55:46  54150      /a/     1.0  200     1680     80        1.7
04:55:46  54149      /html/  1.0  200     432      256752    0.2
04:55:49  56621      /html/  1.0  200     432      225872    2.6
04:55:51  58354      /html/  1.0  200     432      17248     2.5
04:55:53  53211      /html/  1.0  200     224      80        1.6
...       (04:56:11까지 80바이트 응답이 이어짐, 연결 5개에서 POST가 2번씩)
05:00:52  49513      /html/  1.0  200     432      76752     281.4
05:02:05  61115      /html/  1.0  200     432      77248     72.5
```

**합계:**

```spl
index=zeek sourcetype=zeek:http host="amellet.bit"
| stats count AS posts dc(uid) AS connections sum(request_body_len) AS sent sum(response_body_len) AS received min(ts) AS first max(ts) AS last BY uri
| eval first=strftime(first, "%H:%M:%S"), last=strftime(last, "%H:%M:%S")
```

```text
uri     posts  connections  sent    received   first     last
/a/     3      3            4,848   289,805    04:54:03  04:55:46
/html/  36     31           18,144  2,053,089  04:54:59  05:02:05
```

**Zeek weird.log:**

```spl
index=zeek sourcetype=zeek:weird
| stats count BY name id_resp_h
```

```text
name                               id_resp_h       count
unexpected_multiple_HTTP_requests  35.198.166.240  5
inflate_failed                     (광고·CDN 서버)  5
possible_split_routing             23.56.3.183     1
```

**결과 읽기:**

- **방향:** 항상 **PC → 서버**로 먼저 연결했습니다(아웃바운드). C2에서 흔한 모양이에요. 방화벽은 보통 밖으로 나가는 연결을 막지 않으니까요.
- **HTTP/1.0, User-Agent 없음, Content-Type 없음.** 2017년 윈도우 10의 정상 프로그램은 거의 HTTP/1.1을 쓰고 User-Agent를 붙입니다. 최소한의 헤더만 직접 만들어 보내는 **악성코드의 모양**이에요.
- **보내는 것도 받는 것도 암호화.** 요청 본문과 응답 본문 모두 의미 있는 글자가 없습니다. 응답은 `Content-type: text/html`이라고 하지만 실제로는 HTML이 아닙니다(Zeek의 `resp_mime_types`가 비어 있음 = 아는 형식이 아님).
- **`/a/`와 `/html/` 두 경로.** `/a/`(1,584바이트를 보내고 13~15만 바이트를 받음)는 **체크인과 설정 받기**, `/html/`은 **모듈이나 추가 데이터 받기**로 보입니다. `/html/` 응답 크기가 **256,752 / 250,688 / 225,872 / 43,840 / 17,248 / 4,752 바이트가 두 번씩** 나옵니다. 같은 모듈 묶음을 **두 번 받은** 거예요.
- **받은 양 약 2.34MB, 보낸 양 약 23KB.** 받은 것이 훨씬 많습니다 → 주된 활동은 **추가 기능(모듈) 다운로드**입니다. 보낸 23KB에도 PC 정보나 훔친 정보가 들어 있을 수 있지만, 암호화돼서 **내용은 확인할 수 없습니다.**
- **`unexpected_multiple_HTTP_requests` 5개** — HTTP/1.0은 원래 연결 하나에 요청 하나입니다. 그런데 연결 5개에서 POST를 두 번 보냈어요. 규칙을 대충 지키는 직접 만든 HTTP 코드라는 또 다른 증거입니다. (나머지 weird는 광고 서버의 압축 오류 등 사건과 무관한 잡음입니다.)
- **서버 시계가 약 6분 49초 느립니다.** 패킷 시각은 04:54:03인데 서버의 `Date`는 04:47:14예요. 같은 C2 서버를 다른 사건에서 찾을 때 작은 지문이 됩니다.
- 서버 `lighttpd/1.4.45` + `X-Powered-By: PHP/5.3.3` — PHP 5.3.3은 2010년 버전입니다. 오래된 PHP로 C2 패널을 돌리는 흔한 모습이에요.

**악성코드 계열:** 외부 DNS로 `.bit` C2 주소를 찾고, 암호화된 POST로 모듈을 받는 모양은 **Zeus 계열 은행 트로이목마인 Chthonic**과 같습니다. 이 실습의 공개 분석도 Chthonic으로 봤습니다. 다만 우리는 폐쇄망이라 해시 조회를 하지 않았으므로 **"consistent with Chthonic — unconfirmed"**로 적습니다.

### D5단계 — C2 타이밍: 비콘인가 { #c2-timing }

**목적:** C2가 일정한 간격으로 연락하는지(비콘) 봅니다. 간격을 알면 앞으로 같은 PC를 감시할 때 무엇을 기대할지 알 수 있어요.

D4단계의 `gap` 칸을 다시 보면:

```text
04:54:03 – 04:54:44   /a/ 체크인 두 번 (41초 간격)
04:54:59 – 04:56:11   /html/ 34번, 0.2~4초 간격 (모듈 몰아서 받기)
04:56:11 – 05:00:52   4분 41초 조용함
05:00:52, 05:02:05    /html/ 두 번 (73초 간격)
```

**결과 읽기:** 12분짜리 캡처 안에서는 **일정한 비콘 간격이 보이지 않습니다.** 감염 직후 **설정과 모듈을 몰아서 받는 단계**가 대부분이고, 그 뒤 05:00:52와 05:02:05 두 번만 연락했어요. 비콘 간격을 정하려면 더 긴 캡처가 필요합니다. 보고서에는 "no stable beacon interval within 12-min capture"로 적습니다.

### D6단계 — User-Agent 없는 연결 확인(`msftconnecttest`) 폭주 { #connecttest }

**목적:** D1단계의 `www.msftconnecttest.com` 73번을 확인합니다.

**Arkime:**

```text
host.http == www.msftconnecttest.com
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:http host="www.msftconnecttest.com"
| eval minute=strftime(ts, "%H:%M")
| stats count BY minute user_agent
```

- `eval minute=strftime(ts, "%H:%M")` — 초를 버리고 **분 단위**로 묶을 칸을 만듭니다.

**결과:**

```text
minute  user_agent  count
04:55   (없음)      6
04:56   (없음)      1
05:00   (없음)      18
05:01   (없음)      42
05:02   (없음)      6
```

세션 상세의 요청은 이렇게 생겼습니다.

```text
GET /connecttest.txt HTTP/1.1
Connection: Keep-Alive
Host: www.msftconnecttest.com
```

**결과 읽기:**

- 윈도우 10의 진짜 연결 확인(NCSI)은 보통 `User-Agent: Microsoft NCSI`를 붙이고, 네트워크가 바뀔 때 한두 번 합니다. 여기는 User-Agent가 없고 **1분에 42번**까지 몰립니다.
- 시각이 **C2 활동과 겹칩니다**: 04:55(모듈 받기 중), 05:00:51~05:02(05:00:52, 05:02:05 C2 POST 앞뒤).
- 헤더 모양(`Connection`, `Host` 두 줄)도 D2단계 `.exe` 다운로드 요청과 비슷합니다.
- 그래서 **악성코드가 C2에 연락하기 전에 인터넷이 되는지 확인한 것**으로 보입니다. 정상 Microsoft 주소를 쓰기 때문에 이것만으로는 악성이라고 할 수 없어 **추정**으로 두고, 호스트 오퍼레이터에게 **어느 프로세스가 연결했는지** 확인을 부탁합니다.

### D7단계 — 05:02:30 급증과 기술지원 사기 팝업 { #tech-support-scam }

**목적:** C1단계 그래프의 05:02:30 급증과, D1에서 남은 마지막 수상한 도메인을 봅니다.

**Arkime:**

```text
ip.src == 10.0.1.95 && host.http == [www.singlemoms.org, helpcenterforall.bid, krep2010123.tk]
```

- `== [a, b, c]` — 목록 중 하나와 같으면. `||`를 여러 번 쓰는 것보다 짧습니다.

**Splunk:**

```spl
index=zeek sourcetype=zeek:http host IN ("www.singlemoms.org", "helpcenterforall.bid", "krep2010123.tk")
| eval t=strftime(ts, "%H:%M:%S")
| table t id_orig_p id_resp_h method host uri referrer status_code resp_mime_types response_body_len
| sort t
```

- `referrer` — 브라우저가 "어느 페이지에서 왔는지" 알려 주는 Referer 헤더. 웹 사슬을 다시 세울 때 가장 중요한 칸입니다.

**결과:**

```text
t         id_resp_h       method  host                  uri                         referrer                                 status  mime             len
05:02:26  104.18.61.210   GET     www.singlemoms.org    /                           -                                        200     text/html        71878
05:02:28  104.18.61.210   GET     www.singlemoms.org    /states.swf                 http://www.singlemoms.org/               200     x-shockwave-flash 31838
05:02:30  104.18.61.210   GET     www.singlemoms.org    /states.xml                 http://www.singlemoms.org/states.swf     200     text/plain       6137
...
05:03:25  162.244.35.33   GET     helpcenterforall.bid  /index/?MCPKV8              -                                        302     -                0
05:03:25  162.244.35.36   GET     krep2010123.tk        /?number=888-779-0939       -                                        200     text/html        4374
05:03:26  162.244.35.36   GET     krep2010123.tk        /landinf/defender.png       http://krep2010123.tk/?number=888-...    200     image/png        13386
05:03:26  162.244.35.36   GET     krep2010123.tk        /files/css                  http://krep2010123.tk/?number=888-...    200     text/plain       18
05:03:31  162.244.35.36   GET     krep2010123.tk        /favicon.ico                -                                        404     text/html        169
05:03:31  162.244.35.36   GET     krep2010123.tk        /landinf/err.mp3            http://krep2010123.tk/?number=888-...    206     audio/mpeg       251342
```

**`helpcenterforall.bid`로 간 이유를 찾기.** Referer가 비어 있어서 Zeek만으로는 어디서 왔는지 모릅니다. 바로 앞에 열린 페이지 `www.singlemoms.org/`의 **내용**을 봐야 해요. Arkime에서 `host.http == www.singlemoms.org && http.uri == /` 세션을 열고(natural), 브라우저의 찾기(Ctrl+F)로 `helpcenter`를 찾습니다. 이 응답은 압축(gzip)되지 않고 조각(chunk)으로만 나뉘어 와서, 중간중간 조각 크기 숫자가 끼어 있을 뿐 그대로 읽힙니다.

**결과 (페이지 끝에 붙어 있던 스크립트, 줄바꿈과 설명 추가):**

```javascript
function checkTarget(a){
  if(!getCookie("popundr")){                               // "popundr" 쿠키가 없으면 (처음 한 번만)
    doOpen("http://helpcenterforall.bid/index/?MCPKV8");   // 새 창을 열어 이 주소로 보냄
    setCookie("popundr",1,864e5)                           // 쿠키를 24시간(86,400,000ms) 동안 남김
  }
}
...
document.addEventListener("click", checkTarget, !1)       // 페이지 아무 곳이나 클릭하면 checkTarget 실행
PopWin.blur(); _Top.window.focus()                         // 새 창을 지금 창 "뒤로" 숨김 (팝언더)
```

**`krep2010123.tk` 페이지의 글자 (HTML 태그 제거):**

```text
Security Warning
Windows Defender Alert : Zeus Virus Detected In Your Computer !!
Please Do Not Shut Down or Reset Your Computer.
The following data will be compromised if you continue: 1. Passwords 2. Browser History
3. Credit Card Information 4.Local Hard Disk Files.
...
Call Microsoft Technical Department: 888-779-0939 (Toll Free)
```

**결과 읽기:**

- **05:02:30 급증의 정체:** 사용자가 IE11로 `www.singlemoms.org`를 열었습니다. 이 페이지가 **광고·분석 도메인 수십 곳**(media.net, doubleclick, openx, addthis, statcounter …)을 한꺼번에 불러서 세션이 몰렸어요. 이것 자체는 평범한 광고 많은 사이트의 모습입니다.
- **그런데 페이지 끝에 "팝언더(pop-under)" 스크립트가 숨어 있었습니다.** 사용자가 페이지 **어디든 처음 클릭하면** 새 창을 열어 `helpcenterforall.bid`로 보내고, 그 창을 **뒤로 숨깁니다**. 그래서 Referer가 비어 있었어요(빈 창 `about:blank`에서 주소를 바꿨기 때문).
- 05:03:25 사용자가 클릭 → `helpcenterforall.bid`가 **302**로 `krep2010123.tk/?number=888-779-0939`로 보냄 → **가짜 Windows Defender 경고** 페이지, 방패 그림(`defender.png`), **경고음**(`err.mp3`, 251KB), 그리고 **"Microsoft에 전화하세요 888-779-0939"**.
- 이게 **기술지원 사기(tech support scam)**입니다. 전화하면 가짜 상담원이 원격 접속 프로그램을 깔게 하고 돈을 받거나 정보를 훔칩니다. **악성코드 감염은 아니지만**, 사용자가 전화했거나 원격 접속을 허용했다면 **두 번째 사건**이 됩니다. 호스트 오퍼레이터와 사용자에게 꼭 확인할 일이에요.
- 재미있는 우연: 가짜 경고는 "**Zeus** Virus Detected"라고 하는데, 이 PC에는 실제로 **Zeus 계열(Chthonic 유형)** 악성코드가 돌고 있었습니다. 사기 페이지의 고정 문구일 뿐 진짜 탐지와는 관계없어요.
- **두 사건은 별개입니다.** `.exe` → C2(04:52~05:02)와 웹사이트 팝언더 → 사기 페이지(05:02~05:03)는 서로 연결된 흔적이 없습니다. 한 보고서에 둘 다 적되, 별개라는 것을 분명히 합니다.

### D8단계 — 범위 확인: 다른 PC, 측면 이동, 유출 { #scope }

**목적:** 다른 PC도 당했는지, 내부로 퍼졌는지(측면 이동), 정보가 나갔는지(유출) 확인합니다.

```spl
index=zeek sourcetype=zeek:conn (id_resp_h IN (107.180.41.148, 35.198.166.240, 162.244.35.33, 162.244.35.36) OR (proto=tcp id_resp_p=53))
| stats count BY id_orig_h
```

- 악성 IP와 TCP DNS에 연결한 **내부 출발지**를 모두 셉니다.

**결과:** `10.0.1.95` 한 줄뿐(캡처 안에 다른 PC가 없음).

```spl
index=zeek sourcetype=zeek:conn id_orig_h=10.0.1.95 (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16) NOT id_resp_h IN (10.0.1.1, 10.0.1.254, 10.0.1.255)
```

- PC가 라우터·DHCP·브로드캐스트를 **뺀** 내부 IP에 연결했는지.

**결과:** `No results found.`

**결과 읽기:**

- **다른 감염 PC: 없음** — 캡처에 PC가 한 대뿐입니다.
- **측면 이동: 없음** — PC가 다른 내부 장치에 연결한 적이 없습니다(SMB, RDP, WinRM 없음).
- **유출:** C2로 보낸 **본문 합계 22,992바이트**(약 23KB, 39번 POST). 암호화돼서 **무엇이 나갔는지는 알 수 없습니다.** Zeus 계열은 PC 정보, 저장된 비밀번호, 은행 사이트 입력값을 보내곤 하니 **"가능성 있음, 내용 미확인"**으로 적습니다. 큰 파일을 올린 흔적(수 MB POST)은 없습니다.

---

## E부 — Snort 룰 만들고 테스트하기 { #snort }

### E0단계 — 준비 { #snort-prep }

```bash
snort -V
grep -n "ipvar HOME_NET" /etc/snort/snort.conf
grep -n "ipvar EXTERNAL_NET" /etc/snort/snort.conf
grep -n "local.rules" /etc/snort/snort.conf
```

- `snort -V` — 버전. **2.9.x**면 아래 룰을 그대로 씁니다. Snort 3은 HTTP 부분 문법이 다릅니다([E5단계](#snort3)).
- `grep -n "글자" 파일` — 그 글자가 있는 줄을 줄 번호와 함께 보여 줍니다.
- **`ipvar HOME_NET`** — Snort가 "내부"로 보는 범위. 예를 들어 `10.0.0.0/24`면 우리 PC `10.0.1.95`는 "내부"가 아니라서 `$HOME_NET`을 쓰는 룰이 **하나도 안 울립니다.** 테스트할 땐 `10.0.0.0/8`이나 `any`로 바꾸세요.
- **`ipvar EXTERNAL_NET`** — "외부". 보통 `any` 또는 `!$HOME_NET`(내부가 아닌 모든 것). 아래 룰은 둘 다에서 테스트했습니다.
- **`include $RULE_PATH/local.rules`** — 앞에 `#`가 있으면 안 됩니다.
- 예전 **테스트 룰 sid 1000100**(모든 TCP에 울리는 "test" 룰)이 있으면 `#`로 꺼 두세요. 결과를 묻어 버립니다.

### E1단계 — 룰의 구조 다시 보기 { #rule-anatomy }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"..."; ...옵션...; sid:1000201; rev:1;)
└─┬─┘ └┬┘ └───┬───┘ └┬┘ └┬┘ └─────┬─────┘ └────┬────┘ └──────────────────┬──────────────────┘
 동작 프로토콜 출발IP  출발포트 방향  도착IP       도착포트                   옵션(괄호 안)
```

**헤더**(괄호 앞)는 *어떤 패킷을 볼지*, **옵션**(괄호 안)은 *안에서 무엇을 찾을지*입니다. 옵션은 `;`로 끝나고, **룰 하나는 반드시 한 줄**이어야 합니다.

| 옵션 | 뜻 |
|---|---|
| `msg:"…"` | 알림 제목 |
| `flow:established,to_server` | 연결이 맺어진 뒤 **서버 쪽으로** 가는 데이터만 (`to_client` = 반대) |
| `flags:S` | TCP **SYN**(연결 시작 패킷)만 |
| `content:"글자"` | 이 글자가 있어야 함. `\|3a\|` = 16진수 바이트(`3a` = `:`, `22` = `"`, `0d 0a` = 줄바꿈) |
| `content:!"글자"` | 이 글자가 **없어야** 함 |
| `nocase` | 대소문자 무시 |
| `depth:6` | 맨 앞 6바이트 안에서만 |
| `distance:0; within:20` | 앞의 일치 **바로 뒤부터 20바이트 안에서** |
| `http_method` / `http_uri` / `http_header` | 앞의 `content`를 HTTP의 어디서 찾을지(메서드 / URI / 헤더) |
| `file_data` | **HTTP 응답 본문**(압축·chunk를 푼 내용)에서 찾기 시작 |
| `pcre:"/정규식/옵션"` | 정규식. `U` = URI, `H` = 헤더, `i` = 대소문자 무시, `m` = 여러 줄 |
| `flowbits:set,이름` / `isset,이름` / `noalert` | 연결에 표시를 남기기 / 표시가 있는지 확인 / 이 룰 자체는 알림 안 함 |
| `threshold:type limit, track by_src, count 1, seconds 600` | 같은 출발지에 대해 **600초에 1번만** 알림 |
| `classtype` | 알림 분류(우선순위가 정해짐) |
| `sid` / `rev` | 룰 번호 / 수정 번호. 직접 만든 룰은 **1,000,000 이상** |

룰은 두 종류입니다.

- **IOC 룰** — 이번 사례의 정확한 도메인/IP/파일 이름. 정확하지만 공격자가 바꾸면 못 잡습니다.
- **행동 룰** — 공격의 **모양**. 도메인/IP가 바뀌어도 잡히지만, 오탐 위험이 조금 있습니다.

### E2단계 — 룰 하나씩 { #snort-rules }

#### A. DNS — `.bit`와 외부 TCP DNS (sid 1000201–1000204) { #rules-dns }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"LOCAL C2 DNS query amellet.bit over TCP"; flow:established,to_server; content:"|07|amellet|03|bit|00|"; nocase; classtype:trojan-activity; sid:1000201; rev:1;)
alert tcp $HOME_NET any -> any 53 (msg:"LOCAL DNS query for .bit (Namecoin) domain over TCP"; flow:established,to_server; content:"|03|bit|00|"; nocase; classtype:policy-violation; sid:1000202; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL DNS query for .bit (Namecoin) domain over UDP"; content:"|03|bit|00|"; nocase; classtype:policy-violation; sid:1000203; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"LOCAL Internal host DNS over TCP to external resolver"; flags:S; threshold:type limit, track by_src, count 1, seconds 600; classtype:policy-violation; sid:1000204; rev:1;)
```

- **DNS는 점 대신 "글자 수 + 글자"**로 이름을 적습니다. `amellet.bit` → `|07|amellet|03|bit|00|` = 7글자 `amellet`, 3글자 `bit`, 끝(`00`). 패킷 안에 `amellet.bit`라는 글자는 없어서, 점을 넣은 `content:"amellet.bit"`는 **절대 안 맞습니다.**
- **TCP DNS도 같은 형식**입니다. TCP DNS는 앞에 길이 2바이트가 더 붙을 뿐이라, 위치를 지정하지 않은 `content`는 그대로 맞아요.
- **sid 1000201 (IOC)** — `amellet.bit`를 묻는 TCP DNS. `flow:established,to_server` = 연결이 맺어진 뒤 PC가 DNS 서버로 보낸 질문.
- **sid 1000202/1000203 (행동)** — **어떤 `.bit` 이름이든.** 이름 끝이 `|03|bit|00|`이면 `.bit`입니다. 회사 PC가 `.bit`를 물을 이유는 거의 없어서 오탐이 적고, 공격자가 `.bit` 이름을 바꿔도 잡힙니다. TCP와 UDP 두 개를 만든 이유: 이번엔 TCP였지만 다른 변종은 UDP를 쓸 수 있으니까요. UDP 룰은 `flow`를 쓰지 않습니다(UDP는 "연결"이 없음).
- **sid 1000204 (행동)** — 내부 PC가 **외부**의 53번 포트로 **TCP 연결을 시작(SYN)**하면. `threshold:type limit, track by_src, count 1, seconds 600` = 같은 PC에 대해 **10분에 한 번만** 알림. 이게 없으면 이 PCAP에서만 46번 울립니다. 회사에서는 `$EXTERNAL_NET` 대신 `!$DNS_SERVERS`(회사 DNS 서버가 아닌 곳)를 쓰면 더 정확합니다 — `DNS_SERVERS`를 실제 DNS 서버 IP로 정해 둔 경우에만요.

아무 도메인이나 DNS 형식으로 바꾸기:

```bash
python3 -c "
d='amellet.bit'
print(''.join('|%02x|%s' % (len(l), l) for l in d.split('.')) + '|00|')"
```

- `d.split('.')` — 점으로 나눔 → `['amellet', 'bit']`.
- `'|%02x|%s' % (len(l), l)` — 각 조각을 `|글자수(16진수 2자리)|조각`으로.
- 결과: `|07|amellet|03|bit|00|`

#### B. C2 — IP, Host, POST 모양 (sid 1000205–1000207) { #rules-c2 }

```text
alert tcp $HOME_NET any -> 35.198.166.240 any (msg:"LOCAL C2 connection attempt to known C2 IP 35.198.166.240"; flags:S; classtype:trojan-activity; sid:1000205; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL C2 HTTP request Host amellet.bit"; flow:established,to_server; content:"Host|3a| amellet.bit"; http_header; nocase; classtype:trojan-activity; sid:1000206; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Chthonic-like C2 POST - HTTP/1.0 to /a/ or /html/ without User-Agent"; flow:established,to_server; content:"POST /"; depth:6; content:" HTTP/1.0|0d 0a|"; distance:0; within:20; content:"POST"; http_method; pcre:"/^\/(?:a|html)\/$/U"; content:!"User-Agent|3a|"; http_header; classtype:trojan-activity; sid:1000207; rev:1;)
```

- **sid 1000205 (IOC)** — C2 IP로 가는 **SYN만**(`flags:S`). IP만 보는 룰에 `flags:S`가 없으면 **패킷마다** 울려서 수천 개가 됩니다. IP 룰은 항상 이렇게 좁히세요. 어느 포트든(`any`) 잡습니다.
- **sid 1000206 (IOC)** — HTTP 헤더에 `Host: amellet.bit`. `|3a|` = `:`. **IP가 바뀌어도** 같은 도메인이면 잡힙니다.
- **sid 1000207 (행동)** — 도메인도 IP도 안 보고 **C2 요청의 모양**만 봅니다. 조건이 **모두** 맞아야 해요.
    - `content:"POST /"; depth:6;` — 패킷 **맨 앞 6바이트**가 `POST /`. (요청 줄은 HTTP 헤더 버퍼에 안 들어가서, 원래 패킷에서 찾습니다.)
    - `content:" HTTP/1.0|0d 0a|"; distance:0; within:20;` — 바로 뒤 20바이트 안에 ` HTTP/1.0` + 줄바꿈. 즉 요청 줄이 `POST /짧은경로 HTTP/1.0`.
    - `content:"POST"; http_method;` — Snort의 HTTP 해석으로도 메서드가 POST.
    - `pcre:"/^\/(?:a|html)\/$/U"` — URI가 **정확히** `/a/` 또는 `/html/`. `^`=시작, `$`=끝, `(?:a|html)`=a 또는 html, `U`=URI에서.
    - `content:!"User-Agent|3a|"; http_header;` — 헤더에 `User-Agent:`가 **없음**.

#### C. 첫 다운로드 — URL과 "User-Agent 없는 EXE" (sid 1000208–1000210) { #rules-exe }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Malware download URL jgbennett.com 30_723bio_152.exe"; flow:established,to_server; content:"Host|3a| jgbennett.com"; http_header; nocase; content:"/30_723bio_152.exe"; http_uri; nocase; classtype:trojan-activity; sid:1000208; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL EXE requested without User-Agent - set flowbit"; flow:established,to_server; content:"GET"; http_method; content:".exe"; http_uri; nocase; pcre:"/\.exe$/Ui"; content:!"User-Agent|3a|"; http_header; flowbits:set,exe.noua; flowbits:noalert; classtype:trojan-activity; sid:1000209; rev:1;)
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LOCAL Windows EXE downloaded by non-browser client (no User-Agent)"; flow:established,to_client; flowbits:isset,exe.noua; file_data; content:"MZ"; within:2; content:"This program cannot be run in DOS mode"; distance:0; within:200; classtype:trojan-activity; sid:1000210; rev:1;)
```

- **sid 1000208 (IOC)** — 정확한 다운로드 주소. Host 헤더와 URI 두 조건.
- **sid 1000209 + 1000210 (행동, flowbits 한 쌍)** — "User-Agent 없이 `.exe`를 요청했고, 응답이 진짜 윈도우 실행 파일이면" 알림.
    - **1000209 (요청):** GET + URI가 `.exe`로 끝남(`pcre:"/\.exe$/Ui"`) + User-Agent 없음 → `flowbits:set,exe.noua`로 **이 연결에 표시**만 하고, `flowbits:noalert`로 알림은 안 냅니다.
    - **1000210 (응답):** 방향이 반대(`$EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any`, `to_client`) = **서버의 응답**. `flowbits:isset,exe.noua` = 표시된 연결에서만. `file_data;` = 응답 **본문**에서, `content:"MZ"; within:2;` = 본문 **첫 2바이트**가 `MZ`(실행 파일 표시), 그 뒤 200바이트 안에 `This program cannot be run in DOS mode`(모든 윈도우 EXE에 있는 문구).
    - 왜 두 룰로 나누나요? 요청만 보면 이름만 `.exe`인 가짜일 수 있고, 응답만 보면 정상 업데이트 다운로드도 걸립니다. **"브라우저가 아닌 것이 + 진짜 EXE를 받았다"**를 함께 보려면 요청과 응답을 이어야 하고, 그게 flowbits입니다.

#### D. 기술지원 사기 (sid 1000211–1000214) { #rules-scam }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Tech support scam domain helpcenterforall.bid or krep2010123.tk"; flow:established,to_server; pcre:"/^Host\x3a\s*(?:helpcenterforall\.bid|krep2010123\.tk)/Hmi"; classtype:bad-unknown; sid:1000211; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Tech support scam landing - phone number in URI"; flow:established,to_server; content:"number="; http_uri; pcre:"/[?&]number=\d{3}-\d{3}-\d{4}/U"; classtype:bad-unknown; sid:1000212; rev:1;)
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LOCAL Tech support scam page - fake Microsoft call-now text"; flow:established,to_client; threshold:type limit, track by_dst, count 1, seconds 60; file_data; content:"Call Microsoft"; nocase; content:"Toll Free"; nocase; distance:0; within:100; classtype:bad-unknown; sid:1000213; rev:1;)
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LOCAL Injected popunder script on website (popundr cookie)"; flow:established,to_client; file_data; content:"doOpen(|22|http"; content:"setCookie(|22|popundr|22|"; distance:0; within:100; classtype:web-application-activity; sid:1000214; rev:1;)
```

- **sid 1000211 (IOC)** — 두 사기 도메인 중 하나. `content`는 "또는"을 못 하니 정규식으로: `^Host\x3a\s*(?:A|B)`. `\x3a` = `:`, `\s*` = 공백 0개 이상, `H` = HTTP 헤더에서, `m` = `^`가 **각 줄의 시작**에 맞게(헤더는 여러 줄), `i` = 대소문자 무시.
- **sid 1000212 (행동)** — URI에 `number=000-000-0000` 모양의 **전화번호**. 이 사기 계열은 도메인을 자주 바꾸지만 전화번호를 URL로 넘기는 습관은 그대로인 경우가 많아요. `content:"number="; http_uri;`로 먼저 빠르게 거르고, 느린 정규식은 그다음에 돌립니다(좋은 습관).
- **sid 1000213 (행동)** — 응답 본문에 `Call Microsoft`와 그 뒤 100바이트 안에 `Toll Free`. 처음 테스트에서 같은 응답에 **두 번** 울려서, `threshold … track by_dst, count 1, seconds 60`(같은 PC에 60초에 1번)을 넣었습니다. 테스트가 필요한 이유예요.
- **sid 1000214 (행동)** — **해킹되거나 악성 광고가 들어간 웹사이트** 쪽을 잡습니다. 응답 본문에 `doOpen("http` 그리고 그 뒤 100바이트 안에 `setCookie("popundr"`. `|22|` = `"`. 사기 도메인이 바뀌어도 같은 팝언더 코드를 심은 사이트를 찾을 수 있어요. `file_data`는 **gzip을 풀고 chunk를 이은** 본문을 보기 때문에, 압축된 페이지에서도 맞습니다(이 페이지는 chunk 전송이었음).

### E3단계 — PCAP으로 테스트하기 { #snort-test }

1. 14줄을 `local.rules`에 붙여 넣습니다(예: `sudo nano /etc/snort/rules/local.rules`).
2. 문법 검사:

```bash
sudo snort -T -c /etc/snort/snort.conf
```

- `-T` — 실제로 돌리지 않고 설정과 룰만 검사합니다. 성공하면 마지막에 `Snort successfully validated the configuration!`이 나옵니다.
- 실제로 겪은 오류: `Unknown ClassType: social-engineering` — Snort 2.9의 `classification.config`에 없는 분류를 썼을 때입니다. 쓸 수 있는 목록은 `grep "config classification" /etc/snort/classification.config`로 봅니다. 그래서 사기 룰은 `bad-unknown`을 썼어요.

3. PCAP에 돌려서 룰별로 세기:

```bash
mkdir -p /tmp/snorttest
sudo snort -c /etc/snort/snort.conf -r 2017-10-21-traffic-analysis-exercise.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

- `-r 파일` — 실시간 네트워크 대신 **PCAP 파일**을 읽습니다.
- `-A console` — 알림을 화면에 바로 보여 줍니다.
- `-q` — 시작 안내문을 숨깁니다.
- `-k none` — **체크섬 검사를 끕니다.** 캡처에는 "틀린" 체크섬 패킷이 흔하고(랜카드 오프로딩), Snort가 그 패킷을 버리면 룰이 조용히 안 울립니다. 이 PCAP은 `-k none` 없이도 결과가 같았지만, 습관으로 넣으세요.
- `-U` — 시각을 **UTC**로 보여 줍니다.
- `-l /tmp/snorttest` — 테스트용 로그 폴더. 실제 `alert.log`를 더럽히지 않습니다.
- `grep -o "\[1:[0-9]*:[0-9]*\] [^[]*"` — 알림 줄에서 `[1:sid:rev] 제목` 부분만 뽑습니다.
- `sort | uniq -c` — 같은 것끼리 모아 개수를 셉니다.

### E4단계 — 실제 결과 { #snort-results }

**알림 한 줄 읽기:**

```text
10/21-04:52:47.886843  [**] [1:1000210:1] LOCAL Windows EXE downloaded by non-browser client (no User-Agent) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 107.180.41.148:80 -> 10.0.1.95:49691
```

- `10/21-04:52:47.886843` — 패킷 시각(`-U` 때문에 UTC).
- `[1:1000210:1]` — `[엔진:sid:rev]` — 어느 룰이 울렸는지.
- `{TCP} 출발 -> 도착` — 일치한 패킷. 1000210은 **응답** 룰이라 서버 → PC 방향입니다.

**룰별 결과 (`HOME_NET 10.0.0.0/8`과 `HOME_NET any` 두 설정 모두 같은 결과):**

| sid | 룰 | 종류 | 예상 | **실제** | 처음 – 마지막 (UTC) |
|---|---|---|---|---|---|
| 1000201 | TCP DNS `amellet.bit` | IOC | 37 (D3의 질의 수) | **37** ✅ | 04:53:52 – 05:02:05 |
| 1000202 | TCP DNS `.bit` | 행동 | 37 | **37** ✅ | 04:53:52 – 05:02:05 |
| 1000203 | UDP DNS `.bit` | 행동 | 0 (이번엔 UDP 없음) | **0** ✅ | — |
| 1000204 | 외부 TCP 53 SYN (10분에 1번) | 행동 | 1 | **1** ✅ | 04:53:52 |
| 1000205 | C2 IP SYN | IOC | 34 (C2 연결 수) | **34** ✅ | 04:54:03 – 05:02:05 |
| 1000206 | Host `amellet.bit` | IOC | 39 (POST 수) | **39** ✅ | 04:54:03 – 05:02:05 |
| 1000207 | C2 POST 모양 | 행동 | 39 | **39** ✅ | 04:54:03 – 05:02:05 |
| 1000208 | 다운로드 URL | IOC | 1 | **1** ✅ | 04:52:47 |
| 1000209 | (표시만, 알림 없음) | — | 0 | **0** ✅ | — |
| 1000210 | User-Agent 없이 받은 EXE | 행동 | 1 | **1** ✅ | 04:52:47 |
| 1000211 | 사기 도메인 | IOC | 6 (요청 수) | **6** ✅ | 05:03:25 – 05:03:31 |
| 1000212 | URI의 전화번호 | 행동 | 1 | **1** ✅ | 05:03:25 |
| 1000213 | 사기 페이지 글자 | 행동 | 1 | **1** ✅ (threshold 전 2) | 05:03:26 |
| 1000214 | 팝언더 스크립트 | 행동 | 1 | **1** ✅ | 05:02:27 |

**결과 읽기:**

1. **모든 룰이 예상한 개수만큼** 울렸습니다. 예상 개수는 Zeek/Arkime에서 센 값(D부)에서 나왔어요. 룰을 쓰기 **전에** 예상 개수를 적어 두면, 결과가 맞는지 바로 알 수 있습니다.
2. **오탐 0개.** 캡처에는 Microsoft, Google, Bing, 광고 수십 곳의 트래픽도 있는데, 알림의 IP는 모두 악성 사슬(107.180.41.148, 35.198.166.240, 외부 DNS 서버들, 104.18.61.210, 162.244.35.33/36)뿐이었습니다. 특히 1000210은 **User-Agent 없는 다른 요청 63개**(C2, msftconnecttest, OCSP)에서 울리지 않았어요 — `.exe` + `MZ` 조건 덕분입니다.
3. **flowbits가 제대로 동작했습니다.** 1000209는 알림 없이 표시만 했고, 1000210이 같은 연결의 응답에서 한 번 울렸습니다.
4. **threshold가 필요한 곳을 테스트가 알려 줬습니다.** 1000213은 처음에 같은 응답에 2번 울렸습니다.

!!! question "질문: 출력이 왜 시간 순서가 아닌가요?"
    HTTP 룰은 Snort가 **TCP 흐름을 다시 조립한 뒤** 검사합니다. 그래서 조립이 끝나는 시점에 알림이 출력되고, 다른 알림보다 늦게 찍힐 수 있어요. 각 알림의 **시각**은 실제 패킷 시각입니다. 타임라인은 출력 순서가 아니라 **시각**으로 정렬하세요.

### E5단계 — Snort 3을 쓰는 경우 { #snort3 }

Snort 3에서는 `http_uri`, `http_header` 같은 버퍼를 **`content` 앞에** 씁니다(sticky buffer). 예를 들어 sid 1000206은 이렇게 바뀝니다.

```text
alert http $HOME_NET any -> $EXTERNAL_NET any ( msg:"LOCAL C2 HTTP request Host amellet.bit"; flow:established,to_server; http_header; content:"Host|3a| amellet.bit",nocase; classtype:trojan-activity; sid:1000206; rev:2; )
```

- `alert http` — Snort 3은 프로토콜 자리에 `http`를 쓸 수 있고, 포트 대신 **내용으로 HTTP를 알아봅니다.**
- `http_header;` — 이 뒤의 `content`는 모두 헤더에서 찾습니다.
- `content:"…",nocase` — 옵션을 쉼표로 붙입니다.
- `file_data`는 Snort 3에서도 같은 이름입니다. DNS 룰(A)은 그대로 써도 됩니다.
- 이 Snort 3 예시는 문법을 보여 주기 위한 것이고, 이번에는 Snort 2.9로만 테스트했습니다. Snort 3 센서에서는 꼭 `snort -T`와 PCAP 테스트를 다시 하세요.

---

## F부 — 타임라인, IOC, 호스트 오퍼레이터 단서 { #results }

### 타임라인 (UTC, 2017-10-21) { #timeline }

| 시각 | 사건 |
|---|---|
| 04:51:53 | 캡처 시작. DELOREAN-PC가 DHCP로 10.0.1.95 재확인, 윈도우 10 시작 통신(NCSI, 라이브 타일, Bing, DC SRV 질의 — 답 없음) |
| 04:52:40 – 04:52:46 | **Microsoft Office 실행** (`contentstorage.osi.office.net`, `messaging.office.com`, `nexus.officeapps.live.com`, `officeclient.microsoft.com`) |
| **04:52:47** | **첫 악성 이벤트:** `jgbennett.com`(107.180.41.148) DNS → GET `/3cgconsulting.com/30_723bio_152.exe`, **User-Agent·Referer 없음**, 61,440바이트 PE, SHA256 `a56876fd…a490` |
| 04:53:08 | DHCP 재요청과 윈도우 시작 통신이 다시 나옴(네트워크 재연결) |
| 04:53:52 | 첫 **`.bit` DNS 질의**, 외부 DNS 130.255.78.223에 **TCP 53** — 답 없음 |
| 04:54:03 | 188.165.200.156이 `amellet.bit` = **35.198.166.240** 답 → **첫 C2 POST `/a/`**(보냄 1,584 / 받음 157,261바이트) |
| 04:54:44 | 두 번째 `/a/` 체크인 |
| 04:54:59 – 04:56:11 | `/html/` POST 34번, 0.2~4초 간격 — **모듈 다운로드**(약 2MB, 같은 묶음 두 번). 외부 DNS 9곳 시도 |
| 04:55:08 | User-Agent 없는 `msftconnecttest.com` 확인 6번 (추정: 악성코드의 인터넷 확인) |
| 04:56:11 – 05:00:51 | C2 조용함 |
| 05:00:51 – 05:02:31 | User-Agent 없는 `msftconnecttest.com` 확인 66번, 그 사이 **C2 POST 05:00:52, 05:02:05** |
| 05:02:26 | 사용자가 IE11로 `www.singlemoms.org` 열기 → 광고 수십 곳(세션 급증) |
| 05:02:27 | 페이지 안 **팝언더 스크립트** 수신 (Snort sid 1000214) |
| 05:03:25 | 클릭 → `helpcenterforall.bid/index/?MCPKV8` (162.244.35.33) **302** → `krep2010123.tk/?number=888-779-0939` (162.244.35.36) |
| 05:03:26 – 05:03:31 | 가짜 "Windows Defender Alert: Zeus Virus Detected" 페이지, `defender.png`, **경고음 `err.mp3`** |
| 05:03:52 | 캡처 끝 |

### IOC 표 { #iocs }

| 종류 | 값 | 설명 | 조치 |
|---|---|---|---|
| 도메인 | jgbennett[.]com | 악성 EXE 배포(해킹된 서버로 보임) | 차단 |
| IP | 107.180.41.148 | jgbennett[.]com | 차단 / 조회 |
| URL | hxxp://jgbennett[.]com/3cgconsulting.com/30_723bio_152.exe | 다운로드 주소 | 차단 |
| 파일 | 30_723bio_152.exe, 61,440바이트 | 32비트 GUI PE, 서명 없음, 컴파일 시각 2017-07-16 | 호스트에서 찾기 |
| SHA256 | a56876fd456d0737eecc4a8bbe3154b35314ab28accb29abf0df7c518c81a490 | 위 파일 | 정보 조회 |
| MD5 / SHA1 | 658c30fcd1508a65df8b9b9b397a9459 / fe4116d0e66350f54042361e3a87c942ee98529d | 위 파일 | 정보 조회 |
| 도메인 | amellet[.]bit | C2 (Namecoin `.bit`) | 차단 / `.bit` 전체 차단 |
| IP | 35.198.166.240 | C2, HTTP 80, lighttpd/1.4.45, PHP/5.3.3 | 차단 |
| URI | `/a/`, `/html/` (HTTP/1.0 POST, User-Agent 없음) | C2 경로 | 탐지 |
| IP | 188.165.200.156, 144.76.133.38, 130.255.78.223, 62.113.203.99, 93.170.96.235, 31.3.135.232, 130.255.73.90, 37.187.16.17, 85.159.213.210 | 악성코드가 쓴 외부 DNS 서버(TCP 53) | 외부 DNS 직접 연결 차단 |
| 도메인 / IP | helpcenterforall[.]bid / 162.244.35.33 | 사기 리다이렉터 | 차단 |
| 도메인 / IP | krep2010123[.]tk / 162.244.35.36 | 기술지원 사기 페이지 | 차단 |
| 전화번호 | 888-779-0939 | 사기 전화번호 | 사용자 확인 |
| 도메인 / IP | www.singlemoms[.]org / 104.18.61.210 (Cloudflare) | 팝언더 스크립트가 들어 있던 사이트 | 감시 / 사용자 안내 |
| 행동 | User-Agent 없는 `www.msftconnecttest.com` 반복 | 악성코드의 인터넷 확인으로 추정 | 참고 |

### 호스트 오퍼레이터를 위한 단서 { #host-leads }

네트워크 증거를 **PC 안에서 찾을 수 있는 단서**로 바꾼 목록입니다. 이벤트 번호마다 뜻을 적었습니다.

1. **격리와 메모리 먼저.** DELOREAN-PC(10.0.1.95, MAC `60:a4:4c:6a:b2:1f`)를 격리하고, **재부팅 전에 메모리를 수집**하세요. Zeus 계열은 다른 프로세스 안에 숨어서(인젝션) 디스크에 흔적을 적게 남깁니다.
2. **시간 범위:** **04:52:30 – 04:56:15 UTC**(Office 실행 → EXE → C2 모듈), 그리고 05:00:50 – 05:03:35 UTC.
3. **Office 문서 찾기.** 04:52:40쯤 열린 Word/Excel 문서:
    - **Sysmon 이벤트 ID 1**(프로세스가 생성됨, 명령줄과 부모 포함) / **Security 4688**(새 프로세스가 생성됨): `WINWORD.EXE`나 `EXCEL.EXE`의 자식 프로세스(`cmd.exe`, `powershell.exe`, `wscript.exe`, 또는 EXE 자체).
    - 최근 문서 목록, Office의 `Trusted Records` 레지스트리 키(사용자가 "콘텐츠 사용"을 눌렀는지), 다운로드·메일 임시 폴더의 문서, `Zone.Identifier`(인터넷에서 받은 파일 표시).
4. **EXE 찾기.** `30_723bio_152.exe`(SHA256 위 참고) — 이름이 바뀌었을 수 있으니 **해시로** 찾으세요.
    - **Sysmon 이벤트 ID 11**(파일이 생성됨): 04:52:47쯤 생성된 실행 파일. `%TEMP%`, `%APPDATA%` 확인.
    - **Prefetch**, **Amcache**: 실행 흔적과 SHA1(`fe4116d0…529d`).
5. **네트워크 연결한 프로세스.**
    - **Sysmon 이벤트 ID 3**(프로세스가 네트워크에 연결함): 107.180.41.148:80, 35.198.166.240:80, 그리고 **외부 IP의 TCP 53**에 연결한 프로세스. `www.msftconnecttest.com`에 User-Agent 없이 연결한 프로세스도 같은지 확인(D6 추정 검증).
    - **Sysmon 이벤트 ID 22**(DNS 질의, Sysmon 10 이상): `amellet.bit`를 물은 프로세스. 다만 이 악성코드는 윈도우 DNS를 거치지 않고 **직접 TCP로** 물었으므로 ID 22에 안 남을 수 있습니다 — 그러면 ID 3이 기준입니다.
6. **인젝션.** **Sysmon 이벤트 ID 8**(CreateRemoteThread: 한 프로세스가 다른 프로세스 안에 스레드를 만듦), **ID 10**(한 프로세스가 다른 프로세스 메모리에 접근함). 공개 분석에서 Chthonic 로더는 `msiexec.exe` 같은 정상 프로세스에 들어가는 것으로 알려져 있습니다 — 부모 없이 떠 있는 `msiexec.exe`를 확인하세요.
7. **지속성.** **Sysmon 이벤트 ID 13**(레지스트리 값이 설정됨) — `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 등 자동 실행 키. **Security 4698**(예약 작업이 만들어짐), **System 7045**(새 서비스가 설치됨).
8. **04:53:08 DHCP 재요청** — 다운로드 21초 뒤 네트워크가 다시 연결됐습니다. 네트워크 어댑터 재시작, 절전 해제, 사용자 동작인지 **System 로그**(네트워크 프로필, 어댑터 이벤트)에서 확인.
9. **은행 정보·비밀번호.** Zeus 계열은 브라우저 입력값과 저장된 비밀번호를 훔칩니다. **사용자의 비밀번호(특히 은행, 메일)를 깨끗한 다른 기기에서 바꾸게** 하세요. C2로 약 23KB가 암호화돼 나갔습니다.
10. **기술지원 사기.** 사용자에게 05:03:25 이후 **888-779-0939로 전화했는지**, 원격 접속 프로그램(TeamViewer, AnyDesk, LogMeIn 등)을 설치·허용했는지 확인하세요. 그랬다면 **별도 사건**으로 다룹니다. IE의 `popundr` 쿠키(24시간)도 흔적입니다.

---

## 복사용 쿼리 모음 { #query-sheet }

`<…>`를 바꿔 쓰세요. Splunk는 시간 범위 **All time**, 시각은 `ts`를 쓰세요.

**Splunk — 베이스라이닝**

```spl
| tstats count where index=zeek by sourcetype
```

```spl
index=zeek sourcetype=zeek:conn
| stats count min(ts) AS first max(ts) AS last
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
```

```spl
index=zeek sourcetype=zeek:conn (id_orig_h=10.0.0.0/8 OR id_orig_h=172.16.0.0/12 OR id_orig_h=192.168.0.0/16)
| stats count dc(id_resp_h) AS unique_destinations BY id_orig_h
| sort - count
```

```spl
index=zeek sourcetype=zeek:dhcp
| table ts client_addr server_addr assigned_addr mac host_name domain lease_time msg_types
```

```spl
index=zeek sourcetype=zeek:conn (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16) id_resp_p<10000
| stats dc(id_orig_h) AS clients count values(id_resp_p) AS ports BY id_resp_h
```

```spl
index=zeek sourcetype=zeek:conn id_resp_p IN (88, 135, 139, 389, 445, 464, 636, 3268, 3389, 5985, 25, 110, 143, 465, 587, 993, 995)
| stats count BY id_resp_h id_resp_p
```

```spl
index=zeek sourcetype=zeek:dns
| stats count values(proto) AS proto BY id_resp_h
| sort - count
```

```spl
index=zeek sourcetype=zeek:conn
| stats count BY proto service
```

```spl
index=zeek sourcetype=zeek:http id_orig_h=<host-IP>
| fillnull value="(none)" user_agent
| stats count BY user_agent
```

```spl
index=zeek sourcetype=zeek:conn id_orig_h=<host-IP> NOT (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16 OR id_resp_h=224.0.0.0/4 OR id_resp_h=255.255.255.255)
| stats count sum(orig_bytes) AS bytes_out sum(resp_bytes) AS bytes_in values(id_resp_p) AS ports BY id_resp_h
| sort - count
```

**Splunk — 악성 행위**

```spl
index=zeek sourcetype=zeek:http NOT user_agent=*
| fillnull value="-" host
| stats count dc(uid) AS connections values(method) AS method values(version) AS ver BY host id_resp_h
```

```spl
index=zeek sourcetype=zeek:files mime_type="application/x-dosexec"
| table ts tx_hosts rx_hosts seen_bytes total_bytes md5 sha1
```

```spl
index=zeek sourcetype=zeek:dns NOT id_resp_h=<internal-DNS-IP> NOT id_resp_h=224.0.0.0/4 NOT id_resp_h=<broadcast>
| stats count values(query) AS queries BY id_resp_h proto
```

```spl
index=zeek sourcetype=zeek:http host="<domain>"
| sort ts
| streamstats current=f last(ts) AS prev_ts
| eval t=strftime(ts, "%H:%M:%S"), gap=round(ts-prev_ts, 1)
| table t method uri version request_body_len response_body_len gap
```

```spl
index=zeek sourcetype=zeek:weird
| stats count BY name id_resp_h
```

**Arkime**

```text
ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16
ip.src != 10.0.0.0/8
protocols == dhcp
ip.dst == 10.0.0.0/8
ip.src == <host-IP> && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && ip.dst != 255.255.255.255
protocols == http && http.user-agent != EXISTS!
port.dst == 53 && ip.protocol == tcp
host.dns == *.bit
host.http == <domain>
host.http == [<domain1>, <domain2>]
mac.src == <MAC>
```

**Snort**

```bash
sudo snort -T -c /etc/snort/snort.conf
sudo snort -c /etc/snort/snort.conf -r <file>.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

**분석 VM**

```bash
sha256sum <file>.pcap
tshark -r <file>.pcap -Y "dhcp.option.dhcp == 5" -V | grep -E "^ +(DHCP Server Identifier|Subnet Mask|Router|Domain Name Server|Domain Name|IP Address Lease Time):"
tshark -r <file>.pcap --export-objects http,http_objects
```

---

## 배운 점 { #lessons }

1. **베이스라인이 먼저입니다.** "이 PC는 공유기 DNS(10.0.1.1)에 UDP로 묻는다"를 알았기 때문에 **외부 DNS에 TCP로 묻는 것**이 바로 눈에 띄었습니다.
2. **IP 개수 ≠ 장치 수.** IP는 3개였지만 MAC으로 보니 장치는 2대(라우터가 IP 두 개)였습니다.
3. **"없다"도 결과입니다.** DC, 파일 서버, 메일 서버, 인바운드, 측면 이동이 **없다는 것**을 확인하고 적으면, 다음 사람이 다시 찾을 필요가 없습니다.
4. **User-Agent는 "누가 요청했나"를 알려 줍니다.** 브라우저(IE11), 윈도우 구성 요소(CryptoAPI, WNS), 그리고 **아무것도 안 붙인 프로그램**을 나눴더니 악성 통신이 모였습니다. 다만 "없음"에도 정상 잡음(408 응답, OCSP)이 섞이니 하나씩 확인해야 합니다.
5. **앞뒤 몇 초가 원인을 말해 줍니다.** EXE 다운로드 1~7초 전의 Office 질의가 감염 경로(문서 매크로)를 가리켰습니다. 확인은 못 했으니 "추정"으로 적고 호스트 단서로 넘깁니다.
6. **`.bit`와 외부 DNS 직접 질의는 강한 신호입니다.** 회사 PC가 Namecoin 이름을 물을 일은 거의 없고, 회사 DNS를 우회하는 TCP 53은 더더욱 없습니다. 이런 **행동 룰**은 공격자가 도메인과 IP를 바꿔도 남습니다.
7. **한 캡처에 사건이 둘일 수 있습니다.** 악성코드 C2와 기술지원 사기 팝업은 시간이 붙어 있지만 서로 연결된 흔적이 없었습니다. 같은 이야기로 묶지 말고 따로 적으세요.
8. **룰은 쓰기 전에 예상 개수를 적고, PCAP으로 테스트하세요.** 테스트가 분류 이름 오류(`social-engineering`)와 중복 알림(sid 1000213)을 잡아 줬습니다.
9. **폐쇄망이어도 결론은 낼 수 있습니다.** 해시는 다른 사람을 위해 기록하고, 행동으로 판단하고, 계열은 "consistent with … – unconfirmed"로 적으세요.

## 참고 { #references }

- [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Arkime로 PCAP 분석하기](../../network/arkime/offline-pcap-guide.md)
- [Zeek: conn](../../network/zeek/conn-log.md) · [dns](../../network/zeek/dns-log.md) · [http](../../network/zeek/http-log.md) · [files](../../network/zeek/files-log.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [데이터 파악과 시간](../splunk/data-discovery.md)
- [비콘과 C2](../../network/beaconing-c2.md) · [DC/SMB 공격용 Snort 룰](../../training/pcap-ir-labs/dc-smb-and-snort-rules.md)
- [앞의 사례: 피싱 함정과 익스플로잇 킷 (Splunk + Arkime + Snort)](phishing-red-herring-ek-driveby-ursnif-c2.md) · [Arkime만으로 — 비밀번호 탈취와 TLS C2](arkime-only-credential-theft-tls-c2.md)
- [플레이북: 감염된 워크스테이션](../playbooks/compromised-workstation.md)
- 원본 실습: [malware-traffic-analysis.net — 2017-10-21 Doc Brown and Marty McFly: Back to the Present](https://malware-traffic-analysis.net/2017/10/21/index.html)
- 공개 분석: [QA Cafe(CloudShark) — Windows 10 Malware Analysis Exercise](https://qacafe.com/resources/malware-exercise-2017-10-21)
