---
title: Night Dew 두 번째 분석 — pcapbox의 Arkime + Splunk(Zeek)로 C2 응답 모두 풀기, netlogon 비밀번호 대입, 테스트한 Snort 룰 하나
tags:
  - blue-team
  - pcap
  - arkime
  - splunk
  - zeek
  - cyberchef
  - snort
  - c2
  - tls
  - dce-rpc
  - ticket
---

# Night Dew 두 번째 분석 — Arkime + Splunk(Zeek), netlogon 비밀번호 대입, Snort 룰 하나 { #night-dew-2 }

!!! abstract "사례 요약"
    [첫 번째 분석](night-dew-hancitor-pony-zeus-panda-tls-c2.md)과 같은 malware-traffic-analysis.net 2018-05-11 "Night Dew" PCAP을, 홈 랩의 **pcapbox** VM에서 **처음 보는 PCAP이라고 생각하고 처음부터** 다시 분석한 기록입니다. Arkime를 중심으로 쓰고, 개수를 세거나 정렬하거나 프로토콜을 자세히 볼 때는 **Splunk(Zeek 로그)**를 같이 씁니다. Windows 7 PC 한 대(**CHICAGO-7FA3-PC, 사용자 faith.hoffman**)가 `lysedsohap[.]com`에 체크인하고, 명령(Base64 + XOR `0x7a`)을 받아 해킹된 WordPress 사이트에서 암호화된 파일 3개를 내려받고, **작은 암호화 POST 2개**(훔친 비밀번호로 추정)를 보냅니다. 그다음 기본값 자체 서명 인증서를 쓰는 **TLS로 두 번째 C2**를 시작하고, 이번 분석에서 새로 찾은 **DC에 32초 동안 1,522번 netlogon 로그인 확인 요청(비밀번호 대입)**을 보냅니다. 마지막에 체크인과 비콘 21개를 모두 잡는 **Snort 룰 하나**, 초보자용 룰 테스트 가이드, 짧은 티켓으로 마무리합니다.

| | |
|---|---|
| **증거** | `2018-05-11-traffic-analysis-exercise.pcap` — 2018-05-11 02:06:51 – 02:49:41 UTC (42분 50초), 세션 216개, SHA256 `b2c8d0fe…13e51e` |
| **출처** | [malware-traffic-analysis.net 2018-05-11 "Night Dew"](https://malware-traffic-analysis.net/2018/05/11/index.html) |
| **환경** | 폐쇄망. pcapbox VM: Arkime(태그 = 케이스 이름), Splunk(`index=zeek`, 필드 `pcap_case`), Snort 2.9.20, CyberChef |
| **결과물** | 분석, 풀어 낸 C2 명령, PCAP으로 테스트한 Snort 룰 하나, 침해사고 티켓(txt) |
| **관련 페이지** | [첫 번째 분석(Arkime + CyberChef + Snort 룰 8개)](night-dew-hancitor-pony-zeus-panda-tls-c2.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Zeek 로그](../../network/zeek/index.md) · [비콘과 C2](../../network/beaconing-c2.md) |

!!! tip "이 페이지 읽는 법"
    단계마다 같은 순서예요. **목적 → Arkime → Splunk(그쪽이 편할 때) → 결과 → 결과 읽기 → 티켓 기록**. **질문** 상자는 분석하면서 실제로 나온 질문과 답이에요. SPL 쿼리는 모두 한 줄씩 설명합니다.

    전체 원칙은 **모르는 PCAP을 분석한다**는 거예요. 공개된 정답을 가져다 쓰지 않고, 화면에 나온 것만으로 판단합니다. 그래서 악성코드 계열 이름은 **확인되지 않음**으로 둡니다.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인, IP, 해시는 2018년 실제 악성 트래픽에서 나온 값입니다. 본문과 표에서는 무력화(`hxxp`, `[.]`)했고, 코드 블록 안은 입력한 그대로 두었어요. **절대 접속하지 마세요.** 추출한 파일은 실행하지 마세요.

## 첫 번째 분석과 달라진 점 { #what-is-new }

| 주제 | 첫 번째 분석 | 이번 분석 |
|---|---|---|
| DC 통신 | "정상 도메인 활동뿐" | **32초 동안 `NetrLogonSamLogonWithFlags` 1,522번 = DC를 통한 비밀번호 대입** ([5단계](#netlogon)) |
| 도구 | Arkime, tshark | Arkime **와 Splunk(Zeek `conn`, `http`, `files`, `ssl`, `kerberos`, `dhcp`, `dce_rpc` 로그)** |
| 두 번째 구성 요소의 POST | 분석함(헤더 모양, 계열 이름까지) | 처음부터 다시: Splunk POST 요약 + 헤더, 계열은 확인 안 됨으로 ([3-6](#exfil)) |
| C2 응답 | 첫 응답만 디코드 | 첫 응답 **과 비콘 응답**(`{n:}` = 명령 없음)까지 디코드, 예비 다운로드 사이트 접속 여부 확인 |
| Snort | 룰 8개 | **룰 1개**를 조각조각 설명하고, 초보자용 테스트 가이드 전체 |
| 티켓 | 모든 내용을 합친 티켓 | **핵심 발견만** 담은 짧은 티켓(베이스라인 제외) |

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| 감염된 PC | **10.0.14.129, CHICAGO-7FA3-PC**, MAC `00:1a:92:06:5c:7b`(ASUSTek), Windows 7 x64 | 확인됨 |
| 사용자 | **faith.hoffman** (도메인 NIGHTDEW) | 확인됨 |
| 첫 악성 이벤트 | **02:08:04 UTC** — 공인 IP 조회 후 C2 체크인 | 확인됨 |
| 최초 감염 경로 | 캡처에 없음. 악성코드가 이미 PC에 있었고 로그인 때 실행됨 | 추정 |
| HTTP C2 | `lysedsohap[.]com` 185.43.223.6:80, POST `/4/forum.php` 21번(체크인 + 약 120초마다 비콘) | 확인됨 |
| 다운로드 | `wansaiful[.]com` 111.90.144.30:80, 암호화된 파일 3개(`/1`, `/2`, `/3`) | 확인됨 |
| 두 번째 구성 요소 | 02:08:12–02:08:14에 POST `/mlu/forum.php`(206 B), `/d2/about.php`(234 B). MSIE 7.0 User-Agent, 암호화된 본문, `Content-Encoding: binary` — 계정 정보 탈취로 추정 | 확인됨(내용은 암호화) |
| 비밀번호 대입 | DC 10.0.14.3에 32초 동안 netlogon 로그인 확인 1,522번 (02:08:12–02:08:45) | 확인됨(계정과 결과는 안 보임) |
| TLS C2 | `robwassotdint[.]ru` 185.174.175.14:443, 세션 54개, 약 5분 주기, 자체 서명 `Default Company Ltd` 인증서, 02:40–02:42에 약 1.5 MB 내려옴 | 확인됨 |
| 외부 유출 | 큰 업로드는 없음. 작은 암호화 POST 2개(합계 440 B) — 계정 정보가 나간 것으로 간주 | 확인됨(내용은 못 읽음) |
| 악성코드 계열 | 다운로더 + 두 번째 구성 요소 + TLS C2 — 이름은 **확인 안 됨** | 확인 안 됨 |

---

## 0단계 — PCAP을 pcapbox에 넣고 시간 맞추기 { #prep }

**목적:** PCAP을 한 번 넣고 **케이스 이름**을 붙인 뒤, 모든 도구가 **UTC**로 보이게 합니다.

### 0-1. 넣기 { #ingest }

1. PCAP 이름을 원하는 케이스 이름으로 바꿉니다. 예: **`20180511_NIGHT_DEW.pcap`**
2. 호스트 PC에서 `\\10.50.10.60\incoming`에 넣습니다.
3. pcapbox에서 처리 기록을 지켜봅니다.

```bash
tail -f /data/logs/ingest.log
```

- `tail -f`: 파일 끝을 보여 주고, 새 줄이 생기면 계속 출력해요. **Ctrl+C**로 멈춥니다.
- `DONE case=20180511_NIGHT_DEW ...`가 나오면 끝이에요. 바로 위 `START` 줄의 `sha256=` 값이 티켓에 쓸 **증거 해시**입니다.

!!! question "질문: 지금 설정은 서로 다른 PCAP을 구분하려고 태그를 붙이는 것 같은데 맞나요?"
    맞아요. **확장자를 뺀 파일 이름이 케이스 이름**이 되고, 모든 도구가 그 이름을 씁니다.

    - **Arkime:** `capture -t <케이스>`로 모든 세션에 태그를 붙여요 → `tags == 20180511_NIGHT_DEW`로 검색합니다.
    - **Splunk (Zeek):** 로그를 `/data/zeek/<케이스>/`에 저장하고, `props.conf`가 폴더 이름을 **`pcap_case`** 필드로 뽑아요 → `pcap_case=20180511_NIGHT_DEW`.
    - **Splunk (Snort):** `/data/snort/<케이스>/alert` → `index=snort`에도 같은 `pcap_case` 필드가 생겨요.
    - **원본 사본:** `/data/pcap/<케이스>.pcap`

    같은 이름을 두 번 넣으면 덮어쓰지 않고 뒤에 시각이 붙어요. 연습용 PCAP들은 비슷한 사설 IP를 쓰기 때문에, 케이스 이름이 없으면 여러 문제의 결과가 섞여 버립니다.

    들어 있는 케이스 목록 보기:

    ```spl
    index=zeek sourcetype=zeek:conn
    | stats count by pcap_case
    ```

    - `stats count by pcap_case`: 케이스별로 연결 개수를 셉니다. 결과:

    ```text
    pcap_case             count
    20180511_NIGHT_DEW    216
    ```

### 0-2. Arkime를 UTC로 바꾸기 { #utc }

같은 PCAP인데 처음에는 시각이 두 가지로 나왔어요.

```text
Arkime   11:36:51 – 12:19:41
Splunk   02:06:51 – 02:48:51
```

차이가 정확히 **9시간 30분**이에요. Arkime는 **브라우저(노트북)의 현지 시간**으로 보여 주는데, 애들레이드는 2018년 5월에 UTC+9:30이었거든요. Splunk는 이미 UTC였고요. 티켓은 UTC로 쓰니까 Arkime를 한 번 맞춰 둡니다.

- 오른쪽 위 사용자 메뉴 → **Settings** → **General** → **Timezone** → **UTC**
- Splunk: 계정 메뉴 → **Preferences** → **Time zone** = UTC. `strftime`이나 `convert`는 Splunk 사용자 시간대로 출력하기 때문이에요.
- Arkime 시간 범위는 **All**. 2018년 데이터라 기본값(최근 1시간)으로는 안 보여요.

바꾸고 나면 Arkime도 `2018/05/11 02:06:51 – 02:49:41 UTC`로 나와서 Splunk와 맞습니다.

!!! note "끝 시각이 1분 다른 이유"
    Arkime의 끝은 **마지막 패킷** 시각(02:49:41)이에요. Zeek의 `ts`는 연결이 **시작된** 시각이라서, 가장 늦은 `ts`(02:48:51)는 마지막 연결이 시작된 시각입니다.

---

## 1단계 — 전체 그림 { #overview }

**목적:** 세부 내용을 보기 전에 세 가지만 봅니다. 캡처가 언제부터 언제까지인지, 내부 PC가 몇 대인지, 누가 가장 많이 통신했는지.

### Arkime { #overview-arkime }

**Sessions** → 시간 범위 **All** → 검색:

```text
tags == 20180511_NIGHT_DEW
```

**Start Time**으로 정렬하세요(오래된 순서 = 캡처 시작, 한 번 더 누르면 캡처 끝). 그다음 **SPIView** → **General**:

```text
Src IP     10.0.14.129 (212)  10.0.14.1 (3)  0.0.0.0 (1)
Dst IP     10.0.14.3 (91)  185.174.175.14 (54)  10.0.14.1 (23)  185.43.223.6 (23)
           224.0.0.252 (5)  255.255.255.255 (4)  10.0.14.129 (3)  10.0.14.255 (3)
           224.0.0.22 (3)  239.255.255.250 (3)  111.90.144.30 (1)  173.223.52.18 (1)
           184.72.249.110 (1)  216.58.193.68 (1)
Protocols  tcp (131) udp (82) tls (55) dns (34) http (26) krb5 (25) ldap (12)
           dhcp (9) dcerpc (7) smb (6) llmnr (5) igmp (3) ntp (3) ssdp (3)
```

### Splunk { #overview-splunk }

**쿼리 ① 캡처 시간과 규모**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180511_NIGHT_DEW
| stats min(ts) as first max(ts) as last count as sessions
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- 1줄: Zeek 연결 기록(`conn.log`) 가운데 이번 케이스만 가져옵니다.
- 2줄 `stats`: 결과 전체를 한 줄로 요약해요. `min(ts) as first`는 가장 이른 시각, `max(ts) as last`는 가장 늦은 시각, `count as sessions`는 연결 개수예요.
- 3줄 `eval ... strftime(...)`: `ts`는 1970년부터 센 초(epoch)라 읽기 어려워서, 날짜 모양으로 바꿉니다.

```text
first                 last                  sessions
2018-05-11 02:06:51   2018-05-11 02:48:51   216
```

**쿼리 ② 내부 PC별 통신량**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180511_NIGHT_DEW id_orig_h="10.0.14.*"
| stats count as sessions sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h
| sort - sessions
```

- 1줄 `id_orig_h="10.0.14.*"`: 연결을 **시작한** 쪽이 내부망인 것만 남깁니다. `*`는 "아무 숫자나"예요.
- 2줄: 내부 IP마다 연결 수, PC가 보낸 바이트 합(`orig_bytes`), 받은 바이트 합(`resp_bytes`)을 구해요.
- 3줄 `sort - sessions`: 연결이 많은 순서로 정렬합니다. `-`는 내림차순이에요.

```text
id_orig_h      sessions   sent      received
10.0.14.129    215        948119    2206707
```

### 결과 읽기 { #overview-reading }

- **PC는 한 대뿐이에요.** 10.0.14.129가 거의 모든 연결을 시작해요. `0.0.0.0`은 IP를 받기 전에 DHCP로 "IP 주세요"라고 외치는 PC이고, `10.0.14.1`은 DHCP에 답하는 쪽이에요. 트래픽을 뽑아 준 동료가 **알림이 뜬 PC만 걸러 낸** 것으로 보이니, **10.0.14.129를 용의자**로 놓고 시작합니다.
- **내부 목적지:** 10.0.14.3(91개)은 DC예요. 도메인 PC라면 DC와 많이 통신하는 게 정상이에요. 224.x, 239.x, 255.255.255.255, 10.0.14.255는 멀티캐스트와 브로드캐스트입니다.
- **외부 목적지:** **185.174.175.14(54개)**와 **185.43.223.6(23개)**에 몰려 있고, 나머지 외부 IP 4개는 1개씩뿐이에요. 사람이 웹 서핑을 하면 CDN, 광고 서버 등 수십 개 IP에 흩어져야 해요. 특정 IP 두 개에만 반복 접속하는 건 **프로그램이 접속하는 모양(비콘)**이에요. 둘 다 용의자 목록에 올립니다.
- **보낸 양이 많아요.** 보낸 948 KB, 받은 2.2 MB. 일반 PC는 받는 양이 훨씬 크고 보내는 건 적어요. 이 의문은 [5단계](#netlogon)에서 풉니다.
- `tls 55`가 185.174.175.14의 세션 54개와 비슷해요. 나중에 맞춰 볼 단서입니다.

**티켓 기록:** 없음. 베이스라인은 분석 과정이지 발견이 아니에요.

---

## 2단계 — 용의자 PC는 누구인가 { #identity }

**목적:** 보고서에는 **IP, MAC, 호스트 이름, 사용자 계정**이 필요해요. 각각 어느 프로토콜에 들어 있는지 알면 어떤 PCAP에서도 같은 방법으로 찾을 수 있어요.

- **MAC과 호스트 이름 → DHCP.** PC가 IP를 받을 때 자기 MAC과 이름을 같이 보냅니다.
- **사용자 계정 → Kerberos.** Windows 도메인에 로그인할 때 DC에 "나 누구요" 하고 이름을 보냅니다.

### 2-1. DHCP { #dhcp }

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && protocols == dhcp
```

- `protocols == dhcp`: DHCP 세션만 남겨요. `&&`는 "그리고"라는 뜻이에요. SPIView → **dhcp**:

```text
Client MAC   00:1a:92:06:5c:7b (9)
Client OUI   ASUSTek COMPUTER INC. (9)
Host         chicago-7fa3-pc (6)  chicago-7fa3-pc.nightdew.org (3)
Type         ACK (5)  INFORM (3)  REQUEST (3)
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:dhcp pcap_case=20180511_NIGHT_DEW
| table _time client_addr assigned_addr mac host_name msg_types
```

- `table`: 지정한 칸만 표로 보여 줘요. `client_addr`는 PC의 현재 IP, `assigned_addr`는 DHCP 서버가 준 IP, `mac`은 MAC, `host_name`은 PC가 알려 준 자기 이름, `msg_types`는 메시지 종류(DISCOVER, OFFER, REQUEST, ACK, INFORM)예요.

```text
_time                     client_addr   assigned_addr  mac                host_name        msg_types
2018-05-11 02:06:51.484   10.0.14.129   10.0.14.129    00:1a:92:06:5c:7b  Chicago-7fa3-PC  REQUEST ACK
2018-05-11 02:06:54.702   10.0.14.129                  00:1a:92:06:5c:7b  Chicago-7fa3-PC  INFORM ACK
2018-05-11 02:08:03.883   10.0.14.129                  00:1a:92:06:5c:7b  Chicago-7fa3-PC  INFORM ACK
2018-05-11 02:10:16.166   10.0.14.129                  00:1a:92:06:5c:7b  Chicago-7fa3-PC  INFORM ACK
2018-05-11 02:21:51.705   10.0.14.129   10.0.14.129    00:1a:92:06:5c:7b  Chicago-7fa3-PC  REQUEST ACK
2018-05-11 02:36:51.763   10.0.14.129   10.0.14.129    00:1a:92:06:5c:7b  Chicago-7fa3-PC  REQUEST ACK
```

**결과 읽기:** MAC은 어디서나 하나뿐이고 ASUS 랜카드예요. 호스트 이름은 **Chicago-7fa3-PC**, 전체 이름은 `chicago-7fa3-pc.nightdew.org`. REQUEST/ACK가 정확히 **15분마다**(02:06:51 → 02:21:51 → 02:36:51) 나오는 건 임대 갱신이에요. INFORM은 Windows가 프록시 설정 같은 추가 정보를 물어보는 거고요. **DHCP는 정상**이에요. 이상한 점이 없다는 것도 알아 둘 만한 결과입니다.

### 2-2. Kerberos { #kerberos }

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && protocols == krb5
```

SPIView → **krb5**:

```text
cname   chicago-7fa3-pc$ (4)  CHICAGO-7FA3-PC$ (2)  faith.hoffman (2)
Realm   NIGHTDEW.ORG (21)  NIGHTDEW (2)  nightdew.org (2)
sname   krbtgt/NIGHTDEW.ORG (7)  cifs/nightdew-dc.nightdew.org (3)  ldap/Nightdew-DC.nightdew.org (3)
        LDAP/Nightdew-DC.nightdew.org (2)  chicago-7fa3-pc$@NIGHTDEW.ORG (2)  krbtgt/NIGHTDEW (2) ...
```

- 끝에 **`$`가 붙은 이름**은 **컴퓨터 계정**(PC 자신)이고, `$`가 없는 이름이 **사람 계정**이에요. 여기서 사람은 **faith.hoffman** 한 명뿐입니다.

!!! question "질문: cname과 sname의 차이는 무엇인가요?"
    Kerberos 요청에는 항상 **"누가"**와 **"무엇을 쓰려고"**가 들어 있어요.

    - **cname(client name)** — 요청한 쪽, "나는 누구다". 사람 계정(`faith.hoffman`)이나 컴퓨터 계정(`CHICAGO-7FA3-PC$`).
    - **sname(service name)** — 쓰려는 서비스, `서비스종류/서버이름` 모양이에요.
        - `krbtgt/NIGHTDEW.ORG` — 로그인할 때 맨 처음 받는 **입장권(TGT)**
        - `cifs/nightdew-dc.nightdew.org` — DC의 **파일 공유(SMB)**. 로그인 스크립트, 그룹 정책을 가져갈 때 써요.
        - `ldap/Nightdew-DC...` — DC의 **디렉터리(LDAP)** 조회
        - `host/chicago-7fa3-pc...`, `chicago-7fa3-pc$` — **PC 자기 자신**을 위한 티켓

    그래서 "faith.hoffman(cname)이 krbtgt(sname)를 요청했다" = **"faith.hoffman이 도메인에 로그인했다"**는 뜻이에요.

**Splunk** (요약):

```spl
index=zeek sourcetype=zeek:kerberos pcap_case=20180511_NIGHT_DEW
| stats count by request_type client service success
```

- `stats count by ...`: 아래 칸 조합별로 몇 번 나왔는지 셉니다.
- `request_type`: **AS**는 처음 로그인(TGT 요청), **TGS**는 서비스용 티켓 요청, **AP**는 받은 티켓을 서비스에 보여 주는 단계예요.
- `client`는 `계정/도메인`, `service`는 sname, `success`는 성공 여부(true/false)예요.

```text
request_type  client                         service                                   success  count
AP            /NIGHTDEW.ORG                  LDAP/Nightdew-DC.nightdew.org/nightdew.org true     6
AS            CHICAGO-7FA3-PC$/NIGHTDEW.ORG  krbtgt/NIGHTDEW.ORG                       false    1
AS            CHICAGO-7FA3-PC$/NIGHTDEW.ORG  krbtgt/NIGHTDEW.ORG                       true     1
AS            faith.hoffman/NIGHTDEW         krbtgt/NIGHTDEW                           false    1
AS            faith.hoffman/NIGHTDEW         krbtgt/NIGHTDEW.ORG                       true     1
TGS           CHICAGO-7FA3-PC$/NIGHTDEW.ORG  cifs/nightdew-dc.nightdew.org             true     2
...
```

!!! question "질문: 마지막 SPL 쿼리에 Kerberos 티켓을 요청한 호스트의 IP는 못 넣나요?"
    넣을 수 있어요. Zeek의 모든 로그에는 연결 정보가 같이 들어 있어서, `kerberos.log`에도 `id_orig_h`(요청한 IP)와 `id_resp_h`(DC)가 있어요. 시각까지 넣으면 **언제 로그인했는지**도 보여요.

    ```spl
    index=zeek sourcetype=zeek:kerberos pcap_case=20180511_NIGHT_DEW client="faith.hoffman*"
    | table _time id_orig_h id_resp_h request_type client service success error_msg
    | sort _time
    ```

    - 1줄 `client="faith.hoffman*"`: 사람 계정 줄만 남겨요. 값이 `faith.hoffman/NIGHTDEW`처럼 뒤에 도메인이 붙어서 `*`를 붙였어요.
    - 2줄: 시각, 요청한 IP, DC IP, 요청 종류, 계정, 서비스, 성공 여부, **오류 메시지**를 표로 보여 줘요.
    - 3줄: 시간 순서로 정렬합니다.

    ```text
    _time                id_orig_h    id_resp_h  request_type  client                  service              success  error_msg
    2018-05-11 02:..:..  10.0.14.129  10.0.14.3  AS            faith.hoffman/NIGHTDEW  krbtgt/NIGHTDEW      false    <..>
    2018-05-11 02:..:..  10.0.14.129  10.0.14.3  AS            faith.hoffman/NIGHTDEW  krbtgt/NIGHTDEW.ORG  true     -
    ```

    `false`가 있다고 바로 "비밀번호 틀림"으로 보면 안 돼요. Windows는 보통 첫 AS 요청을 비밀번호 증명 없이 보내고, DC가 **`KDC_ERR_PREAUTH_REQUIRED`**("증명을 붙여서 다시 보내라")로 거절한 뒤, 두 번째에 성공해요. 그래서 **`error_msg`를 꼭 같이** 봐야 합니다.

    client가 `/NIGHTDEW.ORG`처럼 이름 없이 나오는 **AP** 줄도 정상이에요. AP 단계에서 사용자 이름은 암호화된 티켓 안에 있어서 Zeek이 볼 수 없거든요.

**결과 읽기:** IP 10.0.14.129, MAC 00:1a:92:06:5c:7b, 호스트 Chicago-7fa3-PC(DHCP 이름과 Kerberos 컴퓨터 계정 `CHICAGO-7FA3-PC$`가 일치 — 두 프로토콜이 서로를 뒷받침), 사용자 **faith.hoffman**, DC/KDC 10.0.14.3.

!!! note "티켓 원칙: 핵심 발견만"
    티켓에는 **핵심 발견만** 넣어요. 베이스라인(캡처 시간, DHCP·Kerberos 세부)과 그때 쓴 쿼리는 넣지 않습니다. 1~2단계에서 티켓에 남는 건 PC 정보뿐이에요.

    ```text
    Infected host (suspected)
      IP address : 10.0.14.129
      MAC address: 00:1a:92:06:5c:7b (ASUSTek)
      Host name  : Chicago-7fa3-PC (chicago-7fa3-pc.nightdew.org)
      User       : faith.hoffman
    ```

---

## 3단계 — HTTP 먼저: 체크인과 다운로드 { #http }

!!! question "질문: HTTP 커넥션을 먼저 봐야 하지 않나요?"
    맞아요. 처음 보는 PCAP에서는 HTTP를 먼저 보는 게 더 좋은 순서예요.

    - **암호화가 안 돼 있어요.** URL, 파일 이름, User-Agent, 실제 파일 종류까지 다 보여요. TLS는 서버 이름 정도밖에 안 보여요.
    - **감염은 보통 무언가를 내려받는 데서 시작**하고, HTTP로 오는 경우가 많아서 **감염이 시작된 시점**을 찾기 좋아요.
    - **양이 적어요.** HTTP 26개 세션은 처음부터 끝까지 시간 순서로 다 읽을 수 있어요.

    "가장 많이 접속한 IP"부터 따라가도 되지만, 이야기 중간부터 보게 됩니다.

### 3-1. 용의자 IP는 어떤 이름이었나 (DNS) { #dns }

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && ip.dns == [185.174.175.14, 185.43.223.6]
```

- `ip.dns`: DNS **응답** 안에 들어 있는 IP예요. `[A, B]`는 A 또는 B라는 뜻이에요.

```text
02:08:04  10.0.14.129 -> 10.0.14.3:53  lysedsohap.com     -> 185.43.223.6
02:08:12  10.0.14.129 -> 10.0.14.3:53  lysedsohap.com     -> 185.43.223.6
02:10:16  10.0.14.129 -> 10.0.14.3:53  robwassotdint.ru   -> 185.174.175.14
02:40:16  10.0.14.129 -> 10.0.14.3:53  robwassotdint.ru   -> 185.174.175.14
```

**결과 읽기:**

- 두 이름 다 **의미 없는 글자를 이어 붙인** 모양이에요. 회사나 서비스 이름 같지 않죠. 악성코드 도메인에서 흔한 모양이에요(의심 근거이지 증거는 아님).
- `robwassotdint.ru`는 **정확히 30분 간격**(02:10:16 → 02:40:16)으로 질의됐어요. 사람이 초 단위까지 같은 간격으로 같은 사이트를 다시 찾지는 않아요. DNS 캐시가 만료됐거나, 프로그램이 정해진 간격으로 동작하는 거예요.
- `lysedsohap.com`(02:08)이 `robwassotdint.ru`(02:10)보다 **먼저**예요. 로그인 2분 뒤죠. HTTP를 볼 때 **02:08 전후**를 특히 보세요.

### 3-2. HTTP 전체를 시간 순서로 { #http-list }

**Arkime:** `tags == 20180511_NIGHT_DEW && protocols == http` → **Start Time** 정렬 → **SPIView → http**에서 Host, URI, User-Agent, Method, Status를 한눈에 봅니다. 수상한 세션은 `+`로 펼쳐서 헤더와 본문을 봐요.

**Splunk** (26개를 표 하나로):

```spl
index=zeek sourcetype=zeek:http pcap_case=20180511_NIGHT_DEW
| sort _time
| table _time id_resp_h host method uri status_code resp_mime_types response_body_len user_agent
```

- `id_resp_h` 서버 IP · `host` HTTP Host 헤더(pcapbox가 Splunk의 `host` 필드에 넣어요) · `method` GET/POST · `uri` 경로 · `status_code` 200/404 등 · `resp_mime_types` Zeek이 **내용을 보고** 판단한 파일 종류 · `response_body_len` 응답 크기 · `user_agent` 요청한 프로그램

```text
_time          id_resp_h       host               method  uri                                          status  mime        len     user_agent
02:07:02.035   173.223.52.18   www.msftncsi.com   GET     /ncsi.txt                                    200     text/plain  14      Microsoft NCSI
02:08:04.098   184.72.249.110  api.ipify.org      GET     /                                            200     text/plain  14      Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
02:08:04.575   185.43.223.6    lysedsohap.com     POST    /4/forum.php                                 200     text/plain  1436    Mozilla/5.0 (... Trident/7.0; rv:11.0) like Gecko
02:08:05.391   111.90.144.30   wansaiful.com      GET     /wp-content/plugins/easy-media-download/1    200                 46341   Mozilla/5.0 (... rv:11.0) like Gecko
02:08:12.248   185.43.223.6    lysedsohap.com     POST    /mlu/forum.php                               200                 20      Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ...)
02:08:13.732   111.90.144.30   wansaiful.com      GET     /wp-content/plugins/easy-media-download/2    200                 47383   Mozilla/5.0 (... rv:11.0) like Gecko
02:08:14.493   111.90.144.30   wansaiful.com      GET     /wp-content/plugins/easy-media-download/3    200                 159255  Mozilla/5.0 (... rv:11.0) like Gecko
02:08:14.739   185.43.223.6    lysedsohap.com     POST    /d2/about.php                                200                 13      Mozilla/4.0 (compatible; MSIE 7.0; ...)
02:10:15.697   185.43.223.6    lysedsohap.com     POST    /4/forum.php                                 200     text/plain  12      Mozilla/5.0 (... rv:11.0) like Gecko
02:12:16.219   185.43.223.6    lysedsohap.com     POST    /4/forum.php                                 200     text/plain  12      ...
... 02:48:25까지 약 2분마다 ...
```

**HTTP 목록에서 늘 확인할 것:** `resp_mime_types`가 `application/x-dosexec`(exe나 dll), zip, 오피스 문서, 스크립트인지 — 특히 URI 확장자와 실제 종류가 다른 경우. host가 도메인이 아니라 IP 숫자인지. User-Agent가 없거나 이상한지. POST가 있는지. DNS에서 찾은 용의자 이름이 나오는지.

### 3-3. HTTP를 한 줄씩 읽기 { #http-reading }

**① 02:07:02 `www.msftncsi[.]com/ncsi.txt` — 정상.** User-Agent가 `Microsoft NCSI`, 응답도 `Microsoft NCSI`(14바이트)예요. Windows가 로그인 직후 "인터넷 연결됐나?"를 확인하는 동작이에요. 정상을 확실히 걸러 내는 것도 분석의 일부예요.

**② 02:08:04.098 `api.ipify[.]org/` — 의심 시작.** ipify는 "내 공인 IP가 뭐야?"를 알려 주는 서비스예요. 사람이 직접 찾아갈 일은 거의 없고, 프로그램이 **자기가 어디서 실행 중인지** 알아낼 때 써요. 응답 크기 **14바이트**를 기억해 두세요.

**③ 02:08:04.575 POST `lysedsohap[.]com/4/forum.php` — 결정적 증거.** Arkime에서 세션을 펼치면 요청 본문이 이래요.

```text
GUID=10412771973665002240&BUILD=09fhx05&INFO=CHICAGO-7FA3-PC @ NIGHTDEW\faith.hoffman&IP=173.236.56.182&TYPE=1&WIN=6.1(x64)
```

감염된 PC가 **자기 정보를 C2 서버에 신고하는 것(체크인)**이에요.

- `INFO=` — 2단계에서 찾은 호스트 이름과 `도메인\사용자`가 그대로 들어 있어요.
- `IP=173.236.56.182` — 이 문자열이 정확히 **14글자**예요. 0.5초 전 ipify 응답이 14바이트였죠. **ipify로 알아낸 공인 IP를 바로 보고**한 거예요. 두 요청이 같은 프로그램에서 나왔다는 강한 증거예요.
- `WIN=6.1(x64)` — Windows 7 64비트. `GUID`, `BUILD` — 감염 PC 번호와 악성코드 버전으로 보여요.
- User-Agent는 IE11인 척하고 있어요.

응답 1,436바이트는 base64처럼 생긴 글자예요. 사람이 보는 웹페이지가 아니라 **암호화된 명령**이에요([3-4](#decode)에서 풉니다).

**④ 02:08:05–02:08:14 GET `wansaiful[.]com/wp-content/plugins/easy-media-download/1`, `/2`, `/3`.** 체크인 1초 뒤 다른 서버에서 46,341 / 47,383 / 159,255바이트를 받아요. 눈여겨볼 점 세 가지: **WordPress 플러그인 경로**(해킹된 WordPress 사이트는 악성 파일 보관소로 흔히 쓰여요), 확장자 없는 파일 이름 `1`, `2`, `3`, 그리고 **비어 있는 `resp_mime_types`**(Zeek이 내용을 보고도 종류를 모름 — 평범한 exe라면 `application/x-dosexec`가 나와요. 그러니 **암호화된 파일**일 가능성이 높아요).

**⑤ 02:08:12 `/mlu/forum.php`, 02:08:14 `/d2/about.php` — User-Agent가 바뀌었어요.** 같은 서버인데 `Mozilla/4.0 (compatible; MSIE 7.0; ...)`예요. 같은 PC에서 **다른 프로그램**이 접속한 거예요. ④에서 받은 파일 중 하나가 실행돼서 자기 방식으로 보고했을 가능성이 높아요. MSIE 7.0은 2018년 Windows 7 PC가 쓸 브라우저도 아니고요. 이 POST 두 개가 무엇을 보냈는지는 [3-6](#exfil)에서 봅니다.

**⑥ 02:10:15–02:48:25 POST `/4/forum.php`가 약 120초마다.** 02:10:15, 02:12:16, 02:14:16, 02:16:17 … 02:48:25(20번). Arkime에서 세션마다 **573 / 1,183바이트**로 크기가 똑같고, 응답은 매번 12바이트예요. 사람은 이렇게 못 해요. **비콘** — "명령 있어?" 하고 정기적으로 묻는 C2 통신이에요.

**⑦ 02:10:16 `robwassotdint[.]ru` 첫 DNS 질의** — 다운로드 2분 뒤에 새 목적지가 나타나요. [4단계](#tls)에서 봅니다.

**최초 감염 경로는 이 캡처에 없어요.** 캡처는 로그인(02:06:51)부터 시작하고, 73초 뒤에 이미 체크인을 해요. 그 전에 메일, 문서, 익스플로잇 다운로드가 없어요. 그러니 **PC는 이미 감염돼 있었고**, 로그인할 때 악성코드가 자동 실행된 거예요. 티켓에는 "초기 감염 경로는 이 캡처에서 관찰되지 않음"이라고 씁니다.

### 3-4. C2 응답을 CyberChef로 풀기 { #decode }

**목적:** ③의 1,436바이트 응답을 읽을 수 있는 글로 바꿉니다.

**알아보고 푸는 순서:**

1. **base64인가?** 글자가 `A–Z a–z 0–9 + /`(그리고 `=`)로만 되어 있어요. 그런데 base64로 풀면 읽을 수 없는 바이트가 나와요. **한 겹 더** 감싸져 있다는 뜻이에요.
2. **1바이트 XOR이 흔해요.** 1바이트 키는 **256가지**뿐이라 전부 해 보면 돼요(**brute force**). 맞는 키를 고르려면 정답에 나올 글자인 **crib(크립)**을 줘요. 이 응답 직후 PC가 파일을 받았으니 응답에 주소가 있을 것 → crib은 **`http`**.
3. 키 **`0x7a`**(문자 `z`)에서만 `{l:http://wansaiful.com/wp-content/plugins/easy-media-dow...`가 나왔어요.

**CyberChef 레시피:**

1. Arkime에서 응답 본문(Destination 쪽)을 처음부터 끝까지 복사합니다.
2. Recipe에 **From Base64**를 넣어요.
3. 그 아래 **XOR Brute Force**를 넣고 Key length `1`, Crib `http`. 키 `7a` 줄에 `{l:http://...`가 보여요.
4. XOR Brute Force를 **XOR**(Key `7a`, **HEX**)로 바꾸면 전체가 풀려요.

**결과:**

```text
bÙ©{l:http://wansaiful.com/wp-content/plugins/easy-media-download/1|http://www.victoryoutreachvallejo.com/wp-content/plugins/regenerate-thumbnails/includes/1|http://medleysoup.com/wp-content/plugins/comicpress-manager/1|http://radiantheartcoaching.com/blog/wp-content/themes/twentyten/1|http://hdmicablereviews.com/wp-content/plugins/google-sitemap-generator/1}{b:http://wansaiful.com/wp-content/plugins/easy-media-download/2|http://www.victoryoutreachvallejo.com/wp-content/plugins/regenerate-thumbnails/includes/2|http://medleysoup.com/wp-content/plugins/comicpress-manager/2|http://radiantheartcoaching.com/blog/wp-content/themes/twentyten/2|http://hdmicablereviews.com/wp-content/plugins/google-sitemap-generator/2}{r:http://wansaiful.com/wp-content/plugins/easy-media-download/3|http://www.victoryoutreachvallejo.com/wp-content/plugins/regenerate-thumbnails/includes/3|http://medleysoup.com/wp-content/plugins/comicpress-manager/3|http://radiantheartcoaching.com/blog/wp-content/themes/twentyten/3|http://hdmicablereviews.com/wp-content/plugins/google-sitemap-generator/3}
```

**결과 읽기:**

- 응답은 **"이 주소들에서 파일을 받아라"는 명령**이었고, 1초 뒤 다운로드가 일어났어요. 응답과 행동이 정확히 이어져요.
- 명령 코드 세 개(`l`, `b`, `r`)에 파일 번호가 하나씩(1, 2, 3)이에요. 글자마다 무슨 동작(실행, 주입 등)인지는 트래픽만으로 알 수 없어서 "명령 코드"라고만 부릅니다.
- 명령마다 **사이트가 5개**예요. 첫 번째가 안 되면 다음으로 넘어가는 예비 주소예요. PC는 첫 번째만 썼어요.
- 다섯 곳 모두 WordPress 경로(`wp-content/plugins`, `themes`)예요. 해킹된 WordPress 사이트를 파일 보관소로 쓴 거예요.
- 맨 앞 3바이트(`bÙ©`)는 의미를 알 수 없는 머리말이라 티켓에서 빼요.

!!! warning "직접 확인한 값만 티켓에 넣으세요"
    스크린샷을 OCR로 읽어 푼 결과는 몇 글자가 틀릴 수 있어요. 티켓에 주소를 적기 전에 **원본 텍스트**를 직접 CyberChef로 풀어 보세요.

!!! question "질문: 위에서 CyberChef에 넣는 이유는 무엇인가요? 설명해 주세요."
    **CyberChef**는 영국 GCHQ가 공개한 브라우저용 데이터 변환 도구예요. 요리처럼 **Input(재료)** → **Recipe(작업을 순서대로 쌓기: base64, XOR, 압축 풀기 등)** → **Output(결과, 바로바로 보임)**. 코드 없이 여러 단계를 이을 수 있고, 레시피를 저장하거나 티켓에 적어 두면 다른 분석가가 **똑같이 재현**할 수 있어요. 실무에서는 **오프라인 버전**(HTML 파일 하나)을 쓰세요. 증거를 웹사이트에 붙여 넣으면 정보가 밖으로 나갈 수 있어요.

    **왜 base64를 먼저, XOR을 나중에?** 서버가 명령을 두 겹으로 포장했어요. (1) `{l:http://...}`를 XOR로 섞어 깨진 바이트로 만들고, (2) 그 바이트를 HTTP로 보내기 쉽게 base64 글자로 바꿨어요. 푸는 쪽은 **거꾸로** — 마지막에 싼 것부터 벗깁니다.

    **왜 숨겼을까?** `http://wansaiful.com/...1`이 그대로 보이면 IDS나 프록시가 쉽게 잡아요. 한 번 섞어 두면 단순한 탐지를 피할 수 있어요. 대신 키가 1바이트라 분석가는 금방 풀어요.

    **XOR Brute Force와 crib.** XOR은 같은 키로 한 번 더 하면 원래대로 돌아와요. 키만 알면 돼요. 1바이트면 256번만 해 보면 되고, crib(`http`)은 256개 결과 중 정답을 골라 줘요. **crib은 트래픽에서 본 행동**(응답 직후 다운로드)을 근거로 정한 거예요. 그냥 찍은 게 아니에요.

    **풀기 전에도 힌트가 있었어요.** base64 글자에 **`Eg4OCkBV`**가 여러 번 반복돼요. 계산해 보면:

    ```text
    원문         h    t    t    p    :    /
    XOR 0x7a     12   0e   0e   0a   40   55
    base64       E g 4 O         C k B V
    ```

    `Eg4OCkBV` = `http:/`를 XOR한 뒤 base64로 바꾼 모양이에요. 주소가 15개라 계속 반복된 거죠. **인코딩된 덩어리에 같은 조각이 반복되면, 원문에도 반복이 있고 키가 짧고 고정돼 있을** 가능성이 높아요. 진짜 암호화(AES 등)는 이런 반복이 안 보여요.

    **`http`로 안 나오면?** Key length를 2, 4로 늘려 보고, crib을 바꿔 봐요(`MZ`는 exe, `<html`, `{`). 그래도 안 되면 진짜 암호화일 가능성이 커서, 악성코드 파일을 리버싱해 키를 찾아야 해요.

    Arkime에도 **Unbase64**, **UnXOR Brute** 버튼이 있지만, CyberChef는 단계를 자유롭게 잇고 재현 가능한 레시피를 남길 수 있어요.

**예비 사이트에 접속했는지 확인.** 티켓에 나머지 4곳에 접속했는지 적어야 해요.

```text
tags == 20180511_NIGHT_DEW && host == [www.victoryoutreachvallejo.com, medleysoup.com, radiantheartcoaching.com, hdmicablereviews.com]
```

- `host`: DNS, HTTP, TLS의 서버 이름을 한꺼번에 찾는 필드예요.

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180511_NIGHT_DEW query IN ("www.victoryoutreachvallejo.com","medleysoup.com","radiantheartcoaching.com","hdmicablereviews.com")
| table _time query answers
```

- `query IN (...)`: DNS로 물어본 이름이 목록 중 하나인 것만 남겨요.

**결과: 두 도구 모두 없음.** 첫 사이트에서 다 받았으니 예비 사이트로 넘어갈 필요가 없었던 거예요. 그래도 이 4곳은 **공격자 인프라**라서, 다른 PC가 여기에 접속했다면 같은 악성코드에 감염됐다는 강한 단서예요. 그래서 IOC에 "접속 안 함"으로 남겨요.

**비콘 응답도 풀어 보기.** 비콘의 요청 본문은 첫 체크인과 **똑같아요**(같은 `GUID=...&INFO=...`, `Content-Length: 123`). 12바이트 응답은 `TGTGARRABw==`예요. 같은 레시피(From Base64 → XOR `7a`)로 풀면:

```text
(머리말 3바이트) {n:}
```

첫 응답은 주소로 가득했는데, 이건 명령 글자만 있고 **내용이 비어 있어요** → "지금은 할 일 없음". 비콘 응답이 매번 12바이트로 똑같았던 이유예요. 한 번 방법을 알아내면 나머지 응답에도 그대로 써 보는 게 좋은 습관이에요.

**티켓 기록:**

```text
[261121 2014, Lee] C2 check-in from 10.0.14.129 to lysedsohap.com - Found
[261121 2049, Lee] Decode of C2 check-in reply - Found
[261121 2100, Lee] Contact with fallback payload sites - Not Found
```

### 3-5. 받은 파일 3개의 정체 { #files }

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && host.http == wansaiful.com
```

세션을 펼쳐서 **응답 본문의 시작 부분**을 보세요. Windows 실행 파일은 `MZ`로 시작하고, 조금 뒤에 `This program cannot be run in DOS mode`가 보여요. **보기만 하고 내려받거나 실행하지 마세요.**

**Splunk (`files.log`):**

```spl
index=zeek sourcetype=zeek:files pcap_case=20180511_NIGHT_DEW tx_hosts="111.90.144.30"
| table _time tx_hosts rx_hosts mime_type seen_bytes total_bytes md5 sha1
```

- `tx_hosts="111.90.144.30"` 그 서버가 **보낸** 파일만 · `mime_type` 내용을 보고 판단한 종류 · `seen_bytes` 캡처에서 실제로 본 크기 · `total_bytes` 서버가 알려 준 원래 크기(같으면 **끝까지 받은 것**) · `md5`, `sha1` IOC용 해시

```text
_time          tx_hosts       rx_hosts      mime_type  seen_bytes  total_bytes  md5                               sha1
02:08:05.661   111.90.144.30  10.0.14.129              46341       46341        ae9dfd2190b07927078cb4a19d0b2187  3f329bbc23037dae9ca3ec59cef5af9d27fc2581
02:08:13.972   111.90.144.30  10.0.14.129              47383       47383        74eb0ec9c04ddf315053773aba5bcb01  05e9e5bb412a6efdae73a2063b8f7a09bedfd7f5
02:08:14.743   111.90.144.30  10.0.14.129              159255      159255       b799ac083efb27e51c46ea1542f89b12  ad2ad300cd79496bce063b3624e0bf3e26da16ae
```

**결과 읽기:**

1. **실행 파일이 아니라 암호화된 덩어리예요.** `MZ`도, 읽을 수 있는 글자도 없어요. Zeek은 `mime_type`을 비워 두고, Arkime의 libfile도 `application/octet-stream`(정체 모를 바이너리)으로만 봐요.
2. **서버가 거짓말을 해요.** 헤더는 `Content-Type: text/plain`인데 내용은 텍스트가 아니에요. 헤더는 서버가 마음대로 쓰는 값이니, **내용을 보고** 판단해야 해요(Zeek과 Arkime libfile이 하는 방식).
3. **왜 암호화했을까?** 네트워크 장비가 "exe 다운로드"를 못 보게 하려는 거예요. 다운로더가 받아서 **메모리 안에서 풀어** 실행해요. 푸는 키는 다운로더 안에 있어서 트래픽만으로는 못 풀어요 — 리버싱의 영역이라 네트워크 분석은 여기까지예요.
4. **연결 하나로 세 파일.** Arkime는 세션 하나(포트 49199)에 `Method GET (3)`, Body MD5 3개로 보여 줘요(**keep-alive**). Zeek은 파일 3개로 나눠 보여 주고요. 같은 사건을 두 도구가 다르게 보여 주는 좋은 예예요.
5. **도구끼리 일치, 파일은 완전.** Arkime Body MD5와 Zeek `md5`가 같고, `seen_bytes = total_bytes`예요 → 세 파일 모두 끝까지 받았어요. 다운로드가 실패했을 가능성은 없어요.
6. **Last-Modified** `2018-05-10 13:29:43 / 13:29:50 / 13:29:58 GMT`: 감염 **하루 전에 8초 간격으로** 올라갔어요. 이번 공격을 막 준비했다는 단서예요. `X-Powered-By: PleskLin`은 웹 호스팅 관리 프로그램이라, 해킹된 호스팅 사이트라는 해석과 맞아요.
7. **서버 시계는 믿지 마세요.** 응답의 `Date: 02:02:54 GMT`는 실제 패킷 시각(02:08:05)과 5분 차이 나요. 타임라인은 **패킷 시각**으로 만들어요.
8. **이 해시는 암호화된 상태의 해시예요.** PC에서 실제로 실행된 파일(복호화된 것)의 해시와는 달라서, 해시를 조회해도 안 나올 수 있어요. 대신 **네트워크 IOC**("이 파일이 다시 내려오나?")로는 정확해요.

!!! tip "해시는 옮겨 쓰지 말고 복사하세요"
    해시는 Splunk 결과에서 그대로 복사하세요. 한 글자만 틀려도 IOC로 쓸 수 없어요.

**티켓 기록:**

```text
[261121 2106, Lee] Follow-up payload downloads from wansaiful.com - Found
```

---

### 3-6. 두 번째 구성 요소의 POST 2개 — 무엇을 내보냈나 { #exfil }

**목적:** POST는 PC가 무언가를 **보냈다**는 뜻이에요. ⑤에서 다른 프로그램이 보낸 POST 2개를 봤죠. 넘어가기 전에 무엇을 보냈는지 확인해요. 작은 POST에도 훔친 비밀번호가 들어 있을 수 있어요.

**Splunk — POST 전체를 표 하나로:**

```spl
index=zeek sourcetype=zeek:http pcap_case=20180511_NIGHT_DEW method=POST
| stats count sum(request_body_len) as sent_bytes values(user_agent) as user_agent by uri
| sort - count
```

- 1줄 `method=POST`: 데이터를 보내는 요청만 남겨요.
- 2줄 `stats ... by uri`: 경로마다 한 줄로 요약해요. `count`는 몇 번, `sum(request_body_len) as sent_bytes`는 PC가 **요청 본문**으로 보낸 바이트 합계예요(`request_body_len`은 보낸 쪽, `response_body_len`은 받은 쪽). `values(user_agent)`는 그 경로에 나온 User-Agent를 모두 보여 줘요.
- 3줄 `sort - count`: 많이 나온 순서로.

```text
uri              count  sent_bytes  user_agent
/4/forum.php     21     2583        Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
/mlu/forum.php   1      206         Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ...)
/d2/about.php    1      234         Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ...)
```

`/4/forum.php`는 21 × 123바이트, 체크인과 비콘이에요. 나머지 둘은 **딱 한 번씩**만 보냈어요.

**Arkime — 헤더 읽기:**

```text
tags == 20180511_NIGHT_DEW && http.request.content-type == application/octet-stream
```

- `http.request.content-type`: **요청** 본문(PC가 보낸 것)의 종류예요. SPIView → http에서 `application/octet-stream`을 누르고 **and**를 고르면 자동으로 들어가요.

세션 2개가 나와요. 둘 다 펼쳐 보세요.

```text
02:08:12  10.0.14.129:49200 -> 185.43.223.6:80
POST /mlu/forum.php HTTP/1.0
Host: lysedsohap.com
Accept: */*
Accept-Encoding: identity, *;q=0
Accept-Language: en-US
Content-Length: 206
Content-Type: application/octet-stream
Connection: close
Content-Encoding: binary
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; ...)

(206바이트 바이너리 — 읽을 수 없음)

02:08:14  10.0.14.129:49202 -> 185.43.223.6:80
POST /d2/about.php HTTP/1.0
... (헤더 모양 같음)  Content-Length: 234
```

**결과 읽기 — 체크인과 비교:**

| 항목 | 체크인 `/4/forum.php` | 이 POST 2개 |
|---|---|---|
| HTTP 버전 | 1.1 | **1.0** |
| User-Agent | IE11 (`rv:11.0`) | **MSIE 7.0** |
| 본문 | 읽을 수 있는 `GUID=...` | **암호화된 바이너리**(`application/octet-stream`) |
| 이상한 헤더 | 없음 | **`Content-Encoding: binary`** |
| 횟수 | 2분마다 | **한 번씩** |

1. **서버는 같은데 프로그램이 달라요.** 헤더 습관이 전부 달라요. [3-5](#files)에서 받은 파일 중 하나가 실행돼서 보낸 것으로 보여요(02:08:12는 `/1`과 `/2` 다운로드 사이이고, `/3`은 02:08:14에 끝나요).
2. **`Content-Encoding: binary`는 HTTP 표준에 없는 값이에요.** 표준은 `gzip`, `deflate`, `br` 같은 거예요. 이렇게 지어낸 헤더는 **그 악성코드 코드의 지문**이라 탐지에 좋아요.
3. **한 번 보내고 끝**은 비밀번호 탈취 프로그램과 맞는 모양이에요. 브라우저, 메일, FTP 프로그램에 저장된 비밀번호를 모아 한 번에 올리고 끝내요. 이 헤더 모양은 알려진 탈취 악성코드 계열의 특징으로 보고돼 있지만([첫 번째 분석](night-dew-hancitor-pony-zeus-panda-tls-c2.md#exfil)에 이름이 있어요), 이번에는 해시 조회나 샌드박스가 없으니 계열은 **확인 안 됨**으로 둬요.
4. **내용이 암호화돼 있으니 털린 것으로 봐요.** 440바이트면 저장된 비밀번호가 적거나 없었을 수도 있어요. 하지만 무엇이 나갔는지 볼 수 없을 때는 나쁜 쪽으로 가정해요. **faith.hoffman 비밀번호를 바꾸라고** 권고해요.
5. **5단계와 이어져요.** netlogon 비밀번호 대입이 02:08:12.835에 시작하는데, `/mlu/forum.php` POST(02:08:12.248)의 **0.6초 뒤**예요. 같은 프로그램이 데이터를 보내고 바로 대입을 시작한 것으로 보여요.
6. 크기로는 못 찾아요. 440바이트는 "보낸 양이 큰 연결" 검색에 절대 안 나와요. **작아도 POST는 다 열어 보세요.**

!!! tip "Snort 룰을 하나 더 만든다면"
    POST에 `Content-Type: application/octet-stream` + `Content-Encoding: binary`가 같이 있으면, 서버가 바뀌어도 이 프로그램을 잡을 수 있어요. 이번 분석은 룰 **하나**만 만들었고([6단계](#snort)), [첫 번째 분석](night-dew-hancitor-pony-zeus-panda-tls-c2.md#snort)에 이 룰을 테스트한 버전(sid 1000013, 알림 2개)이 있어요.

**티켓 기록:**

```text
[261121 2110, Lee] Data sent to lysedsohap.com other than check-ins - Found
```

---

## 4단계 — TLS로 된 두 번째 C2 { #tls }

**목적:** 세션이 54개였던 IP를 봅니다. TLS라 내용은 못 보지만, **언제, 얼마나 자주, 얼마나 많이, 어떤 인증서로** 통신했는지는 보여요.

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && ip == 185.174.175.14
```

Start Time으로 정렬하고, 세션 하나를 펼쳐서 **TLS**와 인증서 칸을 봐요.

```text
Time          2018/05/11 02:10:16 – 02:10:17 UTC
Dst IP/Port   185.174.175.14 : 443
Hosts         robwassotdint.ru
Version       TLSv1.2
Cipher        TLS_RSA_WITH_AES_128_CBC_SHA256
JA3           4d7a28d6f2263ed61de88ca66eb011e3
JA3s          80b3a14bccc8598a1f3bbe83e71f735f
JA4           t12d210500_b973bfd88a0e_677eed04e9fb
Certificate   Serial 00becd5c26e55fc46f [86:af:39:2e:9b:42:ec:50:e2:87:f6:42:9e:f7:48:4c:48:bb:bd:95]
              Not Before 2018/04/29 19:20:31 UTC   Not After 2023/10/20 19:20:31 UTC   Days Valid For 2,000
              Issuer Org Default Company Ltd   Subject Org Default Company Ltd
```

**Splunk ① 접속 간격과 연결 상태:**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180511_NIGHT_DEW id_resp_h="185.174.175.14"
| sort _time
| delta _time as gap
| table _time id_resp_p service duration orig_bytes resp_bytes conn_state gap
```

- `sort _time` 시간 순서 · `delta _time as gap` **바로 앞 연결과 몇 초 차이**인지(비슷한 값이 반복되면 비콘) · `conn_state` 연결이 어떻게 끝났는지:
    - `SF` 정상 연결, 정상 종료 · `S0` 요청했는데 응답 없음 · `REJ` 서버가 거부 · `RSTO`/`RSTR` 중간에 강제로 끊김(O는 PC 쪽, R은 서버 쪽)

```text
_time          id_resp_p  service  duration  orig_bytes  resp_bytes  conn_state  gap
02:10:16.395   443        ssl      0.84      516         1060        SF
02:10:17.044   443        ssl      1.35      1774        6761        SF          0.65
02:10:18.407   443        ssl      0.76      548         1060        SF          1.36
02:10:18.981   443        ssl      1.32      1758        12297       SF          0.57
02:15:20.311   443        ssl      0.75      548         1060        SF          301.33
02:15:20.873   443        ssl      1.32      1854        1513        SF          0.56
...
02:40:18.725   443        ssl      2.56      1774        152790      SF          0.57
02:40:21.910   443        ssl      2.39      1774        197264      SF          0.50
02:40:24.908   443        ssl      2.38      1758        174971      SF          0.57
02:42:28.043   443        ssl      2.97      1758        403937      SF          0.57
02:42:31.691   443        ssl      2.81      1758        502927      SF          0.60
...
02:45:46.021   443        ssl      1.32      1822        1513        SF          0.58
```

**Splunk ② TLS 요약:**

```spl
index=zeek sourcetype=zeek:ssl pcap_case=20180511_NIGHT_DEW id_resp_h="185.174.175.14"
| stats count min(_time) as first max(_time) as last by server_name version cipher established
| convert ctime(first) ctime(last)
```

- `server_name` SNI(비어 있으면 그것도 단서 — 정상 브라우저는 거의 항상 보내요) · `established` 핸드셰이크 성공 여부 · `convert ctime()` epoch을 읽을 수 있는 날짜로

```text
server_name       version  cipher                           established  count  first                       last
robwassotdint.ru  TLSv12   TLS_RSA_WITH_AES_128_CBC_SHA256  true         54     05/11/2018 02:10:16.589867  05/11/2018 02:45:46.215120
```

**결과 읽기:**

1. **파일을 받고 정확히 2분 뒤 시작해요**(02:08:14 → 02:10:16). robwassotdint.ru 첫 DNS 질의와 같은 초예요. 받은 파일이 실행된 뒤 생긴 새 통신이고, `lysedsohap.com`(다운로더)과는 **별개의 두 번째 C2**예요.
2. **인증서가 결정적이에요.** Issuer = Subject = `Default Company Ltd`, `Default City`, `XX` → **자체 서명**이고, OpenSSL로 만들 때 질문마다 엔터만 치면 들어가는 **기본값**이에요. 감염 12일 전에 만들어졌고 유효 기간이 **2,000일**이에요(정상은 보통 1년 안팎).
3. **약 5분 주기**(`gap` 288–301초: 02:10, 02:15, 02:20 … 02:45)로, 묶음 안에서 **짝**으로 나와요. 정확히 **548 / 1,060바이트**인 짧은 연결(0.75초 — 핸드셰이크와 인증서만 하고 끝), 그리고 약 1.8 / 1.5 KB인 데이터 연결(1.3초). 크기와 간격이 일정 = 자동으로 동작하는 **C2 비콘**. HTTP 비콘(2분)과 주기가 달라서 다른 프로그램이라는 해석과도 맞아요.
4. **02:40–02:42에 약 1.5 MB가 내려와요**(152,790 / 197,264 / 174,971 / 403,937 / 502,927 / 22,702 / 38,723바이트). PC가 받은 2.2 MB의 대부분이 여기예요. 02:42:27 연결은 5분 주기에서도 벗어나요(gap 105초). C2가 **추가 모듈이나 설정**을 내려보낸 것으로 보여요. 내용은 암호화돼 있어서 티켓에는 크기와 시각만 적어요.
5. 54개 모두 `SF`, `established = true` — 캡처 끝(02:45:46)까지 문제없이 통신했어요.
6. `TLS_RSA_WITH_AES_128_CBC_SHA256`은 오래된 방식이에요. 그 자체로 증거는 아니지만 메모할 만해요.
7. **JA3/JA4**는 TLS 클라이언트의 "지문"이에요. Windows에서 악성코드가 시스템 TLS 라이브러리를 쓰면 브라우저와 지문이 같아질 수 있어요. IOC로 쓰기 전에 이 PC의 다른 정상 TLS 세션과 비교하세요.

!!! question "질문: Issuer CN이나 Subject CN, Issuer Org나 Subject Org는 다 같은 말인가요?"
    아니에요. **Subject(대상)** = 인증서가 누구의 것인지(서버). **Issuer(발급자)** = 누가 서명했는지(보통 인증 기관). 둘 다 이름이 여러 칸으로 나뉘어요.

    | 칸 | 뜻 |
    |---|---|
    | **CN** (Common Name) | 대표 이름. Subject CN은 보통 **도메인**(`www.example.com`), Issuer CN은 **인증 기관 이름** |
    | **O** (Organization) — Arkime에서는 **Org** | 회사·기관 이름 |
    | OU | 부서 |
    | L | 도시 |
    | ST | 주·도 |
    | C | 나라 코드 두 글자 |

    정상 서버 인증서(예시):

    ```text
    Subject : CN=www.example.com,  O=Example Corp,       C=US
    Issuer  : CN=Example CA 2018,  O=Example Trust Inc,  C=US
    ```

    이번 인증서:

    ```text
    Subject : C=XX, L=Default City, O=Default Company Ltd   (CN 없음)
    Issuer  : C=XX, L=Default City, O=Default Company Ltd   (CN 없음)
    ```

    의심할 점 세 가지: **Subject와 Issuer가 같음**(자체 서명), **값이 전부 기본값**, **Subject CN이 비어 있음** — PC는 `robwassotdint.ru`(SNI)로 접속했는데 인증서에 그 도메인이 없어요. 정상 브라우저라면 경고를 띄울 상황인데 통신이 계속됐으니, **인증서를 검사하지 않는 프로그램(악성코드)**이에요.

    Arkime 필드: `cert.subject.cn`, `cert.issuer.cn`(CN 칸) · `cert.subject.on`, `cert.issuer.on`(Org 칸). 대충 만든 C2 인증서를 찾는 헌팅 쿼리:

    ```text
    cert.issuer.on == "Default Company Ltd" && cert.subject.on == "Default Company Ltd"
    ```

    `cert.hash`는 IP나 도메인이 바뀌어도 같은 인증서를 찾아요.

    ```text
    cert.hash == 86:af:39:2e:9b:42:ec:50:e2:87:f6:42:9e:f7:48:4c:48:bb:bd:95
    ```

**티켓 기록:**

```text
[261121 2119, Lee] TLS C2 to robwassotdint.ru - Found
```

---

## 5단계 — 948 KB는 어디로 갔나? netlogon 비밀번호 대입 { #netlogon }

**목적:** 1단계에서 PC가 **948 KB를 보냈어요.** 그런데 C2 통신은 보내는 양이 다 작아요(HTTP POST 수백 바이트, TLS 연결당 2 KB — 다 합쳐 100 KB 남짓). 800 KB 넘게 외부로 나갔다면 유출이에요.

### 5-1. 보낸 양이 큰 연결 { #top-sent }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180511_NIGHT_DEW id_orig_h="10.0.14.129"
| sort - orig_bytes
| head 10
| table _time id_resp_h id_resp_p service duration orig_bytes resp_bytes
```

- `sort - orig_bytes` **보낸 양**이 큰 순서 · `head 10` 위에서 10개만

```text
_time          id_resp_h  id_resp_p  service            duration  orig_bytes  resp_bytes
02:08:12.835   10.0.14.3  49158      dce_rpc            32.30     779560      231472
02:06:52.227   10.0.14.3  49155      krb,gssapi,dce_rpc 82.91     5859        2854
02:06:52.489   10.0.14.3  445        gssapi,smb,krb     35.61     4342        1558
02:07:30.743   10.0.14.3  445        gssapi,smb,krb     141.35    4187        1306
02:22:49.204   10.0.14.3  445        gssapi,smb,krb     14.88     3853        1200
02:37:49.223   10.0.14.3  445        gssapi,smb,krb     14.86     3853        1200
02:07:49.183   10.0.14.3  445        gssapi,smb,krb     14.90     3694        948
02:21:29.442   10.0.14.3  389        ldap_tcp,krb,gssapi 0.24     3530        3835
02:06:58.781   10.0.14.3  389        krb,gssapi,ldap_tcp 0.03     2934        472
02:06:58.771   10.0.14.3  389        ldap_tcp,krb,gssapi 0.04     2765        3169
```

**결과 읽기:**

- **연결 하나가 거의 전부예요.** **DC**(10.0.14.3:49158, DCE/RPC)로 779,560바이트. 나머지는 몇 KB짜리 정상 도메인 통신(SMB 445, LDAP 389, Kerberos)이에요.
- 그러니 **외부로 큰 업로드는 없었어요.** 티켓에 쓸 중요한 결론이에요. C2 통신 말고 밖으로 나간 데이터는 [3-6](#exfil)의 작은 암호화 POST 2개뿐이에요.
- 하지만 이 연결도 정상이 아니에요. 시작이 **02:08:12.835**, MSIE 7.0으로 `/mlu/forum.php`에 POST한 순간(02:08:12.248)의 0.6초 뒤예요. 그리고 로그인 때의 RPC 연결(02:06:52)은 5.8 KB뿐이었어요. **어떤 RPC 기능을 불렀는지** 봐야 해요.

### 5-2. DCE/RPC를 1분 만에 { #dcerpc }

DCE/RPC는 Windows가 **다른 컴퓨터의 기능을 원격으로 호출하는 방식**이에요. 먼저 **인터페이스(UUID)**를 골라(**bind**) 어떤 서비스를 쓸지 정하고, **operation(opnum)**으로 그 서비스의 어떤 기능을 부를지 정해요.

| 인터페이스 | 서비스 |
|---|---|
| `epmapper` | "서비스 X는 몇 번 포트에 있나요?"(135번 포트) |
| `netlogon` | 로그인 처리, DC와의 보안 채널 |
| `samr` | 계정 관리 |
| `lsarpc` | 보안 정책, SID ↔ 이름 |
| `drsuapi` | AD 복제, 이름 변환 |

내용은 Kerberos로 암호화될 수 있지만(`service`에 `krb,gssapi`가 보이는 이유), **인터페이스와 기능 이름은 보여서** Zeek이 기록해요.

### 5-3. 어떤 기능을 불렀나 { #dce-rpc-log }

```spl
index=zeek sourcetype=zeek:dce_rpc pcap_case=20180511_NIGHT_DEW
| stats count min(_time) as first by id_resp_p named_pipe endpoint operation
| convert ctime(first)
| sort first
```

- `named_pipe` SMB 파이프 이름(높은 포트로 직접 접속하면 포트 번호가 나와요) · `endpoint` 인터페이스 · `operation` 부른 기능 · `count`, `first` 몇 번, 처음 언제

```text
id_resp_p  named_pipe  endpoint  operation                    count  first
135        135         epmapper  ept_map                      4      05/11/2018 02:06:52.151891
49158      49158       netlogon  NetrServerReqChallenge       1      05/11/2018 02:06:52.152403
49158      49158       netlogon  NetrServerAuthenticate3      1      05/11/2018 02:06:52.153549
49158      49158       netlogon  NetrLogonGetCapabilities     1      05/11/2018 02:06:52.1553
49158      49158       netlogon  NetrLogonGetDomainInfo       1      05/11/2018 02:06:52.155301
49155      49155       drsuapi   DRSBind                      2      05/11/2018 02:06:52.257323
49155      49155       drsuapi   DRSCrackNames                4      05/11/2018 02:06:52.257826
49155      49155       drsuapi   DRSUnbind                    2      05/11/2018 02:06:52.258333
49158      49158       netlogon  NetrLogonSamLogonWithFlags   1522   05/11/2018 02:08:12.836886
49155      49155       lsarpc    LsarLookupSids3              1      05/11/2018 02:08:27.138847
```

**결과 읽기:**

- **정상(02:06:52, 로그인 순간):** `ept_map`(포트 찾기), `NetrServerReqChallenge` / `NetrServerAuthenticate3` / `GetCapabilities` / `GetDomainInfo`(PC가 DC와 **보안 채널**을 맺는 과정 — 도메인 PC는 켜질 때 항상 해요), `DRSBind` / `DRSCrackNames` / `DRSUnbind`(이름 형식 변환, 로그인 때 흔해요). 모두 로그인 시각에 한 번씩이에요.
- **이상한 것: `NetrLogonSamLogonWithFlags` 1,522번, 02:08:12.836부터.** 이 기능은 PC가 DC에게 **"이 계정과 비밀번호가 맞나요?"**라고 묻는 거예요. 누가 이 PC에서 NTLM으로 로그인을 시도하면 PC는 직접 판단하지 못하고 DC에 물어요. 정상이면 몇 번 나오는 정도인데, **32초 동안 1,522번, 초당 약 47번**이에요. 사람이 이렇게 할 수는 없어요. **프로그램이 비밀번호를 대입해 보는(brute force)** 패턴이에요.
- 1,522번 × 약 512바이트 ≈ **780 KB** — 큰 연결 크기와 정확히 맞아요. 948 KB의 답이 이거였어요.
- **시각이 악성코드와 이어져요.** 두 번째 구성 요소가 `/mlu/forum.php`에 POST한 0.6초 뒤에 시작해요. 계정 정보를 훔치는 악성코드 중에는 비밀번호 목록을 넣어 두고 Windows 계정에 하나씩 대입해 보는 것이 있어요. 계열 이름은 **확인 안 됨**으로 둡니다.
- `LsarLookupSids3`(02:08:27, 1번, SID → 이름)는 대입 시간 안에 있어요. 같은 프로그램이 계정 이름을 확인했을 수도 있어요. 메모만 해 두세요.

!!! question "질문: Arkime는 결과가 2개 나오는데 별로 유용한 정보가 없습니다. 왜 그런가요?"
    Arkime는 DCE/RPC에서 **어떤 기능을 불렀는지**까지는 풀어 주지 않아요. Zeek은 DCE/RPC 전용 분석기가 있어서 인터페이스와 기능 이름을 하나하나 기록해요. 이런 경우가 바로 **Splunk(Zeek 로그)가 더 편한** 경우예요.

    그래도 Arkime로 세션 자체는 확인할 수 있어요. `tags == 20180511_NIGHT_DEW && port.dst == 49158`로 보면 패킷 1,529 / 1,526개, 데이터 779,560 / 231,472바이트라 크기가 맞아요.

!!! question "질문: 여기서 PSH가 많이 보이는 이유가 무엇인가요?"
    **PSH(Push)**는 보내는 쪽이 **"이번 메시지는 여기까지야. 기다리지 말고 바로 프로그램에 넘겨"**라고 표시하는 플래그예요. 보통 **한 메시지의 마지막 패킷**에 붙어요.

    이 세션은 1,529 + 1,526 = **3,055패킷** 중 **3,046개에 PSH**가 있어요. 빠진 건 SYN, SYN-ACK, FIN, 빈 ACK 몇 개뿐이에요.

    이유는 메시지가 **패킷 하나에 다 들어가기** 때문이에요. 779,560 B ÷ 1,522 ≈ **요청당 512 B**, 231,472 B ÷ 1,522 ≈ **응답당 152 B**. 패킷 하나에 1,400 B 넘게 담을 수 있으니 요청 하나가 패킷 하나이고, 그 패킷이 곧 메시지의 끝이라 PSH가 붙어요 → 요청 1,522 + 응답 1,522 ≈ PSH 3,044개. 크기가 매번 거의 같다는 건 **같은 기능을 반복 호출**했다는 뜻이에요.

    ACK가 5개뿐인 이유: DC가 "받았어"(ACK)를 **응답 패킷에 같이 실어** 보내서, ACK만 따로 보내는 빈 패킷이 거의 필요 없었어요.

    `wansaiful[.]com` 다운로드와 비교해 보면, 서버 쪽 203패킷 중 PSH는 151개였어요. 큰 파일은 꽉 찬 패킷 여러 개로 오고 PSH는 덩어리의 끝에만 붙어요.

    | 모양 | 뜻 |
    |---|---|
    | **PSH ≈ 전체 패킷 수** | 작은 메시지를 계속 주고받는 대화형 통신: 반복 요청(이번 대입 공격), 비콘, 원격 셸 명령 |
    | **PSH가 적고 패킷이 많음** | 한 방향으로 큰 데이터 전송: 다운로드, 업로드 |

    **Payload8**은 각 방향의 첫 데이터 8바이트예요. PC `05 00 0b 07 ...`, DC `05 00 0c 07 ...`. `05 00`은 DCE/RPC 버전 5.0, 세 번째 바이트는 메시지 종류 — `0b`(11)는 **Bind**(이 인터페이스를 쓰겠다), `0c`(12)는 **Bind Ack**(허락). 포트 번호(49158)만으로 프로토콜을 알기 어려울 때 첫 8바이트가 큰 도움이 돼요.

### 5-4. 트래픽으로 알 수 없는 것 — 호스트 오퍼레이터에게 { #host-leads }

netlogon 보안 채널은 암호화돼 있어서 **어떤 계정에, 어떤 비밀번호로, 성공했는지**는 트래픽으로 볼 수 없어요. 호스트 로그로 확인해요.

- **DC Security 로그, 이벤트 4776** — DC가 NTLM 계정 정보를 검증한 기록. 계정, 요청한 PC, 결과 코드가 남아요. `0xC000006A` = 비밀번호 틀림, `0xC0000064` = 없는 계정, **`0x0` = 성공**. 02:08:12–02:08:45 사이 CHICAGO-7FA3-PC가 요청한 4776을 모두 보세요.
- **DC 이벤트 4740** — 계정 잠김. 대입 때문에 잠긴 계정이 있는지.
- **PC Security 로그, 이벤트 4625 / 4624** — PC의 로그온 실패 / 성공. **Process Name**에 시도한 프로그램이 나와요. 악성 파일 경로를 찾는 단서예요.

**티켓 기록:**

```text
[261121 2137, Lee] Password guessing through DC netlogon - Found
[261121 2137, Lee] Large uploads to external hosts - Not Found
```

---

## 6단계 — Snort 룰 하나, 그리고 테스트하는 법 { #snort }

### 6-1. 어떤 룰을, 왜 { #rule-choice }

핵심 하나만 고른다면 **체크인 POST**가 가장 좋아요.

- **도메인이나 IP가 바뀌어도 잡혀요.** C2 도메인은 자주 바뀌지만 본문 형식(`GUID=...&BUILD=...&INFO=...`)은 그대로예요.
- **감염의 시작을 잡아요.** "이 PC가 방금 C2에 등록했다"는 뜻이에요.
- **오탐이 거의 없어요.** 정상 사이트가 이 세 이름을 이 순서로 보내는 경우는 매우 드물어요.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Malware check-in POST GUID/BUILD/INFO - Sung"; flow:to_server,established; content:"POST"; depth:4; content:"GUID="; content:"&BUILD="; distance:0; content:"&INFO="; distance:0; sid:1000001; rev:1;)
```

### 6-2. 룰을 한 부분씩 { #rule-anatomy }

**헤더**

- `alert` — 맞으면 알림을 내요.
- `tcp` — TCP만 봐요.
- `$HOME_NET any -> $EXTERNAL_NET 80` — 내부 어느 포트에서든 **외부 80번(HTTP)**으로 가는 것만. pcapbox에서 HOME_NET은 사설 대역 전체예요.

**옵션 (괄호 안)**

- `msg:"..."` — 알림 설명. 끝에 작성자 이름을 붙이는 건 팀 방식이에요.
- `flow:to_server,established` — TCP 연결이 **맺어진 상태에서 클라이언트가 서버로 보내는** 데이터만 봐요. 응답이나 연결 시작 패킷은 건너뛰어서 빠르고 정확해져요.
- `content:"POST"; depth:4;` — 데이터의 **처음 4바이트**가 `POST`인지(`depth:4` = 앞에서 4바이트 안에서만). HTTP 요청의 첫 단어를 확인하는 거예요.
- `content:"GUID=";` — 어딘가에 `GUID=`가 있는지.
- `content:"&BUILD="; distance:0;` — `distance:0`은 **"바로 앞에서 찾은 위치 뒤에서부터"** 찾으라는 뜻이라, `&BUILD=`가 `GUID=` 뒤에 있어야 맞아요.
- `content:"&INFO="; distance:0;` — `&INFO=`도 `&BUILD=` 뒤에. 세 단어가 **이 순서대로** 나올 때만 울려요.
- `sid:1000001;` — 룰 번호(직접 만든 룰은 1000000 이상).
- `rev:1;` — 룰 버전. 고칠 때마다 1씩 올려요.

**알림이 몇 개 나와야 할까?** 첫 체크인에만 이 본문이 있으면 1개, 비콘도 같은 본문을 보내면 **21개**예요. 테스트 전에 Arkime에서 비콘 하나를 확인해요.

1. 시간 범위 **All**, 검색: `tags == 20180511_NIGHT_DEW && host.http == lysedsohap.com && http.method == POST`
2. **Start Time** 정렬: 맨 위가 02:08:04 체크인, 다음이 `/mlu/forum.php`, `/d2/about.php`, 그다음 **02:10:15**부터 비콘.
3. 02:10:15 세션의 `+`를 눌러 펼치고 아래 패킷 내용으로 스크롤. **Src**만 켜면 요청 쪽만 보여서 편해요.
4. 헤더 아래 빈 줄 다음이 **본문**이에요. `Content-Length`를 체크인(123)과 비교해요.
5. 마지막 비콘(02:48:25)도 똑같이. 처음과 끝이 같으면 중간도 같다고 봐도 돼요.

두 비콘 모두 **본문이 같았고** `Content-Length: 123` → **21개**를 예상합니다.

### 6-3. Snort 룰 테스트 — 초보자 가이드 { #snort-test }

크게 4단계예요. **룰 넣기 → 문법 검사 → PCAP으로 시험 → 결과 읽기**.

**1. `/data/rules/local.rules`에 룰 넣기**

*방법 A — 호스트 PC 메모장*

1. 탐색기 주소창에 `\\10.50.10.60\rules`(사용자 `analyst`, Samba 암호).
2. `local.rules`를 **메모장**으로 엽니다.
3. **서식 → 자동 줄 바꿈 끄기.** 켜져 있으면 긴 룰이 여러 줄처럼 보여요. 룰은 반드시 **한 줄**이어야 해요.
4. 맨 아래 빈 줄에 붙여 넣고 저장(Ctrl+S).

*방법 B — SSH에서 nano*

```bash
nano /data/rules/local.rules
```

- 맨 아래로 내려가 붙여 넣고(PuTTY/PowerShell은 마우스 오른쪽 클릭), **Ctrl+O** → Enter로 저장, **Ctrl+X**로 나와요.

*잘 들어갔는지 확인:*

```bash
tail -3 /data/rules/local.rules
```

- `tail -3`: 마지막 3줄. 맨 마지막 줄에 룰이 **한 줄로 통째로** 보이면 돼요.

!!! warning "둥근 따옴표는 룰을 망가뜨려요"
    웹이나 워드에서 복사하면 `"`가 `“ ”`로 바뀔 수 있어요. Snort는 못 읽으니 이상하면 따옴표를 직접 다시 치세요.

**2. 문법 검사**

오타가 있으면 Snort가 아예 실행되지 않아요. 그래서 **PCAP을 돌리기 전에 항상 문법부터** 검사해요.

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
```

- `-T` — **테스트 모드**: 패킷은 안 보고 설정과 룰만 읽어서 검사해요.
- `-c /etc/snort/snort.conf` — 이 설정 파일을 써요(안에서 `local.rules`를 `include`해요).
- `2>&1` — Snort는 결과를 오류 출력으로 내보내서, 그것까지 화면으로 모아요.
- `| tail -5` — 마지막 5줄.

성공:

```text
        Snort successfully validated the configuration!
Snort exiting
```

실패하면 `ERROR` 줄이 나와요. 예:

```text
ERROR: /data/rules/local.rules(9) Unmatched quote in rule option 'msg'.
Fatal Error, Quitting..
```

`(9)`가 **몇 번째 줄**인지 알려 줘요. 그 줄의 따옴표, 세미콜론, 괄호를 확인하세요.

**3a. 시험 — 쉬운 방법: `snort-test`**

```bash
snort-test 20180511_NIGHT_DEW
```

pcapbox 매뉴얼 8-3단계에서 만든 명령이에요. 문법 검사를 하고, `/data/pcap/20180511_NIGHT_DEW.pcap`을 돌려 룰별 알림 개수를 세요. Splunk나 파일에는 아무것도 남기지 않아서 몇 번이든 다시 돌려도 돼요.

```text
[1/2] 문법 OK
[2/2] /data/pcap/20180511_NIGHT_DEW.pcap
  개수 [gid:sid:rev] 메시지
     21 [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung
```

**3b. 시험 — 직접 실행, 알림 한 줄씩**

```bash
mkdir -p /tmp/snortlog
sudo snort -c /etc/snort/snort.conf -r /data/pcap/20180511_NIGHT_DEW.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

- `mkdir -p /tmp/snortlog` — 임시 폴더(`-p`는 이미 있어도 오류 없음).
- `-r 파일` — 네트워크 대신 이 PCAP을 읽어요.
- `-A console` — 알림을 화면에 한 줄씩.
- `-q` — 시작 안내문 숨기기.
- `-k none` — **체크섬 검사 끄기.** 캡처한 PCAP은 체크섬이 틀린 경우가 많아서, 이게 없으면 Snort가 그 패킷을 버려 알림이 안 뜰 수 있어요.
- `-U` — 시각을 **UTC**로, `-y` — 날짜에 연도.
- `-l /tmp/snortlog` — Snort가 기록 파일을 쓸 폴더(아래 오류 참고).

개수만:

```bash
sudo snort -c /etc/snort/snort.conf -r /data/pcap/20180511_NIGHT_DEW.pcap -A console -q -k none -U -y -l /tmp/snortlog | wc -l
```

- `| wc -l` — 출력 줄 수 = 알림 개수.

**4. 결과 읽기**

```text
05/11/18-02:08:04.575944  [**] [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung [**] [Priority: 0] {TCP} 10.0.14.129:49198 -> 185.43.223.6:80
05/11/18-02:10:15.697332  [**] [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung [**] [Priority: 0] {TCP} 10.0.14.129:49205 -> 185.43.223.6:80
05/11/18-02:12:16.219566  [**] [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung [**] [Priority: 0] {TCP} 10.0.14.129:49210 -> 185.43.223.6:80
...
05/11/18-02:48:25.586602  [**] [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung [**] [Priority: 0] {TCP} 10.0.14.129:49287 -> 185.43.223.6:80
```

- `05/11/18-02:08:04.575944` — 패킷 시각(UTC)
- `[1:1000001:1]` — `[gid:sid:rev]`. gid 1은 일반 룰, sid는 우리 룰 번호, rev는 버전
- 그다음이 `msg` 설명
- `[Priority: 0]` — 룰에 `classtype`을 안 넣어서 0. 지금은 신경 안 써도 돼요.
- `{TCP} 10.0.14.129:49198 -> 185.43.223.6:80` — 프로토콜, 출발지 IP:포트 → 도착지 IP:포트

**확인할 것:**

1. **21개** = 체크인 1 + 비콘 20. ✔
2. **첫 알림 02:08:04.575, 포트 49198** — Arkime, Zeek `http.log`와 같은 세션, 같은 밀리초. 세 도구가 일치 → 신뢰도가 높아요. ✔
3. **간격 약 120.5초**(02:10:15 → 02:12:16 → 02:14:16 …) — 2분 비콘과 같아요. ✔
4. **오탐 없음:** 모두 `185.43.223.6:80`으로 가요. NCSI, ipify, wansaiful, TLS, DC 통신에서는 하나도 안 울렸어요. ✔

룰이 도메인이나 IP를 전혀 안 보는데도 C2 트래픽만 정확히 잡았어요. 공격자가 도메인을 바꿔도 계속 울려요.

**안 울리거나 개수가 다를 때**

1. **0개:** 문법 검사를 다시 하고, `-k none`을 빠뜨리지 않았는지 보세요.
2. **그래도 0개:** 룰을 아주 단순하게 줄여 봐요(예: `content:"GUID=";` 하나만). 울리면 옵션을 하나씩 다시 넣으면서 문제를 찾아요.
3. **개수가 다름:** 안 울린 세션을 Arkime에서 찾아 본문을 비교해요.
4. **고칠 때마다** `rev:1` → `rev:2`로 올려서, 어떤 버전으로 시험했는지 티켓에 남겨요.

**pcapbox에서 만난 오류**

| 오류 | 원인 | 해결 |
|---|---|---|
| `sudo: snort: command not found` | `make install`은 snort를 `/usr/local/bin`에 넣는데, Oracle Linux의 `sudo`는 보안 때문에 `secure_path`에서만 찾고 거기에 `/usr/local/bin`이 없어요 | `sudo ln -sf /usr/local/bin/snort /usr/sbin/snort`(`sudo`가 찾는 곳에 바로가기, pcapbox 스크립트도 이걸로 찾아요). 먼저 `ls -l /usr/local/bin/snort`로 파일이 있는지 확인 — 없으면 `make install` 실패 |
| `ERROR: log_tcpdump: Failed to open log file "/var/log/snort/snort.log.<숫자>": No such file or directory` | Snort가 패킷 기록 파일도 남기려는데 기본 폴더 `/var/log/snort`가 없어요 | `-l /tmp/snortlog` 추가(`mkdir -p /tmp/snortlog` 먼저), 또는 기본 폴더를 한 번 만들기: `sudo mkdir -p /var/log/snort`. `snort-test`는 자체 임시 폴더를 써서 이 오류가 안 나요 |

**티켓 기록:**

```text
[261121 2200, Lee] Snort rule test for C2 check-in - Found
```

---

## 타임라인 (2018-05-11, UTC) { #timeline }

| 시각 | 사건 |
|---|---|
| 02:06:51 | PC가 DHCP로 10.0.14.129를 받음, faith.hoffman 로그인(Kerberos), DC와 보안 채널 |
| 02:07:02 | Windows 연결 확인(NCSI) — 정상 |
| 02:08:04 | `api.ipify[.]org` 공인 IP 조회 → POST `lysedsohap[.]com/4/forum.php` 체크인, 응답 = 다운로드 명령 3개 |
| 02:08:05–02:08:14 | `wansaiful[.]com`에서 암호화된 파일 3개(keep-alive 세션 하나) |
| 02:08:12 | POST `/mlu/forum.php`(암호화 206 B, MSIE 7.0, `Content-Encoding: binary`) — 계정 정보 탈취로 추정 |
| 02:08:12–02:08:45 | DC에 `NetrLogonSamLogonWithFlags` 1,522번(비밀번호 대입) |
| 02:08:14 | POST `/d2/about.php`(암호화 234 B, 같은 프로그램) |
| 02:10:15–02:48:25 | `lysedsohap[.]com`에 약 120초마다 HTTP 비콘(20번), 응답 `{n:}` |
| 02:10:16–02:45:46 | `robwassotdint[.]ru`에 약 5분마다 TLS C2(세션 54개) |
| 02:40:18–02:42:37 | TLS C2에서 PC로 약 1.5 MB |
| 02:49:41 | 캡처 끝, 두 C2 모두 아직 동작 중 |

---

## 침해사고 티켓 { #ticket }

핵심 발견만, 짧은 문장, 쉬운 영어로 썼어요. 팀 양식대로 티켓 본문은 영어예요. 작업자 이름, 작업 로그 시각, 증거 해시는 바꿔 넣을 자리예요.

[:material-download: 티켓 txt 파일 내려받기](files/180511_CHICAGO-7FA3-PC_ticket_pass2.txt){ .md-button }

```text
--8<-- "docs-ko/blueteam/investigations/files/180511_CHICAGO-7FA3-PC_ticket_pass2.txt"
```

보내기 전에: EVIDENCE LOCATIONS에 `ingest.log`의 SHA256을 넣고, **파일 해시 3개를 Splunk 결과와 한 번 대조**하고, 작업 로그 시각과 이름을 실제 값으로 바꾸세요.

---

## 바로 쓰는 쿼리 모음 { #query-sheet }

`<case>`는 케이스 이름으로 바꾸세요. 실제 네트워크에서는 `tags`/`pcap_case` 조건을 빼세요.

**Arkime**

```text
tags == <case>
tags == <case> && protocols == dhcp
tags == <case> && protocols == krb5
tags == <case> && protocols == http
tags == <case> && ip.dns == [185.174.175.14, 185.43.223.6]
tags == <case> && host.http == lysedsohap.com && http.method == POST
tags == <case> && host.http == wansaiful.com
tags == <case> && http.request.content-type == application/octet-stream
tags == <case> && host == [www.victoryoutreachvallejo.com, medleysoup.com, radiantheartcoaching.com, hdmicablereviews.com]
tags == <case> && ip == 185.174.175.14
tags == <case> && port.dst == 49158
cert.hash == 86:af:39:2e:9b:42:ec:50:e2:87:f6:42:9e:f7:48:4c:48:bb:bd:95
cert.issuer.on == "Default Company Ltd" && cert.subject.on == "Default Company Ltd"
```

**Splunk (Zeek)**

```spl
index=zeek sourcetype=zeek:conn | stats count by pcap_case
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h="10.0.14.*" | stats count as sessions sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h | sort - sessions
index=zeek sourcetype=zeek:dhcp pcap_case=<case> | table _time client_addr assigned_addr mac host_name msg_types
index=zeek sourcetype=zeek:kerberos pcap_case=<case> | stats count by request_type client service success
index=zeek sourcetype=zeek:kerberos pcap_case=<case> client="<user>*" | table _time id_orig_h id_resp_h request_type client service success error_msg | sort _time
index=zeek sourcetype=zeek:http pcap_case=<case> | sort _time | table _time id_resp_h host method uri status_code resp_mime_types response_body_len user_agent
index=zeek sourcetype=zeek:http pcap_case=<case> method=POST | stats count sum(request_body_len) as sent_bytes values(user_agent) as user_agent by uri | sort - count
index=zeek sourcetype=zeek:dns pcap_case=<case> query IN ("<name1>","<name2>") | table _time query answers
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | table _time tx_hosts rx_hosts mime_type seen_bytes total_bytes md5 sha1
index=zeek sourcetype=zeek:conn pcap_case=<case> id_resp_h="<c2 ip>" | sort _time | delta _time as gap | table _time id_resp_p service duration orig_bytes resp_bytes conn_state gap
index=zeek sourcetype=zeek:ssl pcap_case=<case> id_resp_h="<c2 ip>" | stats count min(_time) as first max(_time) as last by server_name version cipher established | convert ctime(first) ctime(last)
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h="<host ip>" | sort - orig_bytes | head 10 | table _time id_resp_h id_resp_p service duration orig_bytes resp_bytes
index=zeek sourcetype=zeek:dce_rpc pcap_case=<case> | stats count min(_time) as first by id_resp_p named_pipe endpoint operation | convert ctime(first) | sort first
```

**CyberChef**

```text
From Base64  →  XOR Brute Force (Key length 1, Crib: http)  →  그다음 XOR (Key 7a, HEX)
```

**Snort**

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
snort-test <case>
sudo snort -c /etc/snort/snort.conf -r /data/pcap/<case>.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

---

## 분석하면서 만난 랩 문제 { #lab-notes }

이 사례를 위해 pcapbox를 준비하면서 만난 문제예요. 다시 만날 테니 남겨 둡니다.

- **pcapbox 매뉴얼 7단계 뒤 호스트에서 Arkime/Splunk가 안 열림.** VM 방화벽은 8-6단계에서야 8000/8005를 열어요. 먼저 열기: `sudo firewall-cmd --permanent --add-port=8000/tcp --add-port=8005/tcp`.
- **`firewall-cmd: error: argument --add-service: not allowed with argument --add-port`.** 이 firewalld는 포트와 서비스를 한 명령에 섞지 못해요. 두 명령으로: `--add-port=...` 다음 `--add-service=samba`, 그리고 `sudo firewall-cmd --reload`.
- **Arkime 웹 암호를 매뉴얼 기본값 그대로 둠.** `arkime_add_user.sh`는 계정을 **만드는** 명령이라 다시 실행해도 암호가 안 바뀌어요. 로그인 → **Settings → Password**에서 바꾸고, 관리자는 **Users**에서 다른 계정도 바꿀 수 있어요.
- **호스트 전용 VMnet을 만들 때마다 VMware NAT가 죽음**(Application 로그 이벤트 1000/1001: `vmnat.exe` `0xc0000005` 크래시, VM은 DHCP로 IP를 받는데 NAT 게이트웨이 `.2`로 핑이 안 됨). 원인은 랩 대역이 **호스트의 실제 네트워크와 겹친 것**이었어요. 호스트 Wi-Fi가 /23 대역이고 게이트웨이가 `10.10.10.1`(VMnet2의 호스트 주소와 같음), 유선망이 `172.16.0.0/16`(VMnet3 대역과 같음)이었어요. 해결: 랩을 겹치지 않는 대역으로 옮기기(여기서는 `10.50.10.0/24`, `10.60.0.0/16`). VMnet을 만들기 전에 PowerShell에서 확인: `Get-NetIPAddress -AddressFamily IPv4`, `Get-NetRoute -DestinationPrefix 0.0.0.0/0`.

---

## 배운 점 { #lessons }

1. **시계부터 맞추세요.** 브라우저 시간의 Arkime와 UTC의 Splunk가 정확히 9시간 30분 달랐어요. 타임라인을 한 줄 쓰기 전에 모든 도구를 UTC로.
2. **모르는 PCAP은 HTTP부터.** 평문이고 양이 적고, 이야기가 시작되는 곳을 보여 줘요.
3. **크기와 시각으로 사건을 잇기.** ipify 응답 14바이트 = `IP=` 14글자, netlogon 1,522 × 512 B = 780 KB 업로드. 숫자가 맞으면 연결이 증명돼요.
4. **crib은 행동에서.** 응답 직후 다운로드 → 응답에 `http`가 있을 것. base64 안의 반복 조각은 짧은 XOR 키의 힌트.
5. **헤더가 아니라 내용으로 판단.** `text/plain`은 암호화된 바이너리였고, 서버 시계는 5분 틀렸어요.
6. **비콘 두 개, 프로그램 두 개.** 120초 HTTP와 약 300초 TLS, 서로 다른 User-Agent와 프로토콜.
7. **열린 의문은 끝까지.** "왜 이렇게 많이 보냈지?"가 첫 번째 분석에서 정상 DC 통신으로 넘겼던 비밀번호 대입으로 이어졌어요.
8. **보이는 도구를 쓰세요.** Zeek의 DCE/RPC 분석기는 기능 이름을 보여 줬고, Arkime는 못 보여 줬어요.
9. **공격자가 쉽게 못 바꾸는 것으로 룰을.** 본문 형식은 도메인이 바뀌어도 그대로라, 룰 하나로 21개를 오탐 없이 잡았어요.
10. **트래픽으로 알 수 없는 것과 볼 곳을 적으세요.** 대입한 계정 → DC 이벤트 4776, 대입한 프로세스 → PC 4625/4624.
11. **작아도 POST는 다 열어 보세요.** 440바이트는 "보낸 양이 큰 연결" 검색에 안 나오지만 훔친 비밀번호를 담을 수 있어요.

## 참고 { #references }

- [이 사례의 첫 번째 분석 — Arkime + CyberChef + Snort 룰 8개](night-dew-hancitor-pony-zeus-panda-tls-c2.md)
- [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Arkime로 PCAP 분석하기](../../network/arkime/offline-pcap-guide.md)
- [Zeek 로그](../../network/zeek/index.md) · [conn.log](../../network/zeek/conn-log.md) · [files.log](../../network/zeek/files-log.md) · [ssl과 x509](../../network/zeek/ssl-x509.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [비콘과 C2](../../network/beaconing-c2.md)
- [DC, SMB와 Snort 룰 실습](../../training/pcap-ir-labs/dc-smb-and-snort-rules.md) · [플레이북: 침해된 워크스테이션](../playbooks/compromised-workstation.md) · [플레이북: 계정 침해](../playbooks/account-compromise.md)
- 원본 실습: [malware-traffic-analysis.net — 2018-05-11 Night Dew](https://malware-traffic-analysis.net/2018/05/11/index.html)
