---
title: 대시보드 1 — 트래픽 개요와 베이스라이닝
tags:
  - splunk
  - zeek
  - dashboard
  - baselining
---

# 대시보드 1 — 트래픽 개요와 베이스라이닝 { #overview-dashboard }

<div class="dfir-meta" markdown>
**분류:** Splunk · **대시보드:** `zeek_traffic_overview.xml` (패널 57개) · **마지막 수정:** 2026-11-26
</div>

!!! abstract "이 대시보드로 하는 일"
    **A–C 섹션은 베이스라이닝**이에요 — 캡처 시간, 로그 종류, 내부 PC와 서버, 이름·사용자·OS를 먼저 알아요. **D–I 섹션은 "평소와 다른 것" 찾기**예요 — 바깥 통신, 비콘, DNS, HTTP, TLS 인증서, 파일, 알림. **J 섹션**은 한 호스트가 한 일을 시간 순서로 모두 보여 주고, 줄을 누르면 그 연결(uid)의 모든 Zeek 기록을 열어요.

!!! tip "이 페이지 읽는 법"
    패널마다 **목적 → 쿼리 → 한 줄씩 설명 → 결과 예시 → 읽는 법** 순서예요. 쿼리는 Search 화면에 바로 붙여 돌릴 수 있게 `index=zeek`, `pcap_case="<case>"`로 적었어요(`<case>`를 케이스 이름으로 바꾸세요). 대시보드 안에서는 이 부분이 토큰(`$idx$`, `$case$`, Host IP 필터)으로 되어 있어요. 결과 예시는 **설명용으로 만든 값**이에요(랩 대역 10.0.0.0/24, 바깥 주소는 문서용 대역 198.51.100.x, 203.0.113.x).

## 섹션 지도 { #map }

| 섹션 | 질문 | 패널 |
|---|---|---|
| **A** 캡처 한눈에 | 언제부터 언제까지? 얼마나 큰가? | 숫자 10개 |
| **B** 무엇이 들어 있나 | 어떤 로그, 서비스, 포트, 연결 상태? | 로그 종류, 파이 3개, 시간 그래프, 포트 표 |
| **C** 누가 누구인가 | 내부 PC, 이름, 사용자, MAC, OS, 서버 역할 | 표 4개 |
| **D** 바깥과의 통신 | 누구와, 얼마나, 이상한 포트, 비콘, 유출 | 표 5개, 막대, 시간 그래프 |
| **E** DNS | 어떤 이름을 물었나, 드문 이름, 이상한 이름 | 파이 2개, 표 4개 |
| **F** HTTP | 호스트, User-Agent, POST, 내려받은 프로그램, 리다이렉트 순서 | 파이 3개, 표 6개 |
| **G** TLS | SNI, 버전, 이상한 포트, 자체 서명 인증서 | 파이, 표 3개 |
| **H** 파일 | 어떤 파일이 오갔나, 해시, Windows 프로그램 | 파이 2개, 표 2개 |
| **I** 알림과 이상 | Snort, Zeek weird, Zeek notice | 막대, 표 3개 |
| **J** 활동 타임라인 | 한 호스트가 한 모든 일, 연결 하나의 모든 기록 | 표 2개 |

## 쿼리를 읽기 전에 — 공통 부분 { #common }

### 대시보드 쿼리와 이 페이지 쿼리 { #tokens }

| 이 페이지 | 대시보드 안 | 뜻 |
|---|---|---|
| `index=zeek` | `index=$idx$` | Zeek index 상자 |
| `pcap_case="<case>"` | `$case$` | Case 드롭다운 (All이면 `*`) |
| (없음) | `(id_orig_h="$ip$" OR id_resp_h="$ip$")` | Host IP 상자 (기본 `*` = 전체) |
| `span=1m` | `span=$span$` | Timeline bucket 상자 |
| `IPC$`, `"%$"` | `IPC$$`, `"%$$"` | XML 안의 글자 `$` ([기초 4번](dashboard-basics.md#dollar-cdata)) |

### 내부 / 외부 나누기 { #scope }

여러 패널이 IP가 **내부인지 외부인지**를 이 한 줄로 정해요.

```spl
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
```

- `eval 새필드=case(조건1,값1, 조건2,값2, true(),기본값)` — 위에서부터 **처음 맞는 조건**의 값을 넣어요. `true()`는 "나머지 전부".
- `match(필드,"정규식")` — 필드가 정규식에 맞으면 참.
- 첫 조건 — `224–239.x`(멀티캐스트), `255.x`, 끝이 `.255`(브로드캐스트), `ff..`(IPv6 멀티캐스트). 한 대가 아니라 **여러 대에게 보내는 주소**예요.
- 둘째 조건 — 사설 대역 `10.`, `192.168.`, `172.16–31.`, 그리고 `127.`(자기 자신), `169.254.`(DHCP 실패 시 자동 주소), `0.0.0.0`(DHCP 요청), `fe80:`·`fc`·`fd`(IPv6 내부).
- `\.` — 정규식에서 `.`은 "아무 글자"라서, 진짜 점은 `\.`으로 써요. `^` = 시작, `$` = 끝.
- 보낸 쪽(`id_orig_h`)에는 같은 식으로 `src_scope`를 만들어요.

### Zeek conn.log 필드 { #conn-fields }

| 필드 | 뜻 |
|---|---|
| `id_orig_h` / `id_orig_p` | 연결을 **시작한** 쪽 IP / 포트 (`orig` = originator) |
| `id_resp_h` / `id_resp_p` | **받은** 쪽 IP / 포트 (`resp` = responder) |
| `proto` | `tcp`, `udp`, `icmp` |
| `service` | Zeek가 알아본 프로토콜(`dns`, `http`, `ssl`, `smb` …). 비어 있으면 못 알아봄 |
| `orig_bytes` / `resp_bytes` | 양쪽이 보낸 **데이터** 바이트 |
| `duration` | 연결 시간(초) |
| `conn_state` | 연결이 어떻게 끝났나 ([B3](#b3)) |
| `uid` | 연결 이름표. 다른 로그와 이어 주는 열쇠 |

---

## A. 캡처 한눈에 { #a-glance }

**목적:** 분석을 시작하기 전에 **크기와 시간 범위**를 알아요. 모든 결론은 이 범위 안의 이야기예요.

A1–A8은 베이스 검색 **`b_kpi`** 하나를 나눠 써요.

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval src_scope=case(match(id_orig_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_orig_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| stats min(ts) as first max(ts) as last count as conns dc(eval(if(src_scope="internal",id_orig_h,null()))) as int_hosts dc(eval(if(dst_scope="external",id_resp_h,null()))) as ext_ips sum(eval(if(dst_scope="external",orig_bytes,0))) as ext_out sum(eval(if(dst_scope="external",resp_bytes,0))) as ext_in
```

- 1줄: 연결 로그(conn)만. 대시보드에서는 Case와 Host IP 필터도 붙어요.
- 2–3줄: [내부/외부 나누기](#scope) — 보낸 쪽 `src_scope`, 받은 쪽 `dst_scope`.
- 4줄 `stats`(한 줄로 요약):
    - `min(ts) as first`, `max(ts) as last` — 가장 이른·늦은 시각.
    - `count as conns` — 연결 수.
    - `dc(eval(if(src_scope="internal",id_orig_h,null()))) as int_hosts` — `dc()` = **중복 없이 세기**. `eval(if(조건,값,null()))` = 조건에 맞을 때만 값을 내고 아니면 빈 값 → **내부에서 연결을 시작한 IP 수**.
    - `sum(eval(if(dst_scope="external",orig_bytes,0))) as ext_out` — 바깥으로 **보낸** 바이트 합. 받은 바이트는 `ext_in`.

```text
first        last         conns  int_hosts  ext_ips  ext_out   ext_in       ← 결과 예시
1768870803   1768873375   1840   3          41       918233    22610004
```

각 숫자 패널은 이 한 줄에 **후처리**를 붙여 한 칸만 꺼내요.

| 패널 | 후처리 | 읽는 법 |
|---|---|---|
| A1 First event | `| eval v=strftime(first,"%Y-%m-%d %H:%M:%S") | fields v` | 캡처 시작. Snort·Arkime 시각과 같은지 확인 |
| A2 Last event | 같은 방식으로 `last` | 캡처 끝. 이후 일은 알 수 없어요 |
| A3 Duration | `| eval v=round((last-first)/60,1)` | 분. 30분짜리면 Timeline bucket `1m`, 몇 시간이면 `5m` 이상 |
| A4 Connections | `| fields conns` | 전체 연결 수 |
| A5 Internal hosts | `| fields int_hosts` | 연결을 **시작한** 내부 IP 수. 1이면 PC 한 대 캡처 |
| A6 External IPs | `| fields ext_ips` | 바깥 목적지 수. 웹 브라우징이면 수십–수백, 비콘만 있으면 몇 개 |
| A7 MB sent | `| eval v=round(ext_out/1024/1024,2)` | 바깥으로 보낸 양. **받은 양보다 크면 유출 의심** |
| A8 MB received | 같은 방식으로 `ext_in` | 보통 보낸 양의 10배 이상 |
| A9 Distinct names | 베이스 `b_dnsq`에 `| stats count as v` | DNS로 물어본 이름 수 ([E](#e-dns)) |
| A10 Snort alerts | 따로 검색 (아래) | 0이 아니면 **빨갛게** 돼요 |

- `fields v` — `v` 열만 남겨요. 숫자 패널은 첫 줄 첫 열을 크게 보여 줘요.
- `round(x,1)` — 소수 첫째 자리까지. `/1024/1024` — 바이트 → MB.

```spl
index=snort sourcetype=snort:alert pcap_case="<case>"
| stats count as v
```

- `sourcetype=snort:alert` — pcapbox가 Snort 알림을 넣는 곳. 대시보드에서는 `(src_ip="$ip$" OR dest_ip="$ip$")` 필터가 붙어요.

---

## B. 캡처에 무엇이 들어 있나 { #b-contents }

### B1. Zeek 로그 종류 { #b1 }

```spl
index=zeek pcap_case="<case>"
| stats count by sourcetype
| sort - count
```

- sourcetype을 안 적어서 **이 케이스의 모든 로그 종류**를 세요. 로그마다 IP 필드 이름이 달라서 Host IP 필터는 쓰지 않아요.

```text
sourcetype          count      ← 결과 예시
zeek:conn           1840
zeek:dns            702
zeek:ssl            311
zeek:http           188
zeek:files          160
zeek:dce_rpc        96
zeek:kerberos       44
zeek:smb_mapping    12
zeek:smb_files      9
zeek:ntlm           3
```

**읽는 법 — 있는 로그와 없는 로그가 모두 단서예요.**

| 보이면 | 뜻 |
|---|---|
| `kerberos`, `ldap`, `dce_rpc`, `smb_*`, `ntlm` | Windows 도메인(AD) PC. 사용자와 컴퓨터 이름을 찾을 수 있어요 → [대시보드 2](smb-dashboard.md) |
| `dhcp` | PC가 캡처 중에 IP를 받았어요. 이름·MAC을 바로 알 수 있어요 (C4) |
| `pe` | Zeek가 트래픽 안에서 **Windows 프로그램(EXE/DLL)**&#8203;을 봤어요 (H4) |
| `smtp`, `ftp` | 메일 / FTP — 평문이라 내용까지 보여요 |
| `weird`, `notice` | 규칙에 안 맞는 트래픽 / Zeek 경고 (I 섹션) |
| `http`가 없음 | 웹은 모두 HTTPS. 내용 대신 SNI·인증서로 판단해요 |

### B2. 서비스별 연결 { #b2 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| fillnull value="(not recognised)" service
| stats count by service
| sort - count
```

- `fillnull value="(not recognised)" service` — 서비스가 빈 연결을 지우지 않고 `(not recognised)`로 남겨요.
- `stats count by service` — 서비스마다 연결 수.

**읽는 법:** `(not recognised)`가 크면 Zeek가 모르는 프로토콜(사설 C2, 암호화 터널)이거나 연결만 되고 데이터가 없는 경우(`S0`)예요. B6 포트 표와 D3에서 어떤 포트인지 봐요. `smb,gssapi,ntlm`처럼 쉼표로 이어진 값은 **한 연결 안에서 여러 프로토콜**을 봤다는 뜻이에요.

### B3. 연결 상태 { #b3 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval state=case(conn_state="SF","SF - opened and closed normally", conn_state="S0","S0 - no reply", conn_state="REJ","REJ - rejected", conn_state="S1","S1 - open, never closed", conn_state="S2","S2 - client closed, no server reply", conn_state="S3","S3 - server closed, no client reply", conn_state="RSTO","RSTO - client sent reset", conn_state="RSTR","RSTR - server sent reset", conn_state="RSTOS0","RSTOS0 - SYN then reset, no reply", conn_state="RSTRH","RSTRH - server SYN-ACK then reset", conn_state="SH","SH - SYN then FIN, no reply", conn_state="SHR","SHR - server SYN-ACK and FIN only", conn_state="OTH","OTH - no SYN seen (mid-stream)", true(), conn_state)
| stats count by state
| sort - count
```

- `eval state=case(conn_state="SF","SF - ...", ...)` — 짧은 코드에 **뜻을 붙여요**. 파이에서 바로 읽을 수 있게요.

| 코드 | 뜻 | 많으면 |
|---|---|---|
| `SF` | 정상으로 열리고 닫힘 | 정상 |
| `S0` | 시도했는데 **대답 없음** | 죽은 C2 서버, 스캔, 막힌 포트 |
| `REJ` | 거절됨 (RST) | 닫힌 포트 스캔, 막힌 C2 |
| `S1` | 열린 채 끝까지 안 닫힘 | 캡처 끝까지 이어진 긴 연결 |
| `RSTO` / `RSTR` | 연결 후 보낸 쪽 / 받은 쪽이 끊음(RST) | 앱에 따라 정상 |
| `SH`, `RSTOS0`, `RSTRH`, `SHR` | 반쯤 열린 이상한 모양 | 스캔, 패킷 일부만 캡처됨 |
| `OTH` | SYN을 못 봄 (중간부터 캡처) | 캡처가 대화 중간에 시작됨 |

UDP도 `SF`(양쪽 대화)와 `S0`(대답 없음)을 써요.

### B4. 전송 프로토콜 · B5. 시간에 따른 연결 { #b4 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| stats count by proto
```

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| fillnull value="(not recognised)" service
| eval _time=ts
| timechart span=1m limit=10 useother=t count by service
```

- `eval _time=ts` — 그래프 시간을 Zeek 시각으로 ([기초 7번](dashboard-basics.md#timechart)).
- `timechart span=1m limit=10 useother=t count by service` — 1분마다, 서비스마다 연결 수. 패널 안 **Split by**로 `service` 대신 출발 IP, 목적지 IP, 포트, 상태별로 바꿔 볼 수 있어요.

**읽는 법:** 사람이 쓰는 PC는 **몰렸다 쉬었다** 해요(페이지를 열 때 확 늘어남). **일정한 간격의 낮은 막대**가 끝까지 이어지면 비콘 후보예요 → [D4](#d4). Split by를 **Destination IP**로 바꾸면 어느 목적지가 그런지 보여요.

### B6. 목적지 포트 { #b6 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| fillnull value="-" service
| stats count as conns dc(id_orig_h) as clients dc(id_resp_h) as servers values(service) as service values(dst_scope) as scope by id_resp_p proto
| sort - conns
```

- `values(service) as service` — 그 포트에서 본 서비스 이름들. `values()` = 중복 없는 값 목록.
- `values(dst_scope) as scope` — 그 포트가 내부·외부 어디로 갔나.

```text
id_resp_p  proto  conns  clients  servers  service   scope        ← 결과 예시
53         udp    702    3        1        dns       internal
443        tcp    305    3        38       ssl       external
80         tcp    121    3        9        http      external
445        tcp    18     2        2        smb       internal
4143       tcp    9      1        1        -         external
```

**읽는 법:** 잘 알려진 포트(53, 80, 443, 445, 88, 389, 123) 다음에 오는 **낯선 포트**를 봐요. 위 예시의 `4143`처럼 서비스를 못 알아봤고(`-`) 외부로 나간 포트는 D3에서 자세히 봐요. 포트 번호 뜻은 [잘 알려진 포트 번호](../../../basics/well-known-ports.md)에서 찾을 수 있어요.

---

## C. 누가 누구인가 { #c-identity }

### C1. 연결을 시작하는 내부 호스트 { #c1 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval src_scope=case(match(id_orig_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_orig_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where src_scope="internal"
| stats count as sessions dc(id_resp_h) as destinations dc(id_resp_p) as ports sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first max(ts) as last values(orig_l2_addr) as mac by id_orig_h
| eval sent_KB=round(sent/1024,1), received_KB=round(received/1024,1)
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
| table id_orig_h mac sessions destinations ports sent_KB received_KB first last
| sort - sessions
```

- `where src_scope="internal"` — 내부에서 **시작한** 연결만.
- `dc(id_resp_h) as destinations` — 목적지 수. `dc(id_resp_p) as ports` — 쓴 포트 수.
- `values(orig_l2_addr) as mac` — 보낸 쪽 MAC 주소(pcapbox의 Zeek 설정 `mac-logging`이 넣어 줘요).
- `eval sent_KB=round(sent/1024,1)` — 바이트 → KB.
- `table 필드들` — 보여 줄 열과 순서. `sort - sessions` — 연결이 많은 순.

```text
id_orig_h   mac                sessions  destinations  ports  sent_KB  received_KB  first                last          ← 결과 예시
10.0.0.101  00:0c:29:aa:01:01  1210      44            9      612.4    20811.0      2026-01-20 01:00:03  2026-01-20 01:42:55
10.0.0.102  00:0c:29:aa:01:02  598       12            6      288.1    1210.6       2026-01-20 01:00:09  2026-01-20 01:42:50
10.0.0.10   00:0c:29:aa:00:10  32        3             2      4.2      3.0          2026-01-20 01:02:11  2026-01-20 01:40:02
```

**읽는 법:** 캡처의 **주인공**(연결이 가장 많은 PC)을 먼저 찾아요. 목적지가 수십 개 이상이면 사람이 웹을 본 모습, 1–3개뿐이면 프로그램(비콘)일 가능성이 커요. DC(10.0.0.10)처럼 서버가 연결을 조금 시작하는 것은 보통이에요(DNS 전달, 시간 맞추기).

### C2. 호스트 신원 — 이름, 도메인, 사용자, MAC, OS 힌트 { #c2 }

Windows PC는 여러 곳에서 **자기 이름을 말해요**. 이 패널은 네 로그를 한 번에 모아요.

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:dhcp OR sourcetype=zeek:ntlm OR sourcetype=zeek:kerberos OR sourcetype=zeek:http)
| eval ip=if(sourcetype="zeek:dhcp", coalesce(assigned_addr, client_addr, requested_addr), id_orig_h)
| eval kc=mvindex(split(client,"/"),0), realm=mvindex(split(client,"/"),1)
| eval hostname_seen=case(sourcetype="zeek:dhcp", host_name, sourcetype="zeek:ntlm", hostname, sourcetype="zeek:kerberos" AND like(kc,"%$"), upper(rtrim(kc,"$")))
| eval user_seen=case(sourcetype="zeek:ntlm" AND len(username)>0 AND NOT like(username,"%$"), username."@".coalesce(domainname,"?"), sourcetype="zeek:kerberos" AND len(kc)>0 AND NOT like(kc,"%$"), kc."@".coalesce(realm,"?"))
| eval domain_seen=case(sourcetype="zeek:dhcp", domain, sourcetype="zeek:ntlm", domainname, sourcetype="zeek:kerberos", realm)
| eval mac_seen=if(sourcetype="zeek:dhcp", mac, null())
| eval ua=if(sourcetype="zeek:http", user_agent, null())
| eval os_hint=case(match(ua,"Windows NT 10\.0"),"Windows 10/11", match(ua,"Windows NT 6\.3"),"Windows 8.1", match(ua,"Windows NT 6\.2"),"Windows 8", match(ua,"Windows NT 6\.1"),"Windows 7", match(ua,"Windows NT 6\.0"),"Windows Vista", match(ua,"Windows NT 5\.1"),"Windows XP", match(ua,"iPhone|iPad"),"iOS", match(ua,"Android"),"Android", match(ua,"Macintosh|Mac OS X"),"macOS", match(ua,"Linux"),"Linux")
| where match(ip,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")
| stats values(hostname_seen) as hostname values(domain_seen) as domain values(user_seen) as users values(mac_seen) as mac values(os_hint) as os_hint dc(ua) as user_agents values(sourcetype) as seen_in by ip
| eval seen_in=replace(mvjoin(seen_in," "),"zeek:","")
| sort ip
```

- 1줄: DHCP, NTLM, Kerberos, HTTP 로그를 함께 가져와요(`OR`).
- 2줄 `ip=if(sourcetype="zeek:dhcp", coalesce(assigned_addr, client_addr, requested_addr), id_orig_h)` — DHCP는 받은 주소를, 나머지는 보낸 쪽 IP를 써요. `coalesce(a,b,c)` = **비어 있지 않은 첫 값**.
- 3줄: Kerberos `client`는 `계정/도메인` 모양이라 `split(client,"/")`로 나눠요. `mvindex(목록,0)` = 첫 조각(계정), `1` = 둘째(도메인).
- 4줄 `hostname_seen` — DHCP의 `host_name`, NTLM의 `hostname`, 그리고 Kerberos 계정이 **`$`로 끝나면 컴퓨터 계정**이라 `$`를 떼고(`rtrim(kc,"$")`) 대문자로(`upper`).
- 5줄 `user_seen` — `$`로 안 끝나는 NTLM·Kerberos 계정 = **사람 사용자**. `user@도메인` 모양으로 만들어요. `len(username)>0` = 이름이 실제로 있을 때만.
- 8–9줄 `os_hint` — User-Agent의 `Windows NT 6.1` 같은 버전을 이름으로 바꿔요: `10.0` = Windows 10/11, `6.3` = 8.1, `6.2` = 8, `6.1` = 7, `6.0` = Vista, `5.1` = XP.
- 10줄 `where match(ip,...)` — 사설 IP만.
- 11줄 `stats values(...) by ip` — IP마다 본 값들을 모두 모아요.
- 12줄 `seen_in` — 어느 로그에서 봤는지(`dhcp ntlm kerberos http`).

```text
ip          hostname  domain    users        mac                os_hint     user_agents  seen_in              ← 결과 예시
10.0.0.10   DC01      LAB                                                   0            kerberos
10.0.0.101  PC-01     LAB       alice@LAB    00:0c:29:aa:01:01  Windows 10  4            dhcp http kerberos ntlm
10.0.0.102  PC-02     LAB       bob@LAB      00:0c:29:aa:01:02  Windows 10  2            dhcp http kerberos
```

**읽는 법:** 이름·사용자가 **여러 로그에서 같게** 나오면 확실해요. 한 IP에 사용자가 둘 이상이면 공용 PC이거나, 다른 계정 자격증명을 쓴 흔적일 수 있어요(SMB 대시보드 [F7](smb-dashboard.md#f-ntlm)). User-Agent 수(`user_agents`)가 갑자기 많으면 브라우저 말고 **다른 프로그램도 웹에 접속**했다는 뜻이에요 → F5.

### C3. 내부 서버와 역할 { #c3 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="internal" AND NOT (conn_state="S0" OR conn_state="REJ")
| eval role=case(id_resp_p=53,"DNS", id_resp_p=67,"DHCP server", id_resp_p=88,"Kerberos - domain controller", id_resp_p=389,"LDAP - domain controller", id_resp_p=636,"LDAPS - domain controller", id_resp_p=3268,"Global Catalog - domain controller", id_resp_p=464,"Kerberos password change - DC", id_resp_p=135,"RPC endpoint mapper", id_resp_p=445,"SMB file sharing", id_resp_p=139,"NetBIOS session (old SMB)", id_resp_p=137,"NetBIOS name", id_resp_p=138,"NetBIOS datagram", id_resp_p=123,"NTP time", id_resp_p=80,"Web (HTTP)", id_resp_p=443,"Web (HTTPS)", id_resp_p=8080,"Web proxy or alt HTTP", id_resp_p=3128,"Web proxy", id_resp_p=25,"Mail (SMTP)", id_resp_p=587,"Mail submission", id_resp_p=110,"Mail (POP3)", id_resp_p=143,"Mail (IMAP)", id_resp_p=3389,"Remote Desktop (RDP)", id_resp_p=5985,"WinRM (HTTP)", id_resp_p=5986,"WinRM (HTTPS)", id_resp_p=22,"SSH", id_resp_p=21,"FTP", id_resp_p=1433,"MS SQL", id_resp_p=9100,"Printer (RAW)", id_resp_p=5355,"LLMNR name lookup", id_resp_p=1900,"SSDP discovery", id_resp_p=5353,"mDNS", true(),"port ".id_resp_p."/".proto)
| stats dc(id_orig_h) as clients count as conns values(role) as roles by id_resp_h
| eval roles=mvindex(roles,0,11)
| sort - clients
```

- `where dst_scope="internal" AND NOT (conn_state="S0" OR conn_state="REJ")` — **대답한** 내부 목적지만. 대답 없는 곳은 서버라고 할 수 없어요.
- `eval role=case(id_resp_p=53,"DNS", id_resp_p=88,"Kerberos - domain controller", ...)` — 포트 번호로 역할 이름을 붙여요. 표에 없는 포트는 `port 번호/프로토콜`.
- `stats dc(id_orig_h) as clients count as conns values(role) as roles by id_resp_h` — 서버마다 손님 수, 연결 수, 역할 목록.
- `mvindex(roles,0,11)` — 역할이 너무 많으면 앞 12개만.

```text
id_resp_h   clients  conns  roles                                                                    ← 결과 예시
10.0.0.10   3        410    DNS, Kerberos - domain controller, LDAP - domain controller, NTP time, RPC endpoint mapper, SMB file sharing, port 49667/tcp
10.0.0.1    3        12     DHCP server
10.0.0.102  1        9      SMB file sharing, RPC endpoint mapper
```

**읽는 법:** **88 + 389 + 445 + 53**을 함께 가진 서버 = **도메인 컨트롤러(DC)**. 게이트웨이(보통 `.1` 또는 `.254`)는 DHCP·DNS를 맡기도 해요. **PC(10.0.0.102)가 SMB·RPC 서버처럼 보이면** 다른 PC가 그 PC에 접속했다는 뜻 — 횡적 이동 후보예요 → [대시보드 2](smb-dashboard.md).

### C4. DHCP { #c4 }

```spl
index=zeek sourcetype=zeek:dhcp pcap_case="<case>"
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S"), msg_types=mvjoin(msg_types," ")
| table time client_addr requested_addr assigned_addr mac host_name client_fqdn domain server_addr msg_types
```

- `sort 0 ts` — 시간 순서. `0` = 줄 수 제한 없이 모두.
- `mvjoin(msg_types," ")` — 여러 값을 한 줄 글로. DHCP 메시지 순서(`DISCOVER OFFER REQUEST ACK`)가 보여요.

**읽는 법:** `host_name`이 PC 이름, `mac` 앞 6자리는 제조사(OUI)예요 — `00:0c:29` / `00:50:56` = VMware, `08:00:27` = VirtualBox. 로그가 없으면 PC가 이미 IP를 가진 상태에서 캡처가 시작된 거예요(C2의 NTLM·Kerberos를 봐요).

---

## D. 바깥과의 통신 { #d-external }

D1과 D2는 베이스 **`b_ext`**를 나눠 써요.

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:conn OR sourcetype=zeek:ssl OR sourcetype=zeek:http)
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external"
| eval name=case(sourcetype="zeek:ssl", server_name, sourcetype="zeek:http", mvdedup(host))
| stats count(eval(sourcetype="zeek:conn")) as conns dc(id_orig_h) as clients values(id_resp_p) as ports values(name) as names sum(orig_bytes) as out sum(resp_bytes) as in min(ts) as first max(ts) as last by id_resp_h
| eval out_KB=round(out/1024,1), in_KB=round(in/1024,1), names=mvindex(names,0,4)
```

- 1줄: conn, ssl, http 세 로그를 함께. 연결 수·바이트는 conn에서, **이름**은 ssl(SNI)과 http(Host)에서 가져와요.
- 3줄: 바깥 목적지만.
- 4줄 `name=case(sourcetype="zeek:ssl", server_name, sourcetype="zeek:http", mvdedup(host))` — TLS면 SNI, HTTP면 Host 헤더. `mvdedup()` = 여러 값 중 중복 제거(pcapbox에서 `host`가 두 번 들어가는 경우 대비).
- 5줄 `count(eval(sourcetype="zeek:conn")) as conns` — **conn 로그만** 세요. ssl·http 줄까지 세면 숫자가 부풀어요.

### D1. 바깥 목적지 — 연결 많은 순 { #d1 }

```spl
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
| table id_resp_h names ports conns clients out_KB in_KB first last
| sort - conns
```

```text
id_resp_h      names                                 ports    conns  clients  out_KB  in_KB    first                last          ← 결과 예시
203.0.113.20   cdn.example.com                       443      88     3        120.3   3401.2   2026-01-20 01:00:21  2026-01-20 01:41:10
198.51.100.7   update-check.example.net              443      36     1        18.9    2.1      2026-01-20 01:03:00  2026-01-20 01:42:30
198.51.100.44                                        4143     9      1        0       0        2026-01-20 01:07:12  2026-01-20 01:39:12
```

**읽는 법:** 맨 위는 대부분 CDN, Microsoft, Google 같은 정상 서비스예요. 볼 것은 **모양이 다른 줄**이에요 — 이름이 없음(위 셋째 줄), 흔치 않은 포트, 연결은 많은데 바이트가 작고 일정함(둘째 줄: 비콘 후보 → D4), `out_KB`가 `in_KB`보다 큼(유출 후보 → D5).

### D2. 드문 바깥 목적지 { #d2 }

```spl
| where conns<=3 AND clients=1
| sort first
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
| table first id_resp_h names ports conns out_KB in_KB
```

- `where conns<=3 AND clients=1` — 연결 3번 이하, 한 PC만 간 곳. 악성 다운로드 서버는 **한 번 쓰고 마는** 경우가 많아요.
- `sort first` — 처음 본 시각 순서. 사건의 순서를 따라가기 좋아요.

### D3. 흔치 않은 포트로 나간 트래픽 { #d3 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external" AND NOT (id_resp_p=80 OR id_resp_p=443 OR id_resp_p=53 OR id_resp_p=123)
| fillnull value="-" service
| stats count as conns values(conn_state) as states sum(orig_bytes) as out sum(resp_bytes) as in min(ts) as first by id_orig_h id_resp_h id_resp_p proto service
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| sort - conns
```

- `NOT (id_resp_p=80 OR id_resp_p=443 OR id_resp_p=53 OR id_resp_p=123)` — 웹, DNS, NTP를 빼요. `NOT (...)` = 괄호 안 조건이 **아닌 것**.
- `values(conn_state) as states` — `S0`·`REJ`만 있으면 **연결 실패만 반복** — 죽었거나 막힌 C2예요.

### D4. 비콘 후보 — 규칙적으로 반복되는 연결 { #d4 }

악성코드는 C2 서버에 **일정한 간격**으로 "명령 있어?"라고 물어요(비콘). 사람의 브라우징은 간격이 들쭉날쭉해요. 이 패널은 **간격이 얼마나 일정한지** 숫자로 보여 줘요.

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external"
| sort 0 ts
| streamstats current=f last(ts) as prev_ts by id_orig_h id_resp_h id_resp_p
| eval gap=ts-prev_ts
| stats count as conns avg(gap) as avg_gap stdev(gap) as sd_gap avg(orig_bytes) as avg_out min(ts) as first max(ts) as last by id_orig_h id_resp_h id_resp_p
| where conns>=5
| eval jitter=round(sd_gap/avg_gap,2), avg_gap=round(avg_gap,1), sd_gap=round(sd_gap,1), avg_out=round(avg_out,0), span_min=round((last-first)/60,1)
| sort jitter
| table id_orig_h id_resp_h id_resp_p conns avg_gap sd_gap jitter avg_out span_min
```

- 4줄 `sort 0 ts` — 시간 순서로 먼저 정렬해요. 다음 명령이 "바로 앞 줄"을 보기 때문이에요.
- 5줄 `streamstats current=f last(ts) as prev_ts by id_orig_h id_resp_h id_resp_p` — 같은 **출발 IP → 목적지 IP:포트** 묶음 안에서, **바로 앞 연결의 시각**을 `prev_ts`로 가져와요. `current=f` = 지금 줄은 빼고 앞 줄까지만.
- 6줄 `gap=ts-prev_ts` — 앞 연결과의 간격(초).
- 7줄 `stats count ... avg(gap) ... stdev(gap) ... by ...` — 묶음마다 연결 수, **평균 간격**, **표준편차**(간격이 평균에서 얼마나 흔들리나).
- 8줄 `where conns>=5` — 5번 이상 반복된 것만.
- 9줄 `jitter=round(sd_gap/avg_gap,2)` — 흔들림 ÷ 평균. **0에 가까울수록 시계처럼 규칙적**이에요. `span_min` = 처음부터 마지막까지 몇 분.
- 10줄 `sort jitter` — 가장 규칙적인 것부터.

```text
id_orig_h   id_resp_h     id_resp_p  conns  avg_gap  sd_gap  jitter  avg_out  span_min     ← 결과 예시
10.0.0.101  198.51.100.7  443        36     60.2     1.8     0.03    523      35.1
10.0.0.101  198.51.100.44 4143       9      240.0    0.9     0.00    0        32.0
10.0.0.101  203.0.113.20  443        88     27.5     61.4    2.23    1367     40.8
```

**읽는 법:** 첫 줄 — 60초마다(±2초), 매번 비슷한 크기 → **비콘 모양**. 둘째 줄 — 4분마다 정확히, 데이터 0 → 대답 없는 C2에 계속 시도. 셋째 줄 — jitter 2.23 → 들쭉날쭉한 사람 브라우징. 단, 업데이트 확인·메일 새로고침 같은 **정상 프로그램도 규칙적**이에요. 이름(D1)과 내용(F, G)으로 확인해요. 더 자세한 설명: [비코닝과 C2](../../../network/beaconing-c2.md).

### D5. 바깥으로 가장 많이 보낸 쌍 { #d5 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external"
| stats sum(orig_bytes) as out sum(resp_bytes) as in by id_orig_h id_resp_h
| sort - out
| head 10
| eval pair=id_orig_h." > ".id_resp_h, KB_sent=round(out/1024,1), KB_received=round(in/1024,1)
| table pair KB_sent KB_received
```

- `pair=id_orig_h." > ".id_resp_h` — 두 IP를 한 이름으로(막대 이름). `head 10` — 위 10개.

**읽는 법:** 보통 PC는 받는 양 ≫ 보내는 양이에요. `KB_sent`가 `KB_received`보다 **훨씬 긴 막대**면 업로드 — 데이터 유출, 클라우드 백업, 파일 업로드 중 하나예요. 목적지 이름(D1)과 시각을 확인해요.

### D6. 가장 긴 연결 · D7. 시간에 따른 바깥 연결 { #d6 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| where isnotnull(duration)
| sort - duration
| head 25
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S"), minutes=round(duration/60,1)
| table time id_orig_h id_resp_h id_resp_p proto service minutes orig_bytes resp_bytes conn_state uid
```

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external"
| eval _time=ts
| timechart span=1m limit=10 useother=t count by id_resp_h
```

- D6 `sort - duration | head 25` — 오래 이어진 연결 25개. `minutes=round(duration/60,1)`.
- D7 — 바깥 목적지별 시간 그래프(많은 10곳).

**읽는 법:** 몇십 분 이어진 연결 중 **바이트가 작은 것**은 원격 조종(리버스 셸, 터널)일 수 있어요. 정상 예: 메신저, 화상회의, Windows 푸시 알림(443).

---

## E. DNS { #e-dns }

E4–E6과 A9는 베이스 **`b_dnsq`**를 나눠 써요.

```spl
index=zeek sourcetype=zeek:dns pcap_case="<case>"
| where isnotnull(query)
| eval q=lower(query)
| stats count as queries dc(id_orig_h) as clients values(id_orig_h) as srcs values(qtype_name) as types values(rcode_name) as rcodes values(answers) as answers min(ts) as first max(ts) as last by q
| eval answers=mvindex(answers,0,3)
```

- `where isnotnull(query)` — 물어본 이름이 있는 것만. `lower(query)` — 대소문자를 맞춰요(`WPAD`와 `wpad`를 같게).
- `stats ... by q` — 이름마다 몇 번(`queries`), 몇 대가(`clients`), 누가(`srcs`), 어떤 타입·응답코드·답을 받았나, 처음·마지막 시각.
- `mvindex(answers,0,3)` — 답(IP)이 많으면 앞 4개만.

### E1. 질의 타입 · E2. 응답 코드 { #e1 }

```spl
index=zeek sourcetype=zeek:dns pcap_case="<case>"
| fillnull value="(none)" qtype_name
| stats count by qtype_name
| sort - count
```

```spl
index=zeek sourcetype=zeek:dns pcap_case="<case>"
| fillnull value="(no reply)" rcode_name
| stats count by rcode_name
| sort - count
```

| 보이면 | 뜻 |
|---|---|
| `A`, `AAAA` | IPv4 / IPv6 주소 묻기 — 대부분 |
| `SRV` | 서비스 찾기. `_ldap._tcp.dc._msdcs.도메인` = **DC 찾기** (도메인 PC의 정상 동작) |
| `SOA` | Windows PC가 **자기 이름을 DNS에 등록**하기 전에 보내요 |
| `PTR` | IP → 이름 묻기 |
| `TXT`, `NULL` 많음 | DNS 터널·C2 의심 |
| `NXDOMAIN` 많음 | 없는 이름을 계속 물음 → DGA(자동 생성 도메인) 악성코드 의심 |

### E3. 사용한 DNS 서버 { #e3 }

```spl
index=zeek sourcetype=zeek:dns pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| stats count as queries dc(id_orig_h) as clients by id_resp_h id_resp_p dst_scope
| sort - queries
```

**읽는 법:** 도메인 PC는 DC에게 물어요. `dst_scope=external`인 DNS 서버(예: `8.8.8.8`)에 직접 묻는 PC가 있으면 회사 DNS를 거치지 않는 설정이에요. 악성코드가 일부러 그러기도 해요.

### E4. 가장 드문 이름 · E5. 처음 물어본 순서 { #e4 }

```spl
| sort queries, first
| head 100
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| table q queries clients types rcodes answers first
```

```spl
| sort first
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S.%3N")
| table first q srcs queries types rcodes answers
```

- E4 `sort queries, first` — 적게 물어본 순, 같으면 이른 순. `head 100`.
- E5 `sort first` — **처음 물어본 순서**. 사건 흐름을 이름으로 따라가요: 검색 → 사이트 → 이상한 도메인 → …

```text
first                    q                          srcs        queries  types  rcodes    answers         ← E5 결과 예시
2026-01-20 01:02:10.551  www.example.org            10.0.0.101  2        A      NOERROR   203.0.113.20
2026-01-20 01:02:12.004  cdn.example.com            10.0.0.101  6        A      NOERROR   203.0.113.20
2026-01-20 01:02:58.310  update-check.example.net   10.0.0.101  1        A      NOERROR   198.51.100.7
```

**읽는 법:** 악성 도메인은 보통 **드물고**(E4 위쪽), 특정 시각 **바로 뒤에 처음** 나와요(E5). E5에서 문서를 연 시각이나 다운로드 시각 근처에 처음 보는 이름이 있는지 봐요.

### E6. 이상한 이름 { #e6 }

```spl
| eval len=len(q), labels=mvcount(split(q,".")), t=mvjoin(types," "), r=mvjoin(rcodes," ")
| where len>=40 OR labels>=6 OR match(t,"TXT|NULL") OR match(r,"NXDOMAIN")
| sort - len
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| table q len labels queries types rcodes srcs first
```

- `len(q)` — 이름 길이. `mvcount(split(q,"."))` — 점으로 나눈 조각 수(레이블 수).
- `where len>=40 OR labels>=6 OR match(t,"TXT|NULL") OR match(r,"NXDOMAIN")` — 아주 길거나, 조각이 많거나, TXT/NULL 타입이거나, 없는 이름.

**읽는 법:** `a8f3k2...x9.example.com`처럼 **긴 무작위 글자**가 앞에 붙은 이름이 많으면 DNS 터널(데이터를 이름에 숨겨 보냄) 의심이에요. 정상 예외: 백신 클라우드 조회, CDN의 긴 이름.

---

## F. HTTP { #f-http }

HTTP는 **내용이 다 보이는** 유일한 웹 트래픽이에요. pcapbox에서는 `host` 필드 = HTTP Host 헤더예요.

### F1. 메서드 · F2. 상태 코드 · F3. 응답 파일 형식 { #f1 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| fillnull value="(none)" method
| stats count by method
| sort - count
```

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| fillnull value="(no reply)" status_code
| stats count by status_code
| sort - count
```

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| eval mime=coalesce(mvindex(resp_mime_types,0),"(none)")
| stats count by mime
| sort - count
```

- F3 `mvindex(resp_mime_types,0)` — 응답 본문의 형식(Zeek가 내용으로 알아낸 것). 여러 개면 첫 번째.

| 보이면 | 뜻 |
|---|---|
| `POST`가 많음 | 클라이언트가 데이터를 보냄 — C2 체크인, 로그인, 업로드 (F6) |
| `CONNECT` | 프록시를 거친 HTTPS |
| `200` 대부분 | 정상. `302`/`301` = 다른 곳으로 보냄(리다이렉트 → F9), `404` = 없음 |
| `application/x-dosexec` | **Windows 프로그램**이 HTTP로 내려옴 → F7, H3 |

### F4. HTTP 호스트 · F5. User-Agent (드문 것 먼저) { #f4 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| eval h=mvdedup(host)
| stats count as requests dc(id_orig_h) as clients values(method) as methods dc(uri) as uris sum(response_body_len) as resp_bytes values(id_resp_h) as ips min(ts) as first by h
| eval resp_KB=round(resp_bytes/1024,1)
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| table h ips requests clients methods uris resp_KB first
| sort - requests
```

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| fillnull value="(none)" user_agent
| stats count as requests dc(id_orig_h) as clients values(id_orig_h) as srcs dc(host) as hosts min(ts) as first by user_agent
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| sort requests
| table user_agent requests clients srcs hosts first
```

- F4 `dc(uri) as uris` — 그 호스트에서 연 서로 다른 주소 수. `sum(response_body_len)` — 받은 본문 크기 합.
- F5 `sort requests` — **가장 적게 쓴 User-Agent부터**.

```text
user_agent                                                          requests  clients  srcs        hosts   ← F5 결과 예시
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; ...)             3         1        10.0.0.101  1
Microsoft-CryptoAPI/10.0                                            8         2        10.0.0.101  2
Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120.0 ...      170       2        10.0.0.101  9
```

**읽는 법:** 한 PC에 브라우저 UA는 보통 1–2개예요. **드물고 옛날 모양**(`MSIE 7.0` 등)이거나 **브라우저가 아닌** UA(`WinHTTP`, `curl`, `PowerShell`, 빈 값)가 한 호스트에만 몇 번 나오면 **스크립트나 악성코드**일 가능성이 커요. 정상 예: `Microsoft-CryptoAPI`(인증서 확인), `Windows-Update-Agent`, `Microsoft NCSI`(인터넷 연결 확인).

### F6. POST 요청 { #f6 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>" method=POST
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S.%3N"), h=mvdedup(host)
| table time id_orig_h id_resp_h h uri request_body_len response_body_len status_code user_agent uid
```

- 첫 줄 끝의 `method=POST` — POST 요청만 가져와요.
- `request_body_len` — 보낸 본문 크기, `response_body_len` — 받은 본문 크기.

**읽는 법:** **같은 주소로 비슷한 크기의 POST가 반복**되면 C2 체크인이에요. 본문 내용은 Splunk에 없으니 `uid`나 시각으로 **Arkime**에서 열어 봐요.

### F7. HTTP로 내려받은 프로그램·스크립트·압축·문서 { #f7 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| eval mime=mvjoin(resp_mime_types,","), h=mvdedup(host)
| eval fname=lower(mvindex(split(mvindex(split(uri,"?"),0),"/"),-1)), ext=if(match(fname,"\."), mvindex(split(fname,"."),-1), "")
| where match(mime,"dosexec|x-msdownload|x-executable|java-archive|x-shockwave-flash|zip|x-rar|7z|octet-stream|hta|x-ms-shortcut|msi|msword|ms-excel|ms-powerpoint|officedocument|rtf|pdf") OR match(ext,"^(exe|dll|scr|ps1|vbs|hta|bat|cmd|msi|jar|zip|rar|7z|iso|lnk|doc|docm|xls|xlsm|ppt|pptm|rtf|swf)$")
| eval mismatch=if(match(mime,"dosexec") AND NOT match(ext,"^(exe|dll|scr|sys|msi|com)$"),"EXE under another name","")
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S")
| table time id_orig_h id_resp_h h uri mime response_body_len mismatch status_code uid
```

- 3줄: 주소에서 `?` 앞(`split(uri,"?")`의 첫 조각) → `/`로 나눈 마지막 조각 = **파일 이름**, `.`으로 나눈 마지막 조각 = **확장자**.
- 4줄 `where match(mime,"dosexec|...") OR match(ext,"^(exe|dll|...)$")` — 형식이 프로그램·압축·문서이거나, 확장자가 그런 것.
- 5줄 `mismatch` — 형식은 EXE(`dosexec`)인데 이름이 `.exe`가 아니면 표시 → **이름을 속인 프로그램**(예: `.gif`, `.jpg`로 위장). 빨갛게 보여요.

**읽는 법:** 줄마다 **어디서(h, uri) 누가(id_orig_h) 언제** 받았는지 보고, H3에서 같은 파일의 **해시**를 찾아요.

### F8. IP로 바로 접속하거나 Host가 없는 HTTP { #f8 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| eval h=mvdedup(host)
| where isnull(h) OR match(h,"^\d+\.\d+\.\d+\.\d+(:\d+)?$")
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S")
| table time id_orig_h id_resp_h id_resp_p h method uri status_code user_agent uid
```

- `match(h,"^\d+\.\d+\.\d+\.\d+(:\d+)?$")` — Host가 숫자 IP(포트가 붙어도). `\d+` = 숫자 하나 이상.

**읽는 법:** 정상 웹사이트는 거의 항상 **도메인 이름**으로 접속해요. IP로 바로 가는 HTTP는 악성코드 다운로드·C2에서 자주 보여요.

### F9. 웹 타임라인과 Referer (리다이렉트 따라가기) { #f9 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| sort 0 ts
| head 3000
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S.%3N"), h=mvdedup(host), ref=replace(referrer,"^https?://",""), mime=mvindex(resp_mime_types,0)
| table time id_orig_h method h uri ref status_code mime response_body_len user_agent uid
```

- `head 3000` — 시간 순 처음 3000줄(많으면 Case·Host IP로 좁혀요).
- `ref=replace(referrer,"^https?://","")` — Referer에서 `http://`, `https://`를 떼서 짧게.

**읽는 법:** **Referer** = "어느 페이지에서 왔나". 해킹된 사이트 → 리다이렉터 → 익스플로잇 킷 / 가짜 업데이트 페이지로 이어지는 사슬을 Referer로 따라가요. 갑자기 Referer가 **없는** 요청과 **다른 User-Agent**가 나오면 브라우저가 아니라 새로 실행된 프로그램이에요.

---

## G. TLS와 인증서 { #g-tls }

HTTPS는 내용이 안 보여요. 대신 **SNI**(접속하려는 사이트 이름)와 **인증서**는 보여요.

### G1. TLS 버전 · G2. 서버 이름(SNI) { #g1 }

```spl
index=zeek sourcetype=zeek:ssl pcap_case="<case>"
| fillnull value="(unknown)" version
| stats count by version
```

```spl
index=zeek sourcetype=zeek:ssl pcap_case="<case>"
| fillnull value="(no SNI)" server_name
| stats count as conns dc(id_orig_h) as clients values(id_resp_h) as ips values(id_resp_p) as ports values(version) as versions values(established) as established min(ts) as first by server_name
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| sort - conns
```

- G2 `fillnull value="(no SNI)" server_name` — 이름 없이 접속한 것도 남겨요. `values(established)` — 핸드셰이크가 끝났나(`true`/`false`).

**읽는 법:** `TLSv10`·`SSLv3` 같은 옛 버전은 오래된 악성코드나 장비에서 나와요. SNI 목록에서 **D1·E4와 같은 수상한 이름**을 찾아요. `established=false`만 있으면 연결이 안 됐어요.

### G3. SNI가 없거나 443이 아닌 TLS { #g3 }

```spl
index=zeek sourcetype=zeek:ssl pcap_case="<case>"
| where isnull(server_name) OR id_resp_p!=443
| stats count as conns values(version) as versions values(established) as established min(ts) as first max(ts) as last by id_orig_h id_resp_h id_resp_p server_name
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
| sort - conns
```

**읽는 법:** 브라우저는 거의 항상 SNI를 보내요. **SNI 없이 IP로 가는 TLS**, 또는 443이 아닌 포트(`8443`, `4443`, `447`)의 TLS는 C2에서 자주 보여요.

### G4. 서버 인증서 — 자체 서명과 짧은 기간 { #g4 }

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:ssl OR sourcetype=zeek:x509)
| eval fp=if(sourcetype="zeek:x509", fingerprint, mvindex(cert_chain_fps,0))
| where isnotnull(fp)
| stats values(server_name) as sni values(id_resp_h) as ips count(eval(sourcetype="zeek:ssl")) as conns values(certificate_subject) as subject values(certificate_issuer) as issuer values(san_dns) as san min(certificate_not_valid_before) as nvb max(certificate_not_valid_after) as nva by fp
| where conns>0 AND isnotnull(subject)
| eval self_signed=if(mvjoin(subject,"")=mvjoin(issuer,""),"YES",""), days_valid=round((nva-nvb)/86400,0), not_before=strftime(nvb,"%Y-%m-%d"), not_after=strftime(nva,"%Y-%m-%d"), san=mvindex(san,0,4)
| sort -self_signed, days_valid
| table sni ips conns subject issuer self_signed days_valid not_before not_after san
```

- 1줄: ssl과 x509 로그를 함께. x509(인증서 로그)에는 IP가 없어서 ssl과 **지문(fingerprint)**&#8203;으로 이어요.
- 2줄 `fp=if(sourcetype="zeek:x509", fingerprint, mvindex(cert_chain_fps,0))` — x509는 자기 지문, ssl은 서버가 보낸 인증서 사슬의 **첫 번째(서버 자신)** 지문.
- 4줄 `stats ... by fp` — 같은 지문끼리 묶어서 SNI·IP(ssl 쪽)와 subject·issuer·SAN·유효기간(x509 쪽)을 한 줄로 만들어요. **join 없이 두 로그를 잇는 방법**이에요.
- 5줄 `where conns>0 AND isnotnull(subject)` — 양쪽이 다 있는 것만.
- 7줄 `self_signed` — 발급자(issuer)와 주인(subject)이 같으면 **자체 서명**. `days_valid` — 유효기간 일수.
- 8줄 `sort -self_signed, days_valid` — 자체 서명 먼저, 그다음 기간이 짧은 순.

```text
sni                ips            conns  subject                                        issuer                                         self_signed  days_valid   ← 결과 예시
(없음)             198.51.100.9   14     CN=localhost,O=Default Company Ltd,C=XX        CN=localhost,O=Default Company Ltd,C=XX        YES          365
cdn.example.com    203.0.113.20   88     CN=cdn.example.com                             CN=Example TLS CA 2025,O=Example Trust,C=US                 90
```

**읽는 법:** `O=Default Company Ltd`, `CN=localhost`, `Internet Widgits Pty Ltd` 같은 **OpenSSL 기본값** 인증서는 사람이 대충 만든 서버예요 — C2에서 아주 흔해요. 정상 사이트 인증서는 알려진 CA가 발급하고 SAN에 도메인이 있어요. Let's Encrypt(90일)는 정상 사이트도 많이 써서 **짧은 기간만으로는 악성이 아니에요**.

---

## H. 파일 { #h-files }

Zeek는 HTTP, SMB, FTP, SMTP로 오간 파일을 `files.log`에 적고 **해시**를 계산해요(pcapbox의 `hash-all-files` 설정).

### H1. 파일 형식 · H2. 프로토콜 { #h1 }

```spl
index=zeek sourcetype=zeek:files pcap_case="<case>"
| fillnull value="(unknown)" mime_type
| stats count by mime_type
| sort - count
```

```spl
index=zeek sourcetype=zeek:files pcap_case="<case>"
| fillnull value="(unknown)" file_source
| stats count by file_source
```

- `file_source` — 파일이 지나간 프로토콜(`HTTP`, `SMB`, `FTP_DATA`, `SMTP`). Zeek 원래 이름은 `source`인데 Splunk의 `source`와 겹쳐서 pcapbox가 이름을 바꿨어요.

### H3. 프로그램·스크립트·압축·문서 (해시 포함) { #h3 }

```spl
index=zeek sourcetype=zeek:files pcap_case="<case>"
| eval fname=coalesce(filename,"")
| where match(mime_type,"dosexec|x-msdownload|x-executable|java-archive|zip|x-rar|7z|x-msi|vnd.ms-cab|x-shockwave-flash|msword|ms-excel|ms-powerpoint|officedocument|rtf|pdf|x-ms-shortcut|iso9660") OR match(lower(fname),"\.(exe|dll|scr|ps1|vbs|js|hta|bat|cmd|msi|jar|lnk|iso|zip|rar|7z|docm|xlsm)$")
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S"), KB=round(seen_bytes/1024,1), tx=mvjoin(tx_hosts,","), rx=mvjoin(rx_hosts,",")
| table time file_source tx rx mime_type fname KB md5 sha1 sha256 fuid
```

- `tx`(보낸 쪽) → `rx`(받은 쪽). `mvjoin(tx_hosts,",")` — 여러 값을 한 글로.
- `seen_bytes` — Zeek가 실제로 본 바이트. `total_bytes`보다 작으면 일부만 캡처된 파일이에요.

**읽는 법:** `md5`/`sha256`을 위협 인텔(VirusTotal 등, 폐쇄망이면 내부 IOC 목록)과 비교해요. HTTP로 받은 암호화 페이로드는 **디스크의 파일과 해시가 다를 수 있어요**(받은 뒤 풀어서 저장하니까).

### H4. Windows 프로그램(PE) { #h4 }

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:files OR sourcetype=zeek:pe)
| eval f=if(sourcetype="zeek:pe", id, fuid)
| stats values(tx_hosts) as tx values(rx_hosts) as rx values(file_source) as proto values(filename) as fname values(md5) as md5 values(sha256) as sha256 values(machine) as machine values(os) as os values(subsystem) as subsystem values(is_exe) as is_exe values(is_64bit) as is_64bit values(has_cert_table) as signed values(compile_ts) as compile_ts min(ts) as first by f
| where isnotnull(machine)
| eval compiled=strftime(compile_ts,"%Y-%m-%d %H:%M:%S"), first=strftime(first,"%Y-%m-%d %H:%M:%S")
| table first tx rx proto fname is_exe is_64bit machine subsystem compiled signed md5 sha256
```

- `pe.log`의 `id` = files.log의 `fuid`(파일 이름표). 두 로그를 `f`로 묶어서 이어요.
- `compile_ts` — 프로그램이 만들어진(컴파일된) 시각. `has_cert_table` — 코드 서명이 있나.

**읽는 법:** 컴파일 시각이 **사건 며칠 전**이고 서명이 없는 EXE는 의심스러워요. 단 컴파일 시각은 공격자가 바꿀 수 있어요.

---

## I. 알림과 이상 { #i-alerts }

### I1. Snort 알림 (룰별) · I3. 시간 순 { #i1 }

```spl
index=snort sourcetype=snort:alert pcap_case="<case>"
| stats count by msg
| sort - count
| head 15
```

```spl
index=snort sourcetype=snort:alert pcap_case="<case>"
| sort 0 _time
| eval time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table time sid msg src_ip src_port dest_ip dest_port
```

**읽는 법:** 알림은 **시작점**이지 결론이 아니에요. 알림 시각 ±1분의 HTTP(F9)·DNS(E5)·파일(H3)을 보고 실제로 무슨 일이 있었는지 확인해요. 직접 쓴 룰(`sid` 1000000 이상)이 몇 번 울렸는지도 여기서 세요.

### I2. Zeek weird · I4. Zeek notice { #i2 }

```spl
index=zeek sourcetype=zeek:weird pcap_case="<case>"
| stats count min(ts) as first values(id_orig_h) as srcs values(id_resp_h) as dsts by name
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| sort - count
```

```spl
index=zeek sourcetype=zeek:notice pcap_case="<case>"
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S")
| table time note msg sub src dst p uid
```

| weird `name` 예 | 뜻 |
|---|---|
| `truncated_header`, `data_before_established` | 패킷 일부만 캡처됨 — 보통 별일 아님 |
| `bad_HTTP_request`, `unknown_HTTP_method` | HTTP 규칙을 어긴 요청 — 스캐너, 손으로 만든 C2 |
| `dns_unmatched_reply` | 질문 없이 온 답 |
| `possible_split_routing` | 한쪽 방향만 캡처됨 |

notice는 Zeek 스크립트가 띄운 경고예요(예: `SSL::Invalid_Server_Cert`, 스캔 탐지). pcapbox 기본 설정에서는 거의 없어요.

---

## J. 활동 타임라인과 uid { #j-activity }

### J1. 활동 타임라인 — 모든 로그를 시간 순서로 { #j1 }

**Host IP** 상자에 IP를 넣고 이 표를 보면 그 호스트가 **언제 무엇을 했는지** 한 줄씩 나와요.

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:conn OR sourcetype=zeek:dns OR sourcetype=zeek:http OR sourcetype=zeek:ssl OR sourcetype=zeek:files OR sourcetype=zeek:smb_mapping OR sourcetype=zeek:smb_files OR sourcetype=zeek:dce_rpc OR sourcetype=zeek:ntlm OR sourcetype=zeek:kerberos)
| eval log=replace(sourcetype,"zeek:","")
| eval src=coalesce(id_orig_h, mvjoin(tx_hosts,",")), dst=coalesce(id_resp_h, mvjoin(rx_hosts,",")), dport=id_resp_p
| eval what=case(
    log="conn", coalesce(proto,"")." ".coalesce(service,"-")." state=".coalesce(conn_state,"")." out=".coalesce(orig_bytes,0)." in=".coalesce(resp_bytes,0),
    log="dns", coalesce(qtype_name,"")." ".coalesce(query,"")." > ".coalesce(mvjoin(answers," "), rcode_name, ""),
    log="http", coalesce(method,"")." ".coalesce(mvdedup(host),"").coalesce(uri,"")." [".coalesce(status_code,"-")."]",
    log="ssl", "TLS ".coalesce(server_name,"(no SNI)")." ".coalesce(version,""),
    log="files", coalesce(file_source,"")." ".coalesce(mime_type,"")." ".coalesce(filename,"")." ".coalesce(seen_bytes,"")." B md5=".coalesce(md5,""),
    log="smb_mapping", "MAP ".coalesce(path,""),
    log="smb_files", replace(coalesce(action,""),"SMB::","")." ".coalesce(path,"")." ".coalesce(name,""),
    log="dce_rpc", "RPC ".coalesce(endpoint,"")."::".coalesce(operation,""),
    log="ntlm", "NTLM ".coalesce(username,"")."@".coalesce(domainname,"")." from ".coalesce(hostname,"")." success=".coalesce(success,""),
    log="kerberos", "KRB ".coalesce(request_type,"")." ".coalesce(client,"")." > ".coalesce(service,"")." ".coalesce(error_msg,""))
| sort 0 ts
| head 5000
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S.%3N")
| table time log src dst dport what uid
```

- 1줄: conn, dns, http, ssl, files, SMB, RPC, NTLM, Kerberos 로그를 함께. 대시보드에서는 `(id_orig_h="$ip$" OR id_resp_h="$ip$" OR tx_hosts="$ip$" OR rx_hosts="$ip$")`가 붙어요.
- `log=replace(sourcetype,"zeek:","")` — `zeek:` 글자를 떼서 짧게.
- `src=coalesce(id_orig_h, mvjoin(tx_hosts,","))` — 보통은 출발 IP, files 로그는 보낸 쪽.
- `what=case(log="conn", ..., log="dns", ..., ...)` — 로그 종류마다 **한 줄 요약**을 만들어요. 예: conn = `tcp ssl state=SF out=517 in=4410`, dns = `A cdn.example.com > 203.0.113.20`, http = `GET www.example.org/index.html [200]`.
- `sort 0 ts | head 5000` — 시간 순 처음 5000줄.

```text
time                     log    src         dst            dport  what                                                 uid        ← 결과 예시
2026-01-20 01:02:58.310  dns    10.0.0.101  10.0.0.10      53     A update-check.example.net > 198.51.100.7            CzX1...
2026-01-20 01:02:58.402  conn   10.0.0.101  198.51.100.7   443    tcp ssl state=SF out=517 in=2210                     CfA9...
2026-01-20 01:02:58.402  ssl    10.0.0.101  198.51.100.7   443    TLS update-check.example.net TLSv12                  CfA9...
```

**읽는 법:** 같은 `uid`가 conn과 ssl에 함께 나오죠 — **같은 연결**이에요. 수상한 줄을 찾으면 그 줄을 **누르세요**.

### J2. 누른 연결의 모든 Zeek 기록 { #j2 }

```spl
index=zeek pcap_case="<case>" (uid="<uid>" OR conn_uids="<uid>" OR uids="<uid>")
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S.%3N")
| table time sourcetype _raw
```

- `uid="<uid>" OR conn_uids="<uid>" OR uids="<uid>"` — 연결 로그의 `uid`, files 로그의 `conn_uids`, dhcp 로그의 `uids`까지 같은 이름표를 찾아요.
- `table time sourcetype _raw` — `_raw` = Zeek가 쓴 **원래 JSON 한 줄 전체**. 표에 없는 필드까지 다 보여요.

**읽는 법:** 이 패널은 줄을 누르기 전에는 **숨어 있어요**. Arkime에서 같은 연결을 보려면 시각과 IP·포트로 찾아요(Arkime 검색: `ip == 10.0.0.101 && port == 443`).

---

다음: [대시보드 2 — SMB와 Windows 도메인](smb-dashboard.md) · 분석 순서는 [대시보드로 PCAP 분석하는 순서](analysis-workflow.md)
