---
title: 비코닝과 C2 탐지
tags:
  - concept
  - network
  - hunting
  - c2
---

# 비코닝과 C2 탐지 { #beaconing-c2-detection }

<div class="dfir-meta" markdown>
**분류:** 네트워크 헌팅 · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    임플란트는 집에 전화를 걸어야 하고, 그 방식은 사람과 통계적으로 다릅니다: **일정한 타이밍**, **일정한 크기**, **오랫동안 하나의 목적지**, **이상한 TLS/HTTP 지문**, **아무도 방문하지 않는 목적지**. 이 페이지는 Zeek/Splunk에서 그것을 찾는 체크리스트와 쿼리, 그리고 최신 C2가 숨으려고 하는 방법을 다룹니다.

## 신호 { #the-signals }

| 신호 | 생기는 이유 | 측정할 곳 |
|---|---|---|
| **일정한 간격** (지터 유무와 상관없이) | 임플란트가 체크인 사이에 N초 잠듦 | (`orig_h`, `resp_h`, `resp_p`)별 `conn.log ts` 차이 |
| 대기 중 **일정한 페이로드 크기** | "할 일 없음"은 매번 같은 메시지 | `orig_bytes` / `resp_bytes` 분산; `http.log response_body_len` |
| **오래 지속되는 관계** | 같은 쌍이 몇 시간/며칠 통신 | 쌍별 하루 연결 수; 처음 본 날짜 |
| **드문 목적지** | 감염된 호스트만 C2를 앎 | `resp_h` / SNI / 도메인별 `dc(id.orig_h)` |
| **`dns.log`에 거의 없음** 또는 **새 도메인** | 하드코딩된 IP, 또는 막 등록된 도메인 | 앞선 DNS 없는 연결; 도메인 나이 |
| **지문 불일치** | 임플란트의 TLS/HTTP 스택 ≠ 브라우저 | JA3/JA4 희소성, ALPN 없음, 이상한 UA, 헤더 순서 |
| **인증서 이상** | 자체 서명 / 기본값 / 막 생성됨 | `ssl.log validation_status`, `x509.log not_valid_before` |
| **업무 시간 외 활동** | 기계는 자지 않지만 사람은 잠 | 사용자가 자고 있을 03:00에 워크스테이션의 연결 |
| **바이트가 적은 긴 연결** | 계속 살아 있는 대화형 셸 / 리버스 터널 | `conn.log duration` > 몇 시간, 작은 `orig_bytes` |
| **나가는 바이트 ≫ 들어오는 바이트** | 유출 | 쌍별 `sum(orig_bytes)`; 호스트의 [SRUM](../windows/srum.md) |

## 간격 분석 — 핵심 기법 { #interval-analysis-the-core-technique }

연결이 충분한(예: 하루 20개 이상) (`id.orig_h`, `id.resp_h`, `id.resp_p`)마다 **연속된 연결 사이의 시간**을 계산하고 분포를 보세요:

- **완벽한 비콘**: 모든 차이 ≈ 60초 → 표준편차가 아주 작고 히스토그램에 뾰족한 막대 하나.
- **지터가 있는 비콘** (Cobalt Strike `sleep 60 jitter 30`): 차이가 42–60초에 고르게 퍼짐 → *상자 모양*, 여전히 범위가 정해져 있고 사람 트래픽과는 전혀 다름.
- **사람 / 브라우저**: 밀리초부터 몇 시간까지, 꼬리가 길고, 업무 시간에 몰림.
- **정상 백그라운드**: NTP(완전히 규칙적, 123번 포트, 아주 작음), Windows Update, AV 업데이트, OneDrive, Teams 접속 상태 — 규칙적*이면서* *많은* 호스트가 쓰는 잘 알려진 목적지. 드문 목적지인지가 이들을 가릅니다.

=== "Splunk — 비콘 점수"

    ```spl
    index=zeek sourcetype=zeek:conn local_orig=true local_resp=false
    | sort 0 id.orig_h, id.resp_h, id.resp_p, _time
    | streamstats current=f last(_time) as prev_time by id.orig_h, id.resp_h, id.resp_p
    | eval delta = _time - prev_time
    | where isnotnull(delta) AND delta > 0
    | stats count avg(delta) as avg_gap stdev(delta) as sd_gap avg(orig_bytes) as avg_up stdev(orig_bytes) as sd_up dc(uid) as conns min(_time) as first max(_time) as last by id.orig_h, id.resp_h, id.resp_p
    | where count >= 20
    | eval jitter_pct = round(100 * sd_gap / avg_gap, 1), size_var_pct = round(100 * sd_up / (avg_up+1), 1)
    | eval span_hours = round((last-first)/3600, 1)
    | where jitter_pct < 30 AND span_hours > 2
    | convert ctime(first) ctime(last)
    | sort jitter_pct
    ```

    한 줄씩: `sort 0 …, _time`은 모든 연결을 쌍과 시간 순으로 정렬합니다(`0` = 행 수 제한 없음). `streamstats current=f last(_time) as prev_time by …`는 정렬된 목록을 내려가면서 각 행마다 같은 쌍의 *이전* 행 타임스탬프를 가져옵니다 — `current=f`는 "현재 행은 포함하지 마라"는 뜻이라 이전 행이 나옵니다. `eval delta = _time - prev_time`이 초 단위 간격입니다. 그다음 `stats … by 쌍`이 쌍마다 요약합니다: 간격 개수, 평균과 표준편차, 업로드 크기의 평균/표준편차, 처음/마지막 시각. `jitter_pct`는 표준편차를 평균으로 나눈 백분율입니다 — 완벽한 비콘은 ~0%, 지터 30%인 Cobalt Strike는 15–20% 정도, 웹 브라우징은 100%를 훨씬 넘습니다. `where jitter_pct < 30 AND span_hours > 2`는 규칙적이고 오래 지속된 쌍만 남깁니다. 맨 위에 보이는 결과 예: 워크스테이션 → VPS IP 하나:443, 연결 1,400개, 평균 간격 61초, 지터 3%, 24시간에 걸침.

    같은 쿼리에 희소성을 더하기:

    ```spl
    ... 
    | eventstats dc(id.orig_h) as hosts_to_dest by id.resp_h
    | where hosts_to_dest <= 3
    ```

    `eventstats`는 `stats`와 비슷하지만 원래 행을 유지하고 결과를 새 필드로 붙입니다 — 여기서는 그 목적지와 통신하는 내부 호스트가 몇 대인지. 1–3대만 접속하는 목적지로의 비콘부터 여세요.

=== "Zeek + 셸 (작은 pcap / 하루 치)"

    ```bash
    # deltas for one pair
    zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log \
      | awk '$2=="10.0.0.25" && $3=="203.0.113.7" && $4==443 {print $1}' | sort -n \
      | awk 'NR>1{printf "%.0f\n", $1-prev} {prev=$1}' | sort -n | uniq -c | sort -rn | head
    # → "1372 60" (1,372 gaps of exactly 60 s) is a beacon; a browser gives a long messy list.

    # pairs by connection count, then eyeball the frequent ones
    zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | sort | uniq -c | sort -rn | awk '$1>100' | head -30
    ```

=== "RITA (무료, 전용 도구)"

    ```bash
    # Import Zeek logs, then ask for beacons / long connections / DNS oddities
    rita import /data/zeek/logs/2026-09-16 case01
    rita show-beacons case01 | head -20         # score, src, dst, connections, avg bytes, interval range
    rita show-long-connections case01
    rita show-exploded-dns case01                # subdomain explosion = tunnelling
    rita show-strobes case01                     # extremely high connection counts
    ```

    RITA(Active Countermeasures)는 바로 이 분석을 0–1 비콘 점수로 구현합니다. AC-Hunter는 상용 UI입니다.

## HTTP/TLS 수준 단서 { #httptls-level-tells }

- **같은 URI, 작은 응답, 끝없이**: 매분 `http.log` `GET /pixel.gif`, `response_body_len` 0–100, 결과를 돌려보낼 때 `request_body_len` > 0인 `POST /submit.php?id=…`.
- 1대만 쓰는 **User-Agent**; **HTTP/1.0** 또는 `Accept-Language`/`Referer` 없음; **`Host` 헤더**가 IP 그대로이거나 비어 있음.
- 그 호스트만 쓰는 **JA3/JA4** ([ssl.log](zeek/ssl-x509.md) 참고); **ALPN 없음**; **SNI 비어 있음**; **자체 서명 / 막 만든 인증서**; **`sni_matches_cert = F`** (프론팅).
- **인증서 재사용**: 몇 주에 걸쳐 여러 IP에서 같은 `x509` 지문.
- **Cobalt Strike / Sliver / Mythic / Havoc 기본값**이 있지만(기본 UA 문자열, 기본 인증서 `Major Cobalt Strike`, 기본 URI `/ca`, `/dpixel`, `/__utm.gif`, `/activity`), 유능한 운영자는 바꿉니다 — 행동에 기대고, 기본값은 덤으로 쓰세요.

## DNS C2와 터널링 { #dns-c2-tunnelling }

- **한 도메인**으로의 아주 높은 쿼리 빈도, 길고 엔트로피가 높은 서브도메인, 대부분 `TXT`/`NULL`/`CNAME`/`MX`; 호스트별 전체 **DNS 바이트**가 다른 호스트보다 훨씬 큼; 주소처럼 보이지 않는 응답. ([dns.log](zeek/dns-log.md))
- **회사 것이 아닌 리졸버**로, 또는 **TCP 53**으로 DNS를 쓰는 클라이언트.
- `rita show-exploded-dns`; Splunk: 호스트별·등록 도메인별 `dc(query)`.

## 그 밖의 채널 { #other-channels }

| 채널 | 보이는 모습 |
|---|---|
| **ICMP 터널** | `orig_bytes`가 크고, 패킷이 많고, 양방향인 `conn.log proto=icmp`; Wireshark `icmp && data.len > 64` |
| **오래 유지되는 리버스 셸 / SOCKS (chisel, ngrok, ssh -R)** | 몇 시간짜리 `conn.log duration`, 작은 데이터가 계속 오가는 `history` `ShADad…`, 22번이 아닌 포트의 `service=ssh` 또는 터널링 제공자(`*.ngrok.io`, `*.trycloudflare.com`, `*.serveo.net`)로의 `ssl` |
| **클라우드 서비스 C2** (Slack, Discord, Telegram, Dropbox, GitHub, Google Drive API) | 목적지는 정상처럼 보임; **일정한 간격 + 호스트 하나 + API 엔드포인트**(`api.telegram.org`, `discord.com/api/webhooks`, 일정 주기의 `raw.githubusercontent.com`)와 호스트의 *어떤 프로세스*인지(Sysmon 3 — Discord와 통신하는 `rundll32.exe`는 Discord가 아님)로 구분 |
| **도메인 프론팅 / CDN** | SNI = 큰 CDN, 한 호스트에서 일정한 간격, `sni_matches_cert=F` |
| **DoH** | `dns.log`에서 사라진 호스트가 DoH 제공자로 TLS 연결 |
| **WebSockets** | `http.log status_code=101` 후 하나의 긴 연결 |
| **QUIC/HTTP3** | `service=quic`인 UDP 443 — Zeek 6+는 SNI가 있는 `quic.log`를 기록 |
| **P2P / SMB 네임드 파이프 C2** (Cobalt Strike SMB 비콘) | **피해 호스트에서 인터넷 트래픽이 없음** — 피벗 호스트로의 내부 `445`에서 `smb_files`/`dce_rpc`가 네임드 파이프(`\\pipe\msagent_*`, `\\pipe\postex_*`, `\\pipe\MSSE-*`)를 보여 줌; 밖으로 비코닝하는 것은 피벗 호스트 |

## 잡음 걸러 내기 { #tuning-out-the-noise }

허용 목록은 포트가 아니라 **목적지 + 행동**으로 만드세요. 정상적으로 비코닝하는 것들: NTP(123), Windows Update / 배달 최적화(`*.windowsupdate.com`, `*.delivery.mp.microsoft.com`), Defender/AV 클라우드(`*.wdcp.microsoft.com`), Office/Teams 접속 상태(`*.office.com`, `*.teams.microsoft.com`), OneDrive/Dropbox/Google Drive 동기화, Chrome/Edge 업데이트, Slack, Zoom, Intune/SCCM/Jamf, EDR 에이전트(**자사 에이전트의 목적지를 알아 두세요**), 프린터, UPS/IoT가 자기 클라우드로, 모니터링 에이전트(Zabbix, Nagios, 9997번으로 인덱서에 가는 Splunk UF), 리졸버로의 DNS. 이 목록의 모든 것은 **많은** 호스트가 쓰므로 `dc(id.orig_h) <= 3`이 대부분을 자동으로 제거합니다. 나머지는 SNI/도메인으로 한 번 허용 목록에 넣고 문서화하세요.

## 하나를 찾았다면 { #when-you-find-one }

1. 사실을 고정하세요: 쌍, 포트, 처음 본 시각, 간격, 들어오고 나간 바이트, SNI/URI/JA3, 인증서 지문.
2. 이름과 그것이 해석된 모든 IP는 `dns.log`로; 지문은 `http.log`/`ssl.log`로; 그 `uid`로 다운로드된 것은 `files.log`로 피벗하세요.
3. 전사에서 **같은 목적지, 같은 JA3, 같은 인증서, 같은 URI 패턴**을 헌팅하세요 — 임플란트는 무리 지어 다닙니다.
4. 호스트로 가세요: **프로세스**는 Sysmon 3 / EDR; 바이너리는 [Prefetch](../windows/prefetch.md) / [Amcache](../windows/amcache.md); 앱별 바이트는 [SRUM](../windows/srum.md); 지속성 키는 ([레지스트리 ASEP](../windows/registry-keys.md#autostart-persistence-asep)).
5. 결정하세요: 수집을 **마친 뒤에** 출구에서 차단하세요. 그렇지 않으면 비콘을 잃고 운영자가 눈치챕니다.

## 참고 자료 { #references }

- [Active Countermeasures — RITA](https://github.com/activecm/rita) · [Threat hunting training (free)](https://www.activecountermeasures.com/hunt-training/)
- [Cobalt Strike Malleable C2 — what operators change](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm)
- [MITRE ATT&CK — Command and Control tactic (TA0011)](https://attack.mitre.org/tactics/TA0011/)
- [SANS FOR572 — Advanced Network Forensics](https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response/)
- 관련 페이지: [conn.log](zeek/conn-log.md) · [dns.log](zeek/dns-log.md) · [http.log](zeek/http-log.md) · [ssl.log](zeek/ssl-x509.md) · [Wireshark와 tshark](wireshark-tshark.md)
