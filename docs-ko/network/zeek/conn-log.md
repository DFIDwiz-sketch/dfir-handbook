---
title: conn.log
tags:
  - artifact
  - network
  - zeek
---

# Zeek `conn.log` { #zeek-connlog }

<div class="dfir-meta" markdown>
**분류:** 네트워크 · **출처:** Zeek · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    연결(TCP, UDP, ICMP)마다 한 줄씩, 누가/무엇을/언제/얼마나와 TCP 핸드셰이크가 어떻게 진행됐는지 간단한 기록을 담습니다 — 가장 먼저 집계하는 로그이자 다른 모든 Zeek 로그가 매달린 `uid` 허브입니다.

## 필드 { #fields }

| 필드 | 타입 | 의미 | 분석 메모 |
|---|---|---|---|
| `ts` | time | **첫 패킷** 시각 | UTC epoch. `zeek-cut -d`로 변환 |
| `uid` | string | 고유 연결 ID | 다른 모든 로그와의 결합 키 |
| `id.orig_h` / `id.orig_p` | addr / port | **시작 측**(클라이언트) IP / 포트 | 시작 측 = 첫 패킷을 보낸 쪽 |
| `id.resp_h` / `id.resp_p` | addr / port | **응답 측**(서버) IP / 포트 | 이걸로 정렬/집계해서 C2를 찾음 |
| `proto` | enum | `tcp`, `udp`, `icmp` | |
| `service` | string | Zeek이 내용으로 **탐지한** 프로토콜 (`http`, `ssl`, `dns`, `smb`, `ssh`, `rdp`, `krb_tcp`, `ntlm`, `dce_rpc`…) | `-` = 알 수 없음/탐지 안 됨. 여러 개: `ssl,http`. **포트와 안 맞으면 = 흥미로움** |
| `duration` | interval | 첫 패킷부터 마지막 패킷까지 초 | 아주 길고 바이트가 적으면 대화형/keep-alive |
| `orig_bytes` / `resp_bytes` | count | 시작 측 / 응답 측 **페이로드** 바이트 (TCP: 시퀀스 번호 기반이라 재전송으로 부풀지 않음) | 비대칭이 데이터 흐름 방향을 알려 줌 |
| `conn_state` | string | 연결 결과 요약 (아래 표) | 스캔: `S0`, `REJ`; 정상: `SF` |
| `local_orig` / `local_resp` | bool | orig/resp가 `Site::local_nets`에 속하나? | 로컬 네트워크를 설정했을 때만 채워짐 |
| `missed_bytes` | count | 패킷 드롭으로 잃은 바이트 | 높으면 = 캡처 문제, 바이트 수를 믿지 말 것 |
| `history` | string | 패킷별 플래그 기록 (아래) | 핸드셰이크 이야기처럼 읽힘 |
| `orig_pkts` / `orig_ip_bytes` | count | 시작 측의 패킷 수 / IP 수준 바이트 (헤더 포함) | `orig_bytes`와 비교 |
| `resp_pkts` / `resp_ip_bytes` | count | 응답 측도 동일 | |
| `tunnel_parents` | set | 감싸고 있는 터널의 `uid` (GRE, Teredo, VXLAN, AYIYA) | 비어 있지 않으면 = 터널링된 트래픽 |
| `community_id` (로드했다면) | string | Suricata/Arkime/Elastic과 공유하는 5-튜플 해시 | 도구 간 피벗 |
| `orig_l2_addr` / `resp_l2_addr` (선택 정책) | string | MAC 주소 | 로컬 구간에서 IP → 장치 연결 |
| `vlan`, `inner_vlan` (선택) | int | 802.1Q 태그 | |

### `conn_state` 값 { #conn_state-values }

| 상태 | 의미 | 보통 무엇인가 |
|---|---|---|
| `S0` | SYN만 보이고 응답 없음 | **포트 스캔**, 방화벽 드롭, 죽은 호스트 |
| `S1` | 핸드셰이크 완료, 종료 안 됨 | 캡처가 끝날 때 아직 열려 있음 / 긴 세션 |
| `SF` | 정상 연결과 종료 | 일반 연결 (**"Success Finished"**) |
| `REJ` | SYN → RST | 닫힌 포트 (**스캔이 닫힌 포트에 닿음**) |
| `S2` | 연결됨, orig가 FIN 보냄, resp의 FIN 없음 | |
| `S3` | 연결됨, resp가 FIN 보냄, orig의 FIN 없음 | |
| `RSTO` | 연결됨, **시작 측**이 RST로 중단 | 클라이언트가 끊음 |
| `RSTR` | 연결됨, **응답 측**이 RST로 중단 | 서버가 끊음 (IDS/방화벽 리셋, 서비스 크래시) |
| `RSTOS0` | orig가 SYN 후 RST; resp의 SYN-ACK 없음 | 응답이 없자 RST를 보내는 스캐너 |
| `RSTRH` | resp가 SYN-ACK 후 RST; orig의 SYN은 안 보임 | 비대칭 캡처 |
| `SH` | orig SYN 후 FIN, SYN-ACK 없음 | "하프 오픈" — 스캔/회피인 경우가 많음 |
| `SHR` | resp SYN-ACK 후 FIN, orig의 SYN 없음 | 비대칭 캡처 |
| `OTH` | SYN 안 보임, 중간부터 | 연결 중간에 캡처 시작, 또는 UDP/ICMP |

### `history` 글자 { #history-letters }

대문자 = **시작 측**, 소문자 = **응답 측**. 순서 = 관찰된 순서 (최신 버전은 반복을 합치고 `^`로 방향 전환을 표시).

| 글자 | 의미 |
|---|---|
| `S` / `s` | SYN (ACK 없음) |
| `H` / `h` | SYN-ACK ("handshake") |
| `A` / `a` | 순수 ACK |
| `D` / `d` | **페이로드**가 있는 패킷 ("data") |
| `F` / `f` | FIN |
| `R` / `r` | RST |
| `C` / `c` | 잘못된 체크섬 |
| `G` / `g` | 내용 공백 |
| `T` / `t` | 재전송 |
| `W` / `w` | 제로 윈도우 |
| `I` / `i` | 모순된 패킷 (SYN+RST) |
| `Q` / `q` | 다중 플래그 패킷 (SYN+FIN) |
| `^` | 방향 뒤집힘 (Zeek이 orig/resp를 잘못 추측했다가 고침) |

예시: `ShADadFf` = 완벽한 정상 연결. `S` = SYN 하나, 응답 없음 (스캔 / 드롭). `Sr` = SYN, RST 응답 (닫힌 포트). `ShAD` 후 아무것도 없음 = 클라이언트가 데이터를 보냈는데 아무것도 못 받았거나, 캡처가 끝났거나 멈춤. `ShADadR` = 서버가 리셋하기 전까지 정상. `^d` = 응답 측 데이터만 보임, 중간부터.

## 빠른 쿼리 { #quick-queries }

=== "zeek-cut / 셸"

    ```bash
    # Top talkers by destination (who is everyone connecting to?)
    zeek-cut id.resp_h id.resp_p < conn.log | sort | uniq -c | sort -rn | head -20

    # Outbound connections from one host, readable time, longest first
    zeek-cut -d ts id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes conn_state < conn.log \
      | awk '$2=="10.0.0.25"' | sort -k6 -rn | head

    # Port scan detection: many S0/REJ from one source to many ports
    zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log \
      | awk '$4=="S0"||$4=="REJ"' | awk '{print $1, $2}' | sort | uniq -c | sort -rn | head

    # Services that don't match their port (443 that isn't ssl, 53 that isn't dns, 80 that isn't http)
    zeek-cut id.resp_p service < conn.log | awk '($1==443 && $2!="ssl" && $2!="-") || ($1==53 && $2!="dns") || ($1==80 && $2!="http")' | sort | uniq -c | sort -rn

    # Total bytes uploaded per internal host to external hosts (exfil hunt)
    zeek-cut id.orig_h id.resp_h orig_bytes < conn.log | awk '$1 ~ /^10\./ && $2 !~ /^10\./ {s[$1" -> "$2]+=$3} END {for (k in s) print s[k], k}' | sort -rn | head

    # Long-lived connections (> 1 hour)
    zeek-cut -d ts uid id.orig_h id.resp_h id.resp_p duration < conn.log | awk '$6>3600' | sort -k6 -rn
    ```

=== "Splunk (Zeek JSON, sourcetype bro:conn:json 또는 zeek:conn)"

    ```spl
    index=zeek sourcetype=zeek:conn
    | stats count sum(orig_bytes) as up sum(resp_bytes) as down avg(duration) as avg_dur by id.orig_h, id.resp_h, id.resp_p, service
    | eval up_MB=round(up/1024/1024,1), down_MB=round(down/1024/1024,1)
    | sort - up_MB
    ```

    `stats … by`는 `by` 뒤의 필드로 행을 묶고 묶음마다 요약 행 하나를 계산합니다. `sum(orig_bytes) as up`은 업로드 바이트를 더해서 결과 이름을 `up`으로 붙입니다. `eval`은 수식으로 새 필드를 만듭니다(여기서는 바이트를 MB로 바꾸고 소수 첫째 자리로 반올림). `sort - up_MB`는 가장 많이 올린 쪽을 맨 위로 올립니다.

    ```spl
    index=zeek sourcetype=zeek:conn conn_state IN (S0, REJ)
    | stats dc(id.resp_p) as ports dc(id.resp_h) as hosts by id.orig_h
    | where ports > 50 OR hosts > 50
    ```

    `IN (…)`은 나열된 값 중 하나와 일치합니다. `dc()` = 고유 개수 — 한 출발지가 *서로 다른* 포트/호스트를 몇 개 건드렸는지; `where`는 임계값을 넘는 행만 남깁니다. 포트 스캔(`ports`)과 호스트 스윕(`hosts`) 탐지기입니다.

## 분석 팁 { #analysis-tips }

!!! tip "피벗 패턴"
    `conn.log`에서 집계 → 이상한 쌍(`id.orig_h`, `id.resp_h`, `id.resp_p`) 찾기 → 그 `uid`들 확보 → `grep <uid> *.log` → 프로토콜 상세 읽기. `grep CHhAvVGS1DHFjwGM9 http.log ssl.log dns.log files.log`.

- **바이트 수는 페이로드만입니다.** 0바이트 `SF` 연결은 데이터 없는 핸드셰이크 — TCP 프로브, 헬스 체크, 또는 할 일이 없었던 비콘입니다.
- **`orig_bytes` vs `orig_ip_bytes`**: `orig_bytes`는 0인데 `orig_ip_bytes`가 크다면 페이로드가 재전송에 있었거나 Zeek이 재조립하지 못한 것(`missed_bytes`) — 캡처 품질 문제입니다.
- **UDP "연결"**은 5-튜플로 묶고 비활동 타임아웃을 둔 플로우입니다. `duration`이 여러 데이터그램에 걸칠 수 있고, 같은 리졸버로의 DNS는 긴 UDP 연결 하나로 보일 수 있습니다.
- **ICMP**: `id.orig_p` = ICMP 타입, `id.resp_p` = 코드. `orig_bytes`가 큰 타입 8/0이 많으면 = ICMP 터널.
- **내부 vs. 외부**: `local.zeek`에 `Site::local_nets`를 설정하면 `local_orig/local_resp`가 채워집니다 — 그러면 "내부 → 외부, `orig_bytes` 큼"이 한 줄짜리 쿼리가 됩니다.
- **비코닝**은 여기 있습니다: 같은 `id.orig_h`/`id.resp_h`/`id.resp_p`, `ts` 값 사이의 거의 일정한 간격, 비슷한 `orig_bytes`. [비코닝과 C2](../beaconing-c2.md) 참고.
- **횡적 이동**은 내부 → 내부 `445`(`smb`), `135` + 높은 포트(`dce_rpc`), `3389`(`rdp`), `5985`(그 포트의 `http` = WinRM), `22`로 보입니다. 사고 시간대 이전에는 한 번도 없던 내부 간 쌍을 세어 보세요.
- **Zeek이 orig/resp를 뒤집을 수 있습니다** — 중간부터 시작했을 때(history의 `^`, `OTH` 상태). "서버"가 51234 포트라면 포트 번호를 다시 확인하세요.

## 상관분석 { #correlation }

| 질문 | 다음에 볼 곳 |
|---|---|
| 실제로 무슨 내용이 오갔나? | `uid` → [`http.log`](http-log.md), [`ssl.log`](ssl-x509.md), [`dns.log`](dns-log.md), `smb_*.log`, `ssh.log`, `rdp.log` |
| 어떤 파일이 오갔나? | `uid` → [`files.log`](files-log.md) (`conn_uids`) → `fuid` → `pe.log`, `extract_files/` |
| 호스트의 어떤 프로세스가 만들었나? | Sysmon `3` (`SourceIp/SourcePort/DestinationIp` + 시각), Windows `5156`, [SRUM](../../windows/srum.md) 앱별 시간당 바이트 |
| 어떤 사용자? | `ntlm.log` / `kerberos.log` (`username`, `client`), 목적지의 Windows `4624` |
| 경보가 떴나? | `notice.log`, Suricata `eve.json` (`community_id` / 5-튜플 + 시각) |
| 패킷 | [`tshark -r cap.pcap -Y "ip.addr==A && tcp.port==P"`](../wireshark-tshark.md) |

## 참고 자료 { #references }

- [Zeek docs — conn.log](https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html)
- [Corelight conn.log cheat sheet](https://corelight.com/resources/zeek-cheatsheets)
- [Community ID spec](https://github.com/corelight/community-id-spec)
