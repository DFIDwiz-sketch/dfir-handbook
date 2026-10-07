---
title: 네트워크 포렌식
---

# 네트워크 포렌식 { #network-forensics }

패킷, 플로우, 로그 기반 분석: 구조는 Zeek, 페이로드는 Wireshark/tshark, 그리고 잡음 속에서 명령제어(C2)를 찾아내는 헌팅 기법. **질문**에서 출발하세요.

## 질문 → 어디를 볼까 { #question-where-to-look }

| 질문 | 주요 출처 | 함께 확인 |
|---|---|---|
| **누가 누구와, 얼마나 많이, 얼마나 오래 통신했나?** | [Zeek `conn.log`](zeek/conn-log.md) | NetFlow/IPFIX, 방화벽 로그, `tshark -z conv,tcp` |
| **호스트가 어떤 이름을 조회했고 무엇으로 해석됐나?** | [Zeek `dns.log`](zeek/dns-log.md) | 호스트의 Sysmon 22, DNS 서버 로그, 패시브 DNS |
| **HTTP로 어떤 URL / User-Agent / 파일을 가져왔나?** | [Zeek `http.log`](zeek/http-log.md) | 프록시 로그 (사용자 포함), [`files.log`](zeek/files-log.md), pcap 객체 내보내기 |
| **암호화돼 있다 — 그래도 알 수 있는 건?** | [Zeek `ssl.log` / `x509.log`](zeek/ssl-x509.md) (SNI, JA3/JA4, 인증서) | Suricata TLS, 호스트 프로세스 텔레메트리, 복호화 프록시 |
| **어떤 파일이 오갔나? 해시는?** | [Zeek `files.log` / `pe.log`](zeek/files-log.md) | `smb_files.log`, `smtp.log`, `tshark --export-objects` |
| **이 호스트가 C2로 비코닝하나?** | [비코닝과 C2 탐지](beaconing-c2.md) | RITA, JA3 희소성, [SRUM](../windows/srum.md) 시간별 바이트 |
| **데이터가 유출되고 있나?** | [`conn.log`](zeek/conn-log.md) 쌍별 `orig_bytes`; [`files.log`](zeek/files-log.md) `is_orig=T` | [SRUM](../windows/srum.md), [$UsnJrnl](../windows/mft-usn.md) 압축 파일 생성, DNS 바이트 ([`dns.log`](zeek/dns-log.md)) |
| **내부 호스트 간 횡적 이동?** | `conn.log` 내부→내부 445/135/3389/5985/22; `smb_files.log`, `dce_rpc.log`, `ntlm.log`, `kerberos.log`, `rdp.log` | Windows `4624` type 3/10, `5140/5145`, `7045` ([이벤트 ID](../basics/windows-event-ids.md)) |
| **스캐닝 / 정찰?** | `conn.log` `S0`/`REJ` 개수, `notice.log` `Scan::*`, `ldap.log` 쿼리 양 | Suricata 스캔 규칙, 허니팟 접촉 |
| **실제로 무슨 내용이 오갔나?** | [Arkime](arkime/index.md) 세션 보기 / pcap 내보내기 → [Wireshark / tshark](wireshark-tshark.md) | Zeek `extract_files/` |
| **경보 / IOC가 있다 — 패킷을 보여 주고, 또 누가 그랬나?** | [Arkime 헌팅 워크플로](arkime/hunting-workflows.md) (Sessions → SPIView → Connections → Hunt) | [Arkime 검색 문법](arkime/search-syntax.md), Suricata `eve.json`, Community ID 피벗 |
| **몇 주 치 트래픽에서 문자열 찾기** | Arkime **Hunt** ([워크플로](arkime/hunting-workflows.md#workflow-4-hunt-searching-payloads-for-a-string)) | 잘라 낸 pcap에 `tshark -Y 'frame contains …'` |
| **그 포트는 뭐지?** | [잘 알려진 포트](../basics/well-known-ports.md) | Zeek `service` 필드 (내용 기반) |

## 페이지 { #pages }

<div class="grid cards" markdown>

-   **[Zeek 개요](zeek/index.md)** — 로그가 연결되는 방식(`uid`/`fuid`), 포맷, pcap에 돌리기
-   **[conn.log](zeek/conn-log.md)** — 상태, history 플래그, 바이트 필드, 스캔과 유출 쿼리
-   **[dns.log](zeek/dns-log.md)** — 터널링, DGA, 리졸버 정책, DoH 사각지대
-   **[http.log](zeek/http-log.md)** — User-Agent 트리아지, 위장 다운로드, 웹셸
-   **[ssl.log와 x509.log](zeek/ssl-x509.md)** — SNI, JA3/JA4, 인증서 위험 신호, TLS 1.3의 한계
-   **[files.log와 pe.log](zeek/files-log.md)** — 해시, 추출, SMB 복사, PE 헤더 단서
-   **[Arkime 개요](arkime/index.md)** — 전체 패킷 캡처 + 색인된 세션; Zeek/Suricata와 함께 쓰는 법
-   **[Arkime 검색 문법](arkime/search-syntax.md)** — 연산자, 필드 이름, 레시피, API/URL 요령
-   **[Arkime로 침입 탐지](arkime/hunting-workflows.md)** — 경보 → 증거, SPIGraph의 비콘, Connections의 횡적 이동, Hunt, WISE, Cron Queries
-   **[Wireshark와 tshark](wireshark-tshark.md)** — 디스플레이 필터 치트시트, tshark 레시피, GUI 습관
-   **[비코닝과 C2](beaconing-c2.md)** — 간격 분석, 희소성, 지문, 최신 회피 기법

</div>

## 분석 순서 (네트워크 쪽) { #analysis-order-network-side }

1. **캡처 범위 파악**: 시간 범위, 센서 위치 (NAT 안/밖? 어느 VLAN?), 드롭 (`capinfos`, `conn.log missed_bytes`). *볼 수 없는* 것을 적어 두세요.
2. **`conn.log` 집계**: 상위 목적지, 드문 목적지, 긴 연결, 큰 업로드, 스캔 패턴.
3. **이름 붙이기**: 이상한 IP 뒤의 도메인은 `dns.log`; `ssl.log` SNI/인증서; `http.log` 호스트/URI/UA.
4. **지문 찍기**: JA3/JA4, UA, 인증서 지문 → 전사 검색.
5. **시간 분석**: 후보 쌍의 간격 분석 ([비코닝](beaconing-c2.md)).
6. **내용**: `files.log` 해시 → 인텔리전스; Arkime 세션 페이로드 / 문자열 Hunt; 평문은 pcap follow-stream; 파일 추출.
7. **호스트로 넘어가기**: Sysmon 3/22, Prefetch/Amcache, SRUM, 지속성 — 그다음 그 호스트가 또 무엇과 통신했는지 다시 네트워크로.

!!! info "이 섹션에 페이지 추가하기"
    `python new.py network/<name> -t artifact` (Zeek 로그를 추가한다면 `network/zeek/<name>`) — 사이드바에 자동으로 나타납니다.
