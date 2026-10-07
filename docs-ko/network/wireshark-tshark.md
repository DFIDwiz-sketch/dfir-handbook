---
title: Wireshark와 tshark
tags:
  - tool
  - network
  - pcap
---

# Wireshark와 tshark { #wireshark-tshark }

<div class="dfir-meta" markdown>
**분류:** 패킷 분석 · **플랫폼:** Windows / Linux / macOS · **최종 수정:** 2026-09-16
</div>

!!! abstract "하는 일"
    Wireshark는 GUI 패킷 분석기이고, **tshark**는 같은 엔진의 명령줄 버전입니다(스크립트 가능, 거대한 파일에도 동작, GUI 멈춤 없음). Zeek으로 *어떤* 플로우가 중요한지 찾고, Wireshark/tshark로 *그 안에 무엇이 있었는지* 읽으세요. 아래 필터는 BPF라고 표시하지 않는 한 **디스플레이 필터**(Wireshark 문법)입니다.

## 필터 언어 두 가지 — 섞지 마세요 { #two-filter-languages-dont-mix-them }

| | 디스플레이 필터 (Wireshark / `tshark -Y`) | 캡처 필터 (BPF: `tcpdump`, `tshark -f`, Wireshark 캡처 옵션) |
|---|---|---|
| 문법 | `ip.addr == 10.0.0.5 && tcp.port == 445` | `host 10.0.0.5 and tcp port 445` |
| 적용 시점 | 캡처 후, 파싱된 필드에 | 커널에서, 캡처 전 — 가벼움 |
| 능력 | 해석된 모든 필드 (`http.host`, `tls.handshake.extensions_server_name`) | 헤더/오프셋만 |

## 디스플레이 필터 치트시트 { #display-filter-cheat-sheet }

### 호스트, 포트, 대화 { #hosts-ports-conversations }

```text
ip.addr == 10.0.0.5                       # either direction
ip.src == 10.0.0.5 && ip.dst == 203.0.113.7
ip.addr == 10.0.0.0/24                    # subnet
!(ip.addr == 10.0.0.53)                   # exclude the resolver
tcp.port == 445 || udp.port == 53
tcp.stream eq 42                          # one TCP conversation (get the number from a packet)
udp.stream eq 7
eth.addr == 00:0c:29:aa:bb:cc             # by MAC
frame.time >= "2026-09-16 02:00:00" && frame.time <= "2026-09-16 03:00:00"
frame.time_delta_displayed > 1            # gaps between displayed packets
```

### TCP 동작 { #tcp-behaviour }

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYNs only (scans, new connections)
tcp.flags.reset == 1                      # RSTs
tcp.analysis.flags                        # any TCP problem (retrans, dup ack, zero window…)
tcp.analysis.retransmission
tcp.len > 0                               # packets carrying data
tcp.payload contains "cmd.exe"            # string in payload (case-sensitive)
tcp matches "(?i)powershell"              # regex, case-insensitive
tcp.window_size == 0
```

### DNS { #dns }

```text
dns                                       # all
dns.flags.response == 0                   # queries only
dns.qry.name contains "evil"
dns.qry.name matches "^[a-z0-9]{20,}\."   # long random first label (tunnel/DGA)
dns.qry.type == 16                        # TXT   (1 A, 28 AAAA, 5 CNAME, 15 MX, 10 NULL, 255 ANY)
dns.flags.rcode == 3                      # NXDOMAIN
dns.resp.ttl < 60
dns && !(ip.dst == 10.0.0.53)             # DNS not to the corporate resolver
dns.a == 203.0.113.7                      # answers containing this IP
```

### HTTP { #http }

```text
http.request                              # requests only
http.request.method == "POST"
http.host contains "cdn" || http.host matches "^\d+\.\d+\.\d+\.\d+$"   # raw-IP Host header
http.request.uri contains ".php?"
http.user_agent contains "python" || http.user_agent == ""
http.response.code == 200 && http.content_type contains "application/x-msdownload"
http.file_data contains "MZ"              # body starts like a PE
http.authorization                        # Basic/NTLM auth headers
http.cookie contains "session"
http.request.full_uri                     # (column-friendly) full URL
```

### TLS { #tls }

```text
tls.handshake.type == 1                   # Client Hello
tls.handshake.type == 2                   # Server Hello
tls.handshake.type == 11                  # Certificate
tls.handshake.extensions_server_name contains "example"     # SNI
tls.handshake.extensions_server_name == ""  # no SNI... use: tls.handshake.type==1 && !tls.handshake.extensions_server_name
tls.handshake.ja3                          # JA3 (Wireshark 4.x+ computes it; older: tls.handshake.ja3_full via LUA)
x509sat.uTF8String contains "Cobalt"       # cert subject strings
x509af.notBefore                           # cert validity
tls.record.version == 0x0301              # TLS 1.0 records
tls.alert_message
```

### SMB / Windows 프로토콜 (횡적 이동) { #smb-windows-protocols-lateral-movement }

```text
smb2                                      # SMB2/3
smb2.cmd == 5                             # Create (open file)   3 Tree Connect, 9 Write, 8 Read, 6 Close
smb2.tree contains "ADMIN$" || smb2.tree contains "C$" || smb2.tree contains "IPC$"
smb2.filename contains ".exe" || smb2.filename contains "psexesvc"
smb2.cmd == 9 && smb2.filename contains "PSEXESVC"
ntlmssp.auth.username                     # NTLM user names in the clear (the hash isn't, the name is)
ntlmssp.messagetype == 0x00000003         # NTLM AUTHENTICATE
kerberos.CNameString                      # Kerberos principal
kerberos.msg_type == 12                   # TGS-REQ (10 AS-REQ, 11 AS-REP, 13 TGS-REP, 30 KRB-ERROR)
kerberos.etype == 23                      # RC4 — Kerberoasting hint on TGS-REQ/REP
dcerpc                                    # MS-RPC (135 + dynamic port)
svcctl                                    # Service Control Manager calls (PsExec CreateServiceW/StartServiceW)
svcctl.opnum == 12 || svcctl.opnum == 19  # CreateServiceW (12), StartServiceW (19)
wmi || dcom                               # WMI over DCOM
rdp || tcp.port == 3389
winrm || (http && tcp.port == 5985)
ldap.protocolOp == 3                      # LDAP searchRequest (enumeration: BloodHound = lots)
```

### 그 밖에 유용한 것 { #other-useful }

```text
icmp && data.len > 64                     # oversized ICMP (tunnel)
icmp.type == 8                            # echo request
ftp.request.command == "STOR" || ftp-data # uploads
smtp.req.command == "AUTH" || imf         # mail auth / actual messages
ssh.protocol                              # banner (version strings)
arp.duplicate-address-detected            # ARP spoofing
dhcp.option.hostname                      # hostnames from DHCP
nbns || llmnr || mdns                     # name-resolution poisoning targets (Responder)
frame contains "MZ" || frame contains "This program cannot be run"
```

## tshark 레시피 { #tshark-recipes }

```bash
# Read a pcap with a display filter, show default columns
tshark -r cap.pcap -Y 'http.request && ip.addr==10.0.0.25'

# Pick exact fields as TSV (-T fields), with header
tshark -r cap.pcap -Y 'http.request' -T fields -E header=y -E separator='\t' \
  -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri -e http.user_agent

# DNS queries with answers
tshark -r cap.pcap -Y 'dns.flags.response==1' -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.a -e dns.resp.ttl

# TLS SNI + JA3 per Client Hello
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3

# Certificate subjects
tshark -r cap.pcap -Y 'tls.handshake.type==11' -T fields -e ip.src -e x509sat.printableString -e x509sat.uTF8String -e x509af.notBefore -e x509af.notAfter

# Conversations / endpoints statistics (like conn.log-lite)
tshark -r cap.pcap -q -z conv,tcp            # -z conv,ip / conv,udp
tshark -r cap.pcap -q -z endpoints,ip
tshark -r cap.pcap -q -z io,phs               # protocol hierarchy
tshark -r cap.pcap -q -z http,tree            # HTTP request/response stats
tshark -r cap.pcap -q -z dns,tree
tshark -r cap.pcap -q -z io,stat,60,'ip.addr==10.0.0.25'   # bytes per 60 s — beacon interval eyeballing

# Follow one TCP stream as text (like Follow → TCP Stream)
tshark -r cap.pcap -q -z follow,tcp,ascii,42
tshark -r cap.pcap -q -z follow,tls,ascii,42  # if you have keys loaded

# Export HTTP / SMB / FTP objects to a folder
tshark -r cap.pcap --export-objects http,./objs_http
tshark -r cap.pcap --export-objects smb,./objs_smb
tshark -r cap.pcap --export-objects imf,./objs_mail

# Split a huge pcap: only what matters (fast, then analyse the slice)
tshark -r huge.pcap -Y 'ip.addr==10.0.0.25' -w host25.pcap
editcap -A "2026-09-16 02:00:00" -B "2026-09-16 03:00:00" huge.pcap window.pcap     # by time
editcap -c 100000 huge.pcap chunk.pcap                                            # by packet count
mergecap -w all.pcap part1.pcap part2.pcap

# Capture info / sanity
capinfos cap.pcap                              # duration, first/last time, size, dropped
tshark -r cap.pcap -q -z expert                # expert info (malformed, retrans…)

# Decrypt TLS with a key log file (from a client with SSLKEYLOGFILE set) or RSA key
tshark -r cap.pcap -o tls.keylog_file:keys.log -Y http2
tshark -r cap.pcap -o "tls.keys_list:203.0.113.7,443,http,server.key"

# Live capture (BPF capture filter), rotate files
tshark -i eth0 -f 'not port 22' -b filesize:100000 -b files:20 -w /data/cap.pcap
tcpdump -i eth0 -nn -s0 -w cap.pcap 'host 10.0.0.25 and not port 22'
```

## 효과가 큰 Wireshark GUI 습관 { #wireshark-gui-habits-that-pay-off }

- **열**: `tls.handshake.extensions_server_name`, `http.host`, `dns.qry.name`, `tcp.stream`을 사용자 정의 열로 추가하세요(필드 우클릭 → Apply as Column). 프로필("DFIR")로 저장하세요.
- 패킷 하나라도 읽기 전에 **Statistics → Conversations / Endpoints / Protocol Hierarchy** — pcap판 `conn.log`입니다.
- 호스트/목적지 하나로 필터하고 1초 또는 60초 간격으로 **Statistics → I/O Graph**: 비콘은 빗살무늬를 그립니다.
- 세션을 대화처럼 읽으려면 **Analyze → Follow → TCP/TLS/HTTP Stream**; 파일을 카빙하려면 **File → Export Objects**.
- 메모가 Zeek/이벤트 로그(UTC)와 맞도록 **View → Time Display Format → UTC Date and Time** (⇧⌘/Ctrl+Alt+7).
- 키 로그가 있으면 복호화용으로 **Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename**.
- MAC/전송/네트워크 **이름 해석은 끄세요** — 분석 PC가 공격자 IP를 DNS로 조회하게 하고 싶지 않다면요(켜 두면 실제로 조회합니다).
- 색상 규칙: `tcp.flags.reset==1` 빨강, `tcp.analysis.flags` 노랑, `dns.flags.rcode!=0` 주황 — 문제가 눈에 확 띕니다.
- 잘못된 패킷과 프로토콜 위반은 **Expert Information**(왼쪽 아래 동그라미) — 회피 시도가 거기 있습니다.

## 주의할 점 { #gotchas }

!!! warning
    - **타임스탬프**는 캡처 호스트의 시계에서 옵니다. `capinfos`의 첫 패킷 시각을 알려진 사건과 비교하세요. 동기화되지 않은 센서는 타임라인 전체를 밀어 버립니다.
    - **`-s0` / snaplen**: 잘린 캡처(기본 96/262144바이트)는 페이로드를 잃습니다 — `frame.cap_len < frame.len`이면 알 수 있습니다.
    - **VLAN / GRE / VXLAN / ERSPAN**: 터널링된 캡처는 올바른 디코딩(`Decode As…`)이 필요하고, 그렇지 않으면 필터에 아무것도 안 걸립니다.
    - **체크섬**: NIC 오프로딩 때문에 나가는 체크섬이 틀려 보입니다. 설정에서 검증을 끄세요(Zeek에 `-C`가 필요한 이유와 같음).
    - **`ip.addr == x` vs `ip.src == x`**: `!(ip.addr==x)`는 x가 *어느 쪽에든* 있는 패킷을 제외합니다 — 대개 원하는 동작입니다. 하지만 `ip.addr != x`는 그렇지 **않습니다**(한쪽이라도 x가 아니면 일치 — 거의 모든 패킷).
    - **`contains`는 대소문자를 구분합니다**; 대소문자 무시 정규식은 `matches "(?i)…"`를 쓰세요.
    - **큰 pcap**: Wireshark는 전부 메모리에 올립니다. tshark/editcap으로 먼저 잘라 내거나 Arkime/Zeek으로 색인하세요.

## 참고 자료 { #references }

- [Wireshark display filter reference](https://www.wireshark.org/docs/dfref/)
- [tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [SANS TCP/IP & tcpdump pocket reference](https://www.sans.org/posters/tcp-ip-and-tcpdump/)
- [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures) · [malware-traffic-analysis.net exercises](https://www.malware-traffic-analysis.net/)
