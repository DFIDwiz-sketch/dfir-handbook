---
title: Arkime 검색 문법
tags:
  - tool
  - network
  - arkime
  - cheatsheet
---

# Arkime 검색 문법 { #arkime-search-syntax }

<div class="dfir-meta" markdown>
**분류:** 치트시트 · **도구:** Arkime viewer · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    Arkime 검색식은 `필드 연산자 값` 형태이고 `&&` / `||` / `!`로 잇습니다. 와일드카드, 정규식, 목록, `EXISTS!`를 쓸 수 있습니다 — 필드 이름 서른 개 정도만 익히면 몇 달 치 트래픽에 거의 무엇이든 한 줄로 물어볼 수 있습니다.

## 연산자 { #operators }

| 연산자 | 의미 | 예시 |
|---|---|---|
| `==` | 같음 (문자열은 대소문자 무시) | `ip.dst == 203.0.113.7` |
| `!=` | 같지 않음 | `port.dst != 443` |
| `<` `<=` `>` `>=` | 숫자 비교 | `databytes.src > 1000000` |
| `&&` `\|\|` `!` | 그리고 / 또는 / 아님 | `port.dst == 443 && !(protocols == tls)` |
| `( )` | 묶기 | `(port.dst == 80 \|\| port.dst == 8080) && ip.src == 10.0.0.0/8` |
| `[a, b, c]` | 목록 — 그중 하나 | `port.dst == [445, 135, 3389, 5985]` |
| `*` | 와일드카드 (문자열) | `host.http == *.ngrok.io` |
| `/regex/` | 정규식 (문자열; 넓은 범위에서 느림) | `host.dns == /^[a-z0-9]{25,}\./` |
| `EXISTS!` | 필드가 존재함 | `cert.notbefore == EXISTS!` |
| `$shortcut` | 저장한 목록/변수 (Settings → Shortcuts) | `ip.dst == $c2_ips` |
| `"…"` | 공백/특수문자가 있는 값은 따옴표로 | `http.user-agent == "Mozilla/5.0 (compatible; MSIE 9.0*"` |

IP는 CIDR(`10.0.0.0/8`)을 받고, 범위는 목록이나 여러 조건으로 표현합니다. 시간은 **날짜 선택기**나 URL의 `date=…`로 고르고, API에는 `starttime`/`stoptime`(epoch 초)도 있습니다.

## 실제로 쓰게 될 필드 이름 { #field-names-you-will-actually-use }

필드 이름은 SPIView에 나오고 입력할 때 자동 완성됩니다. 대부분의 프로토콜 필드는 방향이 중요한 경우 `.src`/`.dst` 변형이 있고, 많은 필드에 `.cnt`(세션 안의 고유 개수)가 있습니다.

### 세션과 플로우 { #session-flow }

| 필드 | 의미 |
|---|---|
| `ip`, `ip.src`, `ip.dst` | 주소 (아무쪽 / 출발지 / 목적지) |
| `port`, `port.src`, `port.dst` | 포트 |
| `protocols` | 세션에서 탐지된 프로토콜: `tcp`, `udp`, `http`, `tls`, `dns`, `smb`, `ssh`, `krb5`, `ntlm`, `rdp`, `quic`, `socks`, `dcerpc`, … |
| `ip.protocol` | IP 프로토콜 번호 / 이름 (`tcp`, `udp`, `icmp`, `gre`) |
| `packets`, `packets.src`, `packets.dst` | 패킷 수 |
| `bytes`, `bytes.src`, `bytes.dst` | 실제 전송 바이트 |
| `databytes`, `databytes.src`, `databytes.dst` | **페이로드** 바이트 (헤더 제외) |
| `session.length` | 지속 시간 (ms) |
| `session.segments` | 이 연결이 몇 개 세션으로 나뉘었나 |
| `rootId` | 한 긴 연결의 나뉜 세션을 잇는 ID |
| `starttime`, `stoptime` | 첫/마지막 패킷 (API); UI는 선택기 사용 |
| `country`, `country.src`, `country.dst` / `asn.*` / `rir.*` | GeoIP / ASN / 등록 기관 |
| `mac.src`, `mac.dst`, `vlan`, `node` | 2계층, VLAN 태그, 센서 이름 |
| `tags` | 태그 (`-t`, WISE, Hunt, Cron 쿼리, tagger에서) |
| `communityId` | Community ID 해시 (Zeek/Suricata로 피벗) |
| `id` | 세션 id (URL로 공유 가능) |

### HTTP { #http }

| 필드 | 의미 |
|---|---|
| `host.http` | Host 헤더 |
| `http.uri`, `http.uri.path`, `http.uri.key`, `http.uri.value` | 전체 URI / 경로 / 쿼리 키와 값 |
| `http.method` | `GET`, `POST`, … |
| `http.statuscode` | 응답 코드 |
| `http.user-agent` | User-Agent |
| `http.referer`, `http.cookie.key`, `http.cookie.value`, `http.authorization`, `http.user` | 그 밖의 헤더 / Basic 인증 사용자 |
| `http.request.header`, `http.response.header` | 존재하는 헤더 **이름** (순서 무관) — 빠진 헤더로 도구 식별 |
| `http.request.body`, `http.response.body` | 본문 일부 (본문 캡처가 켜져 있을 때) |
| `http.bodymagic` | 본문의 추정 콘텐츠 타입 (`application/x-dosexec`) |
| `http.md5`, `http.sha256` | HTTP 본문 해시 (켜져 있다면) |
| `http.hasheader.src/dst`, `http.hasheader.*.value` | `config.ini`에서 설정한 사용자 정의 헤더 추출 |

### DNS { #dns }

| 필드 | 의미 |
|---|---|
| `host.dns`, `host.dns.all` | 조회한 이름 (그리고 응답을 포함한 모든 이름) |
| `dns.ip` | 해석된 IP |
| `dns.query.type`, `dns.query.class` | `A`, `TXT`, `NULL`… (최신 Arkime: `dns.qt`) |
| `dns.status` | `NOERROR`, `NXDOMAIN`, … |
| `dns.opcode`, `dns.puny` | Opcode; punycode 이름 |
| `host.dns.tokens` | 토큰화된 레이블 — "단어 포함" 검색을 공짜로 |

### TLS / 인증서 { #tls-certificates }

| 필드 | 의미 |
|---|---|
| `host.tls` (구버전: `tls.sni`) | SNI |
| `tls.version`, `tls.cipher` | 협상된 버전 / 암호 |
| `tls.ja3`, `tls.ja3s`, `tls.ja4`, `tls.ja4s` | 지문 (ja4는 플러그인/최신 빌드 필요) |
| `tls.sessionid`, `tls.srcSessionId`, `tls.dstSessionId` | 세션 ID (재개) |
| `cert.subject.cn`, `cert.issuer.cn`, `cert.subject.on`, `cert.issuer.on` | 주체/발급자 CN과 조직 |
| `cert.alt` | SAN |
| `cert.serial`, `cert.hash` | 일련번호, SHA-1 지문 |
| `cert.notbefore`, `cert.notafter`, `cert.validfor` | 유효 기간 (일) |
| `cert.remainingDays`, `cert.curve`, `cert.publicAlgorithm` | 그 외 |
| `cert.cnt` | 세션의 인증서 수 (복호화 없는 TLS 1.3에서는 0) |

### Windows / 횡적 이동 프로토콜 { #windows-lateral-movement-protocols }

| 필드 | 의미 |
|---|---|
| `smb.fn` | SMB 파일명 |
| `smb.share`, `smb.domain`, `smb.user`, `smb.host`, `smb.os`, `smb.ver` | 공유, 도메인, 사용자, 호스트명, OS 문자열, 방언 |
| `smb.user`, `http.user` | NTLM 사용자명 (SMB 위, 또는 프록시/WinRM의 HTTP 위 NTLM) |
| `krb5.realm`, `krb5.cname`, `krb5.sname` | Kerberos 렐름 / 클라이언트 / 서비스 주체 |
| `protocols == dcerpc` | MS-RPC 세션 (PsExec/WMI/서비스 제어); opnum은 추출되지 **않음** — 내보낸 pcap에서 Wireshark `svcctl` 사용 |
| `protocols == rdp`, `rdp.hostname`, `rdp.user` | RDP; 호스트명/사용자는 첫 요청이 평문일 때만 (대부분은 TLS) |
| `ldap.authtype`, `ldap.bindname` | LDAP bind 상세 |
| `socks.ip`, `socks.port`, `socks.host`, `socks.user` | SOCKS 프록시 대상 |

### SSH, 메일, 기타 { #ssh-mail-misc }

| 필드 | 의미 |
|---|---|
| `ssh.ver`, `ssh.key`, `ssh.hassh`, `ssh.hasshServer` | 클라이언트/서버 버전 문자열, 호스트 키, HASSH 지문 |
| `email.src`, `email.dst`, `email.subject`, `email.fn`, `email.md5`, `email.host`, `email.x-mailer` | SMTP 메타데이터와 첨부 파일 이름/해시 |
| `dhcp.host`, `dhcp.mac`, `dhcp.type` | DHCP 호스트명 — 시간대별 IP ↔ 호스트명 연결 |
| `quic.host`, `quic.ua`, `quic.ver` | QUIC (HTTP/3) SNI 등 |
| `oui.src`, `oui.dst` | MAC으로 본 NIC 제조사 |
| `suricata.signature`, `suricata.category`, `suricata.severity`, `suricata.signatureId`, `suricata.gid`, `suricata.action` | 세션에 붙은 Suricata 경보 (suricata 플러그인) |
| `wise.*` / 설정한 이름 | WISE 보강 필드 (예: `ip.dst.threatfeed`, `tags == wise-*`) |
| `file` | 세션이 들어 있는 pcap 파일명 |
| `payload8.src`/`.dst` | 페이로드 첫 8바이트 (16진수) — 빠른 프로토콜 지문 |

!!! info "필드 이름은 버전마다 바뀝니다"
    Arkime는 v3–v5 즈음에 필드 여러 개의 이름을 바꿨습니다(예: `tls.sni` → `host.tls`, 최신 빌드에서 `dns.query.type` → `dns.qt`). 필드에서 오류가 나면 **SPIView**를 열고 필드 머리글에 마우스를 올려 보세요 — *내 버전*의 정확한 검색식 이름이 나옵니다. 검색창의 자동 완성이 기준입니다.

## 레시피 { #recipes }

```text
# Everything from one internal host to the internet in the window
ip.src == 10.0.0.25 && ip.dst != 10.0.0.0/8 && ip.dst != 192.168.0.0/16 && ip.dst != 172.16.0.0/12

# TLS to a raw IP (no SNI) on 443
port.dst == 443 && protocols == tls && host.tls != EXISTS!

# Self-signed or fresh certificates
cert.validfor < 30 || cert.validfor > 3650
cert.subject.cn == "*Cobalt*" || cert.serial == 146473198

# Rare/odd user agents
http.user-agent == [python*, curl*, Go-http-client*, PowerShell*, "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1*"] 
http.user-agent != EXISTS! && protocols == http                          # HTTP with no UA at all

# Executables downloaded over HTTP (body sniffing)
http.bodymagic == application/x-dosexec || http.bodymagic == application/x-msdownload

# POST to raw-IP hosts
http.method == POST && host.http == /^\d+\.\d+\.\d+\.\d+$/

# DNS tunnelling candidates
protocols == dns && (dns.qt == TXT || dns.qt == NULL) && ip.dst != 10.0.0.53
host.dns == /^[a-z0-9]{30,}\./
databytes.src > 100000 && protocols == dns                                # DNS sessions with lots of client payload

# Uploads: client sent far more than it received
databytes.src > 50000000 && databytes.dst < 1000000 && ip.dst != 10.0.0.0/8

# Long-lived connections (ms) — 1 hour
session.length > 3600000

# Lateral movement protocols internal → internal
ip.src == 10.0.0.0/8 && ip.dst == 10.0.0.0/8 && port.dst == [445, 135, 139, 3389, 5985, 5986, 22]
protocols == smb && smb.fn == [*.exe, *.dll, *.ps1, *.bat, *PSEXESVC*]
protocols == smb && smb.share == [*ADMIN$*, *C$*, *IPC$*]
protocols == krb5 && krb5.sname != *krbtgt*                              # service tickets for non-TGT SPNs (Kerberoast-ish); refine in SPIView

# Scanning: one source, many destinations, tiny sessions — best seen in SPIGraph on ip.dst, but as expression:
ip.src == 10.0.0.66 && packets <= 3 && bytes < 300

# Suricata-alerted sessions, high severity, external destinations
suricata.severity == 1 && ip.dst != 10.0.0.0/8
suricata.signature == "*Cobalt Strike*" || suricata.signature == "*Meterpreter*"

# Tagged by a Hunt / WISE / your import
tags == hunt-mimikatz-string || tags == case01 || tags == wise-badip

# Pivot on Community ID from a Zeek uid you already have
communityId == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="

# SSH client fingerprint (tools have distinct HASSH)
protocols == ssh && ssh.ver == [*libssh*, *paramiko*, *Go*]                # scripted SSH clients; compare ssh.hassh in SPIView
```

## URL과 API 요령 { #url-api-tricks }

```text
# Deep-link a search (share with a colleague / paste in a report)
https://arkime.example/sessions?expression=ip.dst%3D%3D203.0.113.7&date=-24&startTime=...&stopTime=...

# API: same expression, JSON out — great for scripting hunts
curl -s -u user:pass 'https://arkime.example/api/sessions?date=-24&expression=tls.ja3%3D%3D<hash>&length=1000&fields=firstPacket,source.ip,destination.ip,destination.port,http.host,tls.ja3' | jq .

# API: download pcap for an expression (whole result set!) — be careful with size
curl -s -u user:pass 'https://arkime.example/api/sessions/pcap?date=-1&expression=ip.dst%3D%3D203.0.113.7' -o c2.pcap

# API: unique values of a field (like SPIView export)
curl -s -u user:pass 'https://arkime.example/api/unique?date=-24&expression=protocols%3D%3Dhttp&field=http.user-agent&counts=1'
```

`date=-1` = 최근 1시간, `-24` = 최근 하루, `-168` = 일주일; 정확한 구간은 `date=-1`에 `startTime`/`stopTime`(epoch 초)을 함께 쓰세요. **Cron Queries**로 어떤 검색식이든 주기적으로 돌려서 일치하는 세션에 **태그**를 붙이거나 웹훅을 보낼 수 있습니다 — 직접 만드는 경보 시스템입니다.

## 참고 자료 { #references }

- [Arkime — Search expressions & operators](https://arkime.com/settings#search-expressions) (viewer 안의 **Help → Fields**에도 내 버전의 모든 필드가 나옴)
- [Arkime API v3](https://arkime.com/apiv3)
- 관련 페이지: [Zeek 로그](../zeek/index.md) · [비코닝과 C2](../beaconing-c2.md) · [Wireshark와 tshark](../wireshark-tshark.md)
