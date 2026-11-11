---
title: "2 — 호스트 신원 확인"
tags:
  - training
  - incident-response
  - dhcp
  - kerberos
  - fingerprinting
---

# 2 — 호스트 신원 확인 { #host-identification }

!!! abstract "이 페이지의 범위"
    - 알림과 다운로드로 감염 호스트 찾기
    - IP, MAC, 호스트 이름, 윈도우 사용자 계정
    - 도메인 컨트롤러 찾기와 활동 호스트 세기
    - 기기 판별(Ubuntu, 안드로이드, 아마존 Fire, 애플, 스마트 TV)과 운영체제
    - 핵심 네트워크 정보(IP 대역, 게이트웨이, 도메인)와 호스트의 공인 IP

## 감염 호스트 찾기 { #infected-host }

감염 호스트는 악성코드 알림에 나오면서 **동시에** 수상한 파일을 받은 내부 IP입니다. 둘 다 확인해서 같은 주소를 가리키는지 봅니다.

```bash
grep -oE "\{(TCP|UDP)\} [0-9.]+:[0-9]+ -> [0-9.]+:[0-9]+" snort_out/alert | grep -oE "(10|172|192)\.[0-9.]+" | sort | uniq -c | sort -rn | head
zeek-cut -u ts id.orig_h host uri resp_mime_types < zeek_out/http.log | grep -i -E "dosexec|msword|officedocument|ms-office"
```

- 1줄: 알림마다 `{TCP} 출발지 -> 목적지` 부분을 잘라 사설 주소처럼 보이는 것만 남기고 셉니다. (`172.217.x.x` 같은 공인 대역도 걸리므로 목록을 눈으로 확인합니다.)
- 2줄: 윈도우 실행파일(`application/x-dosexec`)이나 Word 문서를 받아 간 요청. `id.orig_h`가 요청한 쪽입니다.

```text
     57 172.xx.xx.xx
2019-xx-xxTxx:xx:xx  172.xx.xx.xx  <site>  /<path>/<file>.doc  application/msword
```

Wireshark: **Statistics → Endpoints → IPv4**로 내부 주소를 보고, **File → Export Objects → HTTP**에서 수상한 파일의 **Packet** 번호를 클릭해 Destination 열을 읽습니다(응답은 클라이언트 *쪽으로* 갑니다). 필터 `http.response && http.file_data contains "This program cannot be run in DOS mode"`는 윈도우 실행파일이 담긴 응답으로 바로 데려갑니다.

## IP, MAC, 호스트 이름 { #ip-mac-hostname }

DHCP에는 IP·MAC·호스트 이름이 함께 있으니 거기서 시작합니다. 캡처에 DHCP가 없으면 호스트가 보낸 패킷과 이름 알림을 봅니다.

```bash
zeek-cut client_addr mac host_name < zeek_out/dhcp.log | sort -u
tshark -r case.pcap -Y "dhcp" -T fields -e ip.src -e eth.src -e dhcp.option.hostname -e dhcp.option.vendor_class_id | sort -u
tshark -r case.pcap -Y "ip.src==<infected IP>" -T fields -e eth.src | sort -u
tshark -r case.pcap -Y "(nbns || mdns || llmnr) && ip.src==<infected IP>" -T fields -e nbns.name -e dns.qry.name | sort -u
```

- 1~2줄: DHCP 기록. 옛날 Wireshark에서는 `dhcp` 대신 `bootp`를 씁니다.
- 3줄: 호스트가 보낸 패킷의 MAC 주소.
- 4줄: 호스트가 스스로 알리는 이름. 윈도우는 NBNS·LLMNR(`DESKTOP-XXXX<00>`), 애플·리눅스·안드로이드는 mDNS(`<이름>.local`).
- 다음 절의 Kerberos 컴퓨터 계정(끝이 `$`)도 믿을 만한 호스트 이름 출처입니다.

Wireshark:

1. 필터 `dhcp` → **Request** 클릭 → **Dynamic Host Configuration Protocol** 펼치기 → **Option (12) Host Name** 우클릭 → **Apply as Column**. **Option (60) Vendor class identifier**도 같은 방법으로 추가합니다.
2. 필터 `ip.src==<infected IP>` → **Ethernet II → Source**가 MAC입니다.
3. 필터 `nbns` → Info 열에 `Registration NB <이름><00>`이 보입니다.

## 윈도우 사용자 계정 { #user-account }

윈도우 PC가 도메인에 로그인하면 Kerberos에 로그인한 이름이 실립니다. `$`로 끝나면 **컴퓨터** 계정, `$`가 없으면 **사용자** 계정입니다.

```bash
tshark -r case.pcap -Y "kerberos.CNameString && ip.src==<infected IP>" -T fields -e kerberos.CNameString -e kerberos.crealm | sort | uniq -c
zeek-cut id.orig_h client < zeek_out/kerberos.log | sort -u
```

```text
      8 DESKTOP-XXXXXXX$   EXAMPLE.LOCAL     ← 컴퓨터 계정(호스트 이름)
      5 <username>         EXAMPLE.LOCAL     ← 사용자 계정
```

Wireshark: 필터 `kerberos.CNameString && !(kerberos.CNameString contains "$")` → **Kerberos → as-req → req-body → cname → cname-string → CNameString** 펼치기 → **Apply as Column**. `!`는 "아닌 것"이라 사용자 이름만 남습니다. 답안에는 대소문자까지 보이는 그대로 씁니다.

## 도메인 컨트롤러 찾기 { #domain-controller }

DC는 Kerberos(88), LDAP(389), DNS(53), SMB(445)에 응답합니다. Kerberos·LDAP 요청을 받는 IP를 셉니다.

```bash
tshark -r case.pcap -Y "tcp.dstport==88 || udp.dstport==88 || tcp.dstport==389 || udp.dstport==389" -T fields -e ip.dst | sort | uniq -c | sort -rn
zeek-cut id.orig_h id.resp_h service < zeek_out/kerberos.log | sort -u | head
```

- 1줄: 보통 IP 하나만 나오며 그게 DC입니다.
- 2줄: `service` 칸의 `krbtgt/<도메인>`, `LDAP/<dc이름>.<도메인>`에서 DC 호스트 이름까지 알 수 있습니다.

Wireshark: 1줄의 필터 입력 → **Statistics → Endpoints → IPv4**에서 **Limit to display filter** 체크 → **Rx Packets**로 정렬. DC 이름은 필터 `kerberos` → `TGS-REQ` 클릭 → **req-body → sname**.

## LAN의 활동 호스트 { #active-hosts }

"활동 중"은 스스로 연결을 **시작한** 내부 IP라는 뜻입니다.

```bash
zeek-cut id.orig_h < zeek_out/conn.log | grep '^172\.16\.' | sort | uniq -c | sort -rn
tshark -r case.pcap -q -z endpoints,ip | grep "172.16."
```

- 앞자리는 실습 대역에 맞게 바꿉니다. `\.`은 진짜 점을 뜻합니다.
- 개수에서 뺄 것: DC(질문이 "DC 말고"라면), 브로드캐스트(`.255`), 멀티캐스트(`224.x`, `239.255.255.250`). 기본 게이트웨이는 보통 ARP에만 나오고 IP 통신자로는 안 나옵니다.

Wireshark: 필터 `ip.src==172.16.0.0/12`(또는 실습 대역) → **Statistics → Endpoints → IPv4** → **Limit to display filter** → **Tx Packets**가 0보다 큰 IP.

## 기기 판별 { #device-fingerprinting }

기기 종류는 단서 세 가지를 합쳐서 판단합니다. 하나만 보면 틀릴 수 있습니다.

| 단서 | 얻는 방법 | 알 수 있는 것 |
| --- | --- | --- |
| MAC 제조사(앞 3바이트, OUI) | `-e eth.src -e eth.src_resolved`, **Statistics → Endpoints → Ethernet** + **Name resolution** | 제조사: Apple, Samsung, Amazon Technologies 등 |
| DHCP vendor class(옵션 60)와 호스트 이름(옵션 12) | 위 DHCP 명령 | `MSFT 5.0` = 윈도우, `android-dhcp-8.0.0` = 안드로이드 8.0.0, `dhcpcd-…` = 리눅스 |
| DNS 질의와 HTTP User-Agent | 아래 명령 | 어떤 서비스와 통신하고 어떤 소프트웨어를 쓰는지 |

```bash
zeek-cut id.orig_h query < zeek_out/dns.log | awk '$1=="<IP>"' | sort | uniq -c | sort -rn | head -30
zeek-cut id.orig_h host user_agent < zeek_out/http.log | awk -F'\t' '$1=="<IP>"' | sort -u
zeek-cut host software_type name unparsed_version < zeek_out/software.log | sort -u
tshark -r case.pcap -Y 'ip.src==<IP> && (mdns || ssdp)' -V | grep -i -E "server:|\.local|_tcp" | sort -u | head -40
```

- `awk -F'\t'`: User-Agent에 띄어쓰기가 있어서 탭으로 칸을 나눕니다.
- `software.log`: Zeek가 User-Agent와 배너에서 찾은 소프트웨어 요약.
- 마지막 줄: TV, 스트리밍 기기, 프린터는 mDNS·SSDP로 스스로를 알립니다. SSDP의 `SERVER:` 헤더와 mDNS 서비스 이름(`_googlecast._tcp.local`, `_airplay._tcp.local`)이 기기 종류를 알려 줍니다.

자주 보이는 특징:

- **Ubuntu**: `connectivity-check.ubuntu.com`, `ntp.ubuntu.com`, `api.snapcraft.io`, `archive/security.ubuntu.com` 질의, User-Agent에 `Ubuntu`.
- **안드로이드**: `connectivitycheck.gstatic.com`, `android.clients.google.com`, User-Agent `Dalvik/2.1.0 (Linux; U; Android 8.0.0; <모델코드> Build/<빌드>)`. 모델코드(예: 삼성은 `SM-`으로 시작)를 검색하면 브랜드와 모델이 나옵니다.
- **아마존 Fire 태블릿**: `amazon` 도메인이 많고, User-Agent에 `Silk`나 `KF`로 시작하는 모델코드, MAC 제조사 Amazon Technologies. Echo 스피커도 아마존과 통신하므로 User-Agent와 MAC까지 확인합니다.
- **애플**: `apple.com`, `icloud.com`, `push.apple.com`, User-Agent `iPhone`이나 `Macintosh`.

Wireshark 필터: `dns.qry.name contains "ubuntu"`, `http.user_agent contains "Android 8.0.0"`, `dns.qry.name contains "amazon" || http.user_agent contains "Silk"`, `ip.src==<IP> && dns.flags.response==0`(그 호스트의 DNS 질문만).

## 운영체제 { #operating-system }

질문이 윈도우라고 말해 주지 않으면, OS 근거를 두세 개 모읍니다.

```bash
tshark -r case.pcap -Y "ip.src==<IP>" -T fields -e ip.ttl | sort | uniq -c
tshark -r case.pcap -Y "ntlmssp.version.major && ip.src==<IP>" -T fields -e ntlmssp.version.major -e ntlmssp.version.minor -e ntlmssp.version.build_number | sort -u
tshark -r case.pcap -Y "smb.native_os && ip.src==<IP>" -T fields -e smb.native_os | sort -u
tshark -r case.pcap -Y "ssh.protocol" -T fields -e ip.src -e ssh.protocol | sort -u
p0f -r case.pcap -o p0f.log && grep "<IP>" p0f.log | grep os=
```

- **TTL**: OS마다 시작값이 다릅니다. 윈도우는 보통 128, 리눅스·macOS·안드로이드는 64. 같은 LAN에서 캡처했다면 시작값이 그대로 보입니다.
- **NTLMSSP 버전**: NTLM 인증에 윈도우 버전이 실립니다. `10 0 19045` = Windows 10 22H2, `6 1 7601` = Windows 7 SP1.
- **smb.native_os**: SMB1 호스트가 알리는 OS 이름.
- **SSH 배너**: `Ubuntu`, `Debian` 같은 글자가 들어 있기도 합니다.
- **User-Agent**: `Windows NT 10.0` = Windows 10/11, `Windows NT 6.1` = Windows 7, `X11; Linux x86_64` = 리눅스.
- **p0f**: TCP SYN 패킷으로 OS를 수동 추정하는 도구.

Wireshark: **Internet Protocol → Time to Live**를 열로 추가, 필터 `ntlmssp.version.major` → **NTLM Secure Service Provider → Version** 펼치기.

## 핵심 네트워크 정보 { #network-info }

DHCP ACK와 Kerberos가 네트워크 자체를 알려 줍니다.

```bash
tshark -r case.pcap -Y "dhcp.option.dhcp == 5" -T fields -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.domain_name_server -e dhcp.option.domain_name | sort -u
tshark -r case.pcap -Y "kerberos" -T fields -e kerberos.realm -e kerberos.crealm | tr '\t' '\n' | sort -u
tshark -r case.pcap -Y 'dns.qry.name contains "_msdcs"' -T fields -e ip.src -e dns.qry.name | sort -u
```

- `dhcp.option.dhcp == 5`: DHCP ACK만. 서브넷 마스크 `255.255.255.0` = /24, router = 기본 게이트웨이, DNS 서버는 보통 DC, domain name = 도메인.
- Kerberos realm = AD 도메인.
- `_ldap._tcp.dc._msdcs.<도메인>`: 윈도우 클라이언트가 DC를 찾는 질의에도 도메인이 드러납니다.

Wireshark: 필터 `dhcp.option.dhcp == 5`에서 옵션 (1) Subnet Mask, (3) Router, (6) Domain Name Server, (15) Domain Name을 읽고, 필터 `kerberos`에서 **AS-REQ**를 열어 **req-body → realm**을 봅니다. 답안은 [네트워크 정보 틀](report-templates.md#network-info-template)을 씁니다.

## 공인 IP { #public-ip }

내부에서는 사설 IP를 쓰고, 방화벽·공유기가 공인 IP로 바꿔 줍니다(NAT). 내부에서 캡처한 PCAP의 패킷 헤더에는 공인 IP가 안 보입니다. 대신 악성코드가 감염 직후 "내 IP 확인" 서비스에 묻는 경우가 많고, 그 **응답 본문**에 답이 있습니다.

```bash
zeek-cut -u ts id.orig_h host uri < zeek_out/http.log | grep -i -E "ip|myip|whatismy|ifconfig"
zeek-cut -u ts query answers < zeek_out/dns.log | grep -i -E "ipify|checkip|ip-api|icanhazip|myexternalip|ipinfo|wtfismyip|ifconfig"
tshark -r case.pcap -Y 'http.response && http.response_for.uri contains "<ip-check domain>"' -T fields -e frame.number -e http.file_data
```

- `http.file_data`: HTTP 응답 본문. `x.x.x.x`나 `{"ip":"x.x.x.x"}` 같은 값이 들어 있습니다. 16진수로 나오면 끝에 `| xxd -r -p`를 붙입니다.
- IP 확인이 HTTPS였다면 본문이 암호화돼 읽을 수 없습니다. 다른 평문 통신(예: C2로 보낸 POST)에서 찾거나, "PCAP으로는 확인 불가 + 이유"를 답안에 씁니다.

Wireshark: 필터 `http.host contains "ip" || dns.qry.name contains "ip"` → 요청 우클릭 → **Follow → HTTP Stream** → 파란색(서버) 본문의 IP. 또는 상세 창의 **Line-based text data** / **JavaScript Object Notation**을 펼칩니다.

!!! note "이 섹션의 성격"
    개인 학습 노트입니다. 어떤 기관의 공식 지침도 아닙니다.
