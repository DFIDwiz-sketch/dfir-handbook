---
title: 잘 알려진 포트
tags:
  - concept
  - basics
  - network
---

# 잘 알려진 포트 { #well-known-ports }

<div class="dfir-meta" markdown>
**분류:** 기초 · **최종 수정:** 2026-09-09
</div>

!!! abstract "한 줄 요약"
    포트 번호는 서비스를 짐작하게 해 주지만 공격자도 그걸 압니다. 그러니 포트만 믿지 말고 항상 프로토콜 분석(Zeek `service` 필드, Wireshark 디섹터)으로 확인하세요.

## 범위 { #ranges }

| 범위 | 이름 | 비고 |
|---|---|---|
| 0 – 1023 | Well-known / 시스템 포트 | 보통 root/관리자 권한이 있어야 바인딩 가능 |
| 1024 – 49151 | 등록 포트 | 벤더가 IANA에 등록한 포트 |
| 49152 – 65535 | 동적 / 임시(ephemeral) 포트 | 클라이언트 쪽 출발지 포트. Windows는 49152–65535, 구버전 Linux는 32768–60999 |

## 핵심 서비스 { #core-services }

| 포트 | 프로토콜 | 서비스 | DFIR 메모 |
|---|---|---|---|
| 20 / 21 | TCP | FTP 데이터 / 제어 | 자격증명이 평문. 패시브 모드는 높은 포트 사용 |
| 22 | TCP | SSH | SFTP/SCP도 여기. 무차별 대입은 `auth.log` 확인 |
| 23 | TCP | Telnet | 평문. IoT/OT에서는 아직도 흔함 |
| 25 | TCP | SMTP | 서버 간 메일 전송. 스팸/피싱 출처 |
| 53 | UDP/TCP | DNS | 큰 응답·존 전송은 TCP. 터널링 주의(긴 TXT, 엔트로피 높은 서브도메인) |
| 67 / 68 | UDP | DHCP 서버 / 클라이언트 | 시간대별 IP ↔ MAC ↔ 호스트명 연결 |
| 69 | UDP | TFTP | 인증 없음. 펌웨어, 악성코드 스테이징에 사용 |
| 80 | TCP | HTTP | 평문 웹 |
| 88 | TCP/UDP | Kerberos | 도메인 인증. Kerberoasting은 RC4(etype 23) TGS-REQ로 보임 |
| 110 | TCP | POP3 | 구식 메일 수신 |
| 111 | TCP/UDP | RPCbind / portmapper | NFS 탐색 |
| 123 | UDP | NTP | 시간 동기화 — 타임라인 상관분석에 중요 |
| 135 | TCP | MS-RPC 엔드포인트 매퍼 | WMI, DCOM, PsExec 류 횡적 이동 |
| 137 / 138 | UDP | NetBIOS 이름 / 데이터그램 | 구식 이름 해석; LLMNR/NBT-NS 포이즈닝 |
| 139 | TCP | NetBIOS 세션 (NetBIOS 위의 SMB) | 구식 SMB |
| 143 | TCP | IMAP | 메일 수신 |
| 161 / 162 | UDP | SNMP / 트랩 | 커뮤니티 문자열 `public` = 공짜 정찰 |
| 389 | TCP/UDP | LDAP | AD 조회. BloodHound 류 열거는 389 트래픽이 많음 |
| 443 | TCP | HTTPS | UDP 443은 QUIC. JA3/JA4, SNI, 인증서 정보 활용 |
| 445 | TCP | SMB (직접) | 파일 공유, PsExec, 횡적 이동, 랜섬웨어 확산 |
| 464 | TCP/UDP | Kerberos 비밀번호 변경 | |
| 465 / 587 | TCP | SMTPS / SMTP 제출 | 클라이언트 메일 발송 |
| 514 | UDP | Syslog | 평문. TLS는 TCP 6514 |
| 515 | TCP | LPD 인쇄 | |
| 548 | TCP | AFP | macOS 파일 공유 |
| 587 | TCP | SMTP 제출 | 인증된 클라이언트 메일 |
| 636 | TCP | LDAPS | |
| 993 / 995 | TCP | IMAPS / POP3S | |
| 1433 / 1434 | TCP / UDP | MS SQL Server / 브라우저 | |
| 1521 | TCP | Oracle DB | |
| 1723 | TCP | PPTP VPN | 취약함. GRE(프로토콜 47)도 사용 |
| 2049 | TCP/UDP | NFS | |
| 3268 / 3269 | TCP | LDAP 글로벌 카탈로그 / GC-SSL | |
| 3306 | TCP | MySQL / MariaDB | |
| 3389 | TCP/UDP | RDP | 무차별 대입, 횡적 이동. 4624 type 10, 4778/4779, TerminalServices 로그와 연결 |
| 5060 / 5061 | UDP/TCP | SIP / SIP-TLS | VoIP |
| 5432 | TCP | PostgreSQL | |
| 5900+ | TCP | VNC | 인증이 약하거나 없는 경우가 많음 |
| 5985 / 5986 | TCP | WinRM HTTP / HTTPS | PowerShell Remoting. 대상 호스트에서 4688 `wsmprovhost.exe` |
| 6379 | TCP | Redis | 인증 없이 노출된 경우가 잦음 |
| 8080 / 8443 | TCP | HTTP 대체 / HTTPS 대체 | 프록시, 개발 서버, C2 |
| 9200 / 9300 | TCP | Elasticsearch | |
| 27017 | TCP | MongoDB | |

## 공격자가 좋아하는 포트 (C2·도구 기본값) { #ports-attackers-love-default-c2-tooling }

이건 **기본값**일 뿐이고 무엇이든 바꿀 수 있습니다. 증거가 아니라 "한번 볼 만한 것"으로 다루세요.

| 포트 | 관련 도구 |
|---|---|
| 4444 | Metasploit 기본 리스너 |
| 1080 | SOCKS 프록시 (Chisel, ssh -D, Cobalt Strike SOCKS) |
| 50050 | Cobalt Strike 팀 서버 (운영자 ↔ 서버 통신, 비콘 아님) |
| 8443 / 443 / 80 | 대부분의 최신 C2(Cobalt Strike, Sliver, Mythic, Havoc)가 여기에 섞여 들어감 |
| 8000 / 8080 | Python `http.server`, 스테이징 서버 |
| 3128 | Squid 프록시 |
| 5555 | Android ADB |
| 6667 / 6697 | IRC (구식 봇넷) |
| 31337 | Back Orifice / "elite" — 추억의 포트, CTF에서 아직 보임 |

## IP 프로토콜 번호 (포트가 아니지만 자주 헷갈림) { #ip-protocol-numbers-not-ports-but-often-confused }

| 번호 | 프로토콜 |
|---|---|
| 1 | ICMP |
| 2 | IGMP |
| 6 | TCP |
| 17 | UDP |
| 41 | IPv6 캡슐화 |
| 47 | GRE |
| 50 | ESP (IPsec) |
| 51 | AH (IPsec) |
| 58 | ICMPv6 |
| 89 | OSPF |
| 132 | SCTP |

## 빠르게 찾아보기 { #quick-lookups }

=== "Linux"

    ```bash
    grep -w 445 /etc/services
    ss -tulpn            # what is listening now
    ```

=== "Windows"

    ```powershell
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort
    netstat -anob        # -b shows the owning binary (admin)
    ```

=== "Zeek"

    ```bash
    # Which services were actually seen on port 443? (should be ssl; anything else is odd)
    zeek-cut id.resp_p service < conn.log | awk '$1==443' | sort | uniq -c | sort -rn
    ```

## 참고 자료 { #references }

- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- [SANS TCP/IP and tcpdump cheat sheet](https://www.sans.org/posters/tcp-ip-and-tcpdump/)
