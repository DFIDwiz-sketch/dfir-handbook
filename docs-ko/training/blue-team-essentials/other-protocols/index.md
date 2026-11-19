---
title: 기타 네트워크 프로토콜
tags:
  - training
  - blue-team
  - network
---

# 기타 네트워크 프로토콜 { #other-protocols }

!!! abstract "한 줄 요약"
    이메일·HTTP·DNS로 들어온 공격자는 그다음 관리자들이 매일 쓰는 평범한 프로토콜로 옆으로 이동하고 자료를 빼냅니다. 이 섹션은 DHCP(IP를 장비로 바꿔 주는 기록)부터 시작해 SMB, SSH, RDP/VNC, PowerShell 원격, FTP, ICMP, 원격 접속 도구까지 — 정상 모습, 악용 방식, 볼 포인트를 다룹니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [DHCP — 눈여겨볼 프로토콜들, IP를 장비 이름으로 바꾸기, 몰래 꽂은 장비 찾기, DORA 한 단계씩](dhcp.md) | 이 프로토콜들을 따로 보는 이유(옆으로 이동, 유출), IP → 호스트·MAC → 사용자와 임대 시각이 중요한 이유, 마지막 고리 4624·4768, Windows DHCP 감사 로그 칸별 해석(ID 10·11·12, 벤더 클래스, 옵션 82), `Get-DhcpServerv4Lease`, Zeek `dhcp.log`, 호스트 이름 규칙과 MAC OUI로 몰래 꽂은 장비 찾기, 로컬 관리 비트, 스스로 말하는 값이라 속일 수 있는 이유, DORA 패킷 단위, 갱신 T1·T2, 릴레이, 가짜 DHCP 서버·풀 고갈·DHCPv6(mitm6)·TunnelVision, 확인 문제 |
| 2 | [SMB — 공격자가 좋아하는 이유, 버전과 협상, 대표 공격](smb.md) | 445·139 포트와 관리용 공유(`C$`, `ADMIN$`, `IPC$`), 관리자 자격 증명 = 원격 실행인 이유(PsExec를 손으로 하는 `net use`/`sc`), 같은 로컬 관리자 비밀번호 문제와 웜, 방언 1 → 3.1.1과 tshark로 보는 NEGOTIATE, `Get-SmbConnection`·SMB1 확인·SMB1 접속 감사, SMB1을 없애야 하는 이유와 "SMB2"를 끄면 안 되는 이유, 자격 증명 방식 vs 익스플로잇 방식, PsExec 이동이 남기는 4624·4672·5140·5145·7045·4688과 Sysmon 1·3, Zeek `smb_mapping`·`smb_files`·`dce_rpc`(`svcctl CreateServiceW`), 익스플로잇 신호, 방어, Windows 11 24H2·Server 2025 기본값, 확인 문제 |
| 3 | [SSH, 밖으로 나가는 SSH로 안으로 들어오는 터널, RDP와 VNC](ssh-rdp-vnc.md) | SSH가 친구이자 위협인 이유, `auth.log`와 Zeek `ssh.log` 읽기, 네 가지 터널 기법(`scp` 유출, `-R` 원격 포워딩, 듀얼 홈 점프 박스를 통한 `-L`/`-D`, X11) 옵션별 해석, `sshd_config`로 잠그기, Windows 기본 내장 `ssh.exe`, 나가는 SSH = 들어오는 RDP: plink `-R 12345:127.0.0.1:3389` 명령, Sysmon 1·3, 443 포트의 `service=ssh`, `127.0.0.1`에서 온 4624 타입 10·1149·21~25, RDP 예방과 감시(4778·4779, RDPClient 1024 포함 이벤트 표), VNC/RFB 배너와 약한 인증, OpenSSH 10·터널 서비스·`.rdp` 피싱 보호, 확인 문제 |

!!! info "이어서 추가될 내용"
    PowerShell 원격, FTP, 악성 ICMP, 모든 원격 접속·관리 도구.

## 꼭 기억할 것 { #must-know }

1. "이 프로토콜은 나쁜가?"가 아니라 "이 장비에서, 이 상대에게, 이 시각에 쓰이는 게 정상인가?"를 묻는다.
2. IP는 빌려 쓰는 값이다. 반드시 알림 시각을 포함하는 임대 기록으로 장비를 찾는다.
3. DHCP 로그는 호스트 이름·IP·MAC을 남기는 망의 출석부지만, 호스트 이름과 MAC은 장비가 스스로 말하는 값이다.
4. MAC의 두 번째 16진수 글자가 2·6·A·E면 로컬 관리 주소다. 조회할 OUI가 없다.
5. DHCP에는 인증이 없다. 승인하지 않은 DHCP 서버를 감시하고 DHCP 스누핑을 쓴다.
6. 관리자 자격 증명이 있으면 SMB는 원격 실행이다. PC마다 다른 로컬 관리자 비밀번호(LAPS)와 워크스테이션 간 445 차단이 횡적 이동 대부분을 끊는다.
7. 4624 타입 3 + 4672 + `ADMIN$` 접근 + 7045 새 서비스 = 서비스 이름이 무엇이든 PsExec 패턴이다.
8. 아무 곳으로나 나가는 SSH = 공격자에게 들어오는 길. `127.0.0.1`이나 `::1`에서 온 RDP 로그온은 터널이다.

## 관련 레퍼런스 { #related }

- [패킷 캡처에서 호스트 식별](../../pcap-ir-labs/host-identification.md) — pcap에서 DHCP·호스트 이름·MAC 찾기
- [잘 알려진 포트](../../../basics/well-known-ports.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md)
- [LLMNR·NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md)
