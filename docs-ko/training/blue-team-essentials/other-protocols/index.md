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

!!! info "이어서 추가될 내용"
    SMB(버전과 대표 공격), SSH와 밖으로 나가는 SSH로 안으로 들어오는 터널, RDP/VNC, PowerShell 원격, FTP, 악성 ICMP, 모든 원격 접속·관리 도구.

## 꼭 기억할 것 { #must-know }

1. "이 프로토콜은 나쁜가?"가 아니라 "이 장비에서, 이 상대에게, 이 시각에 쓰이는 게 정상인가?"를 묻는다.
2. IP는 빌려 쓰는 값이다. 반드시 알림 시각을 포함하는 임대 기록으로 장비를 찾는다.
3. DHCP 로그는 호스트 이름·IP·MAC을 남기는 망의 출석부지만, 호스트 이름과 MAC은 장비가 스스로 말하는 값이다.
4. MAC의 두 번째 16진수 글자가 2·6·A·E면 로컬 관리 주소다. 조회할 OUI가 없다.
5. DHCP에는 인증이 없다. 승인하지 않은 DHCP 서버를 감시하고 DHCP 스누핑을 쓴다.

## 관련 레퍼런스 { #related }

- [패킷 캡처에서 호스트 식별](../../pcap-ir-labs/host-identification.md) — pcap에서 DHCP·호스트 이름·MAC 찾기
- [잘 알려진 포트](../../../basics/well-known-ports.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md)
- [LLMNR·NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md)
