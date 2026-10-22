---
title: Active Directory
tags:
  - oscp
---

# Active Directory { #active-directory }

<div class="dfir-meta" markdown>
**배점:** 40 / 100 (10 + 10 + 20) · **우선순위:** 최상 · **최종 수정:** 2026-10-22
</div>

!!! abstract "한 문장 요약"
    AD 세트는 주어진 도메인 사용자 계정(assumed breach)에서 시작해 머신 두 대를 거쳐 도메인 컨트롤러까지 이어집니다. 이제 부분 점수도 인정되지만, 합격 후기 대부분은 40점을 다 땄습니다.

!!! info "뼈대 페이지"
    지금은 구조만 있습니다 — 아래 제목이 계획이에요. 공부하면서 각 부분을 채워 나가세요.

## Assumed breach 시작 { #assumed-breach-start }

- 받은 크리덴셜 확인 — 이 사용자가 어디에 로그인할 수 있나 (SMB, WinRM, RDP, MSSQL)
- 그 발판에서 도메인 첫 파악

## 정보 수집 { #enumeration }

- BloodHound 수집과 처음 돌려볼 쿼리
- 사용자, 그룹, SPN, 공유 폴더, ACL (LDAP, SMB, PowerView)

## 크리덴셜 공격 { #credential-attacks }

- Kerberoasting · AS-REP roasting · targeted Kerberoast (사용자 쓰기 권한)
- 비밀번호 스프레이와 재사용
- 크랙 — hashcat 모드, john

## 수평 이동 { #lateral-movement }

- Pass-the-Hash · Pass-the-Ticket · Overpass-the-Hash
- PsExec / WMI / WinRM / RDP

## 도메인 장악 { #domain-compromise }

- DCSync · 제한된 위임 · GPO 악용 · NTLM relay (시험 제한 사항 확인)

## 머신마다 정보 수집 { #looting }

- 각 호스트에서 관리자가 된 뒤 모을 것 — 보통 이게 다음 머신의 열쇠

## 도구 { #tools }

- Impacket, NetExec, BloodHound, Rubeus, Mimikatz, bloodyAD

## AD 관련 시험 규칙 { #exam-rules }

- 스푸핑 / 포이즈닝 제한 — [시험 가이드](exam-format.md#exam-rules)에서 확인

## 관련 페이지 { #related-pages }

같은 기법의 탐지 쪽 내용:

- [Kerberoasting](../../adversary/kerberoasting.md) · [AS-REP Roasting](../../adversary/asrep-roasting.md) · [Pass-the-Hash](../../adversary/pass-the-hash.md)
- [DCSync](../../adversary/dcsync.md) · [Golden & Silver Tickets](../../adversary/golden-silver-tickets.md) · [AD CS 악용](../../adversary/adcs-abuse.md)
- [LLMNR / NTLM Relay](../../adversary/llmnr-ntlm-relay.md) · [LSASS 덤프](../../adversary/lsass-dumping.md) · [SAM / NTDS 추출](../../adversary/sam-ntds-extraction.md)
- [PsExec / SMB](../../adversary/psexec-smb.md) · [WMI / WinRM](../../adversary/wmi-winrm.md) · [RDP](../../adversary/rdp.md)
- 다음 단계: [피벗팅과 터널링](pivoting.md)

## 참고 자료 { #references }

- [OffSec — OSCP Exam with AD Preparation](https://help.offsec.com/hc/en-us/articles/4547917816468-Offensive-Security-OSCP-Exam-with-AD-Preparation)
