---
title: 횡적 이동과 도메인 침해
tags:
  - playbook
  - lateral-movement
  - active-directory
---

# 횡적 이동과 도메인 침해 { #lateral-movement-domain-compromise }

<div class="dfir-meta" markdown>
**시나리오:** 공격자가 호스트 간 이동 중, 또는 Domain Admin / DC 침해 의심 · **최종 수정:** 2026-09-17
</div>

!!! abstract "언제 쓰나"
    공격자가 더 이상 한 대에만 있지 않다는 증거 — 한 계정의 로그온이 여러 호스트에 나타남, 관리 공유 접근, 원격으로 설치된 서비스, 또는 도메인 자체가 침해된 징후(DCSync, 골든 티켓, `krbtgt` 우려, 대량 GPO 변경). 온프레미스에서 가장 위험한 시나리오입니다: 도메인이 장악됐다면 **모든 자격증명과 모든 호스트가 의심 대상**입니다.

## 1. 트리아지 (첫 15분) { #1-triage-first-15-minutes }

- 지금까지 **어떤 계정**과 **어떤 호스트**가 관련됐는지 확정하세요. **권한 있는** 계정(Domain Admin, 또는 넓은 권한의 서비스 계정)이 연루됐나?
- **길목** 기법을 찾으세요: [LSASS 덤프](../adversary/lsass-dumping.md) (자격증명 탈취), 그다음 [Pass-the-Hash](../adversary/pass-the-hash.md) / [Kerberoasting](../adversary/kerberoasting.md) (자격증명 사용), 그다음 [PsExec/WMI/WinRM](../adversary/psexec-smb.md) (이동).
- **도메인 수준** 침해 징후를 확인하세요: DCSync (DC가 아닌 곳에서의 복제), `krbtgt` 활동, 새 Domain Admin, 페이로드를 밀어 넣는 GPO 변경.
- 아직은 무작정 전부 재설정하지 **마세요** — 범위를 먼저 파악해야 봉쇄가 완전하고 동시에 이뤄집니다. 그러지 않으면 공격자가 다시 들어옵니다.

## 2. 수집 { #2-collect }

| 출처 | 무엇 | 어디서 |
|---|---|---|
| **DC** Security 로그 | 도메인 전체의 Kerberos/NTLM 인증 | `4768/4769/4771/4776`, `4662` (DCSync), `4720/4728/4732` (계정/그룹 변경) |
| 관련된 각 호스트 | 로그온 + 실행 + 서비스 아티팩트 | [KAPE](../tools/kape.md) / [Velociraptor 전사 헌트](../tools/velociraptor.md) |
| AD | 그룹 멤버십, ACL 변경, 새 객체 | AD 감사, 공격 경로를 위한 BloodHound 수집 |
| 네트워크 | 내부 인증과 이동 | [Zeek](../network/index.md) `ntlm.log`, `kerberos.log`, `smb_files.log`, 내부 `445/135/3389/5985` |

여기에는 Velociraptor가 딱 맞습니다 — 아티팩트 하나(예: `Windows.EventLogs.RDPAuth`, LSASS 접근, 특정 서비스 이름)를 **모든** 호스트에 한 번에 헌팅하세요.

## 3. 분석 — 이동 그래프 그리기 { #3-analyse-map-the-movement-graph }

- **자격증명 탈취 지점**: [LSASS가 덤프된](../adversary/lsass-dumping.md) 곳은? Sysmon 10 LSASS 접근이 있는 모든 호스트가 자격증명을 수확한 곳입니다.
- **어떤 자격증명을 어디서 썼나**: 탈취된 계정마다 [4624 type 3 NTLM](../adversary/pass-the-hash.md)과 [4648](../splunk/security-searches.md)으로 피벗해서 닿은 모든 호스트를 보세요. **출발지→대상 그래프**를 만드세요 ([Arkime Connections 보기](../network/arkime/hunting-workflows.md#workflow-3-lateral-movement-with-connections)가 이걸 그림으로 보여 줌).
- **단계별 이동 기법**: [PsExec `7045`+`5145`](../adversary/psexec-smb.md), [WMI/WinRM parents](../adversary/wmi-winrm.md), RDP `4624/10`+`4778`.
- **도메인 침해**:
    - **DCSync**: DC가 아닌 계정에서 복제 GUID(`DS-Replication-Get-Changes`)가 담긴 DC의 `4662`, 또는 Zeek/Arkime `drsuapi` RPC — 누군가 AD에서 비밀번호 해시를 끌어가는 중.
    - **골든/실버 티켓**: 이상이 있는 TGT/TGS (수명, 사용 중인 티켓에 대한 `4768` 없음, 암호화 다운그레이드). `krbtgt`를 도난당했을 수 있다면 골든 티켓이 보이지 않게 도메인 전체 접근을 줍니다.
    - **새 특권 계정 / 그룹 변경**: Domain Admins로의 `4720`→`4732`; 특권 전역 그룹으로의 `4728`.
    - **AdminSDHolder / ACL 백도어, GPO 악용**: 도메인 수준의 지속성.

## 4. 봉쇄 / 제거 { #4-contain-eradicate }

봉쇄는 **조율되고 거의 동시에** 해야 합니다. 그러지 않으면 정리하는 동안 공격자가 옮겨 갑니다:

- 알려진 침해 호스트를 모두 한 번에 격리하세요.
- **자격증명 재설정**: 공격자가 건드린 모든 계정, 모든 특권 계정, 그리고 — DC나 도메인 관리자가 침해됐다면 — **`krbtgt`를 두 번 재설정**하세요 (간격을 두고 두 번 재설정해야 골든 티켓이 무효화됨). 그다음 더 넓은 계층별 재설정을 계획하세요.
- 공격자가 만든 계정, 그룹 멤버십, ACL 변경, GPO, 그리고 모든 호스트의 지속성을 제거하세요.
- 가능하면 Kerberos 티켓을 폐기하고; C2/유출을 차단하세요.
- DC 수준 침해가 확인되면 깨끗한 매체로 DC를 재구축하세요 — 침해된 DC는 믿을 수 없습니다.

## 5. 복구와 교훈 { #5-recover-lessons }

- **계층화되고 자격증명이 재설정된** 환경으로 복원하세요. BloodHound와 AD 감사로 AD 무결성을 검증하세요 (남아 있는 백도어 ACL/GPO/계정이 없는지).
- 강화: **tier 0/1/2 관리 모델** (워크스테이션 자격증명은 서버/DC에 닿지 못함), LAPS, Protected Users 그룹, LSASS 보호 + Credential Guard, 가능하면 NTLM 비활성화, AES Kerberos, `4662` DCSync와 `4768/4769` 이상 모니터링, 관리자용 특권 접근 워크스테이션(PAW).

## 유용한 쿼리 { #useful-queries }

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| eval user=mvindex(Account_Name,1)
| where NOT match(user,"\\$$")
| stats dc(host) as targets, values(host) as where_to, values(Source_Network_Address) as from by user
| where targets >= 3
| sort - targets
```

`4624 type 3` = 네트워크 로그온, `NTLM` 패키지. 컴퓨터가 아닌 계정 하나가 NTLM으로 서로 다른 호스트 세 대 이상에 인증하면 횡적 이동의 부채꼴입니다 — `values(host)`는 간 곳을, `values(Source_Network_Address)`는 출발한 곳을 나열합니다. [Pass-the-Hash](../adversary/pass-the-hash.md) 참고.

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4662 Access_Mask=0x100
| where match(Properties,"(?i)DS-Replication-Get-Changes|1131f6a|9923a32a")
| table _time, host, Account_Name, Object_Name, Properties
```

DC가 아닌 계정에서 복제 확장 권한 GUID(`DS-Replication-Get-Changes-All`)가 담긴 DC의 `4662`는 **DCSync**입니다 — 공격자가 Active Directory에서 비밀번호 해시를 직접 끌어가고 있습니다. 여기 나오는 DC도 서비스 계정도 아닌 계정은 모두 심각합니다.

```spl
index=botsv3 sourcetype=WinEventLog EventCode IN (4720,4728,4732,4756)
| eval action=case(EventCode==4720,"user created",EventCode==4728,"added to global group",EventCode==4732,"added to local group",EventCode==4756,"added to universal group")
| search Group_Name IN ("Domain Admins","Enterprise Admins","Administrators","Schema Admins") OR EventCode=4720
| table _time, host, Subject_Account_Name, action, Account_Name, Member_Name, Group_Name
| sort 0 _time
```

새 계정과 특권 그룹 추가. 변경 기간이 아닐 때 Domain/Enterprise Admins에 추가됐다면, 특히 `4720` 계정 생성 몇 분 뒤라면 도메인 지속성입니다.

## 참고 자료 { #references }

- [MITRE ATT&CK — Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/) · [DCSync T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- [Microsoft — krbtgt reset guidance](https://learn.microsoft.com/en-us/defender-for-identity/) · [AD tiered admin model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/)
- 관련 페이지: [Pass-the-Hash](../adversary/pass-the-hash.md) · [Kerberoasting](../adversary/kerberoasting.md) · [PsExec/SMB](../adversary/psexec-smb.md) · [WMI/WinRM](../adversary/wmi-winrm.md) · [LSASS 덤프](../adversary/lsass-dumping.md) · [Arkime Connections](../network/arkime/hunting-workflows.md)
