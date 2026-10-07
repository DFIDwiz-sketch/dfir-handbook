---
title: Windows 버전별 강화
tags:
  - adversary
  - hardening
  - reference
---

# Windows 버전별 강화 { #hardening-by-windows-version }

<div class="dfir-meta" markdown>
**범위:** Windows XP / Server 2003 → Windows 11 / Server 2025 · **용도:** "이 호스트에 실제로 어떤 통제를 적용할 수 있는가?" · **최종 수정:** 2026-10-07
</div>

!!! abstract "요약"
    각 기법 페이지는 *Windows 버전별 대응책* 표로 끝납니다. 이 페이지는 그것들을 뒤집어 놓은 것입니다: **세로에는 통제, 가로에는 Windows 버전**을 놓고, 그 뒤에 기법 → 통제 맵을 둡니다. OS 버전이 섞인 환경의 범위를 정할 때, 사고의 권고 사항을 쓸 때, 또는 레거시 호스트를 왜 "강화"가 아니라 격리해야 하는지 설명할 때 쓰세요.

## 범례 { #legend }

| 표시 | 의미 |
|---|---|
| ✅ **Default** | 기본으로 켜져 있음 (새로 설치한 경우) |
| ✅ | 내장되어 있지만 직접 켜거나 설정해야 함 |
| 🔧 | 특정 업데이트 / 추가 구성 요소로 사용 가능 (메모에 명시) |
| ⚠️ | 부분적 — 일부 에디션만, 또는 약한 형태 |
| ❌ | 이 버전에서는 사용 불가 |

## 지원 상태 (2026년 10월 기준) { #support-status-as-of-october-2026 }

| 버전 | 지원 종료 | 의미 |
|---|---|---|
| XP / Server 2003 | 2014년 4월 / 2015년 7월 | 드문 긴급(out-of-band) 패치(MS17-010, BlueKeep) 외에는 보안 수정 없음. **격리** |
| Vista / Server 2008 | 2017년 4월 / 2020년 1월 (ESU는 2023년 1월까지, Azure는 2024년 1월까지) | 격리 |
| 7 / Server 2008 R2 | 2020년 1월 (ESU는 2023년 1월까지) | 격리 또는 이전 |
| 8.1 / Server 2012 / 2012 R2 | 2023년 1월 / 2023년 10월 (Server 2012/2012 R2 ESU는 2026년 10월까지) | 이전 |
| 10 | 2025년 10월 14일 — 이후로는 소비자용 및 기업용 ESU만 | 이전; 아직 널리 배포되어 있음 |
| 11 / Server 2016 / 2019 / 2022 / 2025 | 지원 중 (2016 연장 지원은 2027년 1월 종료) | 전체 통제 사용 가능 |

## 통제 매트릭스 { #control-matrix }

| 통제 | XP / 2003 | Vista / 2008 | 7 / 2008 R2 | 8.1 / 2012 R2 | 10 / 2016 / 2019 | 11 / 2022 / 2025 |
|---|---|---|---|---|---|---|
| **LM 해시 저장 안 함** (`NoLMHash`) | ✅ (직접 설정) | ✅ Default | ✅ Default | ✅ Default | ✅ Default | ✅ Default |
| **WDigest 평문 끄기** (`UseLogonCredential=0`) | ❌ | ❌ | 🔧 KB2871997 | ✅ Default | ✅ Default | ✅ Default |
| **LSA 보호** (`RunAsPPL`) | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ 새로 설치한 11 22H2+에서 Default (조건 충족 시) |
| **Credential Guard** | ❌ | ❌ | ❌ | ❌ | ✅ Ent/Edu 1511+, Server 2016+ | ✅ 11 22H2+ Ent/Edu에서 Default (조건 충족 HW) |
| **Remote Credential Guard** (RDP) | ❌ | ❌ | ❌ | ❌ | ✅ 1607+ | ✅ |
| **Restricted Admin** (RDP) | ❌ | ❌ | 🔧 KB2871997 / KB2973351 | ✅ | ✅ | ✅ |
| **Protected Users** 그룹 (클라이언트 쪽) | ❌ | ❌ | 🔧 KB2871997 | ✅ | ✅ | ✅ |
| **Windows LAPS** (내장) | ❌ | ❌ | ❌ | ❌ | ✅ 10 20H2+, Server 2019+ (2023년 4월 업데이트) | ✅ |
| **Legacy LAPS** (MSI) | ⚠️ | ✅ | ✅ | ✅ | ✅ (지원 중단 예정) | ⚠️ 11 23H2+에서는 불가 |
| **gMSA** (서비스 계정) | ❌ | ❌ | ⚠️ sMSA만 (2008 R2) | ✅ 2012+ | ✅ | ✅ |
| **UAC** | ❌ | ✅ | ✅ Default (슬라이더) | ✅ Default | ✅ Default | ✅ Default (+ Administrator protection 배포 중) |
| **AppLocker** | ❌ | ❌ | ✅ Ent/Ult, 2008 R2 | ✅ Ent | ✅ Ent/Edu | ✅ |
| **WDAC / App Control for Business** | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ (+ 새로 설치한 11의 Smart App Control) |
| **Software Restriction Policies** | ✅ | ✅ | ✅ | ✅ | ⚠️ 지원 중단 예정 | ⚠️ 지원 중단 예정 |
| **AMSI** | ❌ | ❌ | ❌ | ❌ | ✅ Default | ✅ Default |
| **PowerShell 5.1 script-block 로깅 (4104)** | ❌ | ❌ | 🔧 WMF 5.1 | 🔧 WMF 5.1 | ✅ (의심스러운 블록은 자동 기록) | ✅ |
| **PowerShell v2 제거 가능** | n/a | n/a | ⚠️ | ✅ | ✅ | ✅ 11 24H2 / Server 2025에서 제거됨 |
| **Defender Antivirus** (완전한 AV) | ❌ | ⚠️ 안티스파이웨어 | ⚠️ MSE 추가 설치 | ✅ Default | ✅ Default | ✅ Default |
| **ASR 규칙** | ❌ | ❌ | ❌ | ⚠️ 2012 R2는 MDE 통합 에이전트로 | ✅ 1709+ / Server 2019 (2016은 MDE로) | ✅ |
| **Tamper Protection** | ❌ | ❌ | ❌ | ❌ | ✅ 1903+ | ✅ Default |
| **HVCI / 메모리 무결성** | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ 새로 설치 시 Default |
| **취약 드라이버 차단 목록** | ❌ | ❌ | ❌ | ❌ | ⚠️ 선택적 사용(opt-in) | ✅ 11 22H2+에서 Default |
| **BitLocker** | ❌ | ✅ Ent/Ult, Server | ✅ Ent/Ult, Server | ✅ Pro/Ent | ✅ Pro/Ent | ✅ (많은 11 24H2 기기에서 장치 암호화가 기본) |
| **SMBv1 제거** | ❌ (필수) | ❌ | 🔧 레지스트리 | ✅ 제거 가능 | ✅ 새로 설치한 1709+에는 설치 안 됨 | ✅ 설치 안 됨 |
| **SMB 서명 필수** (모든 연결) | ✅ (직접 설정) | ✅ (직접 설정) | ✅ (직접 설정) | ✅ (직접 설정) | ✅ (직접 설정) — DC는 기본 | ✅ **11 24H2 / Server 2025에서 Default** |
| **GPO로 LLMNR 끄기** | n/a (LLMNR 없음) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **NTLMv1 / LM 거부** (`LmCompatibilityLevel=5`) | ✅ (직접 설정) | ✅ | ✅ | ✅ | ✅ | ✅ 11 24H2 / Server 2025에서 NTLMv1 **제거됨** |
| **LDAP 서명 + 채널 바인딩** (DC) | ⚠️ 서명만 | ✅ 서명; 🔧 CB (2020 업데이트) | 🔧 CB (2020 업데이트) | 🔧 CB (2020 업데이트) | ✅ | ✅ Server 2025에서 더 엄격한 기본값 |
| **RDP용 NLA** | ⚠️ 클라이언트만 (SP3) | ✅ | ✅ Default | ✅ Default | ✅ Default | ✅ Default |
| **계정 잠금** 기본값 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 새로 설치한 11 22H2+ |
| **4688의 명령줄 기록** | ❌ | ❌ | 🔧 KB3004375 | ✅ | ✅ | ✅ |
| **고급 감사 정책** | ❌ (기본만) | ⚠️ auditpol로 | ✅ GPO | ✅ | ✅ | ✅ |
| **Windows Event Forwarding** | 🔧 WinRM 추가 설치 | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Sysmon** (현재 릴리스) | ❌ | ❌ | ⚠️ 구버전 Sysmon만 | ✅ 2012 R2 | ✅ | ✅ (11 / Server 2025에 내장 Sysmon 기능 도입 중) |

!!! note "매트릭스는 최저선이 아니라 최고선으로 읽으세요"
    "✅"는 그 통제를 배포*할 수 있다*는 뜻입니다. 사고 대응에서는 실제로 **배포되어 있었는지**를 항상 확인하세요 — 예: Credential Guard / HVCI는 `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`, `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL`, `Get-MpComputerStatus | Select IsTamperProtected`, `Get-SmbServerConfiguration | Select RequireSecuritySignature,EnableSMB1Protocol`.

## 기법 → 통제 { #technique-controls }

| 기법 | 주요 통제 (우선순위 순) | 페이지 |
|---|---|---|
| LSASS 덤프 | 관리자 계층화 · Credential Guard · LSA PPL · WDigest 끄기 · ASR LSASS 규칙 | [LSASS 덤프](lsass-dumping.md) |
| SAM / LSA secrets / NTDS | LAPS · Tier 0 격리 · BitLocker · HiveNightmare 수정 · 낮은 CachedLogonsCount | [SAM과 NTDS](sam-ntds-extraction.md) |
| DCSync | 복제 권한 최소화 · 4662 감사 · 계층화 · Protected Users | [DCSync](dcsync.md) |
| Kerberoasting | gMSA / 긴 비밀번호 · AES만 사용 · 관리자 계정에 SPN 두지 않기 | [Kerberoasting](kerberoasting.md) |
| AS-REP roasting | `DONT_REQ_PREAUTH` 제거 · AES만 사용 | [AS-REP roasting](asrep-roasting.md) |
| Golden / Silver / PtT | krbtgt 교체 · 패치된 DC · Credential Guard · PAC 검증 | [Golden과 Silver](golden-silver-tickets.md) |
| Pass-the-Hash | LAPS · 로컬 계정의 네트워크 로그온 거부 · Credential Guard · SMB 서명 | [Pass-the-Hash](pass-the-hash.md) |
| LLMNR / NTLM 릴레이 | LLMNR+NBT-NS 끄기 · SMB 서명 · LDAP 서명/CB · EPA · NTLMv1 끄기 | [LLMNR과 릴레이](llmnr-ntlm-relay.md) |
| ADCS ESC1 / ESC8 | 템플릿 관리 · EPA/HTTPS 또는 웹 등록 제거 · 강력한 인증서 매핑 | [ADCS 악용](adcs-abuse.md) |
| PowerShell 크래들 | Script-block 로깅 · AMSI · CLM + WDAC · PSv2 제거 | [PowerShell 크래들](powershell-cradles.md) |
| LOLBins | WDAC 차단 규칙 · ASR · AppLocker · 외부 통신 프록시 | [LOLBins](lolbins.md) |
| WMI / WinRM | 원격 관리를 관리용 호스트로 제한 · JEA · WMI 구독 모니터링 | [WMI와 WinRM](wmi-winrm.md) |
| PsExec / SMB | LAPS · 호스트 방화벽 445 · SMB 서명 · 7045 모니터링 | [PsExec와 SMB](psexec-smb.md) |
| RDP | 인터넷 RDP 금지 + MFA · NLA · Remote Credential Guard · 계정 잠금 | [RDP](rdp.md) |
| 지속성 | Autoruns 기준선 · 4698/7045 알림 · WDAC | [지속성](persistence.md) |
| UAC 우회 | 로컬 관리자 없애기 · 항상 알림 · Administrator protection | [UAC 우회](uac-bypass.md) |
| Potato / 토큰 | 거점 차단 · 최소 권한 서비스 계정 · Spooler 끄기 | [토큰과 Potato](token-impersonation-potato.md) |
| 프로세스 인젝션 | EDR · ASR · Exploit Protection · HVCI · PPL | [프로세스 인젝션](process-injection.md) |
| 방어 회피 / 로그 삭제 | 호스트 밖 로깅 · Tamper Protection · 드라이버 차단 목록 · 하트비트 | [방어 무력화](impair-defenses-log-clearing.md) |
| EternalBlue | MS17-010 · SMBv1 제거 · 445 차단 · 레거시 격리 | [EternalBlue](eternalblue-smbv1.md) |
| PrintNightmare | 서버/DC에서 Spooler 끄기 · 패치 · 드라이버 설치 제한 | [PrintNightmare](printnightmare.md) |

## 업그레이드할 수 없는 호스트는 어떻게 할까 { #what-to-do-with-a-host-that-cannot-be-upgraded }

레거시 Windows(XP/2003/7)는 OT, 실험실, 의료, 임베디드 시스템에 살아남아 있습니다. 위의 통제 대부분이 그곳에는 아예 없으므로, 전략이 *호스트 강화*에서 *호스트 봉쇄*로 바뀝니다:

1. **네트워크 격리** — 전용 VLAN, 기본 거부 방화벽, 일반 네트워크에서의 SMB/RDP 금지, 인터넷 금지.
2. 호스트에 **도메인 자격증명 두지 않기** — 고유한 비밀번호를 가진 로컬 계정만, Domain Admin 로그온은 절대 금지.
3. 최신 통제를 갖춘 **점프 호스트**가 유일한 진입로; 그 점프 호스트를 면밀히 모니터링.
4. 호스트 로깅이 약하므로 해당 구간 주변에 **네트워크 기반 탐지**(Zeek, IDS).
5. 위험 수용 결정과 교체 일정을 문서화.

## 참고 자료 { #references }

- [Microsoft — Windows lifecycle fact sheet](https://learn.microsoft.com/lifecycle/faq/windows)
- [Microsoft — Mitigating Pass-the-Hash and other credential theft v2](https://www.microsoft.com/download/details.aspx?id=36036)
- [Microsoft — Securing privileged access (enterprise access model)](https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model)
- 관련 페이지: [공격 기법 목록](index.md) · [Windows 이벤트 ID](../basics/windows-event-ids.md) · [플레이북](../playbooks/index.md)
