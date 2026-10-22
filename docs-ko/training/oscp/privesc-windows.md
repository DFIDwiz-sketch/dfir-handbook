---
title: Windows 권한 상승
tags:
  - oscp
---

# Windows 권한 상승 { #windows-privilege-escalation }

<div class="dfir-meta" markdown>
**배점:** Windows standalone 대당 10점 (`proof.txt`) + AD 세트 호스트 · **최종 수정:** 2026-10-23
</div>

!!! abstract "한 문장 요약"
    저권한 사용자에서 Administrator / SYSTEM까지. 정보 수집 스크립트를 돌리고, 토큰 권한을 먼저 보고, 그다음 서비스·예약 작업·저장된 크리덴셜을 확인합니다.

!!! note "이 페이지 구성"
    공부 체크리스트입니다. Windows에서 가장 빠른 승리는 보통 서비스 토큰 권한이나 저장된 크리덴셜이라, 그것부터 일찍 확인하세요. Proving Grounds Windows 박스로 연습하세요 → [실습 랩](practice-labs.md).

## 1. 정보 수집 { #enumeration }

```powershell
whoami /priv          # 토큰 권한 — 가장 먼저 읽을 것
whoami /groups        # 그룹 소속
systeminfo            # OS 빌드, 핫픽스 (누락 패치 확인용)
```

그다음 자동 스크립트를 위에서 아래로 읽습니다:

```powershell
.\winPEASx64.exe              # 또는 PrivescCheck.ps1 / SharpUp.exe audit
```

`whoami /priv` 가 가장 중요한 한 줄입니다. `SeImpersonatePrivilege` 나 `SeAssignPrimaryTokenPrivilege` 가 **Enabled** 로 보이면 아래 potato 계열로 바로 가세요.

## 2. 흔한 경로 { #vectors }

| 경로 | 볼 것 | 단서 |
|---|---|---|
| **토큰 권한** | `SeImpersonatePrivilege` (서비스 계정, `xp_cmdshell`, 웹 셸에 흔함) | PrintSpoofer / GodPotato → SYSTEM → [potato](#token-privileges) |
| **서비스 설정 실수** | 쓰기 가능한 서비스 바이너리, 약한 서비스 권한, 공백이 있는 **unquoted service path** | 서비스가 SYSTEM으로 실행하는 바이너리를 교체 / 심기 |
| **예약 작업** | 내가 수정할 수 있는 스크립트·바이너리를 권한 있는 사용자로 돌리는 작업 | 그 작업이 실행하는 대상을 고치기 |
| **AlwaysInstallElevated** | 두 레지스트리 키가 모두 설정됨 | 악성 MSI를 SYSTEM으로 설치 (`msfvenom` MSI는 허용) |
| **저장된 크리덴셜** | GPP 비밀번호, 저장된 자격 증명, PowerShell 히스토리, 설정 / XML 파일 | 재사용 → [루팅](active-directory.md#looting) |
| **DLL 하이재킹** | 권한 있는 프로세스가 쓰기 가능한 경로에서 DLL 로드 | DLL 심기 |
| **패치 안 된 커널** | `systeminfo` + 알려진 익스플로잇 | Linux처럼 마지막 수단 |

### 토큰 권한 / potato { #token-privileges }

`SeImpersonatePrivilege` 는 프로세스가 건네받은 토큰을 가장(impersonate)하게 해 줍니다. "potato" 도구는 권한 있는 서비스가 인증하도록 유도한 뒤 그 SYSTEM 토큰을 가장합니다. standalone 박스에서 가장 흔한 승리이고, SQL / IIS 서비스 계정에 아주 흔합니다.

→ 탐지 쪽과 정확한 원리: [토큰 가장 / Potato](../../adversary/token-impersonation-potato.md).

## 3. 저장된 크리덴셜 { #stored-credentials }

어떤 익스플로잇보다 빠른 경우가 많습니다 — 파기 전에 먼저 보세요:

```powershell
cmdkey /list                                   # 저장된 자격 증명
Get-Content (Get-PSReadlineOption).HistorySavePath   # PowerShell 히스토리
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"
Get-ChildItem C:\ -Include *.config,*.xml,*.ini,*.kdbx -Recurse -ErrorAction SilentlyContinue
```

SAM만으로 부족할 때는 LSA secrets와 캐시된 로그온에 서비스 비밀번호가 있습니다 → [SAM / NTDS 추출](../../adversary/sam-ntds-extraction.md), [LSASS 덤프](../../adversary/lsass-dumping.md).

## 4. UAC와 커널 { #uac-kernel }

- **관리자** 인데 medium-integrity 셸이라면, 그건 권한 상승이 아니라 [UAC 우회](../../adversary/uac-bypass.md)입니다 — 이미 권한은 있고, 토큰을 올리면 됩니다.
- 커널 / 누락 패치 익스플로잇(`systeminfo` 기반)은 Linux와 같은 이유로 마지막 수단입니다.

## 체크리스트 { #checklist }

- [ ] `whoami /priv` 읽기 → `SeImpersonate`/`SeAssignPrimaryToken` 이면 potato
- [ ] winPEAS / PrivescCheck 돌리고 읽기
- [ ] 서비스 확인 (쓰기 가능한 바이너리, unquoted path, 약한 권한)
- [ ] 예약 작업 확인
- [ ] AlwaysInstallElevated 키 확인
- [ ] 저장된 크리덴셜 찾기 (cmdkey, 히스토리, 레지스트리, 파일)
- [ ] 누락 패치용 `systeminfo` 기록 (마지막 옵션)

## 관련 페이지 { #related-pages }

- [토큰 가장 / Potato](../../adversary/token-impersonation-potato.md) · [UAC 우회](../../adversary/uac-bypass.md)
- [SAM / NTDS 추출](../../adversary/sam-ntds-extraction.md) · [LSASS 덤프](../../adversary/lsass-dumping.md)
- [레지스트리 키](../../windows/registry-keys.md) · [이벤트 로그](../../windows/event-logs.md) · [방법론과 습관](methodology.md)

## 참고 자료 { #references }

- [LOLBAS](https://lolbas-project.github.io/)
- [PEASS-ng (winPEAS)](https://github.com/peass-ng/PEASS-ng)
