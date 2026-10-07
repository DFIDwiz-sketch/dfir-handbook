---
title: DFIR용 레지스트리 키
tags:
  - artifact
  - windows
  - registry
---

# DFIR용 레지스트리 키 { #registry-keys-for-dfir }

<div class="dfir-meta" markdown>
**분류:** 레지스트리 · **OS:** Windows 7 → 11 · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    조사에서 실제로 열어 보는 레지스트리 키를 답하는 질문별로 묶었습니다 — 시스템 정보, 사용자 활동, 프로그램 실행, USB 장치, 네트워크, 지속성.

## 하이브와 위치 { #hives-and-where-they-live }

| 하이브 (regedit에서 보이는 이름) | 디스크상의 파일 | 범위 |
|---|---|---|
| `HKLM\SYSTEM` | `C:\Windows\System32\config\SYSTEM` | 서비스, 드라이버, ControlSet, 마운트된 장치, Shimcache, BAM |
| `HKLM\SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` | 설치된 소프트웨어, OS 버전, Run 키(머신), 프로필, 네트워크 목록 |
| `HKLM\SAM` | `C:\Windows\System32\config\SAM` | 로컬 계정, RID, 마지막 로그온, 비밀번호 힌트 |
| `HKLM\SECURITY` | `C:\Windows\System32\config\SECURITY` | LSA 시크릿, 캐시된 도메인 자격증명 (SYSTEM 부트키 필요) |
| `HKU\<SID>` | `C:\Users\<user>\NTUSER.DAT` | 사용자별: Run 키, MRU 목록, UserAssist, WordWheel, TypedPaths |
| `HKU\<SID>_Classes` | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | **ShellBags**, MUI 캐시, 사용자별 COM/클래스 등록 |
| `HKLM\BCD00000000` | `\Boot\BCD` (시스템 파티션) | 부팅 설정 |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | [Amcache](amcache.md) |

각 하이브와 함께 **트랜잭션 로그**(`*.LOG1`, `*.LOG2`)를 꼭 가져오세요 — 최근 변경은 하이브에 기록되기 전까지 거기에만 있을 수 있습니다. Registry Explorer / `rla.exe` 같은 파서가 이를 재생해 줍니다. 오래된 하이브 버전은 `C:\Windows\System32\config\RegBack\`(최신 Win10+에서는 대개 비어 있음)와 볼륨 섀도 복사본도 확인하세요.

`CurrentControlSet`은 심볼릭 링크입니다: `SYSTEM\Select\Current`(보통 `1` → `ControlSet001`)를 읽으세요. `LastKnownGood`은 이전 것을 가리킵니다.

## 시스템 정보와 시간 { #system-identity-timing }

| 질문 | 키 | 메모 |
|---|---|---|
| OS 버전, 설치 날짜 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `ProductName`, `CurrentBuild`, `InstallDate` (epoch), `RegisteredOwner` |
| 컴퓨터 이름 | `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` | |
| 시간대 | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | `ActiveTimeBias` (분 단위, 부호 반대), `TimeZoneKeyName`. **타임라인을 만들기 전에 반드시 확인** |
| 마지막 종료 | `SYSTEM\CurrentControlSet\Control\Windows\ShutdownTime` | FILETIME |
| 네트워크 인터페이스 / IP | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}` | `DhcpIPAddress`, `DhcpServer`, `LeaseObtainedTime`, `DhcpDomain` |
| 접속했던 네트워크 (SSID, 처음/마지막 연결) | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}` + `Signatures\Unmanaged` | `ProfileName`, `DateCreated`, `DateLastConnected` (128비트 SYSTEMTIME), `DefaultGatewayMac` — BSSID로 위치 추정 |
| 이 PC의 사용자 프로필 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>` | `ProfileImagePath`, `LocalProfileLoadTimeLow/High`, `LocalProfileUnloadTime` |
| 로컬 계정 | `SAM\Domains\Account\Users\<RID hex>` | `F` 값: 마지막 로그온, 비밀번호 마지막 설정, 계정 만료, 잘못된 비밀번호 횟수, 로그온 횟수; `V` 값: 사용자명, 전체 이름, 설명. RegRipper `samparse`로 파싱 |
| Prefetch 켜져 있나? | `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters` | `EnablePrefetcher` |
| 종료 시 페이지 파일 삭제? | `...\Memory Management\ClearPageFileAtShutdown` | 안티포렌식 단서 |
| 마지막 접근 타임스탬프 켜져 있나? | `SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate` | Win10 1803+에서 `0x80000000`–`0x80000003` = 시스템 관리 (작은 볼륨에서는 켜짐) |
| RDP 허용? | `SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` | `0` = RDP 허용 |
| Defender 변조 | `SOFTWARE\Policies\Microsoft\Windows Defender` (`DisableAntiSpyware`, `DisableRealtimeMonitoring`), `...\Exclusions\Paths` | 공격자는 도구를 떨어뜨리기 전에 예외를 추가함 |
| WDigest 평문 자격증명 | `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` | `1` = LSASS가 평문 보관 → Mimikatz 준비 작업 |
| LSA 보호 / RunAsPPL | `SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | |

## 프로그램 실행 (별도 표시 없으면 사용자별) { #program-execution-per-user-unless-noted }

| 키 | 기록하는 것 | 메모 |
|---|---|---|
| **UserAssist** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | GUI로 실행한 프로그램(탐색기, 시작 메뉴, 바로가기)과 **실행 횟수, 마지막 실행 시각, 포커스 시간** | 값 이름은 **ROT-13**. `{CEBFF5CD-…}` = 실행 파일, `{F4E57C4B-…}` = 바로가기. cmd 콘솔에서 실행한 것은 기록하지 *않음* |
| **BAM / DAM** `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (Win10 1709+) | 실행된 파일의 전체 경로 + **마지막 실행 시각**, 사용자 SID별 | Background Activity Moderator. *사용자*가 붙은 몇 안 되는 *"마지막 실행"* 타임스탬프. Server 2019+에도 있음 |
| **RecentApps** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` | 앱 + 마지막 접근 + 연 파일 (Win10 1607–1709) | 이후 빌드에서 제거됨 |
| **MUICache** `UsrClass\Local Settings\Software\Microsoft\Windows\Shell\MuiCache` | 실행한 파일의 표시 이름 (버전 리소스에서) | 타임스탬프 없음; 바이너리가 존재했고 탐색기로 실행됐다는 증거 |
| **AppCompatFlags / Layers** `NTUSER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` (HKLM에도) | 사용자가 호환성 옵션("관리자 권한으로 실행")을 설정한 프로그램 | |
| **Store** `NTUSER\...\AppCompatFlags\Compatibility Assistant\Store` | PCA(프로그램 호환성 관리자)가 관찰한 프로그램 — 실행된 EXE 경로가 보임 | 설치 파일/도구 찾을 때 유용 |
| **Shimcache** `SYSTEM\...\Session Manager\AppCompatCache` | [Shimcache](shimcache.md) 참고 | 시스템 전체 |
| **RunMRU** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | **Win+R**에 입력한 명령 | `MRUList`가 순서를 알려 줌 |
| **TypedPaths** `NTUSER\...\Explorer\TypedPaths` | 탐색기 주소창에 입력한 경로 | |
| **WordWheelQuery** `NTUSER\...\Explorer\WordWheelQuery` | 탐색기/시작 메뉴 **검색창**에 입력한 단어 | |
| **PowerShell ConsoleHost_history** (레지스트리 아님) | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | PS 5.1+의 모든 대화형 PowerShell 명령 — 같은 시점에 찾게 되므로 여기 적어 둠 |

## 연 파일과 폴더 (사용자별) { #files-folders-opened-per-user }

| 키 | 기록하는 것 | 메모 |
|---|---|---|
| **RecentDocs** `NTUSER\...\Explorer\RecentDocs` (+ 확장자별 하위 키) | 탐색기/공통 대화상자로 연 파일, 확장자별 | 키 LastWrite = 가장 최근 것; 나머지 순서는 `MRUListEx`. `Recent\`의 `.lnk` 파일과 짝지어 볼 것 |
| **OpenSavePidlMRU** `NTUSER\...\Explorer\ComDlg32\OpenSavePidlMRU\<ext>` | **열기/저장 대화상자**에서 고른 파일 (브라우저 다운로드 "다른 이름으로 저장", 첨부 파일) | |
| **LastVisitedPidlMRU** `NTUSER\...\Explorer\ComDlg32\LastVisitedPidlMRU` | 열기/저장 대화상자를 **어떤 실행 파일**이 썼고 **마지막으로 어느 폴더**를 봤는지 | 프로그램 ↔ 폴더를 연결 |
| **ShellBags** `UsrClass\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` & `Bags`; `NTUSER\Software\Microsoft\Windows\Shell\BagMRU`에도 | 사용자가 **탐색기에서 둘러본** 폴더(로컬, 네트워크, 이동식, zip 내부)와 보기 설정, 당시 폴더의 **MFT 참조 + 타임스탬프** | 폴더가 존재했고 열렸다는 증거 — 삭제됐거나 지금은 빠진 USB라도. **SBECmd / ShellBags Explorer**로 파싱 |
| **Office MRU** `NTUSER\Software\Microsoft\Office\<ver>\<App>\File MRU` / `Place MRU` | Word/Excel/PowerPoint에서 연 문서와 **마지막으로 연 시각** | `[F00000000][T01D9A…]` — T = FILETIME 16진수 |
| **Office 신뢰할 수 있는 문서** `NTUSER\Software\Microsoft\Office\<ver>\<App>\Security\Trusted Documents\TrustRecords` | 사용자가 **콘텐츠 사용 / 편집 사용**을 누른 문서 | 악성 매크로 문서 → 이 키. 타임스탬프 = 신뢰를 준 시각 |
| **Reading Locations** (Word) `...\Word\Reading Locations` | 최근 연 문서의 마지막 위치와 날짜 | |
| **MountPoints2** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | **사용자**가 접근한 볼륨 (USB GUID, 네트워크 공유 포함) | 장치를 *사용자*와 연결; USB 섹션 참고 |
| **Map Network Drive MRU** `NTUSER\...\Explorer\Map Network Drive MRU` | 사용자가 매핑한 UNC 경로 | |

## USB와 이동식 장치 (시스템) { #usb-removable-devices-system }

| 키 | 기록하는 것 |
|---|---|
| `SYSTEM\CurrentControlSet\Enum\USBSTOR\<Ven_Prod_Rev>\<SerialNo>` | 제조사, 제품, **시리얼 번호** (두 번째 자리가 `&`이면 실제 시리얼이 아니라 Windows가 만든 ID). 하위 키 `Properties\{83da6326-…}\0064` = 처음 설치, `0066` = 마지막 연결, `0067` = 마지막 제거 (Win8+) |
| `SYSTEM\CurrentControlSet\Enum\USB\VID_xxxx&PID_xxxx\<Serial>` | VID/PID 기준의 같은 장치; `Properties` 타임스탬프는 위와 같음 |
| `SYSTEM\MountedDevices` | `\DosDevices\E:`와 `\??\Volume{GUID}` ↔ 시리얼이 들어 있는 장치 문자열 연결 |
| `SOFTWARE\Microsoft\Windows Portable Devices\Devices` | 장치의 **표시 이름 / 볼륨 레이블** |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` | ReadyBoost — 볼륨 시리얼 번호 ↔ 장치 (구형 시스템, HDD) |
| `NTUSER\...\Explorer\MountPoints2\{Volume GUID}` | **어느 사용자**가 그 볼륨을 마운트했는지 (키 LastWrite = 그 사용자의 마지막 마운트) |
| `SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` | 휴대용 장치 (휴대폰, 카메라) |
| 그 외 (레지스트리 아님) | `C:\Windows\inf\setupapi.dev.log` — 처음 연결한 시각과 드라이버 설치 정보 |

## 자동 시작 / 지속성 (ASEP) { #autostart-persistence-asep }

| 키 | 메모 |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `RunOnceEx` | 머신 전체, 누가 로그온하든 실행 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` | 사용자별 |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` | 64비트의 32비트 뷰 — 자주 잊힘 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`과 HKCU 버전 | 정책 기반 Run |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell` (`explorer.exe`여야 함), `Userinit` (`C:\Windows\system32\userinit.exe,`여야 함), `Notify` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` | `Debugger` 값 → 하이재킹 (예: 고정 키 `sethc.exe` → `cmd.exe`); `GlobalFlag` + `SilentProcessExit` 조합 |
| `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | `ImagePath`, `Start` (2 = 자동), `Type`, svchost 호스팅 서비스는 `Parameters` 아래 `ServiceDll`. 새 서비스 = System `7045` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` (+ `LoadAppInit_DLLs`) | user32.dll을 로드하는 모든 프로세스에 DLL 주입 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` | `autocheck autochk *`만 있어야 함 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` — `Authentication Packages`, `Security Packages`, `Notification Packages` | SSP 주입 (Mimikatz `memssp`, 사용자 정의 비밀번호 필터) |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` & `Tasks\{GUID}` | 예약 작업의 레지스트리 쪽; `Actions` blob에 명령이 있음. `C:\Windows\System32\Tasks\*` XML과 비교 — **Tree에는 없고 Tasks에는 있는** 작업은 숨긴 작업 |
| `HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32`와 `HKCU\Software\Classes\CLSID\...` | **COM 하이재킹** — HKCU가 HKLM보다 우선 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, `ShellExecuteHooks`, `ShellServiceObjectDelayLoad` | 탐색기/IE 확장 지점 |
| `HKLM\SOFTWARE\Microsoft\Netsh` | Netsh 도우미 DLL |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`, `Print\Monitors`, `Print\Providers` | 드문 드라이버 수준 ASEP |
| `HKCU\Environment\UserInitMprLogonScript` | 로그온 시 실행되는 로그온 스크립트 — 고전적이고 조용함 |
| `HKCU\Software\Microsoft\Command Processor\AutoRun` (HKLM에도) | `cmd.exe`가 시작될 때마다 실행 |
| `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{GUID}\StubPath` | 사용자당 로그온 시 한 번 실행 |
| 시작 프로그램 폴더 (레지스트리 아님) | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp` |

**Autoruns**(`autorunsc.exe -a * -c -h -s -v -zip`)나 RegRipper의 `autoruns` 류 플러그인으로 이 모두를 한 번에 훑으세요. 오프라인 이미지라면 Autoruns의 **File → Analyze Offline System**으로 마운트한 시스템을 분석할 수 있습니다.

## 파싱 { #parsing }

=== "Registry Explorer / RECmd (Eric Zimmerman)"

    ```powershell
    # Batch mode with the community "Kroll" batch file — hits most keys above in one go
    RECmd.exe -d C:\Case\Registry --bn BatchExamples\Kroll_Batch.reb --csv C:\Case\out --nl

    # Replay transaction logs into a clean hive first if the tool complains the hive is dirty
    rla.exe -d C:\Case\Registry --out C:\Case\Registry\clean
    ```

    GUI: **Registry Explorer**에는 이 페이지의 모든 키가 북마크로 들어 있고, 슬랙 공간에서 삭제된 키/값도 보여 줍니다.

=== "RegRipper 3"

    ```bash
    rip.pl -r NTUSER.DAT -f ntuser   > ntuser.txt
    rip.pl -r UsrClass.dat -f usrclass > usrclass.txt
    rip.pl -r SYSTEM -f system > system.txt
    rip.pl -r SOFTWARE -f software > software.txt
    rip.pl -r SAM -f sam > sam.txt
    # single plugins
    rip.pl -r NTUSER.DAT -p userassist
    rip.pl -r SYSTEM -p bam
    rip.pl -r SYSTEM -p usbstor
    ```

=== "라이브 (PowerShell)"

    ```powershell
    # Run keys, both hives, both views
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'

    # BAM last-executed per SID
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' | ForEach-Object {
      $sid=$_.PSChildName; Get-ItemProperty $_.PSPath | Select-Object -Property * -ExcludeProperty PS* |
      ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Value -is [byte[]] } |
      ForEach-Object { [pscustomobject]@{SID=$sid; Path=$_.Name; Last=[DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($_.Value,0))} } } }
    ```

## 분석 팁 { #analysis-tips }

!!! tip "모든 키에는 LastWrite 시각이 있습니다 — 활용하세요"
    타임스탬프 값이 따로 없는 키(MUICache, RecentDocs 하위 키, USBSTOR)도 *키가 마지막으로 바뀐 시각*은 알려 줍니다. MRU 형태의 키라면 그것이 가장 최근 항목의 시각입니다.

- **시간대부터.** 레지스트리 FILETIME은 UTC, 이벤트 로그도 UTC, `$SI` 타임스탬프도 UTC이지만 *사용자가 보는 시간*과 많은 애플리케이션 로그는 로컬 시간입니다. 무엇보다 먼저 `TimeZoneInformation`을 확인하세요.
- **삭제된 키도 복구됩니다.** Registry Explorer와 `yarp`/`regipy`는 할당되지 않은 셀을 카빙할 수 있어서, 삭제된 Run 값과 서비스가 살아남는 경우가 많습니다.
- **COM은 HKCU가 HKLM을 이깁니다.** `HKCU\Software\Classes` 아래 CLSID는 머신 쪽 설정을 조용히 덮어씁니다 — 사용자가 쓸 수 있는 경로를 가리키는 `InprocServer32` 값을 찾으세요.
- **더티 하이브.** 라이브 상태에서 이미징했다면 `.LOG1/.LOG2`를 적용(rla.exe)하지 않으면 마지막 몇 분의 활동을 놓칠 수 있습니다 — 바로 그때 지속성이 설치되는 경우가 많습니다.

## 참고 자료 { #references }

- [SANS Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/)
- [Eric Zimmerman — Registry Explorer / RECmd / RECmd batch files](https://github.com/EricZimmerman/RECmd)
- [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [Harlan Carvey — Windows Registry Forensics, 2nd ed.](https://www.elsevier.com/books/windows-registry-forensics/carvey/978-0-12-803291-6)
- [MITRE ATT&CK T1547 — Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
