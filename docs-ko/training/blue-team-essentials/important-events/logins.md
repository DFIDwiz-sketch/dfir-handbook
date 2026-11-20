---
title: "로그인 이벤트 — 4624/4625와 로그온 유형, 4648 명시적 자격 증명, Linux 로그인과 로그인 실패"
tags:
  - training
  - blue-team
  - windows
  - linux
  - logging
  - authentication
---

# 로그인 이벤트 — 4624/4625와 로그온 유형, 4648 명시적 자격 증명, Linux 로그인과 로그인 실패 { #logins }

!!! abstract "이 페이지에서 다루는 것"
    분석가가 매일 읽는 로그인 이벤트. Windows **4624**(로그온 성공)와 **4625**(로그온 실패)를 칸 하나하나 읽는 법, *Account Domain*이 실제로 무엇을 알려 주는지(도메인 이름일 수도, 컴퓨터 이름일 수도), 모든 **로그온 유형(Logon Type)** 과 각각이 조사에서 뜻하는 것, 로그온 하나를 그 세션이 한 모든 일과 이어 주는 **로그온 ID(Logon ID)**, 컴퓨터 계정과 시스템 로그온이 만드는 엄청난 잡음을 걸러 내는 법, 로그온이 왜 실패했는지 알려 주는 **Status/SubStatus** 코드. **4648**(명시적 자격 증명을 쓴 로그온, 이른바 "runas" 이벤트) — 누가, 어떤 계정을 빌려서, 어느 서버에 썼는지, 그리고 왜 이 이벤트는 *출발지* 컴퓨터에 남는지. 이어서 Linux: SSH 로그인 하나가 PID로 묶인 여러 syslog 줄로 나뉘어 남는 모습, 그 줄들이 어디에 저장되는지, 그리고 Linux 로그인 실패가 얼마나 여러 모양으로 나오는지. PowerShell과 셸 명령을 한 줄씩 풀이하고, SOC 점검 목록, 2026년 관점, 확인 문제가 이어집니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. **4624** = 계정이 로그온에 성공함, **4625** = 로그온 시도가 실패함. 둘 다 **Security** 채널에 있고, 사용자가 앉아 있는 컴퓨터가 아니라 **로그온을 받은 컴퓨터**(대상)에 남습니다.
2. 가장 중요한 칸은 **누가**(`TargetUserName`, `TargetDomainName`), **어떻게**(`LogonType`, `LogonProcessName`, `AuthenticationPackageName`), **어디서**(`IpAddress`, `WorkstationName`)입니다. 로컬 계정이면 "도메인" 칸에 **그 컴퓨터 자기 이름**이 들어갑니다.
3. **로그온 유형**은 로그온의 *종류*입니다. 2 콘솔, 3 네트워크(파일 공유, 대부분의 원격 관리 도구), 4 배치(예약 작업), 5 서비스, 7 잠금 해제/재연결, 8 평문 비밀번호 네트워크, 9 새 자격 증명(`runas /netonly`, pass-the-hash 도구), 10 RDP, 11 캐시된 도메인 로그온. 외워 두세요.
4. **[정정]** 유형 11은 "도메인 계정으로 키보드 앞에서 로그인"이 아닙니다. 그건 여전히 유형 2입니다. 유형 11은 도메인 컨트롤러에 닿지 못해서 **캐시된** 자격 증명을 썼다는 뜻입니다. 그리고 유형 2가 물리적으로 그 자리에 있었다는 증거도 아닙니다. 원격 제어 도구와 `runas`도 유형 2를 만듭니다.
5. **`TargetLogonId`** 는 세션의 일련번호입니다. 같은 값이 4672(관리자 권한), 4688(실행된 프로세스), 4634/4647(로그오프)에도 나옵니다. 로그온 하나와 그 안에서 벌어진 모든 일을 이어 줍니다.
6. 4624 대부분은 잡음입니다. **컴퓨터 계정**(이름이 `$`로 끝남), `SYSTEM`, `LOCAL SERVICE`, `DWM-*`, `UMFD-*`, `ANONYMOUS LOGON`. 헌팅할 때는 걸러 내되, 수집에서는 절대 빼지 마세요. 공격자도 컴퓨터 계정을 악용합니다.
7. **4648** = 어떤 프로세스가 **명시적 자격 증명**을 썼다는 뜻입니다. "사용자 X가 계정 Y로 서버 Z에 무언가를 했다." **출발지** 컴퓨터에 남기 때문에, 훔친 계정이 *어디에서* 쓰이고 있는지 보여 줍니다. 평소와 다른 X→Y 짝은 옆으로 이동(lateral movement)의 대표 신호입니다.
8. Linux에는 로그인 이벤트 ID가 없습니다. SSH 로그인 하나는 `sshd`(와 PAM)가 남긴 **여러 줄**이고 **PID**로 묶이며, `/var/log/auth.log`, `/var/log/secure`, 또는 저널에 있습니다. 실패는 여러 문구(`Invalid user`, `Failed password`, `authentication failure`)로 나오고, 각각 따로 검색 패턴이 필요합니다.

## 로그인 이벤트가 왜 중요한가 { #why }

거의 모든 침입은 어딘가에 로그온해야 합니다. 피싱당한 사용자의 세션, VPN에 뿌려 본 훔친 비밀번호, 파일 서버에서 다시 쓰인 서비스 계정, 데스크톱에서 서버로 옮겨 가는 탈취된 관리자 계정 — 모두 로그인 기록을 남깁니다. 공격자가 새 악성코드를 들여와도 못 볼 수 있지만, 계정을 *쓰려면* 인증을 거쳐야 하고, 시스템은 그걸 적어 둡니다.

문마다 방명록이 있는 건물을 떠올려 보세요. 방명록은 손님이 안에서 무엇을 했는지는 알려 주지 않지만, 누가 들어왔는지, 어느 문으로 들어왔는지(정문, 화물 출입구, 옆 창문), 언제, 어디서 왔는지는 알려 줍니다. 모든 문의 방명록을 이어 보면 한 사람이 건물 안을 어떻게 돌아다녔는지 따라갈 수 있습니다. 로그인 이벤트가 바로 그 방명록입니다. **4624/4625**가 방명록 한 줄, **로그온 유형**이 들어온 문, `IpAddress`가 "어디서 왔나", **로그온 ID**가 안에서 한 일을 맞춰 볼 수 있게 해 주는 방문증 번호입니다.

기술적인 실제로 돌아오면, Windows에서는 감사 하위 범주 **Logon**(*Logon/Logoff* 아래)이 켜져 있을 때 로컬 보안 기관(LSA, Local Security Authority)이 로그인을 **Security** 채널에 씁니다. Linux에서는 `sshd`, `login`, 디스플레이 관리자(display manager), PAM이 syslog나 systemd 저널로 씁니다. 이 페이지의 나머지는 그 기록을 빠르고 정확하게 읽는 연습입니다.

## Windows 4624: 로그온 성공 { #4624 }

### 언제 생기나 { #4624-when }

이벤트 **4624 — "An account was successfully logged on"(계정이 로그온에 성공함)** 은 로그온을 *받아들인* 컴퓨터가, 새 로그온 세션이 만들어질 때마다 씁니다. 키보드 앞에 앉아 로그인할 때, 파일 공유를 열 때, 예약 작업이 시작될 때, 서비스가 자기 계정으로 시작될 때, 웹 서버가 비밀번호를 확인할 때, RDP로 접속할 때 — 모두 받는 쪽 컴퓨터에 4624를 만듭니다. 그래서 Windows 환경에서 가장 많은 이벤트 중 하나입니다. 도메인 컨트롤러와 파일 서버는 1분에 수천 개를 쓰기도 합니다.

공격자 입장에서 이 이벤트가 중요한 이유는, **정상 계정 사용**(MITRE ATT&CK **T1078**, Valid Accounts. 도메인 계정 **T1078.002**, 로컬 계정 **T1078.003**)과 **옆으로 이동**을 기록하기 때문입니다. SMB(**T1021.002**), RDP(**T1021.001**), WinRM(**T1021.006**)을 통한 원격 로그온은 모두 대상 컴퓨터에 4624를 남깁니다.

### 이벤트 전체 모습 { #4624-sample }

사용자 `CORP\j.park`가 워크스테이션 `WS-114`(`10.20.7.31`)에서 파일 서버 `FS-02`의 공유 폴더를 연결합니다. `FS-02`에 남은 4624의 EventData 부분입니다(System 부분은 줄였습니다. 전체 구조는 [Windows 이벤트 구조](../windows-logging/event-structure-channels.md) 참고).

```xml
<System>
  <EventID>4624</EventID>
  <TimeCreated SystemTime="2026-11-20T01:12:44.1904530Z" />
  <Channel>Security</Channel>
  <Computer>FS-02.corp.example</Computer>
</System>
<EventData>
  <Data Name="SubjectUserSid">S-1-0-0</Data>
  <Data Name="SubjectUserName">-</Data>
  <Data Name="SubjectDomainName">-</Data>
  <Data Name="SubjectLogonId">0x0</Data>
  <Data Name="TargetUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="TargetUserName">j.park</Data>
  <Data Name="TargetDomainName">CORP</Data>
  <Data Name="TargetLogonId">0x2a91c7f</Data>
  <Data Name="LogonType">3</Data>
  <Data Name="LogonProcessName">Kerberos</Data>
  <Data Name="AuthenticationPackageName">Kerberos</Data>
  <Data Name="WorkstationName">-</Data>
  <Data Name="LogonGuid">{3f0d2a6e-9b41-0c55-7e12-8a4d6b2f1c90}</Data>
  <Data Name="TransmittedServices">-</Data>
  <Data Name="LmPackageName">-</Data>
  <Data Name="KeyLength">0</Data>
  <Data Name="ProcessId">0x0</Data>
  <Data Name="ProcessName">-</Data>
  <Data Name="IpAddress">10.20.7.31</Data>
  <Data Name="IpPort">51522</Data>
  <Data Name="ImpersonationLevel">%%1833</Data>
  <Data Name="RestrictedAdminMode">-</Data>
  <Data Name="TargetOutboundUserName">-</Data>
  <Data Name="TargetOutboundDomainName">-</Data>
  <Data Name="VirtualAccount">%%1843</Data>
  <Data Name="TargetLinkedLogonId">0x0</Data>
  <Data Name="ElevatedToken">%%1843</Data>
</EventData>
```

이벤트 뷰어의 쉬운 보기에서는 같은 데이터가 *Subject*, *Logon Information*, *New Logon*, *Process Information*, *Network Information*, *Detailed Authentication Information* 같은 제목 아래 묶여 보입니다. `%%` 숫자는 뷰어가 글자로 바꿔 주는 메시지 코드입니다. `%%1842` = Yes, `%%1843` = No, `%%1833` = Impersonation.

### 칸 하나씩 { #4624-fields }

- `SubjectUserSid` / `SubjectUserName` / `SubjectLogonId` — *이 컴퓨터에서* 로그온을 요청한 계정입니다. 네트워크 로그온은 요청이 밖에서 왔으니 비어 있습니다(`S-1-0-0`, `-`, `0x0`). 콘솔이나 RDP 로그온이면 보통 컴퓨터 자신(`S-1-5-18`, `FS-02$`, `0x3e7`)입니다. Windows의 `winlogon`이 LSA에게 "이 사용자 로그인시켜 줘"라고 부탁한 것이죠. Subject를 로그인한 사람으로 착각하지 마세요.
- `TargetUserSid` / `TargetUserName` — **누가 로그온했나.** 헌팅할 때 쓰는 계정 이름입니다. 이름은 바꿀 수 있지만 SID는 못 바꾸니, SID가 더 믿을 만합니다.
- `TargetDomainName` — 계정을 관리하는 **주체**입니다. 도메인 계정이면 도메인(`CORP`)이 들어갑니다. **로컬** 계정이면 **컴퓨터 이름**이 들어갑니다. `WS-114`의 로컬 관리자는 `WS-114\Administrator`로 나옵니다. `도메인\사용자`로 붙여 쓰면 한눈에 보입니다. `CORP\j.park`는 도메인 사용자이고, `FS-02\backupadm`는 그 서버 한 대에만 있는 계정입니다. 로컬 계정이 네트워크로 여러 컴퓨터에 로그온한다면, 같은 로컬 관리자 비밀번호를 돌려 쓰고 있고 누군가 그걸 악용한다는 위험 신호입니다(pass-the-hash가 좋아하는 상황).
- `TargetLogonId` — 새 세션의 **로그온 ID**(`0x2a91c7f`). 기억해 두세요. 다른 이벤트에서 이 값으로 찾게 됩니다.
- `LogonType` — **어떤 종류의 로그온인가**(다음 절). `3` = 네트워크.
- `LogonProcessName` — 로그온을 처리한 신뢰된 프로세스입니다. `User32`(`winlogon`을 거친 대화형/RDP), `NtLmSsp`(NTLM), `Kerberos`, `Advapi`(서비스, IIS, 일부 스크립트처럼 API로 하는 로그온), `seclogo`(보조 로그온 서비스 — `runas`).
- `AuthenticationPackageName` — 쓰인 프로토콜. `Kerberos`, `NTLM`, 또는 둘 중 하나를 고르는 `Negotiate`. `NTLM`이면 `LmPackageName`에 버전이 나옵니다(`NTLM V2`, 또는 보고할 만한 약점인 `NTLM V1`).
- `WorkstationName` — 클라이언트가 *스스로 밝힌* 이름입니다. Kerberos 네트워크 로그온은 자주 비워 두고, NTLM은 채웁니다. 클라이언트가 주는 값이라 공격 도구가 아무 이름이나 넣을 수 있으니 `IpAddress`보다 덜 믿으세요.
- `ProcessId` / `ProcessName` — 로그온을 만든 로컬 프로세스(예: RDP는 `C:\Windows\System32\svchost.exe`, 서비스는 `C:\Windows\System32\services.exe`). 네트워크 로그온은 비어 있습니다.
- `IpAddress` / `IpPort` — **어디서 왔나.** 네트워크·RDP 로그온이면 클라이언트 주소이고, 이동 경로를 따라갈 때 쓰는 칸입니다. `-`나 `127.0.0.1`/`::1`이면 로컬 로그온입니다.
- `ImpersonationLevel` — 서버가 그 사용자 행세를 어디까지 할 수 있는가. `Delegation`(`%%1840`)이면 서버가 그 신원을 다른 서버로 넘길 수 있습니다. 어떤 서비스에는 정상이지만, 예상 못 한 곳에서 나오면 눈여겨볼 만합니다.
- `RestrictedAdminMode` — RDP에서 *Restricted Admin*(자격 증명을 서버로 보내지 않는 방식)을 썼는지.
- `VirtualAccount` — 가상 서비스 계정인지.
- `ElevatedToken` / `TargetLinkedLogonId` — 세션이 관리자 전체 권한 토큰을 받았는지. 관리자가 사용자 계정 컨트롤(UAC)이 켜진 상태로 대화형 로그인하면 Windows가 **서로 연결된 세션 두 개**(권한을 줄인 것, 올린 것)를 만듭니다. 서로의 로그온 ID를 가리키는 4624 두 개가 보이는데, 정상이고 두 번 로그인한 게 아닙니다.

### 로그온 유형 { #logon-types }

로그온이라고 다 같지 않습니다. "진이 공유 폴더를 열었다", "누가 서버에 RDP로 들어왔다", "서비스가 시작됐다"를 구분해 주는 가장 쓸모 있는 칸이 로그온 유형입니다.

| 유형 | 이름 | 무엇이 만드나 | 조사에서의 뜻 |
| --- | --- | --- | --- |
| 2 | Interactive(대화형) | 콘솔에서 로그인; `/netonly` 없는 `runas`; 콘솔을 직접 조작하는 여러 원격 제어 도구(VNC류, 원격 지원) | *이* 컴퓨터의 데스크톱을 누군가 썼다. 물리적으로 있었다는 증거는 아님. |
| 3 | Network(네트워크) | 공유 폴더 접근(`\\FS-02\finance`), `net use`, PsExec식 서비스 생성, WMI, WinRM/PowerShell 원격, 대부분의 RPC | 옆으로 이동에서 가장 흔한 유형. `IpAddress`를 따라간다. 대상 메모리에 자격 증명이 남지 않음. |
| 4 | Batch(배치) | 사용자 계정으로 도는 예약 작업 | 새 작업 + 새 계정 = 지속성일 수 있음(**T1053.005**). |
| 5 | Service(서비스) | 설정된 계정으로 서비스가 시작됨 | 아는 서비스면 정상. 새 서비스 계정이나 사람 계정이 서비스로 쓰이면 확인(7045와 같이 보기). |
| 7 | Unlock(잠금 해제) | 잠긴 워크스테이션 잠금 해제, 기존 RDP 세션에 다시 연결 | 대개 무해. RDP는 재연결 때 유형 10 대신 이게 나올 수 있음. |
| 8 | NetworkCleartext(평문 네트워크) | 비밀번호가 평문으로 서버에 도착: IIS Basic 인증, DC의 LDAP simple bind | 어떤 프로토콜이 비밀번호를 드러내고 있다 — 그 자체로 발견 사항. |
| 9 | NewCredentials(새 자격 증명) | `runas /netonly`, 그리고 자격 증명을 주입해 프로세스를 띄우는 pass-the-hash / overpass-the-hash 도구(`LogonProcessName` = `seclogo`) | 로컬 신원은 그대로이고, 빌린 자격 증명은 네트워크에서만 쓰임. 평소엔 드묾 — 헌팅 가치가 높은 칸(**T1550.002**). |
| 10 | RemoteInteractive(원격 대화형) | 원격 데스크톱 | 누군가 네트워크 너머로 데스크톱 전체를 썼다(**T1021.001**). 워크스테이션끼리의 RDP나 낯선 출발지를 본다. |
| 11 | CachedInteractive(캐시 대화형) | 도메인 컨트롤러에 닿지 못할 때(오프라인 노트북) 콘솔에서 도메인 사용자 로그인 | Windows가 캐시된 자격 증명을 썼다. 출장자에게는 정상. |
| 12 | CachedRemoteInteractive | 11과 같은데 RDP | 드묾. |
| 13 | CachedUnlock | 캐시된 자격 증명으로 잠금 해제 | 드묾. |

**[정정]** "도메인 계정으로 키보드 앞에서 로그인하면 유형 11"이라는 설명을 자주 봅니다. 아닙니다. 도메인 컨트롤러에 닿을 수 있으면 콘솔에서 로그인한 도메인 사용자도 로컬 사용자와 똑같이 **유형 2**입니다. 유형 11은 캐시된 자격 증명을 썼을 때만 나옵니다. 마찬가지로 "유형 2면 공격자가 물리적으로 접근했다"도 지나친 해석입니다. 원격 제어 도구를 쓰거나 `runas`를 실행한 공격자도 유형 2를 만듭니다. 유형 2는 "이 로그온은 이 컴퓨터 자체의 데스크톱 세션에서 일어났다"로 읽고, *어떻게* 일어났는지는 부모 프로세스와 네트워크 활동을 보고 판단합니다.

**[보충] RDP는 로그온을 하나 이상 남깁니다.** 네트워크 수준 인증(NLA, Network Level Authentication — 기본값)이 켜져 있으면 서버는 먼저 **유형 3** 로그온으로 자격 증명을 확인하고, 그다음 데스크톱 세션을 **유형 10**으로 만듭니다. 끊긴 세션에 다시 연결하면 유형 7로 나올 수 있습니다. 나머지는 RDP 전용 채널(`Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`의 1149, `LocalSessionManager/Operational`의 21/24/25)이 채워 줍니다. [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md) 참고.

### 로그온 ID로 세션 하나 따라가기 { #logon-id }

`TargetLogonId`는 병원 환자 팔찌 번호 같은 겁니다. 그 환자가 받는 검사와 처치에는 모두 그 번호가 붙죠. Windows도 이후 이벤트에 같은 번호를 찍습니다.

| 이벤트 | 로그온 ID가 들어가는 칸 | 더해 주는 정보 |
| --- | --- | --- |
| 4672 — 새 로그온에 특수 권한 부여 | `SubjectLogonId` | 이 세션이 관리자급 권한(SeDebugPrivilege 등)을 가졌다. 관리자는 4624 바로 뒤에 나옴. |
| 4688 — 새 프로세스 생성 | `SubjectLogonId` | 세션 안에서 실행된 모든 프로그램(프로세스 감사가 켜져 있을 때). |
| 4634 — 계정 로그오프 / 4647 — 사용자가 로그오프 시작 | `TargetLogonId` | 세션이 언제 끝났나 — 세션 길이를 알려 줌. |
| 4648 — 명시적 자격 증명으로 로그온 | `SubjectLogonId` | 이 세션이 다른 계정을 빌렸다. |

그래서 일하는 순서는 이렇습니다. 수상한 4624를 찾는다 → `TargetLogonId`를 복사한다 → 같은 컴퓨터의 이벤트에서 그 값을 찾는다 → 그 세션이 한 일을 읽는다. 로그온 ID는 **컴퓨터별, 부팅별로만** 고유하니 꼭 컴퓨터 이름과 같이 검색하세요.

### 잡음 걸러 내기 { #noise }

도메인 컨트롤러의 4624 대부분은 **컴퓨터 계정**에서 옵니다. 컴퓨터마다 계정이 하나씩 있고(`WS-114$`, `FS-02$`), 정책과 티켓을 받으려고 도메인에 끊임없이 로그온합니다. 그 밖에 흔한 잡음은 `SYSTEM`(`S-1-5-18`), `LOCAL SERVICE`, `NETWORK SERVICE`, 대화형 로그인마다 생기는 `DWM-1`/`DWM-2`(데스크톱 창 관리자)와 `UMFD-0`/`UMFD-1`(글꼴 드라이버 호스트), 그리고 `ANONYMOUS LOGON` 네트워크 세션입니다.

사용자 활동을 헌팅할 때 쓸 만한 첫 필터는 이렇습니다. `TargetUserName`이 `$`로 끝나면 빼고, 잘 알려진 서비스 신원을 빼고, 유형 2, 3, 7, 9, 10, 11만 남깁니다. PowerShell로 로컬 Security 로그에 이 필터를 돌려 보면:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} |
  ForEach-Object {
    $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; User="$($d.TargetDomainName)\$($d.TargetUserName)";
                       Type=$d.LogonType; Auth=$d.AuthenticationPackageName; From=$d.IpAddress; LogonId=$d.TargetLogonId }
  } |
  Where-Object { $_.User -notmatch '\$$' -and $_.User -notmatch '\\(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON)$' -and $_.Type -in '2','3','7','9','10','11' } |
  Format-Table -AutoSize
```

한 줄씩:

- `Get-WinEvent -FilterHashtable @{...}` — 이벤트를 읽는데, 거르는 일을 이벤트 로그 서비스가 해 줘서 빠릅니다. `LogName='Security'`는 채널, `Id=4624`는 이벤트, `StartTime=(Get-Date).AddHours(-24)`는 최근 24시간.
- `ForEach-Object { ... }` — 이벤트 하나마다:
    - `$d = @{}`는 빈 사전(dictionary)을 만듭니다. `([xml]$_.ToXml()).Event.EventData.Data`는 이벤트를 XML로 바꾸고 `<Data Name="...">` 요소를 하나씩 돌고, `$d[$_.Name] = $_.'#text'`는 칸을 이름별로 저장합니다. 메시지 문장을 파싱하지 않고 칸을 이름으로 읽는 방식입니다.
    - `[pscustomobject]@{...}`는 깔끔한 한 줄을 만듭니다. 시각, `도메인\사용자`, 유형, 인증 패키지, 출발지 IP, 로그온 ID.
- `Where-Object { ... }` — 사용자가 `$`로 끝나지 않고(`'\$$'` = 끝에 글자 그대로의 `$`), 기본 신원이 아니고, 유형이 우리가 보는 것인 줄만 남깁니다.
- `Format-Table -AutoSize` — 표로 찍습니다.

`FS-02`에서 실제로 나오는 모습:

```
Time                  User               Type Auth     From         LogonId
----                  ----               ---- ----     ----         -------
20/11/2026 1:12:44 AM CORP\j.park        3    Kerberos 10.20.7.31   0x2a91c7f
20/11/2026 1:40:02 AM CORP\svc_scan      3    NTLM     10.20.9.200  0x2b02a11
20/11/2026 2:03:17 AM FS-02\backupadm    3    NTLM     10.20.7.88   0x2b11e40
20/11/2026 2:03:19 AM FS-02\backupadm    10   Negotiate 10.20.7.88  0x2b11f9d
```

읽어 보면: `j.park`가 공유를 연 건 평범합니다. 스캐너 주소에서 NTLM으로 온 `svc_scan`은 아마 취약점 스캐너일 테니 확인하고 허용 목록에 넣습니다. 흥미로운 건 마지막 두 줄입니다. `FS-02`의 **로컬** 계정(`FS-02\backupadm`)이 네트워크로 로그온한 뒤 **RDP**로 들어왔고, 출발지가 관리용 점프 호스트가 아니라 워크스테이션(`10.20.7.88`)입니다. 다음 단계: `FS-02`의 4688에서 `0x2b11f9d`를 찾아 무엇을 실행했는지 보고, 같은 로컬 계정을 다른 서버에서도 찾습니다.

**[주의]** 컴퓨터 계정을 거르는 건 *헌팅*용이지 *수집*용이 아닙니다. 실제 공격에서 컴퓨터 계정이 악용됩니다(컴퓨터 인증 중계, 위조 서비스 티켓, 리소스 기반 제한 위임 악용). 그리고 컴퓨터 계정이 그 컴퓨터가 아닌 IP에서 로그온했다면 그 자체로 강한 신호입니다. 이벤트는 남겨 두고, 쿼리에서 거르세요.

## Windows 4625: 로그온 실패 { #4625 }

### 언제 생기나 { #4625-when }

**4625 — "An account failed to log on"(계정이 로그온하지 못함)** 은 로그온을 거절한 컴퓨터가 씁니다. 콘솔에서 비밀번호를 잘못 친 경우, 틀린 비밀번호로 공유에 연결한 경우, RDP 시도, 저장된 비밀번호가 만료된 서비스 등. 칸은 4624와 거의 같고, *왜* 실패했는지 알려 주는 칸 세 개가 더 있습니다. `Status`, `SubStatus`, `FailureReason`. 실패를 기록하려면 *Logon* 하위 범주의 **Failure** 감사가 켜져 있어야 합니다. 켜져 있겠거니 하지 말고 감사 정책을 확인하세요.

공격자는 비밀번호를 추측할 때(**T1110.001**, Password Guessing), 비밀번호 하나를 여러 계정에 뿌릴 때(**T1110.003**, Password Spraying), 훔친 자격 증명이 이미 낡았을 때(**T1110.004**, Credential Stuffing) 4625를 만듭니다.

### 예시 { #4625-sample }

RDP가 열린 점프 서버 `JMP-01`에 인터넷에서 추측 시도가 들어옵니다.

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-0-0</Data>
  <Data Name="TargetUserSid">S-1-0-0</Data>
  <Data Name="TargetUserName">administrator</Data>
  <Data Name="TargetDomainName">JMP-01</Data>
  <Data Name="Status">0xc000006d</Data>
  <Data Name="FailureReason">%%2313</Data>
  <Data Name="SubStatus">0xc000006a</Data>
  <Data Name="LogonType">3</Data>
  <Data Name="LogonProcessName">NtLmSsp </Data>
  <Data Name="AuthenticationPackageName">NTLM</Data>
  <Data Name="WorkstationName">KALI</Data>
  <Data Name="LmPackageName">-</Data>
  <Data Name="KeyLength">0</Data>
  <Data Name="ProcessName">-</Data>
  <Data Name="IpAddress">203.0.113.77</Data>
  <Data Name="IpPort">0</Data>
</EventData>
```

- `TargetUserSid` `S-1-0-0` — "아무도 아님". 계정 세션까지 가지도 못했습니다.
- `TargetUserName` / `TargetDomainName` — *시도한* 이름(`administrator`), 그리고 로컬 계정을 노렸으니 컴퓨터 이름.
- `Status` `0xc000006d`와 `FailureReason` `%%2313`("Unknown user name or bad password") — 일반적인 이유입니다. 정확한 이유는 `SubStatus`가 알려 줍니다. `0xc000006a` = 사용자는 있는데 **비밀번호가 틀렸음**.
- `LogonType` `3`과 `NtLmSsp` / `NTLM` — NLA가 켜진 RDP는 이렇게 실패합니다. 데스크톱이 생기기 전에 네트워크 로그온으로 자격 증명을 확인하니까요. 그래서 RDP 추측 실패는 보통 10이 아니라 **3**으로 나옵니다.
- `WorkstationName` `KALI` — 클라이언트가 밝힌 이름. 단서가 될 때도 있지만 바꾸기 아주 쉽습니다.
- `IpAddress` `203.0.113.77` — 출발지. 한 주소에서 실패가 많으면 추측, 한두 주소에서 여러 계정에 계정마다 한 번씩 실패하면 스프레이입니다.

### Status와 SubStatus 코드 { #status-codes }

| 코드 | 뜻 | 무엇을 암시하나 |
| --- | --- | --- |
| `0xc0000064` | 사용자 이름이 없음 | 사용자 이름 추측이나 오타. 이름이 다양하면 계정 열거 |
| `0xc000006a` | 사용자는 맞고 비밀번호가 틀림 | 진짜 계정에 대한 비밀번호 추측 |
| `0xc0000234` | 계정 잠김 | 추측이 이미 잠금 기준을 넘겼다(DC의 4740 확인) |
| `0xc0000072` | 계정 비활성화됨 | 꺼 둔 계정을 누가 시도 — 낡은 훔친 자격 증명이거나 퇴사자 |
| `0xc0000193` | 계정 만료됨 | 비활성화와 비슷 |
| `0xc0000071` | 비밀번호 만료됨 | 옛 비밀번호를 가진 서비스인 경우가 많음 — 또는 옛 비밀번호를 가진 공격자 |
| `0xc0000224` | 다음 로그온 때 비밀번호를 바꿔야 함 | 대개 무해 |
| `0xc000006f` | 허용된 시간 밖의 로그온 | 정책에 걸림 |
| `0xc0000070` | 이 계정에 허용되지 않은 워크스테이션에서 로그온 | 제한된 관리자 계정을 다른 곳에서 시도 — 흥미로움 |
| `0xc000015b` | 그 로그온 유형이 허용되지 않음(예: "RDP 로그온 거부") | 정책이 막은 방식으로 계정을 시도 — 관리자·서비스 계정이라면 아주 흥미로움 |
| `0xc0000133` | 시계 차이가 너무 큼 | 시간 동기화 문제, 대개 Kerberos |

**[보충] 도메인 계정 실패가 함께 남는 곳.** 도메인 계정이면 도메인 컨트롤러도 자기 관점에서 기록합니다. **4771**(Kerberos 사전 인증 실패 — 실패 코드 `0x18` = 비밀번호 틀림), **4776**(NTLM 자격 증명 확인, 오류 코드 포함). 여러 호스트를 노린 스프레이는 모든 시도가 결국 DC로 모이니까 DC에서 보기가 가장 쉬운 경우가 많습니다. Kerberos 이벤트는 이 섹션의 뒤 페이지에서 다룹니다.

## Windows 4648: 명시적 자격 증명으로 로그온 { #4648 }

### 무엇인가 { #4648-what }

Linux 사용자라면 `sudo`와 `su`를 압니다. "이걸 다른 사람으로 실행해 줘." Windows에도 같은 것이 있습니다. `runas`, "다른 사용자로 실행", `net use \\server\share /user:...`, `-u`를 쓴 PsExec, 저장된 RDP 자격 증명, 그리고 사용자 이름과 비밀번호를 넘겨 프로세스를 띄우거나 서버에 연결하는 API 호출. 어떤 프로세스가 **로그온한 사용자의 것이 아닌 자격 증명**을 쓸 때마다 Windows는 **4648 — "A logon was attempted using explicit credentials"(명시적 자격 증명으로 로그온 시도)** 를 씁니다.

4624와 결정적으로 다른 점은, 4648은 대상이 아니라 자격 증명을 *입력하거나 주입한* **출발지** 컴퓨터에 남는다는 것입니다. 그래서 "`WS-114`에 남은, `FS-02`를 가리키는 4648" + "`FS-02`에 남은, `WS-114` IP에서 온 유형 3 4624"를 짝지으면 한 번의 이동을 양쪽 끝에서 이어 붙일 수 있습니다.

### 예시 { #4648-sample }

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="SubjectUserName">j.park</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x1c3e9a0</Data>
  <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
  <Data Name="TargetUserName">adm.lee</Data>
  <Data Name="TargetDomainName">CORP</Data>
  <Data Name="TargetLogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
  <Data Name="TargetServerName">FS-02.corp.example</Data>
  <Data Name="TargetInfo">FS-02.corp.example</Data>
  <Data Name="ProcessId">0x1f24</Data>
  <Data Name="ProcessName">C:\Windows\System32\net.exe</Data>
  <Data Name="IpAddress">-</Data>
  <Data Name="IpPort">-</Data>
</EventData>
```

- `SubjectUserName` `j.park` / `SubjectLogonId` — **누가** 했나. 명령을 실행한 세션의 사용자(그리고 세션. 그래서 `net.exe`를 띄운 4688을 찾을 수 있습니다).
- `TargetUserName` / `TargetDomainName` `CORP\adm.lee` — **어느 계정의 자격 증명을 썼나**(쉬운 보기에서 "Account Whose Credentials Were Used").
- `TargetServerName` / `TargetInfo` — **어디에** 썼나. 여기서는 파일 서버. 로컬 `runas`라면 `localhost`.
- `ProcessName` — **무엇이** 썼나. `net.exe`(`/user:`를 붙인 `net use`). 그 밖에 흔한 값은 `runas.exe`, `mstsc.exe`(RDP 클라이언트), `svchost.exe`(예약 작업, 서비스), `lsass.exe`, `consent.exe`(UAC 자격 증명 창). 스크립트 호스트나 모르는 실행 파일이 여기 나오면 수상합니다.

### 공격자를 잡는 방법 { #4648-use }

공격자가 진의 노트북 `WS-114`에 백도어를 심었고, 서버 관리자 `adm.lee`의 비밀번호도 훔쳤다고 해 봅시다. 진의 세션으로는 재무 공유 폴더를 못 읽습니다. 그래서 `runas`나 `net use /user:CORP\adm.lee`로 `adm.lee`가 "됩니다". 위의 4648이 그 결과입니다. 진의 세션이 관리자 자격 증명을 서버에 쓴 거죠. `adm.lee`는 관리용 점프 호스트에서만 써야 한다는 걸 안다면, 이건 바로 경보로 만들 수 있는 이상 상황입니다. *Subject 계정 ≠ Target 계정, Target 계정이 특권 계정, 출발지가 관리용 호스트가 아님.*

ATT&CK으로 보면: 훔친 자격 증명 사용은 **T1078**(Valid Accounts), `runas`로 다른 사용자 프로세스 만들기는 **T1134.002**(Access Token Manipulation: Create Process with Token), 서버로 넘어가는 것은 **T1021.002** 같은 옆으로 이동입니다. 같은 컴퓨터에서 4648 옆에 **유형 9**(`seclogo`) 4624가 있다면, `runas /netonly` — 그리고 많은 pass-the-hash 도구 — 가 남기는 모양입니다.

**[주의]** 4648은 알려진 것보다 시끄럽습니다. 관리자가 자격 증명을 치는 UAC 창, 예약 작업, 일부 백업·관리 에이전트, 저장된 자격 증명을 쓰는 RDP 클라이언트 모두 이 이벤트를 만듭니다. 호스트 역할별로 정상적인 `ProcessName` + `TargetUserName` 짝을 기준선으로 잡고, 나머지에 경보를 거세요.

## Linux 로그인 { #linux-logins }

### 로그인 하나, 여러 줄 { #linux-multiline }

Linux 로그인은 사람이 읽기는 쉽고 SIEM이 파싱하기는 어렵습니다. 이벤트 ID도 정해진 형식도 없습니다. 로그인은 자유 문장 syslog 메시지로 남고, SSH 로그인 하나가 부분 정보를 담은 **여러 줄**로 나뉘어 시스템의 다른 모든 인증 메시지와 섞입니다. Debian/Ubuntu는 **`/var/log/auth.log`**, Red Hat 계열은 **`/var/log/secure`**, 저널만 쓰는 시스템(rsyslog 없는 Debian 12 이후 등)은 **저널**에만 있습니다. [Linux 로그 파일과 저널](../linux-logging/log-files-journal.md) 참고.

`web-01`에 SSH 키로 로그인할 때:

```
Nov 20 03:02:11 web-01 sshd[4590]: Connection from 198.51.100.61 port 57356 on 10.20.30.41 port 22 rdomain ""
Nov 20 03:02:11 web-01 sshd[4590]: Postponed publickey for deploy from 198.51.100.61 port 57356 ssh2 [preauth]
Nov 20 03:02:11 web-01 sshd[4590]: Accepted publickey for deploy from 198.51.100.61 port 57356 ssh2: ED25519 SHA256:kq3V0bXa1nYv7k0Lr2Wc9mT4Jt8sQ1eZpHfUo6dNgAs
Nov 20 03:02:11 web-01 sshd[4590]: pam_unix(sshd:session): session opened for user deploy(uid=1003) by deploy(uid=0)
Nov 20 03:02:11 web-01 systemd-logind[612]: New session 57 of user deploy.
Nov 20 03:02:11 web-01 sshd[4590]: Starting session: shell on pts/0 for deploy from 198.51.100.61 port 57356 id 0
```

한 줄씩:

- `sshd[4590]: Connection from 198.51.100.61 port 57356 on 10.20.30.41 port 22` — TCP 연결이 들어왔습니다(`VERBOSE` 같은 높은 `LogLevel`일 때 보임). 클라이언트 주소와 포트, 이어서 서버 자기 주소와 포트. **`[4590]`이 PID**이고, 뒤따르는 모든 줄을 묶어 주는 실입니다.
- `Postponed publickey for deploy ... [preauth]` — 클라이언트가 공개 키를 내밀었고, 서버가 개인 키를 가졌는지 증명하라고 했습니다. `[preauth]` = 아직 인증 전.
- `Accepted publickey for deploy from 198.51.100.61 ... ED25519 SHA256:kq3V...` — **인증 성공.** 방법(`publickey`, 또는 `password`, `keyboard-interactive`), 사용자, 출발지, 그리고 **키 지문(fingerprint)**. 이 한 줄에 이야기 대부분이 들어 있습니다. 지문이 *어느* 키를 썼는지 알려 주니 `~deploy/.ssh/authorized_keys`와 맞춰 볼 수 있습니다(거기 모르는 키가 있으면 지속성, **T1098.004**).
- `pam_unix(sshd:session): session opened for user deploy(uid=1003)` — PAM(Pluggable Authentication Modules, 대부분의 Linux 프로그램이 함께 쓰는 인증 층)이 세션을 열었습니다. PAM 줄은 프로그램이 `sshd`든 `sudo`, `su`, `cron`, 디스플레이 관리자든 모양이 같고, 프로그램은 괄호 안(`sshd:session`)에 나옵니다.
- `systemd-logind[612]: New session 57 of user deploy.` — 로그인 관리자가 세션 57을 등록했습니다. 프로그램도 PID도 다르니, 여기서는 시각과 사용자로 맞춰야 합니다.
- `Starting session: shell on pts/0 for deploy ...` — 가상 터미널 `pts/0`에 셸이 떴습니다. 로그아웃하면 `Disconnected from user deploy ...`와 `session closed for user deploy`가 나옵니다.

Linux 원격 로그인 성공도 Windows와 같은 ATT&CK 기법에 해당합니다. **T1078**(Valid Accounts), 그리고 옆으로 이동 통로로서의 SSH는 **T1021.004**.

로그인 하나의 줄을 모두 모으려면 PID로 찾습니다.

```
grep 'sshd\[4590\]' /var/log/auth.log
journalctl _PID=4590
```

- `grep 'sshd\[4590\]'` — 역슬래시가 `[`와 `]`를 글자 그대로 만들어서, 그 sshd 프로세스의 줄만 맞춥니다.
- `journalctl _PID=4590` — 저널에서 같은 일. `_PID`는 journald가 붙이는 신뢰 칸이라 보낸 쪽이 위조할 수 없습니다.

**[변경됨]** OpenSSH 9.8부터 접속별 처리가 `sshd-session`이라는 별도 프로그램으로 옮겨졌습니다. 그 버전을 쓰는 배포판에서는 이 줄들 상당수가 `sshd[4590]:`이 아니라 `sshd-session[4590]:` 태그로 나옵니다. 글자 그대로 `sshd[`에 맞추는 파서와 경보는 둘 다 잡도록 고쳐야 합니다.

### 로컬·데스크톱 로그인 { #linux-local }

콘솔이나 그래픽 로그인 화면에서 하는 로그인은 다른 프로그램이 쓰고 모양도 다릅니다. 텍스트 콘솔은 `login[...]`, 데스크톱은 `gdm-password]`, `lightdm`, `sddm`이고, 모두 PAM을 거칩니다.

```
Nov 20 08:15:42 lab-ws3 gdm-password]: pam_unix(gdm-password:session): session opened for user m.choi(uid=1001) by (uid=0)
```

PAM 서비스 이름(`gdm-password`)이 들어온 문을, `uid=1001`이 계정을 알려 줍니다. 네트워크가 없으니 출발지 IP도 없습니다.

## Linux 로그인 실패 { #linux-failures }

Windows에는 실패용 ID(4625)가 하나 있습니다. Linux에는 없습니다. 그래서 로그인 프로그램마다, 실패 종류마다 **모양**을 알고 전부 찾아야 합니다.

```
Nov 20 03:10:02 web-01 sshd[4711]: Invalid user oracle from 203.0.113.45 port 40122
Nov 20 03:10:04 web-01 sshd[4711]: Failed password for invalid user oracle from 203.0.113.45 port 40122 ssh2
Nov 20 03:10:09 web-01 sshd[4715]: Failed password for root from 203.0.113.45 port 40130 ssh2
Nov 20 03:10:15 web-01 sshd[4715]: error: maximum authentication attempts exceeded for root from 203.0.113.45 port 40130 ssh2 [preauth]
Nov 20 03:12:30 web-01 sshd[4730]: Connection closed by authenticating user deploy 203.0.113.45 port 40166 [preauth]
Nov 20 08:19:19 lab-ws3 lightdm: pam_unix(lightdm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=m.choi
Nov 20 09:01:55 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1003 euid=0 tty=/dev/pts/0 ruser=deploy rhost=  user=deploy
Nov 20 09:02:03 web-01 sudo:   deploy : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
```

- `Invalid user oracle from 203.0.113.45` — **틀린 사용자 이름**: 그런 계정이 없습니다. 한 IP에서 흔한 서비스 이름 목록(`oracle`, `test`, `pi`, `ubuntu`)이 나오면 자동 스캔입니다.
- `Failed password for invalid user oracle` — 없는 계정에 이어서 한 비밀번호 시도.
- `Failed password for root from 203.0.113.45` — SSH로 **진짜 계정에 틀린 비밀번호**. 빠르게 반복되면 추측(**T1110.001**)입니다.
- `maximum authentication attempts exceeded for root` — 연결 하나에서 `MaxAuthTries`에 걸렸습니다.
- `Connection closed by authenticating user deploy ... [preauth]` — 진짜 사용자의 키나 비밀번호 시도가 성공 전에 끊겼습니다. 틀린 키를 내미는 클라이언트인 경우가 많고, 대량이면 키를 뿌려 보는 도구입니다.
- `lightdm: pam_unix(lightdm:auth): authentication failure; ... tty=:0 ... user=m.choi` — **데스크톱** 로그인 화면에서 비밀번호가 틀렸습니다. `tty=:0`은 로컬 그래픽 화면이고, 네트워크로 연결한 사람이 없으니 `rhost=`가 비어 있습니다.
- `sudo: pam_unix(sudo:auth): authentication failure; ... user=deploy`와 `3 incorrect password attempts` — `deploy`의 세션에서 누군가 sudo 비밀번호를 세 번 틀렸습니다. 웹 서버 침해 뒤 침입자가 `sudo`에 비밀번호를 넣어 보면 딱 이렇게 보입니다(권한 상승 시도).

**절대** 기록되지 않는 것도 보세요. 비밀번호 자체입니다. 원격 실패에는 출발지 IP와 시도한 사용자 이름이, 로컬 실패에는 터미널과 사용자가 남습니다.

**[주의] 사용자 이름 칸에 들어간 비밀번호.** 사용자가 *사용자 이름* 칸에 비밀번호를 치는 일이 가끔 있습니다. 그러면 로그에 `Invalid user <그 사람 비밀번호> from ...`이 평문으로 남습니다. 인증 로그는 민감한 데이터로 다루세요. SIEM에서 읽을 수 있는 사람을 제한하고, 검색하다 이런 걸 만날 수 있다고 생각해 두세요.

출발지 주소별로 SSH 실패를 빠르게 세 보기:

```
grep -hE 'Failed password|Invalid user' /var/log/auth.log /var/log/auth.log.1 |
  grep -oE 'from [0-9a-f.:]+' | sort | uniq -c | sort -rn | head -5
```

- `grep -hE 'Failed password|Invalid user' ...` — 지금 로그와 직전에 순환된 로그에서 두 가지 실패 모양을 모두 찾습니다(`-E`는 "또는"을 뜻하는 `|`를 쓰게 해 주고, `-h`는 파일 이름을 숨깁니다).
- `grep -oE 'from [0-9a-f.:]+'` — `from <주소>` 부분만 찍습니다(`-o`). IPv4든 IPv6든.
- `sort | uniq -c` — 같은 주소끼리 묶어서 셉니다.
- `sort -rn | head -5` — 많은 순서로, 위 다섯 개.

출력:

```
    412 from 203.0.113.45
     37 from 198.51.100.200
      3 from 10.20.30.12
```

`203.0.113.45`는 누가 봐도 추측 공격입니다. 세 번 실패한 내부 주소 `10.20.30.12`는 아마 사람이 오타를 낸 것이겠지만, 로그에서 바로 다음 줄이 같은 주소의 `Accepted`라면 계속 읽어 봐야 합니다. 저널에서는 `journalctl -u ssh --since today -g 'Failed password|Invalid user'`로 같은 일을 합니다(`-g`는 메시지를 grep합니다. Red Hat 계열은 유닛 이름이 `sshd`).

## Windows와 Linux 나란히 보기 { #comparison }

| | Windows | Linux |
| --- | --- | --- |
| 성공 | 4624(Security 채널) | `Accepted ... for <user> from <ip>`(sshd), `session opened`(PAM) |
| 실패 | Status/SubStatus가 있는 4625 | `Invalid user`, `Failed password`, `authentication failure` 등 여러 가지 |
| 로그온 종류 | `LogonType` 칸 | 어느 프로그램이 썼나(`sshd`, `login`, `gdm`, `sudo`)와 PAM 서비스 이름 |
| 출발지 | `IpAddress`, `WorkstationName` | `from <ip> port <n>`, `rhost=` |
| 세션 연결 | `TargetLogonId` | PID, `systemd-logind` 세션 번호, auditd `ses`/`auid` |
| 명시적 자격 증명 | 4648 | `sudo` / `su` 줄 |
| 위치 | 대상의 Security 로그 | 대상의 `auth.log` / `secure` / 저널 |

## SOC에서 써먹기 { #soc-use }

- 감사 정책 확인: 모든 Windows 시스템에서 *Logon* 성공 **과** 실패, *Special Logon*(4672), *Logoff*. GPO에 뭐라고 적혔는지가 아니라 실제로 무엇이 들어오는지 확인합니다.
- Security 로그를 **도메인 컨트롤러, 서버, 워크스테이션** 모두에서 수집합니다. 4648은 워크스테이션에 있습니다.
- 정규화: `user`, `domain`, `logon_type`, `src_ip`, `auth_package`, `logon_id`, `host`. 이름과 SID를 둘 다 저장합니다.
- 헌팅·경보 대상: 워크스테이션끼리의 RDP(유형 10); 로컬 계정(`TargetDomainName` = 호스트 이름)이 네트워크로 여러 호스트에 로그온; 알려진 관리 도구 밖에서 나온 `seclogo` 유형 9; Kerberos여야 할 곳의 NTLM; 일반 사용자 세션이 특권 계정을 쓴 4648; `0xc000015b`, `0xc0000070`, `0xc0000072` 실패; 한 출발지에서 여러 계정에 걸친 많은 4625/4771(스프레이).
- Linux: 쓰고 있는 모든 로그인 프로그램의 `Accepted`/`Failed`/`Invalid user`/`authentication failure`를 파싱하고, `sshd-session`을 처리하고, 키 지문을 남깁니다.
- 로그인에서 늘 그 세션이 한 일로 넘어갑니다. Windows는 로그온 ID, Linux는 PID/세션/`auid`.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    이벤트 4624, 4625, 4648, 4672, 4634/4647과 그 칸들, 로그온 유형 번호는 바뀌지 않았고 여전히 Windows 신원 조사의 기초입니다. `sshd`와 PAM이 남기는 Linux 로그인 줄도 설명한 모습 그대로이고, 여전히 이벤트 ID가 없습니다. 로그온을 찾고, 유형과 출발지를 읽고, 세션 ID를 따라가는 흐름은 SIEM이든 EDR 콘솔이든 타임라인 도구든 지금 분석가가 하는 그대로입니다.

!!! info "[변경됨] 바뀐 점"
    - **신원이 일부 클라우드로 옮겨 갔습니다.** 하이브리드·클라우드 중심 조직에서는 많은 로그인이 Windows Security 로그를 아예 거치지 않습니다. Microsoft Entra ID 로그인 로그(대화형·비대화형), ID 공급자(IdP) 로그, VPN/SSO 로그가 이제 4624만큼 중요합니다. 신원 위협 탐지 제품(예: Microsoft Defender for Identity)이 DC 인증 트래픽과 이벤트를 대신 분석해 주지만, 바탕이 되는 이벤트는 이 페이지에 나온 그것들입니다.
    - **NTLM이 은퇴하는 중입니다.** NTLMv1은 Windows 11 24H2와 Windows Server 2025에서 제거됐고, 이 버전들에 더 자세한 NTLM 감사가 들어갔으며, Microsoft는 앞으로의 릴리스에서 NTLM을 기본으로 끄는 단계별 계획을 발표했습니다(2026년 말 기준 정확한 날짜는 없음). `AuthenticationPackageName = NTLM`은 점점 드물어질 것이고, 그래서 나타났을 때 더 의미가 커집니다.
    - **4624 칸이 늘었습니다.** Windows 10 / Server 2016부터 `ElevatedToken`, `TargetLinkedLogonId`, `VirtualAccount`, `RestrictedAdminMode`, `ImpersonationLevel`이 들어 있습니다. 옛 안내서와 파서는 이걸 놓칠 수 있습니다.
    - **OpenSSH 9.8의 `sshd-session`** 과 **저널만 쓰는 배포판** 때문에 Linux 로그인 기록이 새 태그를 달거나 저널에만 있을 수 있습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **유형 11을 "키보드 앞의 도메인 사용자"로 읽지 마세요**(그건 유형 2). 유형 2를 물리적 접근의 증거로 읽지도 마세요.
    - **수집 단계에서 컴퓨터 계정 로그온을 버리지 마세요.** 쿼리에서 거르세요. 컴퓨터 계정 악용은 실제로 일어납니다.
    - **`WorkstationName`을 믿지 마세요.** 클라이언트가 정합니다. `IpAddress`를 우선하고 DHCP·자산 정보와 맞춰 보세요.
    - **RDP 무차별 대입이 유형 10으로 보일 거라 기대하지 마세요.** NLA가 있으면 유형 3으로 실패합니다.
    - **4648을 대상 컴퓨터에서 찾지 마세요.** 자격 증명을 쓴 출발지 컴퓨터에 있습니다.
    - **실패 감사가 켜져 있다고 가정하지 마세요.** 시스템마다 4625가 실제로 들어오는지 확인하세요.
    - **Linux 인증 로그를 민감한 데이터로 다루세요.** 사용자 이름 칸에 친 비밀번호가 평문으로 남습니다.

## 확인 문제 { #quiz }

### 문제 1

파일 서버 `FS-02`에서 `TargetUserName` = `Administrator`, `TargetDomainName` = `WS-207`, `LogonType` = `3`, `AuthenticationPackageName` = `NTLM`, `IpAddress` = `10.20.7.88`인 4624를 봤습니다. 5분 뒤 다른 서버 두 대에서도 같은 모양이 나옵니다. 각 칸이 무엇을 알려 주고, 어떤 가설을 세우겠습니까?

??? success "정답과 해설"
    - `TargetUserName` `Administrator`와 `TargetDomainName` `WS-207` — `WS-207`이라는 워크스테이션의 **로컬** Administrator 계정입니다(로컬 계정의 "도메인"은 컴퓨터 이름). 그런데 다른 컴퓨터인 `FS-02`에 로그온했습니다. `FS-02`에도 **같은 비밀번호나 해시**를 가진 로컬 `Administrator`가 있어야만 가능한 일이니, 로컬 관리자 자격 증명을 돌려 쓰고 있다는 신호입니다.
    - `LogonType` `3` — 네트워크 로그온(공유, PsExec식 서비스, WMI). 옆으로 이동의 대표 유형입니다.
    - `NTLM` — 로컬 계정은 컴퓨터를 넘어 Kerberos를 못 쓰니 여기서 NTLM은 예상된 것이고, 재사용된 해시로 하는 NTLM이 바로 pass-the-hash가 기대는 방식입니다.
    - `IpAddress` `10.20.7.88` — 출발지. 어느 호스트인지 확인하세요(`WS-207`이 아닐 수도 있습니다. 도메인 칸은 출발지가 아니라 계정의 소속을 말해 줍니다).

    **가설:** 로컬 Administrator 해시/비밀번호를 가진 누군가가 서버로 옆으로 이동 중입니다(**T1550.002** Pass the Hash / **T1078.003** Local Accounts, **T1021.002**를 통해). 다음: `10.20.7.88`에서 4648과 유형 9 로그온, 그 시각 전후의 프로세스 생성과 EDR 경보를 보고, 서버들에서는 각 `TargetLogonId`를 4688/7045로 따라갑니다. 복구 조치로 로컬 관리자 비밀번호를 컴퓨터마다 다르게(Windows LAPS) 하고, 로컬 계정의 네트워크 로그온을 막습니다.

### 문제 2

스프레이 경보가 울립니다. 10분 동안 `198.51.100.23`에서 실패한 로그온 120개, 서로 다른 사용자 120명에게 한 번씩입니다. 4625 대부분은 SubStatus `0xc000006a`, 몇 개는 `0xc0000064`, 한 사용자는 `0xc0000234`입니다. 그다음 같은 IP에서 `CORP\h.yoon`의 4624가 나옵니다. 코드를 해석하고, 가장 먼저 무엇을 하겠습니까?

??? success "정답과 해설"
    - 한 출발지에서 여러 사용자에게 한 번씩 = **비밀번호 스프레이**(**T1110.003**). 잠금 기준 아래로 머물려는 방식입니다.
    - `0xc000006a` — 사용자는 있고 비밀번호가 틀림. 공격자가 **진짜** 사용자 이름 목록을 갖고 있습니다.
    - `0xc0000064` — 없는 사용자. 목록의 이름 몇 개가 틀렸거나 낡았습니다.
    - `0xc0000234` — 그 계정은 잠겼습니다(DC의 4740도 확인).
    - 같은 IP에서 나온 `h.yoon`의 4624가 결정적입니다. 계정 하나에 **스프레이가 성공했습니다.**

    **가장 먼저:** `h.yoon`을 탈취된 계정으로 다룹니다. 비밀번호를 재설정하고, 세션과 토큰을 끊고(동기화된 계정이면 클라우드 세션까지), MFA를 확인합니다. 그다음 그 4624의 `LogonType`과 `TargetLogonId`로 세션을 따라갑니다(4672, 4688, 4648, 파일 접근). 출발지를 차단하고, 모든 로그(VPN, Entra ID 로그인, DC의 4771/4776)에서 같은 IP와 다른 성공을 찾습니다.

### 문제 3

Ubuntu 서버 `web-01`에서 다음 줄을 찾았습니다. 각 줄을 설명하고, 무슨 일이 있었는지 판단하고, 다음에 무엇을 확인할지 말하세요.

```
Nov 20 04:41:10 web-01 sshd[6120]: Accepted password for www-data from 203.0.113.45 port 41890 ssh2
Nov 20 04:41:10 web-01 sshd[6120]: pam_unix(sshd:session): session opened for user www-data(uid=33) by www-data(uid=0)
Nov 20 04:43:57 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=www-data uid=33 euid=0 tty=/dev/pts/2 ruser=www-data rhost=  user=www-data
Nov 20 04:44:05 web-01 sudo:   www-data : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash
```

??? success "정답과 해설"
    - 1번 줄 — 외부 주소에서 **`www-data`로 SSH 비밀번호 로그인 성공.** `www-data`는 웹 서버의 서비스 계정입니다. 대화형으로 로그인하면 안 되고, 보통은 쓸 수 있는 비밀번호나 셸도 없습니다. 누군가 비밀번호를 설정했거나(또는 잘못된 설정을 악용해) 로그인했습니다(**T1078**, **T1021.004**).
    - 2번 줄 — PAM이 uid 33(`www-data`)의 세션을 열었습니다. PID `6120`이 1번 줄과 묶어 줍니다.
    - 3번 줄 — 그 세션(`tty=/dev/pts/2`)에서 `www-data`의 `sudo` 인증이 실패했습니다.
    - 4번 줄 — `/var/www/html`에서 `/bin/bash`를 **root**로 실행하려고 비밀번호를 세 번 틀렸습니다. 들어온 뒤 권한을 올리려는 시도입니다.

    **무슨 일:** 아마 웹 침해(웹셸)로 `www-data`에 비밀번호나 셸을 준 뒤 SSH로 직접 들어오고, root가 되려 한 것입니다. **다음 확인:** `/etc/passwd`와 `/etc/shadow`에서 `www-data`의 셸과 비밀번호 변경(그리고 인증·감사 로그에서 `passwd`/`chpasswd`/`usermod`); `~www-data/.ssh/authorized_keys`; 04:41 이전 웹 접근 로그에서 웹셸; `203.0.113.45`의 모든 로그인(`grep`, `last -F`, 저널); 그 세션의 명령을 담은 auditd/EDR 기록; 다른 권한 상승 시도(SUID 악용, 커널 익스플로잇). 무엇보다 먼저 로그를 호스트 밖에 보존합니다.

## 관련 레퍼런스 { #related }

- [꼭 알아야 할 이벤트](index.md) — 이 섹션 개요
- [Windows 이벤트 구조와 채널](../windows-logging/event-structure-channels.md) — XML 읽는 법, 그리고 메시지 문장보다 칸이 나은 이유
- [Windows 이벤트 로그가 동작하는 방식](../windows-logging/how-event-logging-works.md) — 감사 정책과 Security 로그의 출처
- [Linux 로그 파일과 systemd 저널](../linux-logging/log-files-journal.md) — Linux 인증 줄이 저장되는 곳
- [Windows 이벤트 로그(EVTX)](../../../windows/event-logs.md)
- [Linux 인증과 셸 히스토리](../../../linux/auth-and-history.md)
- [자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) — pass-the-hash 자격 증명이 어디서 오는가
- [SMB](../other-protocols/smb.md)와 [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md) — 이 로그온들의 네트워크 쪽 모습
