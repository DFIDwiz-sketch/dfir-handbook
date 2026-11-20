---
title: "Kerberos 이벤트 — AS와 TGS의 동작, 4768 TGT 요청, 4769/4770 서비스 티켓, 4624에서 Kerberos 알아보기"
tags:
  - training
  - blue-team
  - windows
  - logging
  - kerberos
  - active-directory
---

# Kerberos 이벤트 — 4768, 4769/4770, 그리고 4624 속 Kerberos { #kerberos }

!!! abstract "이 페이지에서 다루는 것"
    Windows 도메인이 "당신이 누구인지"를 확인하는 기본 방식과, 그게 남기는 흔적입니다. Kerberos가 왜 필요한지와 등장인물 셋(클라이언트, 서비스, 그리고 도메인 컨트롤러에 있는 **키 배포 센터(Key Distribution Center, KDC)** — 그 안의 **인증 서비스(Authentication Service)** 와 **티켓 발급 서비스(Ticket Granting Service)**); 비밀번호에서 나온 키 → **티켓 발급 티켓(Ticket Granting Ticket, TGT)** → **서비스 티켓(Service Ticket)** → 마지막 로그온까지 Kerberos 로그온의 여섯 단계와, 단계마다 어느 컴퓨터의 어느 로그에 무엇이 남는지; **4768**(TGT 요청)을 결과 코드, 티켓 옵션, 암호화 유형, 사전 인증 유형까지 칸별로 읽기; 관련 이벤트 **4771**, **4772**; **4769**(서비스 티켓 요청)와 **4770**(갱신)을 칸별로 읽기, 시끄러운 `0x20` 실패 포함; 대상 서버의 **4624**에서 Kerberos였는지 NTLM이었는지 알아보는 법(`AuthenticationPackageName`, `LogonProcessName`, `LmPackageName`, `KeyLength`)과 `LogonGuid`로 DC 기록과 잇는 법; Kerberoasting, AS-REP 로스팅, 위조 티켓, 티켓 전달 공격이 이 이벤트들에서 어떻게 보이는지; 중요한 이벤트를 계속 익혀 나가는 법; SOC 점검 목록, 2026년 관점, 확인 문제.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 도메인, 호스트, 계정, SID, GUID, IP는 모두 설명용 가상 값입니다(`corp.example`, 문서용·사설 IP).

## 한눈에 보는 핵심 8가지 { #key-points }

1. **Kerberos**는 Active Directory 도메인의 기본 인증 프로토콜입니다. Windows는 쓸 수 있으면 언제나 Kerberos를 쓰고(도메인 계정이고, 도메인이 아는 이름으로 대상을 불렀을 때), 안 되면 **NTLM**으로 물러납니다.
2. 등장인물은 셋입니다. **클라이언트**(사용자 컴퓨터), **서비스**(파일 공유, 웹 앱, SQL 서버 등), 그리고 **KDC** — Windows에서는 모든 **도메인 컨트롤러**가 KDC입니다. KDC 안에는 서비스가 둘 있습니다. 누구인지 확인하고 **TGT**를 내주는 **인증 서비스(AS)**, 그리고 TGT를 받고 특정 서비스 하나에 쓸 **서비스 티켓**으로 바꿔 주는 **티켓 발급 서비스(TGS)** 입니다.
3. 로그온 한 번의 흔적이 여러 컴퓨터에 나뉘어 남습니다. DC에 **4768**(TGT), DC에 **4769**(서비스 티켓, 서비스마다 하나), 대상 서버에 **4624**(실제 로그온). 4770(갱신)은 드물고 4769와 비슷하게 생겼습니다.
4. DC 쪽 이벤트는 *Account Logon* 범주에서 나옵니다. *Audit Kerberos Authentication Service*(4768, 4771, 4772)와 *Audit Kerberos Service Ticket Operations*(4769, 4770, 4773). **도메인 컨트롤러에만** 남으니 **모든** DC에서 모아야 합니다.
5. **4768**은 "어느 계정이, 어느 IP에서 TGT를 달라고 했고, 됐나?"에 답합니다. `Result Code 0x0` = 성공, 다른 값은 찾아볼 수 있는 실패입니다(`0x6` 없는 사용자, `0x12` 계정 사용 안 함·잠김·만료). 비밀번호가 틀리면 보통 4768이 아니라 **4771**(`0x18`)이 남습니다.
6. **4769**에는 **어느 서비스인지**(`ServiceName`, 예: `FS-02$`)가 더해집니다. 여기서 잠시 뒤 그 서버의 4624로 넘어가세요. 쏟아지는 `0x20` 실패(만료된 티켓, 무해함)는 무시합니다.
7. 많은 공격이 **암호화 유형** 칸에서 드러납니다. `0x12`/`0x11` = AES(정상), `0x17` = RC4(옛날 방식 — 사용자 계정으로 도는 서비스에 대해 이게 보이면 **Kerberoasting**, T1558.003의 표시). 4768의 `Pre-Authentication Type 0` = 사전 인증 없음 — **AS-REP 로스팅**(T1558.004)의 전제 조건입니다.
8. 대상 서버 4624의 `AuthenticationPackageName`은 `Kerberos`, `NTLM`, `Negotiate` 중 하나입니다. Kerberos 로그온은 `LmPackageName` `-`, `KeyLength` `0`이고, NTLM은 `NTLM V1`/`NTLM V2`에 보통 `128`입니다. `Negotiate`는 "나머지 두 칸을 보고 누가 이겼는지 판단하라"는 뜻입니다.

## 왜 Kerberos이고, 왜 그 로그를 읽어야 하나 { #why }

큰 음악 축제를 떠올려 보세요. 무대마다, 바마다, 천막마다 여권을 보여 주지 않습니다. **정문에서 한 번만** 여권을 보여 주면, 정문 직원이 명단과 맞춰 보고 손목에 **팔찌**를 채워 줍니다. 이제 VIP 천막에 들어가고 싶으면, 작은 부스에 팔찌를 보여 주고 **그 천막 하나에만 쓸 수 있는, 오늘 밤만 유효한 종이 입장권**을 받습니다. 천막 경비는 여러분 여권을 한 번도 보지 않습니다. 그 입장권이 축제 본부 부스에서 찍어 낸 진짜이고 자기 천막용인지만 확인합니다.

이게 Kerberos입니다.

- 여권 = 여러분의 **비밀번호**(정확히는 비밀번호에서 만든 키)
- 정문 = DC의 **인증 서비스**
- 팔찌 = **티켓 발급 티켓(TGT)**
- 부스 = 역시 DC에 있는 **티켓 발급 서비스**
- 종이 입장권 = **서비스 티켓**
- 천막 경비 = **서비스**(예: 파일 서버)

기술적인 실제로 돌아오면, 도메인에는 여러분이 누구인지 알아야 하는 서비스가 수천 개 있습니다. 서비스마다 비밀번호(나 그 해시)를 보내면 비밀번호가 사방에 노출되고, 서버마다 매번 DC에 물어봐야 합니다. Kerberos는 둘 다 해결합니다. 비밀번호에서 나온 키는 DC를 상대로 **딱 한 번** 쓰이고, 그다음부터는 DC와 해당 서비스만 아는 키로 암호화된 티켓을 들고 다닙니다. 서비스는 **DC에 연락하지 않고도** 티켓을 확인할 수 있습니다.

SOC 입장에서 이 말은, 가장 중요한 질문인 "누가, 어디서, 무엇에 로그온했나"의 답이 **두 곳**에 있다는 뜻입니다. DC(누가 어느 IP에서 어떤 티켓을 달라고 했나)와 대상 서버(실제로 누가 로그온했나). 아이덴티티에 관한 분석가의 일상 업무 — 수상한 로그온, 털린 계정, 옆으로 이동 — 는 결국 이 이벤트들로 모입니다. 그리고 유명한 Active Directory 공격 다수(Kerberoasting, AS-REP 로스팅, 골든·실버 티켓, 티켓 전달 공격)는 **Kerberos 자체를 노리는** 공격입니다. 정상 Kerberos 이벤트가 어떻게 생겼는지 알아야만 이상한 걸 알아챌 수 있습니다.

공격자 쪽 이야기는 [자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md)와 [옆으로 이동, 수집, 유출](../endpoint-attacks/lateral-collection-exfil.md)에, 로그온 쪽은 [로그인 이벤트](logins.md)에 있습니다.

## 등장인물과 소품 { #cast }

| 누구 / 무엇 | 무엇인가 | 어디 있나 |
| --- | --- | --- |
| **클라이언트** | 사용자가 앉아 있는, 서비스에 닿고 싶은 장치 | 워크스테이션, 예: `WS-031` |
| **서비스** | 사용자가 최종적으로 원하는 것: SMB 공유, IIS 사이트, SQL 서버, Exchange 등. `cifs/FS-02.corp.example` 같은 **서비스 주체 이름(Service Principal Name, SPN)** 으로 구별 | 멤버 서버, 예: `FS-02` |
| **KDC** | 키 배포 센터. 도메인 **모든** 계정의 장기 키를 알고, AS와 TGS를 돌림 | 모든 도메인 컨트롤러(`kdc` 서비스, `lsass.exe`) |
| `krbtgt` **계정** | 도메인의 **모든 TGT**를 암호화하고 서명하는 키를 가진, 사용 안 함 상태의 특별한 계정. RID **502** | Active Directory |
| **장기 키(Long-term Key)** | 계정 비밀번호에서 만든 키(RC4에서는 NT 해시와 같고, AES에서는 계정 이름을 소금(salt)으로 써서 만듦). 클라이언트와 KDC가 둘 다 가짐 — 비밀번호 자체는 절대 전송되지 않음 | 입력 후 클라이언트 메모리; DC의 AD 데이터베이스 |
| **TGT** | 이미 인증했다는 증명. `krbtgt` 키로 암호화돼서 DC만 읽을 수 있음. 기본 수명 **10시간**, 최대 **7일**까지 갱신 가능 | 클라이언트 메모리(`lsass.exe` 안) |
| **서비스 티켓** | 서비스 **하나**를 위한 증명. **그 서비스 계정의** 키로 암호화돼서 그 서비스(와 DC)만 읽을 수 있음 | 클라이언트 메모리, 그다음 서비스에 건네짐 |

[보충] 서비스 티켓은 **그 서비스를 실행하는 계정**의 키로 암호화됩니다. 대부분의 서비스는 **컴퓨터 계정**(`FS-02$`)으로 도는데, 컴퓨터 계정 비밀번호는 길고 무작위이며 30일마다 바뀝니다. 그런데 서비스가 SPN이 등록된 **사용자 계정**(예: `svc_sql`)으로 돌면, 티켓은 사람이 정한 비밀번호에서 나온 키로 암호화됩니다. 바로 이 약점을 Kerberoasting이 노립니다(아래 참고).

## Kerberos를 한 단계씩 { #steps }

워크스테이션 `WS-031`(`10.20.7.31`)의 사용자 `j.park`이 아침에 로그온하고, 그다음 `\\FS-02\projects`를 여는 상황입니다. 암호 수학은 단순화했습니다. 핵심은 무슨 일이 일어나고 단계마다 무엇이 기록되는지입니다.

```text
   WS-031 (client)                   DC-01 (KDC)                     FS-02 (service)
        |                         [AS]        [TGS]                         |
   1    |--- AS-REQ (user, time   -->|                                      |
        |    encrypted with key)     |                                      |
   2    |<-- AS-REP (TGT) -----------|      -> 4768 on DC-01                |
        |                                                                   |
   3    |--- TGS-REQ (TGT + "cifs/FS-02") -->|                              |
   4    |<-- TGS-REP (service ticket) -------|  -> 4769 on DC-01            |
        |                                                                   |
   5    |--- AP-REQ (service ticket) ---------------------------------------->|
   6    |<-- access granted -------------------------------------------------|  -> 4624 on FS-02
```

한 줄씩 보면:

1. **AS-REQ.** `j.park`이 로그온 화면에서 비밀번호를 치면, `WS-031`은 장기 키를 만들고 AS에 "나는 `j.park`이야, TGT 줘"라고 요청합니다. 키를 안다는 걸 증명하려고 **현재 시각**을 그 키로 암호화해서 같이 보냅니다. 이 증명을 **사전 인증(Pre-authentication)** 이라고 합니다. DC는 같은 키를 AD에 갖고 있으니 시각을 풀어 보고, 자기 시계와 **5분** 안쪽으로 맞는지 확인합니다.
2. **AS-REP.** 맞으면 AS가 **TGT**(`krbtgt` 키로 암호화 — 클라이언트는 읽지 못하고 들고만 다님)와 클라이언트가 읽을 수 있는 세션 키를 돌려줍니다. DC는 **4768**을 씁니다. 사전 인증이 실패하면(비밀번호 틀림) 대신 **4771**을 씁니다.
3. **TGS-REQ.** 나중에 `j.park`이 `\\FS-02\projects`를 엽니다. 클라이언트는 TGT와 원하는 서비스 이름 `cifs/FS-02.corp.example`을 TGS에 보냅니다.
4. **TGS-REP.** TGS는 TGT를 확인하고(DC만 풀 수 있음), 그 SPN이 어느 계정 것인지(`FS-02$`) 찾아서, `FS-02$`의 키로 암호화한 **서비스 티켓**을 돌려줍니다. DC는 **4769**를 씁니다. 주의: DC는 `j.park`이 그 공유를 읽어도 되는지 **확인하지 않습니다**. 그건 서버가 할 일입니다.
5. **AP-REQ.** 클라이언트는 SMB 세션을 맺으면서 서비스 티켓을 `FS-02`에 건넵니다.
6. **접근.** `FS-02`는 자기 키로 티켓을 풀고, 사용자가 누구이고 어떤 그룹에 속하는지(티켓 안의 **PAC**, 권한 속성 인증서(Privilege Attribute Certificate))를 읽고 로그온시킵니다. `FS-02`는 **4624**(로그온 유형 3, `AuthenticationPackageName` `Kerberos`)를 씁니다. 그 뒤로는 평범한 파일 권한이 무엇을 읽을 수 있는지 정합니다.

여기서 조사에 중요한 사실 두 가지가 나옵니다.

- **DC는 5, 6단계를 보지 못합니다.** 09:00에 쓴 서비스 티켓이 08:00에 발급됐을 수도 있습니다. 그리고 공격자가 서비스 티켓을 **위조**하면("실버 티켓"), 4769는 아예 없고 대상 서버의 4624만 남습니다.
- **대상 서버는 비밀번호를 보지 못합니다.** 그래서 `FS-02`의 4624는 비밀번호가 1분 전에 맞게 입력됐는지 9시간 전에 입력됐는지 알려 주지 못합니다. 그건 DC의 4768로 돌아가서 봐야 합니다.

[보충] 이벤트와의 일대일 대응: AS 교환 → 4768/4771/4772, TGS 교환 → 4769/4770/4773, 클라이언트-서버 교환 → 대상 서버의 4624/4625(로그오프는 4634). TGT는 로그온할 때(그리고 만료되면 다시) 요청하고, 서비스 티켓은 티켓 수명 동안 서비스마다 한 번 요청합니다. 여는 파일마다가 아닙니다.

## 켜는 법과 이벤트 찾기 { #config }

```text
C:\> auditpol /get /subcategory:"Kerberos Authentication Service","Kerberos Service Ticket Operations"
System audit policy
Category/Subcategory                      Setting
Account Logon
  Kerberos Service Ticket Operations      Success and Failure
  Kerberos Authentication Service         Success and Failure
```

한 줄씩 보면:

- `auditpol /get` — 지금 적용된 감사 정책을 보여 줍니다(관리자 권한으로, **도메인 컨트롤러에서** 실행).
- `/subcategory:"...","..."` — 이 두 하위 범주만 봅니다.
- `Account Logon` — 범주 이름입니다. "계정 로그온(Account Logon)"은 **자격 증명 확인**(도메인 계정이면 DC가 함)이고, "로그온/로그오프(Logon/Logoff)"는 접속당하는 컴퓨터에서 **세션을 만드는 것**(4624)입니다. 초보자가 자주 헷갈리는 부분입니다. DC의 4768과 서버의 4624는 서로 다른 컴퓨터에서 일어나는 서로 다른 일입니다.
- `Kerberos Service Ticket Operations` — 4769, 4770, 4773을 만듭니다.
- `Kerberos Authentication Service` — 4768, 4771, 4772를 만듭니다.

멤버 서버와 워크스테이션은 KDC가 아니라서 이 하위 범주가 아무것도 만들지 않습니다. 기본 DC 정책은 최소한 성공은 남깁니다. 공격 신호 상당수가 실패이니 실패도 켜져 있는지 확인하세요. 양이 많습니다. 사용자 1만 명 도메인이면 4769만 하루에 수백만 건일 수 있습니다. 저장 공간은 계획하되, 수집 단계에서 거르지 말고 쿼리에서 거르세요.

## 이벤트 4768: Kerberos 인증 티켓(TGT)이 요청됨 { #4768 }

### 이벤트 전체 { #4768-sample }

```xml
<System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
  <EventID>4768</EventID>
  <Task>14339</Task>
  <Keywords>0x8020000000000000</Keywords>
  <TimeCreated SystemTime="2026-11-20T22:02:11.4417263Z" />
  <Channel>Security</Channel>
  <Computer>DC-01.corp.example</Computer>
</System>
<EventData>
  <Data Name="TargetUserName">j.park</Data>
  <Data Name="TargetDomainName">CORP.EXAMPLE</Data>
  <Data Name="TargetSid">S-1-5-21-1004336348-1177238915-682003330-1187</Data>
  <Data Name="ServiceName">krbtgt</Data>
  <Data Name="ServiceSid">S-1-5-21-1004336348-1177238915-682003330-502</Data>
  <Data Name="TicketOptions">0x40810010</Data>
  <Data Name="Status">0x0</Data>
  <Data Name="TicketEncryptionType">0x12</Data>
  <Data Name="PreAuthType">2</Data>
  <Data Name="IpAddress">::ffff:10.20.7.31</Data>
  <Data Name="IpPort">51544</Data>
  <Data Name="CertIssuerName"></Data>
  <Data Name="CertSerialNumber"></Data>
  <Data Name="CertThumbprint"></Data>
</EventData>
```

이벤트 뷰어의 "일반" 탭은 같은 내용을 글로 보여 줍니다. *Account Information*(Account Name, Supplied Realm Name, User ID), *Service Information*(Service Name, Service ID), *Network Information*(Client Address, Client Port), *Additional Information*(Ticket Options, Result Code, Ticket Encryption Type, Pre-Authentication Type), *Certificate Information*. SIEM에서는 보통 위의 XML 이름으로 보입니다.

### 칸 하나씩 { #4768-fields }

- `EventID` `4768`, `Task` `14339` — "A Kerberos authentication ticket (TGT) was requested(Kerberos 인증 티켓(TGT)이 요청됨)", 하위 범주 *Kerberos Authentication Service*.
- `Keywords` `0x8020000000000000` — 감사 성공. `0x8010000000000000`(감사 실패)인 4768은 실패한 요청이니 `Status`를 읽으세요.
- `Computer` `DC-01.corp.example` — **답해 준 DC**입니다. 사용자 컴퓨터는 여기가 아니라 `IpAddress`에 있습니다.
- `TargetUserName` `j.park` — "Account Name": TGT를 달라고 한 계정. 이름이 `$`로 끝나면(`WS-031$`) **컴퓨터 계정**입니다. 컴퓨터도 부팅할 때와 주기적으로 TGT를 받기 때문에, 도메인의 4768 대부분은 컴퓨터입니다. 쿼리에서 거르고, 버리지는 마세요.
- `TargetDomainName` `CORP.EXAMPLE` — "Supplied Realm Name": 클라이언트가 요청한 Kerberos 영역(realm, 대문자로 쓴 DNS 도메인 이름). 클라이언트가 짧은 NetBIOS 이름으로 요청하면 `CORP`로 보일 수도 있습니다. 같은 도메인입니다.
- `TargetSid` — "User ID": 계정의 SID. 계정이 없어서 실패한 경우엔 비어 있거나 `S-1-0-0`(NULL SID)입니다.
- `ServiceName` `krbtgt`, `ServiceSid` `...-502` — 요청한 "서비스"가 **TGT 서비스 자체**이고, 그 뒤의 계정이 `krbtgt`(RID 502)입니다. 4768에서는 늘 `krbtgt`입니다. 이벤트가 "이건 TGT 요청이었다"고 말하는 방식입니다.
- `TicketOptions` `0x40810010` — 클라이언트가 요청한 32비트 깃발 묶음입니다. 비트 번호는 **왼쪽부터** 셉니다(비트 0 = 가장 높은 비트). `0x40810010` = 비트 1 **forwardable(전달 가능)**(`0x40000000`) + 비트 8 **renewable(갱신 가능)**(`0x00800000`) + 비트 15 **canonicalize(이름 정규화)**(`0x00010000`) + 비트 27 **renewable-ok**(`0x00000010`). 이 값이 평범한 Windows 클라이언트가 보내는 값이니 기준선이 됩니다. 한 호스트에서 낯선 값이 계속 나오면(예: **proxiable(대리 가능)** 이 더해진 `0x50800000`을 보내는 도구들) 한 번 더 볼 만합니다. 다만 이것만으로는 약한 신호입니다.
- `Status` `0x0` — "Result Code(결과 코드)". `0x0` = 성공. 자주 보는 실패:

| 코드 | 이름 | 보통 뜻하는 것 |
| --- | --- | --- |
| `0x6` | `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 없는 사용자 이름. 한 IP에서 많이 나오면 **사용자 이름 추측 / 열거**(T1087.002 / T1110) |
| `0x12` | `KDC_ERR_CLIENT_REVOKED` | 계정 사용 안 함, 만료, 또는 **잠김** — 스프레이가 잠금에 걸렸거나, 퇴사자 계정을 누가 쓰는 중 |
| `0x17` | `KDC_ERR_KEY_EXPIRED` | 비밀번호 만료 — 보통 무해 |
| `0x18` | `KDC_ERR_PREAUTH_FAILED` | 틀린 비밀번호. 보통 4768이 아니라 **4771**로 남음 |
| `0x25` | `KRB_AP_ERR_SKEW` | 클라이언트 시계가 5분 넘게 틀림 — 설정이 잘못된 장치, 또는 외부 컴퓨터에서 도는 도구 |
| `0xE` | `KDC_ERR_ETYPE_NOSUPP` | 공통 암호화 유형 없음 — 옛날 장치, 또는 AES 전용 정책인데 AES 키가 없는 계정 |

- `TicketEncryptionType` `0x12` — **발급된 티켓**의 암호화 방식입니다. `0x12` = AES256, `0x11` = AES128(둘 다 정상), `0x17` = RC4-HMAC(옛날 방식), `0x1`/`0x3` = DES(절대 나오면 안 됨, 최신 Windows에서 제거됨), `0xffffffff` = 실패(티켓 발급 안 됨). 요즘 도메인은 거의 전부 `0x12`입니다. 평소 `0x12`를 받던 워크스테이션에서 사용자 계정이 갑자기 `0x17` TGT를 받는다면, 도구가 일부러 RC4를 요청했을 수 있습니다. 예를 들어 "오버패스 더 해시(overpass-the-hash)"는 훔친 NT 해시(이게 곧 RC4 키)로 TGT를 받습니다(T1550.002).
- `PreAuthType` `2` — 클라이언트가 자기를 증명한 방법입니다. `2` = 비밀번호 키로 **암호화한 시각**(평범한 비밀번호 로그온). `15`/`16`/`17` = **PKINIT**, 인증서 기반(스마트 카드, Windows Hello for Business, 인증서) — 이때는 `Cert*` 칸이 채워집니다. `0` = **사전 인증 없음**: 계정에 *Do not require Kerberos preauthentication(Kerberos 사전 인증 필요 없음)* 이 켜져 있어서, DC가 요청한 누구에게나 암호화된 답을 내줬다는 뜻입니다. **AS-REP 로스팅**(T1558.004)이 찾는 게 바로 이 설정입니다. 실패에서는 `-`가 보입니다.
- `IpAddress` `::ffff:10.20.7.31` — "Client Address(클라이언트 주소)". 앞의 `::ffff:`는 **IPv4 매핑 IPv6 주소**입니다. DC가 IPv6와 IPv4를 같이 듣기 때문에 IPv4 클라이언트가 이렇게 적힙니다. 다른 로그와 합칠 때는 떼어 내세요. `::1`은 DC 자신이 요청했다는 뜻입니다.
- `IpPort` `51544` — 클라이언트의 출발 포트, 무작위 높은 번호입니다. 패킷 캡처와 맞춰 볼 때나 씁니다. DC 자신의 요청이면 `0`인 경우가 많습니다.
- `CertIssuerName`, `CertSerialNumber`, `CertThumbprint` — 인증서 로그온(PKINIT)일 때만 채워집니다. 아무도 모르는 인증서로 특권 계정이 로그온했다면 **AD 인증서 서비스 악용**의 전형적인 신호입니다([AD 인증서 서비스 악용](../../../adversary/adcs-abuse.md) 참고).

### 4768로 할 수 있는 것 { #4768-use }

- **"어떤 사용자가 어느 IP에 있었나?"** 사람 계정의 4768은 아침 로그온 때 계정과 IP를 묶어 줍니다. DHCP 로그로 그 IP의 호스트 이름을 알면 어느 컴퓨터를 썼는지 알게 됩니다. 반대 질문인 "09:00에 `10.20.7.31`에 누가 있었나?"에도 답이 됩니다.
- **낯선 곳에서 온 계정.** 서버 대역, 한 번도 안 쓰던 VPN 주소 풀, 또는 같은 시각 두 IP에서 `j.park`의 TGT 요청.
- **절대 인증하면 안 되는 계정.** 사용 안 함, 퇴사자, 비상용(break-glass), 미끼(honey) 계정. 목록을 만들고, 성공이든 실패든 4768이 나오면 경보를 거세요.
- **명명 규칙에 안 맞는 이름**(`administrator`, `admin`, `test`, `root`, 띄어쓰기가 든 이름)이 `0x6` 실패 4768에 보이면 누가 추측하고 있는 겁니다.
- **묶어서 세기.** 계정별, IP별, 결과 코드별로 세세요. 한 IP에서 여러 이름에 걸쳐 `0x6`과 `0x12`가 수백 건 = 스프레이나 열거. 한 계정이 IP 20개에서 요청 = 공유되거나 도난된 자격 증명일 수 있습니다.

[보충] **4771** "Kerberos pre-authentication failed(Kerberos 사전 인증 실패)"가 Kerberos에서 **비밀번호가 틀렸을 때**의 이벤트입니다. `Status` `0x18`과 계정, 클라이언트 IP가 있고, `PreAuthType` 칸도 있습니다. 한 IP에서 **여러 계정**에 한두 번씩 4771 `0x18`이 쌓이면 비밀번호 스프레이(T1110.003)입니다. DC에서는 모든 시도가 한곳에 보입니다. **4772**는 드문 TGT 발급 실패입니다. DC가 NTLM으로 확인할 때는 대신 **4776**이 남습니다. 둘 다 [로그인 이벤트](logins.md#4625)에서 소개했습니다.

## 이벤트 4769: Kerberos 서비스 티켓이 요청됨 { #4769 }

### 이벤트 전체 { #4769-sample }

4768 몇 초 뒤, `j.park`이 `FS-02`의 공유를 엽니다.

```xml
<System>
  <EventID>4769</EventID>
  <Task>14337</Task>
  <Keywords>0x8020000000000000</Keywords>
  <TimeCreated SystemTime="2026-11-20T22:02:15.0921884Z" />
  <Channel>Security</Channel>
  <Computer>DC-01.corp.example</Computer>
</System>
<EventData>
  <Data Name="TargetUserName">j.park@CORP.EXAMPLE</Data>
  <Data Name="TargetDomainName">CORP.EXAMPLE</Data>
  <Data Name="ServiceName">FS-02$</Data>
  <Data Name="ServiceSid">S-1-5-21-1004336348-1177238915-682003330-1310</Data>
  <Data Name="TicketOptions">0x40810000</Data>
  <Data Name="TicketEncryptionType">0x12</Data>
  <Data Name="IpAddress">::ffff:10.20.7.31</Data>
  <Data Name="IpPort">51551</Data>
  <Data Name="Status">0x0</Data>
  <Data Name="LogonGuid">{6c3e9f12-08ab-4d7e-b1d4-2f7a90c5e811}</Data>
  <Data Name="TransmittedServices">-</Data>
</EventData>
```

### 칸 하나씩 { #4769-fields }

- `EventID` `4769`, `Task` `14337` — "A Kerberos service ticket was requested(Kerberos 서비스 티켓이 요청됨)", 하위 범주 *Kerberos Service Ticket Operations*.
- `Computer` — 역시 티켓을 발급한 DC입니다.
- `TargetUserName` `j.park@CORP.EXAMPLE` — 티켓을 **받는** 계정입니다. 4768과 달리 `사용자@영역` 모양으로 적힙니다. 컴퓨터 계정은 `WS-031$@CORP.EXAMPLE`처럼 보입니다.
- `TargetDomainName` — 영역(realm).
- `ServiceName` `FS-02$` — 요청한 **서비스를 가진 계정**입니다. 여기서는 파일 서버의 컴퓨터 계정이니, 사용자가 `FS-02`(SMB든 컴퓨터 계정으로 도는 다른 서비스든)로 가려던 겁니다. Microsoft 문서상 이 칸은 선택 사항이라 가끔 비어 있을 수 있고, 믿을 만한 건 `ServiceSid`입니다. 알아봐야 할 모양 세 가지:
    - `$`로 끝남 → 컴퓨터(가장 흔하고 정상)
    - `krbtgt` → 클라이언트가 TGT로 **TGT 갱신**이나 다른 도메인 안내(referral)를 받는 중, 정상
    - `svc_sql` 같은 **사용자 계정** → 사용자 계정으로 도는 서비스. 그 자체는 정상이지만, Kerberoasting의 표적이 바로 이것들입니다.
- `ServiceSid` — 그 계정의 SID. 이벤트 뷰어는 할 수 있으면 `CORP\FS-02$` 같은 이름으로 바꿔 보여 줍니다.
- `TicketOptions` `0x40810000` — forwardable, renewable, canonicalize. 서비스 티켓에서 평범한 Windows 값입니다. (`0x60810010`이면 **forwarded(전달됨)** 와 renewable-ok가 더해진 것으로, 위임(delegation) 등으로 전달된 TGT로 요청했을 때 보입니다.)
- `TicketEncryptionType` `0x12` — **서비스 티켓**의 암호화로, **서비스 계정**이 무엇을 지원하느냐에 달려 있습니다. 코드표는 4768과 같습니다. **사용자 서비스 계정에 대해 `0x17`(RC4)이 보이면 Kerberoasting의 핵심 신호**입니다(아래 참고).
- `IpAddress` / `IpPort` — 클라이언트. `::ffff:` 규칙도 같습니다.
- `Status` `0x0` — "Failure Code(실패 코드)". `0x0` 성공. `0x20`(`KRB_AP_ERR_TKT_EXPIRED`)은 내민 TGT가 만료됐다는 뜻이고, Windows 클라이언트는 새로 받아 옵니다. Microsoft도 이 실패가 아주 많이 나오고 보안상 의미가 거의 없다고 말합니다. 대시보드에서 빼세요. 쓸모 있는 다른 코드: `0x7`(`KDC_ERR_S_PRINCIPAL_UNKNOWN`, 그런 SPN이 없음 — 오타, 낡은 설정, 또는 누가 **SPN을 훑는 중**), `0x1F`(무결성 검사 실패 — 깨지거나 **조작된 티켓**), `0xE`(공통 암호화 유형 없음).
- `LogonGuid` `{6c3e9f12-...}` — **대상 서버 4624**의 `LogonGuid`에도 똑같이 나오는 GUID입니다. 시각과 IP로 짐작하는 대신, DC 쪽 기록과 서버 쪽 기록을 정확히 잇는 방법입니다.
- `TransmittedServices` `-` — "Transited Services(거쳐 간 서비스)": **위임**(S4U / 제한된 위임)을 쓸 때만 채워지고, 사용자 대신 요청한 서비스들이 적힙니다. 여기 뜻밖의 값(웹 서버가 관리자 대신 DC 티켓을 요청)이 있으면 들여다볼 만합니다.

### 한 문장으로 읽기 { #4769-read }

"UTC 22:02:15에 `10.20.7.31`의 사용자 `j.park`이 `DC-01`에게 `FS-02$`가 돌리는 서비스의 티켓을 요청했고, 받았으며(`0x0`), 그 티켓은 AES256으로 암호화됐다." 다음 단계: `FS-02`에서 몇 초 안에 `TargetUserName` `j.park`, `IpAddress` `10.20.7.31`, 로그온 유형 3, `AuthenticationPackageName` `Kerberos`, 그리고 같은 `LogonGuid`를 가진 4624를 찾습니다.

### 이벤트 4770: Kerberos 서비스 티켓이 갱신됨 { #4770 }

**4770**은 클라이언트가 새 티켓을 달라는 대신 *renewable* 깃발이 켜진 티켓을 갱신할 때 남습니다. 4769와 거의 같은 칸(계정, 서비스, 티켓 옵션, 암호화 유형, 클라이언트 주소)을 갖고 상태 코드만 없으니, 같은 방식으로 분석하면 됩니다. 실제로는 4769보다 훨씬 드물고, 갱신의 상당수는 TGT 자체(`ServiceName` `krbtgt`)에 대한 것입니다. **4773**은 예전 문서에 나오는 서비스 티켓 요청 실패 이벤트인데, 요즘 시스템에서는 실패가 감사 실패로 표시된 4769로 남습니다.

### 4769로 할 수 있는 것 { #4769-use }

- **옆으로 이동한 지도.** "이 계정이 어떤 서버들의 티켓을 받았나?" 4769를 `TargetUserName`으로 묶으면 `ServiceName` 목록이 나옵니다. 헬프데스크 계정이 10분 만에 `DC-01$`, `BACKUP-01$`, 서버 스무 대의 티켓을 받았다면 둘러보거나 퍼지는 중입니다.
- **이 사용자에게 드문 서비스.** 어떤 계정이 민감한 서버(도메인 컨트롤러, 백업, 하이퍼바이저 관리, PKI)의 티켓을 처음으로 받음.
- **양.** 한 계정이 **짧은 시간에 서로 다른 서비스 여러 개**의 티켓을 요청함 — 특히 RC4로 된 사용자 계정 서비스라면 — 이게 Kerberoasting의 모양입니다.
- **나머지 칸의 이상.** 낯선 티켓 옵션, 뜻밖의 `TransmittedServices`, AES가 정상인데 RC4, `0x1F` 실패.

## 대상 서버의 4624에서 Kerberos 알아보기 { #4624-kerberos }

모든 로그온이 Kerberos를 쓰지는 않습니다. 클라이언트가 이름 대신 **IP 주소**로 접속하거나(`\\10.20.5.12\share`), 계정이 대상 서버의 **로컬** 계정이거나, DC에 닿을 수 없거나, 도구가 **NTLM을 강제**하면(예: 패스 더 해시) Windows는 NTLM을 씁니다. 어느 쪽이었는지는 대상 서버의 4624가 알려 줍니다. `FS-02`에 같은 사용자의 4624 두 개를 나란히 놓아 봅니다.

```xml
<!-- Logon A -->
<Data Name="TargetUserName">j.park</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">Kerberos</Data>
<Data Name="AuthenticationPackageName">Kerberos</Data>
<Data Name="WorkstationName">-</Data>
<Data Name="LogonGuid">{6C3E9F12-08AB-4D7E-B1D4-2F7A90C5E811}</Data>
<Data Name="LmPackageName">-</Data>
<Data Name="KeyLength">0</Data>
<Data Name="IpAddress">10.20.7.31</Data>

<!-- Logon B -->
<Data Name="TargetUserName">j.park</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">WS-118</Data>
<Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
<Data Name="LmPackageName">NTLM V2</Data>
<Data Name="KeyLength">128</Data>
<Data Name="IpAddress">10.20.7.118</Data>
```

A와 B를 한 줄씩 비교하면:

- `LogonType` `3` — 둘 다 네트워크 로그온입니다. 공유에 접속하면 늘 이렇습니다.
- `LogonProcessName` — A는 `Kerberos`, B는 `NtLmSsp`(NTLM 보안 지원 공급자(Security Support Provider)).
- `AuthenticationPackageName` — 바로 답입니다. `Kerberos` 대 `NTLM`.
- `WorkstationName` — A는 `-`: Kerberos는 워크스테이션 이름을 보내지 않습니다. NTLM은 보내서 B에는 `WS-118`이 보이지만, 이 이름은 클라이언트가 적어 보내는 거라 아무 값이나 될 수 있습니다. `IpAddress`를 더 믿으세요.
- `LogonGuid` — A는 진짜 GUID이고, DC의 **4769에 있던 `LogonGuid`와 같습니다**(대소문자만 다름). B는 전부 0입니다. NTLM에는 티켓이 없으니 맞출 것도 없습니다.
- `LmPackageName` — A는 `-`: Kerberos에는 NTLM 버전이 없으니 Kerberos일 때는 **절대 채워지지 않습니다**. B는 `NTLM V2`(NTLM에서 정상). `NTLM V1`이나 `LM`이면 보고할 만한 약점입니다. 쉽게 깨지거나 중계(relay)되는 옛날 프로토콜이라 어디서도 쓰이면 안 됩니다.
- `KeyLength` — A는 `0`: 이 칸은 NTLM 세션 키에 관한 것이라 **Kerberos에서는 늘 0**입니다. B는 `128`, NTLMv2에서 정상입니다. 주의: NTLM에서도 `0`일 수 **있습니다**(예: 익명 로그온이나 세션 키를 맺지 않은 경우). 그래서 `KeyLength 0` 하나만으로 Kerberos라고 단정하면 안 되고, `LmPackageName`과 같이 봐야 합니다.

패키지가 **`Negotiate`** 라면? 대화형 로그온과 RDP(유형 2, 10, 11)에서 흔합니다. 로그온 프로세스(`User32`, `Advapi`)가 Negotiate 패키지에게 Kerberos가 되면 Kerberos, 안 되면 NTLM을 **골라 달라고** 하는 겁니다. 그럴 때는:

| `AuthenticationPackageName` | `LmPackageName` | `KeyLength` | 결론 |
| --- | --- | --- | --- |
| `Kerberos` | `-` | `0` | Kerberos |
| `NTLM` | `NTLM V2` / `NTLM V1` / `LM` | 보통 `128`(`0`일 수도 있음) | NTLM(적힌 버전) |
| `Negotiate` | `-` | `0` | 협상에서 Kerberos가 이김 |
| `Negotiate` | `NTLM V2` 등 | `128` | NTLM이 이김 |

Kerberos가 돼야 하는 도메인에서 **수상한 쪽은 로그온 B**입니다. 같은 사용자인데 NTLM이고, 평소 쓰던 컴퓨터가 아닌 다른 컴퓨터(`10.20.7.118`)에서 왔습니다. **패스 더 해시**(T1550.002)의 모양입니다. NT 해시를 가진 공격자는 NTLM만 쓸 수 있습니다. 해시는 티켓이 아니니까요. 증거는 아닙니다 — 어떤 앱이나 IP로 접속하는 경우는 정상적으로 NTLM을 씁니다 — 하지만 헌팅의 좋은 출발점입니다. 더 자세한 건 [로그인 이벤트](logins.md#4624-fields)와 [Pass-the-Hash](../../../adversary/pass-the-hash.md)에 있습니다.

[보충] 4769(DC)와 4624(대상 서버)를 `LogonGuid`로 이으면, **짝이 되는 4769가 없는 Kerberos 4624**를 찾을 수 있습니다. 진짜 서비스 티켓은 반드시 DC에서 나오니, 어느 DC도 발급한 기억이 없는 티켓으로 된 Kerberos 로그온은 **위조된 서비스 티켓**("실버 티켓", T1558.002)일 수 있습니다. 단서: 티켓은 발급되고 한참 뒤에도 쓰일 수 있고, 로그는 덮어써지며, **모든** DC의 4769가 필요합니다. 경보가 아니라 헌팅의 실마리로 다루세요.

## 이 이벤트들에서 보게 될 공격 { #attacks }

방어자에게 필요한 수준까지만 봅니다. 공격이 무엇이고, 왜 통하고, 무엇을 남기는지. 실행 방법은 다루지 않습니다.

| 기법(ATT&CK) | 공격자가 하는 일 | 어디서 보이나 |
| --- | --- | --- |
| **Kerberoasting**(T1558.003) | 아무 도메인 사용자나 **사용자 계정**으로 도는 서비스의 티켓을 요청해서 가져간 뒤, 오프라인에서 서비스 계정 비밀번호를 추측함. 티켓 요청은 정상 동작이라 막을 수는 없고 알아챌 수만 있음 | **4769**: 계정 하나가 몇 분 만에 서로 다른 사용자 계정 `ServiceName` 여러 개, 흔히 `TicketEncryptionType` **`0x17`**(RC4가 훨씬 빨리 깨져서 도구가 요청함) |
| **AS-REP 로스팅**(T1558.004) | 사전 인증이 꺼진 계정은 누구나 AS-REP를 요청해서 일부를 오프라인으로 깰 수 있음 | `PreAuthType` **`0`** 인 **4768**, 흔히 `0x17`, 그 계정 주인의 컴퓨터가 아닌 곳에서. 더 좋은 건 그런 계정을 찾아서 고치기(`userAccountControl` 깃발 `DONT_REQ_PREAUTH`) |
| **비밀번호 스프레이**(T1110.003) | 흔한 비밀번호 몇 개를 계정 여러 개에 | 한 IP에서 여러 계정에 걸친 **4771** `0x18`, **4768** `0x6`/`0x12` |
| **오버패스 더 해시**(T1550.002) | 훔친 NT 해시를 RC4 키로 써서 진짜 TGT를 받음 | 평소 `0x12`를 받는 계정의 `0x17` **4768**, 낯선 IP에서 |
| **티켓 전달(Pass-the-Ticket)**(T1550.003) | 한 컴퓨터 메모리에서 티켓을 훔쳐 다른 컴퓨터에서 씀 | 그 계정의 4768을 받은 적 없는 IP에서 나온 4769/4624 |
| **골든 티켓**(T1558.001) | `krbtgt` 키(DC 장악이나 DCSync로 얻음)로 아무나, 아무 그룹으로 TGT를 위조 | 앞선 4768 **없이** 나오는 **4769**, 이상한 수명, 없는 계정 이름이나 SID와 안 맞는 이름. 진짜 해결책은 `krbtgt`를 두 번 바꾸기 |
| **실버 티켓**(T1558.002) | 서비스 계정의 키로 그 서비스 하나의 티켓을 위조 | 어느 DC에도 **4769가 없는**, 대상 서버의 Kerberos **4624** |

자세한 설명: [Kerberoasting](../../../adversary/kerberoasting.md), [AS-REP Roasting](../../../adversary/asrep-roasting.md), [Golden, Silver 티켓과 Pass-the-Ticket](../../../adversary/golden-silver-tickets.md), [DCSync](../../../adversary/dcsync.md).

[정정] "Kerberoasting에는 관리자 권한이 필요하다." 아닙니다. **인증된 도메인 사용자라면 누구나** 아무 SPN의 서비스 티켓이든 요청할 수 있습니다. Kerberos가 원래 그렇게 동작합니다. 방어는 서비스 계정에 길고 무작위인 비밀번호(또는 그룹 관리 서비스 계정(group Managed Service Account, gMSA)), AES 전용 암호화, 그리고 4769 패턴 탐지입니다.

## PowerShell로 빠르게 헌팅하기 { #hunting }

DC에서, 지난 하루 동안 RC4로 발급된 서비스 티켓을 컴퓨터 계정과 `krbtgt`를 빼고 뽑아 봅니다.

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4769; StartTime=(Get-Date).AddDays(-1) } |
  ForEach-Object { $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; User=$d.TargetUserName; Service=$d.ServiceName
                       Enc=$d.TicketEncryptionType; Status=$d.Status; From=$d.IpAddress } } |
  Where-Object { $_.Enc -eq '0x17' -and $_.Service -notlike '*$' -and $_.Service -ne 'krbtgt' -and $_.Status -eq '0x0' } |
  Group-Object User | Sort-Object Count -Descending | Select-Object Count, Name
```

한 줄씩 보면:

- `Get-WinEvent -FilterHashtable @{ ... }` — Security 로그를 읽되, 이벤트 로그 서비스 안에서 걸러서 지난 24시간의 ID 4769만 가져옵니다.
- `ForEach-Object { $x = [xml]$_.ToXml(); $d = @{}` — 이벤트마다 XML로 바꾸고, 빈 표 `$d`를 준비합니다.
- `$x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }` — `<Data Name="...">값</Data>`를 전부 `$d`에 옮깁니다. 그러면 위치를 세지 않고 `$d.ServiceName`처럼 쓸 수 있습니다.
- `[pscustomobject]@{ ... }` — 필요한 칸만 담은 깔끔한 행 하나를 만듭니다.
- `Where-Object { ... }` — RC4(`0x17`)이고, 서비스 이름이 `$`로 끝나지 **않고**(컴퓨터가 아님), `krbtgt`가 아니고, 성공한 행만 남깁니다.
- `Group-Object User | Sort-Object Count -Descending` — 요청한 사용자별로 세고, 많은 순으로 정렬합니다.
- `Select-Object Count, Name` — 개수와 사용자만 보여 줍니다.

출력은 이렇게 생겼습니다.

```text
Count Name
----- ----
   23 a.lim@CORP.EXAMPLE
    2 backup.agent@CORP.EXAMPLE
    1 j.park@CORP.EXAMPLE
```

`a.lim`이 하루에 사용자 계정 서비스의 RC4 티켓을 23개 받았습니다. 다른 누구보다 훨씬 많습니다. 다음: 그 사용자에 대해 **어떤** 서비스였는지 보고(`$_.Group | Select Service, From`), 출발 IP를 확인하고, `a.lim`이 그 서비스들을 건드릴 이유가 있는지 물어보세요. SIEM에서는 같은 논리를 임계값과 사용자별 기준선이 있는 예약 검색으로 만듭니다. 바쁜 DC에서는 이 스크립트가 느립니다. 운영용 탐지가 아니라 빠르게 한번 보는 용도입니다.

## 중요한 이벤트를 계속 익혀 나가기 { #keep-learning }

이 섹션에서는 가장 자주 나오는 이벤트들을 다뤘지만, 이벤트는 수백 개가 더 있고 지름길은 없습니다. 효과가 있는 방법:

1. **공격을 먼저 이해합니다.** 레드팀 글, 위협 보고서, ATT&CK 기법 페이지를 읽고 공격자가 **무엇을**, **어떤 순서로** 하는지 압니다.
2. **그다음 행동마다 흔적을 짝지어 봅니다.** 기법마다 물어보세요. 어느 감사 하위 범주가 기록하나, 어느 컴퓨터에, 어떤 이벤트 ID와 칸으로? [Windows 이벤트 ID](../../../basics/windows-event-ids.md) 페이지와 Microsoft의 이벤트별 문서가 좋은 참고 자료이고, 공개된 커뮤니티 치트 시트와 Windows 보안 이벤트 백과사전, 어떤 이벤트를 모아야 하는지에 관한 정부 기관 지침도 좋습니다.
3. **실습 환경에서 재현합니다.** 감사를 다 켜고 Sysmon을 깐 테스트 도메인에서 기법을 실행해 보고 무엇이 나타나는지 봅니다. 직접 만든 이벤트가 어떤 표보다 많이 가르쳐 주고, **여러분의** Windows 버전에서 어떤 칸이 채워지는지도 알게 됩니다.
4. **최신으로 유지합니다.** 새 Windows 버전은 칸과 이벤트를 더하고(아래 Kerberos 암호화 변경이 한 예), 새 기법은 해마다 나옵니다. 정기적으로 시간을 내세요.

## SOC에서 써먹기 { #soc-use }

- **모읍니다.** **모든** 도메인 컨트롤러에서 4768, 4769, 4770, 4771, 4772, 4776(그리고 System 로그의 `Kdcsvc` 이벤트), 모든 서버와 워크스테이션에서 4624/4625. DC의 `auditpol`에서 성공 **그리고** 실패가 켜져 있는지 확인합니다.
- **암호화 유형의 기준선을 잡습니다.** 건강한 2026년 도메인이라면 티켓은 거의 전부 `0x12`입니다. 아직 RC4가 필요한 몇 안 되는 시스템 목록을 두고, 나머지는 조사할 예외로 다룹니다.
- **확신도 높은 경보:** 사용 안 함·퇴사자·미끼 계정의 4768이나 4769; `PreAuthType 0`인 4768(그리고 그 계정 고치기); 한 계정이 여러 사용자 계정 서비스의 RC4 티켓 요청(Kerberoasting); `0x1F` 실패; 모르는 인증서로 관리자 계정이 인증서 로그온(`PreAuthType` 16/17); 모든 `0x1`/`0x3`(DES).
- **헌팅하고 다듬기:** 출발 IP별 `0x6`/`0x12`/`0x18` 실패(스프레이와 열거); 관리자가 아닌 계정의 DC와 다른 티어 0 서버에 대한 4769; Kerberos가 돼야 하는데 NTLM인 4624; 4769 없는 Kerberos 4624(실버 티켓); 그 IP에서 그 계정의 4768 없이 나온 4769(골든 티켓 / 티켓 전달).
- **수집이 아니라 쿼리에서 거릅니다:** 컴퓨터 계정(`$`), `0x20` 실패, `krbtgt` 갱신.
- **잇습니다.** DC와 대상 서버는 `LogonGuid`로, IP와 호스트는 DHCP/DNS 로그로. `::ffff:` 접두어와 XML 속 DC 이벤트 시각이 UTC라는 걸 잊지 마세요.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효한 것"
    Kerberos는 지금도 Active Directory의 기본 인증 프로토콜이고, 4768, 4769, 4770, 4771은 Windows Server 2025에서도 뜻과 핵심 칸이 같습니다. 계정, 클라이언트 IP, 서비스, 결과 코드, 암호화 유형, 사전 인증 유형을 읽는 게 오늘날 분석가가 일하는 방식 그대로입니다. 4624의 `AuthenticationPackageName`, `LmPackageName`, `KeyLength`로 Kerberos와 NTLM을 구별하는 법도 그대로 통합니다. Kerberoasting, AS-REP 로스팅, 골든·실버 티켓, 티켓 전달 공격은 실제 침해에서 여전히 흔하고, 위의 이벤트 패턴이 여전히 이들을 잡는 고전적인 방법입니다.

!!! info "[변경됨] 바뀐 점"
    - **RC4가 꺼지고 있습니다.** Microsoft는 2025년 12월에 "RC4 너머로(beyond RC4)" 가겠다고 발표했고, 2026년 1월 업데이트(CVE-2026-20833)부터 단계적 변경을 시작했습니다. 먼저 기본값으로 RC4가 쓰일 상황이면 DC의 **System** 로그에 새 `Kdcsvc` 이벤트(ID **201–209**)를 쓰는 감사 단계, 그다음 RC4를 명시적으로 허용하지 않은 계정에 대해 DC가 **AES 전용**으로 가정하는 강제 단계입니다(2026년 4월부터 배포, 2026년 7월 업데이트에서 수동 되돌리기 선택지 제거). 패치된 도메인에서는 `0x17` 티켓이 드물어져야 하고, 그래서 남은 하나하나가 더 의미 있어집니다. RC4가 사라졌다고 가정하기 전에 DC의 System 로그에서 그 이벤트들을 확인하세요.
    - **4768/4769의 칸이 늘었습니다.** Windows Server 2019, 2022, 2025용 최근 업데이트가 RC4 의존성을 찾도록 이 이벤트들에 암호화 정보(계정이 지원하는 암호화 유형, 어떤 키가 있는지, 세션 암호화 유형 등)를 더했습니다. 칸 이름과 배치는 빌드마다 다를 수 있으니, 파서를 만들기 전에 여러분 DC의 실제 이벤트를 확인하세요.
    - **DES**는 최신 Windows Server와 Windows 11의 Kerberos에서 더 이상 지원되지 않습니다. DES 티켓 유형이 보이면 이제는 설정 오류이거나 공격입니다.
    - **NTLM도 떠나는 중입니다**(Windows 11 24H2 / Server 2025에서 NTLMv1 제거, NTLM 기본 비활성화를 향한 단계적 계획). 그래서 도메인 안의 NTLM 4624는 점점 더 설명이 필요한 예외가 됩니다.
    - **아이덴티티가 일부 클라우드로 옮겨 갔습니다.** 하이브리드 환경에서는 인증의 상당 부분이 Microsoft Entra ID에서 일어나고(4768이 아니라 로그인 로그), Windows Hello for Business와 Entra Kerberos는 TGT 요청 모양을 바꿉니다(인증서/PKINIT와 클라우드가 발급한 티켓이 늘어남). Microsoft Defender for Identity 같은 아이덴티티 중심 도구가 이 DC 이벤트와 네트워크 트래픽을 읽어서 이 페이지의 공격들을 자동으로 탐지하지만, 경보를 확인하려면 여전히 원본 이벤트를 읽을 줄 알아야 합니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 것"
    - **DC 한 대에서만 모으지 마세요.** DC마다 자기가 발급한 티켓만 기록하고, 클라이언트는 아무 DC로나 갈 수 있습니다.
    - **수집 단계에서 `$` 계정을 버리지 마세요.** 쿼리에서 거르세요. 어떤 공격(예: 중계와 위임 악용)에서는 컴퓨터 계정 티켓이 중요합니다.
    - **`KeyLength 0` 하나만으로 Kerberos라고 단정하지 마세요.** `AuthenticationPackageName`, `LmPackageName`과 같이 보세요.
    - **4769 `0x20`에 경보를 걸지 마세요.** 만료된 티켓 잡음입니다.
    - **Kerberos 로그온이 성공했다고 정상이라고 가정하지 마세요.** 위조되거나 훔친 티켓도 완벽하게 평범해 보이는 4624를 만듭니다. 증거는 DC 쪽에 **없는 것**이나 **안 맞는 것**에 있습니다.
    - **"혹시 몰라서" RC4를 계속 허용하지 마세요.** RC4가 필요한 시스템을 찾아서(새 `Kdcsvc` 이벤트와 4768/4769 칸이 도와줍니다) 고치고, 강제 단계가 적용되게 두세요.

## 확인 문제 { #quiz }

### 문제 1

`DC-02`에서 4분 안에 성공한 **4769**가 31건 보입니다. `TargetUserName` = `m.cho@CORP.EXAMPLE`, `IpAddress` = `::ffff:10.20.9.44`, `TicketEncryptionType` = `0x17`, `ServiceName`은 매번 다릅니다: `svc_sql`, `svc_backup`, `svc_iis`, `svc_report`… `m.cho`는 재무팀입니다. 무슨 일일 가능성이 높고, 암호화 유형이 왜 중요하며, 어떻게 하겠습니까?

??? success "정답과 해설"
    **Kerberoasting**(T1558.003)의 모양입니다. `m.cho`(또는 `10.20.9.44`에서 `m.cho`의 세션을 쓰는 무언가)가 몇 분 만에 **사용자 계정으로 도는 서비스 여러 개**(끝에 `$` 없음)의 서비스 티켓을 요청했습니다. 티켓마다 그 서비스 계정 비밀번호에서 나온 키로 암호화돼 있으니, 가져가서 오프라인으로 깰 수 있습니다. 재무팀 사용자가 백엔드 서비스 31개에 접근할 이유가 없고, 4분 만이라면 더더욱 그렇습니다.

    `0x17`(RC4)이 중요한 이유는 RC4 티켓이 AES보다 훨씬 빨리 깨지기 때문에 공격 도구가 일부러 RC4를 요청하기 때문입니다. 평소 `0x12`를 발급하는 도메인에서 사용자 계정 서비스의 RC4 티켓이 몰려 나오면 강한 신호입니다. **다음 할 일:** 그 시각 `10.20.9.44`에서 무슨 프로세스였는지 찾고(4688/Sysmon/EDR), 확인되면 호스트를 격리하고, 목록의 **모든 서비스 계정** 비밀번호를 길고 무작위인 값으로 바꾸고(또는 gMSA로 옮기고), 그 뒤 그 계정들이 낯선 곳에서 로그온하지 않았는지 보고, 그 서비스들을 AES 전용으로 만드세요. `DC-01`과 다른 DC도 확인하세요. 같은 활동이 여러 DC에 나뉘어 있을 수 있습니다.

### 문제 2

서버 `APP-07`에 `CORP\svc_deploy`의 유형 3 로그온 4624가 두 개 있습니다. 로그온 1: `AuthenticationPackageName` `Negotiate`, `LmPackageName` `-`, `KeyLength` `0`. 로그온 2: `AuthenticationPackageName` `NTLM`, `LmPackageName` `NTLM V1`, `KeyLength` `0`, `WorkstationName` `BUILD01`, `IpAddress` `10.20.30.77`. 각 로그온은 어떤 프로토콜을 썼고, 무엇을 보고할 만합니까?

??? success "정답과 해설"
    **로그온 1 = Kerberos.** 패키지가 `Negotiate`이니 나머지 칸을 봅니다. `LmPackageName` `-`(NTLM 버전 없음)와 `KeyLength` `0`이 둘 다 협상에서 Kerberos가 이겼다고 말합니다. DC에서 같은 `LogonGuid`를 가진 4769를 찾으면 확인할 수 있습니다.

    **로그온 2 = NTLM, 버전 1.** `AuthenticationPackageName`이 바로 `NTLM`이라고 말합니다. 여기서 `KeyLength` `0`은 Kerberos라는 뜻이 아니라 NTLM 세션 키가 맺어지지 않았다는 뜻이고, NTLM에서도 그럴 수 있습니다. 바로 그래서 `KeyLength` 하나만 보면 안 되는 겁니다. **보고할 것:** `NTLM V1`은 옛날의 약한 프로토콜(깨기도 중계하기도 쉬움)이라 어디서도 쓰이면 안 되고, 최신 Windows에서는 제거됐습니다. `10.20.30.77`에서 무엇이 아직 NTLMv1을 쓰는지 찾고(`BUILD01`이라는 이름은 믿지 마세요 — 클라이언트가 적어 보낸 값입니다), 고치거나 격리하고, 정상인지부터 확인하세요. 낯선 호스트에서 NTLMv1로 로그온하는 서비스 계정은 깨기 쉬운 응답을 얻으려는 다운그레이드 시도일 수도 있습니다.

### 문제 3

`DC-01`에서 `old.admin`(인사팀 말로는 작년에 퇴사한 사람 계정)의 성공한 **4768**을 찾았습니다. `PreAuthType` `0`, `TicketEncryptionType` `0x17`, `IpAddress` `::ffff:192.0.2.80` — 잘못 설정된 VPN 주소 풀을 통해 들어온, 내부 대역 밖의 주소입니다. 그 앞에는 4771이나 다른 실패가 전혀 없습니다. 각 단서를 설명하고, 공격자가 무엇을 얻었는지 말해 보세요.

??? success "정답과 해설"
    - **계정이 없거나 꺼져 있어야 합니다.** 아직 살아 있는 퇴사자 계정은 공격자에게 선물이고, 그 계정의 4768은 그것만으로 경보가 울려야 합니다.
    - **`PreAuthType 0`** 은 계정에 *Do not require Kerberos preauthentication* 이 켜져 있다는 뜻입니다. DC가 비밀번호 증명 **없이** 답했습니다. 실패가 없는 이유도 이것입니다. 아무것도 확인하지 않았으니까요. **AS-REP 로스팅** 패턴(T1558.004)입니다. 응답에 계정의 비밀번호 키로 암호화된 데이터가 들어 있어서, 요청한 사람이 오프라인으로 깰 수 있습니다.
    - **`0x17`(RC4)** — 요청한 쪽이 가장 빨리 깨지는 RC4를 골랐습니다. 최신 Windows 클라이언트라면 AES를 썼을 겁니다.
    - **`192.0.2.80`** — 여러분의 워크스테이션이 아닙니다. 평소 클라이언트가 아닌 누군가가 DC에 직접 묻고 있습니다.

    **공격자가 얻은 것:** 아직 쓸 수 있는 로그온은 아닙니다. 오프라인으로 깨 볼 수 있는 암호화된 덩어리를 얻었고, `old.admin`의 비밀번호가 약했다면 곧 비밀번호를 알게 됩니다. **다음 할 일:** `old.admin`을 지금 사용 안 함으로 바꾸고, 비밀번호를 재설정하고, 그 계정의 `DONT_REQ_PREAUTH` 깃발을 지우고 **그 깃발이 있는 다른 계정을 모두 찾고**, VPN 주소 풀을 막거나 고치고, `old.admin`의 이후 4768/4769/4624(사전 인증 2라면 깨는 데 성공했다는 뜻)를 찾고, 그 계정이 무엇에 접근할 수 있었는지 검토하세요.

## 관련 레퍼런스 { #related }

- [꼭 알아야 할 이벤트](index.md) — 이 섹션 개요
- [로그인 이벤트](logins.md) — 4624/4625 칸, 로그온 유형, DC의 4771/4776
- [계정, Defender, PowerShell 이벤트](accounts-defender-powershell.md) — 자격 증명을 얻은 공격자가 이어서 하는 계정 변경
- [자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) — 훔친 해시와 티켓이 어디서 오는지
- [옆으로 이동, 수집, 유출](../endpoint-attacks/lateral-collection-exfil.md) — 공격자가 그걸로 하는 일
- [Windows 이벤트 속 들여다보기](../windows-logging/event-structure-channels.md) — XML과 Security 채널 읽기
- [Kerberoasting](../../../adversary/kerberoasting.md), [AS-REP Roasting](../../../adversary/asrep-roasting.md), [Golden, Silver 티켓과 Pass-the-Ticket](../../../adversary/golden-silver-tickets.md), [Pass-the-Hash](../../../adversary/pass-the-hash.md), [AD 인증서 서비스 악용](../../../adversary/adcs-abuse.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
