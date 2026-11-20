---
title: "PAW, 권한과 특권, EDR, DLP, UEBA, 감사 로깅 — 관리자 열쇠는 지키고, 모든 건 기록하기"
tags:
  - training
  - blue-team
  - endpoint
  - hardening
  - edr
  - dlp
  - ueba
  - logging
---

# PAW, 권한과 특권, EDR, DLP, UEBA, 감사 로깅 — 관리자 열쇠는 지키고, 모든 건 기록하기 { #paw-edr-dlp-ueba }

!!! abstract "이 페이지에서 다루는 것"
    엔드포인트 심층 방어의 마지막 방어선들입니다. 첫째, 관리 전용 PC(PAW). 관리자 자격 증명을 왜 평범한 PC에서 절대 입력하면 안 되는지, "깨끗한 출발점" 원칙, 계층화(tiering), 그리고 tier 0 계정이 있으면 안 되는 곳에 로그온했을 때 SOC가 어떻게 잡는지(4624, 4672). 둘째, Windows 권한(permission)과 특권(privilege). *어떤 물건을 만질 수 있나*(ACL)와 *어떤 행동을 할 수 있나*(`SeDebugPrivilege`, `SeBackupPrivilege`, `SeLoadDriverPrivilege`, `SeImpersonatePrivilege` 같은 특권)의 차이를 `icacls`와 `whoami /priv`로 읽어 보고, 각 특권이 어떻게 권한 상승으로 이어지는지. 셋째, EDR — 모든 호스트에 달린 비행 기록 장치. 무엇을 기록하는지, 프로세스 트리 기록이 칸별로 어떻게 생겼는지, 그리고 탐지만큼 *대응* 절반이 왜 중요한지, 거기에 XDR. 넷째, DLP. 분류 등급, 내용 검사, 내부자/외부자 세 가지 쓰임새, 그리고 마음먹은 공격자를 막기보다 늦추는 도구인 이유. 다섯째, UEBA. 기준선, 동료 그룹, 이상 점수, 그리고 기저율 문제. 마지막으로 감사 정책과 중앙 로그 수집(`auditpol`, 명령줄 기록, `auditd` 규칙, 전달, 1102), 그리고 심층 방어 정리. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름, 해시는 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. <strong>관리 전용 PC(PAW, Privileged Access Workstation)</strong>는 관리 작업*만* 하는 따로 떼어 놓고 단단히 잠근 컴퓨터(또는 격리된 VM)다. 관리자 계정은 평소 쓰는 PC에서 절대 쓰지 않는다. 그래서 평소 PC가 피싱이나 웹 감염을 당해도 관리자 계정은 도둑맞지 않는다.
2. <strong>깨끗한 출발점 원칙(Clean Source Principle)</strong>: 어떤 장치*에서* 관리하는 모든 것은 그 장치만큼만 안전하다. 노트북 하나가 뚫리면 점프 서버, 관리자 계정, 그걸로 관리하는 모든 것이 같이 흔들린다.
3. <strong>권한(Permission, ACL)</strong>은 계정이 *어떤 물건* — 파일, 폴더, 레지스트리 키, 서비스 — 을 읽거나 바꿀 수 있는지를 정한다. 올바른 기본값은 시스템 실행 파일이 백도어 버전으로 바꿔치기되는 걸 막고, 허술한 ACL은 가장 흔한 권한 상승 경로 중 하나다.
4. <strong>특권(Privilege, 사용자 권한 User Rights)</strong>은 ACL과 상관없이 계정이 *어떤 행동*을 할 수 있는지를 정한다. 아무 프로세스나 디버깅하기, 아무 파일이나 백업하기, 드라이버 올리기, 토큰 가장하기. 이 중 몇 개는 "변장한 관리자"라서 바로 권한 상승이나 자격 증명 탈취로 이어진다.
5. **EDR**은 모든 호스트에서 프로세스·파일·레지스트리·네트워크·DLL·서비스 활동과 *그것들 사이의 관계*를 기록해서, 무슨 일이 있었는지 다시 돌려 볼 수 있게 한다. **대응** 절반 — 격리, 프로세스 종료, 수집, 스크립트 실행 — 은 뚫렸을지 모르는 PC에 관리자 자격 증명을 입력하지 않고도 SOC가 움직일 수 있는 안전한 별도 통로다. XDR은 같은 생각을 이메일, 아이덴티티, 클라우드, 네트워크 데이터까지 넓힌 것이다.
6. **DLP**는 민감한 데이터가 있으면 안 되는 곳에 있거나, 가면 안 되는 곳(USB, 개인 클라우드, 이메일, 웹 업로드)으로 가는 걸 찾는다. 분류 등급과 내용 패턴을 쓴다. 실수를 막고 부주의한 내부자를 잡는 데는 아주 좋지만, 마음먹은 공격자는 결국 피해 간다(암호화, 압축, 조금씩 빼내기).
7. **UEBA**는 사용자, 호스트, 동료 그룹마다 통계적 기준선을 만들고 벗어난 정도에 점수를 매긴다. "이상한 건 악성일 가능성이 더 높다"는 데 거는 것인데, 이게 꽤 자주 맞아서 잡음을 크게 줄여 준다. 하지만 이벤트가 10억 개면 0.001%도 1만 건이다. 최종 판단은 여전히 업무를 아는 사람이 한다.
8. **감사 정책 + 중앙 로그 수집**이 다른 모든 것의 바닥이다. 감사 정책은 무엇을 기록할지 정하고, 로그를 호스트 밖으로 빨리 보내 두면 공격자가 엔드포인트에서 로그를 지워도(T1070.001) 사본은 못 지운다. 심층 방어의 목표는 단계마다 덫을 놓아서 공격자를 느리게 만들고, 결국 하나는 밟게 하는 것이다.

## 관리 전용 PC(PAW) — 관리자 열쇠를 길거리에 들고 다니지 않기 { #paw }

### 왜 필요한가 { #paw-why }

건물 모든 사무실을 여는 마스터키가 있다고 해 봅시다. 그 열쇠를 주머니에 넣고 장 보러 다니고, 카페에 앉아 있고, 모르는 사람과 부딪히며 다니진 않겠죠. 금고실에 두고 거기서만 꺼낼 겁니다. 관리자 자격 증명이 바로 그 마스터키이고, 평소 쓰는 PC가 길거리입니다. 메일을 읽고, 첨부 파일을 열고, 웹을 돌아다니고, 사용자가 설치한 걸 실행합니다. 피싱과 웹 감염이 노리는 게 정확히 그런 일들입니다.

기술적으로 보면, 위험은 Windows가 로그온을 다루는 방식에서 옵니다. 계정이 대화형으로 로그온하면(콘솔, RDP, `runas`), 로컬 보안 기관(LSA, `lsass.exe`)은 사용자가 비밀번호를 다시 치지 않고도 다른 자원에 접근할 수 있도록 재료를 들고 있습니다. NT 해시, Kerberos 티켓과 키 같은 것들입니다([자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) 참고). 그 PC에서 관리자 권한을 가진 사람은 이걸 읽어서(T1003.001) 다른 곳에서 다시 쓸 수 있습니다(해시 전달 T1550.002, 티켓 전달 T1550.003). 그러니 도메인 관리자가 공격자가 이미 장악한 헬프데스크 PC에 한 번이라도 로그온하면, 공격자는 익스플로잇 하나 없이 도메인 관리자를 얻습니다.

### PAW란 무엇인가 { #paw-what }

PAW는 특권 작업만을 위한 전용 장치입니다. 실제로는 이런 뜻입니다.

- **먼저 계정을 나눈다.** 관리자는 메일·웹용 일반 계정(`j.park`)과 관리용 특권 계정(`adm-j.park`)을 따로 가집니다. 이게 없으면 PAW는 의미가 없습니다.
- **장치나 환경을 따로 둔다.** 특권 계정은 PAW에서만 씁니다. 방법은 전용 물리 노트북(가장 강함)부터, *호스트*가 PAW이고 평소 쓰는 데스크톱은 그 안의 게스트 VM으로 도는 방식까지 있습니다. 거꾸로 하면 절대 안 됩니다. 평소 쓰는 OS가 호스트면, 그게 뚫릴 때 그 안의 PAW 게스트도 같이 뚫립니다.
- **아주 단단히 잠근다.** 메일 없음, 일반 웹 서핑 없음(또는 관리 포털만 허용 목록으로), 애플리케이션 제어 강제 모드, Credential Guard, 전체 디스크 암호화, 별도의 관리 체계, 로컬 관리자 권한 제거, USB 제한.
- **반대 방향의 로그온도 막는다.** 그룹 정책(`Deny log on locally`, `Deny log on through Remote Desktop Services`)이나 인증 정책/사일로(authentication policy/silo)로 특권 계정이 일반 PC와 멤버 서버에 로그온하는 걸 *거부*합니다. 그러면 깜빡한 관리자라도 엉뚱한 곳에서 자격 증명을 칠 수가 아예 없습니다.

### 깨끗한 출발점과 계층화 { #clean-source }

깨끗한 출발점 원칙은 "어떤 시스템의 보안은 그것을 조종하는 모든 것의 보안에 달려 있다"는 뜻입니다. 사슬을 떠올려 보세요. PAW → 점프 서버 → 도메인 컨트롤러. PAW가 뚫리면 공격자는 관리자의 키 입력을 엿보고(T1056.001), 세션을 가로채고, 토큰을 훔칠 수 있습니다. 그러면 점프 서버를 아무리 단단히 했어도 소용없습니다. 그래서 *장치*가 선택 사항이 아니라 바닥 기초입니다.

여기서 자연스럽게 <strong>계층화(Tiering)</strong>가 나옵니다. 계정과 장치를 무엇을 조종하느냐에 따라 나눕니다. 단순하게 그리면 이렇습니다.

| Tier | 조종하는 것 | 예 | 로그온해도 되는 곳 |
| --- | --- | --- | --- |
| 0 (제어 평면) | 아이덴티티 자체 | 도메인 컨트롤러, AD CS, Entra ID 전역 관리자, 아이덴티티 동기화 서버 | tier 0 시스템과 tier 0 PAW만 |
| 1 (서버 관리) | 서버와 애플리케이션 | 파일, 데이터베이스, 애플리케이션 서버 | tier 1 시스템과 PAW |
| 2 (사용자 접근) | PC와 사용자 | 헬프데스크, PC 지원 | PC |

규칙은 "아래로는 절대 로그온하지 않는다"입니다. tier 0 계정은 tier 1이나 tier 2 장치에 절대 인증하지 않습니다. 아래 장치가 뚫리기 쉽고, 뚫리면 위 계정의 자격 증명이 드러나기 때문입니다.

### SOC가 지켜보는 것 { #paw-detection }

PAW를 운영하면 SOC는 선명하고 값진 탐지 하나를 얻습니다. *특권 계정이 있으면 안 되는 곳에서 인증했다.* PAW가 아닌 PC에서 그게 어떻게 보이는지 봅시다.

```xml
<Event>
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-11-18T22:41:07.512Z" />
    <Computer>WS-HR-0142.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">WS-HR-0142$</Data>
    <Data Name="TargetUserName">adm-j.park</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetLogonId">0x8A3F21C</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32</Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">WS-HR-0142</Data>
    <Data Name="IpAddress">10.20.4.77</Data>
    <Data Name="ElevatedToken">%%1842</Data>
  </EventData>
</Event>
```

- `EventID 4624` — "계정이 성공적으로 로그온했습니다". 로그온*당하는* 쪽 PC에서, 성공한 로그온마다 생깁니다. 공격자에게 중요한 이유는 특권 계정이 약한 PC에 로그온할 때마다 자격 증명을 훔칠 기회가 생기기 때문이고, 방어자에게 중요한 이유는 자격 증명이 어디에 노출됐는지 알려 주는 기록이기 때문입니다.
- `Computer WS-HR-0142` — 인사팀 PC입니다. 바로 이게 문제입니다. PAW도 아니고 tier 0/1 서버도 아닙니다.
- `TargetUserName adm-j.park` — 로그온한 계정. 이 이름 규칙에서 `adm-` 접두어는 특권 계정이라는 표시입니다. (`SubjectUserName WS-HR-0142$`는 로그온을 처리한 로컬 컴퓨터 계정이라 정상입니다.)
- `TargetLogonId 0x8A3F21C` — 세션 번호. 이걸로 이 로그온을 뒤따르는 이벤트(4688의 프로세스, 4672의 특권, 4634의 로그오프)와 묶습니다.
- `LogonType 10` — RemoteInteractive, 즉 RDP. RDP 로그온은 *이* PC의 LSASS에 다시 쓸 수 있는 자격 증명을 남깁니다. (유형 2 = 콘솔, 3 = 네트워크, 9 = `runas /netonly` 같은 NewCredentials. 로그온 유형 전체는 뒤의 "꼭 알아야 할 이벤트" 섹션에서 다룹니다.)
- `LogonProcessName User32`와 `AuthenticationPackageName Negotiate` — Winlogon이 처리한 대화형 로그온이고, 협상(Kerberos 우선, 안 되면 NTLM)으로 인증했다는 뜻. RDP에서 흔한 모습입니다.
- `IpAddress 10.20.4.77` — RDP 세션이 온 곳. 그게 그 관리자의 PAW인가요? 또 다른 평범한 PC라면 규칙을 두 개 어긴 겁니다.
- `ElevatedToken %%1842` — "예". 이 세션이 상승된(관리자) 토큰을 받았다는 뜻입니다.

바로 뒤에는 보통 이런 이벤트가 따라옵니다.

```
EventID 4672  Special privileges assigned to new logon.
  SubjectUserName : adm-j.park
  SubjectLogonId  : 0x8A3F21C
  PrivilegeList   : SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege
                    SeTakeOwnershipPrivilege SeDebugPrivilege
                    SeLoadDriverPrivilege SeImpersonatePrivilege ...
```

**4672**("새 로그온에 특수 권한이 할당되었습니다")는 새 로그온 세션이 정해진 민감한 특권 중 하나라도 받으면 생깁니다. 실제로는 관리자급 계정이 로그온할 때마다 생긴다고 보면 됩니다. `SubjectLogonId`가 4624의 `TargetLogonId`와 같으니 같은 세션이라는 게 확인됩니다. 공격자에게 중요한 이유는 이 특권들이 있어야 자격 증명 덤프와 드라이버 올리기가 되기 때문이고, 방어자는 4672를 "여기 관리자가 로그온했다"는 단순한 신호로 씁니다.

탐지 규칙은 저절로 나옵니다. *특권 그룹 구성원이 PAW나 tier 0/tier 1 목록에 없는 호스트에서 4624(유형 2, 10, 11, 9)나 4672를 만들면 경보.* 드물게 생기고, 관리자 팀에게 설명하기 쉽고, 걸리는 건 전부 정책 위반이거나 훔친 관리자 계정을 쓰는 공격자입니다.

**[보충]** Microsoft의 현재 안내는 PAW를 더 넓은 *특권 접근 전략(privileged access strategy, 엔터프라이즈 접근 모델)*의 일부로 설명합니다. 특권 장치, 특권 계정, 그리고 점프 서버나 클라우드 관리 포털 같은 중간 경유지를 함께 보호한다는 생각입니다. Essential Eight의 "관리자 권한 제한"도 특권 계정 분리와 안전한 관리용 PC를 분명히 포함합니다. 호주 프레임워크 아래에서 일한다면 바로 관련이 있습니다.

## Windows 권한과 특권 { #permissions-privileges }

### 서로 다른 두 질문 { #two-questions }

비유하면 이렇습니다. 사무실 건물에서 **문마다 달린 자물쇠**는 누가 어느 방을 열 수 있는지를 정합니다. 이게 권한입니다. 그런데 **직책**은 어느 방에 있든 무엇을 *할 수 있는지*를 정합니다. 소방 담당자는 화재경보를 울릴 수 있고, 보안 요원은 누구 가방이든 검사할 수 있습니다. 이게 특권입니다. 공격자는 둘 다 좋아합니다. 잠그지 않은 문(허술한 ACL), 아니면 조용히 엄청난 걸 하게 해 주는 직책(위험한 특권).

- <strong>권한(Permission)</strong>은 물건의 접근 제어 목록(ACL, Access Control List)에 있는 항목입니다. 파일, 폴더, 레지스트리 키, 서비스, 명명된 파이프, 공유, AD 개체에 붙습니다. "계정 X가 *이 물건*을 읽기/쓰기/지우기 할 수 있나?"에 답합니다.
- <strong>특권(Privilege)</strong>은(사용자 권한 User Rights, `Se…Privilege`라고도 부름) 계정의 액세스 토큰 안에 들어 있고, 정책(로컬 보안 정책 → 사용자 권한 할당, 또는 GPO)으로 줍니다. "계정 X가 *이런 종류의 행동*을 아예 할 수 있나?"에 답하고, 때로는 ACL을 *건너뜁니다*.

### 권한은 시스템의 온전함을 지킨다 { #permissions }

Windows는 꼼꼼한 기본 ACL을 달고 나옵니다. `C:\Windows\System32`의 대부분은 `TrustedInstaller`(업데이트를 담당하는 계정)가 소유하고, 관리자도 기본으로는 읽기와 실행만 할 수 있습니다. 덮어쓰려면 먼저 소유권을 가져와야 합니다. 일부러 그렇게 만든 겁니다. 시스템 실행 파일을 가볍게, 또는 자동화된 도구로 쉽게 건드리지 못하게 하려고요.

```
C:\> icacls C:\Windows\System32\utilman.exe
C:\Windows\System32\utilman.exe NT SERVICE\TrustedInstaller:(F)
                                BUILTIN\Administrators:(RX)
                                NT AUTHORITY\SYSTEM:(RX)
                                BUILTIN\Users:(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)

Successfully processed 1 files; Failed processing 0 files
```

- `NT SERVICE\TrustedInstaller:(F)` — 업데이트 담당 계정만 모든 권한(Full)을 가집니다. 건강한 기본값입니다.
- `BUILTIN\Administrators:(RX)`와 `NT AUTHORITY\SYSTEM:(RX)` — 읽기와 실행만. 관리자는 실행은 할 수 있지만, 소유권을 먼저 가져오지 않으면 덮어쓸 수 없습니다.
- `BUILTIN\Users:(RX)` — 일반 사용자도 실행할 수 있습니다.
- `APPLICATION PACKAGE AUTHORITY` 두 줄은 샌드박스(스토어/AppContainer) 앱이 읽을 수 있게 하는 것으로 정상입니다.

왜 하필 이 파일일까요? `utilman.exe`는 *로그온 화면*에서 띄울 수 있는 접근성 도구이고, 거기서는 SYSTEM으로 돕니다. 고전적인 백도어는 이 파일(또는 고정 키 처리기 `sethc.exe`)을 `cmd.exe`로 바꿔치기합니다. 그러면 비밀번호 없이 로그온 화면에서 SYSTEM 셸이 뜹니다 — **접근성 기능(Accessibility Features), T1546.008**. 이 파일의 ACL에 `Administrators:(F)`가 보이거나 소유자가 `TrustedInstaller`가 아니라면, 누군가 소유권을 가져간 겁니다. 조사하세요. 이런 실행 파일에 거는 파일 무결성 모니터링([애플리케이션 제어, FIM, 지속성 잡기](appcontrol-fim-persistence.md) 참고)과 정기적인 권한 점검이 이걸 잡아냅니다.

반대 경우 — 권한이 *너무 느슨한* 경우 — 는 [권한 상승](../endpoint-attacks/privilege-escalation.md)에서 다뤘습니다. `Users`가 쓸 수 있는 서비스 실행 파일이나 레지스트리 키가 있으면, 누구든 자기 코드로 바꿔 놓고 SYSTEM이 실행하게 만들 수 있습니다.

### 특권은 로그온 뒤에 무엇을 할 수 있는지 정한다 { #privileges }

내 특권은 `whoami /priv`로 봅니다. 아래는 관리자 권한으로 띄운 명령 창입니다(일부 생략).

```
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeBackupPrivilege             Back up files and directories             Disabled
SeRestorePrivilege            Restore files and directories             Disabled
SeDebugPrivilege              Debug programs                            Disabled
SeLoadDriverPrivilege         Load and unload device drivers            Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeTakeOwnershipPrivilege      Take ownership of files or other objects  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
```

- `Privilege Name` — 로그(4672, 4673, 4674)와 도구에서 보게 될 내부 이름.
- `Description` — 사용자 권한 할당 화면에서 쓰는 이름.
- `State` — **Disabled는 "없다"는 뜻이 아닙니다.** 목록에 줄이 있으면 그 계정은 특권을 *가지고 있고*, 프로그램이 쓰기 전에 켜기만(`AdjustTokenPrivileges`) 하면 됩니다. 어떤 도구든 호출 한 번이면 켭니다. 목록에 아예 없어야 "없다"입니다.

위험한 특권과 그 이유입니다.

| 특권 | 정상 용도 | 공격자가 악용하는 방법 | ATT&CK |
| --- | --- | --- | --- |
| `SeDebugPrivilege` | 디버거가 아무 프로세스에나 붙기 | `lsass.exe`를 열어 메모리 읽기 → 자격 증명 | T1003.001 |
| `SeBackupPrivilege` | 백업 프로그램이 모든 파일 읽기 | ACL과 상관없이 파일 읽기. 예: `HKLM\SAM`과 `HKLM\SYSTEM` 저장(로컬 해시), DC에서 `NTDS.dit` 복사 | T1003.002, T1003.003 |
| `SeRestorePrivilege` | 백업 복원 | ACL과 상관없이 아무 파일이나 쓰기 — 서비스 실행 파일이나 `utilman.exe` 바꿔치기 | T1574, T1546.008 |
| `SeLoadDriverPrivilege` | 드라이버 설치 | 취약한 서명 드라이버를 올려 커널에 닿기(BYOVD), 흔히 EDR을 끄는 데 씀 | T1068, T1562.001 |
| `SeImpersonatePrivilege` | 서비스가 클라이언트 대신 일하기(IIS, SQL) | "Potato" 기법으로 SYSTEM이 공격자 프로세스에 인증하게 속인 뒤 그 신원을 가장 | T1134.001 |
| `SeTakeOwnershipPrivilege` | 주인 없는 파일 되찾기 | 아무 물건의 소유권을 가져온 뒤 ACL 다시 쓰기 | T1222.001 |

백업 예는 특권이 ACL을 어떻게 건너뛰는지 잘 보여 주니 자세히 봅시다. **Backup Operators** 그룹 구성원은 관리자가 아니고, 보통은 SAM 레지스트리 하이브를 읽을 수 없습니다. 그런데 백업 특권은 Windows에게 "이 계정이 *백업 목적으로는* 뭐든 읽게 해 줘"라고 말합니다. 그래서 이렇게 됩니다.

```
C:\> reg save HKLM\SAM C:\Users\Public\s.hiv
The operation completed successfully.
C:\> reg save HKLM\SYSTEM C:\Users\Public\y.hiv
The operation completed successfully.
```

- `reg save HKLM\SAM <파일>` — SAM 하이브(로컬 계정 해시)의 사본을 파일로 씁니다. SYSTEM 하이브에는 그걸 풀 때 필요한 부트 키가 있습니다.
- `The operation completed successfully.` — 백업 특권이 있으면, 평소엔 그 키를 열 수 없는 계정이라도 이게 성공합니다.

공격자는 두 파일을 밖으로 복사해서 오프라인으로 해시를 뽑아냅니다. 가상 머신도 같은 논리입니다. 돌아가는 VM의 스냅숏을 찍거나 복제할 수 있는 사람은 그 메모리 사본 — LSASS 포함 — 을 얻습니다. 그래서 하이퍼바이저 관리자와 백업 관리자는 자기가 보호하는 시스템에 대해서는 사실상 tier 0입니다.

**찾아볼 증거:** 알려진 백업 작업이 아닌데 `reg.exe save HKLM\SAM|SECURITY|SYSTEM`, `ntdsutil`, `wbadmin`, `diskshadow`, `vssadmin`이 찍힌 4688(또는 Sysmon 1), 예상 밖의 프로세스가 `SeBackupPrivilege`나 `SeDebugPrivilege`를 쓴 4673/4674("특권 서비스가 호출되었습니다" / "특권 개체에 대한 작업이 시도되었습니다", 양이 많아서 골라서 수집), Backup Operators 같은 그룹의 구성원 변경(4728/4732/4756), 새 커널 드라이버에 대한 7045.

방어 원칙: 이런 특권을 가진 계정은 전부 특권 계정으로 대하고, Backup Operators, Server Operators, Print Operators 같은 그룹은 꼭 필요하지 않으면 비워 두고, 사용자 권한 할당 GPO도 그룹 구성원만큼 꼼꼼히 검토합니다.

## EDR — 모든 엔드포인트에 달린 비행 기록 장치 { #edr }

### 왜 생겼나 { #edr-why }

백신은 파일 하나에 대해 질문 하나에 답합니다. "나쁜가, 아닌가?" 그런데 익스플로잇 이후 활동 대부분에는 백신이 잡을 만한 파일이 없습니다. 이상한 인자를 단 `powershell.exe`, `AppData`에서 뭔가를 올리는 `rundll32.exe`, 새 서비스, 낯선 IP로 가는 연결. 한 단계씩 보면 다 평범한데, *이어진 순서*가 바로 공격입니다. Windows 이벤트 로그는 그 조각들을 보여 주지만, 조각 사이의 연결은 빠져 있을 때가 많고, 그나마 감사 정책을 제대로 켰을 때만 남습니다.

<strong>EDR(Endpoint Detection and Response, 엔드포인트 탐지·대응)</strong>이 그 틈을 메웁니다. 비행기의 블랙박스를 떠올려 보세요. 추락을 막아 주진 않지만, 모든 걸 기록해서 조사관이 무슨 일이 있었는지 초 단위로 재구성할 수 있게 합니다. EDR은 모든 호스트에 달린 그런 기록 장치입니다. 그리고 블랙박스와 달리, 원격으로 조종간을 잡을 수도 있습니다.

### 무엇을 기록하나 { #edr-records }

EDR 에이전트(커널 드라이버 + 사용자 모드 서비스)는 이런 이벤트를 기록합니다. 전체 명령줄이 붙은 프로세스 생성·종료, 부모/자식 관계, 파일 생성·수정·삭제, 레지스트리 변경, 어느 프로세스가 연 건지가 붙은 네트워크 연결, DLL과 드라이버 로드, 서비스와 예약 작업 생성, 로그온, 그리고 한 프로세스가 다른 프로세스를 열거나 그 안에 쓰는 것 같은 수상한 메모리 동작. 이벤트마다 해시, 서명자 정보, 사용자와 무결성 수준, 그리고 프로세스와 묶는 ID가 붙습니다. 콘솔은 이 관계를 프로세스 트리와 타임라인으로 그려 줍니다.

EDR의 원시 텔레메트리나 내보내기에서 보게 될 프로세스 생성 기록을 단순하게 만들면 이렇습니다.

```json
{
  "event_type": "ProcessCreate",
  "timestamp": "2026-11-18T09:14:52.318Z",
  "device": { "name": "WS-FIN-0031", "os": "Windows 11 24H2" },
  "process": {
    "pid": 7412,
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...",
    "sha256": "9f2c...e41a",
    "signer": "Microsoft Windows",
    "user": "CORP\\m.lee",
    "integrity": "Medium"
  },
  "parent": {
    "pid": 5120,
    "name": "WINWORD.EXE",
    "command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\m.lee\\Downloads\\Invoice_4471.docm\""
  },
  "network_after": [
    { "remote_ip": "203.0.113.45", "remote_port": 443, "seconds_after_start": 2 }
  ]
}
```

- `event_type` / `timestamp` — 무슨 일이 언제(UTC) 있었나.
- `device` — 어느 호스트인지. 콘솔에서 여기서 그 PC의 다른 모든 것으로 넘어갈 수 있습니다.
- `process.name` / `path` — 원래 자리에 있는, Microsoft가 서명한 진짜 `powershell.exe`. 백신은 실행 파일 자체에서 아무 문제도 못 봅니다.
- `command_line` — 핵심. `-nop`(프로필 안 읽음), `-w hidden`(창 숨김), `-enc`(Base64로 인코딩한 UTF-16 명령). `SQBFAFgA`를 풀면 `IEX` — Invoke-Expression, 즉 "내려받은 글자를 코드로 실행해"입니다(T1059.001).
- `user` / `integrity` — 로그온한 사용자로, 중간 무결성 수준에서 돕니다. 아직 권한 상승 전입니다.
- `parent` — **`WINWORD.EXE`**가 `Downloads`의 매크로 문서를 열고 있습니다. Word가 PowerShell을 띄우는 건 악성 매크로의 대표적인 신호입니다(T1204.002 사용자 실행, T1566.001 피싱 첨부 파일).
- `network_after` — 2초 뒤 새 PowerShell이 `203.0.113.45:443`으로 연결합니다. 다음 단계를 내려받는 것일 가능성이 큽니다(T1105).

칸 하나만으로는 아무것도 증명되지 않지만, *Downloads의 문서 → Word → 숨긴 인코딩 PowerShell → 밖으로 나가는 연결*이라는 사슬은 오해할 수가 없습니다. 이런 관계 데이터가 EDR이 그냥 로그보다 더 주는 것입니다.

### "R": 대응 { #edr-response }

탐지는 가치의 절반입니다. 나머지 절반은 EDR이 보안팀에게 모든 호스트로 가는 별도의 인증된 통로를 준다는 점입니다.

- **호스트 격리(봉쇄)** — EDR 클라우드로 가는 것만 빼고 모든 네트워크를 끊습니다. 공격자는 C2를 잃지만, 우리는 조사 통로를 그대로 가집니다.
- **프로세스 종료, 파일 격리·삭제, 지속성 항목 제거.**
- 분석용 파일, 메모리, 분류용 묶음 **수집**.
- **라이브 대응(Live Response)** — 제한된 원격 셸이나 스크립트 실행.
- 해시나 지표를 전체 PC에서 **차단**.

"별도 통로"가 왜 중요할까요? 수상한 호스트를 조사하려고 도메인 관리자 계정으로 RDP 접속하면, 방금 PAW 부분에서 하지 말라고 한 바로 그 일 — 공격자가 장악했을지 모르는 PC에 관리자 자격 증명 올려놓기 — 을 한 겁니다. EDR 라이브 대응은 에이전트를 통해 에이전트 자신의 신원으로 돌기 때문에, 다시 쓸 수 있는 자격 증명이 호스트에 남지 않습니다. SOC에게 이건 힘을 몇 배로 키워 주는 도구입니다. 분석가 한 명이 수백 대에 걸친 사고 범위를 몇 분 안에 잡고 봉쇄할 수 있습니다.

### 공격자도 EDR을 안다 { #edr-evasion }

EDR의 눈을 가리려는 시도를 예상하세요. 에이전트 중지나 제거, 설정 변조, 클라우드로 가는 에이전트 통신 차단, 취약한 드라이버를 올려 커널에서 EDR을 죽이기(T1562.001, T1068). 방어와 신호: **변조 방지(Tamper Protection)** 켜기, 에이전트가 보고를 멈추면 경보(호스트는 네트워크에서 여전히 말하고 있는데 "센서 오프라인"이면 수상함), 새 커널 드라이버 경보(`.sys` 경로가 찍힌 7045, Sysmon 6), Microsoft의 취약 드라이버 차단 목록.

### XDR { #xdr }

<strong>XDR(Extended Detection and Response, 확장 탐지·대응)</strong>은 EDR의 생각을 더 많은 데이터로 넓힌 것입니다. 엔드포인트에 더해 이메일, 아이덴티티, 클라우드 워크로드, SaaS, 네트워크. 가치는 상관관계에 있습니다. 피싱 메일, 새 나라에서 온 사용자 로그인, 엔드포인트 프로세스 사슬, 클라우드 파일 다운로드가 네 콘솔의 서로 관계없는 경보 네 개가 아니라 하나의 사고로 보입니다. 실제로 "XDR"은 대부분 한 업체의 플랫폼(같은 업체의 EDR, 이메일, 아이덴티티 제품이 한 콘솔로 모이는 것)이고, 가끔 다른 업체 데이터를 더하기도 합니다. 엄격한 표준 정의는 없습니다.

## DLP — 민감한 데이터를 있어야 할 곳에 두기 { #dlp }

### 무엇을 위한 것인가 { #dlp-what }

<strong>DLP(Data Loss Prevention, 데이터 유출 방지)</strong>는 공격의 끝부분을 노립니다. 데이터가 어디 있는지 찾기(탐색), 모으기(수집), 내보내기(유출, TA0010). 크게 두 가지 형태가 있습니다.

- **네트워크 DLP**는 나가는 트래픽(웹 프록시, 이메일 게이트웨이, 때로는 SSL을 풀어 본 흐름)에서 민감한 내용을 찾습니다.
- **엔드포인트(호스트) DLP**는 장치의 파일과 사용자가 그걸로 하는 일을 지켜봅니다. USB로 복사, 브라우저 업로드, 웹 앱에 붙여 넣기, 인쇄, 이메일 전송, 개인 클라우드 폴더 동기화.

요즘 제품은 클라우드 앱(API나 CASB로)과, 점점 더 생성형 AI 프롬프트까지 다룹니다.

### 어떻게 판단하나 { #dlp-how }

DLP는 두 가지에 답해야 합니다. *이 데이터가 민감한가*, 그리고 *이 이동이 허용되는가*.

**민감한가**는 이렇게 판단합니다.

1. <strong>분류 등급(Classification Label)</strong> — 사용자가 붙이거나 자동으로 붙은 등급(`PROTECTED`, `OFFICIAL: Sensitive`, `Confidential – HR`)이 파일 메타데이터에 저장돼 있습니다.
2. <strong>내용 검사(Content Inspection)</strong> — 패턴(정규식 + 추가 확인), 키워드, 문서 지문(계약서 양식 같은 템플릿의 해시), 정확한 데이터 일치(실제 고객 표의 해시).

카드 번호 패턴을 보면 "추가 확인"이 왜 중요한지 알 수 있습니다.

```
\b(?:4\d{3}|5[1-5]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b
```

- `\b … \b` — 단어 경계. 더 긴 문자열의 일부가 아니게 합니다.
- `(?:4\d{3}|5[1-5]\d{2})` — 4(Visa 계열)나 51~55(Mastercard 계열)로 시작하고 숫자 세 개가 더 붙음.
- `[ -]?` — 묶음 사이에 공백이나 대시가 있어도 되고 없어도 됨.
- `\d{4}` ×3 — 나머지 숫자 묶음.

이것만으로는 주문 번호, 일련번호가 잔뜩 걸립니다. 실제 DLP 엔진은 **Luhn 체크섬** 검사(카드 번호에 들어 있는 검증 숫자)를 더하고, 근처에 키워드("card", "expiry", "CVV")가 있어야 한다는 조건을 걸고, **개수 기준**을 둡니다(1개 일치 = 아마 잡음, 한 파일에 500개 = 데이터 덤프). 세금 번호, 여권 번호, 건강 식별 번호 등도 같은 원리입니다.

**허용되는가**는 정책에서 나옵니다. "`PROTECTED` 등급 파일은 이동식 저장 장치로 복사하거나 회사 것이 아닌 클라우드에 올릴 수 없음, `OFFICIAL: Sensitive`는 경고하고 사유 입력 요구, 카드 번호 50개 초과면 차단하고 경보."

엔드포인트 DLP 경보를 단순하게 만들면 이렇습니다.

```
Alert: DLP policy match - "PII bulk to removable media"
Time:        2026-11-19T17:52:10Z
Device:      WS-HR-0142.corp.example
User:        CORP\s.kim
Activity:    FileCopiedToRemovableMedia
File:        C:\Users\s.kim\Documents\staff_export_2026.xlsx
Destination: E:\  (USB, VendorID 0x0781, Serial 4C53000123456789)
Label:       OFFICIAL: Sensitive
Matched:     Tax File Number x 1,248 ; Date of Birth x 1,251
Action:      Blocked (user override not permitted)
```

- `Activity FileCopiedToRemovableMedia` — 엔드포인트 에이전트가 가로챈 행동(T1052.001, USB를 통한 유출).
- `File` — 사용자의 Documents에 있는 직원 명단 내보내기 파일.
- `Destination` — USB 장치. 제조사 ID와 일련번호가 있어서 실제 USB를 특정하고, 다른 PC의 장치 연결 이벤트와 맞춰 볼 수 있습니다.
- `Label` — 파일에 이미 붙어 있던 분류 등급.
- `Matched` — 내용 검사 결과. 세금 번호 1,248개면 기록 한 건짜리 실수가 아니라 분명한 대량 개인정보입니다.
- `Action Blocked` — 복사는 일어나지 않았습니다. 그래도 분류해 볼 가치가 있습니다. 왜 인사팀 사용자가 퇴근 직전인 17시 52분에 직원 전체 명단을 USB로 옮기려 했을까요?

### 세 가지 쓰임새 { #dlp-use-cases }

- **악의 없는 내부자** — 가장 흔하고, DLP가 가장 잘하는 쪽입니다. 직원이 집에서 일하려고 스프레드시트를 개인 메일로 보내거나, 건강 기록을 암호화 안 된 USB에 담습니다. 팝업 하나("이 파일에는 민감한 개인정보가 있습니다 — 승인된 공유 폴더를 쓰세요")로 대부분 해결됩니다. 실수 방지와 정책 강제입니다.
- **악의 있는 내부자** — 퇴사 전에, 또는 팔려고 일부러 데이터를 훔치거나 망가뜨리거나 지우는 직원(T1052, T1567, T1485). DLP는 평소와 다른 양, 목적지, 시간에 경보를 냅니다. 인사 맥락(사직서, 성과 관리 절차)과 합치면 실제 사건이 이렇게 시작되는 경우가 많습니다.
- **악의 있는 외부자** — 계정을 장악하고 데이터를 모아서 내보내려는 공격자([옆으로 이동, 수집, 유출](../endpoint-attacks/lateral-collection-exfil.md) 참고). DLP가 뻔한 유출 경로를 막거나 표시할 수 있습니다.

### 한계 { #dlp-limits }

DLP는 두 가지만큼만 좋습니다. **분류**(등급도 없고 알아볼 패턴도 없는 데이터는 안 보임)와 **가시성**(암호화된 압축 파일, 자체 프로토콜, 스크린숏, 관리 안 되는 장치, 개인 휴대폰으로 화면 찍기). 데이터를 파일 이름까지 암호화한 비밀번호 압축 파일(`7z -mhe=on -p`)에 넣거나, 허용된 클라우드 서비스로 천천히 조금씩 빼내는 공격자는 대개 내용 검사를 통과합니다. 그래서 DLP는 벽이 아니라, 마음먹은 공격자를 *늦추고* 쓸 만한 신호(큰 암호화 압축 파일, 평소와 다른 업로드 양)를 만들어 주는 인계철선으로 보세요.

## UEBA — 평소와 다른 것 찾기 { #ueba }

### 생각의 출발점 { #ueba-idea }

DLP와 대부분의 SIEM 규칙은 "X가 일어나면 경보"라고 말합니다. <strong>UEBA(User and Entity Behavior Analytics, 사용자·개체 행동 분석)</strong>는 "평소에 무슨 일이 일어나는지 배운 다음, 다른 걸 알려 줘"라고 말합니다. "개체(Entity)"는 사용자만이 아니라 호스트, IP 주소, 서비스 계정, 애플리케이션, 장치도 포함합니다.

같은 건물에서 10년 일한 경비원은 규칙집이 없어도 항상 5시에 퇴근하는 회계 담당자가 새벽 2시에 서버실에 있으면 이상하다는 걸 압니다. 그게 UEBA입니다. "*이 사람*치고는 이상한데"를 자동화한 것입니다.

### 어떻게 돌아가나, 쉽게 { #ueba-how }

1. 활동을 **모은다**: 로그온(4624/4625), VPN과 클라우드 로그인, 파일 접근, 프로세스 실행, 프록시 로그, DLP 이벤트.
2. 개체마다, 그리고 <strong>동료 그룹(Peer Group)</strong>(역할이나 부서가 같은 사람들)마다 **기준선을 만든다**: 평소 시간대, 평소 호스트, 평소 나라, 평소 데이터 양, 평소 애플리케이션.
3. 새 활동에 통계로 **점수를 매긴다** — 기준선에서 얼마나 멀리 떨어졌나? "처음 있는 일"("이 사용자가 이 서버에 처음 로그온", "이 계정이 이 나라를 처음 사용")이 큰 비중을 차지합니다.
4. 한 개체에 생긴 작은 이상 여러 개를 하나의 위험 점수로 **합친다**. 이상한 일 하나는 넘어가지만, 한 시간에 다섯 개면 떠오릅니다.

UEBA 결과를 단순하게 만들면 이렇습니다.

```
Entity:         CORP\svc-backup (service account)
Risk score:     87 / 100   (baseline 5)
Time window:    2026-11-19 01:10 – 01:48 UTC
Anomalies:
  - Interactive logon (LogonType 10) - never seen for this account in 90 days
  - Logon to DC01.corp.example - first time; peer group (service accounts) 0 %
  - Source host WS-ENG-0077 - first time
  - Process: ntdsutil.exe - first time for this account
  - Outbound volume from WS-ENG-0077: 4.2 GB (baseline 50 MB/day)
```

- `Entity` — 백업 서비스 계정. 평소엔 예약된 작업만 돌리고 대화형으로 로그온하는 일이 없습니다.
- `Risk score 87 (baseline 5)` — 38분 안에 이상 여러 개가 쌓였습니다.
- 이상 한 줄 한 줄은 따로 보면 설명이 될 수도 있습니다. 하지만 모아 보면 이야기가 나옵니다. 훔친 서비스 계정(T1078.002)으로 RDP를 통해 도메인 컨트롤러에 가서 `ntdsutil`을 돌리고(아마 `NTDS.dit` 복사, T1003.003), 기가바이트 단위로 밖으로 보냈습니다. 바로 이게 UEBA가 잘하는 일입니다. 공격이 정상 자격 증명과 내장 도구만 썼으니 시그니처는 아무것도 안 울렸을 겁니다.

### 기저율 문제 { #ueba-base-rate }

핵심 가정은 "이상한 건 악성일 가능성이 더 높다"입니다. 맞는 말이지만, *더 높다*는 *높다*가 아닙니다. 계산해 봅시다. UEBA가 하루 10억 개 이벤트 중 99.999%를 정상으로 버려도, 1,000,000,000의 0.001%는 여전히 하루 **1만 건**입니다. 그리고 이상한 일 대부분은 무해합니다. 새 프로젝트, 조직 개편, 출장, 새 도구, 신입의 첫날, 월말 정비를 하는 관리자.

그래서 UEBA에는 이런 게 필요합니다. 점수가 의미를 갖기 전까지 과거 데이터로 배우는 **학습 기간**(흔히 몇 주), 알려진 무해한 패턴을 누르는 **다듬기**, 그리고 재무팀이 분기 말마다 대량 내보내기를 한다는 걸 아는, **업무 지식을 가진 분석가**. 이상은 들여다볼 이유이지 판결이 아닙니다. UEBA 점수는 단독 경보보다는 경보의 *우선순위를 정하고* *정보를 보태는* 데(이 사용자는 위험 점수도 87이다) 쓰세요.

## 감사 정책과 중앙 로그 수집 { #audit-logging }

### 왜 모든 것의 바닥인가 { #audit-why }

이 페이지의 모든 탐지 — PAW 로그온 규칙, 특권 사용 이벤트, DLP와 UEBA의 입력 — 는 두 가지에 달려 있습니다. 애초에 이벤트가 **기록**되는가, 그리고 그 기록이 분석될 때까지 **살아남는가**. 첫째는 <strong>감사 정책(Audit Policy)</strong>이, 둘째는 <strong>중앙 로그 수집</strong>(SIEM이나 로그 관리)이 맡습니다.

이벤트 로그는 감사 기록(audit trail)입니다. 누가, 무엇을, 언제, 어디서 바꿨나. 그런데 로그는 호스트에 있고, 관리자 권한을 가진 공격자는 지울 수 있습니다(`wevtutil cl Security`, T1070.001). Security 로그가 지워지면 Windows는 **1102**("감사 로그가 지워졌습니다")를 쓰고 지운 계정을 남깁니다. 하지만 공격자가 다른 짓을 하기 전에 그 이벤트가 호스트 밖으로 나갔을 때만 쓸모가 있습니다. 로그를 몇 초 안에 전달하는 것이 로그를 믿을 수 있게 만듭니다.

### Windows: 무엇이 기록되나 { #windows-audit-policy }

기본 상태의 Windows는 SOC에 필요한 것보다 훨씬 적게 기록합니다. 실제로 적용된 정책은 `auditpol`로 확인합니다.

```
C:\> auditpol /get /category:"Logon/Logoff","Detailed Tracking"
System audit policy
Category/Subcategory                      Setting
Logon/Logoff
  Logon                                   Success and Failure
  Logoff                                  Success
  Account Lockout                         Success
  Special Logon                           Success
  Other Logon/Logoff Events               No Auditing
Detailed Tracking
  Process Creation                        No Auditing
  Process Termination                     No Auditing
  DPAPI Activity                          No Auditing
  RPC Events                              No Auditing
```

- `auditpol /get /category:…` — 적힌 범주에 실제로 적용된 *고급* 감사 정책을 보여 줍니다(`/category:*`는 전부).
- `Logon … Success and Failure` — 4624와 4625가 기록됩니다. 좋습니다.
- `Special Logon Success` — 이게 **4672**를 만듭니다. 위의 PAW 탐지에 필요합니다.
- `Process Creation No Auditing` — 큰 구멍. 이게 없으면 **4688**이 없으니, Sysmon이나 EDR이 없는 한 어떤 프로그램이 돌았는지 기록이 없습니다. 켜세요. *그리고* 따로 있는 "프로세스 생성 이벤트에 명령줄 포함" 설정(관리 템플릿 → 시스템 → 프로세스 생성 감사)도 켜야 합니다. 안 그러면 4688에 인자 없이 `powershell.exe`만 찍힙니다.

SOC 기준으로 보통 켜는 다른 값진 하위 범주: 보안 그룹 관리(4728/4732/4756), 사용자 계정 관리(4720, 4722, 4738), 보안 시스템 확장(4697 서비스 설치), 기타 개체 액세스 이벤트(4698 예약 작업), Kerberos 인증 서비스와 서비스 티켓 작업(4768/4769), 그리고 PowerShell 스크립트 블록 로깅(4104). Security 로그의 최대 크기도 옛 기본값보다 훨씬 크게 늘려서, 로컬 로그가 몇 시간 만에 덮어써지지 않게 합니다.

Windows 이벤트 로깅이 어떻게 돌아가는지 — 채널, 공급자, XML 구조 — 는 다음 섹션인 "Windows 로그"의 주제입니다.

### Linux: syslog와 auditd { #linux-audit }

Linux에서는 syslog 데몬(rsyslog나 syslog-ng), systemd 저널, 커널 감사 시스템(`auditd`)이 같은 역할을 합니다. 작은 예 두 개입니다.

```
# /etc/audit/rules.d/soc.rules
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k priv_change
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmds
```

- `-w /etc/passwd -p wa -k identity` — 이 파일의 **쓰기**(w)와 **속성 변경**(a)을 감시하고, 걸린 기록에 `identity`라는 키를 붙여서 나중에 찾을 수 있게 합니다(`ausearch -k identity`).
- `-w /etc/sudoers -p wa -k priv_change` — sudo 설정(특권 변경)도 같게.
- `-a always,exit -F arch=b64 -S execve` — 64비트 `execve` 시스템 호출(모든 프로그램 실행)을 끝날 때 기록하는데…
- `-F euid=0 -F auid>=1000 -F auid!=unset` — …root로 돌고(`euid=0`), 실제로 로그인한 사람이 시작한 경우만(`auid`는 `sudo`/`su`를 거쳐도 그대로 남는 로그인 UID이고, 일반 사용자 번호여야 함). 시스템 데몬은 빼고, 사람이 root로 실행한 명령만 잡습니다.
- `-k root_cmds` — 검색 키.

```
# /etc/rsyslog.d/90-forward.conf
*.* @@siem.corp.example:6514
```

- `*.*` — 모든 facility, 모든 severity.
- `@@` — **TCP**로 전달(`@` 하나면 UDP라서 메시지가 소리 없이 빠질 수 있음). 6514번 포트는 관례상 TLS 위의 syslog인데, TLS 자체는 여기 안 보이는 추가 설정이 필요합니다.
- `siem.corp.example` — 중앙 수집기.

syslog 형식, facility, 저널은 이어지는 "Linux 로그" 섹션에서 다룹니다.

### SOC가 꼭 알아야 할 것 { #audit-soc }

분석가가 모든 감사 설정을 직접 하는 사람일 필요는 없지만, *무엇이 수집되고 무엇이 안 되는지*는 반드시 알아야 합니다. 이벤트가 *없다*는 건 그 이벤트가 기록됐을 경우에만 의미가 있기 때문입니다. "DC01에 `ntdsutil` 4688이 없다"는 그 서버에서 프로세스 생성 감사가 켜져 있고 로그가 실제로 도착했을 때만 증거가 됩니다. 짧은 수집 범위 지도를 갖고 있으세요. 어떤 로그 소스가, 어느 호스트에서, 어떤 정책으로, 얼마나 빨리 들어오는지. 애플리케이션과 장비 로그(웹 서버, VPN, 방화벽, 클라우드 감사 로그)도 그 지도에 들어가야 합니다.

## 심층 방어 — 정리 { #defence-in-depth-summary }

방어 수단을 공격 단계에 맞춰 늘어놓으면 이 섹션 전체의 요점이 보입니다.

| 단계 | 엔드포인트의 덫 |
| --- | --- |
| 전달 / 익스플로잇 | 패치, 익스플로잇 보호, ASR, 백신, 브라우저와 Office 하드닝 |
| 설치 | 애플리케이션 제어, FIM, 백신, 지속성 감시, 권한 |
| 권한 상승 / 자격 증명 접근 | 올바른 ACL과 특권, LSA 보호, Credential Guard, PAW와 계층화 |
| C2 | 호스트 방화벽, EDR 네트워크 텔레메트리, 나가는 방향 필터링 |
| 최종 목표 행동 | DLP, UEBA, EDR, 감사 로깅 |

완벽한 덫은 하나도 없고, 그게 목표도 아닙니다. 덫 하나하나가 공격자를 느리게 하거나, 더 조용한 기법을 고르게 하거나, 위험을 감수하게 만듭니다. 덫이 많을수록 공격자는 느려지고, 느려질수록 우리는 경보를 울리는 그 한 번의 실수를 알아챌 시간이 늘어납니다. 그리고 쫓아내기 전에 그들이 낼 수 있는 피해도 줄어듭니다. 공격자가 멀리 갈수록 피해가 커지니, 일찍 잡는 게 마지막 단계에서 잡는 것보다 훨씬 쌉니다. 그래서 모든 방어선은 **막는** 동시에 중앙 로그에 **증거를 남겨야** 합니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    관리자 계정 분리와 관리 전용 장치, 깨끗한 출발점 원칙, "아래로는 로그온하지 않기", ACL 권한과 특권의 차이와 `SeDebug`/`SeBackup`/`SeRestore`/`SeLoadDriver`/`SeImpersonate`의 위험, 기록 장치 + 원격 대응 통로로서의 EDR, DLP가 분류와 가시성에 달려 있다는 점, UEBA의 기저율 문제, 탐지의 바닥으로서의 중앙 로그 수집 — 모두 그대로입니다. 이벤트 ID 4624, 4672, 4673/4674, 4688, 1102, 7045도 바뀌지 않았습니다.

!!! info "[변경됨] 바뀐 점"
    - **EDR은 이제 기본이고, 시장은 합쳐졌다.** EDR과 함께 이름이 오르던 여러 업체가 주인이 바뀌었습니다. Panda Security는 WatchGuard의 일부가 됐고, Carbon Black은 Broadcom 아래에 있으며, 2025년에는 MSSP인 LevelBlue가 Cybereason을 인수했습니다. 이제 대부분의 조직은 EDR을 따로 사기보다 더 넓은 XDR이나 관리형 탐지·대응(MDR) 서비스 안에서 삽니다.
    - **2024년 7월 보안 에이전트 업데이트 오류로 생긴 전 세계 장애 이후**, Microsoft는 Windows Resiliency Initiative를 시작하고, 백신/EDR 업체가 코드의 더 많은 부분을 커널 밖에서 돌릴 수 있는 Windows 엔드포인트 보안 플랫폼을 발표했습니다(2025년). 실제 적용은 업체가 따라오느냐에 달렸으니, 짐작하지 말고 우리 업체가 무엇을 지원하는지 확인하세요.
    - **SIEM, XDR, UEBA가 합쳐지는 중.** Microsoft Sentinel은 통합 Defender 포털로 옮겨 가고 있고(Azure 포털 화면은 Microsoft가 2027년으로 미룬 일정에 따라 은퇴 예정), 원시 로그를 행동 단위로 요약해 주는 AI 보조 UEBA "behaviors" 계층을 더했습니다. 다른 업체들도 UEBA를 SIEM/XDR에 묶어 넣어서, 이제 UEBA는 따로 사는 제품이라기보다 기능 하나인 경우가 많습니다.
    - **DLP가 생성형 AI까지 다룬다.** 엔드포인트와 브라우저 DLP 정책이 사용자가 AI 도우미나 웹 AI 앱에 붙여 넣거나 올리는 내용을 검사할 수 있고, Microsoft Purview는 Microsoft 365 Copilot 프롬프트용 DLP를 더했습니다. "챗봇에 민감한 데이터 붙여 넣기"는 2026년 DLP의 대표 쓰임새입니다.
    - **특권 접근은 클라우드와 아이덴티티 중심으로.** Microsoft 안내는 PAW를 특권 접근 전략(엔터프라이즈 접근 모델) 안에서, 클라우드로 관리하는 장치, 필요할 때만 올려 주는 권한(Entra PIM), 관리자용 피싱 저항 MFA와 함께 설명합니다. 이제 tier 0에는 클라우드 아이덴티티 평면 — Entra 전역 관리자, 아이덴티티 동기화 서버, 장치 관리 콘솔 — 도 들어갑니다.
    - **Sysmon이 Windows 내장 기능이 되는 중**(2026년 Windows 11과 Server 2025에 배포 시작). 다른 업체 설치 없이 풍부한 프로세스·네트워크·레지스트리 텔레메트리를 얻기 쉬워졌지만, 여전히 설정과 수집이 필요합니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **PAW를 평소 데스크톱 위의 VM으로 돌리지 마세요.** 평소 OS가 호스트면, 그게 뚫릴 때 PAW도 뚫립니다. PAW가 호스트(또는 별도 장치)여야 합니다.
    - **수상한 호스트를 도메인 관리자 계정으로 RDP 접속해서 조사하지 마세요.** EDR 라이브 대응이나 전용으로 제한된 사고 대응 계정을 씁니다. 안 그러면 공격자에게 자격 증명을 건네주는 셈입니다.
    - **`whoami /priv`의 "Disabled"를 "안전"으로 읽지 마세요.** 특권은 가지고 있고, 호출 한 번이면 켜집니다.
    - **백업, 하이퍼바이저, EDR 콘솔을 평범한 tier 1/2로 대하지 마세요.** DC 스냅숏을 찍거나, 모든 파일을 읽거나, EDR 콘솔로 모든 엔드포인트에서 스크립트를 돌릴 수 있는 사람은 사실상 tier 0입니다.
    - **DLP를 유출을 막는 벽으로 믿지 마세요.** 암호화 압축 파일과 허용된 서비스를 통한 느린 업로드는 통과합니다. 네트워크 감시와 UEBA를 같이 씁니다.
    - **UEBA 이상을 곧바로 사고로 올리지 마세요.** 우선순위와 정보 보태기에 쓰고, 학습 기간이 끝나기 전에는 쓸 만한 점수를 기대하지 마세요.
    - **보안 로그를 그냥 UDP syslog로 보내지 말고**, 프로세스 생성 감사나 명령줄 옵션을 꺼 둔 채로 두지 마세요. 1102와 에이전트 오프라인 이벤트에는 즉시 경보가 울리게 합니다.

## 확인 문제 { #quiz }

### 문제 1

SIEM에 `WS-HR-0142`에서 `TargetUserName adm-r.choi`, `LogonType 10`, `IpAddress 10.20.4.91`인 4624가 보이고, 같은 로그온 ID의 4672가 뒤따릅니다. `adm-r.choi`는 Domain Admins 구성원입니다. `10.20.4.91`은 r.choi가 평소 쓰는 노트북입니다. 어떤 규칙 두 개가 깨졌고, 위험은 무엇이며, 다음에 무엇을 확인하겠나요?

??? success "정답과 해설"
    **깨진 규칙 두 개:** (1) 특권 계정을 PAW가 아니라 평소 노트북에서 썼습니다. 즉 메일을 읽고 웹을 돌아다니는 PC에서 자격 증명을 입력했습니다. (2) tier 0 계정이 RDP로 tier 2 PC(인사팀 PC)에 *아래로* 로그온했습니다. 이러면 그 PC의 LSASS에 다시 쓸 수 있는 자격 증명 재료가 남습니다. 같은 로그온 ID의 4672는 그 세션이 관리자급 특권을 가졌다는 걸 확인해 줍니다.

    **위험:** 노트북(키로깅, 토큰 탈취, T1056.001)이나 인사팀 PC(LSASS 덤프, T1003.001) 중 하나라도 뚫려 있거나 뚫리면, 공격자는 도메인 관리자를 얻고 해시/티켓 전달(T1550.002/.003)로 다시 씁니다. 애초에 r.choi가 아니었을 수도 있습니다. 훔친 관리자 계정이 딱 이렇게 보입니다.

    **다음 확인:** r.choi 본인(과 변경 일정)에게 본인이 한 건지 확인, 그 시간 전후 두 PC의 EDR/4688에서 수상한 프로세스 확인, 특히 `WS-HR-0142`에서 `lsass.exe`를 연 것(Sysmon 10), 최근 며칠 전체 환경에서 `adm-r.choi`의 다른 로그온 찾기, 조금이라도 의심스러우면 계정 비밀번호를 바꾸고 세션과 Kerberos 티켓을 끊고, 두 호스트를 노출됐을 수 있는 것으로 대합니다. 장기적으로는 GPO/인증 정책으로 특권 그룹의 PC 로그온을 거부하고, 위반마다 경보를 겁니다.

### 문제 2

헬프데스크 계정이 "사용자 파일을 복원할 수 있도록" **Backup Operators** 구성원입니다. 멤버 서버의 4688 이벤트에서 그 계정이 실행한 `reg.exe save HKLM\SAM C:\Users\Public\s.hiv`와 `reg.exe save HKLM\SYSTEM C:\Users\Public\y.hiv`가 보이고, 이어서 서버에서 한 PC로 나가는 SMB 연결이 있습니다. 이 계정은 로컬 관리자가 아닙니다. 어떻게 이게 가능했고, 공격자는 무엇을 얻었으며, 무엇을 바꾸겠나요?

??? success "정답과 해설"
    **어떻게:** Backup Operators는 **`SeBackupPrivilege`**(와 `SeRestorePrivilege`)를 가집니다. 백업 특권은 *백업 목적으로* 아무 파일이나 레지스트리 하이브를 읽게 해 주고, 평소에 관리자가 아닌 계정을 SAM에서 막는 ACL을 건너뜁니다. 그래서 관리자가 아니어도 `reg save`가 됩니다. SAM을 통한 자격 증명 접근, **T1003.002**입니다.

    **얻은 것:** SAM 하이브에는 그 서버 *로컬* 계정의 NT 해시가 있고, SYSTEM 하이브에는 그걸 푸는 데 필요한 부트 키가 있습니다. 둘을 밖으로 복사했으니(나가는 SMB 연결), 공격자는 오프라인으로 로컬 Administrator 해시를 뽑을 수 있습니다. 다른 서버들의 로컬 관리자 비밀번호가 같다면(LAPS 없음), 그 해시는 해시 전달(T1550.002)로 어디서든 통합니다. 도메인 컨트롤러였다면 같은 특권으로 `NTDS.dit` — 도메인의 모든 해시 — 를 복사할 수 있었습니다.

    **바꿀 것:** 헬프데스크 계정을 Backup Operators에서 빼고, 파일 복원은 전용 도구나 공유 권한 위임으로 대신합니다. 내장 Operators 그룹은 비워 둡니다. 백업/복원/디버그/드라이버 특권이 있는 계정은 모두 특권 계정으로 대합니다(PAW, 계층화, 감시). LAPS로 로컬 관리자 비밀번호를 서로 다르게 만듭니다. 알려진 백업 작업이 아닌 SAM/SECURITY/SYSTEM `reg save`에 경보를 겁니다.

### 문제 3

팀장이 이렇게 제안합니다. "EDR 갱신 대신 UEBA를 사자. 어차피 UEBA가 이상한 건 다 찾아 줄 거야." 각 도구가 실제로 하는 일을 근거로, 이게 나쁜 거래인 이유 세 가지를 말해 보세요.

??? success "정답과 해설"
    아래 중 세 가지면 됩니다.

    - **데이터가 다르다.** EDR은 자세한 호스트 활동 — 전체 명령줄, 부모/자식 프로세스 사슬, 프로세스와 묶인 파일·레지스트리·네트워크 이벤트 — 을 기록합니다. UEBA는 넣어 주는 로그로만 일하고, 대개 요약된 것(로그온, 로그인, 파일 접근)입니다. EDR(또는 잘 설정한 Sysmon과 감사 로그)이 없으면 UEBA에는 "Word → 숨긴 인코딩 PowerShell → 밖으로 나가는 연결" 같은 분석 재료가 없습니다.
    - **대응이 없다.** EDR의 "R" — 호스트 격리, 프로세스 종료, 파일 수집, 관리자 자격 증명을 드러내지 않는 라이브 대응 — 에 해당하는 게 UEBA에는 없습니다. UEBA는 *뭔가 이상하다*고 말해 줄 뿐, 아무것도 봉쇄하지 못합니다.
    - **기저율 문제.** UEBA는 이상을 표시하고, 이상 대부분은 무해합니다. 10억 이벤트의 0.001%도 1만 건입니다. 학습 기간과 다듬기가 필요하고, 그 이상이 악성인지 가리려면 분석가에게 여전히 EDR 수준의 상세 정보가 필요합니다.
    - **이미 알려진 나쁜 짓을 놓친다.** 그 사용자의 평소 활동처럼 보이는 공격(평소 PC에서 오전 10시에 도는 피싱 페이로드)은 UEBA 점수가 낮을 수 있지만, EDR의 행위 탐지와 차단은 악성 기법 자체를 잡습니다.
    - **심층 방어.** 둘은 다른 단계를 겨냥한 서로 보완하는 방어선입니다. EDR은 실행, 지속성, 권한 상승, C2 전반, UEBA는 주로 정상 계정 오용과 내부자 활동. 하나를 다른 것으로 바꾸면 덫이 늘어나는 게 아니라 하나가 사라집니다.

## 관련 레퍼런스 { #related }

- [애플리케이션 제어, 파일 무결성 모니터링, 지속성 잡기](appcontrol-fim-persistence.md) — 앞 방어선 · [Credential Guard, Application Guard, 호스트 방화벽, 백신](vbs-firewall-antivirus.md) · [자산 목록, 취약점 스캔, 패치, 익스플로잇 보호](inventory-vulns-patching.md)
- [권한 상승](../endpoint-attacks/privilege-escalation.md) · [자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) · [옆으로 이동, 수집, 유출](../endpoint-attacks/lateral-collection-exfil.md)
- [LSASS 자격증명 덤프](../../../adversary/lsass-dumping.md) · [SAM, LSA Secrets 및 NTDS.dit 추출](../../../adversary/sam-ntds-extraction.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [토큰 가장과 Potato 공격](../../../adversary/token-impersonation-potato.md)
- [방어 무력화와 로그 삭제](../../../adversary/impair-defenses-log-clearing.md) · [Windows 이벤트 로그 (EVTX)](../../../windows/event-logs.md) · [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
