---
title: "애플리케이션 제어, 파일 무결성 모니터링, 지속성 잡기 — 아는 프로그램만 돌게, 바뀌면 바로 알게"
tags:
  - training
  - blue-team
  - endpoint
  - hardening
  - application-control
  - fim
  - persistence
---

# 애플리케이션 제어, 파일 무결성 모니터링, 지속성 잡기 — 아는 프로그램만 돌게, 바뀌면 바로 알게 { #appcontrol-fim-persistence }

!!! abstract "이 페이지에서 다루는 것"
    공격자가 자기 코드를 실행하고 재부팅 뒤에도 살아남게 만드는 *설치* 단계를 노리는 세 가지 방어입니다. 첫째, 애플리케이션 제어(허용 목록). "목록에 있는 것만 실행"이 왜 백신이 놓치는 처음 보는 악성코드까지 잡는지, 규칙 종류(이름, 경로, 게시자/서명, 해시)와 각각의 강도, 감사 모드 vs 강제 모드, Windows(AppLocker, App Control for Business)·macOS(Gatekeeper)·Linux(AppArmor/SELinux, fapolicyd)의 내장 기능, 그리고 차단·감사 이벤트 읽는 법. 둘째, 공격자가 이걸 피해 가는 방법 — 스크립트, 시스템에 원래 있는 프로그램 악용, 코드 인젝션, 쓰기 가능한 허용 경로, 이름 바꾸기, 훔친 서명 키, 해시 충돌 — 과 각 우회가 SOC에 남기는 흔적. 셋째, 파일 무결성 모니터링(FIM). 무엇을 검사하는지, 웹 셸을 심는 순간을 어떻게 잡는지, AIDE와 에이전트 경보를 한 줄씩. 마지막으로 지속성 잡기. 흔한 자동 시작 지점(ASEP), 권한 수준에 따라 공격자가 쓸 수 있는 지점이 어떻게 달라지는지, Autoruns로 찾는 법. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름, 해시는 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. <strong>애플리케이션 제어(Application Control, 허용 목록 Allowlisting)</strong>는 백신의 질문을 뒤집는다. 백신은 "이게 *나쁜* 목록에 있나?"를 묻고, 애플리케이션 제어는 "이게 *좋은* 목록에 있나?"를 묻는다. 승인되지 않은 건 전부 막거나 보고한다 — 아무도 본 적 없는 악성코드까지.
2. 이건 파일이 들어오는 걸 막는 게 아니라 **실행**을 막는다. 악성코드는 여전히 다운로드되고 디스크에 써질 수 있다. 다만 *실행*이 안 될 뿐이다. 좋은 제품은 스크립트, 설치 패키지(MSI), DLL도 다룬다. 다루지 않으면 바로 그 틈이 공격자의 입구다.
3. <strong>감사 모드(Audit Mode)</strong>는 막지 않고 "막았을 것"만 보고한다. 강제하기 전에 우리 환경을 배우려면 꼭 필요하고, 끝까지 강제하지 않더라도 감사 이벤트 자체가 "모르는 프로그램이 여기서 돌았다"를 알려 주는 훌륭한 센서다.
4. 규칙 종류마다 강도가 크게 다르다. **파일 이름**(가장 약함 — 이름만 바꾸면 끝), **경로**(그 폴더의 쓰기 권한만큼만 강함), **게시자/서명**(서명 키를 훔치지 않는 한 강함), **해시**(가장 강하지만 업데이트마다 깨짐).
5. 대표적인 우회는 **스크립트**(T1059), **믿을 만한 시스템 프로그램을 발사대로 쓰기** — 리빙 오프 더 랜드(T1218), **이미 허용된 프로세스에 코드 주입**(T1055), **허용됐지만 쓰기 가능한 경로의 파일 덮어쓰기**(T1574), **이름 바꾸기**(T1036.005), **서명된 악성코드**(T1553.002)다. 각각 다른 흔적을 남긴다.
6. <strong>파일 무결성 모니터링(FIM, File Integrity Monitoring)</strong>은 정해 둔 파일·폴더의 기준 상태(해시, 크기, 소유자, 권한, 어떤 파일이 있는지)를 기록해 두고 무엇이든 바뀌면 경보를 낸다. 바뀌는 일이 드물고 바뀌면 의미가 있는 곳에서 특히 좋다. 시스템 실행 파일, 웹 루트(웹 셸, T1505.003), 시작 위치, `hosts` 파일.
7. <strong>지속성(Persistence)</strong>은 권한에 달려 있다. 일반 사용자는 *자기* Run 키, 시작 프로그램 폴더, 예약 작업만 건드릴 수 있고, 관리자나 root는 서비스, 시스템 전체 작업, 드라이버, 루트킷까지 넣을 수 있다. 흔한 ASEP는 Run 키/시작 프로그램 폴더(T1547.001), 서비스(T1543.003), 예약 작업(T1053.005), 브라우저 확장(T1176.001), 그리고 그냥 훔친 정상 계정(T1078)이다.
8. **Autoruns**(Sysinternals)는 수백 개의 ASEP를 서명 확인, 선택적으로 평판 확인까지 해서 보여 준다. PC 한 대를 빠르게 점검하는 가장 쉬운 방법이다. 전체 PC를 보려면 같은 생각을 계속 돌아가는 로그(Sysmon/EDR의 레지스트리·파일 이벤트, 서비스·작업 생성 이벤트)로 바꾸고 *새로 생긴* 항목에 경보를 건다.

## 애플리케이션 제어 — 아는 프로그램만 실행되게 { #application-control }

### 왜 이게 그렇게 값진가 { #why-app-control }

백신이 어떻게 일하는지 떠올려 봅시다. 수배자 사진첩을 들고 들어오는 사람마다 얼굴을 대조합니다. 아직 아무도 사진을 찍지 못한 범인은 그냥 걸어 들어옵니다. <strong>애플리케이션 제어</strong>는 비공개 행사의 초대 명단과 같습니다. 문지기는 당신이 수배자인지 아닌지 신경 쓰지 않습니다. 명단에 이름이 없으면 못 들어옵니다. 질문 하나를 바꾼 것뿐인데 그래서 효과가 큽니다. 한 시간 전에 우리 조직만을 노리고 만든 새 악성코드라도 걸리려면 조건이 딱 하나면 됩니다. *승인 목록에 없다.*

기술적으로 보면, 애플리케이션 제어는 운영체제가 프로세스를 만들거나 코드를 메모리에 올리려는 바로 그 순간에 끼어듭니다. 코드가 돌기 전에 OS(또는 에이전트의 드라이버)가 파일을 정책 규칙과 비교합니다. 허용 규칙이 있으면 실행, 없으면 차단(강제 모드)하거나 허용하되 기록(감사 모드)합니다.

여기서 두 가지가 바로 따라 나옵니다.

- 파일이 들어오는 건 **막지 않습니다.** 피싱 첨부 파일은 여전히 저장되고, 드로퍼는 여전히 `%TEMP%`에 `update.exe`를 쓸 수 있습니다. 애플리케이션 제어는 그게 *실행*돼도 되는지만 정합니다. 그래서 파일 쓰기를 알아채는 FIM이나 EDR과 짝을 이루면 좋습니다.
- 다루라고 한 것만 다룹니다. 사고 대부분에 어느 시점엔가 실행 파일이 끼어 있으니 `.exe`만 막아도 많이 걸러집니다. 하지만 좋은 정책은 **스크립트**(PowerShell, VBScript, JScript), **설치 패키지**(`.msi`), 가능하면 **DLL**과 **드라이버**까지 다룹니다. 빠뜨린 종류 하나하나가 열린 문입니다.

보안 기준들도 이걸 늘 상위에 둡니다. CIS Controls v8.1에서는 세부 항목 2.5(승인된 소프트웨어 허용 목록), 2.6(승인된 라이브러리 허용 목록), 2.7(승인된 스크립트 허용 목록)이 전부 이 이야기입니다. 호주 Essential Eight도 완화 전략 목록 맨 앞에 애플리케이션 제어를 둡니다.

### 규칙 네 종류 — 각각 얼마나 강한가 { #rule-types }

규칙이 "이 프로그램"을 무엇으로 알아보느냐가 속이기 쉬운 정도를 정합니다. 손님 확인에 비유하면, **이름만** 묻기(누구나 "저 김 씨예요"라고 할 수 있음), **어느 문으로 들어왔나** 보기(누가 옆문을 열어 두지 않는 한 괜찮음), **믿을 만한 기관이 발급한 신분증** 보기(신분증 발급처 자체가 털리지 않는 한 강함), **지문** 보기(위조가 거의 불가능하지만, 사람이 바뀔 때마다 다시 등록해야 함)입니다.

| 규칙 종류 | 무엇으로 맞추나 | 강도 | 실무 문제 |
| --- | --- | --- | --- |
| 파일 이름 | `chrome.exe` | 아주 약함 — 악성코드 이름만 바꾸면 됨 | 거의 쓰면 안 됨 |
| 경로 | `C:\Program Files\*` | 그 폴더의 쓰기 권한만큼 강함 | 사용자가 거기 쓸 수 있으면 무너짐 |
| 게시자/서명 | 코드 서명 인증서(게시자, 제품, 버전) | 강함 | 그 게시자가 서명한 *모든 것*을 믿음 — 취약하거나 악용 가능한 도구까지 |
| 해시 | 파일의 SHA-256 | 가장 강함 | 업데이트마다 해시가 바뀌어 규칙을 계속 고쳐야 함 |

실제 정책은 섞어 씁니다. 잘 알려진 서명 소프트웨어(Microsoft, 브라우저 회사, 업무용 소프트웨어 회사)는 게시자 규칙, 일반 사용자가 쓸 수 없는 폴더(`C:\Windows`, `C:\Program Files`)만 경로 규칙, 서명이 없는 소수의 사내 도구는 해시 규칙.

경로 규칙의 고전적인 함정이 있습니다. 재무팀 보고서 도구가 `C:\Tools`에 있어서 `C:\Tools\*`를 허용했는데, 그 폴더를 만든 설치 프로그램이 `Users`에게 수정 권한을 줘 버린 경우입니다. 이러면 모든 사용자 — 그리고 사용자 한 명을 피싱한 공격자 모두 — 가 허용된 폴더에 아무거나 넣을 수 있습니다.

```
C:\> icacls C:\Tools
C:\Tools BUILTIN\Administrators:(OI)(CI)(F)
         NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Users:(OI)(CI)(M)

Successfully processed 1 files; Failed processing 0 files
```

- `icacls C:\Tools` — 폴더의 접근 제어 목록(ACL, Access Control List)을 보여 줍니다.
- `BUILTIN\Administrators:(OI)(CI)(F)` — 관리자는 모든 권한(`F`, Full)이 있고, 그 권한이 안의 파일(`OI`, 개체 상속)과 하위 폴더(`CI`, 컨테이너 상속)로 내려갑니다. 정상입니다.
- `NT AUTHORITY\SYSTEM:(OI)(CI)(F)` — SYSTEM도 같습니다. 정상입니다.
- `BUILTIN\Users:(OI)(CI)(M)` — **모든 사용자에게 수정(`M`, Modify: 읽기·쓰기·삭제) 권한**이 있습니다. 이게 발견 사항입니다. `C:\Tools\*`를 허용하는 경로 규칙은 사실상 "사용자 누구든 여기 쓴 건 다 허용"이 됩니다.

고치는 방법은 `Users`의 쓰기 권한을 빼거나, 경로 규칙을 게시자·해시 규칙으로 바꾸는 것입니다.

### 먼저 감사, 그다음 강제 { #audit-vs-enforce }

실제 조직에서 첫날부터 강제 모드를 켜면 뭔가가 꼭 깨집니다. IT가 몰랐던 급여 프로그램, 엔지니어링 팀의 스크립트, 프린터 드라이버 도우미 같은 것들이요. 그래서 애플리케이션 제어는 보통 단계별로 깝니다.

1. **목록 만들기와 감사.** 처음 정책을 만들고(흔히 기준이 되는 "골든" PC와 [인벤토리 페이지](inventory-vulns-patching.md#inventory-systems)에서 본 소프트웨어 목록을 바탕으로), **감사 모드**로 배포해서 "막았을 것" 이벤트를 몇 주 동안 모읍니다.
2. **다듬기.** 감사 이벤트 하나하나는 규칙이 필요한 정상 소프트웨어이거나, 아예 있으면 안 되는 무언가입니다. 후자는 그 자체로 SOC의 단서입니다.
3. **강제**를 순서대로. 위험이 크고 쓰는 프로그램이 단순한 그룹(키오스크, 역할이 고정된 서버, 관리자 전용 PC)부터, 일반 데스크톱은 나중에.

**[보충] 감사 모드 자체가 탐지 도구다.** 끝내 강제 모드까지 못 가는 조직이라도 감사 이벤트를 SIEM으로 보낼 수 있습니다. 변화가 적은 환경에서 "정책에 없는 실행 파일이 `C:\Users\<user>\AppData\Local\Temp\`에서 실행됨"은 양이 적고 신뢰도는 높은 경보입니다. 정책을 만드는 수고는 똑같고, 다른 건 마지막 스위치를 켜느냐뿐입니다.

### 운영체제별 내장 기능 { #built-in-options }

**Windows**에는 내장 엔진이 둘 있습니다.

- **AppLocker** — 오래된 쪽(Windows 7 / Server 2008 R2부터). 실행 파일, Windows Installer 파일, 스크립트, DLL, 패키지(스토어) 앱에 대해 경로·게시자·해시 규칙을 만들고, 규칙을 특정 사용자나 그룹에만 적용할 수 있습니다. **Application Identity** 서비스(`AppIDSvc`)가 강제하므로, 그 서비스가 돌고 있어야 합니다.
- **App Control for Business** — 새로운 쪽. 예전 이름은 <strong>Windows Defender 애플리케이션 제어(WDAC, Windows Defender Application Control)</strong>입니다. 커널의 코드 무결성(Code Integrity) 구성 요소가 강제하고, 드라이버와 사용자 모드 코드를 모두 다루며, 평판(Intelligent Security Graph)과 관리형 설치 관리자(managed installer)를 쓸 수 있고, 정책은 PC 전체에 적용됩니다. Microsoft가 새로 도입할 때 권하는 엔진입니다. AppLocker도 여전히 지원되지만 새 기능은 그쪽으로 가지 않습니다.

**macOS**에는 **Gatekeeper**가 있습니다. 인터넷에서 받은 앱이 처음 실행될 때 확인된 개발자가 서명했는지, Apple의 <strong>공증(Notarization)</strong>을 받았는지 확인하고, 아니면 사용자에게 묻습니다. 조직이 정하는 허용 목록이라기보다는 평판·서명 관문입니다. macOS에서 엄격한 허용 목록을 하려면 보통 MDM 정책과 서드파티 도구를 함께 씁니다.

**Linux** 기본 시스템에는 "허용 목록" 스위치 하나가 따로 없지만, 비슷한 재료가 있습니다.

- **AppArmor**(Ubuntu, SUSE)와 **SELinux**(Red Hat 계열)는 <strong>강제 접근 제어(MAC, Mandatory Access Control)</strong> 시스템입니다. "이 프로그램이 실행돼도 되나?"가 아니라 "이 프로그램은 이 자원만 읽고, 쓰고, 실행할 수 있다"를 정합니다. 갇힌(confined) 웹 서버가 익스플로잇을 당해도, 프로필이 막으면 `/bin/bash`를 실행하거나 자기 폴더 밖에 쓰지 못합니다. 방식은 다르지만 얻는 이점은 상당 부분 같습니다.
- **fapolicyd**(Red Hat 계열)는 진짜 애플리케이션 허용 목록에 더 가깝습니다. 신뢰 데이터베이스(기본값은 시스템 패키지로 설치된 파일)를 기준으로 어떤 파일이 실행될 수 있는지 정합니다.
- 그 외에는 Linux에서 엄격한 허용 목록을 하려면 보통 서드파티 에이전트를 씁니다.

### 이벤트는 어떻게 생겼나 { #app-control-events }

**AppLocker**는 `응용 프로그램 및 서비스 로그 → Microsoft → Windows → AppLocker`에 기록하고, 규칙 묶음마다 채널이 따로 있습니다. 가장 자주 보는 ID는 이렇습니다.

| 채널 | 허용 | 감사("막았을 것") | 차단 |
| --- | --- | --- | --- |
| EXE and DLL | 8002 | 8003 | 8004 |
| MSI and Script | 8005 | 8006 | 8007 |

차단된 실행 파일 하나를 이벤트 XML의 `UserData` 부분까지 보면 이렇습니다(줄임, 가상 값).

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-AppLocker" />
    <EventID>8004</EventID>
    <TimeCreated SystemTime="2026-11-18T23:41:07.5512Z" />
    <Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel>
    <Computer>WS-FIN-0412.corp.example</Computer>
    <Security UserID="S-1-5-21-1111111111-2222222222-3333333333-4120" />
  </System>
  <UserData>
    <RuleAndFileData>
      <PolicyNameBuffer>EXE</PolicyNameBuffer>
      <RuleId>{00000000-0000-0000-0000-000000000000}</RuleId>
      <RuleNameBuffer>-</RuleNameBuffer>
      <RuleSddlBuffer>-</RuleSddlBuffer>
      <TargetUser>S-1-5-21-1111111111-2222222222-3333333333-4120</TargetUser>
      <TargetProcessId>9184</TargetProcessId>
      <FilePath>%OSDRIVE%\USERS\J.PARK\APPDATA\LOCAL\TEMP\INVOICE_VIEWER.EXE</FilePath>
      <FileHash>3F1C...9A0E</FileHash>
      <Fqbn>-</Fqbn>
    </RuleAndFileData>
  </UserData>
</Event>
```

- `EXE and DLL` 채널의 `EventID 8004` — 실행 파일이 **차단**됐다는 뜻입니다. (8003이면 감사 모드: 실행은 됐지만 "막았을 것"으로 기록됨.)
- `Computer` / `Security UserID` / `TargetUser` — 어느 PC에서, 어느 사용자 세션이 실행하려 했는지. SID는 SIEM에서 사용자 이름으로 바꿔 봅니다.
- `PolicyNameBuffer EXE` — 적용된 규칙 묶음.
- `RuleId {00000000-…}`와 `RuleNameBuffer -` — **맞는 규칙이 없었다**는 뜻입니다. 암묵적 차단은 이렇게 생겼습니다. 그냥 목록에 없었던 거죠. (허용된 8002 이벤트라면 맞은 규칙의 GUID와 이름이 보입니다.)
- `FilePath …\APPDATA\LOCAL\TEMP\INVOICE_VIEWER.EXE` — 사용자 임시 폴더에 있는 "청구서 뷰어" 실행 파일. 이메일 첨부나 압축 파일에서 풀려 나온 것의 전형적인 모습입니다.
- `FileHash` — 파일의 SHA-256. 다른 PC나 평판 서비스에서 찾아볼 때 쓰는 열쇠입니다.
- `Fqbn -` — 완전한 바이너리 이름(Fully Qualified Binary Name). 서명에서 나온 게시자, 제품, 버전이 들어가는 칸인데 대시면 **서명이 없다**는 뜻입니다.

합쳐 읽으면: 임시 폴더의 서명 없는 실행 파일이, 허용 규칙이 없어서, 밤 11시 41분에 재무팀 사용자 세션에서 차단됐습니다. 통제는 제 몫을 했습니다. 그래도 SOC는 그 파일이 어떻게 들어왔는지(이메일, 다운로드, 부모 프로세스), 강제 모드가 아닌 다른 PC에 같은 해시가 나타났는지 알아야 합니다.

**App Control for Business**는 `Microsoft-Windows-CodeIntegrity/Operational`에 기록합니다. **3076** = 감사(막았을 것), **3077** = 강제 모드에서 차단. 파일 이름, 그 파일을 올리려던 프로세스, 정책 이름, 파일 서명 정보 같은 필드가 있습니다. 스크립트 강제 이벤트는 App Control이 스크립트용으로 그 채널을 같이 쓰기 때문에 `Microsoft-Windows-AppLocker/MSI and Script`에 나타납니다(8028 감사, 8029 차단).

**AppArmor**가 막은 기록은 커널/감사 로그(`/var/log/audit/audit.log`, `/var/log/kern.log`, 또는 `journalctl -k`)에 나옵니다.

```
type=AVC msg=audit(1763509267.441:2218): apparmor="DENIED" operation="exec" profile="/usr/sbin/nginx" name="/usr/bin/bash" pid=40211 comm="nginx" requested_mask="x" denied_mask="x" fsuid=33 ouid=0
```

- `type=AVC` — 접근 벡터 캐시(Access Vector Cache) 메시지. MAC 결정에 쓰는 형식입니다.
- `msg=audit(1763509267.441:2218)` — 밀리초까지 있는 유닉스 시간과 감사 일련번호(관련 기록끼리 묶을 때 씀).
- `apparmor="DENIED"` — 프로필이 그 동작을 막았습니다. (AppArmor의 감사 모드인 *complain* 모드에서는 `"ALLOWED"`가 나옵니다.)
- `operation="exec"` — 프로그램을 실행하려는 동작이었습니다.
- `profile="/usr/sbin/nginx"` — 규칙이 적용된 갇힌 프로그램: 웹 서버.
- `name="/usr/bin/bash"` — 실행하려던 것: 셸.
- `pid=40211 comm="nginx"` — 그걸 한 프로세스 ID와 명령 이름.
- `requested_mask="x" denied_mask="x"` — 실행 권한을 요청했고 거부됐습니다.
- `fsuid=33` — 그 프로세스는 UID 33(Debian/Ubuntu의 `www-data`)으로 돌았습니다. `ouid=0` — 대상 파일 소유자는 root.

웹 서버가 `bash`를 실행하려 했다는 건 웹 익스플로잇이나 웹 셸의 가장 분명한 신호 중 하나입니다. 이 한 줄만으로도 경보를 걸 가치가 있습니다.

## 공격자는 애플리케이션 제어를 어떻게 피하나 { #app-control-bypass }

애플리케이션 제어는 완벽하지 않습니다. SOC가 그 빈틈을 알아야 어디를 볼지 압니다. 아래 우회마다 방어법이 있고, 흔적이 남습니다.

### 스크립트와 설치 패키지 { #bypass-scripts }

정책이 `.exe`만 다룬다면 공격자는 페이로드를 스크립트로 씁니다 — PowerShell, VBScript, JScript, HTA, 배치 파일 — 그리고 *허용된* 인터프리터가 그걸 실행하게 합니다(**T1059 Command and Scripting Interpreter**). 인터프리터(`powershell.exe`, `wscript.exe`, `mshta.exe`)는 Microsoft가 서명한 프로그램이니 통과합니다.

방어와 흔적: 스크립트와 MSI 규칙을 넣습니다. Windows에서 AppLocker나 App Control의 스크립트 강제를 켜면, PowerShell이 믿을 수 없는 스크립트에 대해 <strong>제한 언어 모드(Constrained Language Mode)</strong>로 내려가서 위험한 .NET·COM 호출 대부분을 막습니다. 세션의 모드는 이렇게 확인합니다.

```powershell
PS C:\> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

- `$ExecutionContext.SessionState.LanguageMode` — 지금 PowerShell 세션의 언어 모드를 출력합니다.
- `ConstrainedLanguage` — 제한이 걸려 있습니다. 강제 모드여야 하는 PC에서 `FullLanguage`가 나오면 빈틈입니다. (또는 이 제한을 무시하는 PowerShell 2.0이 아직 깔려 있어서 쓰이고 있다는 뜻일 수 있으니 `powershell.exe -Version 2`를 찾아보세요.)

PowerShell 스크립트 블록 로깅(이벤트 4104)은 난독화됐거나 네트워크에서 받아 온 스크립트라도 그 내용을 기록합니다. 이 이벤트는 나중에 따로 한 페이지에서 다룹니다.

### 리빙 오프 더 랜드 — 믿을 만한 프로그램을 발사대로 { #bypass-lolbins }

Windows에는 *다른* 코드를 불러오거나 실행할 수 있는 서명된 프로그램이 많이 들어 있습니다. `rundll32.exe`는 아무 DLL의 내보낸 함수를 실행하고, `regsvr32.exe`는 COM 구성 요소를 등록하며(URL에서 스크립틀릿을 받아 올 수도 있음), `mshta.exe`는 HTML 애플리케이션을 실행하고, `msbuild.exe`는 프로젝트 파일 안의 코드를 컴파일해서 실행하고, `installutil.exe`는 .NET 어셈블리 안의 코드를 실행합니다. MITRE는 이것들을 **T1218 System Binary Proxy Execution**으로 묶습니다(예: **T1218.011 Rundll32**, **T1218.010 Regsvr32**, **T1218.005 Mshta**). 커뮤니티 목록인 LOLBAS가 이걸 정리해 둡니다. "땅에 있는 걸로 먹고산다(Living off the Land)"는 말 그대로, 공격자가 자기 도구 대신 원래 있는 도구를 쓰는 겁니다. 정책이 DLL을 다루지 않으면 공격자는 `evil.dll`을 쓰고 이렇게 실행합니다.

```
rundll32.exe C:\Users\j.park\AppData\Roaming\cache.dll,Start
```

- `rundll32.exe` — 허용됨, Microsoft 서명, `C:\Windows\System32`에 있음.
- `C:\Users\j.park\AppData\Roaming\cache.dll` — 공격자의 DLL. 사용자가 쓸 수 있는 폴더에 있습니다.
- `,Start` — 호출할 내보낸 함수. 그 안의 코드가 이제 믿을 만한 프로세스 안에서 돕니다.

방어와 흔적: 가능하면 DLL까지 다룹니다(성능과 관리 부담이 커서 많은 곳이 실행 파일과 스크립트부터 시작합니다). 그리고 일반 사용자에게 필요 없는 프로그램(개발자가 아닌 PC의 `mshta.exe`, `msbuild.exe`, `installutil.exe` 등)을 막는 Microsoft 권장 차단 규칙을 씁니다. 탐지에는 프로세스 생성 로그가 친구입니다. `AppData`나 `Temp`의 DLL을 올리는 `rundll32.exe`, `/i:http…`가 붙은 `regsvr32.exe`, Outlook이나 Word가 띄운 `mshta.exe`는 모두 고전적인 경보입니다. [LOLBins](../../../adversary/lolbins.md)를 보세요.

### 승인된 프로세스에 코드 주입 { #bypass-injection }

애플리케이션 제어는 코드가 *파일로* 올라오는 순간을 검사합니다. 공격자가 이미 *어떤* 코드든 돌리고 있다면 — 예를 들어 매크로나 스크립트 — Windows API로 이미 돌고 있고 이미 승인된 프로세스의 메모리에 페이로드를 써 넣고 거기서 스레드를 시작할 수 있습니다(**T1055 Process Injection**). 새로 "실행"되는 게 없으니 허용/차단 판단이 아예 일어나지 않습니다.

방어와 흔적: 여기는 애플리케이션 제어가 아니라 EDR, ASR 규칙, 메모리 검사의 몫입니다. EDR은 다른 프로세스 메모리에 쓰기와 원격 스레드 생성을 기록합니다. 무료 도구로는 Sysmon 이벤트 8(`CreateRemoteThread`)과 이벤트 10(`ProcessAccess`)이 같은 역할입니다. 브라우저나 Office 프로세스가 `explorer.exe` 안에 스레드를 만드는 건 정상이 아닙니다. [프로세스 인젝션](../../../adversary/process-injection.md)을 보세요.

### 약한 규칙 악용: 이름, 경로, 권한 { #bypass-weak-rules }

- **파일 이름 규칙** — 공격자는 무엇이 허용되는지 알아낸 뒤(사용자가 정책을 읽을 수 있는 경우가 많고, 흔한 이름을 짐작할 수도 있음) 악성코드 이름을 `chrome.exe`로 바꿉니다(**T1036.005 Masquerading: Match Legitimate Name or Location**). 방어: 파일 이름 규칙을 쓰지 마세요.
- **쓰기 가능한 폴더의 경로 규칙** — 위 `icacls` 예처럼 공격자가 허용된 폴더에 씁니다. 변형으로, 쓰기 가능한 폴더에 있는 허용 프로그램을 악성코드로 *바꿔치기*하거나, 그 옆에 DLL을 심어서 그 프로그램이 불러오게 합니다(**T1574 Hijack Execution Flow**). 방어: 경로 규칙은 관리자만 쓸 수 있는 폴더에만, ACL은 정기적으로 확인, 허용 폴더에 FIM을 걸면 바꿔치기를 잡습니다.

### 서명과 해시 { #bypass-signatures-hashes }

- **게시자 규칙**은 정면으로 깨기 어렵습니다. 공격자는 우리가 믿는 게시자가 서명한 악성코드가 필요합니다. 실제로 일어난 적이 있습니다. 공격자가 소프트웨어 회사의 코드 서명 키를 훔쳐 자기 도구나 드라이버에 서명한 사례들이죠(**T1553.002 Subvert Trust Controls: Code Signing**). 잘 알려진 국가 배후 작전들도 훔친 드라이버 서명 인증서를 썼습니다. 드물고 비싸지만, 가치가 큰 표적이라면 배제하지 마세요. 더 흔한 변형은 믿는 게시자가 *정상적으로* 서명했지만 취약하거나 양날의 칼인 소프트웨어를 악용하는 겁니다. 그래서 "X 회사가 서명한 건 다 믿음"은 들리는 것보다 범위가 넓습니다.
- **해시 규칙**은 알고리즘이 강한 한 사실상 깰 수 없습니다. 속이려면 해시가 같은 다른 파일 — <strong>충돌(Collision)</strong> — 이 필요합니다. SHA-1은 2017년에 그게 가능하다는 게 증명됐습니다. 연구자들이 대략 6,500 CPU-년과 약 110 GPU-년의 계산으로 SHA-1 값이 같은 서로 다른 PDF 두 개를 만들었죠. 그 뒤로 원하는 앞부분을 정해 놓고 충돌을 만드는 공격(chosen-prefix)은 더 싸졌습니다. SHA-256은 알려진 실용적 충돌이 없습니다. AppLocker와 App Control은 해시 규칙에 SHA-256을 쓰니 이건 이론적인 걱정입니다 — 하지만 허용 목록을 MD5나 SHA-1로 만들면 절대 안 되는 이유이기도 합니다.

### 그럼 할 가치가 있나? 있다 { #worth-it }

이 중 어느 것도 애플리케이션 제어가 약하다는 뜻이 아닙니다. 다운로드한 "청구서 뷰어", 크랙 소프트웨어, 흔한 로더 같은 기회주의적 공격의 엄청난 양을 걷어 내서, 팀이 남은 공격에 시간을 쓸 수 있게 해 줍니다. 그리고 남은 공격자를 더 좁은 기술(LOLBin, 인젝션, 스크립트)로 몰아넣는데, 그 하나하나는 콕 집어서 지켜볼 수 있습니다. 문턱은 높이고 *볼 곳은 좁히는 것* — SOC가 바라는 게 정확히 그겁니다.

## 파일 무결성 모니터링 — 바뀌면 다 알아채기 { #fim }

### 무엇인가 { #fim-what }

거의 모든 침입은 어딘가의 파일을 바꿉니다. 떨어뜨린 도구, 바꿔치기한 실행 파일, 새 시작 스크립트, 고친 `hosts` 파일, 웹사이트 폴더의 웹 셸. <strong>파일 무결성 모니터링(FIM)</strong>은 정해 둔 파일·폴더의 모습을 스냅숏으로 찍어 두고, 일정 간격으로 또는 실시간으로 다른 점이 있는지 검사합니다.

비유하자면, 겨울 동안 비워 둘 별장을 떠나기 전에 방마다 사진을 찍어 두는 겁니다. 돌아와서 사진과 방을 비교하면 옮겨진 것, 늘어난 것, 없어진 것이 바로 눈에 띕니다. 누가 했는지는 아직 몰라도요.

FIM은 보통 감시 대상마다 이런 걸 기록합니다.

- 내용의 **해시**(SHA-256) — 안의 내용이 조금이라도 바뀌면 잡습니다.
- **크기**와 **수정 시각** — 싸고 빠른 힌트(시각은 조작될 수 있으니 해시가 중요).
- **소유자와 그룹** — 소유자가 바뀐 걸 잡습니다.
- **권한** — 예를 들어 스크립트가 누구나 쓸 수 있게 바뀌거나 실행 파일에 SUID 비트가 붙은 걸 잡습니다.
- **어떤 파일이 있는지** — **새** 파일이 생기거나 파일이 사라진 걸 잡습니다.

FIM은 보통 <strong>호스트 기반 침입 탐지·방지 시스템(HIDS/HIPS)</strong>이나 EDR·보안 에이전트의 기능 하나입니다(예: Wazuh/OSSEC의 "syscheck", Tripwire, Linux의 AIDE, 상용 에이전트의 FIM 모듈). Windows의 기본 재료는 <strong>개체 액세스 감사(Object Access Auditing)</strong>입니다. 폴더에 감사 규칙(SACL)을 걸어 두면 누가 거기에 쓸 때 Windows가 이벤트 **4663**("개체에 접근하려는 시도가 있었습니다")을 남깁니다. 이 이벤트는 나중에 따로 다룹니다.

### 어디를 볼까 { #fim-where }

FIM은 바뀌는 일이 드물고 바뀌면 의미가 있는 곳에서만 쓸모 있습니다. 디스크 전체에 걸면 로그 파일과 브라우저 캐시마다 경보가 쏟아집니다. 좋은 대상은 이렇습니다.

- **시스템 실행 파일과 라이브러리** — `C:\Windows\System32`, `/bin`, `/sbin`, `/usr/bin`, `/lib`. 패치만 이걸 바꿔야 하니, 패치 시간 밖의 변경은 수상합니다.
- **웹 루트** — `/var/www/html`, `C:\inetpub\wwwroot`. 사이트 내용은 배포할 때 바뀝니다. 그 외 시간에 새로 생긴 `.php`/`.aspx`/`.jsp` 파일은 아니라는 게 증명될 때까지 웹 셸입니다.
- **시작·지속성 위치** — 시작 프로그램 폴더, `/etc/systemd/system`, `/etc/cron*`, `~/.bashrc`, `/etc/rc.local`, 작업·서비스 폴더.
- **보안에 중요한 설정** — `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `C:\Windows\System32\drivers\etc\hosts`.
- **애플리케이션 제어 경로 규칙이 허용한 폴더** — 허용된 프로그램이 바꿔치기되는 걸 잡기 위해.

### 예: 웹 셸 잡기 { #fim-webshell }

회사 웹사이트가 `web01.corp.example`의 `/var/www/html`에서 돌고 있습니다. 공격자가 콘텐츠 관리 시스템의 취약한 플러그인을 익스플로잇해서 작은 PHP 파일 하나를 올립니다. <strong>웹 셸(Web Shell)</strong>입니다(**T1505.003 Server Software Component: Web Shell**). 그 뒤로 공격자는 `https://www.shop.example/wp-content/uploads/2026/11/thumb.php?c=...`에 접속하고, PHP 코드가 서버에서 공격자의 명령을 실행합니다. HTTP 위에 올린 원격 명령 프롬프트 같은 거죠.

이 웹사이트의 파일은 계획된 배포 때만 바뀝니다. 그래서 "배포가 아닌데 `/var/www/html`에 새 파일"은 완벽한 FIM 규칙입니다. **AIDE**(Advanced Intrusion Detection Environment)는 이렇게 보고합니다.

```
$ sudo aide --check
Start timestamp: 2026-11-19 02:00:01 +0000 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:      48211
  Added entries:                1
  Removed entries:              0
  Changed entries:              1

---------------------------------------------------
Added entries:
---------------------------------------------------

f++++++++++++++++: /var/www/html/wp-content/uploads/2026/11/thumb.php

---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /var/www/html/.htaccess

---------------------------------------------------
Detailed information about changes:
---------------------------------------------------

File: /var/www/html/.htaccess
  SHA256    : 9b0e3c...41aa                   | 77d1f2...c0e8
```

- `sudo aide --check` — 지금 파일 시스템을 미리 `aide --init`으로 만들어 기준으로 복사해 둔 데이터베이스와 비교합니다. 보통 cron이나 systemd 타이머로 돌리는데, 여기서는 새벽 2시에 돌았습니다.
- `AIDE found differences…` — 기준과 다른 게 있습니다.
- `Total number of entries: 48211` — 감시 중인 파일·폴더 수.
- `Added entries: 1`, `Changed entries: 1` — 새 파일 하나, 바뀐 파일 하나.
- `f++++++++++++++++: …/thumb.php` — `f` = 일반 파일. 전부 `+`면 **모든 속성이 새것**, 즉 기준에는 없던 파일이라는 뜻입니다. 이미지만 있어야 할 *uploads* 폴더 안의 PHP 파일 — 이게 웹 셸입니다.
- `f   ...    .C... : /var/www/html/.htaccess` — 속성 문자열은 어떤 속성이 바뀌었는지 보여 줍니다. `C`는 **체크섬(내용)이 바뀜**, 점은 크기·권한·소유자가 그대로라는 뜻입니다. 공격자는 원래 PHP가 실행되지 않는 폴더에서 실행되게 하거나 방문자를 다른 곳으로 보내려고 `.htaccess`를 자주 고칩니다.
- `SHA256 : 이전 | 이후` — 내용의 이전·이후 해시.

한계도 보입니다. AIDE는 새벽 2시에 돌았으니, 웹 셸이 전날 오후 2시에 올라왔다면 공격자에게는 아무도 모르는 12시간이 있었던 셈입니다. **실시간** 감시(Linux의 inotify, Windows의 파일 시스템 드라이버)를 하는 에이전트 기반 FIM이 그 틈을 메웁니다. 같은 사건을 Wazuh 방식의 경보로 SIEM에서 보면 이렇습니다(줄임).

```json
{
  "timestamp": "2026-11-18T14:03:27.118+0000",
  "agent": { "name": "web01", "ip": "10.20.1.15" },
  "rule": { "id": "554", "level": 5, "description": "File added to the system." },
  "syscheck": {
    "path": "/var/www/html/wp-content/uploads/2026/11/thumb.php",
    "event": "added",
    "mode": "realtime",
    "size_after": "1184",
    "uname_after": "www-data",
    "perm_after": "rw-r--r--",
    "sha256_after": "c41b...7e02"
  }
}
```

- `timestamp` — 변경을 본 시각: 오후 2시 3분, 업로드 몇 초 뒤입니다.
- `agent.name` / `agent.ip` — 어느 서버인지.
- `rule.description "File added to the system."` — 새 파일 규칙이 울렸습니다. (규칙 ID와 수준은 제품·버전에 따라 다르니, 웹 루트는 심각도를 올려 두세요.)
- `syscheck.path` — 새 파일.
- `event "added"`와 `mode "realtime"` — 새 파일이고, 예약 검사가 아니라 실시간 감시로 잡았습니다.
- `size_after 1184` — 약 1KB. 웹 셸은 대개 아주 작습니다.
- `uname_after "www-data"` — **웹 서버 계정이 소유자**입니다. 정상 사이트 파일은 보통 배포용 계정이 올립니다. *웹 서버 프로세스 자신이 만든* 파일이라는 건 웹 애플리케이션이 직접 썼다는 뜻이고, 업로드 익스플로잇이 바로 그렇게 합니다.
- `perm_after`, `sha256_after` — 권한, 그리고 다른 곳에서 찾아볼 해시.

SOC의 다음 단계: 웹 서버 접근 로그에서 그 파일을 올린 요청(오후 2시 3분 전후 플러그인 업로드 주소로 간 `POST`)과 그 뒤 `thumb.php`로 온 모든 요청(누가, 어느 IP에서, 어떤 파라미터로 썼나)을 찾고, 웹 서버 프로세스가 셸을 띄웠는지(`www-data`가 `sh`, `bash`, `id`, `whoami`를 실행 — 위 AppArmor 거부 기록도 같은 이야기) 확인하고, 지우기 전에 파일을 보존합니다.

### FIM을 견딜 만하게 만들기 { #fim-tuning }

- **승인된 변경마다 기준을 다시 잡는다.** 패치 날에는 시스템 파일 수백 개가 바뀝니다. 패치 시간에는 FIM 경보를 잠시 누르고 끝난 뒤 기준을 다시 잡거나, 패치·배포 시스템과 연계해서 설명되지 않는 변경만 경보가 울리게 합니다.
- **중요한 곳은 실시간, 나머지는 예약 검사.** 웹 루트와 지속성 위치는 실시간, 큰 시스템 폴더는 밤마다.
- **"누가"를 붙인다.** FIM만으로는 *무엇이* 바뀌었는지 압니다. 감사 데이터(같은 경로에 건 Linux `auditd` 규칙, Windows 4663, 쓰는 프로세스를 기록하는 EDR)와 합치면 *어떤 프로세스와 사용자가* 바꿨는지 압니다. 보통 이쪽이 더 쓸모 있는 답입니다.

## 지속성 잡기 { #catching-persistence }

### 방법이 몇 가지나 있나 { #how-many-asep }

지속성은 공격자가 재부팅, 로그오프, 비밀번호 변경 뒤에도 접근을 유지하는 방법입니다. 운영체제 안에서 무언가가 자동으로 시작되도록 설정할 수 있는 자리를 <strong>자동 시작 확장 지점(ASEP, Auto-Start Extensibility Points)</strong>이라고 합니다. 정해진 개수는 없습니다. Windows 버전마다, 설치된 제품마다(Office 추가 기능, 인쇄 공급자, 브라우저 확장) 새 자리가 생기고, 연구자들도 계속 숨은 자리를 찾아냅니다. MITRE ATT&CK의 **Persistence** 전술(TA0003)이 잘 알려진 기법을 정리해 두었으니 점검표로 쓰기 좋습니다.

방어자의 전략은 두 갈래입니다.

1. **흔한 자리를 알고 계속 지켜본다.** 이상적으로는 새 항목이 생길 때마다 고유한 경보가 울리게(레지스트리 감사, FIM, Sysmon/EDR).
2. **사고 중에는 전체 목록을 한 번에 점검한다.** 수백 개 자리를 아는 도구로.

### 가장 흔한 ASEP { #common-aseps }

| ASEP | 무엇인가 | ATT&CK | 흔적 예 |
| --- | --- | --- | --- |
| Run 키와 시작 프로그램 폴더 | `…\CurrentVersion\Run` 키나 Startup 폴더로 로그온 때 시작 | T1547.001 | 레지스트리 쓰기(Sysmon 13), Startup에 새 파일(Sysmon 11) |
| 서비스 | 새로 만들거나 고친 Windows 서비스(SYSTEM으로, 부팅 때 시작) | T1543.003 | System 7045, Security 4697 |
| 예약 작업 | 로그온, 부팅, 정해진 시각에 도는 작업 | T1053.005 | Security 4698, TaskScheduler/Operational 106 |
| 브라우저 확장 | 브라우저를 열 때마다 도는 확장 — 페이지를 읽고 쿠키를 훔침 | T1176.001 | 새 확장 폴더나 정책 키, 브라우저 관리 로그 |
| 정상 계정 | 훔친 자격 증명으로 다시 로그인하거나, 공격자가 만든 새 계정 | T1078, T1136 | 낯선 출발지의 4624, 계정 생성 4720 |
| Linux: cron, systemd, 셸 프로필 | `crontab`, 새 `.service` 유닛, `~/.bashrc`에 한 줄 | T1053.003, T1543.002, T1546.004 | `/etc/cron*`, `/etc/systemd/system`, 홈 점 파일에 FIM/auditd |
| Linux/macOS: SSH 키 | `~/.ssh/authorized_keys`에 키 추가 | T1098.004 | `authorized_keys`에 FIM |

가장 자주 보게 될 Run 키는 이렇습니다.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run         (current user, no admin needed)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run         (all users, needs admin)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup             (current user)
%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp         (all users, needs admin)
```

- `HKCU` = HKEY_CURRENT_USER — 로그온한 사용자만의 설정. 어떤 사용자든 여기에 쓸 수 있으니, 피싱당한 일반 사용자 권한만으로도 지속성을 만들 수 있습니다.
- `HKLM` = HKEY_LOCAL_MACHINE — PC 전체 설정. 쓰려면 관리자 권한이 필요하고, 항목은 로그온하는 모든 사용자에게 실행됩니다.
- `Run` 항목은 로그온할 때마다, `RunOnce` 항목은 한 번 실행되고 지워집니다(공격자는 가끔 매번 다시 넣습니다).
- 두 `Startup` 폴더도 똑같이 작동하는데, 레지스트리 값 대신 파일이나 바로 가기를 씁니다.

PowerShell로 키 하나를 빠르게 보면 이렇습니다.

```powershell
PS C:\> Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

OneDrive     : "C:\Users\j.park\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
MsEdgeUpdate : C:\Users\j.park\AppData\Roaming\MsEdge\msedgeupd.exe
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
...
```

- `Get-ItemProperty '<key>'` — 그 레지스트리 키 아래의 값들을 보여 줍니다. 값 이름 하나가 항목 하나, 값 데이터가 실행될 명령입니다.
- `OneDrive` — 원래 설치 위치에 있는 진짜 OneDrive 클라이언트. 정상입니다.
- `MsEdgeUpdate` — Edge 업데이트 프로그램처럼 보이지만, 진짜 Edge 업데이트는 `C:\Program Files (x86)\Microsoft\EdgeUpdate\`에서 예약 작업/서비스로 돌지, 사용자의 `AppData\Roaming\MsEdge\` 폴더에서 돌지 않습니다. 회사 이름을 흉내 낸 이름 + 사용자가 쓸 수 있는 경로 — 전형적인 위장입니다.
- `PSPath…` — PowerShell 자체의 관리용 속성입니다. 무시합니다.

### 권한이 선택지를 정한다 { #privilege-and-persistence }

공격자가 쓸 수 있는 자리는 어디까지 올라왔느냐에 달려 있습니다.

- **일반 사용자** — 사용자별 위치만: HKCU Run 키, 그 사용자의 Startup 폴더, 사용자별 예약 작업, 그 사용자의 브라우저 확장, Linux라면 자기 홈 폴더의 셸 프로필 파일. 시끄럽고 찾기 쉬우며, 그 사용자가 로그온할 때만 작동합니다.
- **관리자 / root** — PC 전체 위치: 서비스, 시스템 예약 작업, HKLM 키, WMI 이벤트 구독(T1546.003), 시스템 전체의 systemd 유닛과 cron 작업, 그리고 가장 깊은 곳인 **커널 드라이버와 루트킷**(T1014). 루트킷은 운영체제 자신에게서 파일, 프로세스, 레지스트리 키를 숨길 수 있습니다. 감염된 시스템 안에서는 찾기가 극히 어렵고, 솔직한 답은 "PC를 다시 설치하자"인 경우가 많습니다.

그래서 권한 상승([권한 상승](../endpoint-attacks/privilege-escalation.md) 참고)이 방어자에게도 중요합니다. 공격자가 얼마나 깊이 파고들 수 있는지, 그래서 정리 작업을 얼마나 믿을 수 있는지를 정하니까요.

### Autoruns로 찾기 { #autoruns }

**Autoruns**(Sysinternals, Microsoft 무료 도구)는 수백 개의 ASEP 위치를 압니다 — 로그온 항목, 서비스, 드라이버, 예약 작업, 탐색기·Office 추가 기능, WMI, 코덱, 인쇄 모니터, LSA 공급자 등. 각 항목의 디지털 서명을 확인하고 해시를 VirusTotal에서 조회할 수도 있습니다. PC 한 대는 GUI가 좋고, 여러 대에서 모을 때는 명령줄 버전 `autorunsc.exe`가 낫습니다.

```
C:\> autorunsc64.exe -accepteula -a * -c -h -s -m -nobanner > C:\IR\ws-fin-0412_autoruns.csv
```

- `autorunsc64.exe` — 64비트 명령줄 버전.
- `-accepteula` — 라이선스 확인 창을 조용히 수락(자동 실행에 필요).
- `-a *` — **모든** ASEP 분류를 검사(일부만 고를 수도 있음: `-a l` 로그온, `-a s` 서비스, `-a t` 예약 작업).
- `-c` — CSV로 출력. 정렬하고 비교하기 좋습니다.
- `-h` — 파일 해시 포함(MD5, SHA-1, SHA-256 등).
- `-s` — 디지털 서명 확인.
- `-m` — Microsoft가 서명한 항목 숨기기. 목록이 수백 줄에서 정말 봐야 할 수십 줄로 줄어듭니다. (LOLBin을 기억하세요. ASEP에 있는 Microsoft 서명 프로그램도 *인자*가 악성이면 악성입니다. 중요한 PC에서는 `-m` 없이 한 번 전체를 보세요.)
- `-nobanner` — 출력 맨 위의 배너 문구 생략.
- `> …csv` — 분석하거나 수집 공유 폴더에 올리려고 파일로 저장.

결과 중 몇 줄(열 줄임, 가상 값):

```
Time,Entry Location,Entry,Enabled,Category,Description,Signer,Image Path,Launch String,SHA-256
2026-02-03 08:11,HKCU\...\CurrentVersion\Run,OneDrive,enabled,Logon,Microsoft OneDrive,(Verified) Microsoft Corporation,c:\users\j.park\appdata\local\microsoft\onedrive\onedrive.exe,"""C:\Users\j.park\AppData\Local\Microsoft\OneDrive\OneDrive.exe"" /background",5D0A...
2026-11-18 23:52,HKCU\...\CurrentVersion\Run,MsEdgeUpdate,enabled,Logon,,(Not Verified),c:\users\j.park\appdata\roaming\msedge\msedgeupd.exe,C:\Users\j.park\AppData\Roaming\MsEdge\msedgeupd.exe,8E77...
2026-11-18 23:55,Task Scheduler,\Microsoft\Windows\Maintenance\SysCheck,enabled,Tasks,,(Verified) Microsoft Windows,c:\windows\system32\windowspowershell\v1.0\powershell.exe,"powershell.exe -w hidden -enc SQBFAFgA...",9785...
```

읽는 법:

- `Time` — 항목(레지스트리 키나 작업 파일)이 마지막으로 쓰인 시각. 11월 18일 밤늦게 4분 간격으로 만들어진 두 항목이, 앞에서 본 AppLocker 차단 바로 뒤와 맞아떨어집니다.
- `Entry Location` / `Entry` — 어디에, 무엇이. HKCU Run 키의 `MsEdgeUpdate`, 그리고 진짜 Windows 작업들이 있는 `\Microsoft\Windows\Maintenance\` 작업 폴더에 숨은 `SysCheck`라는 작업 — 또 하나의 위장입니다.
- `Signer` — OneDrive의 `(Verified) Microsoft Corporation`은 괜찮습니다. `msedgeupd.exe`의 `(Not Verified)` — Microsoft 업데이트 프로그램인 척하는 서명 없는 파일입니다. 작업의 서명자가 `(Verified) Microsoft Windows`인 건 실행 파일이 `powershell.exe`라서입니다. 그래서 `-m`을 쓰면 숨겨질 수 있고, 그래서 **Launch String**을 꼭 읽어야 합니다.
- `Launch String` — `powershell.exe -w hidden -enc SQBFAFgA...`: 숨긴 창과 Base64로 인코딩한 명령(`-enc`). `SQBFAFgA`를 UTF-16LE Base64로 풀면 `IEX`, 즉 PowerShell의 `Invoke-Expression` — 받아서 실행하는 크래들의 시작입니다. 정상 Windows 유지 관리 작업은 이렇게 생기지 않습니다.
- `SHA-256` — 전체 PC에서 찾아볼 해시.

**[보충] 읽기만 하지 말고 비교하라.** 여러 대에 걸친 Autoruns의 힘은 *비교(diff)*에 있습니다. 모든 PC에서 CSV를 모으거나, PC 한 대를 정상 기준 이미지와 비교해서, 한 대나 몇 대에만 있는 항목을 찾습니다. 백신 탐지에서 본 "희귀성"과 같은 생각입니다. 정상 소프트웨어는 어디에나 있고, 공격자의 지속성은 한 곳에 있습니다.

### 점검에서 계속 돌아가는 탐지로 { #continuous-persistence-detection }

Autoruns는 한 순간의 스냅숏입니다. 계속 지켜보려면 지속성이 *만들어지는 순간*을 기록합니다.

- Run/RunOnce 등 ASEP 키에 대한 **레지스트리 쓰기** — Sysmon 이벤트 **13**(레지스트리 값 설정)이나 EDR 레지스트리 텔레메트리.
- Startup 폴더, 작업 폴더, `/etc/cron*`, `/etc/systemd/system`, `authorized_keys`의 **파일 생성** — Sysmon 이벤트 **11**(파일 생성), FIM, `auditd` 감시.
- **서비스 설치** — System 이벤트 **7045**와 Security 이벤트 **4697**("시스템에 서비스가 설치되었습니다").
- **예약 작업 생성** — 작업에 대한 개체 액세스 감사가 켜져 있으면 Security 이벤트 **4698**("예약된 작업이 만들어졌습니다").
- **새 계정** — Security 이벤트 **4720**.

이 이벤트들은 나중에 "꼭 알아야 할 이벤트" 페이지에서 하나씩 자세히 설명합니다. 여기서 핵심은 설계입니다. 흔한 ASEP마다, 새 항목이 생길 때 울리는 이벤트 하나를 정해 두고 *그것*을 SOC로 보냅니다. 매일 전체 목록을 보내는 게 아니라요.

## 한데 모으면 — SOC가 이 방어선에서 얻는 것 { #soc-use }

- **애플리케이션 제어 감사·차단 이벤트** — "목록에 없는 게 실행하려 했다". 양은 적고 가치는 큽니다. 특히 `Temp`, `Downloads`, `AppData`, `ProgramData`에서 온 것. 부모 프로세스와 파일이 어떻게 들어왔는지 확인합니다.
- **우회 신호** — 제한 언어 모드에 걸린 스크립트 블록, 이상한 인자나 이상한 부모를 가진 LOLBin, 프로세스 간 인젝션, 이름 바꾼 실행 파일, 허용 폴더의 ACL 변경.
- **FIM 경보** — 바뀌는 일이 드문 곳의 새 파일·바뀐 파일: 웹 루트, 시스템 실행 파일, 지속성 폴더, `hosts`, SSH 키. "어떤 프로세스, 어떤 사용자?"를 묻습니다.
- **지속성 생성 이벤트** — 새 Run 값, 서비스, 작업, 계정, cron 항목, systemd 유닛. *새로 생긴 것*에 경보, Autoruns 비교로 *희귀한 것*을 사냥.
- **이야기** — 이 통제들은 흔히 순서대로 울립니다. 막혔거나 감사된 실행 파일, 그다음 지속성 항목, 그다음 낯선 곳의 새 파일. 한 PC에서 이걸 함께 보면 중간 수준 경보 세 개가 신뢰도 높은 사고 하나가 됩니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    가장 효과적인 엔드포인트 통제 중 하나로서의 허용 목록, 파일 이름/경로/게시자/해시 규칙의 강도 차이, 강제 전에 감사하기와 감사 이벤트를 탐지원으로 쓰기, 고전적인 우회(스크립트, LOLBin, 인젝션, 쓰기 가능한 경로, 훔친 서명 키), 웹 루트·시스템 실행 파일처럼 드물게 바뀌는 경로의 FIM, 권한이 가능한 지속성을 정한다는 점, 점검 도구로서의 Autoruns — 모두 그대로입니다. AppLocker 이벤트 ID(8002~8007)와 CodeIntegrity 3076/3077도 바뀌지 않았습니다.

!!! info "[변경됨] 바뀐 점"
    - **이름.** Windows Defender 애플리케이션 제어(WDAC)는 이제 **App Control for Business**라고 부릅니다. AppLocker도 여전히 지원되지만, Microsoft는 새로 도입할 때 App Control을 권하고 새 기능도 그쪽에 넣습니다. Intune에 관리형 설치 관리자를 지원하는 App Control 전용 정책 유형이 생겨서, 옛날 XML과 GPO 방식보다 배포가 훨씬 쉬워졌습니다.
    - <strong>스마트 앱 컨트롤(Smart App Control)</strong>은 일반 사용자·소규모 사업장용 Windows 11에 평판 기반 앱 제어를 가져왔습니다. 처음에는 새로 설치할 때만 켤 수 있었는데, 2026년 업데이트부터는 다시 설치하지 않고도 다시 켤 수 있습니다. 조직이 관리하는 정책을 대신하지는 못하지만, 그 차단 기록을 보게 되면 알아볼 수 있어야 합니다.
    - **Sysmon이 Windows의 일부가 되는 중.** Microsoft는 2026년에 Windows 11과 Windows Server 2025에 Sysmon 기능을 내장 선택 기능으로 넣기 시작했습니다. 쓸모 있으려면 여전히 설정과 로그 수집이 필요하고, 빌드에 따라 있는지 없는지가 다르니 우리 환경을 확인하세요.
    - **MITRE ATT&CK 갱신.** 브라우저 확장은 이름이 바뀐 상위 기법 **T1176 Software Extensions** 아래의 하위 기법 **T1176.001**이 됐습니다(IDE 확장 T1176.002도 같이 들어감). 최근 ATT&CK 릴리스는 탐지 안내를 "탐지 전략(detection strategies)"으로 다시 짰습니다. 옛 탐지 규칙의 기법 ID를 다시 확인하세요.
    - **macOS Gatekeeper가 더 엄격해졌다.** macOS Sequoia부터는 예전의 Control-클릭 "그래도 열기" 지름길로 Gatekeeper를 건너뛸 수 없고, 사용자가 시스템 설정에서 앱을 승인해야 합니다. 사회 공학이 조금 더 어려워졌습니다.
    - **지속성이 아이덴티티와 클라우드로 옮겨 갔다.** 공격자는 점점 엔드포인트를 아예 건드리지 않고 지속성을 만듭니다. OAuth 앱 동의, MFA 수단 추가, 메일함 규칙, 서비스 주체(service principal) 비밀, 훔친 세션 토큰. ATT&CK에서는 T1098(Account Manipulation)과 T1078.004(Cloud Accounts)가 다룹니다. 엔드포인트 ASEP 사냥은 여전히 필요하지만, 더는 전체 그림이 아닙니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **파일 이름 규칙을 쓰지 말고**, 일반 사용자가 쓸 수 있는 경로를 허용하지 마세요. 경로 규칙을 쓰기 전에 `icacls`로 ACL을 확인합니다.
    - **`.exe`만 다루지 마세요.** 스크립트·MSI 규칙(가능하면 DLL도)이 없으면 정책에 옆문이 열려 있습니다. 일반 사용자에게 필요 없는 LOLBin에 대한 Microsoft 권장 차단 규칙도 넣으세요.
    - **강제 모드 PC에 PowerShell 2.0을 남겨 두지 마세요.** 제한 언어 모드를 무시합니다. (최신 Windows 11 빌드에서는 제거됐지만, 옛 이미지에는 아직 있을 수 있습니다.)
    - **게시자 규칙을 "좋은 소프트웨어만"으로 믿지 마세요.** 그 게시자가 서명한 모든 실행 파일 — 옛 취약 버전과 양날의 칼 도구까지 — 을 허용합니다. 최소 버전과 거부 규칙을 함께 씁니다.
    - **허용 목록이나 FIM 기준을 MD5나 SHA-1로 만들지 마세요.** SHA-256을 씁니다.
    - **웹 서버에 밤마다 도는 FIM만 믿지 마세요.** 웹 셸은 검사 전까지 몇 시간이고 쓰일 수 있습니다. 웹 루트는 실시간 감시를 씁니다.
    - **중요한 PC에서 Autoruns를 `-m`으로만 돌리지 마세요.** ASEP에 있는 Microsoft 서명 프로그램이 악성 인자를 달고 있을 수 있습니다. 실행 문자열을 읽으세요.
    - **표적 사고의 해시나 파일을 생각 없이 공개 서비스에 올리지 마세요.** 해시 조회는 대개 괜찮지만, 샘플을 올리면 공격자에게 들킬 수 있습니다.

## 확인 문제 { #quiz }

### 문제 1

우리 조직은 AppLocker를 이런 규칙으로 강제하고 있습니다. *실행 파일 — Everyone에게 `C:\Windows\*`와 `C:\Program Files\*` 허용, Everyone에게 `C:\Apps\*` 허용(옛 재무 도구 때문에 추가).* 스크립트, MSI, DLL 규칙은 없습니다. 공격자가 일반 사용자 한 명을 피싱했습니다. 그래도 공격자가 코드를 실행할 수 있는 방법 세 가지, 각각 로그에 어떻게 보일지, 각 틈을 어떻게 막을지 말해 보세요.

??? success "정답과 해설"
    아래 중 세 가지면 좋은 답입니다.

    - **`C:\Apps`에 쓰기.** 일반 사용자가 거기 쓸 수 있다면(`icacls C:\Apps`로 확인 — `Users:(M)`이나 `(W)`가 틈), 공격자는 `payload.exe`를 `C:\Apps\`에 넣고 경로 규칙 덕분에 허용됩니다(T1574 / 약한 경로 규칙 악용). *흔적:* 재무 도구가 아닌 파일에 대해 `C:\Apps` 규칙 이름이 찍힌 AppLocker **8002**(허용), 그 폴더의 새 파일(FIM이나 Sysmon 11). *막기:* 사용자 쓰기 권한을 빼거나, 경로 규칙을 재무 도구에 대한 게시자·해시 규칙으로 바꿉니다.
    - **스크립트 쓰기.** 스크립트 규칙이 없으니 `.ps1`, `.vbs`, `.js`, `.hta`가 허용된 인터프리터로 실행됩니다(T1059). *흔적:* Outlook이나 탐색기에서 `powershell.exe`/`wscript.exe`/`mshta.exe` 프로세스 생성, PowerShell 4104 스크립트 블록. *막기:* 스크립트·MSI 규칙 추가. 스크립트 규칙을 강제하면 믿을 수 없는 PowerShell이 제한 언어 모드로도 내려갑니다.
    - **LOLBin으로 DLL 실행.** DLL 규칙이 없으니 `rundll32.exe C:\Users\<user>\AppData\Roaming\x.dll,Start`가 `C:\Windows`의 Microsoft 서명 프로그램 안에서 공격자 코드를 실행합니다(T1218.011). *흔적:* 사용자 폴더의 DLL을 올리는 `rundll32.exe` 프로세스 생성, Sysmon 7 이미지 로드. *막기:* DLL 규칙(또는 원래 DLL을 다루는 App Control), 사용자에게 필요 없는 LOLBin 차단 규칙.
    - 매크로로 발판을 만든 뒤 **허용된 프로세스에 인젝션**(T1055) — *흔적:* EDR/Sysmon 8/10, *막기:* EDR과 ASR 규칙. 애플리케이션 제어는 인젝션을 못 봅니다.

    핵심: 실행 파일만 다루고 쓰기 가능한 경로까지 허용한 허용 목록은 대부분 보여 주기입니다. 정책은 코드를 실행하는 *다른* 길도 덮어야 합니다.

### 문제 2

웹 서버 `web02.corp.example`(UID 33 = `www-data`)의 FIM 에이전트가 새벽 3시 12분에 경보 두 개를 냅니다. 새 파일 `/var/www/html/images/icon_x.aspx.php`(소유자 `www-data`, 2KB), 그리고 `/var/www/html/.htaccess` 변경(체크섬 바뀜, 소유자 `deploy`, 크기는 몇 바이트 차이). 그날 밤 배포는 없었습니다. 무슨 일이 일어났다고 보나요? 소유자 칸이 왜 중요하고, 다음 세 단계는 무엇인가요?

??? success "정답과 해설"
    **무슨 일:** 거의 확실히 **웹 셸** 업로드입니다(T1505.003). *images* 폴더에 작은 스크립트 파일이 생겼고, 대충 보거나 허술한 업로드 필터에는 무해해 보이도록 확장자를 두 개(`.aspx.php`) 붙였고, `.htaccess`가 고쳐졌습니다. 아마 그 폴더에서 PHP가 실행되게 하거나 확장자를 PHP 처리기에 연결하려는 것이겠죠. 예정된 배포가 없었으니 정상으로 설명할 길이 없습니다.

    **소유자가 중요한 이유:** 새 파일의 소유자는 **`www-data`** — 웹 서버 자신의 계정입니다. 사이트 파일은 보통 `deploy`가 배포합니다(`.htaccess`의 소유자가 보여 주듯이). `www-data`가 만든 파일이라는 건 **웹 애플리케이션 자신이 그 파일을 썼다**는 뜻이고, 업로드 취약점이나 이미 있던 웹 셸이 바로 그렇게 합니다. `.htaccess`는 소유자 `deploy`는 그대로인데 내용이 바뀌었으니, 그 파일에 쓰기 권한이 있는 무언가가 그 자리에서 고친 겁니다. 웹 사용자는 원래 그 파일에 쓸 수 없어야 하니, 무엇이 썼는지 찾아야 합니다.

    **다음 단계(합리적인 세 가지면 됨):** (1) 3시 12분 전후 웹 접근 로그에서 업로드 요청(업로드나 플러그인 주소로 간 `POST`)과 그 뒤 `icon_x.aspx.php`로 온 모든 요청 — 출발지 IP, 파라미터, 응답 크기 — 을 찾습니다. (2) `www-data`가 실행한 명령(프로세스 로그, `auditd` EXECVE 기록, `nginx` → `bash` 같은 AppArmor/SELinux 거부)을 확인해서 셸이 쓰였는지, 무엇을 했는지 봅니다. (3) 파일과 `.htaccess`를 보존(복사, 해시)한 뒤 격리합니다 — 출발지 IP 차단, 사이트 점검 모드 전환이나 서버 격리, 취약한 구성 요소 패치, 그리고 웹 루트 전체에서 다른 새 파일 찾기(웹 셸은 혼자 있는 일이 드뭅니다).

### 문제 3

PC `WS-ENG-0077` 사고 조사 중 `autorunsc64.exe -a * -c -h -s -m`을 돌렸습니다. 결과 중에 이런 항목이 있습니다.

```
HKCU\...\CurrentVersion\Run, Teams, (Verified) Microsoft Corporation, c:\users\a.cho\appdata\local\microsoft\teams\current\teams.exe
HKLM\System\CurrentControlSet\Services, WinDefendHelper, (Not Verified), c:\programdata\winhelp\wdhelper.exe
Task Scheduler, \OneDrive Reporting Task-S-1-5-21-...-1107, (Verified) Microsoft Corporation, c:\users\a.cho\appdata\local\microsoft\onedrive\onedrivestandaloneupdater.exe
```

어느 항목이 수상하고, 그 위치가 공격자의 권한 수준에 대해 무엇을 말해 주나요? 언제 만들어졌는지 찾으려면 어떤 Windows 이벤트를 검색하겠나요? 그리고 그걸 지운 뒤에도 왜 아직 걱정해야 할까요?

??? success "정답과 해설"
    **수상한 항목:** 서비스 **`WinDefendHelper`**. Microsoft Defender를 흉내 낸 이름이고(`WinDefend`가 Defender의 진짜 서비스 이름), **서명 없는** 실행 파일(`Not Verified`)이며, 어떤 프로세스든 만들 수 있는 `C:\ProgramData\winhelp\` 폴더에서 돕니다. 진짜 Defender 구성 요소는 `C:\ProgramData\Microsoft\Windows Defender\Platform\…`이나 `C:\Program Files\Windows Defender\` 아래에 있고 서명돼 있습니다. 위장(T1036) + 악성 서비스(T1543.003)입니다. Teams와 OneDrive 항목은 서명돼 있고 원래의 사용자별 위치에 있습니다.

    **권한 수준:** `HKLM\System\CurrentControlSet\Services` 아래에 서비스를 만들려면 **관리자** 권한이 필요하고, 서비스는 보통 부팅 때 **SYSTEM**으로 돕니다. 즉 공격자는 이 PC에서 관리자 권한을 가졌거나 얻었습니다. 더는 일반 사용자 발판이 아닙니다. 그만큼 위험이 커집니다. 관리자라면 자격 증명 덤프, 다른 시스템 전체 지속성(WMI 구독, 드라이버), 보안 도구 변조도 할 수 있었으니까요.

    **찾을 이벤트:** System **7045**("시스템에 서비스가 설치되었습니다": 서비스 이름, 실행 파일 경로, 계정, 시작 유형)와 Security **4697**(같은 내용 + 설치한 계정, 감사 정책이 켜져 있다면). 그리고 서비스 레지스트리 키에 대한 Sysmon 13, `wdhelper.exe`가 언제 누구에 의해 써졌는지 보는 Sysmon 11 / 프로세스 생성. 그 시각부터 거꾸로 거슬러 올라가 직전의 로그온(4624)을 찾습니다.

    **지운 뒤에도 걱정하는 이유:** 관리자 수준 공격자는 지속성 하나만 남기는 일이 드뭅니다. `-m`이 숨긴 다른 것(작업이나 WMI 구독 안에서 악성 인자를 단 Microsoft 서명 `powershell.exe`)이 있을 수 있고, 훔친 자격 증명(**정상 계정**을 통한 지속성, T1078 — 서비스를 지운다고 로그아웃되지 않음)이 있을 수 있고, 최악의 경우 호스트 안의 도구에게서 자신을 숨기는 커널 수준 루트킷이 있을 수 있습니다. 그 PC에서 쓰인 자격 증명의 범위를 잡고, `-m` 없이 Autoruns를 전체로 한 번 더 돌리고, 청소하는 대신 다시 설치하는 걸 고려하세요.

## 관련 레퍼런스 { #related }

- [Credential Guard, Application Guard, 호스트 방화벽, 백신](vbs-firewall-antivirus.md) — 앞 방어선 · [자산 목록, 취약점 스캔, 패치, 익스플로잇 보호](inventory-vulns-patching.md)
- [실행, 지속성, 정보 탐색](../endpoint-attacks/execution-persistence-discovery.md) · [권한 상승](../endpoint-attacks/privilege-escalation.md)
- [지속성 — 서비스, 예약 작업, Run 키](../../../adversary/persistence.md) · [LOLBins](../../../adversary/lolbins.md) · [프로세스 인젝션](../../../adversary/process-injection.md) · [PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md)
- [방어 무력화와 로그 삭제](../../../adversary/impair-defenses-log-clearing.md) · [Windows 버전별 하드닝](../../../adversary/hardening-by-version.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
