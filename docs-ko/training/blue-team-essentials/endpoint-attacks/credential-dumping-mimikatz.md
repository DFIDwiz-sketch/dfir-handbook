---
title: "자격 증명 덤프와 Mimikatz — 관리자 한 명에서 수많은 계정으로"
tags:
  - training
  - blue-team
  - endpoint
  - credential-access
---

# 자격 증명 덤프와 Mimikatz — 관리자 한 명에서 수많은 계정으로 { #credential-dumping-mimikatz }

!!! abstract "이 페이지에서 다루는 것"
    공격자가 Windows 호스트 한 대에서 관리자가 된 <strong>바로 다음</strong>에 하는 일을 봅니다. <strong>자격 증명 덤프(credential dumping)</strong> — 그 기계에 로그인해 있는 <strong>모든</strong> 사용자에 대해 Windows가 들고 있는 비밀번호·해시·티켓을 읽어 내서, 다른 사람으로, 다른 곳에 로그인하는 것입니다. 왜 이걸 하려면 애초에 관리자 권한이 필요한지, 그리고 이미 관리자인 공격자에게 왜 그래도 이득인지. Windows 통합 로그인(SSO)이 어떻게 동작하고, 그 때문에 왜 `lsass.exe`가 메모리에 비밀을 들고 있는지. <strong>Mimikatz</strong>가 무엇이고, 요즘 Windows에서 무엇을 얻고 무엇은 못 얻는지(대개 평문이 아니라 해시), 그리고 왜 "Mimikatz만 막으면 된다"가 안 통하는지(다시 컴파일, 이름 바꾸기, PowerShell로 다시 쓰기, 메모리에서만 실행, 비슷한 도구가 수두룩). 그다음 자격 증명 덤프가 그렇게 위험한 이유인 <strong>사슬</strong>을 봅니다. 여러 사용자가 로그인한 기계 한 대가 뚫리면 계정 여러 개가 한꺼번에 털리고, 공격자는 도메인 관리자가 걸릴 때까지 호스트에서 호스트로 건너갑니다. 모든 샘플(`GrantedAccess`를 풀어 본 `lsass.exe` 접근 Sysmon 10, WDigest를 바꾼 Sysmon 13, PowerShell 4104, 가린 덤프 결과, 로그온 유형 9 `seclogo`와 NTLM 네트워크 로그온 4624, 드라이버 7045, Credential Guard·LSA 보호 확인)을 칸 단위로 풀어 봅니다. 끝에 확인 문제가 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 해시, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. <strong>자격 증명 접근(Credential Access, TA0006)</strong>은 ATT&CK에서 독립된 전술입니다. 운영체제에서 자격 증명을 빼내는 것은 <strong>T1003 OS Credential Dumping</strong>, 그중 `lsass.exe` 프로세스에서 읽어 내는 것은 <strong>T1003.001 LSASS Memory</strong>입니다. 실제로는 <strong>신원을 통한 권한 상승</strong>처럼 동작합니다. 이미 가진 접근을 써서 <em>다른 계정이 되는</em> 겁니다.
2. 앞 페이지의 권한 상승 수법과 다른 점은 <strong>먼저 관리자(또는 SYSTEM)가 돼 있어야</strong> 한다는 것입니다. 다른 프로세스의 메모리나 레지스트리의 보호된 부분을 읽는 건 관리자만 할 수 있습니다.
3. 이미 관리자인데 왜 굳이? 덤프는 내 계정만이 아니라 <strong>그 기계에 로그인해 있는 모든 계정</strong>을 주기 때문입니다. 때로는 <strong>평문 비밀번호</strong>까지 줘서, 그 비밀번호가 통하는 모든 곳에서 쓸 수 있습니다.
4. Windows는 <strong>통합 로그인(SSO, Single Sign-On)</strong>을 위해 자격 증명을 저장합니다. 비밀번호를 한 번 입력하면 Windows가 거기서 나온 비밀 값(NTLM 해시, Kerberos 티켓, 때로는 되돌릴 수 있는 형태)을 `lsass.exe` 메모리에 두고, 나중에 나 대신 답합니다. 바로 그 편리함을 공격자가 훔칩니다.
5. <strong>Mimikatz</strong>(ATT&CK 소프트웨어 <strong>S0002</strong>)는 `lsass.exe`에서 그 비밀을 읽어 내는 가장 유명한 도구입니다. 요즘 제대로 설정된 Windows에서는 보통 <strong>평문이 아니라 해시와 티켓</strong>을 얻습니다. 그래도 해시만 있으면 다른 곳에 로그인할 수 있습니다(<strong>T1550.002 Pass the Hash</strong>, <strong>T1550.003 Pass the Ticket</strong>).
6. 파일 하나를 막는 걸로는 방어가 안 됩니다. Mimikatz는 다시 컴파일된 것, 직접 만든 것, 이름 바꾼 것, <strong>메모리에서만 도는 PowerShell 버전</strong>, 다른 도구 안의 기능으로 존재합니다. 게다가 LSASS를 같은 방식으로 덤프하는 도구가 많습니다. 파일 이름이 아니라 <strong>행동</strong>(무언가가 `lsass.exe`를 열어 메모리를 읽음)을 탐지하세요.
7. 진짜 위험은 <strong>사슬</strong>입니다. 여러 사람이 로그인한 서버의 관리자는 그 사람들 전부를 덤프할 수 있고, 털린 계정 하나하나가 기계를 더 열어 주고, <strong>도메인 관리자</strong>가 나올 때까지 반복됩니다. 기계 한 대가 네트워크 전체가 됩니다. 이게 <strong>옆으로 이동(Lateral Movement, TA0008)</strong>의 연료입니다.
8. 가장 좋은 방어는 <em>훔칠 것</em>과 <em>훔칠 수 있는 사람</em>을 줄이는 것입니다. 관리자 자격 증명을 귀하게 다루고 <strong>높은 권한 계정으로 신뢰 낮은 기계에 절대 로그인하지 않기</strong>, 기계마다 다른 로컬 관리자 비밀번호(LAPS), <strong>Credential Guard</strong>, <strong>LSA 보호</strong>, <strong>Protected Users</strong> 그룹, 그리고 LSASS에서 자격 증명 훔치기를 막는 Defender 규칙.

## 전술로서의 자격 증명 덤프 { #tactic }

### 공격 흐름에서 어디쯤인가 { #where }

앞 페이지에서 공격자는 호스트 한 대 안에서 일반 사용자에서 <strong>로컬 관리자나 SYSTEM</strong>까지 올라왔습니다. <em>첫 번째</em> 오르막은 끝났지만, 아직 기계는 한 대뿐입니다. 공격자의 진짜 목표 — 파일 서버, 재무 시스템, 도메인 컨트롤러 — 는 다른 곳에 있고, 거기에 들어가려면 <strong>거기서 통하는 계정</strong>이 필요합니다.

자격 증명 덤프가 그 다리입니다. ATT&CK은 이걸 <strong>자격 증명 접근(TA0006)</strong> 전술의 <strong>T1003 OS Credential Dumping</strong> 기법으로 분류하고, Windows와 리눅스가 비밀을 두는 장소마다 하위 기법을 둡니다.

| 하위 기법 | 비밀이 나오는 곳 | 관리자 필요? |
| --- | --- | --- |
| T1003.001 LSASS Memory | `lsass.exe` 메모리 — 로그인한 사용자의 해시, 티켓, 때로는 평문 | 예(SYSTEM 프로세스에 디버그 수준 접근) |
| T1003.002 Security Account Manager | `SAM` 레지스트리 하이브 — <strong>로컬</strong> 계정 해시 | 예 |
| T1003.004 LSA Secrets | `SECURITY` 하이브 — 서비스 계정 비밀번호, 기계 비밀 값 | 예(SYSTEM) |
| T1003.005 Cached Domain Credentials | `SECURITY` 하이브 — 최근 도메인 로그온의, 깨기 어려운 해시 | 예(SYSTEM) |
| T1003.003 NTDS | 도메인 컨트롤러의 `ntds.dit` — 도메인의 <strong>모든</strong> 계정 | 예, DC에서 |
| T1003.006 DCSync | DC에게 네트워크로 비밀번호 데이터를 복제해 달라고 요청 | 복제 권한(보통 도메인 관리자급) |
| T1003.007 / .008 | 리눅스: `/proc`을 통한 프로세스 메모리, `/etc/shadow` | root |

이 페이지는 <strong>T1003.001</strong>에 집중합니다. "여러 사용자를 한꺼번에" 효과가 바로 여기서 나오기 때문입니다. 나머지는 [SAM·NTDS 추출](../../../adversary/sam-ntds-extraction.md)과 [DCSync](../../../adversary/dcsync.md)에서 다룹니다.

### 왜 관리자 권한이 필요한가 — 그래도 왜 이득인가 { #why-admin }

호텔을 떠올려 보세요. 손님마다 자기 방만 열리는 카드 키가 있습니다. 프런트는 모든 카드 키 코드를 잠긴 사무실에 보관합니다. 손님 방 하나의 자물쇠를 딴 도둑(일반 사용자)은 그 방에만 들어갑니다. 사무실에 들어간 도둑(관리자)은 <strong>모든 손님의 코드</strong>를 베낄 수 있고, 프런트 컴퓨터는 그 코드로 새 카드를 기꺼이 찍어 줍니다.

기술적으로 보면:

- `lsass.exe`는 <strong>SYSTEM</strong>으로 돕니다. 그 메모리를 읽으려면 <strong>`PROCESS_VM_READ`</strong> 권한이 있는 핸들(handle, 프로세스를 다루기 위한 손잡이)을 얻어야 합니다. Windows는 이걸 <strong>`SeDebugPrivilege`</strong>(프로그램 디버그 특권)를 가진, 이미 관리자인 프로세스에게만 줍니다. 이 특권은 기본적으로 `Administrators`의 것이고 일반 사용자에게는 없습니다.
- `SAM`과 `SECURITY` 레지스트리 하이브는 SYSTEM만 읽게 잠겨 있어서, 관리자도 한 단계 더 거쳐야 합니다(하이브를 저장하거나 SYSTEM으로 읽기).

그래서 일반 사용자는 자격 증명을 덤프할 수 없고, 자격 증명 덤프는 권한 상승 <strong>다음</strong>에 옵니다. 하지만 관리자가 되고 나면 공격자는 전에 없던 세 가지를 얻습니다.

1. <strong>다른 사람의 계정.</strong> 덤프는 로그인한 모두를 돌려줍니다. 어제 무언가 고쳐 준 헬프데스크 직원, 예약 작업의 서비스 계정, 지난주에 RDP로 들어온 관리자(그 세션이 아직 살아 있다면).
2. <strong>다른 곳에서도 통하는 형태.</strong> NTLM 해시나 Kerberos 티켓은 비밀번호를 몰라도 다른 기계에 <strong>그대로 다시 내밀 수</strong> 있습니다. <strong>평문</strong>을 얻으면 웹 포털, VPN, 이메일 등 그 사용자가 같은 비밀번호를 쓴 모든 곳에서도 쓸 수 있습니다.
3. <strong>신원을 통한 지속성.</strong> 악성코드는 지워지지만, 훔친 비밀번호는 누가 바꿀 때까지 계속 통합니다. "다 정리했다"던 사고가 다시 터지는 경우 상당수는 공격자가 그냥 다시 로그인한 겁니다.

!!! tip "[보충] 여기서 말하는 “해시”는 정확히 뭐고, 왜 비밀번호만큼 위험한가"
    Windows는 비밀번호 자체를 저장하지 않습니다. 비밀번호로 계산한, 16진수 32자짜리 고정 값인 <strong>NT 해시</strong>(흔히 NTLM 해시라고 부름)를 저장합니다. NTLM 인증 프로토콜은 비밀번호가 아니라 <strong>해시로</strong> 계산해서 "비밀번호를 안다"를 증명합니다. 그러니 해시를 가진 사람은 서버의 질문(challenge)에 나와 똑같이 답할 수 있습니다. "해시만 털렸다"가 전혀 안심이 안 되는 이유입니다. NTLM에서는 해시가 <strong>곧</strong> 자격 증명입니다. Kerberos도 비슷해서, 훔친 티켓(TGT나 서비스 티켓)은 만료될 때까지 그대로 내밀 수 있습니다. [Pass-the-Hash](../../../adversary/pass-the-hash.md)와 [골든·실버 티켓](../../../adversary/golden-silver-tickets.md)을 보세요.

## Windows 통합 로그인이 메모리에 비밀을 두는 방식 { #sso }

이 모든 게 가능한 이유가 되는 설계 선택이 있습니다. Microsoft는 사용자가 <strong>비밀번호를 한 번만</strong> 입력하길 원합니다. 로그인한 뒤에는 파일 공유, 메일함, 사내 사이트, 프린터가 그냥 열려야 합니다. 이게 <strong>통합 로그인(SSO)</strong>입니다.

그러려면 Windows는 비밀번호를 입력하고 몇 분, 몇 시간이 지난 뒤에도 <strong>나 대신</strong> 인증 요청에 답해야 합니다. 그래서 로그인할 때 <strong>로컬 보안 기관 하위 시스템 서비스(Local Security Authority Subsystem Service)</strong>, 즉 `lsass.exe`가 필요한 것을 자기 메모리에 들고 있습니다. <strong>인증 패키지(authentication package, 보안 지원 공급자)</strong>별로 정리돼 있습니다.

| 패키지 | 들고 있는 것 | 이유 |
| --- | --- | --- |
| <strong>MSV1_0</strong>(NTLM) | NT 해시 | 파일 공유, 오래된 앱의 NTLM 질문에 답하기 |
| <strong>Kerberos</strong> | 티켓(TGT, 서비스 티켓)과 비밀번호에서 나온 키 | 다시 묻지 않고 새 서비스 티켓 받기 |
| <strong>WDigest</strong> | 예전에는 <strong>되돌릴 수 있게 저장한 평문</strong> 비밀번호 | 옛 HTTP Digest 인증 — Windows 8.1 / Server 2012 R2부터 <strong>기본 꺼짐</strong> |
| <strong>TsPkg / CredSSP</strong> | RDP·원격 로그인용으로 넘겨준 자격 증명 | 원격 서버에 내 로그인을 전달 |
| <strong>자격 증명 관리자(vault)</strong> | 사이트, 공유, 앱용으로 저장한 비밀번호 | "자격 증명 기억" |

이 표가 <strong>공격자의 장보기 목록</strong>입니다. `lsass.exe` 메모리를 읽고 이 구조를 이해하는 도구는 사용자마다 해시, 세션마다 티켓, 그리고 아직 평문을 들고 있는 패키지가 있으면 평문까지 뽑아냅니다.

비유하면, SSO는 믿을 만한 집사에게 모든 열쇠 사본을 맡겨 하루 종일 문을 대신 열게 하는 것입니다. 편리하죠. 누가 그 집사를 털기 전까지는요.

!!! tip "[보충] 어떤 로그온이 다시 쓸 수 있는 비밀을 남기나"
    모든 로그온이 로그인당한 기계의 `lsass.exe`에 자격 증명을 남기지는 않습니다. 아래 "여러 사용자" 문제에서 이게 아주 중요합니다.

    | 로그온 유형(4624 `LogonType`) | 예 | 그 호스트에 다시 쓸 수 있는 비밀이 남나? |
    | --- | --- | --- |
    | 2 Interactive(대화형) | 키보드 앞에서 로그인 | <strong>예</strong> |
    | 10 RemoteInteractive(원격 대화형) | 보통의 RDP 세션 | <strong>예</strong> |
    | 4 Batch / 5 Service | 비밀번호를 저장한 예약 작업·서비스 | <strong>예</strong>(비밀번호는 LSA 비밀에도 있음) |
    | 9 NewCredentials | `runas /netonly` | <strong>예</strong>(따로 넣은 자격 증명) |
    | 3 Network(네트워크) | `\\server\share` 열기, 대부분의 원격 관리 | <strong>아니요</strong>(보통 신원만 증명하고 비밀번호나 다시 쓸 해시는 남기지 않음) |

    그래서 서버를 네트워크 로그온(유형 3)으로 관리하는 관리자는 RDP(유형 10)로 들어가는 관리자보다 훨씬 덜 남깁니다. RDP의 <strong>Restricted Admin(제한된 관리자)</strong> 모드와 <strong>Remote Credential Guard(원격 자격 증명 보호)</strong>는 이 점에서 RDP를 네트워크 로그온처럼 동작하게 만들려고 있는 기능입니다.

## Mimikatz { #mimikatz }

### 무엇인가 { #what }

<strong>Mimikatz</strong>는 프랑스 연구자가 만든 오픈소스 Windows 보안 도구로, 2011년 무렵 처음 공개됐습니다. Windows가 메모리에 되살릴 수 있는 자격 증명을 들고 있다는 걸 보여 주는 개념 증명으로 시작해서, Windows 자격 증명에 관한 거의 모든 걸 하는 도구 상자로 커졌습니다. `lsass.exe`에서 읽기, SAM과 LSA 비밀 읽기, Kerberos 티켓 내보내기·끼워 넣기, 티켓 위조, DCSync 등. 랜섬웨어 조직부터 국가 배후 그룹까지, 침해 보고서마다 등장합니다. 효과적이고, 무료이고, 문서가 잘 돼 있기 때문입니다. ATT&CK은 소프트웨어 <strong>S0002</strong>로 추적합니다.

모든 방어자가 하는 이 말의 주된 이유이기도 합니다. <strong>평소 업무에 관리자 계정을 쓰지 말고, 일반 기계에 도메인 관리자 계정으로 절대 로그인하지 마라.</strong> 그럴 때마다 집사 주머니에 열쇠를 하나씩 넣어 두는 겁니다.

### 동작 방식 — 방어자가 알아야 할 수준으로 { #how-it-works }

Mimikatz를 막으려고 직접 돌려 볼 필요는 없습니다. <strong>무엇을 건드리는지</strong>만 알면 됩니다. 그게 바로 우리 눈에 보이는 부분이니까요.

1. <strong>권한이 필요합니다.</strong> `SeDebugPrivilege`를 켜거나(관리자만 가능) SYSTEM으로 돕니다.
2. <strong>`lsass.exe`에 핸들을 엽니다.</strong> 메모리 읽기 권한을 달라고 합니다. 탐지에서 가장 중요한 한 지점입니다.
3. <strong>메모리를 읽고 해독합니다.</strong> 인증 패키지마다의 구조를 찾아서, 역시 `lsass.exe` 메모리에 있는 키로 저장된 비밀을 풉니다.
4. <strong>결과를 출력하거나 저장합니다.</strong> 사용자 이름, 도메인, NT 해시, 때로는 평문 비밀번호, Kerberos 티켓.

명령은 <em>모듈</em>로 묶여 있습니다(예: LSASS 읽기는 `sekurlsa`, SAM·LSA 비밀·DCSync는 `lsadump`, 티켓은 `kerberos`). 이 모듈 이름이 PowerShell 로그, 명령줄, EDR 경보에 나오니 알아볼 수 있어야 합니다. `sekurlsa::logonpasswords`가 "LSASS에서 전부 덤프하기"의 대표 명령입니다.

방어자가 공격자의 출력 파일이나 스크립트 로그에서 되찾은 <strong>결과</strong>는 이렇게 생겼습니다(비밀 값은 가림).

```
Authentication Id : 0 ; 4519873 (00000000:0044f7c1)
Session           : RemoteInteractive from 2
User Name         : b.santos
Domain            : CORP
Logon Server      : DC01
Logon Time        : 2026-11-17 09:12:40
SID               : S-1-5-21-1111111111-2222222222-3333333333-1188
        msv :
         [00000003] Primary
         * Username : b.santos
         * Domain   : CORP
         * NTLM     : [redacted - 32 hex characters]
        wdigest :
         * Username : b.santos
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : b.santos
         * Domain   : CORP.EXAMPLE
         * Password : (null)
```

한 줄씩 읽어 봅니다.

- `Authentication Id : 0 ; 4519873 (00000000:0044f7c1)` — <strong>로그온 세션 ID</strong>(LUID)입니다. 16진수 `0x44f7c1`은 그 사용자의 <strong>4624</strong> 이벤트에 있는 `TargetLogonId`와 같은 값이라, 덤프를 그 사용자가 <em>언제, 어떻게</em> 로그인했는지와 이어 붙일 수 있습니다.
- `Session : RemoteInteractive from 2` — 이 사용자는 <strong>RDP</strong>(로그온 유형 10)로 로그인해 있습니다. 비밀이 여기 남은 건 <em>바로</em> 이 서버에 RDP로 들어왔기 때문입니다.
- `User Name : b.santos` / `Domain : CORP` / `Logon Server : DC01` — 누구인지, 어느 도메인인지, 어느 DC가 인증했는지.
- `msv` → `NTLM : …` — <strong>NT 해시</strong>. 이것만으로 pass-the-hash가 됩니다.
- `wdigest` → `Password : (null)` — WDigest가 평문을 들고 있지 않습니다(요즘 Windows의 기본값). 오래됐거나 설정이 잘못된 호스트라면 이 줄에 <strong>진짜 비밀번호</strong>가 나옵니다.
- `kerberos` → `Password : (null)` — Kerberos 쪽에도 평문은 없습니다. 티켓은 티켓 관련 명령으로 따로 나옵니다.

실제 덤프에는 이런 덩어리가 <strong>로그온 세션마다 하나씩</strong> 들어 있습니다. 이게 다음 절의 핵심입니다.

!!! tip "[보충] 옛 호스트가 평문을 흘리는 이유와 WDigest 수법"
    Windows 7 / Server 2008 R2 이전에는 WDigest가 기본으로 비밀번호를 풀 수 있는 형태로 들고 있어서, Mimikatz가 평문을 그대로 출력했습니다. Microsoft가 이걸 껐고(Windows 8.1 / Server 2012 R2부터 기본, 옛 버전은 업데이트), 레지스트리 값 `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`로 조절합니다. 관리자 권한을 가진 공격자는 이걸 <strong>다시 `1`로</strong> 바꾸고 기다립니다. 다음에 누군가 로그인하면 평문이 다시 메모리에 남습니다. 이 변경은 쉽게 잡힙니다(아래 Sysmon 13). ATT&CK은 <strong>T1112 Modify Registry</strong>로 분류합니다.

### 왜 "Mimikatz만 막으면 된다"가 안 통하나 { #why-not-block }

처음엔 이렇게 생각하기 쉽습니다. 백신이 Mimikatz를 알잖아, 해시랑 이름을 막으면 끝. 이게 안 되는 이유는 여러 가지입니다.

- <strong>소스에서 다시 컴파일.</strong> 코드가 공개돼 있습니다. 직접 컴파일하면 파일 해시가 바뀌고, 문자열과 구조를 조금 바꾸면 많은 시그니처를 피합니다.
- <strong>직접 만든 빌드.</strong> 유명한 문자열을 지우고, 함수 이름을 바꾸고, 압축하거나 암호화합니다.
- <strong>다른 언어, 파일 없음.</strong> <strong>PowerShell</strong>(옛 `Invoke-Mimikatz` 스크립트), C#, Python 등으로 옮겨지거나 감싸졌습니다. 한 줄짜리 다운로드 크래들이 인터넷에서 그런 스크립트를 가져와 <strong>메모리에서만</strong> 돌릴 수 있습니다. 백신이 검사할 파일이 디스크에 하나도 안 생깁니다([PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md)).
- <strong>프레임워크에 내장.</strong> 많은 C2(명령·제어) 프레임워크가 Mimikatz 같은 기능을 품고 있거나 모듈로 불러옵니다.
- <strong>다른 도구, 같은 기법.</strong> 그 자리에서 해독하는 대신, 공격자는 흔히 정상처럼 보이는 도구나 Windows 기본 DLL로 <strong>`lsass.exe` 메모리 전체를 파일로 떠서</strong>, 그 파일을 밖으로 가져가 자기 기계에서 해독합니다. 그러면 우리 네트워크에서는 Mimikatz가 <em>한 번도</em> 돌지 않습니다.

그러니 방어자의 질문은 "`mimikatz.exe`가 돌았나?"가 아니라 "<strong>무언가가 `lsass.exe`를 열어 메모리를 읽었나, 아니면 그 덤프를 파일로 썼나?</strong>"입니다.

## 로그에서 자격 증명 덤프 찾기 { #evidence }

### 1. 무언가가 LSASS를 열었다 — Sysmon 10 { #sysmon10 }

Sysmon <strong>이벤트 10(ProcessAccess, 프로세스 접근)</strong>은 한 프로세스가 다른 프로세스의 핸들을 연 것을 기록합니다. `lsass.exe`를 지켜보도록 설정하면 가장 좋은 단일 신호입니다.

```
Event ID: 10   Process accessed
UtcTime:        2026-11-18 03:14:22.508
SourceProcessId: 7344
SourceImage:    C:\Users\Public\Music\svchost64.exe
SourceUser:     CORP\adm.jlee
TargetProcessId: 712
TargetImage:    C:\Windows\system32\lsass.exe
TargetUser:     NT AUTHORITY\SYSTEM
GrantedAccess:  0x1010
CallTrace:      C:\Windows\SYSTEM32\ntdll.dll+9d204|C:\Windows\System32\KERNELBASE.dll+2c13e|UNKNOWN(00000204A1B3C2D1)
```

- `Event ID 10` — "프로세스 접근": 핸들이 열렸습니다. 무엇을 읽었는지는 말해 주지 않고, 어떤 권한으로 문을 열었는지만 알려 줍니다.
- `SourceImage C:\Users\Public\Music\svchost64.exe` — <strong>연 쪽</strong>입니다. <strong>공용 사용자 폴더</strong>에 있는 "svchost" 흉내는 가짜입니다. 진짜 `svchost.exe`는 `System32`에 삽니다. LSASS를 정상적으로 여는 프로그램은 짧고 알려진 목록입니다(우리 EDR/백신, `MsMpEng.exe`, `wininit.exe`, 일부 관리 에이전트).
- `SourceUser CORP\adm.jlee` — 관리자 계정. 기억하세요. 덤프에는 관리자가 <em>필요</em>하니, 관리자가 연 것은 공격일 때 당연한 모습이지 안심할 이유가 아닙니다.
- `TargetImage …\lsass.exe` — 대상은 자격 증명 저장소입니다.
- `GrantedAccess 0x1010` — 접근 마스크(access mask)로, <em>어떤 종류의</em> 문이 열렸는지 알려 줍니다. 비트로 나눠 읽습니다.
    - `0x1000` = `PROCESS_QUERY_LIMITED_INFORMATION`(프로세스의 기본 정보 조회)
    - `0x0010` = `PROCESS_VM_READ`(<strong>메모리 읽기</strong>)
    - 합치면 `0x1010` = "LSASS 메모리를 읽게 해 줘" — 전형적인 Mimikatz식 마스크입니다. 그 밖에 경보할 만한 마스크는 `0x1410`, `0x1438`, `0x143a`, `0x1fffff`(모든 권한) 등입니다. 무해한 도구 상당수는 `0x1000`이나 `0x1400`(정보 조회만, 메모리 읽기 없음)만 요청합니다.
- `CallTrace … UNKNOWN(00000204A1B3C2D1)` — 이 호출을 한 코드의 연결 고리입니다. 정상 항목은 디스크에 있는 DLL 이름이 나옵니다. <strong>`UNKNOWN`</strong>은 어떤 파일에도 바탕을 두지 않고 메모리에서 도는 코드라는 뜻으로, 주입되거나 반사적으로(reflectively) 불려 온 도구의 전형입니다. 디스크를 전혀 건드리지 않은 메모리 Mimikatz도 이렇게 잡습니다.

### 2. 덤프 파일이 써졌다 — Sysmon 11 / 4688 { #dump-file }

공격자가 LSASS를 파일로 뜬다면, 그 일을 한 프로세스와 쓴 파일을 찾습니다.

```
EventID:            4688
NewProcessName:     C:\Windows\System32\rundll32.exe
CommandLine:        rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Windows\Temp\wd.bin full
ParentProcessName:  C:\Windows\System32\cmd.exe
SubjectUserName:    adm.jlee
TokenElevationType: %%1937
```

- `NewProcessName …\rundll32.exe` — `rundll32`는 DLL이 내보낸 함수를 실행합니다. 공격자가 좋아하는 <strong>환경 속에 숨어 사는(living off the land)</strong> 바이너리입니다([LOLBins](../../../adversary/lolbins.md)).
- `CommandLine … comsvcs.dll, MiniDump 712 … full` — Windows 기본 DLL의 `MiniDump` 함수를 <strong>프로세스 ID 712</strong>에 대해 부릅니다. 위의 Sysmon 10을 보면 712가 `lsass.exe`입니다. 그리고 <strong>메모리 전체 덤프</strong>를 `C:\Windows\Temp\wd.bin`에 씁니다. 확장자를 일부러 `.dmp`로 하지 않았습니다.
- `TokenElevationType %%1937` — <strong>상승된</strong> 토큰(UAC에서 "예"를 눌렀거나 우회됨). 다시 말하지만 관리자가 필요합니다.

`wd.bin`에 대한 <strong>Sysmon 11(파일 생성)</strong>, 그리고 `rundll32.exe`가 `lsass.exe`를 연 <strong>Sysmon 10</strong>과 짝지어 보세요. 그다음 그 파일이 밖으로 나갔는지(그 호스트에서 나가는 SMB, 클라우드 업로드, 새 압축 파일)를 찾습니다. 같은 계열(덤프 유틸리티, 작업 관리자의 "덤프 파일 만들기", 직접 만든 덤프 도구)은 [LSASS 덤프](../../../adversary/lsass-dumping.md)를 보세요.

### 3. 메모리에서 도는 PowerShell 버전 — 4104 { #ps4104 }

PowerShell 포팅판이 다운로드 크래들로 돌면, 스크립트 블록 로깅이 그 본문을 잡습니다.

```
Log Name:       Microsoft-Windows-PowerShell/Operational
Event ID:       4104
Level:          Warning
Computer:       SRV-APP-07.corp.example
User:           CORP\adm.jlee
Message:        Creating Scriptblock text (3 of 112):
                ...
                function Invoke-Mimikatz
                ...
                $PEBytes64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAA...
ScriptBlock ID: 0c4a8f1e-5b77-4d2a-9e63-4f1d0a2b9c11
Path:
```

- `Level Warning` — PowerShell 스스로 이 블록을 <strong>수상하다</strong>고 보고 자동으로 기록했습니다.
- `(3 of 112)` — 아주 큰 스크립트가 이벤트 112개로 나뉘었습니다. `ScriptBlock ID`로 이어 붙입니다.
- `function Invoke-Mimikatz` — 대표적인 함수 이름(공격자가 자주 바꾸니 이것만 믿지는 마세요).
- `$PEBytes64 = "TVqQ…"` — `TVqQ`로 시작하는 긴 Base64 문자열입니다. `TVqQ`는 `MZ`의 Base64, 즉 <strong>Windows 실행 파일</strong>의 시작입니다. 스크립트가 프로그램 하나를 통째로 품고 있다가 메모리에 올리는 겁니다. 함수 이름이 뭐든, 스크립트 블록 안의 `TVqQ`로 시작하는 거대한 Base64 덩어리는 수상합니다.
- `Path:` 비어 있음 — 디스크의 파일이 아니라 메모리나 명령줄에서 왔습니다.

AMSI 덕분에 Defender나 EDR이 실행 순간 같은 텍스트를 검사하고 막을 수 있습니다.

### 4. 누군가 평문 저장을 다시 켰다 — Sysmon 13 { #wdigest }

```
Event ID: 13   Registry value set
UtcTime:      2026-11-18 03:09:57.114
Image:        C:\Windows\System32\reg.exe
TargetObject: HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
Details:      DWORD (0x00000001)
User:         CORP\adm.jlee
```

- `TargetObject …\WDigest\UseLogonCredential` — 평문 저장 스위치입니다.
- `Details DWORD (0x00000001)` — <strong>1 = 켜짐</strong>으로 바뀌었습니다. 요즘 Windows 호스트에서는 정당한 이유가 거의 없습니다. 여기에 `1`이 써지면 무조건 경보하고, 다음 로그인 뒤에 덤프가 올 거라고 예상하세요.

### 5. 훔친 자격 증명이 쓰인다 — 4624 { #use }

덤프 자체는 네트워크에서 조용하지만, 결과를 <strong>쓰는 것</strong>은 조용하지 않습니다. 알아 둘 두 가지 모양이 있습니다(로그온 이벤트는 뒤의 섹션에서 따로 한 페이지로 다룹니다).

공격자 쪽 호스트에서는 pass-the-hash 실행기가 보통 <strong>새 자격 증명</strong>으로 프로세스를 띄웁니다.

```
EventID:                   4624
LogonType:                 9
LogonProcessName:          seclogo
AuthenticationPackageName: Negotiate
SubjectUserName:           adm.jlee
TargetUserName:            adm.jlee
TargetOutboundUserName:    c.ito
TargetOutboundDomainName:  CORP
```

- `4624` — "계정이 성공적으로 로그온했습니다".
- `LogonType 9` — <strong>NewCredentials</strong>: "내 로컬 신원은 그대로 두고, 네트워크 접근에만 <em>다른</em> 자격 증명을 써라" — `runas /netonly`가 하는 일입니다. 정당한 기능이지만 대부분의 PC와 서버에서는 드뭅니다.
- `LogonProcessName seclogo` — 보조 로그온(Secondary Logon) 서비스. 낯선 프로세스에서 나온 `seclogo` 로그온 유형 9는 잘 알려진 pass-the-hash 모양입니다.
- `TargetOutboundUserName c.ito` — 네트워크에서 쓰일 신원, 즉 <strong>다른 사람의 계정</strong>이자 훔친 자격 증명입니다.

공격자가 옮겨 간 기계에서는 NTLM을 쓴 네트워크 로그온으로 들어옵니다.

```
EventID:                   4624
Computer:                  FS-FIN-02.corp.example
LogonType:                 3
TargetUserName:            c.ito
LogonProcessName:          NtLmSsp
AuthenticationPackageName: NTLM
LmPackageName:             NTLM V2
KeyLength:                 0
WorkstationName:           SRV-APP-07
IpAddress:                 10.20.4.37
```

- `LogonType 3` — 네트워크 로그온(공유 접근, 원격 서비스 등).
- `TargetUserName c.ito` — 쓰인 계정.
- `AuthenticationPackageName NTLM` / `LogonProcessName NtLmSsp` — Kerberos가 아니라 NTLM입니다. 요즘 도메인에서는 도메인 기계 사이의 로그온 대부분이 Kerberos인데, pass-the-hash는 <strong>NTLM</strong>을 쓸 수밖에 없습니다.
- `KeyLength 0` — 세션 키 없음. NTLM 네트워크 로그온에서 흔하고, pass-the-hash에서도 자주 보입니다.
- `WorkstationName SRV-APP-07` / `IpAddress 10.20.4.37` — <strong>어디서</strong> 왔는지. `c.ito`가 애플리케이션 서버에서 로그인한 적이 한 번도 없는 재무 직원이라면 이게 실마리입니다.

4624 하나만으로 pass-the-hash가 증명되지는 않습니다. 하지만 *SRV-APP-07의 Sysmon 10 → 4624 유형 9 seclogo → 그 서버를 쓴 적 없는 계정들의, SRV-APP-07에서 출발한 새 NTLM 유형 3 로그온*이라는 사슬은 무해하게 설명되는 일이 거의 없습니다.

### 6. LSA 보호 깨기 — 7045 { #driver }

LSA 보호가 켜져 있으면(아래) 그냥 Mimikatz로는 `lsass.exe`를 못 엽니다. 그러면 공격자는 <strong>커널 드라이버</strong>로 보호를 벗기려 합니다. Mimikatz에는 드라이버(`mimidrv.sys`)가 딸려 있고, 취약하지만 서명된 드라이버도 같은 식으로 씁니다(BYOVD, [권한 상승](privilege-escalation.md#kernel) 참고). 드라이버를 올리면 서비스가 생깁니다.

```
EventID:      7045
Service Name: mimidrv
Image Path:   C:\Users\Public\Music\mimidrv.sys
Service Type: kernel mode driver
Start Type:   demand start
Account Name:
```

- `Service Type kernel mode driver` — <strong>커널에서</strong> 돌 코드입니다.
- 공용 사용자 폴더에 있는 `Image Path` — 드라이버는 `System32\drivers`나 제조사 폴더에 있어야 합니다.
- `Service Name mimidrv` — 기본 이름이지만, 제대로 된 공격자는 바꿉니다. 진짜 신호는 <em>모양</em>입니다. 사용자가 쓸 수 있는 경로에서 새 커널 드라이버가 올라오고, 곧이어 LSASS 접근이 있음.

## 관리자 한 명에서 네트워크 전체로 { #chain }

### 사슬을 한 단계씩 { #steps }

공격자가 이걸 그렇게 좋아하는 이유입니다. 침해 하나를 따라가 봅시다.

```
[Alice's laptop]          admin: Alice           signed in: Alice
      | dump  -> Alice's hash
      v
[App server SRV-APP-07]   admin: Alice (help-desk group)   signed in: Bob, Charlie (RDP)
      | dump  -> Bob's and Charlie's hashes
      v
[Charlie's laptop]        admin: Charlie         signed in: Charlie, d.admin (left an RDP session)
      | dump  -> domain admin's hash
      v
[Domain admin's laptop / DC]  -> every account in the domain -> sensitive data, ransomware
```

1. <strong>Alice의 노트북.</strong> Alice가 악성 첨부 파일을 엽니다. 공격자는 관리자로 올라가 덤프합니다. <strong>Alice의</strong> 자격 증명을 얻습니다. Alice는 많은 서버의 로컬 관리자인 헬프데스크 그룹 소속입니다.
2. <strong>SRV-APP-07.</strong> Alice의 해시로 애플리케이션 서버에 로그인합니다. 거기엔 <strong>Bob과 Charlie가 RDP로 로그인</strong>해 있습니다. 다시 덤프하면 <strong>Bob과 Charlie의</strong> 자격 증명까지 생깁니다. 침해 하나가 셋이 됐습니다.
3. <strong>Charlie의 노트북.</strong> Charlie는 자기 노트북의 관리자입니다. 공격자가 그리로 가서 덤프해 보니, 지난주 무언가를 고치러 RDP로 들어왔던 <strong>도메인 관리자</strong>의 세션이 아직 열려 있습니다.
4. <strong>끝.</strong> 도메인 관리자로 모든 기계, 모든 계정에 닿습니다. 데이터를 훔치고, 그룹 정책으로 랜섬웨어를 뿌리고, 뒷문 계정을 만듭니다.

비유하면, 자물쇠 하나를 땄더니 프런트의 열쇠 꾸러미가 나왔고, 그 꾸러미의 열쇠 하나가 직원 사무실을 열었고, 거기에 또 꾸러미가 있었고, 결국 건물 관리인의 꾸러미를 찾은 겁니다.

그림 속에 숨은 교훈이 둘 있습니다.

- <strong>여러 사용자가 로그인한 공용 서버는 노다지입니다.</strong> 터미널 서버, 점프 호스트, 관리자들이 RDP로 들어가는 모든 서버는 공격자에게 PC 한 대보다 훨씬 값집니다. 그만큼 지키세요.
- <strong>관리자 권한이 사슬의 고리입니다.</strong> 매번 건너뛸 수 있었던 건 어떤 계정이 <strong>다음 기계의 관리자</strong>였기 때문입니다. Alice가 SRV-APP-07의 로컬 관리자가 아니었다면, 또는 Charlie가 자기 노트북의 관리자가 아니었다면 사슬은 끊겼을 겁니다. 그래서 "관리자 자격 증명을 통제하라"가 Windows 네트워크에서 가장 중요한 방어입니다.

### 사슬 끊기 { #defend }

| 방어 | 어느 고리를 끊나 |
| --- | --- |
| <strong>계층화(tiering) / 신뢰 낮은 기계에 높은 권한으로 로그인 금지</strong>(도메인 관리자는 DC와 전용 관리 PC에서만) | Charlie의 노트북에 훔칠 도메인 관리자 비밀이 없음 |
| <strong>기계마다 다른 로컬 관리자 비밀번호 — LAPS</strong>(Windows LAPS 기본 내장) | 훔친 로컬 관리자 해시 하나가 모든 PC에서 통하지 않음 |
| 사용자와 넓은 헬프데스크 그룹의 <strong>상시 로컬 관리자 권한 제거</strong>, 필요할 때만 권한 부여(JIT) | 다음 기계로 건너가기 실패 |
| 관리 작업에 RDP 대신 <strong>네트워크 로그온</strong>, RDP는 <strong>Restricted Admin</strong>이나 <strong>Remote Credential Guard</strong>로 | 관리자가 서버에 다시 쓸 수 있는 비밀을 안 남김 |
| 관리자를 <strong>Protected Users 그룹</strong>에 | NTLM 없음, 캐시된 자격 증명 없음, 짧은 Kerberos 티켓 — 훔칠 게 적고 쓸 시간도 짧음 |
| <strong>Credential Guard</strong> | NT 해시와 Kerberos TGT를 가상화로 보호되는 격리 프로세스로 옮김. `lsass.exe`를 읽어도 안 나옴 |
| <strong>LSA 보호(RunAsPPL)</strong> | `lsass.exe`가 보호 프로세스로 돎. 관리자 도구도 커널 드라이버 없이는 메모리 읽기로 못 엶 |
| <strong>Defender ASR 규칙 "Windows 로컬 보안 기관 하위 시스템에서 자격 증명 도용 차단"</strong> | 믿을 수 없는 프로세스가 LSASS 메모리를 읽지 못하게 막음 |
| <strong>WDigest 끄고 감시</strong> | 되찾을 평문이 없음 |

!!! tip "[보충] Credential Guard와 LSA 보호가 진짜 돌고 있는지 확인하기"
    짐작하지 말고 확인하세요. Credential Guard는:

    ```powershell
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
      Select-Object SecurityServicesConfigured, SecurityServicesRunning
    ```

    ```
    SecurityServicesConfigured SecurityServicesRunning
    -------------------------- -----------------------
    {1, 2}                     {1, 2}
    ```

    - `Get-CimInstance … Win32_DeviceGuard` — 가상화 기반 보안(VBS) 상태를 조회합니다.
    - `SecurityServicesConfigured {1, 2}` — 정책이 <em>요구하는</em> 것: `1` = Credential Guard, `2` = 메모리 무결성(HVCI).
    - `SecurityServicesRunning {1, 2}` — <em>실제로 돌고 있는</em> 것. 여기에 `1`이 없으면 Credential Guard가 설정만 되고 돌지 않는 겁니다(흔히 하드웨어나 펌웨어 문제).

    LSA 보호는 부팅 때 <strong>System</strong> 로그에 남는 <strong>WinInit 이벤트 12</strong>를 봅니다. "LSASS.exe was started as a protected process with level: 4(LSASS.exe가 보호 프로세스로 시작됨)". 이게 없으면 LSASS는 보호받지 못하고 있습니다. 보호된 LSASS에 올라가지 못하고 막힌 플러그인은 `Microsoft-Windows-CodeIntegrity/Operational`에 나옵니다(예: 이벤트 3033, 3063).

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    자격 증명 덤프는 지금도 사람이 직접 하는 침투와 랜섬웨어 사례에서 가장 흔한 단계 중 하나이고, LSASS 메모리(T1003.001)는 여전히 가장 인기 있는 출처입니다. Mimikatz 자체도 여전히 보이지만, 점점 더 그 <strong>기법</strong>이 다른 도구, Windows 기본 DLL, 직접 만든 덤프 도구, C2 모듈을 통해 나타납니다. 그래서 행동 기반 탐지(`lsass.exe` 핸들, 덤프 파일 생성, `UNKNOWN` 호출 추적)가 표준입니다. 관리자 한 명에서 수많은 계정으로 가는 사슬은 지금도 대부분의 도메인 장악을 설명하고, "권한 높은 자격 증명을 신뢰 낮은 기계에 두지 마라"는 여전히 핵심 조언입니다.

!!! info "[변경됨] 바뀐 점"
    - <strong>Credential Guard가 더 많은 곳에서 기본으로 켜집니다.</strong> Windows 11 22H2와 Windows Server 2025부터, Microsoft는 요구 사항(Enterprise/Education 에디션, VBS와 보안 부팅이 되는 하드웨어)을 갖춘 도메인 가입·비 DC 시스템에서 이를 UEFI 잠금 없이 기본으로 켭니다. 이게 돌고 있으면 LSASS를 덤프해도 로그인한 도메인 사용자의 NT 해시나 TGT가 나오지 않습니다.
    - <strong>새 기업 설치에서는 LSA 보호가 기본으로 켜집니다.</strong> Windows 11 22H2 이후, 기업 가입(AD, Entra, 하이브리드)이고 HVCI를 지원하는 <strong>새 설치</strong>(업그레이드 말고)에서 자동으로 켜집니다. 공격자는 커널 드라이버와 BYOVD로 보호를 벗기려 하니, 새 드라이버(7045, Sysmon 6)도 자격 증명 도용 탐지의 일부로 지켜보세요.
    - <strong>NTLM이 퇴장하고 있습니다.</strong> NTLMv1은 Windows 11 24H2와 Windows Server 2025에서 제거됐고, 2026년에 Microsoft는 앞으로의 Windows 릴리스에서 네트워크 NTLM을 기본으로 끄는 단계별 계획을 발표했습니다. pass-the-hash가 줄어들겠지만, 지금은 대부분의 네트워크가 여전히 NTLM을 허용합니다. 우리 버전의 정확한 일정은 Microsoft의 최신 안내를 확인하세요.
    - <strong>도용이 토큰과 클라우드 쪽으로 옮겨 갔습니다.</strong> 하이브리드 환경에서 공격자는 NT 해시 대신, 또는 그와 함께 엔드포인트에서 <strong>브라우저 세션 쿠키와 클라우드 토큰</strong>(Entra ID 갱신 토큰, 기본 갱신 토큰 PRT)을 훔치는 일이 늘었습니다. 흔한 정보 탈취 악성코드(infostealer)로요. ATT&CK에서는 <strong>T1539 Steal Web Session Cookie</strong>, <strong>T1528 Steal Application Access Token</strong>입니다. LSASS 보호는 이걸 막지 못하니 MFA만으로는 부족하고, 토큰 보호와 기기에 묶인 세션이 중요합니다.
    - <strong>ATT&CK.</strong> T1003과 하위 기법, T1550.002/.003, Mimikatz(S0002)는 ID가 그대로입니다. v19에서 Defense Evasion 전술이 Stealth와 Defense Impairment로 나뉜 것은 보호 기능 끄기 같은 주변 기법에 영향을 줄 뿐, 자격 증명 접근 자체는 바뀌지 않았습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - <strong>`mimikatz.exe`의 이름이나 해시만으로 탐지하지 마세요.</strong> 다시 컴파일되고, 이름이 바뀌고, 메모리에서 돕니다. LSASS 접근, 덤프 파일 생성, WDigest 변경, 이상한 NTLM 로그온을 탐지하세요.
    - <strong>Credential Guard가 모든 걸 지켜 준다고 생각하지 마세요.</strong> <strong>SAM</strong>(로컬 계정), <strong>도메인 컨트롤러</strong>(거기엔 권장되지 않음), `ntds.dit`은 지키지 않습니다. 관리자 권한을 가진 공격자는 침해 <strong>이후에 입력되는</strong> 비밀번호를 여전히 가로챌 수 있습니다(예: 악성 보안 지원 공급자나 키로거). 그리고 "Windows 11이니까"가 아니라 실제로 <em>돌고 있는지</em> 확인하세요.
    - <strong>"해시만 털렸다"를 믿지 마세요.</strong> NTLM에서는 해시가 곧 자격 증명입니다. 비밀번호를 바꾸세요. 아주 높은 권한 계정은 Kerberos 키까지 고려해야 하고, `krbtgt`는 문서화된 두 번 재설정 절차를 따르세요.
    - <strong>도메인 관리자 계정으로 PC나 공용 서버에 "잠깐 확인하러" RDP 하지 마세요.</strong> 위 사슬이 꼭대기까지 닿는 방법이 바로 그겁니다. 전용 관리 PC와 네트워크 기반 도구, 또는 Remote Credential Guard를 쓰세요.
    - <strong>승인 없이 운영 환경에서 "시험 삼아" LSASS 덤프 도구를 돌리지 마세요.</strong> 누군가 지켜야 하는 진짜 자격 증명 파일이 생기고, 우리 분석가들이 그 경보를 무시하도록 길들이게 됩니다.

## 확인 문제 { #quiz }

### 문제 1

`SRV-APP-07`에서 Sysmon 이벤트 10이 보입니다. `SourceImage = C:\Users\Public\Music\svchost64.exe`, `TargetImage = C:\Windows\system32\lsass.exe`, `GrantedAccess = 0x1010`, `CallTrace`는 `UNKNOWN(...)`으로 끝납니다. 연 사용자는 `CORP\adm.jlee`입니다. 각 정보가 무엇을 말해 주고, 다음에 무엇을 하겠습니까?

??? success "정답과 해설"
    `0x1010` = `PROCESS_QUERY_LIMITED_INFORMATION` + <strong>`PROCESS_VM_READ`</strong>. 무언가가 <strong>LSASS 메모리를 읽겠다</strong>고 요청했습니다. 자격 증명 덤프(T1003.001)의 핵심 동작입니다. 연 바이너리는 공용 사용자 폴더의 가짜 "svchost"로, 백신·EDR 같은 알려진 LSASS 접근 프로그램이 아닙니다. 호출 추적의 `UNKNOWN`은 그 코드가 어떤 파일에도 바탕을 두지 않았다는 뜻, 즉 주입됐거나 메모리에서 도는 도구입니다. 관리자가 연 건 당연합니다(덤프에는 관리자가 필요). 즉 `adm.jlee` — 또는 그 세션을 가진 누군가 — 가 뚫렸다는 뜻입니다.

    다음 할 일: 호스트를 격리합니다. 그 시간 무렵 <strong>SRV-APP-07에 로그인해 있던 모든 계정</strong>을 털린 것으로 봅니다(4624 이벤트와 활성 세션으로 목록을 만들고, 특히 RDP 사용자). 앞선 권한 상승과 `adm.jlee`를 어떻게 얻었는지 찾습니다. 덤프 파일(Sysmon 11), WDigest 변경(Sysmon 13), 새 드라이버(7045)를 찾습니다. 그다음 그 계정들이 다른 곳에서 <strong>쓰였는지</strong> 사냥합니다. 이 호스트에서 출발한 새 NTLM 유형 3 로그온과 4624 유형 9 `seclogo`. 해당 비밀번호를 바꾸고, 왜 애플리케이션 서버에 그렇게 많은 사용자가 로그인해 있었는지 검토합니다.

### 문제 2

터미널 서버에 40명이 RDP로 로그인해 있고, 그중 모든 PC의 로컬 관리자인 헬프데스크 계정이 둘 있습니다. 공격자가 이 서버의 로컬 관리자가 됐습니다. 노트북 한 대의 로컬 관리자보다 왜 훨씬 나쁜가요? 피해를 가장 크게 줄일 변경 세 가지는?

??? success "정답과 해설"
    RDP 세션은 <strong>로그온 유형 10</strong>이라 그 서버의 `lsass.exe`에 다시 쓸 수 있는 비밀(NT 해시, Kerberos 티켓)을 남깁니다. 관리자 권한으로 덤프 한 번이면 <strong>계정 40개가 한꺼번에</strong> 나오고, 그중 둘은 모든 PC의 관리자라 공격자는 아무 PC로나 가서 더 높은 계정이 나올 때까지 계속 덤프할 수 있습니다. 노트북 한 대에는 보통 사용자 한두 명뿐입니다.

    가장 효과 큰 변경: (1) 헬프데스크 계정의 <strong>넓은 상시 로컬 관리자 권한 제거</strong>(필요할 때만 부여)와 <strong>LAPS</strong>로 기계마다 다른 로컬 관리자 비밀번호, (2) <strong>권한 높은 계정을 공용 서버에 올리지 않기</strong> — 관리자는 네트워크 로그온이나 Remote Credential Guard/Restricted Admin을 쓰고, 관리자를 <strong>Protected Users</strong>에 넣기, (3) 그 서버에 <strong>Credential Guard와 LSA 보호</strong>를 켜고(돌고 있는지 확인), LSASS 자격 증명 도용 ASR 규칙과 LSASS 접근에 대한 Sysmon 10 경보 추가.

### 문제 3

한 관리자가 말합니다. "백신 차단 목록에 Mimikatz 파일 해시를 넣었고 `mimikatz.exe`라는 이름의 파일도 다 막았으니 자격 증명 덤프는 해결됐습니다." 어떻게 답하겠습니까?

??? success "정답과 해설"
    가장 서툰 공격자만 막는 겁니다. Mimikatz는 오픈소스라 다시 컴파일하거나 고친 빌드는 <strong>해시가 다릅니다</strong>. 이름을 바꾸면 이름 규칙도 무력해집니다. <strong>PowerShell</strong> 등 다른 언어 판은 한 줄짜리로 가져와서 <strong>메모리에서만</strong> 돌릴 수 있어 검사할 파일이 없습니다. C2 프레임워크도 같은 기능을 품고 있습니다. 그리고 공격자는 흔히 Mimikatz를 아예 건너뛰고 Windows 기본 구성 요소(예: `rundll32 comsvcs.dll MiniDump`)로 <strong>`lsass.exe`를 파일로 떠서</strong> 밖에서 해독합니다.

    실제로 막는 것: <strong>행동 탐지</strong> — 메모리 읽기 권한으로 `lsass.exe`를 여는 프로세스에 대한 Sysmon 10/EDR 경보, 덤프 파일 생성, 4104 스크립트 블록 로깅과 AMSI, WDigest 레지스트리 변경, 새 커널 드라이버 — 그리고 상품 자체를 없애는 <strong>예방</strong> — Credential Guard, LSA 보호, ASR 규칙, Protected Users, LAPS, 권한 높은 계정을 신뢰 낮은 기계에 두지 않기.

## 관련 레퍼런스 { #related }

- [권한 상승](privilege-escalation.md) — 이 단계 바로 앞 · [실행, 지속성, 정보 탐색](execution-persistence-discovery.md)
- [LSASS 덤프](../../../adversary/lsass-dumping.md) · [SAM·NTDS 추출](../../../adversary/sam-ntds-extraction.md) · [DCSync](../../../adversary/dcsync.md)
- [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [골든·실버 티켓](../../../adversary/golden-silver-tickets.md) · [SMB를 통한 PsExec](../../../adversary/psexec-smb.md)
- [SMB](../other-protocols/smb.md) — 훔친 자격 증명으로 옆으로 이동할 때 네트워크에서 보이는 모습
- [PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md) · [LOLBins](../../../adversary/lolbins.md) · [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
