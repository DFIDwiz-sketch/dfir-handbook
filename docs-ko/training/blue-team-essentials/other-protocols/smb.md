---
title: "SMB — 공격자가 좋아하는 이유, 버전과 협상, 대표 공격"
tags:
  - training
  - blue-team
  - network
  - smb
  - lateral-movement
---

# SMB — 공격자가 좋아하는 이유, 버전과 협상, 대표 공격 { #smb }

!!! abstract "이 페이지에서 다루는 것"
    SMB(Server Message Block)가 무엇인지, 왜 네트워크 안에서 가장 많이 공격받고 가장 잘 먹히는 서비스 중 하나인지, 그리고 "모든 PC에 같은 로컬 관리자 비밀번호"가 왜 피싱 한 번을 회사 전체 장악으로 바꾸는지. SMB 버전(dialect)들과 클라이언트·서버가 버전을 고르는 방법, SMB1을 반드시 없애야 하는 이유와 그게 SMB2에는 무슨 뜻인지(그리고 무슨 뜻이 아닌지). 이어서 SMB 공격의 두 갈래 — 진짜 계정으로 로그인하는 방식(PsExec류)과 SMB 서비스 자체의 취약점을 노리는 방식(EternalBlue류) — 를 한 단계씩 따라가며, 각 단계가 남기는 Windows 이벤트(4624, 4672, 5140, 5145, 7045, 4697, 4688, Sysmon 1·3)와 Zeek 로그를 읽습니다. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. SMB는 **Windows 기본 파일·프린터 공유 프로토콜**이다(Linux에서는 Samba가 구현). **TCP 445**(옛 NetBIOS 경로는 TCP 139)를 쓰고, Windows 도메인 환경에서는 **거의 모든 PC에 기본으로 열려 있다.**
2. 445번 포트는 **인터넷 쪽으로 절대 열려 있으면 안 된다**(들어오는 쪽도, 나가는 쪽도). 진짜 위험은 안쪽이다. 공격자가 한 대를 잡으면 SMB는 거의 어디서나 쓸 수 있어서 <strong>내부 정찰과 옆으로 이동(lateral movement)</strong>에 쓰인다.
3. SMB는 파일 복사만 하는 게 아니다. 원격 PC의 **관리자 아이디·비밀번호**가 있으면 SMB로 **그 PC에서 아무 프로그램이나 실행하고 명령줄을 쓸 수 있다.** SSH만큼 강력하지만, 관리자 권한이 필요하다.
4. 그래서 **여러 PC에 같은 관리자 비밀번호를 쓰는 것**(예: 기본 로컬 Administrator)이 가장 치명적인 실수 중 하나다. 한 대가 뚫리면 나머지 전부에 로그인할 수 있다.
5. 클라이언트와 서버가 각자 말할 수 있는 버전(dialect) 목록을 내밀고, **양쪽이 다 지원하는 가장 높은 버전**을 쓴다. 요즘 Windows는 SMB **3.1.1**을 쓴다.
6. **SMB1은 반드시 꺼야 한다.** 과거 최악의 SMB 익스플로잇들(EternalBlue와 그 형제들, WannaCry·NotPetya가 사용)이 바로 SMB1의 허술한 설계에 기대고 있었다.
7. SMB 공격은 두 갈래다. **진짜 계정 + 원격 실행 도구(PsExec류)**, 그리고 **패치 안 된 SMB를 노리는 서버 쪽 익스플로잇(EternalBlue류)**. 어느 쪽이든 공격자는 보통 일반 사용자가 아니라 **Administrator나 SYSTEM**이 된다.
8. 관리자가 되면 그 PC에 로그온해 있는 모든 사람의 자격 증명을 빼낼 수 있고(Mimikatz 등), 그 계정으로 또 이동한다. 그래서 PC끼리 SMB가 열려 있으면 **나쁜 상황이 순식간에 더 나빠진다.**

## SMB란 무엇인가 { #what-is-smb }

파일 탐색기에서 `\\SRV-FS-0001\Finance`를 열 때, 네트워크 드라이브를 연결할 때, 공유 프린터로 인쇄할 때, 그리고 도메인 PC가 `\\corp.victim.example\SYSVOL`에서 그룹 정책을 내려받을 때 — 이게 전부 SMB입니다. Windows가 "저쪽 컴퓨터의 파일을 열고, 읽고, 쓰고, 잠그게 해 줘"라고 말할 때 쓰는 프로토콜이죠. 그런데 그게 다가 아닙니다. SMB는 <strong>이름 있는 파이프(named pipe)</strong>도 실어 나릅니다. 이름 있는 파이프는 한 컴퓨터가 다른 컴퓨터의 관리 기능(원격 서비스 제어, 레지스트리, 예약 작업 등)을 불러 쓰게 해 주는 통로입니다(DCE/RPC라는 방식으로).

- **Windows 기본 기능.** 모든 Windows 클라이언트와 서버에 SMB 클라이언트와 SMB 서버("Server" 서비스, `LanmanServer`)가 들어 있습니다.
- **Linux도 씁니다.** Samba가 오픈소스 구현이라, Linux 파일 서버나 NAS도 SMB를 말합니다.
- **포트.** **TCP 445**는 "TCP 위에서 바로 SMB"이고 요즘 시스템은 이걸 씁니다. **TCP 139**는 옛 경로인 NetBIOS 세션 서비스 위의 SMB입니다(이름·데이터그램용으로 UDP 137·138도 같이). 요즘 139가 보이면 대개 오래된 장비나 오래된 설정입니다.
- **도메인에서는 기본으로 열려 있음.** 도메인 PC는 도메인 컨트롤러의 SYSVOL·NETLOGON에 가려면 SMB가 필요하고, 관리자는 SMB로 PC를 관리합니다. 도메인 프로필의 Windows 방화벽은 흔히 "파일 및 프린터 공유" 인바운드를 허용합니다. 그 결과 많은 회사 네트워크에서 **모든 PC가 다른 모든 PC의 445에 닿을 수 있습니다.**

큰 사무실 건물을 떠올려 보세요. 사무실(PC)마다 직원용 정문이 있지만, 건물에는 모든 사무실 뒤로 이어진 **직원 전용 관리 통로**가 있습니다. 시설 관리팀이 마스터키 하나로 어느 방이든 들어갈 때 쓰는 길이죠. 그 통로가 SMB입니다. 바깥 도로(인터넷)와는 연결되어 있지 않지만, 일단 건물 안에 들어와 마스터키(관리자 비밀번호)를 손에 넣은 사람은 모든 사무실에 들어갈 수 있습니다.

기술적으로 다시 말하면, SMB에는 Windows가 자동으로 만드는 <strong>관리용 공유(administrative share)</strong>가 있습니다. `C$`(C: 드라이브 전체), `ADMIN$`(`C:\Windows` 폴더), `IPC$`(이름 있는 파이프로 들어가는 입구). `C$`와 `ADMIN$`은 관리자만 쓸 수 있습니다. 이 세 개가 공격 도구들이 쓰는 "마스터키 문"입니다.

## 공격자가 SMB를 좋아하는 이유 { #why-attackers }

### 관리자 자격 증명 = 원격 명령 실행 { #remote-exec }

방어자가 꼭 알아야 할 핵심은 이겁니다. **어떤 PC의 관리자 자격 증명이 있으면, SMB로 그 PC를 원격에서 완전히 조종할 수 있습니다.** 쓰이는 부품은 전부 평범한 Windows 기능입니다.

1. SMB로 대상 PC에 인증합니다(NTLM 또는 Kerberos).
2. 프로그램을 `\\대상\ADMIN$`(즉 `C:\Windows`)에 복사합니다.
3. 이름 있는 파이프 `\\대상\IPC$\svcctl`(서비스 제어 관리자의 원격 창구)을 열고, 그 프로그램을 실행하는 **서비스를 만듭니다.**
4. 서비스를 시작합니다. 서비스는 로컬에서 가장 높은 권한인 **SYSTEM**으로 돌아갑니다.
5. 다른 이름 있는 파이프로 그 프로그램과 대화하며 **대화형 명령줄**을 얻습니다.

Sysinternals PsExec가 하는 일이 정확히 이것이고, 많은 공격 도구가 이걸 흉내 냅니다. 정말 기본 기능뿐이라는 걸 보여 드리기 위해, 공격자(또는 관리자)가 손으로 칠 수 있는 버전을 보겠습니다.

```
C:\> net use \\10.20.30.52\ADMIN$ /user:LT-FIN-0419\Administrator *
C:\> copy updater.exe \\10.20.30.52\ADMIN$\updater.exe
C:\> sc \\10.20.30.52 create UpdSvc binPath= "C:\Windows\updater.exe" start= demand
C:\> sc \\10.20.30.52 start UpdSvc
```

한 줄씩 보면:

- 1번 줄: `net use`로 `10.20.30.52`의 `ADMIN$` 공유에 그 PC의 **로컬** 관리자(`LT-FIN-0419\Administrator`)로 연결합니다. `*`는 비밀번호를 물어보게 합니다. `The command completed successfully.`가 나오면 비밀번호가 맞고, **그리고** 그 계정이 그 PC의 관리자라는 뜻입니다(관리자가 아니면 `System error 5 has occurred. Access is denied.`).
- 2번 줄: `copy`로 `updater.exe`를 원격 PC의 `C:\Windows`에 SMB로 씁니다.
- 3번 줄: `sc \\호스트 create`는 SMB 위의 원격 서비스 제어 창구(`svcctl` 파이프)로 새 서비스를 등록합니다. `binPath=`는 실행할 프로그램이고, `=` 뒤의 띄어쓰기는 `sc`의 특이한 문법상 꼭 필요합니다. 성공하면 `[SC] CreateService SUCCESS`가 나옵니다.
- 4번 줄: `sc \\호스트 start`로 시작합니다. 이제 프로그램이 SYSTEM으로 돌아갑니다. 진짜 서비스 프로그램이 아니면 `sc`가 오류 1053("시간 안에 응답하지 않았다")을 내지만, 프로그램은 이미 실행된 뒤라 공격자에게는 그걸로 충분합니다.

SSH와 비교해 보면, SSH도 원격 셸을 주지만 계정만 있으면 어떤 사용자든 로그인할 수 있습니다. SMB 원격 실행은 **대상 PC의 관리자 권한**이 있어야 합니다. 그래서 다음 이야기가 그렇게 중요합니다.

### 같은 로컬 관리자 비밀번호 문제 { #shared-passwords }

많은 조직이 PC를 이미지 하나로 찍어 내고, 그 이미지에는 기본 로컬 `Administrator` 비밀번호가 똑같이 들어 있습니다. 공격자를 따라가 보죠.

1. 사용자 한 명이 피싱 첨부 파일을 엽니다. 공격자가 `LT-FIN-0412`를 손에 넣습니다.
2. 공격자가 그 PC에서 관리자 권한을 얻고(익스플로잇, 또는 원래 사용자가 로컬 관리자), SAM 데이터베이스에서 **로컬 Administrator의 비밀번호 해시**를 빼냅니다.
3. 같은 비밀번호(또는 NTLM 해시만으로도 — [Pass-the-Hash](../../../adversary/pass-the-hash.md) 참고)가 **같은 이미지로 만든 다른 모든 PC**에서 통합니다.
4. 모든 PC 사이에 445가 열려 있으니, 공격자는 SMB로 그 PC들 전부에서 코드를 실행합니다.

건물 비유로 돌아가면, 모든 사무실 자물쇠가 같은 열쇠 하나로 열리게 맞춰져 있는 셈입니다. 한 사무실에서 열쇠를 훔치면 건물 전체가 열립니다.

그래서 **피싱 한 대 + 같은 관리자 비밀번호 + 445가 다 열린 평평한 네트워크 = 전체 장악**입니다. 해결책은 특별하지 않습니다. **PC마다 다른 로컬 관리자 비밀번호**(Windows LAPS — [변경됨](#trends) 참고), 워크스테이션끼리 445를 막는 방화벽 규칙, 그리고 일반 PC에서는 절대 쓰지 않는 관리자 계정.

### 웜도 같은 길을 탄다 { #worms }

이 단계를 악성코드가 자동으로 하면 <strong>웜(worm)</strong>이 됩니다. WannaCry(2017년 5월)는 SMB 위의 EternalBlue 익스플로잇으로 퍼졌고, NotPetya(2017년 6월)는 EternalBlue/EternalRomance에 **훔친 자격 증명과 PsExec·WMI**를 섞어서, 패치를 다 한 PC도 관리자 자격 증명만 찾으면 쓰러뜨렸습니다. 두 악성코드가 몇 시간 만에 회사 전체로 번진 이유가 이 조합입니다.

## SMB 버전과 협상 { #versions }

### 버전(dialect)들 { #dialects }

SMB는 오랜 세월 여러 버전을 거쳤습니다. 각 버전을 <strong>방언(dialect)</strong>이라고 부릅니다.

| 버전 | 처음 들어간 Windows | 추가된 것(간단히) |
| --- | --- | --- |
| SMB1 / CIFS | Windows NT 4.0 시절, XP / Server 2003 R2까지의 주력 | 원조. 협상 과정에 제대로 된 무결성 보호가 없고, 암호화 없음, 말이 아주 많음. CIFS는 NT 시절 SMB1 방언의 이름 |
| SMB 2.0.2 | Windows Vista / Server 2008 | 완전히 새로 설계. 명령 수가 크게 줄고, 큰 읽기·쓰기, 더 나은 서명(HMAC-SHA256) |
| SMB 2.1 | Windows 7 / Server 2008 R2 | 성능 개선(리싱, 더 큰 MTU) |
| SMB 3.0 | Windows 8 / Server 2012 | **암호화**(AES-CCM), 멀티채널, 클러스터 기능 |
| SMB 3.0.2 | Windows 8.1 / Server 2012 R2 | 작은 개선, SMB1을 제거할 수 있는 옵션 |
| SMB 3.1.1 | Windows 10 / Server 2016 | <strong>사전 인증 무결성(pre-authentication integrity)</strong>(협상 내용을 SHA-512로 묶어 버전 낮추기 공격을 막음), AES-GCM 암호화. 이후 Windows에서 AES-256, AES-GMAC 서명, SMB over QUIC 추가 |

<strong>[정정]</strong> 목록에서 "SMB 3.1"이라는 표기를 자주 봅니다. 실제 방언 번호는 **3.1.1**(`0x0311`)이고, 따로 3.1이라는 버전은 없습니다.

<strong>[보충]</strong> "SMB2"와 "SMB3"는 서로 다른 두 프로토콜이 아닙니다. 2.x와 3.x 방언은 모두 **같은 SMB2 패킷 형식**을 쓰고, 3.x는 그냥 방언 번호가 더 높고 기능이 더 많을 뿐입니다. 이게 아래 "SMB2도 끄라"는 조언을 볼 때 중요합니다.

### 클라이언트와 서버가 버전을 고르는 방법 { #negotiation }

SMB의 첫 메시지는 <strong>NEGOTIATE(협상)</strong>입니다. 클라이언트가 "나는 이 방언들을 할 수 있어"라고 말하면, 서버가 **양쪽이 다 지원하는 가장 높은 것**을 고르고, 그 뒤 세션은 그 버전으로 진행됩니다. 나라가 다른 두 사람이 서로 할 줄 아는 언어를 확인하고, 둘 다 제일 잘하는 언어로 이야기하기로 정하는 것과 같습니다.

패킷 캡처에서는 이렇게 보입니다. tshark(Wireshark의 명령줄 버전)를 썼습니다.

```
$ tshark -r fs-session.pcap -Y "smb2.cmd == 0" -T fields -e frame.time -e ip.src -e ip.dst -e smb2.flags.response -e smb2.dialect
Nov 18, 2026 09:01:12.104  10.20.30.41  10.20.0.20  0  0x0202,0x0210,0x0300,0x0302,0x0311
Nov 18, 2026 09:01:12.106  10.20.0.20  10.20.30.41  1  0x0311
```

명령어를 보면:

- `-r fs-session.pcap` — 이 캡처 파일을 읽습니다.
- `-Y "smb2.cmd == 0"` — 표시 필터. SMB2 명령 번호 0, 즉 NEGOTIATE만 봅니다.
- `-T fields -e …` — 이 칸들만 탭으로 나눠 출력합니다. 시각, 출발지, 목적지, 응답인지(`smb2.flags.response`, 0 = 요청, 1 = 응답), 방언.

출력을 보면:

- 1번 줄 — 클라이언트 `10.20.30.41`(Windows 11 노트북)이 **`0x0202`(2.0.2), `0x0210`(2.1), `0x0300`, `0x0302`, `0x0311`**을 내밉니다.
- 2번 줄 — 파일 서버 `10.20.0.20`이 **`0x0311`** = SMB 3.1.1을 골라 답합니다. 이후는 전부 3.1.1입니다.

SMB1만 하는 클라이언트는 SMB2 NEGOTIATE를 아예 보내지 않고, `NT LM 0.12` 같은 문자열을 나열한 SMB1 `Negotiate Protocol Request`를 보냅니다. Wireshark에서 `smb2`가 아니라 `smb` 필터로 보면 SMB1 트래픽이 나옵니다. **요즘 네트워크에서 SMB1이 보이면 그 자체가 발견 사항입니다.** 교체해야 할 오래된 장비이거나, 스캐너나 익스플로잇 도구입니다(많은 SMB1 익스플로잇과 스캐너가 SMB1 협상으로 시작합니다).

Windows PC에서 확인하는 방법:

```powershell
Get-SmbConnection | Select-Object ServerName, ShareName, UserName, Dialect
```

- `Get-SmbConnection` — 이 PC가 클라이언트로서 지금 열어 둔 SMB 연결 목록을 보여 줍니다.
- `Select-Object` — 필요한 칸만 골라 보여 줍니다.

```
ServerName   ShareName  UserName          Dialect
----------   ---------  --------          -------
SRV-FS-0001  Finance    CORP\j.kim        3.1.1
dc01         IPC$       CORP\LT-FIN-0412$ 3.1.1
```

모든 줄이 3.x여야 합니다. `2.0.2`가 보이거나, `1.5`(Windows가 SMB1을 이렇게 표시합니다)가 보이면 오래된 서버나 NAS라는 뜻입니다.

그리고 그 PC에 SMB1이 아직 남아 있는지:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EncryptData
```

```
FeatureName   State
-----------   -----
SMB1Protocol  Disabled

EnableSMB1Protocol RequireSecuritySignature EncryptData
------------------ ------------------------ -----------
             False                     True       False
```

- `SMB1Protocol Disabled` — SMB1 구성 요소가 설치되어 있지 않습니다. 요즘 Windows의 기본값입니다.
- `EnableSMB1Protocol False` — 서버 쪽에서 SMB1을 받지 않습니다.
- `RequireSecuritySignature True` — 서버가 <strong>서명(signing)</strong>을 요구합니다. 메시지마다 서명이 붙어 있어서 중간에서 바꾸거나 다른 곳으로 중계(relay)할 수 없습니다.
- `EncryptData False` — 모든 공유에 암호화를 강제하지는 않습니다(공유별로 또는 전체로 켤 수 있음).

<strong>[보충]</strong> 큰 네트워크에서 SMB1을 지우기 전에 누가 아직 쓰는지 찾을 수 있습니다. `Set-SmbServerConfiguration -AuditSmb1Access $true`를 켜면, 클라이언트가 SMB1로 접속할 때마다 서버가 `Microsoft-Windows-SMBServer/Audit` 로그에 **이벤트 3000**을 클라이언트 주소와 함께 남깁니다. 몇 주 모아서 그 클라이언트들을 고치거나 바꾼 다음 SMB1을 지우면 됩니다.

### SMB1을 없애야 하는 이유 — 그럼 SMB2는? { #smb1 }

SMB1은 "공격자"라는 개념이 거의 없던 시절에 설계됐습니다. 협상 과정을 중간에서 조작할 수 있고(강제로 낮은 버전 쓰게 하기), 서명은 약하고 느려서 보통 꺼져 있었고, 암호화가 없고, 코드가 오래되고 복잡합니다. 2017년 MS17-010 취약점들 — NSA가 만들고 Shadow Brokers가 유출한 **EternalBlue, EternalRomance, EternalSynergy, EternalChampion**이 노린 것 — 은 모두 **SMB1 서버 코드** 안에 있었습니다. SMB1을 지운 PC에는 그 취약한 코드 경로 자체가 없습니다. Microsoft의 SMB 담당 팀도 몇 년째 SMB1을 그만 쓰라고 말해 왔고, 지금 Windows는 SMB1을 설치하지 않습니다. 익스플로잇 자체는 [EternalBlue와 SMBv1](../../../adversary/eternalblue-smbv1.md)에서 봅니다.

<strong>[정정]</strong> "가능하면 SMB2도 끄라"는 말을 볼 수 있는데, 조심해야 합니다. 2.x와 3.x는 하나의 프로토콜 스택을 공유하기 때문에, **Windows에서 "SMB2"를 끄면(`EnableSMB2Protocol $false`) SMB 3.x도 같이 꺼집니다.** 파일 공유, 그룹 정책, 그 밖의 많은 것이 망가지고, Microsoft도 하지 말라고 분명히 말합니다. 그 조언을 요즘 식으로 바꾸면 **SMB 3.x만 허용하기**입니다. 최소 방언을 정하면 되고(Windows 11 24H2·Windows Server 2025에서 지원, 예: `Set-SmbServerConfiguration -Smb2DialectMin SMB300`), 그 전에 2.x가 꼭 필요한 오래된 장비가 없는지 먼저 확인합니다.

## 대표적인 SMB 공격 { #attacks }

SMB 공격은 두 갈래로 나뉩니다. 이 그림이 둘 다 보여 줍니다.

```
                                     ┌─────────────────────────┐
                                     │ SRV-APP-0007 (unpatched)│ ◀── 2) exploit over 445
                                     └─────────────────────────┘     succeeds: SYSTEM
                                                  ▲
   Internet                                       │ SMB exploit (EternalBlue style)
  ┌────────┐   C2 over HTTPS    ┌──────────────┐  │
  │attacker│ ◀────────────────▶ │ LT-FIN-0412  │──┘
  └────────┘                    │ (phished)    │──┐
                                └──────────────┘  │ 1) PsExec with shared
                                     │            │    local admin password
                                     │            ▼
                                     │      ┌──────────────┐   ┌──────────────┐
                                     │      │ LT-FIN-0419  │──▶│ LT-HR-0233   │ ...
                                     │      └──────────────┘   └──────────────┘
                                     ▼
                         ┌──────────────────────────────┐
                         │ SRV-FS-0001 (patched,        │ ◀── exploit blocked:
                         │ host firewall blocks 445)    │     445 filtered
                         └──────────────────────────────┘
```

1. **자격 증명 방식(PsExec류).** 피싱당한 노트북이 공격자에게 발판이 됩니다. 같은 로컬 관리자 비밀번호로 `LT-FIN-0419`로, 다시 `LT-HR-0233`으로 건너갑니다. 취약점이 필요 없습니다. <strong>로그인 자체는 "정상"</strong>이라서 백신이 아무 말도 안 하는 경우가 많습니다.
2. **익스플로잇 방식(EternalBlue류).** 발판에서 445가 열린 장비를 찾아 하나씩 익스플로잇을 쏩니다. `SRV-APP-0007`은 패치가 안 돼 있어서 넘어갑니다(SYSTEM). `SRV-FS-0001`은 패치가 돼 있고 방화벽이 워크스테이션에서 오는 445를 막아서 익스플로잇이 닿지도 않습니다.

두 경우 모두 공격자는 보통 일반 사용자가 아니라 **Administrator나 SYSTEM**이 됩니다. 그리고 관리자가 되면 Mimikatz 같은 도구로 LSASS(로그온 비밀을 들고 있는 프로세스)의 메모리를 읽어, 그 PC에 **지금 로그온해 있는 모든 사람**의 자격 증명을 꺼냅니다. 뭔가 고치러 들어왔던 헬프데스크나 도메인 관리자일 수도 있죠. 계정이 늘어나면 건너갈 곳도 늘어납니다. [LSASS 덤프](../../../adversary/lsass-dumping.md) 참고.

### PsExec 한 번 건너가기가 로그에 남기는 것 { #psexec-logs }

한 번의 이동을 따라가 봅시다. `LT-FIN-0412`(`10.20.30.41`)에 있는 공격자가 로컬 Administrator 계정으로 `LT-FIN-0419`(`10.20.30.52`)에 PsExec를 실행합니다. 기법 자세한 설명은 [PsExec와 SMB 횡적 이동](../../../adversary/psexec-smb.md)에 있습니다.

**출발지(`LT-FIN-0412`) — Sysmon 이벤트 3(네트워크 연결):**

```
Event ID: 3   Network connection detected
UtcTime:          2026-11-18 05:14:07.311
Image:            C:\Users\j.kim\AppData\Local\Temp\ps.exe
User:             CORP\j.kim
Protocol:         tcp
SourceIp:         10.20.30.41
DestinationIp:    10.20.30.52
DestinationPort:  445
```

- Sysmon(자세한 로그를 더해 주는 Microsoft의 무료 도구) 이벤트 **3**은 **어느 프로세스가** 네트워크 연결을 했는지 남깁니다. Windows 기본 로그만으로는 이걸 알 수 없습니다.
- `Image` — 연결한 프로그램. **이름을 바꾼 PsExec가 Temp 폴더에서 실행**됐습니다(`ps.exe`). 진짜 관리자는 사용자 Temp 폴더에서 도구를 돌리지 않습니다.
- **워크스테이션에서 다른 워크스테이션으로** `DestinationPort 445`: 보통 PC는 파일 서버와 DC에 SMB를 쓰지, PC끼리는 쓰지 않습니다. 이 연결 하나만으로도 강한 단서입니다.

**대상(`LT-FIN-0419`) — Security 로그 4624(로그온 성공):**

```
Event ID: 4624   An account was successfully logged on
Logon Type:                3
New Logon:  Account Name:  Administrator
            Account Domain: LT-FIN-0419
            Logon ID:      0x3E1A7F2
Network Information:
            Workstation Name: LT-FIN-0412
            Source Network Address: 10.20.30.41
Detailed Authentication Information:
            Logon Process:          NtLmSsp
            Authentication Package: NTLM
```

- **4624**는 로그온을 받는 PC에서, 로그온이 성공할 때마다 남습니다. (실패는 **4625**. 한 출발지에서 여러 PC로 Administrator 4625가 쏟아지면 비밀번호 스프레이나 대입 공격입니다.)
- `Logon Type 3` = **네트워크 로그온**. 키보드 앞(2)이나 RDP(10)가 아니라 네트워크로(예: SMB) 이 PC에 접근했다는 뜻입니다.
- `Account Name Administrator`, `Account Domain LT-FIN-0419` — 도메인 계정이 아니라 이 PC의 **로컬** 관리자 계정입니다. 도메인 환경에서 PC끼리 로컬 관리자로 네트워크 로그온할 이유는 거의 없습니다.
- `Source Network Address 10.20.30.41` — 어디서 왔는지. [DHCP](dhcp.md)로 `LT-FIN-0412`라는 걸 찾습니다.
- `Authentication Package NTLM` — 로컬 계정은 Kerberos를 못 쓰니 여기선 NTLM이 당연합니다. [Pass-the-Hash](../../../adversary/pass-the-hash.md)가 쓰는 것도 NTLM입니다.
- `Logon ID 0x3E1A7F2` — 세션 번호. **이 세션에서 이어지는 모든 이벤트가 같은 Logon ID를 달고 나오므로** 하나로 묶을 수 있습니다.

<strong>4672(새 로그온에 특수 권한 부여)</strong>가 같은 Logon ID로 바로 뒤따릅니다. 이 세션이 관리자급 권한(`SeDebugPrivilege`, `SeBackupPrivilege` 등)을 가졌다는 뜻입니다. 공격자 입장에서는 이 기법 전체에 관리자가 필요하니 중요하고, 방어자 입장에서는 워크스테이션 동료에게서 온 4624 타입 3 + 4672가 "관리자가 방금 네트워크로 들어왔다"는 신호입니다.

**5140(네트워크 공유 개체에 접근):**

```
Event ID: 5140   A network share object was accessed
Account Name:   Administrator      Logon ID: 0x3E1A7F2
Source Address: 10.20.30.41
Share Name:     \\*\ADMIN$
Share Path:     \??\C:\Windows
Access Mask:    0x1
```

- 세션이 공유에 처음 접근할 때 남습니다. 단, **"파일 공유 감사(Audit File Share)"가 켜져 있을 때만**입니다(워크스테이션은 기본으로 꺼져 있음).
- `Share Name \\*\ADMIN$` — `C:\Windows`를 가리키는 관리용 공유. 일반 사용자는 동료 PC의 `ADMIN$`에 접속하지 않습니다. **공격 도구가 쓰는 문이 바로 이것입니다.**

<strong>5145(상세 파일 공유 검사)</strong>는 개별 파일까지 남깁니다. `Share Name \\*\ADMIN$`, `Relative Target Name PSEXESVC.exe`, `Accesses WriteData (or AddFile)`. "상세 파일 공유 감사(Audit Detailed File Share)"가 필요하고, 파일 서버에서는 엄청나게 시끄럽지만 워크스테이션에서는 쓸 만큼 조용합니다.

**System 로그 7045(시스템에 서비스가 설치됨):**

```
Event ID: 7045   Source: Service Control Manager
Service Name:       PSEXESVC
Service File Name:  %SystemRoot%\PSEXESVC.exe
Service Type:       user mode service
Service Start Type: demand start
Service Account:    LocalSystem
```

- **7045**는 **System** 로그에 있고 기본으로 켜져 있습니다. 새 서비스가 생기면 무조건 남습니다. **4697**은 Security 로그 쪽 짝입니다("보안 시스템 확장 감사(Audit Security System Extension)" 필요).
- `PSEXESVC`는 PsExec의 기본 서비스 이름입니다(옵션으로 바꿀 수 있음). Impacket의 psexec는 **무작위 짧은 이름**과 무작위 `.exe` 이름을 쓰고, smbexec류 도구는 `cmd.exe` 자체를 서비스 프로그램으로 씁니다. 그러니 `Service File Name`에 `cmd.exe /c`, `%COMSPEC%`, `powershell`이 들어 있는지도 봅니다.
- 이상한 이름에, `C:\Windows\`에 있고, `demand start`, `LocalSystem`으로 도는 서비스가 동료 PC에서 온 타입 3 로그온 직후에 생겼다 — 전형적인 횡적 이동 패턴입니다.

**4688 / Sysmon 1(프로세스 생성):** `services.exe` → `PSEXESVC.exe` → `cmd.exe` → 공격자가 치는 것(`whoami`, `net group "domain admins" /domain`, 자격 증명 덤프 도구). 4688은 "프로세스 생성 감사"(그리고 명령줄 포함 옵션)를 켜야 하고, Sysmon 1은 기본으로 명령줄과 해시를 남깁니다.

타임라인으로 모으면(대상 PC 시계, UTC):

```
05:14:07  4624  type 3, LT-FIN-0419\Administrator, from 10.20.30.41, NTLM, LogonID 0x3E1A7F2
05:14:07  4672  same LogonID, admin privileges
05:14:07  5140  \\*\ADMIN$ from 10.20.30.41
05:14:07  5145  ADMIN$\PSEXESVC.exe WriteData
05:14:08  7045  service PSEXESVC, %SystemRoot%\PSEXESVC.exe, LocalSystem
05:14:08  4688  services.exe -> PSEXESVC.exe
05:14:09  4688  PSEXESVC.exe -> cmd.exe
05:14:15  4688  cmd.exe -> whoami.exe
```

8초 만에 이야기가 완성됩니다. **누가**(로컬 Administrator), **어디서**(`10.20.30.41`), **어떻게**(SMB + 새 서비스), **그다음 무엇을**(SYSTEM으로 명령 실행).

### 같은 이동이 네트워크에서는 — Zeek { #zeek-smb }

Zeek를 돌리는 네트워크 센서는 PC를 건드리지 않고도 같은 이동을 봅니다. Zeek는 SMB 관련 로그를 여러 개 남깁니다.

```
# smb_mapping.log — which shares were connected
ts=2026-11-18T05:14:07Z uid=CmQ1z84 id.orig_h=10.20.30.41 id.resp_h=10.20.30.52 id.resp_p=445 path=\\10.20.30.52\ADMIN$ share_type=DISK

# smb_files.log — which files were opened/written
ts=2026-11-18T05:14:07Z uid=CmQ1z84 id.orig_h=10.20.30.41 id.resp_h=10.20.30.52 action=SMB::FILE_WRITE path=\\10.20.30.52\ADMIN$ name=PSEXESVC.exe size=383872

# dce_rpc.log — remote management calls over named pipes
ts=2026-11-18T05:14:08Z uid=CmQ1z84 id.orig_h=10.20.30.41 id.resp_h=10.20.30.52 named_pipe=svcctl endpoint=svcctl operation=CreateServiceW
ts=2026-11-18T05:14:08Z uid=CmQ1z84 id.orig_h=10.20.30.41 id.resp_h=10.20.30.52 named_pipe=svcctl endpoint=svcctl operation=StartServiceW
```

- `uid` — 연결 번호. **세 로그 모두 같은 `uid`**라는 건 TCP 연결 하나가 이걸 전부 했다는 뜻입니다. [conn.log](../../../network/zeek/conn-log.md)에서도 같은 번호로 찾을 수 있습니다.
- `smb_mapping.log`의 `path=\\10.20.30.52\ADMIN$` — 워크스테이션이 다른 워크스테이션의 관리용 공유를 연결했습니다.
- `smb_files.log`의 `name=PSEXESVC.exe` — 실행 파일이 `ADMIN$`에 쓰였습니다. Zeek 파일 분석이 켜져 있으면 [files.log](../../../network/zeek/files-log.md)에 해시가 남습니다.
- `dce_rpc.log`의 `endpoint=svcctl operation=CreateServiceW`, 이어서 `StartServiceW` — **원격 서비스 생성과 시작**입니다. 워크스테이션에서 SMB로 오는 이 한 쌍은 네트워크 쪽에서 가장 믿을 만한 횡적 이동 신호 중 하나입니다. (그 밖에 알아 둘 것: `atsvc`/`ITaskSchedulerService` = 원격 예약 작업, `winreg` = 원격 레지스트리, `samr`/`lsarpc` = 계정·도메인 정보 조회.)

<strong>[보충]</strong> SMB 3 **암호화**가 켜져 있으면 Zeek와 Wireshark는 협상과 인증까지만 보고, 그 안의 공유 경로·파일 이름·RPC 호출은 **못 봅니다.** 서명만으로는 내용이 숨겨지지 않습니다. 그래서 SMB를 암호화하는 환경에서는 PC 쪽 로그(위의 이벤트들)의 비중이 커지고, 네트워크가 줄 수 있는 건 주로 연결 메타데이터(누가 누구에게 445로 말하나)가 됩니다.

### 익스플로잇 시도는 어떻게 보이나 { #exploit-signals }

익스플로잇 쪽은 흔적이 다릅니다.

- **있어서는 안 되는 SMB1 협상**, 특히 워크스테이션 한 대가 여러 호스트에게.
- **한 출발지가 몇 초 만에 여러 호스트의 445를 건드림** — 대상을 찾는 스캔입니다. `conn.log`에서 한 `id.orig_h`가 `445`로 짧은 연결을 잔뜩 만들고, 그중 많은 수가 `conn_state` `REJ`나 `S0`(응답 없음)입니다.
- **IDS 시그니처.** EternalBlue 같은 공개 익스플로잇은 잘 알려진 네트워크 시그니처가 있습니다(비정상적인 SMB1 트랜잭션 요청, DoublePulsar 백도어의 "핑" 응답).
- **성공해도 로그온 이벤트가 없음.** 익스플로잇은 로그온을 하지 않으니 4624가 아예 없을 수 있습니다. 대신 `lsass.exe`나 `spoolsv.exe` 같은 시스템 프로세스가 갑자기 `cmd.exe`나 `rundll32.exe`를 띄우거나, 익스플로잇이 실패하면 시스템이 다운됩니다(`System` 로그의 버그체크). SYSTEM 프로세스의 이상한 프로세스 트리가 PC 쪽 단서입니다.

## SMB 방어 — SOC가 밀어붙여야 할 것 { #defence }

- **445(와 139)를 인터넷 쪽으로 절대 열지 않는다.** 나가는 방향도 중요합니다. 나가는 445를 막으면 NTLM 해시가 공격자 서버로 새는 걸 막습니다(`\\203.0.113.50\share` 같은 악성 링크를 열면 Windows가 인증을 시도합니다).
- **워크스테이션끼리 445를 막는다**(호스트 방화벽). 워크스테이션은 파일 서버와 DC에 SMB가 필요하지, 서로에게는 필요 없습니다. 이 규칙 하나가 위의 횡적 이동 대부분을 끊습니다.
- **PC마다 다른 로컬 관리자 비밀번호**(Windows LAPS), 그리고 워크스테이션에서 로컬 계정의 네트워크 로그온을 거부합니다(`Local account and member of Administrators group` 대상에 "네트워크에서 이 컴퓨터 액세스 거부" 권한).
- **SMB1 제거**, SMB 패치, **서명 필수**(SMB를 통한 NTLM 릴레이 차단 — [LLMNR·NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md) 참고).
- **메모리 속 자격 증명 보호**(Credential Guard, LSA 보호), 특권 계정은 일반 PC에서 쓰지 않기(관리자 계층화, tiering).
- **탐지:** 워크스테이션 간 445, 관리자 PC가 아닌 곳에서 `ADMIN$`/`C$` 접근, 타입 3 로그온 직후 7045/4697 새 서비스, Zeek `svcctl CreateServiceW`, 모든 SMB1.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    SMB는 여전히 TCP 445 위에서 도는 Windows 파일 공유·원격 관리의 뼈대이고, 대부분의 내부망에서 여전히 열려 있으며, 여전히 횡적 이동과 랜섬웨어 배포의 주요 통로입니다. PsExec식 원격 서비스 생성, 관리용 공유, 같은 로컬 관리자 비밀번호 문제, 관리자가 된 뒤 LSASS에서 자격 증명 훔치기, "SMB1은 없애야 한다" 모두 설명한 그대로입니다. 탐지 짝(4624 타입 3 + 4672 + 7045, Zeek `svcctl` 호출)도 그대로입니다.

!!! info "[변경됨] 바뀐 점"
    - **Windows 11 24H2와 Windows Server 2025의 안전한 기본값.** SMB **서명이 모든 들어오고 나가는 연결에 기본으로 필수**가 됐고(예전에는 SYSVOL/NETLOGON과 DC 연결만), **게스트 대체 접속(guest fallback)이 꺼졌으며**(Windows 11 Pro도 게스트 접속 불가), <strong>인증 속도 제한기(authentication rate limiter)</strong>가 NTLM이나 로컬 Kerberos 인증이 실패할 때마다 2초씩 지연을 넣어서 SMB 비밀번호 대입을 느리게 만듭니다. SMB 클라이언트가 나가는 연결에서 **NTLM을 차단할 수 있게** 됐고, 관리자가 **최소·최대 방언을 정할 수 있으며**, SMB1은 설치되지 않습니다. 서명을 지원하지 않는 오래된 NAS는 업그레이드 뒤 접속이 안 될 수 있는데, 올바른 해결은 서명을 끄는 게 아니라 NAS를 업데이트하는 것입니다.
    - **NTLM은 퇴장 중.** Microsoft가 NTLM을 지원 중단(deprecated)하고, Windows 11 24H2와 Windows Server 2025에서 NTLMv1을 제거했습니다. NTLM(v2) 자체는 아직 동작하고, 로컬 계정 SMB 로그온과 Pass-the-Hash가 여전히 이걸 쓰니 탐지에서는 계속 중요합니다.
    - **SMB over QUIC**(VPN 없이 원격 사용자를 위해 UDP 443 위 TLS 1.3 안에 SMB를 넣은 것)을 모든 Windows Server 2025 에디션에서 쓸 수 있습니다. 서버로 가는 SMB가 UDP 443에서 보이면 정상일 수 있습니다. 동시에 "경계에서 445를 막았다"가 더 이상 모든 SMB 경로를 설명하지 못한다는 뜻이기도 합니다.
    - **Windows LAPS**가 Windows에 기본 내장됐고(2023년 업데이트부터), 비밀번호를 Entra ID나 AD에 저장할 수 있습니다. 같은 로컬 관리자 비밀번호를 쓸 핑계가 더는 없습니다.
    - **SMB 취약점은 2017년에 끝나지 않았습니다.** SMBGhost(CVE-2020-0796, SMB 3.1.1 압축 기능)는 SMB3 코드도 웜이 될 수 있다는 걸 보여 줬고, CVE-2025-33073(NTLM 반사 보호를 우회해서 서명을 강제하지 않는 PC에서 SYSTEM을 얻을 수 있는 SMB 클라이언트 취약점)은 2025년 6월에 패치되고 2025년 10월 CISA의 '실제 악용 취약점(KEV)' 목록에 올랐습니다.
    - **랜섬웨어는 여전히 SMB로 퍼뜨립니다.** 암호화 프로그램을 `ADMIN$`/`C$`에 복사하고 서비스·예약 작업·PsExec로 시작하며, 한 대에서 **SMB로 파일 공유를 원격 암호화**하는 경우도 많습니다. 그러면 파일 서버에는 로컬 악성코드가 아니라 클라이언트 한 대에서 오는 대량 파일 쓰기가 보입니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **오래된 방언을 없애려고 "SMB2"를 끄지 마세요.** Windows에서는 SMB 3.x도 같이 꺼집니다. 대신 최소 방언을 정합니다.
    - **"인터넷 경계에서 445를 막았다"로 충분하다고 생각하지 마세요.** 위험은 안쪽입니다. 워크스테이션끼리도 445를 막습니다.
    - **SMB 암호화가 켜져 있으면 네트워크 로그에만 기대지 마세요.** 공유 이름과 파일 이름이 숨겨집니다. 4624/4672/7045(가능하면 워크스테이션의 5140/5145, Sysmon 1/3까지)가 SIEM에 들어오는지 확인합니다.
    - **`PSEXESVC`라는 이름만 찾지 마세요.** 이름은 바꿀 수 있고, 다른 도구들은 무작위 이름이나 `cmd.exe`를 서비스 프로그램으로 씁니다. 행동을 찾습니다: 동료 PC에서 온 타입 3 관리자 로그온 → 관리용 공유에 쓰기 → 새 서비스.
    - **Windows 업그레이드 뒤 오래된 NAS나 프린터를 "고치려고" 서명을 끄지 마세요.** NTLM 릴레이 길이 다시 열립니다. 장비를 업데이트하거나 교체합니다.

## 확인 문제 { #quiz }

### 문제 1

동료가 "SMB는 그냥 파일 공유잖아요. 공격자가 할 수 있는 최악은 문서 읽기 정도죠"라고 말합니다. 왜 틀렸는지, 그리고 PC 사이에 445가 다 열린 네트워크에서 같은 로컬 Administrator 비밀번호가 왜 그렇게 위험한지 설명하세요.

??? success "정답과 해설"
    **왜 틀렸나:** PC의 **관리자 자격 증명**이 있으면 SMB는 파일 접근이 아니라 **원격 실행** 통로입니다. 관리용 공유(`ADMIN$`, `C$`)로 대상 PC에 프로그램을 복사하고, `IPC$` 위의 `svcctl` 이름 있는 파이프로 그 프로그램을 **SYSTEM**으로 실행하는 **서비스**를 만들고 시작할 수 있습니다 — PsExec가 하는 일 그대로이고, 대화형 명령줄까지 얻습니다. SSH와 비슷하지만 관리자 권한이 필요하다는 점만 다릅니다.

    **같은 비밀번호가 치명적인 이유:** 모든 PC의 로컬 Administrator 비밀번호가 같으면, 피싱당한 **한 대**에서 그 비밀번호(또는 NTLM 해시)를 훔치는 것만으로 **전부**의 관리자가 됩니다. PC끼리 445가 열려 있으니 공격자는 PC에서 PC로 건너가고(NotPetya처럼 웜이 자동으로 할 수도 있음), 가는 곳마다 로그온해 있는 사람의 자격 증명을 꺼내 결국 도메인 관리자를 찾습니다. 노트북 한 대 감염 → 전체 장악. 해결: PC마다 다른 비밀번호(Windows LAPS), 워크스테이션 간 445 차단, 로컬 관리자 계정의 네트워크 로그온 거부.

### 문제 2

`LT-HR-0233`(`10.20.30.77`)에서 아래 이벤트를 찾았습니다. 모두 Logon ID `0x51C0D9`입니다. 무슨 일이 있었는지 설명하고, 다음에 무엇을 확인할지 적으세요.

```
07:42:10  4624  Logon Type 3, Account LT-HR-0233\Administrator, Source 10.20.30.52, NTLM
07:42:10  4672  special privileges
07:42:10  5140  \\*\ADMIN$
07:42:11  7045  Service Name: XbKq  File: %SystemRoot%\wQmTrGfA.exe  LocalSystem  demand start
```

??? success "정답과 해설"
    **무슨 일:** `10.20.30.52`에서 누군가 이 PC의 **로컬 Administrator**로 NTLM을 써서 **네트워크 로그온**(타입 3)을 했고, 관리자 권한을 받았고(4672), **`ADMIN$`** 공유를 열었고(5140), 1초 만에 **무작위 이름의 새 서비스**(`XbKq`)가 **`C:\Windows`의 무작위 이름 exe**를 **SYSTEM**으로 실행하도록 설치됐습니다(7045). 서비스를 이용한 원격 실행 — PsExec 패턴이고, 무작위 이름으로 보아 진짜 Sysinternals PsExec보다는 Impacket류 도구에 가깝습니다. **`10.20.30.52`에서 온** 횡적 이동입니다(위 예시에서는 그 PC 자신도 피해자였던 `LT-FIN-0419`).

    **다음 확인:**

    1. `LT-HR-0233`에서 07:42:11 이후 프로세스 생성(4688/Sysmon 1): `wQmTrGfA.exe`가 무엇을 띄웠는지(자식 프로세스, 명령줄), 그리고 그 해시.
    2. 07:42 기준 DHCP로 `10.20.30.52`를 장비로 바꾸고, 그 PC에서 출발지 쪽 흔적(445로 가는 Sysmon 3, 실행된 도구)과 **그 PC가** 어떻게 뚫렸는지 — 사슬을 거꾸로 따라갑니다.
    3. 모든 호스트에서 같은 패턴(워크스테이션에서 온 타입 3 로컬 Administrator 로그온, 무작위 이름의 7045)을 찾아 모든 이동 지점을 파악합니다.
    4. 자격 증명 노출: `LT-HR-0233`에 어떤 계정이 로그온해 있었는지 보고, 비밀이 털렸다고 가정해 재설정합니다. 로컬 Administrator 비밀번호는 전부 바꿉니다(LAPS).
    5. 네트워크: Zeek `dce_rpc.log`에서 `10.20.30.52`가 다른 곳에 `svcctl CreateServiceW`를 했는지.

### 문제 3

점검 중 세 가지를 발견했습니다. 각각 문제인지, 어떻게 할지 말하세요. (a) SMB 2.0.2로만 협상하는 오래된 NAS 한 대, (b) 워크스테이션 한 대가 1분 안에 서로 다른 40대 호스트에 보낸 `smb`(SMB1) 패킷, (c) 서버 관리자가 "오래된 SMB2를 없애려고" `Set-SmbServerConfiguration -EnableSMB2Protocol $false`를 제안.

??? success "정답과 해설"
    **(a)** 긴급하진 않지만 약점입니다. SMB 2.0.2는 암호화가 없고 서명도 옛 방식이며, SMB 3.x 이상만 허용하도록 최소 방언을 올리면 이 NAS는 끊깁니다. 펌웨어 업데이트나 교체를 계획하고, 서명을 지원하는지 확인하고(Windows 11 24H2/Server 2025 클라이언트는 기본으로 서명을 요구), 필요 없는 네트워크에서는 떼어 둡니다.

    **(b)** **심각한 발견입니다.** 요즘 Windows는 기본으로 SMB1을 쓰지 않고, 워크스테이션 한 대가 1분 안에 40대의 445를 건드리는 건 **스캔**입니다. SMB1 익스플로잇이나 취약점 스캐너일 가능성이 아주 높습니다(EternalBlue류 도구는 SMB1 협상으로 시작). 그 워크스테이션을 감염된 것으로 보고 격리하고, 연결을 만든 프로세스(Sysmon 3)를 확인하고, 대상 호스트들에서 익스플로잇 성공 흔적(시스템 프로세스의 예상 밖 자식 프로세스, 다운)을 보고, 모든 곳에서 SMB1이 제거됐는지 확인합니다.

    **(c)** **하면 안 됩니다.** Windows에서 SMB 2.x와 3.x는 하나의 프로토콜 스택을 공유하므로, "SMB2"를 끄면 **SMB 3.x도 같이 꺼져서** 파일 공유와 그룹 정책이 망가집니다. 오래된 방언을 없애는 올바른 방법은, 2.x가 필요한 클라이언트((a)의 NAS 같은)가 없는지 확인한 뒤 최소 방언을 정하는 것입니다(예: Windows Server 2025 / Windows 11 24H2에서 `-Smb2DialectMin SMB300`).

## 관련 레퍼런스 { #related }

- [PsExec와 SMB 횡적 이동](../../../adversary/psexec-smb.md)
- [EternalBlue와 SMBv1](../../../adversary/eternalblue-smbv1.md)
- [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [LSASS 덤프](../../../adversary/lsass-dumping.md) · [LLMNR·NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md) · [Zeek files.log](../../../network/zeek/files-log.md)
- [DC·SMB·Snort 규칙 실습](../../pcap-ir-labs/dc-smb-and-snort-rules.md)
