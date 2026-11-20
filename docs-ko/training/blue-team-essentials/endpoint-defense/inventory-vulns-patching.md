---
title: "자산 목록, 취약점 스캔, 패치, 익스플로잇 보호 — 공격이 자리 잡기 전에 막기"
tags:
  - training
  - blue-team
  - endpoint
  - vulnerability-management
  - hardening
---

# 자산 목록, 취약점 스캔, 패치, 익스플로잇 보호 — 공격이 자리 잡기 전에 막기 { #inventory-vulns-patching }

!!! abstract "이 페이지에서 다루는 것"
    엔드포인트 방어가 왜 한 겹으로는 절대 부족한지, 그리고 흔히 쓰는 엔드포인트 방어 수단들이 공격 단계(익스플로잇, 설치, 명령·제어, 최종 목표 행동)에 어떻게 하나씩 맞물리는지. 이어서 가장 먼저 오고 가장 싼 방어선인 "익스플로잇 막기"를 자세히 봅니다. 우리가 실제로 무슨 소프트웨어를 돌리고 있는지 알기(인벤토리 시스템과 네트워크 스캔, Nmap 스캔 결과를 한 줄씩), 그게 언제 위험해지는지 알기(인증 없는 스캔 vs 인증 스캔, 결과에 우선순위 매기기), 빨리 패치하기(OS·서버·클라이언트 소프트웨어, 긴급 패치), 그리고 패치가 놓친 익스플로잇을 잡는 익스플로잇 방지 도구 — 은퇴한 EMET에서 오늘날의 익스플로잇 보호, 제어된 폴더 액세스, 네트워크 보호, 공격 표면 축소(ASR) 규칙까지 — 를 SOC가 실제로 읽는 명령어와 Defender 이벤트(1121~1126)와 함께 봅니다. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. **방어는 한 겹으로는 절대 부족하다.** 엔드포인트 방어 수단마다 막는 공격 단계가 다르고, 여러 겹을 겹쳐야 <strong>심층 방어(defence in depth)</strong>가 된다. 각 겹은 공격자를 막거나, 못 막더라도 늦추고 흔적을 남기게 한다.
2. 방어 수단을 킬 체인에 맞춰 줄 세워 보면: **익스플로잇** → 자산 목록, 스캔, 패치, 익스플로잇 방지 / **설치** → 하드닝, 백신, 파일 무결성 모니터링, 특권 접근 워크스테이션, 애플리케이션 제어 / **C2** → 호스트 방화벽, 호스트 IDS/IPS / **최종 목표 행동** → 감사, 행동 분석, 암호화, 로깅, DLP.
3. **모르는 건 지킬 수 없다.** 소프트웨어 인벤토리(에이전트나 로그인으로 설치된 프로그램 목록 만들기)와 네트워크 스캔(실제로 무엇이 듣고 있나)은 서로 다른 걸 본다. 둘 다 쓴다.
4. **Nmap** 같은 스캐너는 "포트가 열렸나"만 보지 않는다. 서비스 배너를 읽고, OS를 추측하고, 스크립트(익명 FTP, SMB 호스트 정보)까지 돌린다. 공격자도 똑같은 스캔을 하니, 우리가 먼저 공격자 눈으로 우리 네트워크를 봐야 한다.
5. **취약점 스캔은 계속 돌아야 한다.** 오늘 안전한 서버가 내일 뚫릴 수 있다. **인증 없는(unauthenticated)** 스캔은 네트워크로 드러난 것만 보고, **인증(authenticated)** 스캔은 로그인해서 설치된 버전을 정확히 안다.
6. 패치는 **익스플로잇을 막는 가장 확실한 방법**이다. OS, 서버 소프트웨어, 그리고 *클라이언트* 소프트웨어(브라우저, PDF 리더, Office)까지. 서비스를 멈추고라도 긴급 패치할 기준을 미리 정해 둔다.
7. 패치가 모든 걸 막을 수는 없어서 **익스플로잇 방지(anti-exploitation)** 도구가 익스플로잇 기법 자체를 깨뜨린다. 그리고 그만큼 중요한 것 — **익스플로잇 시도가 있었다는 로그를 남긴다.** SOC에게는 빠르고 질 좋은 경보다.
8. Windows에서 EMET는 사라졌고, 후계자는 Windows와 Microsoft Defender에 내장돼 있다. **익스플로잇 보호**, **제어된 폴더 액세스**(랜섬웨어 방지), **네트워크 보호**(모든 앱의 나쁜 목적지 접속 차단), **ASR 규칙**(예: Office가 자식 프로세스를 못 띄우게). 이들의 차단·감사 이벤트는 Defender 운영 로그에 남고, SIEM으로 꼭 보내야 한다.

## 킬 체인을 따라 겹겹이 막기 { #defence-in-depth }

공항 보안을 떠올려 보세요. 예약 단계에서 요주의 인물인지 확인하고, 카운터에서 신분증을 보고, 짐과 사람을 검색대에 통과시키고, 조종실 문은 잠겨 있고, 기내에는 보안 요원이 탑니다. 어느 하나도 완벽하지 않습니다. 하지만 각 단계가 다른 단계가 놓친 걸 일부 잡아 주고, 나쁜 마음을 먹은 사람은 그 *모든* 단계를 다 통과해야 합니다. 그리고 단계가 하나 늘 때마다 시간이 더 걸리고, 들킬 기회도 하나 더 생깁니다.

엔드포인트 방어도 똑같습니다. 앞 섹션에서는 공격자가 호스트 위를 지나가는 길을 따라갔습니다. [최초 침투](../endpoint-attacks/initial-exploitation.md), [실행·지속성·정보 탐색](../endpoint-attacks/execution-persistence-discovery.md), [권한 상승](../endpoint-attacks/privilege-escalation.md), [자격 증명 덤프](../endpoint-attacks/credential-dumping-mimikatz.md), [옆으로 이동과 유출](../endpoint-attacks/lateral-collection-exfil.md). 이 섹션은 같은 길을 방어자 쪽에서 다시 걸으면서, 단계마다 "이걸 막거나 드러내는 건 뭐지?"라고 묻습니다.

| 공격 단계 | 공격자에게 필요한 것 | 그에 맞서는 엔드포인트 방어 |
| --- | --- | --- |
| 익스플로잇 | 익스플로잇이 닿을 수 있는 취약한 프로그램 | 소프트웨어 인벤토리, 네트워크 스캔, 취약점 스캔, 패치, 익스플로잇 방지 |
| 설치(지속성) | 자기 코드를 쓰고 실행하고, 재부팅 뒤에도 살아남기 | 하드닝, 백신/EDR, 파일 무결성 모니터링, 특권 접근 워크스테이션(PAW), 애플리케이션 제어 |
| 명령·제어(C2) | 자기 서버로 나가는 네트워크 길 | 호스트 방화벽, 호스트 침입 탐지·차단(HIDS/HIPS) |
| 최종 목표 행동 | 데이터에 닿고, 모으고, 빼내거나 시스템 망가뜨리기 | 감사, 사용자·개체 행동 분석(UEBA), 암호화, 로깅, 데이터 유출 방지(DLP) |

이 표 뒤에는 두 가지 생각이 깔려 있습니다.

- **일찍 막을수록 싸다.** 공격자 코드가 한 바이트도 돌기 전에 익스플로잇을 막으면 비용은 경보 하나입니다. 같은 공격자를 3주 뒤, 자격 증명을 다 털고 PC 40대를 건드린 다음에 찾으면 비용은 침해 사고 대응 전체입니다.
- **막는 것과 알아채는 것, 둘 다 결과물이다.** 좋은 방어 수단은 그 단계를 막거나, 기록을 남겨 SOC가 보게 합니다. 둘 다 하면 제일 좋습니다. 조용히 막기만 해도 없는 것보단 낫지만, 막고 *기록까지* 남기면 공격자의 실패한 시도가 우리의 가장 빠른 경고가 됩니다.

이 페이지는 표의 첫 줄, 익스플로잇 막기를 다룹니다. 나머지 줄은 다음 페이지들에서 봅니다.

## 1단계 — 우리 소프트웨어를 안다 { #inventory }

익스플로잇에는 과녁이 필요합니다. 공격자가 닿을 수 있는 곳에서 돌고 있는, 특정 프로그램의 특정 취약한 버전이죠. `SRV-APP-0007`이 아직 오래된 Java 애플리케이션 서버를 돌리고 있다는 걸 모르면, 패치도 안 하고, 지켜보지도 않고, 그게 셸을 띄우기 시작해도 눈치채지 못합니다. 그래서 자산 목록이 이 페이지 나머지 전부의 바닥입니다.

목록을 만드는 방법은 두 가지이고, 서로를 보완합니다.

### 인벤토리 시스템 — 안에서 본 목록 { #inventory-systems }

<strong>인벤토리 시스템(inventory system)</strong>은 각 PC에게 "뭐가 설치돼 있어?"라고 묻습니다. 설치된 에이전트(엔드포인트 관리 도구, EDR, 구성 관리 도구)로 묻기도 하고, 주기적으로 로그인해서 묻기도 합니다. 답은 중앙 데이터베이스에 모여서, "7-Zip X 버전보다 오래된 게 깔린 PC는?" 같은 질문에 바로 답할 수 있게 됩니다.

약점은 *어떻게 묻느냐*에 있습니다. 대부분의 도구는 OS가 가진 "설치된 프로그램 목록"을 읽습니다. 그런데 거기에 자기를 등록하지 않은 소프트웨어 — 사용자 다운로드 폴더에 복사한 실행 파일 하나짜리 프로그램, `C:\Tools`에 압축만 풀어 놓은 도구, `pip`로 깐 Python 패키지, 컨테이너 이미지 — 는 목록에 아예 안 나올 수 있습니다. 목록은 그걸 만드는 방법만큼만 정확합니다.

많은 도구가 속으로 하는 기본적인 Windows 확인 방법은 이렇습니다.

```powershell
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $paths |
  Where-Object DisplayName |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
  Sort-Object DisplayName
```

한 줄씩 보면:

- 1~2번 줄 — 설치 프로그램이 자기를 등록하는 레지스트리 두 곳. 일반 64비트 목록과, 64비트 Windows에 깔린 32비트 프로그램용 `WOW6432Node` 목록입니다. 한쪽만 보면 소프트웨어 절반을 놓칩니다.
- `Get-ItemProperty $paths` — 그 키 밑의 항목을 전부 읽습니다.
- `Where-Object DisplayName` — 표시 이름이 없는 항목(업데이트, 내부 구성 요소)은 뺍니다.
- `Select-Object …` — 쓸모 있는 칸만 남기고, `Sort-Object`로 이름순 정렬합니다.

```
DisplayName                       DisplayVersion   Publisher               InstallDate
-----------                       --------------   ---------               -----------
7-Zip 19.00 (x64)                 19.00            Igor Pavlov             20210314
Google Chrome                     131.0.6778.86    Google LLC              20261102
Microsoft 365 Apps for enterprise 16.0.18129.20158 Microsoft Corporation   20261110
Notepad++ (64-bit x64)            8.1.9            Notepad++ Team          20220119
```

분석가 눈으로 읽으면: Chrome과 Microsoft 365는 이번 달에 업데이트됐으니 자동 업데이트가 돌고 있는 것 같습니다. 반면 2021년의 `7-Zip 19.00`과 2022년의 `Notepad++ 8.1.9`는 한 번도 업데이트된 적이 없습니다. 공격자가 함정 파일로 노리는 게 바로 이런 잊힌 클라이언트 소프트웨어입니다. 그리고 사용자가 `%USERPROFILE%\Downloads`에 둔 실행 파일 하나짜리 도구들은 이 목록에 아예 없다는 점도 기억하세요.

Linux에서는 패키지 관리자가 곧 인벤토리입니다.

```
$ dpkg-query -W -f='${Package} ${Version}\n' openssh-server openssl sudo
openssh-server 1:9.6p1-3ubuntu13.5
openssl 3.0.13-0ubuntu3.4
sudo 1.9.15p5-3ubuntu5
```

- `dpkg-query -W`는 Debian/Ubuntu에 설치된 패키지를 보여 주고, `-f`는 출력 모양(패키지 이름과 버전)을 정합니다. Red Hat 계열에서는 `rpm -qa`가 같은 역할입니다.
- 배포판은 보안 수정을 <strong>백포트(backport)</strong>합니다. 즉 `3.0.13-0ubuntu3.4` 안에는 원래 개발처(upstream)가 더 나중의 3.x 버전에서야 고친 버그의 수정이 들어 있을 수 있습니다. 앞쪽 버전 숫자만 비교하면 "취약하다"는 오탐이 나옵니다. 좋은 스캐너가 배포판 패키지 버전을 이해해야 하는 이유입니다.

<strong>[주의]</strong> 인벤토리에 `Get-CimInstance Win32_Product`(또는 옛 `wmic product`)를 쓰지 마세요. 이 클래스를 조회하면 Windows Installer가 *MSI로 설치된 모든 프로그램을 다시 점검하고, 필요하면 복구까지* 합니다. 느리고, Application 로그를 시끄럽게 만들고, 설치 상태를 바꿀 수도 있습니다. Uninstall 레지스트리 키를 읽거나 관리 도구를 씁니다.

### 네트워크 스캔 — 밖에서 본 목록 { #network-scanning }

두 번째 관점은 다른 질문을 합니다. **이 PC가 네트워크에 실제로 뭘 내놓고 있지?** PC가 스스로 말하는 목록을 믿는 대신, 공격자처럼 직접 접속해 봅니다. 그러면 인벤토리가 놓친, 듣고 있는 서비스가 잡힙니다. 개발자가 "잠깐" 띄운 웹 서버, 잊힌 장비의 관리 화면, Telnet이 열린 프린터 같은 것들이죠.

스캔에는 **능동(active)** 방식(탐침을 보내고 누가 답하나 보기)과 **수동(passive)** 방식(이미 흐르는 트래픽 듣기 — 예를 들어 Zeek이나 네트워크 센서가 `10.20.0.88`이 TCP 8080에서 답하는 걸 알아챔)이 있습니다. 수동 방식은 능동 탐침이 위험하거나 허락되지 않는 곳에서 씁니다. 대표적인 게 산업 제어 장비와 의료 장비입니다. 일부는 스캔만 받아도 멈춰 버리거든요.

**Nmap**은 가장 유명한 능동 스캐너이고, 이 종류의 도구가 뭘 하는지 보여 주기에 딱 좋습니다. 방어자가 작은 서버 서브넷에 서비스·OS 스캔을 돌린다고 해 봅시다.

```
$ sudo nmap -sS -sV -O --script "ftp-anon,smb-os-discovery" -p 21,22,80,445,3389,8080 10.20.0.0/24 -oA scans/srv-2026-11-19
```

하나씩 뜯어 보면:

- `sudo` — 원시 패킷 스캔과 OS 탐지에는 root가 필요합니다.
- `-sS` — **SYN 스캔**("반만 연결"). SYN을 보내고 SYN/ACK가 돌아오면 포트가 열린 겁니다. Nmap은 핸드셰이크를 끝내지 않고 연결을 끊어 버립니다.
- `-sV` — **버전 탐지**. 열린 포트를 찾으면 접속해서 서비스의 <strong>배너(banner)</strong>(서비스가 처음에 내보내는 자기소개 문자열)를 읽거나 끌어내서 제품과 버전을 알아냅니다.
- `-O` — **OS 탐지**. TCP/IP 스택이 답하는 미세한 차이(TTL, 윈도 크기, 옵션 순서)로 운영체제를 추측합니다. 확실한 답이 아니라 경험에 기댄 추측입니다.
- `--script "ftp-anon,smb-os-discovery"` — **NSE 스크립트**(Nmap Scripting Engine) 두 개를 돌립니다. `ftp-anon`은 익명 FTP 로그인을 시도하고 보이는 파일을 나열하고, `smb-os-discovery`는 SMB 서버에게 이름·도메인·OS를 묻습니다.
- `-p 21,22,80,445,3389,8080` — 이 포트들만 봅니다(전체 65,535개는 `-p-`).
- `10.20.0.0/24` — 대상. 주소 256개입니다.
- `-oA scans/srv-2026-11-19` — 결과를 세 가지 형식(일반, XML, grep용)으로 모두 저장합니다. 그래야 다른 도구로 가져가고 지난달 결과와 비교할 수 있습니다.

출력의 일부:

```
Nmap scan report for srv-ftp-02.corp.victim.example (10.20.0.31)
Host is up (0.00041s latency).
PORT     STATE  SERVICE       VERSION
21/tcp   open   ftp           vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0          48213 Oct 02 09:14 payroll-export.csv
22/tcp   open   ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   closed http
445/tcp  closed microsoft-ds
3389/tcp closed ms-wbt-server
8080/tcp open   http          Apache Tomcat 9.0.31
Device type: general purpose
Running: Linux 4.X|5.X
OS details: Linux 4.15 - 5.15

Nmap scan report for srv-app-0007.corp.victim.example (10.20.0.37)
PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds  Microsoft Windows Server 2012 R2 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Host script results:
| smb-os-discovery:
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   Computer name: SRV-APP-0007
|   Domain name: corp.victim.example
|_  System time: 2026-11-19T10:02:44+10:00
```

한 줄씩 읽어 보면:

- `Nmap scan report for srv-ftp-02… (10.20.0.31)` — 역방향 DNS 이름과 IP. `Host is up` — 답이 왔습니다.
- `21/tcp open ftp vsftpd 3.0.3` — FTP가 열려 있고, 배너로 제품과 버전을 알아냈습니다.
- `ftp-anon: Anonymous FTP login allowed (FTP code 230)` — 스크립트가 **자격 증명 없이** 로그인에 성공했습니다. 다음 줄에 네트워크의 누구나 내려받을 수 있는 파일이 보입니다. `payroll-export.csv`(급여 내보내기 파일). 취약점을 따지기도 전에 이미 발견 사항입니다.
- `22/tcp … OpenSSH 8.2p1 Ubuntu 4ubuntu0.5` — 버전 문자열에 Ubuntu 패키지 번호까지 들어 있어서, 대략 어떤 Ubuntu 릴리스인지(20.04)도 알 수 있습니다.
- `closed` — 호스트가 리셋으로 답했습니다. 거기서 듣는 건 없습니다. (`filtered`였다면 아무 답도 없었다는 뜻이고, 보통 방화벽 때문입니다.)
- `8080/tcp open http Apache Tomcat 9.0.31` — 표준이 아닌 포트에 애플리케이션 서버가 있고, 버전도 오래됐습니다. 이게 인벤토리에 있었나? 누가 패치하고 있나?
- `Device type / Running / OS details` — OS *추측*. 쓸모는 있지만 확인이 필요합니다.
- `srv-app-0007` 쪽: `445 … Windows Server 2012 R2`. `smb-os-discovery` 스크립트가 **로그인도 안 하고** 정확한 OS 빌드, 컴퓨터 이름, 도메인을 알아냈습니다. Windows Server 2012 R2는 2023년 10월에 확장 지원이 끝났습니다. 유료 확장 보안 업데이트(ESU)에 가입하지 않았다면 보안 패치가 더는 안 나옵니다. 업그레이드하거나, 떼어 놓거나, 다른 보완 통제로 감싸야 하는 호스트입니다.

두 관점을 합치면: 인벤토리는 무엇이 *설치돼* 있는지, 스캔은 무엇이 *드러나* 있는지 알려 줍니다. 설치됐지만 듣고 있지 않은 프로그램도 악성 파일로는 여전히 뚫릴 수 있습니다(클라이언트 측). 포트는 열려 있는데 인벤토리에는 없다면 사각지대입니다. 둘을 합친 게 <strong>공격 표면(attack surface)</strong>, 즉 공격자가 시도해 볼 수 있는 것들의 모음입니다. 이걸 알아야 줄이고(필요 없는 건 없애고) 나머지를 지킬 수 있습니다.

<strong>[보충]</strong> 공격자도 첫 발판에서 똑같은 스캔을 합니다. ATT&CK **T1046 Network Service Discovery**(네트워크 안에서)와 **T1595 Active Scanning**(공격 전, 바깥에서)입니다. 그래서 SOC는 우리 스캐너를 잘 알아야 합니다. 허가된 스캔은 정해진 스캐너 호스트에서 정해진 시간에 와야 하고(그래야 예외 처리할 수 있음), *그 밖의* 호스트가 갑자기 IP·포트 수백 쌍을 건드리면 경보를 울릴 만합니다. 그리고 스캔은 허가받은 네트워크에만 하고, 하기 전에 SOC에 알립니다.

## 2단계 — 취약점 스캔을 계속 돌린다 { #vuln-scanning }

`srv-ftp-02`가 Tomcat 9.0.31을 돌린다는 걸 아는 건 일의 절반입니다. 나머지 절반은 **그 버전이 언제 위험해지는지** 아는 겁니다. 취약점은 매일 발표되고, 익스플로잇 코드는 며칠 안에 따라 나오는 경우가 많습니다. 월요일에 패치를 다 한 서버가, 아무도 손대지 않았는데 목요일에는 회사에서 가장 위험한 장비가 될 수 있습니다.

<strong>취약점 스캐너(vulnerability scanner)</strong>가 이걸 자동으로 해 줍니다. 모든 호스트와 그 소프트웨어를 데이터베이스에 두고, 계속 갱신되는 알려진 취약점 목록(CVE)과 버전을 비교해서 위험이 어디 있는지 보여 줍니다. 건물을 다 지었을 때 한 번 오는 게 아니라, 매주 "결함 부품 최신 목록"을 들고 다시 오는 건물 점검관이라고 생각하면 됩니다.

### 인증 없는 스캔 vs 인증 스캔 { #scan-types }

| | 인증 없는 스캔(unauthenticated) | 인증 스캔(authenticated, credentialed) |
| --- | --- | --- |
| 방법 | Nmap처럼 네트워크로 탐침: 배너, 프로토콜 반응, 몇 가지 안전한 점검 | 로그인(SSH, Windows 관리자 SMB/WinRM, 또는 로컬 에이전트)해서 설치 패키지, 파일 버전, 레지스트리, 패치 수준, 설정을 읽음 |
| 보이는 것 | 서비스가 스스로 드러내는 것만 | 실제로 설치된 것 전부. 포트를 열지 않는 클라이언트 소프트웨어까지 |
| 정확도 | 낮음: 많은 서비스가 버전을 숨기거나 가짜로 보여 주고, 백포트 때문에 오탐 | 높음: 정확한 버전과 설치된 패치 |
| 주 용도 | 인터넷에 노출된 대역을 공격자 눈으로 보기 | 내부 호스트 — 패치 결정을 내릴 때 믿는 스캔 |

같은 서버를 두 가지 눈으로 본 스캐너 보고서는 이런 모습입니다.

```
Host: 10.20.0.31 (srv-ftp-02)                Scan: unauthenticated  2026-11-19 02:10Z
  [Medium] Anonymous FTP enabled                         port 21
  [Info]   SSH server detected: OpenSSH 8.2p1            port 22
  [Info]   HTTP server: Apache Tomcat (version hidden)   port 8080

Host: 10.20.0.31 (srv-ftp-02)                Scan: authenticated    2026-11-19 03:40Z
  [Critical] Apache Tomcat 9.0.31 < 9.0.98 multiple RCE  /opt/tomcat/lib/catalina.jar
  [High]     openssl 1.1.1f-1ubuntu2.16 outdated         package
  [High]     sudo 1.8.31-1ubuntu1.2 privilege escalation package
  [Medium]   Anonymous FTP enabled                       port 21
  [Medium]   Kernel 5.4.0-150 reboot pending (patch installed, not active)
```

- 인증 없는 스캔: 익명 FTP와 OpenSSH는 찾았지만, Tomcat이 버전을 숨기도록 설정돼 있어서 "Tomcat, 버전 모름"이라고밖에 못 했습니다. 치명적 발견 없음 — 위험할 만큼 안심되는 결과입니다.
- 인증 스캔: SSH로 로그인해서 실제 Tomcat 라이브러리 파일과 패키지 데이터베이스를 읽었습니다. 이제 **치명적인 원격 코드 실행(RCE)** 위험이 보이고, 공격자가 일단 들어온 뒤에 중요한 로컬 권한 상승(`sudo`)도 보입니다.
- `reboot pending` — 패치는 깔렸지만 옛 커널이 아직 돌고 있습니다. 인증 점검으로만 보이는 것이고, "패치한" 시스템이 여전히 뚫리는 흔한 이유입니다.

### 결과를 결정으로 바꾸기 { #prioritise }

큰 네트워크는 발견 사항이 수천 개 나옵니다. 패치를 즉시 100% 할 수는 없으니, 스캐너의 진짜 가치는 **줄 세우기**에 있습니다.

- **취약점의 심각도** — 얼마나 나쁜가? (CVSS 점수. 다만 점수만으로는 왜 부족한지는 [아래](#trends) 참고)
- **공격받을 가능성** — 지금 실제로 악용되고 있나? 공개된 익스플로잇 코드가 있나?
- **자산의 중요도** — 도메인 컨트롤러, 인터넷에 노출된 VPN, 급여 서버가 실습실 PC보다 중요합니다.
- **묶음별** — 사업부, OS, 담당자, 규제 범위별로 나눠서 팀마다 자기 목록을 받게 합니다.

전형적인 "목록 맨 위" 화면:

```
Rank  CVE (example)      Host            Exposure         Asset tier  Exploited in wild  Action
1     CVE-2026-0xxxx     vpn-gw-01       Internet         Tier 0      Yes (KEV)          Patch today (emergency)
2     CVE-2026-1xxxx     srv-ftp-02      Internal 8080    Tier 2      Public PoC         Patch this week
3     CVE-2025-4xxxx     450 laptops     Client (PDF)     Tier 3      No                 Normal monthly cycle
```

- 1번: 인터넷에 노출된 최상위(Tier 0) VPN이고, 이미 실제 악용 중(KEV 목록에 있음) → 오늘 긴급 패치.
- 2번: 내부 서버지만 공개된 개념 증명(PoC) 코드가 있음 → 이번 주.
- 3번: 노트북 450대의 PDF 리더, 아직 악용 소식 없음 → 정기 월간 주기.

한 취약점에 대해 "아직 몇 대가 남았나?"를 시간에 따라 그린 게, 큰 취약점이 터졌을 때 경영진이 찾는 감소 그래프(burn-down chart)입니다. 그리고 마지막까지 남은 낙오자 목록이 SOC가 가장 유심히 지켜봐야 할 곳입니다.

<strong>[보충]</strong> SOC에게 취약점 데이터베이스는 패치 도구일 뿐 아니라 **조사 도구**입니다. IDS 경보가 "10.20.0.31에 CVE-X 익스플로잇 시도"라고 하면 첫 질문은 "10.20.0.31이 실제로 CVE-X에 취약한가?"입니다. 패치된 호스트에 대한 시도는 잡음이고, 어젯밤 스캐너가 표시한 호스트에 대한 같은 시도는 사고입니다.

## 3단계 — 패치한다 { #patching }

패치는 **익스플로잇을 막는 단일 수단 중 가장 효과가 큽니다.** 더는 존재하지 않는 버그를 노리는 익스플로잇은 아무것도 못 하니까요. CIS 핵심 보안 통제(CIS Critical Security Controls)는 오래전부터 "우리 소프트웨어 알기"와 "지속적인 취약점 관리"를 목록 맨 위쪽에 두어 왔습니다. (옛 v7 번호로는 소프트웨어 인벤토리가 2번, 지속적인 취약점 관리가 3번이었고, 지금의 v8/v8.1에서는 Control 2 *소프트웨어 자산 목록과 통제*, Control 7 *지속적인 취약점 관리*이며, 1번은 여전히 Control 1 *기업 자산 목록과 통제*입니다.)

"지속적"이라는 말은, "Y 제품 X 버전에 치명적 취약점"이라는 소식이 터졌을 때 월간 주기를 기다리지 않고 빠르게 움직일 수 있는 능력을 뜻합니다. 대상은 세 묶음이고, 셋 다 중요합니다.

- **운영체제** — Windows, Linux 커널, macOS, 네트워크 장비 펌웨어. 흔히 **재부팅**이 필요해서, 서버라면 계획된 서비스 중단을 뜻합니다.
- **서버 소프트웨어** — 웹 서버, 데이터베이스, VPN 게이트웨이, 메일 서버. [서비스 측 익스플로잇](../endpoint-attacks/initial-exploitation.md#service-side)의 과녁입니다.
- **클라이언트 소프트웨어** — 브라우저, PDF 리더, Office, 압축 도구, 메신저. [클라이언트 측 익스플로잇](../endpoint-attacks/initial-exploitation.md#client-side)의 과녁입니다. 포트 스캔에 절대 안 나와서 잊기 쉽습니다. 위 인벤토리 예시의 2021년산 7-Zip이 딱 그런 경우입니다.

### 기준은 미리 정해 둔다 { #emergency-bar }

제조사는 버그가 실제로 악용되고 있으면 정기 일정 밖에서 **긴급(out-of-band) 패치**를 자주 내놓습니다. 운영 서버를 내려서라도 패치할지 정하기에 가장 나쁜 때는 새벽 2시, 일이 터지고 있는 바로 그 순간입니다. 보안팀이 서비스 중단을 밀어붙일 수 있는 위험 수준을 미리, 글로 합의해 둡니다. 예: "인터넷에 노출 + 원격 코드 실행 + 실제 악용 중이거나 공개 익스플로잇 있음 → 서비스가 멈추더라도 48시간 안에 패치하거나 완화 조치". 조직이 호주의 Essential Eight를 따른다면, 그 패치 요구 사항(예: 높은 성숙도 단계에서는 취약점이 치명적이거나 동작하는 익스플로잇이 있으면 인터넷 노출 서비스를 48시간 안에)이 이미 그런 기준이 되어 줍니다.

장기 목표는 OS와 서드파티 애플리케이션 모두에 대한 **자동 패치 관리**입니다. 그래야 "빨리 패치하기"가 영웅적인 수작업이나 고통스러운 서비스 중단 없이도 가능해집니다.

### 패치가 정말 들어갔는지 확인하기 { #verify-patch }

"패치를 배포했다"와 "모든 호스트가 패치됐다"는 다른 말입니다. 간단히 확인하는 방법 몇 가지:

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3
```

```
Source        Description      HotFixID      InstalledBy           InstalledOn
------        -----------      --------      -----------           -----------
LT-FIN-0412   Security Update  KB50xxxxx     NT AUTHORITY\SYSTEM   11/12/2026 12:00:00 AM
LT-FIN-0412   Update           KB50yyyyy     NT AUTHORITY\SYSTEM   11/12/2026 12:00:00 AM
LT-FIN-0412   Security Update  KB50zzzzz     NT AUTHORITY\SYSTEM   10/15/2026 12:00:00 AM
```

- `Get-HotFix`는 OS의 QFE(Quick Fix Engineering) 목록에 기록된 Windows 업데이트를 보여 줍니다. `Sort-Object InstalledOn -Descending`은 최신순, `Select-Object -First 3`은 위에서 3개만.
- `InstalledBy NT AUTHORITY\SYSTEM`은 Windows Update가 설치한 경우 정상입니다.
- 서드파티 애플리케이션 업데이트는 **안 보이고**, 요즘 누적 업데이트에서는 모든 구성 요소가 다 보이지 않을 수도 있습니다. 빠른 확인용이지 완전한 목록이 아닙니다.

**System** 이벤트 로그에도 출처 `Microsoft-Windows-WindowsUpdateClient`로 Windows Update 결과가 남습니다. 이벤트 **19** = 업데이트 설치 성공, **20** = 설치 실패, **43** = 설치 시작. 같은 업데이트에 20이 계속 찍히는 호스트는 조용히 뒤처지고 있는 겁니다. Linux에서는:

```
$ apt list --upgradable 2>/dev/null | grep -i security
openssl/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
$ [ -f /var/run/reboot-required ] && cat /var/run/reboot-required
*** System restart required ***
```

- `apt list --upgradable`은 새 버전이 있는 패키지를 보여 줍니다(`2>/dev/null`은 경고 문구 숨김). `security`로 거르면 보안 저장소에서 온 것만 남습니다. 결과 줄은 "openssl을 3.0.13-0ubuntu3.4에서 3.5로 올릴 수 있다"는 뜻입니다.
- `/var/run/reboot-required`는 Ubuntu/Debian에서 설치된 업데이트(보통 커널이나 핵심 라이브러리)가 재부팅해야 적용될 때 생기는 파일입니다. "깔렸지만 아직 안 먹힌" 상태 — 위 스캐너의 "reboot pending"과 같은 함정입니다.

## 4단계 — 익스플로잇 방지: 패치로 부족할 때 { #anti-exploitation }

### 패치로는 못 푸는 문제 { #why-anti-exploit }

이런 장면을 떠올려 보세요. 사용자가 `Invoice_7731.pdf`가 붙은 메일을 받고, 내려받아서 엽니다. PDF 안에는 PDF 리더를 노린 익스플로잇이 들어 있습니다. 질문 두 개.

1. **먹힐까?** 리더가 취약해야만 먹힙니다. 그런데 그게 *제로데이*(아직 패치가 없는 취약점)이거나, 리더가 잊힌 미패치 사본 중 하나라면 — 먹힙니다.
2. **일어났다는 걸 어떻게 알까?** 따로 도구가 없으면 모를 수도 있습니다. 사용자는 빈 문서만 보고, 첫 신호는 며칠 뒤 C2 트래픽일 수도 있습니다.

악성 파일은 메일, 웹 다운로드, USB, 메신저로 들어옵니다. 패치와 스캔은 그 모두를 앞질러 갈 수 없고, 제로데이라면 더더욱 그렇습니다. <strong>익스플로잇 방지(anti-exploitation)</strong> 도구는 버그가 무엇이든 *익스플로잇 기법* 자체가 실패하게 만들어서 이 문제를 풉니다. 익스플로잇은 호스트 위에서 벌어지는 첫 공격 단계라서, 엔드포인트가 사슬을 끊을 수 있는 가장 이른 지점입니다. 그리고 일찍 끊을수록 쌉니다.

### 익스플로잇 완화 기능은 어떻게 동작하나 { #how-mitigations-work }

건물 비유로 돌아가 봅시다. 패치는 고장 난 특정 자물쇠를 고치는 겁니다. 익스플로잇 방지는 건물을 *구조적으로* 뚫기 어렵게 만드는 쪽에 가깝습니다. 모든 창문에 창살, 바깥으로만 열리는 문, 드릴로 뚫으면 경보가 울리는 벽. 어떤 자물쇠를 여는 새 기술을 가진 도둑도 결국 창살에 막힙니다.

기술적으로 보면, 대부분의 메모리 손상 익스플로잇은 몇 가지 정해진 수를 씁니다. 공격자 데이터로 메모리를 덮어쓰고, 실행 흐름을 그 데이터나 이미 있는 코드 조각들로 돌리는 거죠. 완화 기능들은 그 수를 노립니다.

| 완화 기능 | 막는 것(단순화) |
| --- | --- |
| DEP(Data Execution Prevention, 데이터 실행 방지) | 데이터용 메모리(스택, 힙)에서 코드를 실행하기 |
| ASLR(Address Space Layout Randomization, 주소 무작위화), 강제/상향식 | 코드와 라이브러리가 메모리 어디에 있는지 알기 — 익스플로잇이 기대는 정보 |
| CFG(Control Flow Guard, 제어 흐름 보호) | 간접 호출이 정상 함수 시작점이 아닌 주소로 뛰기 |
| SEHOP | 예외 처리기 사슬을 덮어써서 실행 흐름 가로채기 |
| 내보내기/가져오기 주소 필터링, 호출자 검사, ROP 완화 | 공격자가 엮은 코드 사슬에서 민감한 함수(예: 메모리를 실행 가능하게 바꾸기) 부르기 |
| 자식 프로세스 차단, 코드 무결성 보호, 원격·낮은 무결성 이미지 로드 차단 | 페이로드 단계: `cmd.exe` 띄우기, 서명 안 된 DLL 올리기 |

여기에 큰 덤이 붙습니다. 이 도구들은 막을 때 그게 버퍼 오버플로나 ASLR 우회라는 걸 *알아보기* 때문에, **익스플로잇 시도가 있었다는 로그를 남길 수 있습니다.** 조용한 공격이 몇 초 만에 SOC 경보로 바뀌는 거죠. 그리고 정상 소프트웨어는 이런 완화 기능에 거의 걸리지 않으니, 아주 질 좋은 경보입니다.

### EMET에서 Exploit Guard, 그리고 지금까지 { #emet-exploit-guard }

이 분야에서 Microsoft가 처음 널리 쓰게 한 도구는 **EMET**(Enhanced Mitigation Experience Toolkit)입니다. 이런 완화 기능 없이 만들어진 옛 프로그램에도 완화 기능을 강제로 씌울 수 있는 무료 추가 도구였고, Windows 8.1 / Server 2012 R2까지 썼습니다. EMET는 2018년 7월에 지원이 끝났고, 지금은 쓰면 안 됩니다. 후계자는 Windows 10에 **Windows Defender Exploit Guard**라는 이름으로 내장됐고, 네 가지 통제로 이루어져 있었습니다. "Exploit Guard"라는 브랜드 이름은 그 뒤로 흐려졌고 — 지금은 Windows 보안과 Microsoft Defender for Endpoint 안에서 *익스플로잇 보호*, *공격 표면 축소* 기능으로 불립니다 — 네 구성 요소는 그대로입니다.

**1. 익스플로잇 보호(Exploit protection)** — EMET 완화 기능의 직접 후계자입니다. 시스템 전체 기본값에 프로그램별 예외 설정을 더하고, 각각 *켜기* 또는 *감사(audit)* 모드로 둡니다. 프로그램별 설정을 읽어 볼 수 있습니다.

```powershell
Get-ProcessMitigation -Name AcroRd32.exe
```

```
ProcessName                     : AcroRd32.exe
DEP:
    Enable                      : ON
ASLR:
    ForceRelocateImages         : ON
    BottomUp                    : ON
    HighEntropy                 : ON
ControlFlowGuard:
    Enable                      : ON
ChildProcess:
    DisallowChildProcessCreation: ON
    Audit                       : OFF
ImageLoad:
    BlockRemoteImageLoads       : ON
    BlockLowLabelImageLoads     : ON
```

- `Get-ProcessMitigation -Name`은 이름으로 지정한 프로그램에 걸린 완화 기능을 보여 줍니다(`-System`은 시스템 전체 기본값).
- `DEP Enable ON`, `ASLR ForceRelocateImages ON` — 이 프로그램이 그 기능을 갖고 컴파일되지 않았어도 고전적인 메모리 보호를 강제합니다("강제 ASLR").
- `ChildProcess DisallowChildProcessCreation ON` — PDF 리더는 다른 프로그램을 띄울 수 없습니다. 메모리 안에서는 익스플로잇이 성공했더라도, 그다음 `powershell.exe`를 띄우려는 순간 페이로드 단계에서 막힙니다. `Audit OFF`는 감사 모드가 아니라 실제로 막는다는 뜻입니다.
- `ImageLoad BlockRemoteImageLoads` — 네트워크 공유에서 DLL을 올리지 못하게 합니다. 익스플로잇이 흔히 쓰는 수입니다.
- 막힌 완화 기능은 `Microsoft-Windows-Security-Mitigations/UserMode`와 `…/KernelMode` 로그(이벤트 뷰어 → 응용 프로그램 및 서비스 로그 → Microsoft → Windows → Security-Mitigations)에 남습니다. 이 채널들을 로그 수집 대상에 넣으세요. 양은 적고 가치는 큽니다.

강제하기 전에 시험합니다. 오래된 애플리케이션 중에는 강제 완화 기능 아래에서 죽는 것도 있어서 *감사* 모드가 있는 겁니다.

**2. 제어된 폴더 액세스(Controlled folder access)** — Microsoft의 랜섬웨어 대응책입니다. 폴더를 *보호 폴더*로 지정하면(기본으로 문서, 사진, 바탕 화면 등, 거기에 재무 공유 폴더 같은 우리 폴더 추가), 허용 목록(Microsoft의 신뢰 앱 목록 + 우리가 더한 앱)에 있는 프로그램만 그 안의 파일을 바꿀 수 있습니다. 사용자 권한으로 돌던 랜섬웨어가 `C:\Users\m.lee\Documents\budget.xlsx`를 덮어쓰려 하면 거부됩니다. (노리는 ATT&CK 기법은 **T1486 Data Encrypted for Impact**.)

```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled        # or AuditMode
Add-MpPreference -ControlledFolderAccessProtectedFolders 'D:\FinanceShare'
```

- 1번 줄: 기능을 켭니다(`Enabled` = 막기, `AuditMode` = 기록만).
- 2번 줄: `D:\FinanceShare`를 보호 폴더에 더합니다. `Set-`이 아니라 `Add-`라서 기존 목록에 추가됩니다.

차단은 Defender 로그에 이벤트 **1123**으로 남습니다.

```
Log Name:  Microsoft-Windows-Windows Defender/Operational
Event ID:  1123
Controlled Folder Access blocked C:\Users\m.lee\AppData\Local\Temp\svch0st.exe from making changes to the folder C:\Users\m.lee\Documents\
 Detection time: 2026-11-19T04:12:07.331Z
 User: CORP\m.lee
 Path: C:\Users\m.lee\Documents\budget.xlsx
 Process Name: C:\Users\m.lee\AppData\Local\Temp\svch0st.exe
```

- `Event ID 1123` = 제어된 폴더 액세스 **차단**(`1124` = 감사 모드에서 같은 상황, `1127`/`1128` = 보호된 디스크 섹터 쓰기 차단/감사).
- `Path` — 바꾸려던 파일. `Process Name …\Temp\svch0st.exe` — 철자가 틀린 `svchost`가 Temp에서 돌면서 문서에 쓰려고 했습니다. 여기서 막히는 정상 프로그램은 보통 허용 목록에 넣어야 하는 업무용 앱인데, 이건 그런 게 아닙니다. 한 프로세스가 몇 초 사이에 여러 파일에 대해 1123을 수십 개 찍으면 랜섬웨어 행동입니다. 호스트를 격리합니다.

**3. 네트워크 보호(Network protection)** — Microsoft의 SmartScreen 평판 검사(원래는 Edge 안에서만)를 **모든 애플리케이션의** 나가는 연결로 넓힙니다. 스크립트든, 모르는 `.exe`든, 다른 브라우저든, 어떤 프로세스가 나쁘거나 평판 낮은 도메인·IP에 접속하려 하면 막습니다. 이벤트: **1126** = 차단, **1125** = 감사. C2와 피싱 사이트에 거는 추가 브레이크이지, 프록시를 대신하는 건 아닙니다.

**4. 공격 표면 축소(ASR, Attack Surface Reduction) 규칙** — Office 문서, 메일, 스크립트로 들어오는 악성코드의 전형적인 행동을 막는 규칙들입니다. 규칙마다 GUID와 모드가 있습니다(`0` 끔, `1` 차단, `2` 감사, `6` 경고). 잘 알려진 규칙 몇 가지:

| ASR 규칙(이름) | 막는 것 |
| --- | --- |
| Block all Office applications from creating child processes | `WINWORD.EXE` → `powershell.exe` / `cmd.exe` |
| Block Office applications from creating executable content | 매크로가 디스크에 `update.exe` 쓰기 |
| Block executable content from email client and webmail | Outlook 첨부 파일의 `.exe`·스크립트를 바로 실행 |
| Block JavaScript or VBScript from launching downloaded executable content | 스크립트형 드로퍼 |
| Block execution of potentially obfuscated scripts | 심하게 난독화된 PowerShell/JS |
| Block credential stealing from the Windows local security authority subsystem | 메모리를 읽으려고 `lsass.exe` 열기([자격 증명 덤프](../endpoint-attacks/credential-dumping-mimikatz.md)) |
| Block persistence through WMI event subscription | WMI를 이용한 지속성 |

호스트에 무엇이 설정돼 있는지 확인하기:

```powershell
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

```
d4f940ab-401b-4efc-aadc-ad5f3c50688a
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
1
2
1
```

- 첫 명령은 설정된 규칙 GUID를, 둘째 명령은 그에 맞는 동작을 **같은 순서로** 보여 줍니다. 즉 Office 자식 프로세스 = `1`(차단), LSASS 자격 증명 탈취 = `2`(감사만), 메일 실행 콘텐츠 = `1`(차단).
- 둘을 같이 읽는 게 중요합니다. 감사 모드인 규칙은 기록은 하지만 지켜 주지는 않습니다.

SOC가 반겨야 할 이벤트 — ASR 차단, Defender 이벤트 **1121**:

```
Log Name:  Microsoft-Windows-Windows Defender/Operational
Event ID:  1121
Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator.
 ID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A
 Detection time: 2026-11-19T01:22:41.508Z
 User: CORP\m.lee
 Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 Process Name: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
 Target Commandline: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...
```

칸별로 보면:

- `Event ID 1121` = ASR 규칙이 무언가를 **차단**함(`1122` = 규칙이 감사 모드라서, 차단*했을* 거라고 기록만 함).
- 메시지에 아직 "Exploit Guard"라고 나옵니다. 옛 이름이 이벤트 문구에 남아 있는 겁니다.
- `ID D4F940AB-…` = 규칙 GUID. *Block all Office applications from creating child processes*입니다.
- `Process Name …\WINWORD.EXE` — 뭔가 하려던 부모. `Path …\powershell.exe` — 띄우려던 것.
- `Target Commandline … -nop -w hidden -enc …` — 프로필 없이(`-nop`), 창을 숨기고(`-w hidden`), Base64로 인코딩한 명령(`-enc`)을 넘긴 PowerShell. 전형적인 매크로 드로퍼 행동입니다(ATT&CK **T1204.002 Malicious File** → **T1059.001 PowerShell**).
- 익스플로잇이나 매크로는 Word 안에서 *이미 돌았고*, 그다음 단계만 막혔습니다. 그러니 할 일은: 문서를 찾고(`m.lee`가 01:22에 어떤 파일을 열었나?), 다른 사용자도 받았는지 보고, 그 문서에서 다른 무언가가 성공하지 않았는지 — 예를 들어 어떤 규칙도 막지 않는 다른 기법으로 — 확인하는 겁니다.

**라이선스 — 그리고 2026년 현실.** 처음에는 익스플로잇 보호와 제어된 폴더 액세스는 모든 Windows 10 에디션에, 네트워크 보호는 Enterprise E3에, ASR(그리고 당시 Defender ATP의 중앙 관리·보고)은 E5에 묶여 있었습니다. 지금은 이 기능들이 Microsoft Defender 백신이 주 백신으로 동작하는 Windows 10/11 Pro와 Enterprise에서 돌아갑니다(여러 기능이 실시간 보호와 클라우드 보호에 기댑니다). Microsoft는 E3에서도 ASR을 지원하지만, 완전한 중앙 보고·경보·고급 헌팅은 Microsoft Defender for Endpoint(Plan 2 / E5)가 있어야 합니다. 그게 없다면 Defender 운영 로그를 직접 수집해서 1121~1126이 SIEM에 들어오게 하세요. 그리고 다른 회사 백신이 주 백신이면 Defender는 수동(passive) 모드가 되고, 이 기능들은 보통 강제되지 않습니다. 짐작하지 말고 확인합니다.

## 정리 — SOC가 이 방어선에서 챙길 것 { #soc-use }

- **스캔 일정과 스캐너 IP** — 알고, 예외 처리하고, 그 밖에 스캔처럼 보이는 건 전부 경보로.
- **SIEM 안의 취약점 데이터** — IDS/EDR 경보에 "이 호스트가 이 CVE에 취약한가?"를 붙여 줍니다.
- **패치 낙오자** — 업데이트가 계속 실패하는 호스트(이벤트 20, 스캐너의 "reboot pending")가 공격자가 성공하는 곳입니다. 감시를 더 붙입니다.
- **익스플로잇 방지 이벤트** — Security-Mitigations 이벤트와 Defender 1121/1123/1126(차단)은 경보로 보내고, 1122/1124/1125(감사)는 검토해서 튜닝한 뒤 차단으로 바꿉니다.
- **모든 익스플로잇 경보에서 물을 질문:** 막혔나? 그리고 그게 일어난 *유일한* 일이었나? 자식 프로세스가 막혔다는 건 첫 단계는 돌았다는 뜻입니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    공격 단계를 따라 겹겹이 막는 심층 방어, "모르는 건 지킬 수 없다", 인벤토리와 네트워크 스캔 함께 쓰기, 인증 없는 스캔보다 인증 스캔, 익스플로잇에 맞서는 가장 효과적인 통제로서의 패치(OS, 서버, *그리고* 클라이언트), 긴급 패치 기준 미리 정하기, 막고 기록까지 남기는 익스플로잇 방지 — 모두 설명한 그대로입니다. Nmap의 SYN 스캔, 버전 탐지, OS 추측, NSE 스크립트도 보여 준 대로 동작하고, Exploit Guard의 네 구성 요소도 같은 Defender 이벤트 ID(1121~1128)로 여전히 있습니다.

!!! info "[변경됨] 바뀐 점"
    - **이름과 묶음.** EMET는 2018년부터 지원이 없습니다. "Windows Defender Exploit Guard"는 이제 Microsoft Defender 백신 / Defender for Endpoint 안의 익스플로잇 보호, 제어된 폴더 액세스, 네트워크 보호, ASR 규칙으로 불립니다. ASR은 처음 규칙들보다 훨씬 늘었고(예: LSASS 자격 증명 탈취, WMI 지속성, 취약한 서명 드라이버, 서버의 웹셸 생성 차단), *경고(warn)* 모드도 생겼습니다. ASR은 E3에서도 지원되고, 완전한 보고는 Defender for Endpoint를 통해서입니다.
    - **CIS Controls 번호.** v7의 "Top 20"은 v8(2021)과 v8.1(2024)에서 18개로 바뀌었습니다. 소프트웨어 인벤토리는 Control 2, 지속적인 취약점 관리는 Control 7입니다.
    - **우선순위가 CVSS를 넘어섰다.** CVSS v4.0(2023)이 나왔지만, 요즘 팀들은 심각도에 *가능성*을 더합니다. CISA의 실제 악용 취약점(KEV) 목록, 악용 확률 점수 EPSS, 자산 노출 정도. "9.0 이상은 전부 패치"만으로는 더 이상 좋은 전략으로 보지 않습니다.
    - **익스플로잇까지 걸리는 시간이 무너졌다.** 업계 분석(예: Google/Mandiant의 time-to-exploit 연구)에 따르면, 공개부터 악용까지의 평균 간격이 몇 년 전 약 한 달에서 2023년에 악용된 취약점 기준 약 5일로 줄었고, 상당수는 제로데이로 악용됐습니다. 인터넷 노출 시스템에 월간 패치만으로는 너무 느립니다.
    - **경계 장비가 1순위 과녁.** VPN 게이트웨이, 방화벽, 파일 전송 장비 같은 경계 장비가 2023년 이후 가장 많이 악용되는 제품군에 속합니다. 이런 장비는 EDR이나 익스플로잇 방지 도구를 못 올리는 경우가 많아서, 인벤토리·빠른 패치·로그 전송이 더 중요합니다.
    - **재부팅이 줄었다.** 핫패치(재시작 없는 보안 업데이트)가 Windows 11 Enterprise 24H2와 Windows Server 2025(Azure Arc 구독)에서 가능해졌고, Windows Autopatch 같은 서비스가 배포를 자동화합니다. "빨리 패치하면 서비스가 멈춘다"는 반론이 일부 사라졌습니다.
    - **노출 관리(exposure management).** 인벤토리, 취약점, 공격 표면 데이터가 점점 "노출 관리" / 외부 공격 표면 관리(EASM) 제품으로 합쳐지고, 인터넷 쪽에서 계속 스캔해 줍니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **EMET를 배포하지 마세요.** EMET를 언급하는 옛 가이드에도 기대지 마세요. 지원이 끝났고 지금 Windows와 맞지 않습니다.
    - **인증 없는 스캔의 "치명적 발견 없음"을 믿지 마세요.** 숨긴 배너와 클라이언트 소프트웨어 때문에 눈이 반쯤 가려져 있습니다. 패치 결정에는 인증 스캔이나 에이전트를 씁니다.
    - **"패치 설치됨"을 "패치 완료"로 치지 마세요.** 재부팅이 됐고 재스캔으로 확인될 때까지는 아닙니다.
    - **인벤토리에 `Win32_Product` / `wmic product`를 쓰지 마세요.** PC 전체에 MSI 복구 점검을 일으킵니다. (`wmic` 자체도 Windows에서 제거되는 중입니다.)
    - **ASR 규칙을 감사 모드에 영원히 두지 마세요.** 감사는 튜닝용이고, 감사 모드 규칙은 아무것도 지켜 주지 않습니다. 그리고 Defender가 실제로 주 백신인지 확인하세요. 수동 모드에서는 규칙이 강제되지 않습니다.
    - **약한 OT·의료 장비에 공격적인 능동 스캔을 하지 마세요.** 장비 담당자와 합의 없이는 안 되고, 거기서는 수동 방식으로 찾습니다.
    - **지원이 끝난 시스템을 잊지 마세요.** 확장 보안 업데이트 없는 Windows Server 2012 R2 같은 호스트는 패치가 아예 안 나옵니다. 월간 주기 티켓이 아니라 업그레이드나 격리가 필요합니다.

## 확인 문제 { #quiz }

### 문제 1

자산 관리팀이 "우리 인벤토리 시스템은 커버리지 100%라서 네트워크 스캔은 필요 없어요"라고 말합니다. 인벤토리가 놓칠 수 있지만 네트워크 스캔은 찾아내는 구체적인 예 두 가지와, 그 반대의 예 하나를 드세요.

??? success "정답과 해설"
    **인벤토리가 놓치는 것(스캔은 찾는 것):**

    1. OS에 자기를 등록하지 않은 소프트웨어 — 다운로드 폴더에서 띄운 실행 파일 하나짜리 웹 서버나 개발 도구, 폴더에 풀어 놓은 Python·Java 서비스, 포트를 연 컨테이너. Uninstall 목록에는 없지만 네트워크에서 **듣고** 있습니다.
    2. 에이전트가 아예 없는 장비 — 각종 장비(appliance), 프린터, IP 카메라, 잊힌 테스트 VM, 협력업체 노트북. 인벤토리 시스템은 그 존재 자체를 모르지만, 스캔은 TCP 80/23/8080에서 답하는 IP를 찾아냅니다.

    (또: 인벤토리에는 *있지만* 위험하게 설정된 서비스, 예를 들어 익명 FTP. 직접 찔러 봐야만 보입니다.)

    **반대(인벤토리는 찾고 스캔은 놓치는 것):** 포트를 전혀 열지 않는 클라이언트 소프트웨어 — 오래된 PDF 리더, 압축 도구, 브라우저. 포트 스캔으로는 안 보이지만, 악성 파일을 통한 클라이언트 측 익스플로잇의 과녁입니다. 그래서 둘을 합칩니다. 설치된 것 + 드러난 것 = 공격 표면.

### 문제 2

IDS가 `198.51.100.23`에서 `10.20.0.31:8080`으로 "Apache Tomcat RCE 익스플로잇 시도" 경보를 냈습니다. 어젯밤 `10.20.0.31`에 대한 인증 없는 스캔은 치명적 발견이 없었습니다. 같은 밤의 인증 스캔은 Tomcat 9.0.31의 치명적 RCE 취약점과 "커널 reboot pending"을 보여 줍니다. 각 스캔이 말해 주는 것, 이 경보의 긴급도, 다음에 확인할 것을 말하세요.

??? success "정답과 해설"
    **두 스캔:** 인증 없는 스캔은 Tomcat이 숨긴 버전을 못 읽었으니, "치명적 발견 없음"은 "안전하다"가 아니라 "알 수 없다"는 뜻입니다. 인증 스캔은 디스크에서 실제 버전을 읽었습니다. 이 호스트는 지금 시도되는 종류의 익스플로잇에 **취약합니다.** "reboot pending"은 깔린 패치조차 아직 안 먹혔다는 뜻입니다.

    **긴급도:** 높음. 그 익스플로잇에 *취약하다고 확인된* 호스트에 대한 시도는 잡음이 아니라 침해 가능성이 큰 사건입니다. (같은 경보가 패치된 호스트에 대한 것이었다면 낮은 우선순위입니다.)

    **다음 확인:**

    1. `srv-ftp-02`에서: 경보 시각 전후로 Tomcat 프로세스(`java`)가 무언가 — `sh`, `bash`, `curl`, `wget` — 를 띄웠나(프로세스 로그 / auditd / EDR)? webapps 폴더에 새 파일(웹셸)이 생겼나? 호스트에서 밖으로 나가는 연결이 있나?
    2. 웹/Tomcat 접근 로그에서 `198.51.100.23`의 요청과 HTTP 상태 코드.
    3. 성공 흔적이 있으면 격리. 어쨌든 Tomcat을 패치하고(긴급 기준 충족: 닿을 수 있음, RCE, 실제 시도 중) 재부팅합니다.
    4. 같은 출발지가 다른 호스트도 건드렸는지, 같은 취약 버전을 돌리는 다른 호스트가 있는지 확인합니다.

### 문제 3

재무팀 노트북에서 1분 안에 아래 이벤트들을 찾았습니다. 각 이벤트를 설명하고, 무엇이 막혔는지, 사고가 끝났는지 말하세요.

```
01:22:41  Defender 1121  ID D4F940AB-401B-4EFC-AADC-AD5F3C50688A  Process: WINWORD.EXE  Path: powershell.exe  Cmd: powershell -nop -w hidden -enc ...
01:22:43  Defender 1122  ID 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2  Process: C:\Users\Public\rdr.exe  Path: lsass.exe
01:22:50  Defender 1123  Process: C:\Users\Public\rdr.exe  Folder: C:\Users\m.lee\Documents\
```

??? success "정답과 해설"
    **1121(차단)** — ASR 규칙 *Block all Office applications from creating child processes*가 Word가 숨긴 창의 인코딩된 PowerShell을 띄우는 걸 막았습니다. 악성 문서가 열렸고, 그 매크로나 익스플로잇은 돌았습니다.

    **1122(감사)** — 규칙 *Block credential stealing from LSASS*가 **감사** 모드뿐입니다. `C:\Users\Public\rdr.exe`가 `lsass.exe`를 열었고, 규칙은 **막지 않았습니다** — 막았을 거라고 기록만 했습니다. 자격 증명 탈취가 성공했을 수 있습니다.

    **1123(차단)** — 제어된 폴더 액세스가 같은 `rdr.exe`가 문서 폴더의 파일을 바꾸는 걸 막았습니다. 랜섬웨어 같은 행동이 차단됐습니다.

    **끝나지 않았고, 심각합니다.** PowerShell 단계는 막혔는데도 `rdr.exe`가 존재하고 돌고 있습니다. 즉 문서가 실행 파일을 떨어뜨리고 실행할 **다른 길**을 찾았거나(또는 두 번째 단계가 다른 경로로 왔거나), 그다음 LSASS를 읽고(허용됨) 파일을 암호화하려 했습니다(차단됨). 노트북을 격리하고, 문서와 `rdr.exe`를 수집하고, `rdr.exe`가 어떻게 생겼는지(프로세스 생성 로그, Sysmon 11 파일 생성) 찾고, 그 노트북에 캐시된 모든 자격 증명을 털린 것으로 보고 재설정하고, 그 계정들이 다른 곳에서 쓰였는지 찾고, 튜닝 뒤 LSASS 규칙을 감사에서 차단으로 바꿉니다. 교훈: 감사 모드 규칙은 보이게 해 줄 뿐, 지켜 주지는 않습니다.

## 관련 레퍼런스 { #related }

- [엔드포인트 공격](../endpoint-attacks/index.md) — 이 섹션이 막으려는 공격 단계들
- [최초 침투](../endpoint-attacks/initial-exploitation.md) · [자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md)
- [피싱 전달](../../../adversary/phishing-delivery.md) · [EternalBlue와 SMBv1](../../../adversary/eternalblue-smbv1.md) · [PrintNightmare](../../../adversary/printnightmare.md)
- [Windows 버전별 하드닝](../../../adversary/hardening-by-version.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md) · [잘 알려진 포트](../../../basics/well-known-ports.md)
