---
title: "방화벽과 개체 접근 이벤트 — Windows 방화벽 로그(pfirewall.log, 5156/5157/5152/5154), iptables/UFW 로그, 4663/4657/4660"
tags:
  - training
  - blue-team
  - windows
  - linux
  - logging
  - firewall
---

# 방화벽과 개체 접근 이벤트 — Windows 방화벽 로그, iptables/UFW 로그, 4663/4657/4660 { #firewall-object-access }

!!! abstract "이 페이지에서 다루는 것"
    "**무엇이 무엇과 통신했나**", 그리고 "**누가 이 중요한 걸 건드렸나**"에 답하는 엔드포인트 로그 두 종류입니다. 먼저 **호스트 방화벽 로그**. 컴퓨터마다 있는 방화벽이 왜 네트워크 경계의 큰 방화벽보다 더 좋은 네트워크 센서가 되는지(네트워크 *안쪽* 통신을 보고, 연결을 만든 **프로세스**까지 안다), Windows 방화벽이 로그를 남기는 두 방법 — 텍스트 파일 **`pfirewall.log`**(형식을 칸별로 읽기, 한계, 프로필별 파일)와 Security 채널의 **필터링 플랫폼(Filtering Platform)** 이벤트(**5156** 허용, **5157** 연결 차단, **5152** 패킷 버림, **5154** 수신 대기) — 그리고 5156 하나를 한 줄씩 읽고, **방화벽 설정 자체가 바뀔 때** 남는 이벤트까지. 이어서 Linux 쪽: **iptables/UFW** 로그 한 줄을 syslog 머리와 `KEY=value` 쌍으로 쪼개 읽고, 왜 파싱이 까다로운지, nftables로 바뀌어도 형식이 어떻게 유지되는지. 마지막으로 **개체 접근 감사(object access auditing)**: 누군가 일부러 그 파일이나 레지스트리 키에 감시를 걸어 둬야만 4663이 생기는 이유, 두 단계 설정(감사 정책 + SACL), 그리고 **4663**(개체 접근), **4657**(레지스트리 값 변경), **4660**(개체 삭제)을 칸별로 읽기. SOC 점검 목록, 2026년 관점, 확인 문제가 이어집니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. **호스트 방화벽(host firewall)** 로그는 엔드포인트마다 붙은 네트워크 센서입니다. 경계 방화벽을 지나지 않는 내부 컴퓨터끼리의 통신(동서 트래픽, east-west traffic)을 보고, Windows에서는 연결 하나하나를 그걸 만든 **프로세스**와 이어 줍니다. 네트워크 장비는 이걸 못 합니다.
2. Windows 방화벽은 두 가지로 기록할 수 있습니다. **텍스트 파일**(`%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`, 기본은 꺼짐, 프로필별 파일 가능, 최대 약 32 MB) 또는 *Filtering Platform* 감사 하위 범주가 만드는 **Security 채널 이벤트**. Security 로그 전달은 이미 대부분 하고 있으니 보통 이벤트 쪽이 수집하기 쉽습니다.
3. 핵심 필터링 플랫폼 이벤트: **5156** 연결 허용, **5157** 연결 차단, **5152** 패킷 버림, **5154** 프로그램이 포트에서 수신 대기. 5156에는 **프로그램 경로와 프로세스 ID**, 방향, 주소, 포트, 프로토콜이 들어 있습니다.
4. 이 이벤트들은 **양이 엄청납니다.** 계획하고 켜고, 강하게 거르고(쿼리에서, 또는 좁게 검토한 수집 필터로), 차단 이벤트·수신 대기 이벤트·이상한 프로세스의 외부 연결을 우선하세요.
5. 방화벽 자체의 변경(규칙 추가, 방화벽 끄기)은 따로 기록됩니다. 방화벽 전용 채널과 Security 이벤트 4946–4950입니다. 공격자는 포트를 열고 방화벽을 끄니(ATT&CK **T1562.004**) 경보를 걸 가치가 있습니다.
6. Linux **iptables/UFW** 로그 한 줄은 **커널**이 쓴 syslog 줄이고, 뒤에 거의 `KEY=value` 쌍이 붙습니다(`IN=`, `OUT=`, `SRC=`, `DST=`, `PROTO=`, `SPT=`, `DPT=`). 그런데 어떤 건 값 없는 깃발(`DF`, `SYN`)이고, 어떤 키는 비어 있어서(`IN=`) 파서가 선택적인 칸을 허용해야 합니다. **프로세스 정보는 없습니다.**
7. **개체 접근 감사**(4663, 4657, 4660)에는 **두 가지**가 필요합니다. 감사 하위 범주를 켜는 것, **그리고** 파일·폴더·레지스트리 키마다 감사 항목(SACL)을 거는 것. 정책만 켜면 아무것도 기록되지 않습니다. 그래서 개체 접근 이벤트가 있다는 건 보통 누군가 그 개체가 중요하다고 정했다는 뜻입니다.
8. 4663은 **Subject**(누가), **Object**(무엇을), **Process**(어떤 프로그램으로), **Access**(어떤 종류 — 읽기, 쓰기, 삭제)로 읽습니다. 4657은 레지스트리 값의 **옛 값과 새 값**을 더 주고, 4660은 개체가 **삭제됐다**고만 말하니 이름을 알려면 앞선 이벤트와 핸들 ID로 이어야 합니다.

## 호스트 방화벽 로그가 왜 중요한가 { #why-host-firewall }

큰 사무실 건물을 떠올려 보세요. 정문 경비(네트워크 방화벽)는 건물에 들어오고 나가는 사람을 다 확인합니다. 하지만 일단 안에 들어온 사람은 이 사무실 저 사무실을 돌아다녀도 경비가 보지 못합니다. 이번엔 사무실 문마다 작은 자물쇠와 방문 기록부가 있다고 해 봅시다. 기록부에는 누가 몇 시에 어느 방에서 왔는지 적히고, 정문 경비와 달리 얼굴만이 아니라 **사원증 이름**까지 적힙니다. 호스트 방화벽이 바로 문마다 붙은 자물쇠와 기록부입니다. 여기서 "사원증"은 연결을 연 **프로세스**입니다.

기술적인 실제로 돌아오면, 많은 조직은 이미 호스트 방화벽을 돌리고 있습니다. 운영체제에 들어 있거나(Windows 방화벽, Linux의 `nftables`/`iptables`와 UFW·firewalld 같은 앞단 도구), 엔드포인트 보안 제품에 딸려 오기 때문입니다. SOC에게 이 방화벽의 가치는 대부분 **로그 출처**로서이고, 이유는 세 가지입니다.

- **네트워크 안쪽이 보입니다.** 옆으로 이동(lateral movement) — 워크스테이션끼리의 SMB, 서버 사이의 RDP, WinRM, 내부 대역 스캔(T1046, Network Service Discovery) — 은 보통 경계 방화벽을 지나지 않습니다. 받는 쪽 컴퓨터의 호스트 방화벽은 그걸 봅니다. 허용됐든 막혔든.
- **프로세스를 압니다.** Windows 필터링 플랫폼은 소켓마다 어느 프로그램 것인지 압니다. "`\device\harddiskvolume3\users\public\inv.exe`가 443 포트로 나갔다"는 5156 한 줄은 "10.20.4.114 → 198.51.100.23:443"이라는 네트워크 로그보다 훨씬 많은 걸 말해 줍니다.
- **회사 밖에서도 기록됩니다.** 집이나 호텔에 있는 노트북은 네트워크 센서 밖에 있지만, 호스트 방화벽 로그는 여전히 그 노트북이 한 일을 기록합니다. 수집만 할 수 있다면요.

함정은 **양**입니다. 바쁜 워크스테이션은 한 시간에 수천 번 연결을 만듭니다(브라우저, 업데이트, 텔레메트리, 이름 조회). 이걸 다 SIEM으로 보내면 다른 출처를 다 합친 것보다 비쌀 수 있습니다. 현실적인 답은 출처를 버리는 게 아니라 *골라서* 모으는 것입니다. 막힌 트래픽, 수신 대기 이벤트, 워크스테이션으로 들어오는 연결, 이상한 프로그램의 외부 연결 같은 것들이요.

[보충] 호스트 방화벽이 무언가를 **막은 것** 자체도 탐지입니다. 어떤 워크스테이션에 갑자기 이웃 컴퓨터에서 온 SMB 접속 시도가 수백 건 막혔다면, 지금 바로 웜이나 공격자의 탐색을 실시간으로 보고 있는 겁니다.

## Windows 방화벽 로그 방법 1: pfirewall.log { #pfirewall }

### 켜는 법 { #pfirewall-config }

Windows 방화벽(옛 문서에서는 "Windows Firewall with Advanced Security", 그 뒤 몇 년은 "Windows Defender Firewall", 지금 Microsoft 문서에서는 그냥 "Windows Firewall")에는 **프로필(profile)** 이 셋 있습니다. **Domain**(회사 도메인에 연결됨), **Private**(집처럼 믿을 수 있는 네트워크), **Public**(그 밖의 모든 곳). 로그는 **프로필마다** 설정하고, 기본값은 버린 패킷도 성공한 연결도 **꺼져 있습니다.**

그룹 정책에서는 *Computer Configuration → Windows Settings → Security Settings → Windows Firewall with Advanced Security → Properties → (프로필) → Logging → Customize*에 있습니다. PowerShell로는 이렇게 합니다.

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public `
  -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' `
  -LogMaxSizeKilobytes 32767 -LogBlocked True -LogAllowed True
Get-NetFirewallProfile | Select-Object Name, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked
```

- 1행 — `Set-NetFirewallProfile`은 지정한 프로필의 설정을 바꿉니다. 여기서는 셋 다. 줄 끝의 백틱(`` ` ``)은 명령이 다음 줄로 이어진다는 표시입니다.
- 2행 — `-LogFileName`으로 파일을 정합니다. 기본 이름과 폴더를 그대로 썼습니다. 프로필마다 **파일을 따로**(예: `domainfw.log`, `publicfw.log`) 줄 수도 있는데, 그러면 노트북이 회사 밖에 있을 때 어느 프로필이 켜져 있었는지 바로 보입니다.
- 3행 — `-LogMaxSizeKilobytes 32767`은 크기 한도를 기본 **4,096 KB**에서 최대값(32 MB 조금 못 됨)으로 올립니다. 파일이 꽉 차면 Windows는 그걸 `pfirewall.log.old`로 이름을 바꾸고 새 파일을 시작합니다. 즉 호스트에는 **파일 두 개 분량의 기록만** 남습니다. `-LogBlocked`와 `-LogAllowed`는 무엇을 적을지 고릅니다.
- 4행 — 결과를 보여 줘서 확인할 수 있습니다.

```text
Name    LogFileName                                              LogMaxSizeKilobytes LogAllowed LogBlocked
----    -----------                                              ------------------- ---------- ----------
Domain  %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log                  32767       True       True
Private %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log                  32767       True       True
Public  %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log                  32767       True       True
```

이 파일을 밖으로 보내 주는 기능은 따로 없습니다. 다른 텍스트 로그처럼 모으면 됩니다. 파일 끝을 계속 읽는 로그 에이전트나 SIEM의 파일 감시 입력을 쓰세요.

### 파일 읽기 { #pfirewall-read }

파일은 칸 이름을 알려 주는 W3C 방식 머리로 시작하고, 그 뒤에 이벤트마다 공백으로 나뉜 한 줄이 이어집니다.

```text
#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid

2026-11-20 10:14:03 ALLOW TCP 10.20.4.114 198.51.100.23 51544 443 0 - 0 0 0 - - - SEND 7996
2026-11-20 10:14:09 DROP TCP 10.20.4.37 10.20.4.114 49822 445 52 S 1928374650 0 64240 - - - RECEIVE 4
2026-11-20 10:14:09 DROP TCP 10.20.4.37 10.20.4.114 49823 3389 52 S 2203948811 0 64240 - - - RECEIVE 0
2026-11-20 10:14:12 ALLOW UDP 10.20.4.114 10.20.0.10 60512 53 0 - - - - - - - SEND 2312
2026-11-20 10:14:20 DROP ICMP 10.20.4.37 10.20.4.114 - - 60 - - - - 8 0 - RECEIVE 0
```

머리 줄:

- `#Version: 1.5` — 형식 버전입니다. Windows 버전에 따라 칸 목록이 조금 다를 수 있으니, **고정 위치가 아니라 늘 `#Fields:` 줄을 보고** 파싱하세요.
- `#Time Format: Local` — 시각이 UTC가 아니라 그 컴퓨터의 **현지 시각**입니다. 시간대가 다른 여러 호스트로 타임라인을 만들 때는 먼저 바꿔야 합니다.
- `#Fields:` — 칸 이름이 순서대로 나옵니다. 최근 Windows는 끝에 `pid`(프로세스 ID)를 붙이고, 옛 버전은 `path`에서 끝납니다.

첫 번째 데이터 줄을 쪼개 보면:

| 칸 | 값 | 뜻 |
| --- | --- | --- |
| `date` `time` | `2026-11-20 10:14:03` | 호스트의 현지 시각 |
| `action` | `ALLOW` | `ALLOW`, `DROP`, 가끔 `INFO-EVENTS-LOST`(기록이 따라가지 못함) |
| `protocol` | `TCP` | `TCP`, `UDP`, `ICMP`, 또는 프로토콜 번호 |
| `src-ip` / `dst-ip` | `10.20.4.114` → `198.51.100.23` | 출발지와 목적지 주소 |
| `src-port` / `dst-port` | `51544` → `443` | 포트(ICMP는 `-`) |
| `size` | `0` | 패킷 크기(바이트). 허용된 연결은 보통 `0`, 버린 패킷에는 값이 있음 |
| `tcpflags` | `-` | 버린 패킷의 TCP 플래그(`S` = SYN, `A` = ACK, `F` = FIN, `R` = RST, `P` = PSH) |
| `tcpsyn` / `tcpack` / `tcpwin` | `0 0 0` | 버린 패킷의 TCP 순서 번호, 확인 번호, 윈도 크기 |
| `icmptype` / `icmpcode` | `-` `-` | ICMP일 때 유형과 코드(`8 0` = 에코 요청, 즉 ping) |
| `info` | `-` | 일부 항목의 추가 정보 |
| `path` | `SEND` | 이 호스트 기준 방향: `SEND` = 나감, `RECEIVE` = 들어옴, 라우팅되면 `FORWARD` |
| `pid` | `7996` | 연결을 가진 프로세스 ID(있는 경우) |

이제 다섯 줄을 이야기로 읽어 봅시다. 1행: 이 워크스테이션(`10.20.4.114`)이 밖으로 HTTPS 연결을 했고, 그 연결의 주인은 프로세스 7996입니다. 2행과 3행: 같은 초에 다른 워크스테이션 `10.20.4.37`이 이 호스트의 **445(SMB)** 와 **3389(RDP)** 포트로 SYN 패킷(`S`)을 보냈고, 둘 다 들어오다가 **버려졌습니다.** 4행: 내부 DNS 서버로 가는 평범한 DNS 질의. 5행: 같은 이웃이 보낸 ping(`8 0`)이 버려졌습니다. 워크스테이션이 이웃의 SMB, RDP, ICMP를 찔러 보는 건 전형적인 내부 정찰(T1046)이거나 옆으로 이동 시도(T1021.001 RDP, T1021.002 SMB/Windows Admin Shares)입니다. 바로 `10.20.4.37`을 봐야 합니다. 누가 로그온해 있는지, 10시 14분 즈음 어떤 프로세스가 돌았는지.

한계 두 가지를 기억하세요. 첫째, `pfirewall.log`에는 **프로세스 ID는 있지만 프로세스 이름은 없습니다.** `7996`을 프로그램 이름으로 바꾸려면 같은 호스트, 같은 시각의 프로세스 로그([프로세스 생성 이벤트](process-creation.md))가 필요합니다. 둘째, 로컬 관리자나 관리자로 도는 악성코드는 로그 설정을 바꾸거나 파일을 지울 수 있습니다. 그러니 빨리 호스트 밖으로 보내세요.

## Windows 방화벽 로그 방법 2: Security 로그의 필터링 플랫폼 이벤트 { #wfp-events }

### 켜는 법 { #wfp-config }

Windows 방화벽 뒤에서 실제로 일하는 엔진은 **Windows 필터링 플랫폼(Windows Filtering Platform, WFP)** 입니다. 고급 감사 정책의 *Object Access* 아래 하위 범주 두 개를 켜면 WFP가 **Security** 채널에 감사 이벤트를 씁니다.

```text
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable
auditpol /get /subcategory:"Filtering Platform Connection","Filtering Platform Packet Drop"
```

- 1행 — *Filtering Platform Connection*: 성공(Success)은 **5156**(허용된 연결)과 **5158**(프로그램이 로컬 포트에 묶임)을, 실패(Failure)는 **5157**(막힌 연결)을 만들고, **5154/5155**(프로그램의 수신 대기 허용/차단)도 이 범주가 맡습니다.
- 2행 — *Filtering Platform Packet Drop*: 실패는 **5152**(패킷 버림)와 **5153**(더 엄격한 규칙이 패킷을 거부)을 만듭니다.
- 3행 — 지금 설정을 보여 줍니다.

```text
System audit policy
Category/Subcategory                      Setting
Object Access
  Filtering Platform Packet Drop          Failure
  Filtering Platform Connection           Success and Failure
```

도메인 환경에서는 `auditpol`을 손으로 치지 말고 그룹 정책으로 설정하세요. 그리고 조심하세요. *Filtering Platform Connection*의 *성공*을 켜면 그 컴퓨터가 만드는 **거의 모든 연결**마다 5156이 생깁니다. 그래서 많은 조직은 실패(차단)만 전체에 켜고, 성공은 서버에만 켜거나 수집 단계에서 거릅니다.

### 이벤트와 생기는 때 { #wfp-ids }

| 이벤트 | 이름 | 언제 생기나 | 왜 중요한가 |
| --- | --- | --- | --- |
| **5156** | The Windows Filtering Platform has permitted a connection | 연결(TCP)이나 흐름(UDP)이 허용됨, 들어오든 나가든 | 프로세스–네트워크 지도: 어느 프로그램이 어느 주소·포트와 통신했나 |
| **5157** | The Windows Filtering Platform has blocked a connection | 연결이 차단 규칙에 걸림 | 닫힌 문을 두드리는 탐색과 옆으로 이동, 외부 통신이 막힌 악성코드 |
| **5152** | The Windows Filtering Platform blocked a packet | 패킷이 버려짐(흔히 받는 프로그램도 규칙도 없는, 요청하지 않은 인바운드) | 스캔과 잡음. 한꺼번에 몰릴 때 쓸모 있음 |
| **5154** | The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections | 프로그램이 수신 대기 포트를 엶 | 새 수신 대기 = 백도어, 바인드 셸, 예상 못 한 서비스 |
| 5158 | The Windows Filtering Platform has permitted a bind to a local port | 프로그램이 로컬 포트에 묶임(아주 시끄러움) | 거의 수집 안 함 |

공격자에게 이 이벤트들이 중요한 이유는, 그들이 조용히 하려는 바로 그 일을 잡기 때문입니다. 이상한 프로그램이 인터넷으로 보내는 비컨(명령 제어, Command and Control, T1071), 백도어용 새 수신 대기, 네트워크 너머 관리 포트로의 연결 같은 것들이요.

### 5156 전체 보기 { #5156-sample }

프로세스 생성 이야기에 나왔던 `inv.exe`(`certutil`이 `C:\Users\Public\`에 내려받은 파일)가 이제 바깥으로 연락합니다.

```xml
<System>
  <EventID>5156</EventID>
  <TimeCreated SystemTime="2026-11-20T02:14:21.0937714Z" />
  <Channel>Security</Channel>
  <Computer>WS-114.corp.example</Computer>
  <Keywords>0x8020000000000000</Keywords>
</System>
<EventData>
  <Data Name="ProcessID">8124</Data>
  <Data Name="Application">\device\harddiskvolume3\users\public\inv.exe</Data>
  <Data Name="Direction">%%14593</Data>
  <Data Name="SourceAddress">10.20.4.114</Data>
  <Data Name="SourcePort">51561</Data>
  <Data Name="DestAddress">203.0.113.77</Data>
  <Data Name="DestPort">443</Data>
  <Data Name="Protocol">6</Data>
  <Data Name="FilterRTID">70241</Data>
  <Data Name="LayerName">%%14611</Data>
  <Data Name="LayerRTID">48</Data>
  <Data Name="RemoteUserID">S-1-0-0</Data>
  <Data Name="RemoteMachineID">S-1-0-0</Data>
</EventData>
```

칸별로 보면:

- `Keywords` `0x8020000000000000` — "감사 성공(Audit Success)" 키워드. 5157이라면 `0x8010000000000000`(감사 실패)입니다.
- `ProcessID` — `8124`, 연결을 가진 프로세스입니다. 여기서는 **10진수**입니다(같은 숫자를 4688은 16진수 `0x1fbc`로 씁니다). 이벤트를 이을 때 이 변환에서 자주 걸려 넘어집니다.
- `Application` — 프로그램 경로가 **장치 형식(device form)** 입니다. `C:\` 대신 `\device\harddiskvolume3\`. 같은 파일, 다른 표기입니다. 프로세스 로그와 잇기 전에 정규화하거나(또는 경로 끝부분으로 비교하세요). `\users\public\`에 있는 프로그램이 인터넷에 연결한다는 것만으로도 수상합니다.
- `Direction` — `%%14593` = **나감(Outbound)**, `%%14592` = 들어옴(Inbound). 다른 `%%` 값처럼 이벤트 뷰어가 글자로 바꿔 주는 메시지 표 코드입니다([Windows 이벤트 구조와 채널](../windows-logging/event-structure-channels.md) 참고).
- `SourceAddress` / `SourcePort` — 나가는 연결이면 늘 **이 컴퓨터** 쪽, 들어오는 연결이면 **상대방** 쪽입니다. `Direction`과 같이 읽으세요.
- `DestAddress` / `DestPort` — `203.0.113.77:443`, HTTPS 포트의 인터넷 주소. 프록시, DNS, 위협 정보에서 확인하세요.
- `Protocol` — IP 프로토콜 번호. `6` = TCP, `17` = UDP, `1` = ICMP.
- `FilterRTID` — 이 연결을 허용한 WFP 필터(규칙)의 실행 시간 ID. 호스트에서(`netsh wfp show filters`) 찾아보면 어떤 방화벽 규칙이 맞았는지 알 수 있습니다.
- `LayerName` / `LayerRTID` — WFP 계층. `%%14611`(계층 48) = *ALE Connect*(나가는 연결 승인). 들어오는 연결 수락이면 *Receive/Accept* 계층(`%%14610`)이 보입니다.
- `RemoteUserID` / `RemoteMachineID` — IPsec 인증을 쓸 때만 채워집니다. `S-1-0-0` = 없음.

이제 여러 출처에 걸친 이야기가 완성됩니다. 4688은 `certutil`이 `inv.exe`를 내려받는 걸(T1105), 다음 4688은 `inv.exe`가 시작되는 걸, 5156은 **바로 그 파일이** `203.0.113.77:443`으로 나가는 걸 보여 줍니다. HTTPS를 통한 명령 제어일 가능성이 높습니다(T1071.001). 네트워크 로그만으로는 "워크스테이션 → 203.0.113.77:443"밖에 안 보였을 겁니다.

### 방화벽 변경을 기록하는 이벤트 { #firewall-changes }

[보충] 공격자는 백도어나 원격 접속을 위해 포트를 열거나(`netsh advfirewall firewall add rule ...`, `New-NetFirewallRule`), 방화벽을 아예 끕니다(`netsh advfirewall set allprofiles state off`, `Set-NetFirewallProfile -Enabled False`). ATT&CK은 이걸 **T1562.004, Impair Defenses: Disable or Modify System Firewall**(방어 무력화: 시스템 방화벽 끄기·바꾸기)이라고 부릅니다. 다음을 지켜보세요.

- Security 채널(하위 범주 *MPSSVC Rule-Level Policy Change*): **4946** 규칙 추가, **4947** 규칙 수정, **4948** 규칙 삭제, **4950** 방화벽 설정 변경.
- 방화벽 전용 채널 `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`(기본으로 켜져 있음): **2004** 규칙 추가, **2005** 규칙 수정, **2006** 규칙 삭제, **2003** 프로필 설정 변경(예: 방화벽 끔). 최신 Windows 11 빌드는 같은 동작을 새 번호 계열로 씁니다(예: 규칙 추가에 **2097**, 일부 빌드에서는 **2071**). 탐지를 쓰기 전에 우리 Windows 버전이 어떤 번호를 남기는지 꼭 확인하세요.
- 명령줄이 있는 `netsh.exe advfirewall`이나 PowerShell `*-NetFirewallRule`/`Set-NetFirewallProfile`의 프로세스 생성 이벤트.

사용자가 쓸 수 있는 폴더에 있는 프로그램으로 들어오는 트래픽을 허용하는 규칙, 또는 서버에서 Domain 프로필이 꺼진 것은 바로 들여다볼 만합니다.

## Linux 호스트 방화벽 로그: iptables, nftables, UFW { #iptables }

### 로그는 어디서 오나 { #iptables-source }

Linux에서 패킷 거르기는 커널(**netfilter**) 안에서 일어납니다. 규칙은 `iptables`(옛 방식), `nft`(**nftables**, 요즘 대체품), 또는 더 쉬운 앞단 도구 **UFW**(Ubuntu), **firewalld**(Red Hat 계열)로 관리합니다. 규칙에 `LOG` 동작(iptables)이나 `log` 구문(nftables)이 있으면 **커널**이 자기 로그 버퍼에 한 줄을 씁니다. 거기서 `rsyslog`가 파일로 옮깁니다. Debian/Ubuntu는 `/var/log/kern.log`나 `/var/log/syslog`, Red Hat은 `/var/log/messages`이고, UFW는 자기 rsyslog 설정으로 `/var/log/ufw.log`에 따로 씁니다. systemd 저널이 있으면 `journalctl -k`로 볼 수 있습니다([Syslog](../linux-logging/syslog.md), [Linux 로그 파일과 저널](../linux-logging/log-files-journal.md) 참고).

관리망 밖에서 들어오는 새 SSH 연결을 기록하고 버리는 가장 간단한 iptables 예:

```text
iptables -A INPUT -p tcp --dport 22 ! -s 10.20.9.0/24 -m conntrack --ctstate NEW -j LOG --log-prefix "SSH-DENY " --log-level 4
iptables -A INPUT -p tcp --dport 22 ! -s 10.20.9.0/24 -j DROP
```

- `-A INPUT` — 이 호스트로 들어오는 트래픽의 체인 끝에 규칙을 붙입니다.
- `-p tcp --dport 22` — 22번 포트로 가는 TCP.
- `! -s 10.20.9.0/24` — 출발지가 관리 대역이 **아닌** 것.
- `-m conntrack --ctstate NEW` — 새 연결의 첫 패킷만(패킷마다가 아니라 연결마다 한 번 기록).
- `-j LOG --log-prefix "SSH-DENY " --log-level 4` — 접두어로 시작하는 커널 로그 한 줄을 syslog 심각도 4(warning)로 씁니다. `LOG`는 패킷을 멈추지 않습니다. 그래서 두 번째 규칙이 실제로 버립니다.

UFW로는 `ufw deny 22/tcp`와 `ufw logging on`이면 됩니다. 그러면 UFW가 `[UFW BLOCK]`, `[UFW ALLOW]`, `[UFW AUDIT]` 같은 접두어를 씁니다.

### 한 줄 읽기 { #iptables-read }

Ubuntu 서버의 두 줄입니다. 하나는 허용된 나가는 DNS 질의, 하나는 막힌 들어오는 SSH 시도입니다.

```text
Nov 20 07:32:33 web-01 kernel: [  945.682935] [UFW ALLOW] IN= OUT=ens33 SRC=10.20.30.15 DST=10.20.0.10 LEN=76 TOS=0x00 PREC=0x00 TTL=64 ID=61739 DF PROTO=UDP SPT=45469 DPT=53 LEN=56
Nov 20 07:35:02 web-01 kernel: [ 1094.120771] [UFW BLOCK] IN=ens33 OUT= MAC=00:50:56:aa:bb:cc:00:50:56:dd:ee:ff:08:00 SRC=203.0.113.45 DST=10.20.30.15 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=21877 DF PROTO=TCP SPT=40122 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0
```

syslog 머리(커널 줄은 모두 같음):

- `Nov 20 07:32:33` — syslog 데몬이 붙인 시각. 호스트의 현지 시각이고 **연도가 없습니다**(전통적인 BSD syslog 형식).
- `web-01` — 호스트 이름.
- `kernel:` — "프로그램"이 커널 자신입니다. PID가 없습니다.
- `[  945.682935]` — 커널 자체 시계로 잰 부팅 후 초. 순서를 맞출 때는 편하지만 실제 시각으로는 못 씁니다. 설정에 따라 안 보이기도 합니다.
- `[UFW ALLOW]` / `[UFW BLOCK]` — 규칙에서 정한 **로그 접두어(log prefix)**. **동작(허용/차단)** 이 나오는 곳은 여기뿐입니다. 순수 iptables라면 관리자가 써 넣은 무엇이든(`SSH-DENY `) 나옵니다. 파서는 우리 환경의 접두어를 알아야 합니다.

본문을 칸별로(두 번째 줄):

| 칸 | 값 | 뜻 |
| --- | --- | --- |
| `IN=` | `ens33` | 패킷이 들어온 인터페이스. 이 컴퓨터가 만든 나가는 패킷이면 **비어 있음**(첫 줄) |
| `OUT=` | (비어 있음) | 나가는 인터페이스. 이 호스트로 배달되는 패킷이면 비어 있음 |
| `MAC=` | `00:50:56:aa:bb:cc` `00:50:56:dd:ee:ff` `08:00` | 목적지 MAC, 출발지 MAC, EtherType(`08:00` = IPv4)이 붙어 있음. 들어오는 패킷에만 |
| `SRC=` / `DST=` | `203.0.113.45` → `10.20.30.15` | 출발지와 목적지 IP |
| `LEN=` | `60` | IP 패킷 전체 길이(바이트) |
| `TOS=` / `PREC=` | `0x00` | 서비스 유형 / 우선순위 비트. 거의 쓸 일 없음 |
| `TTL=` | `49` | 남은 수명. 시작값은 보통 64(Linux)나 128(Windows)이니, 49는 15홉쯤 떨어진 Linux 비슷한 발신자를 뜻함 |
| `ID=` | `21877` | IP 식별 번호 |
| `DF` | (깃발) | "조각내지 마시오(Don't Fragment)" 설정 — **key=value가 아니라 단어 하나** |
| `PROTO=` | `TCP` | `TCP`, `UDP`, `ICMP` |
| `SPT=` / `DPT=` | `40122` → `22` | 출발지·목적지 포트 |
| `WINDOW=` / `RES=` | `64240` / `0x00` | TCP 윈도 크기, 예약 비트 |
| `SYN` | (깃발) | TCP 플래그는 단어로 나옴(`SYN`, `ACK`, `FIN`, `RST`, `PSH`) |
| `URGP=` | `0` | 긴급 포인터 |

첫 줄의 두 번째 `LEN=`을 보세요. 앞의 `LEN=76`은 IP 패킷 길이이고, 뒤의 `LEN=56`은 **UDP** 길이입니다. 한 줄 안에서 같은 키가 두 가지 뜻으로 쓰입니다. 이것, 그리고 값 없는 깃발, 빈 키, 어떤 프로토콜에서만 나오는 칸(`MAC=`, `WINDOW=`, ICMP의 `TYPE=`/`CODE=`) 때문에 이 로그는 파싱이 까다롭습니다. 좋은 파서는 머리와 본문을 나누고, 접두어를 동작으로 잡고, `KEY=value` 쌍을 읽고, 혼자 있는 단어는 깃발로 모으고, **첫 번째** `LEN`을 패킷 길이로 씁니다.

보안 관점에서 중요한 칸은 시각, 호스트, **동작(접두어)**, 인터페이스(컴퓨터의 어느 쪽인가), **SRC/DST**, **PROTO**, **SPT/DPT**입니다. 두 번째 줄은 인터넷 주소가 SSH를 시도했다가(SYN만 있으니 연결은 시작도 못 함) 막힌 것입니다. 인터넷에 열린 서버라면 늘 있는 배경 잡음이지만, 한 출발지에서 이런 줄이 **몰려** 나오거나, *내부* 주소에서 SSH가 막혔다면 들여다볼 만합니다(T1110 무차별 대입, T1021.004 SSH 옆으로 이동).

Linux 줄에 **없는 것**: **프로세스**입니다. netfilter는 패킷을 다룰 뿐, 어느 프로그램이 보냈는지 모릅니다. 나가는 트래픽을 프로세스와 이으려면 auditd `connect` 규칙, eBPF 기반 센서, EDR이 필요합니다.

[보충] nftables의 `log` 구문도 같은 커널 로그 경로를 쓰기 때문에 줄 모양이 같습니다(접두어, 그다음 `IN=`/`OUT=`/`SRC=`...). 요즘 UFW와 firewalld도 밑에서는 nftables를 씁니다. 배포판이 iptables에서 nftables로 넘어가도 파서는 바꿀 필요가 없습니다.

### Windows와 Linux 방화벽 로그 비교 { #fw-comparison }

| | Windows `pfirewall.log` | Windows 5156/5157/5152/5154 | Linux iptables/nftables/UFW |
| --- | --- | --- | --- |
| 위치 | 프로필별 텍스트 파일 | Security 채널 | 커널 로그 → `kern.log`/`syslog`/`messages`/`ufw.log`, 저널 |
| 기본값 | 꺼짐 | 꺼짐(감사 하위 범주) | `LOG`/`log`가 있는 규칙만(UFW: `ufw logging on`) |
| 프로세스 | PID만(최근 버전) | **경로 + PID** | 없음 |
| 시각 | 현지 시각, 시간대 표시 없음 | 이벤트 안에 UTC | syslog 현지 시각, 연도 없음 |
| 형식 | 공백 구분, 머리가 칸 이름을 알려 줌 | 구조화된 이벤트 칸 | syslog 머리 + `KEY=value` + 깃발 단어 |
| 회전/한도 | 최대 약 32 MB + `.old` 파일 하나 | Security 로그 크기와 전달 | 일반 로그 회전 |

## Windows 개체 접근 감사: 4663, 4657, 4660 { #object-access }

### 이 이벤트들이 특별한 이유 { #object-access-why }

박물관을 떠올려 보세요. 대부분의 방에는 카메라가 없습니다. 가장 귀한 물건이 든 진열장 몇 개에만 전용 카메라가 있고, 유리가 열릴 때마다 기록이 남습니다. 그 진열장에서 경보가 왔다면 바로 두 가지를 압니다. 누군가 진열장을 건드렸다는 것, **그리고** 누군가 예전에 그 진열장이 지켜볼 만큼 귀하다고 정했다는 것.

개체 접근 감사가 똑같습니다. Windows는 파일이나 레지스트리 접근을 전부 기록하지 **않습니다.** 그러면 한 시간에 수백만 건이 될 테니까요. 두 가지를 해야 합니다.

1. **감사 하위 범주를 켭니다.** 고급 감사 정책의 *Object Access* 아래 *Audit File System*(파일과 폴더), *Audit Registry*(레지스트리 키), 관련된 개체 종류에는 *Audit Kernel Object*, *Audit Removable Storage*, *Audit Detailed File Share*.
2. **지켜볼 개체마다 감사 항목을 겁니다.** 모든 파일, 폴더, 레지스트리 키에는 보통 권한 목록(DACL) 말고도 **SACL**(System Access Control List, 시스템 접근 제어 목록)이 있습니다. SACL의 감사 항목은 "*이* 계정이나 그룹이 *이런* 종류로 접근하면(읽기, 쓰기, 삭제...) 성공 그리고/또는 실패를 기록하라"는 뜻입니다. 개체의 *Properties → Security → Advanced → Auditing* 탭에서, `Set-Acl`로, 또는 그룹 정책(*File System*과 *Registry* 정책, 또는 컴퓨터의 모든 파일이나 키에 SACL을 거는 **Global Object Access Auditing** — 아주 조심해서 쓰세요)으로 중앙에서 겁니다.

정책만 켜고 SACL이 없는 파일이면 아무것도 **안 생깁니다.** 그래서 개체 접근 이벤트가 있다는 것 자체가 무언가를 말해 줍니다. 누군가 그 개체를 골랐다는 것. 아니면 누군가 **너무 넓은** SACL(예: 드라이브 전체에 `Everyone`, 모든 접근)을 걸어서 Security 로그가 넘치고 쓸모 있는 이벤트가 밀려나는 중일 수도 있습니다. 현장에서 흔한 실수입니다.

지켜볼 만한 것: 민감한 데이터가 든 폴더(재무, 인사, 법무), 자격 증명 저장소와 그 백업(`ntds.dit` 복사본, `SAM`/`SECURITY` 하이브 백업 — T1003.002, T1003.003), `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` 같은 **레지스트리의 지속성(persistence) 위치**(T1547.001), 보안 도구 설정 키(T1562.001), 그리고 아무도 열 일이 없는 "카나리아(canary)" 미끼 파일.

### 이벤트 4663: 개체에 접근하려는 시도가 있었음 { #4663 }

**4663**은 어떤 계정이 감사 대상 개체에 대해 접근 권한을 **실제로 사용할 때** 생깁니다. 읽고, 쓰고, 지우고, 권한을 바꿀 때요. (짝인 **4656** "개체 핸들이 요청됨"은 프로그램이 접근을 *요청*할 때 생기고 실패도 포함합니다. "실제로 무슨 일이 있었나"에는 보통 4663이 더 쓸모 있습니다. **4658**은 핸들이 닫힌 기록입니다.)

한 사용자 계정이 재무 공유의 감사 대상 폴더에서 파일을 복사해 갑니다.

```xml
<System>
  <EventID>4663</EventID>
  <TimeCreated SystemTime="2026-11-20T03:41:55.2201930Z" />
  <Channel>Security</Channel>
  <Computer>FS-02.corp.example</Computer>
</System>
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="SubjectUserName">j.park</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x8a3f21</Data>
  <Data Name="ObjectServer">Security</Data>
  <Data Name="ObjectType">File</Data>
  <Data Name="ObjectName">D:\Shares\Finance\Payroll\2026-11-payroll.xlsx</Data>
  <Data Name="HandleId">0x1c84</Data>
  <Data Name="AccessList">%%4416</Data>
  <Data Name="AccessMask">0x1</Data>
  <Data Name="ProcessId">0x4</Data>
  <Data Name="ProcessName"></Data>
  <Data Name="ResourceAttributes">S:AI</Data>
</EventData>
```

이벤트 메시지가 보여 주는 네 부분과 그 뒤의 칸:

- **Subject** — *누가*: `SubjectUserSid`/`SubjectUserName`/`SubjectDomainName` = `CORP\j.park`. `SubjectLogonId` `0x8a3f21`은 `FS-02`의 4624로 이어져 어떻게 로그온했는지 보여 줍니다. 여기서는 그 사람 워크스테이션에서 온 **유형 3(네트워크)** 로그온일 겁니다([로그인 이벤트](logins.md) 참고).
- **Object** — *무엇을*: `ObjectServer`는 파일이면 늘 `Security`, `ObjectType`은 `File`(레지스트리면 `Key`, 폴더도 `File`), `ObjectName`은 전체 경로, `HandleId` `0x1c84`는 핸들 번호입니다. 같은 열기에 대한 4656, 4663, 4658, 4660을 묶어 주는 열쇠입니다.
- **Process Information** — *어떤 프로그램으로*: `ProcessId`와 `ProcessName`. 여기서 `0x4`와 빈 이름은 **System** 프로세스를 뜻합니다. 파일에 **SMB로 네트워크를 통해** 접근하면 이렇게 보입니다. 서버의 커널(System, PID 4)이 사용자 대신 일을 하기 때문입니다. 로컬 접근이라면 `C:\Windows\explorer.exe`나 `C:\Users\Public\inv.exe` 같은 실제 경로가 보입니다. (공유 접근은 *Audit Detailed File Share*의 이벤트 **5145**가 클라이언트 IP와 공유 이름을 더 줍니다.)
- **Access Request Information** — *어떤 종류*: `AccessList` `%%4416` = **ReadData(또는 ListDirectory)**, `AccessMask` `0x1`은 같은 권한을 숫자로 쓴 것입니다.

자주 만나는 파일 접근 권한:

| `AccessMask` | `AccessList` | 파일(폴더)에서의 뜻 |
| --- | --- | --- |
| `0x1` | `%%4416` | ReadData(ListDirectory) — 읽기(목록 보기) |
| `0x2` | `%%4417` | WriteData(AddFile) — 쓰기(파일 추가) |
| `0x4` | `%%4418` | AppendData(AddSubdirectory) — 덧붙이기(하위 폴더 추가) |
| `0x80` | `%%4423` | ReadAttributes — 속성 읽기 |
| `0x100` | `%%4424` | WriteAttributes — 속성 쓰기 |
| `0x10000` | `%%1537` | DELETE — 삭제 |
| `0x40000` | `%%1539` | WRITE_DAC — 권한 바꾸기 |
| `0x80000` | `%%1540` | WRITE_OWNER — 소유권 가져오기 |

마스크는 비트를 더해서 합칩니다. `0x6` = WriteData + AppendData.

이벤트 하나가 아니라 패턴으로 읽는 법: 한 사용자가 급여 파일 하나를 읽는 건 아마 업무입니다. 같은 계정이 **몇 분 사이에 여러 폴더의 파일 수백 개를** 읽는다면 유출을 위한 수집(T1039, Data from Network Shared Drive)이거나 랜섬웨어의 훑어보기입니다. 많은 파일에서 `WriteData`가 몰리고 이어서 `DELETE`가 나오면 암호화 후 삭제의 모습입니다(T1486). 관리자가 아닌 사람이 민감한 폴더에 `WRITE_DAC`을 했다면 따져 볼 만한 권한 변경입니다(T1222.001).

### 이벤트 4657: 레지스트리 값이 바뀜 { #4657 }

**4657**은 감사 대상 레지스트리 키 아래의 값이 만들어지거나, 바뀌거나, 지워질 때 생깁니다(하위 범주 *Audit Registry*, 그리고 그 키에 "Set Value" SACL). 가장 큰 장점은 **옛 값과 새 값**을 기록한다는 것입니다. 공격자가 지속성을 위해 Run 키 항목을 추가합니다.

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="SubjectUserName">j.park</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x2b04e11</Data>
  <Data Name="ObjectName">\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</Data>
  <Data Name="ObjectValueName">OneDriveSyncHelper</Data>
  <Data Name="HandleId">0x2f8</Data>
  <Data Name="OperationType">%%1904</Data>
  <Data Name="OldValueType">-</Data>
  <Data Name="OldValue">-</Data>
  <Data Name="NewValueType">%%1873</Data>
  <Data Name="NewValue">C:\Users\Public\inv.exe -silent</Data>
  <Data Name="ProcessId">0x20d8</Data>
  <Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
</EventData>
```

- `ObjectName` — **커널 형식**의 키 이름. `\REGISTRY\MACHINE\` = `HKLM\`, `\REGISTRY\USER\<SID>\` = `HKU\<SID>\`(어떤 사용자의 `HKCU`). 이건 컴퓨터 전체에 걸리는 Run 키라서, 여기 적힌 건 어떤 사용자가 로그온하든 시작됩니다.
- `ObjectValueName` — 값 이름 `OneDriveSyncHelper`. 공격자는 정상 소프트웨어처럼 보이는 이름을 고릅니다. 이름은 아무것도 증명하지 않습니다.
- `OperationType` — `%%1904` = **새 값 만듦**, `%%1905` = 있던 값 바꿈, `%%1906` = 값 지움.
- `OldValueType` / `OldValue` — 전에 값이 없었으니 `-`. 수정이라면 여기에 이전 데이터가 보입니다. 공격자가 정상 항목의 경로를 *바꿔치기*할 때 아주 쓸모 있습니다.
- `NewValueType` / `NewValue` — `%%1873` = `REG_SZ`(문자열). 데이터는 시작할 프로그램, 즉 사용자가 쓸 수 있는 폴더에 있는 우리의 `inv.exe`입니다. 이것이 **T1547.001, Boot or Logon Autostart Execution: Registry Run Keys**(부팅·로그온 자동 실행: 레지스트리 Run 키)입니다.
- `ProcessId` / `ProcessName` — `reg.exe`가 바꿨으니, 바로 앞에 `reg.exe add HKLM\...\Run /v OneDriveSyncHelper ...`의 4688이 있어야 합니다(T1112, Modify Registry).
- `HKLM\...\Run`에 쓰려면 관리자 권한이 필요합니다. 그러니 이 시점에 공격자는 이미 권한을 올렸습니다. `SubjectLogonId` `0x2b04e11`의 로그온과 토큰을 확인하세요.

### 이벤트 4660: 개체가 삭제됨 { #4660 }

**4660**은 감사 대상 개체가 지워졌다고 말하지만, 헷갈리게도 **개체 이름이 없습니다.** `HandleId`, subject, 프로세스만 있습니다. *어떤* 파일이 지워졌는지 알려면 조금 전에 **같은 `HandleId`, 같은 프로세스 ID, 같은 호스트**로 남은 4663(`DELETE`, `0x10000`)이나 4656을 찾으세요.

```text
03:52:10.118  4663  FS-02  HandleId=0x2210  ProcessName=C:\Users\Public\inv.exe  ObjectName=D:\Shares\Finance\Payroll\2026-11-payroll.xlsx  AccessMask=0x10000
03:52:10.119  4660  FS-02  HandleId=0x2210  ProcessName=C:\Users\Public\inv.exe
```

- 1행 — 4663이 파일 이름을 알려 주고, 핸들 `0x2210`으로 `0x10000`(DELETE)을 쓰는 걸 보여 줍니다.
- 2행 — 1밀리초 뒤, 같은 핸들의 4660이 삭제가 실제로 일어났다는 걸 확인해 줍니다.

Windows에는 일부 경우를 위한 **4659**(삭제할 생각으로 핸들을 요청함)도 있습니다. 감사 대상 파일이 한꺼번에 지워지는 건 랜섬웨어의 뒷정리나 흔적을 지우는 공격자의 전형입니다(T1070.004, Indicator Removal: File Deletion).

### 관련 개체 접근 이벤트 { #object-access-other }

- **4656** — 개체 핸들 요청(실패한 시도도 포함 — "누군가 카나리아 파일을 열려고 *했다*"에 좋음).
- **4658** — 핸들 닫힘(파일을 얼마나 오래 열어 두었는지 잴 수 있음).
- **4670** — 개체 권한이 바뀜(옛 보안 설명자와 새 보안 설명자).
- **5140 / 5145** — 네트워크 공유에 접근함 / 공유 안의 파일에 대해 접근 확인을 함(하위 범주 *Audit File Share* / *Audit Detailed File Share*. 클라이언트 IP 포함 — [SMB](../other-protocols/smb.md) 참고).
- **`lsass.exe`에 대한 4663** — *Audit Kernel Object*를 켜고 LSASS 프로세스에 감사 항목이 있으면, 그 메모리를 읽으려는 시도가 `ObjectType` = `Process`인 4656/4663을 남깁니다. 자격 증명 덤프의 고전적인 신호입니다(T1003.001, [자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) 참고). 보통은 EDR 제품이 더 확실하게 잡습니다.

## SOC에서 써먹기 { #soc-use }

- **호스트 방화벽에서 무엇을 모을지 정하세요.** 최소한: 워크스테이션과 서버에서 막힌 인바운드(5157/5152 또는 `DROP` 줄, UFW `BLOCK`), 새 수신 대기 포트(5154), 방화벽 설정 변경(4946–4950, 방화벽 채널 규칙 이벤트). 허용된 연결(5156)은 서버에서, 또는 워크스테이션에서는 브라우저가 아닌 프로세스와 표준이 아닌 포트로 걸러서 더하세요.
- **공통 칸으로 정규화하세요:** `host`, `action`, `direction`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `process_path`, `process_id`. 장치 경로는 드라이브 문자로, 10진수/16진수 PID는 한 형식으로, 현지 시각은 UTC로 바꿉니다.
- **사냥하고 경보 걸 것:** 워크스테이션끼리의 SMB/RDP/WinRM, 한 출발지가 여러 호스트나 여러 포트를 두드림(차단), `Temp`, `Downloads`, `Public`, `ProgramData`의 프로그램이 밖으로 연결, Office나 스크립트 호스트의 인터넷 연결, 워크스테이션의 새 수신 대기, 방화벽 끄기나 넓은 허용 규칙 추가, Linux `BLOCK` 줄의 내부 출발지 SSH.
- **값어치 있는 곳에 SACL을 거세요.** 민감한 공유(읽기와 삭제), Run 키와 다른 자동 실행 키(값 설정), 보안 도구 키, 미끼 파일(모든 접근). SACL 범위를 검토하고, 볼륨 전체에 `Everyone`/모든 접근은 피하세요.
- **이벤트 하나만 쳐다보지 말고 이으세요.** `SubjectLogonId` → 4624(어떻게 로그온했나), `ProcessName`/`ProcessId` → 4688(그 프로세스가 무엇이었나), `HandleId` → 4663/4660(무엇이 지워졌나), 5156 `ProcessID` → 4688 `NewProcessId`(16진수로 바꾸기!).
- **증거를 지키세요.** 빨리 호스트 밖으로 보내고, 1102(Security 로그 지움)와 감사 정책 변경(4719)에 경보를 거세요.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효한 것"
    Windows 방화벽의 두 가지 기록 방법, `pfirewall.log` 형식과 한계, 필터링 플랫폼 이벤트 5156/5157/5152/5154와 그 칸, iptables/UFW 로그 형식, 그리고 4663/4657/4660을 쓰는 개체 접근 감사는 최신 Windows 11, Windows Server 2025, 최신 Linux 배포판에서 모두 설명대로 동작합니다. 바탕에 깔린 생각 — 프로세스를 아는 네트워크 센서로서의 호스트 방화벽, 그리고 누군가 SACL을 건 곳에서만 일어나는 개체 감사 — 도 그대로입니다.

!!! info "[변경됨] 바뀐 점"
    - **이름.** Microsoft 문서는 이제 대부분 그냥 **Windows Firewall**이라고 부릅니다(몇 년 동안은 "Windows Defender Firewall"이었습니다). 관리 스냅인은 여전히 "with Advanced Security"라고 나옵니다. 로그 설정은 바뀌지 않았습니다.
    - **방화벽 변경 이벤트 번호.** 최신 Windows 11 빌드는 방화벽 채널에서 규칙 변경을 옛 2004–2006 계열과 함께, 또는 그 대신 새 번호(2097, 일부 빌드에서 2071 등)로 남깁니다. 공개 탐지 규칙(예: Sigma)도 이제 이 번호들을 다 찾습니다. 우리 빌드가 무엇을 쓰는지 확인하세요.
    - **nftables가 기본 패킷 필터**입니다. 최신 Debian, Ubuntu, Red Hat 계열에서 `iptables` 명령은 흔히 그 위의 호환 계층이고, UFW와 firewalld도 밑에서 nftables를 씁니다. 분석가가 보는 커널 로그 줄 형식은 그대로입니다.
    - **EDR 네트워크 기록**(Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend 등) 덕에 이제 대부분의 조직은 5156을 전부 켜지 않고도 프로세스–연결 기록을 얻습니다. Sysmon 이벤트 3(네트워크 연결)도 같은 일을 하는데, 단독 도구로도, 2026년에는 Windows에 들어간 선택적 기능으로도 쓸 수 있습니다. 5156/5157은 에이전트 없는 독립 출처로서 여전히 쓸모 있습니다.
    - **공통 스키마**(Elastic Common Schema, OCSF, Microsoft ASIM)가 네트워크와 파일 활동의 표준 칸을 정해 두었으니, 수집할 때 정규화하면 탐지 하나로 pfirewall, 5156, UFW, EDR 데이터를 다 덮을 수 있습니다.
    - **클라우드와 아이덴티티가 먼저.** 민감한 데이터의 상당수가 이제 SaaS와 클라우드 저장소에 있고, 거기서 "개체 접근"은 Windows 4663이 아니라 그 서비스의 감사 로그(예: Microsoft 365 파일 접근 이벤트, 클라우드 저장소 접근 로그)가 기록합니다. 사내 파일 서버에는 여전히 4663이 필요합니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **모든 컴퓨터에서 Filtering Platform Connection 성공을 켜고 전부 보내지 마세요.** SIEM이 넘치고, Security 로그가 몇 분 만에 한 바퀴 돌아 로그온과 프로세스 이벤트가 밀려납니다. 양부터 계획하세요.
    - **`pfirewall.log`가 켜져 있다고, 기록이 오래 남는다고 가정하지 마세요.** 기본은 꺼짐이고, 현재 파일과 `.old` 하나만 남습니다.
    - **`pfirewall.log` 시각을 바꾸지 않고 이벤트 시각과 비교하지 마세요.** 현지 시각과 UTC입니다.
    - **10진수를 16진수로 바꾸지 않고 5156 `ProcessID`를 4688 `NewProcessId`와 잇지 마세요.** `\device\harddiskvolumeN\` 경로도 정규화하세요.
    - **Linux 방화벽 로그에서 프로세스를 기대하지 마세요.** 그건 auditd, eBPF 센서, EDR의 몫입니다.
    - **4663이 없다고 "아무도 그 파일을 안 건드렸다"고 결론 내리지 마세요.** SACL이 없으면 애초에 아무것도 기록되지 않습니다. SACL부터 확인하세요.
    - **시험 없이 Global Object Access Auditing이나 드라이브 전체에 `Everyone`/모든 권한 SACL을 쓰지 마세요.** Security 로그를 묻어 버릴 수 있습니다.
    - **4660에서 파일 이름을 찾지 마세요.** `HandleId`를 따라 4663/4656으로 거슬러 가세요.

## 확인 문제 { #quiz }

### 문제 1

워크스테이션 `WS-207`에서 이 `pfirewall.log` 줄들을 봤습니다(현지 시각). 무엇을 보여 주는지, 어떤 칸이 중요한지, 다음에 무엇을 할지 말하세요.

```text
2026-11-20 14:02:11 DROP TCP 10.20.4.91 10.20.4.207 50112 445 52 S 3391827401 0 64240 - - - RECEIVE 4
2026-11-20 14:02:11 DROP TCP 10.20.4.91 10.20.4.207 50113 135 52 S 1029384756 0 64240 - - - RECEIVE 0
2026-11-20 14:02:12 DROP TCP 10.20.4.91 10.20.4.207 50114 5985 52 S 2938475610 0 64240 - - - RECEIVE 0
```

??? success "정답과 해설"
    - `DROP` + `RECEIVE` — 들어오던 패킷을 이 호스트의 방화벽이 **버렸습니다.**
    - `src-ip` `10.20.4.91` → `dst-ip` `10.20.4.207` — 출발지가 다른 **내부** 컴퓨터(워크스테이션 대역)입니다. 경계 방화벽은 이 트래픽을 절대 못 봅니다.
    - `dst-port` `445`, `135`, `5985` — SMB, RPC 엔드포인트 매퍼, WinRM(HTTP). Windows 원격 관리와 옆으로 이동의 고전적인 세 문입니다.
    - `tcpflags` `S` — SYN 패킷뿐. 세션이 맺어진 게 아니라 연결 시도입니다.
    - 같은 출발지에서 약 1초 안에 포트 세 개 — 사람이 둘러보는 게 아니라 자동화된 탐색입니다.

    **보여 주는 것:** `10.20.4.91`이 스캔하거나 옆으로 이동하려 합니다(T1046, T1021.002 SMB, T1021.006 WinRM). 이 호스트의 방화벽이 막았습니다. **다음:** `10.20.4.91`을 봅니다. 누가 로그온해 있는지(4624), 14시 2분 즈음 어떤 프로세스가 돌았는지(4688/Sysmon/EDR), 그 컴퓨터에서 나간 연결. 다른 호스트들의 방화벽 로그에서 같은 출발지를 검색해 몇 대를 건드렸는지 확인하고, 격리를 검토합니다. 시각이 현지 시각이라는 걸 잊지 마세요. UTC인 Security 이벤트와 비교하기 전에 바꿔야 합니다.

### 문제 2

어떤 서버에 `Application` = `\device\harddiskvolume2\windows\system32\rundll32.exe`, `Direction` = `%%14593`, `DestAddress` = `198.51.100.140`, `DestPort` = `8443`, `Protocol` = `6`, `ProcessID` = `5320`인 5156이 있습니다. 각 칸을 설명하고, `rundll32.exe`가 무엇을 돌리고 있었는지 어떻게 찾을지 말하세요.

??? success "정답과 해설"
    - `Application` — 진짜 `rundll32.exe`(`C:\Windows\System32\rundll32.exe`의 장치 경로 표기). 프로그램 자체는 정상입니다. DLL 안의 함수를 실행하는 도구라 악성 DLL을 돌리는 데 자주 악용됩니다(T1218.011).
    - `Direction` `%%14593` — **나가는** 연결.
    - `DestAddress`/`DestPort` — 표준이 아닌 HTTPS 비슷한 포트 TCP 8443의 인터넷 주소. `rundll32.exe` 자신은 인터넷과 직접 통신할 이유가 없습니다. 통신하는 건 그게 불러온 DLL입니다.
    - `Protocol` `6` — TCP.
    - `ProcessID` `5320` — 10진수. 4688에서 같은 프로세스는 `NewProcessId` `0x14c8`로 나옵니다.

    **무엇을 돌렸는지 찾기:** 그 호스트에서 5156 조금 전의 4688(또는 Sysmon 1/EDR)에서 `NewProcessId` = `0x14c8`이고 `NewProcessName`이 `rundll32.exe`로 끝나는 걸 찾습니다. 그 `CommandLine`이 어떤 DLL과 함수인지(예: `C:\ProgramData\`나 `AppData`의 DLL), `ParentProcessName`이 무엇이 띄웠는지 보여 줍니다. 그다음 프록시/DNS/위협 정보에서 목적지를 확인하고, DLL을 수집해 분석하고, 다른 컴퓨터에서도 같은 목적지가 있는지 찾습니다. 명령 제어 통로일 가능성이 큽니다(T1071.001).

### 문제 3

동료가 말합니다. "어제 도메인 감사 정책에서 *Audit File System*과 *Audit Registry*를 켰는데, Run 키나 재무 공유에 대한 4663이나 4657이 하나도 없어요. 감사 정책이 고장 났나 봐요." 가장 그럴듯한 이유는 무엇이고, 어떻게 고치고, 무엇을 조심해야 할까요?

??? success "정답과 해설"
    정책은 아마 멀쩡합니다. 개체 접근 감사에는 **두 가지**가 필요합니다. 하위 범주 켜기(했음), **그리고 개체마다 감사 항목(SACL)**. `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`과 재무 공유 폴더에 SACL이 없으면 Windows는 기록할 게 없습니다.

    **고치기:** SACL을 겁니다. Run 키에는 `Everyone`이나 *Authenticated Users*의 *Set Value*(그리고 *Create Subkey*/*Delete*) 성공을, 재무 폴더에는 관련 그룹의 *Read Data*, *Write Data*, *Delete*, *Change Permissions*(성공, 시도까지 보고 싶으면 실패도)를. 일관되게 적용되도록 그룹 정책(*File System*/*Registry* 보안 정책)으로 배포하고 시험합니다. 시험 값을 바꾸고 시험 파일을 읽은 뒤 4657과 4663이 생기는지 확인하세요.

    **조심할 것:** SACL은 좁게 거세요. 드라이브 전체에 `Everyone`/모든 권한도, 시험 없는 Global Object Access Auditing도 안 됩니다. 그러면 Security 로그가 차서 한 바퀴 돌고, 로그온과 프로세스 이벤트가 밀려납니다. 먼저 시범 서버에서 이벤트 양을 확인하고, Security 로그 크기를 늘리고, 이벤트가 호스트 밖으로 전달되는지 확인하세요.

## 관련 레퍼런스 { #related }

- [꼭 알아야 할 이벤트](index.md) — 이 섹션 개요
- [로그인 이벤트](logins.md) — `SubjectLogonId` 뒤의 로그온
- [프로세스 생성 이벤트](process-creation.md) — PID나 `ProcessName`을 전체 명령줄로 바꾸기
- [Windows 이벤트 구조와 채널](../windows-logging/event-structure-channels.md) — `%%` 메시지 코드와 방화벽 채널
- [Syslog](../linux-logging/syslog.md) — 커널 방화벽 줄마다 붙는 머리
- [Linux 로그 파일과 systemd 저널](../linux-logging/log-files-journal.md) — `kern.log`, `ufw.log`, `messages`가 있는 곳
- [Credential Guard, Application Guard, 호스트 방화벽, 백신](../endpoint-defense/vbs-firewall-antivirus.md) — 방어 수단으로서의 호스트 방화벽
- [애플리케이션 제어, FIM, 지속성 잡기](../endpoint-defense/appcontrol-fim-persistence.md) — 방어 쪽에서 Run 키와 파일 지켜보기
- [옆으로 이동, 수집, 유출](../endpoint-attacks/lateral-collection-exfil.md) — 이 로그들이 잡는 공격자 행동
- [SMB](../other-protocols/smb.md) — 공유 접근과 5140/5145
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
