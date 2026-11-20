---
title: "Credential Guard, Application Guard, 호스트 방화벽, 백신 — 비밀은 따로 가두고, 호스트에는 울타리 치기"
tags:
  - training
  - blue-team
  - endpoint
  - hardening
  - credential-guard
  - firewall
  - antivirus
---

# Credential Guard, Application Guard, 호스트 방화벽, 백신 — 비밀은 따로 가두고, 호스트에는 울타리 치기 { #vbs-firewall-antivirus }

!!! abstract "이 페이지에서 다루는 것"
    패치와 익스플로잇 보호 다음에 오는 방어선들입니다. 먼저 가상화 기반 보안(VBS). Credential Guard가 LSASS가 쥐고 있던 비밀을 하이퍼바이저가 지키는 별도의 세계로 옮겨서, 관리자조차 더는 덤프할 수 없게 만드는 원리, 정말 돌고 있는지 확인하는 법, 그리고 Credential Guard가 *못* 지키는 것. 이어서 같은 생각을 위험한 웹 서핑과 Office 문서에 적용한 Application Guard(그리고 왜 지금은 은퇴했는지). 두 번째로 호스트 방화벽. 프로필, 기본 차단, 나가는 규칙이 왜 중요한지, `pfirewall.log`와 Windows 필터링 플랫폼 이벤트(5156/5157) 읽는 법, 그리고 옆으로 이동을 막고 *보는* 데에서 호스트 방화벽이 네트워크 방화벽보다 나은 이유. 세 번째로 백신. 시그니처 vs 머신러닝, 메모리 공백, 공격자가 백신을 끄는 방법, Defender 탐지 이벤트(1116/1117) 읽는 법, 지루한 탐지 수백 개 속에서 진짜 흥미로운 하나를 찾는 법. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. <strong>가상화 기반 보안(VBS, Virtualization-Based Security)</strong>은 CPU의 가상화 기능과 Hyper-V 하이퍼바이저로 작고 분리된 "안전한 세계"를 만든다. 보통의 Windows 커널은 SYSTEM 권한이나 커널 권한이 있어도 그 안을 읽거나 바꿀 수 없다.
2. **Credential Guard**는 LSASS가 쥐고 있던 비밀(NTLM 해시, Kerberos 티켓과 키)을 그 안전한 세계의 `LsaIso.exe`라는 프로세스로 옮긴다. `lsass.exe`는 그대로 있지만 심부름꾼 역할만 한다. 이제 LSASS 메모리를 덤프하면 쓸 수 있는 해시 대신 암호화된 덩어리만 나온다. 그래서 **자격 증명 덤프(T1003.001)**, **패스 더 해시(T1550.002)**, <strong>패스 더 티켓(T1550.003)</strong>이 크게 무뎌진다.
3. Credential Guard가 **전부를 해결하지는 않는다.** 로컬 SAM 계정, 키 입력, 앱에 직접 입력하는 비밀번호, *새로* 로그온하는 사람의 비밀번호를 가로채는 악성 보안 패키지는 못 막는다. 그리고 켜져 있다고 짐작하지 말고 정말 돌고 있는지(`Win32_DeviceGuard`, `LsaIso.exe`) 확인한다.
4. **Application Guard**는 같은 격리를 위험한 행동에 적용했다. Edge의 믿을 수 없는 웹사이트, Office의 인터넷 문서를 쓰고 버리는 Hyper-V 컨테이너 안에서 열었다. 지금은 **지원 중단되고 최신 Windows 11에서 제거됐다.** 옛 환경을 이해하기 위해 알아 두되, 새로 설계할 때 기대면 안 된다.
5. **호스트 방화벽**은 익스플로잇, 옆으로 이동, C2, 유출 — 여러 단계에 동시에 작동한다. **프로필**(도메인/개인/공용), **들어오는 연결 기본 차단**, 그리고 정의할 수 있는 곳에서는 나가는 연결도 기본 차단.
6. 호스트 방화벽 로그는 **전술적으로 걸러 쓰면** 최고의 센서다. 공격자가 좋아하는 포트(SMB, RDP, WinRM, SSH)의 차단 기록만 모으고, 알려진 스캐너는 뺀다. 전부 다 기록하면 SIEM이 잠겨 버린다.
7. 네트워크 방화벽만 있을 때와 비교하면, 호스트 방화벽은 **같은 서브넷 안 두 PC 사이의 트래픽을 막고 기록한다.** 네트워크 방화벽은 그 트래픽을 아예 못 본다. "PC가 옆 PC에 SMB로 접속하려 했다"가 간단하면서도 가치 큰 경보가 된다.
8. **백신**은 주로 설치 단계를 막는다. 시그니처는 알려진 악성코드를, 머신러닝 엔진은 새 변종을 잡고, 메모리 검사(예: AMSI)가 파일 없는 공격의 빈틈을 메운다. 우회될 수는 있지만 흔한 악성코드 잡음을 없애 주고 — **처음 보는 희귀한 탐지 하나**가 진짜 사고의 시작인 경우가 많다.

## 가상화 기반 보안 — 비밀을 위한 별도의 방 { #vbs }

### Credential Guard가 푸는 문제 { #why-credential-guard }

[자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md)에서 공격자가 왜 `lsass.exe`를 좋아하는지 봤습니다. <strong>LSASS(Local Security Authority Subsystem Service, 로컬 보안 기관 하위 시스템 서비스)</strong>는 로그온을 처리하는 프로세스입니다. 한 번 로그인하면 다른 서버에 다시 비밀번호를 치지 않아도 되는 싱글 사인온(SSO)이 되려면, 누군가 비밀을 기억하고 있어야 하죠. 그게 LSASS입니다. 로그온한 사용자의 NT 해시, Kerberos 티켓(TGT)과 그 세션 키, 설정이 나쁜 시스템이면 평문 비밀번호까지 메모리에 들고 있습니다.

관리자 권한 — 정확히는 다른 프로세스의 메모리를 열 수 있는 권한(`SeDebugPrivilege`) — 이 있으면 누구나 그 메모리를 읽고 비밀을 들고 나갈 수 있습니다. 이게 **T1003.001 OS Credential Dumping: LSASS Memory**이고, 곧바로 옆으로 이동하는 **T1550.002 Pass the Hash**, **T1550.003 Pass the Ticket**으로 이어집니다.

전통적인 방어 — "사용자를 관리자로 두지 마라", "도메인 관리자 계정으로 일반 PC에 로그온하지 마라" — 는 좋은 방법입니다. 하지만 공격자가 SYSTEM을 얻는 순간 전부 무너집니다. 보통의 Windows에서 SYSTEM은 뭐든 읽을 수 있으니까요. 그래서 질문이 바뀝니다. **SYSTEM한테서도 비밀을 지킬 수 있을까?**

### 생각의 핵심: 건물 관리인도 못 여는 금고 { #vbs-idea }

은행을 떠올려 보세요. 그런데 이 은행은 금고가 본관 지하가 아니라, 옆에 따로 지은 봉인된 건물에 있습니다. 본관 창구 직원은 그 건물에 들어갈 수 없고, 작은 창구 구멍으로 요청서만 넣을 수 있습니다. "이 서명 맞는지 확인해 주세요", "이 수표에 도장 찍어 주세요". 그러면 답만 돌아옵니다. 강도가 지점장실과 모든 마스터키까지 포함해 본관 전체를 차지해도 금고에는 손이 안 닿습니다. 강도가 할 수 있는 건 구멍으로 요청서를 넣는 것뿐이고, 금고 직원은 정해진 질문에만 답합니다.

기술적으로 이 "따로 지은 건물"은 <strong>하이퍼바이저(hypervisor)</strong>가 만듭니다. VBS가 켜지면 Windows는 자기 아래에 Hyper-V를 먼저 띄우고, 컴퓨터를 두 개의 <strong>가상 신뢰 수준(VTL, Virtual Trust Level)</strong>으로 나눕니다.

- **VTL0 — 보통 세계.** 평소의 Windows 커널, 드라이버, `lsass.exe`, 모든 애플리케이션이 여기 있습니다. 공격자가 커널 권한을 얻어도 여기 안에 있습니다.
- **VTL1 — 안전한 세계.** 아주 작은 <strong>보안 커널(secure kernel)</strong>과 몇 개의 <strong>트러스트릿(trustlet)</strong>(격리된 사용자 모드 프로세스)만 있습니다. 하이퍼바이저는 CPU의 2단계 주소 변환(SLAT) 기능으로 VTL1의 메모리를 VTL0에서 접근 금지로 표시합니다. 보통 커널은 권한이 얼마나 높든 그 메모리 페이지를 들여다볼 수 없습니다.

**Credential Guard**를 켜면 비밀이 VTL1의 **`LsaIso.exe`**(LSA Isolated, 격리된 LSA)라는 트러스트릿으로 옮겨 갑니다. `lsass.exe`는 VTL0에서 그대로 돌고 로그온도 여전히 거기를 거칩니다. 하지만 자격 증명을 써야 할 때(예를 들어 NTLM 질문에 답하거나 Kerberos 서비스 티켓을 받을 때) `lsass.exe`는 좁고 정해진 통로로 `LsaIso.exe`에게 부탁합니다. `LsaIso.exe`가 암호 계산을 하고 *결과*만 돌려줍니다. 해시나 키 자체는 절대 내주지 않습니다. 그 좁은 통로가 비유 속 "창구 구멍"입니다.

### 그 뒤 공격자의 덤프는 어떻게 보이나 { #dump-with-cg }

효과를 이해하려고 공격 도구를 돌릴 필요는 없습니다. Credential Guard가 없는 PC에서 덤프 도구가 LSASS 메모리를 읽으면, 로그온한 사용자 항목에 읽을 수 있는 NT 해시가 나옵니다. Credential Guard가 켜져 있으면 같은 자리가 대략 이렇게 바뀝니다(줄이고 지어낸 값).

```
Authentication Id : 0 ; 4810233 (00000000:00496ff9)
User Name         : m.lee
Domain            : CORP
        msv :
         [00000003] Primary
         * Username : m.lee
         * Domain   : CORP
           * LSA Isolated Data: NtlmHash
             Unk-Key  : 4a1f...e90c
             Encrypted: 7b22c1...0d3f9a (long encrypted blob)
```

한 줄씩 보면:

- `Authentication Id`, `User Name`, `Domain` — 도구가 찾은 로그온 세션. 이건 여전히 보입니다. Credential Guard는 비밀을 숨기는 거지, 누가 로그온해 있다는 사실까지 숨기진 않습니다.
- `msv` — 그 세션에 대한 NTLM 인증 패키지의 데이터.
- `LSA Isolated Data: NtlmHash` — 도구는 해시가 *있다는 건* 알아보지만, 그게 격리된 형태로 보관돼 있습니다.
- `Encrypted: …` — VTL1 안에만 있는 키로 암호화된 덩어리. 그 키 없이는 패스 더 해시에 쓸 수 없습니다.

Kerberos 티켓도 똑같이 다뤄집니다. TGT 세션 키가 `LsaIso.exe` 안에 머물러서, 훔친 티켓 데이터를 다른 곳에서 그냥 다시 쓸 수 없습니다.

### 필요 조건과 정말 켜졌는지 확인하기 { #cg-requirements }

Credential Guard는 하드웨어와 펌웨어가 받쳐 줘야 합니다.

- 64비트 Windows, **UEFI** 펌웨어(옛 BIOS 방식 아님), **보안 부팅(Secure Boot)**.
- CPU 가상화 기능(**Intel VT-x** 또는 **AMD-V**)과 **SLAT**(Intel EPT / AMD RVI).
- **TPM**(1.2 또는 2.0)을 강하게 권장합니다. Credential Guard 설정을 지키는 키를 하드웨어에 묶어 두기 위해서입니다.
- 에디션: Windows 10/11 **Enterprise 또는 Education**, Windows Server 2016 이상. 도메인 컨트롤러에서는 지원되지 않습니다(DC는 자격 증명을 AD 데이터베이스에 저장하는데, Credential Guard는 그걸 지키지 않습니다).

켜는 방법은 그룹 정책(*컴퓨터 구성 → 관리 템플릿 → 시스템 → Device Guard → 가상화 기반 보안 켜기*의 Credential Guard 옵션), Intune, 또는 레지스트리입니다. 그런데 "정책을 걸었다"와 "돌고 있다"는 다른 말입니다. 펌웨어 설정, 가상화 미지원, 드라이버 호환성 문제 때문에 조용히 안 켜질 수 있습니다. 확인해 봅시다.

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
```

```
VirtualizationBasedSecurityStatus SecurityServicesConfigured SecurityServicesRunning
--------------------------------- -------------------------- -----------------------
                                2 {1, 2}                     {1, 2}
```

- `Get-CimInstance … Win32_DeviceGuard` — Windows가 관리하는 Device Guard / VBS 상태 정보를 읽습니다. `Select-Object`로 필요한 칸 세 개만 남깁니다.
- `VirtualizationBasedSecurityStatus 2` — VBS가 켜져 있고 **실제로 돌고 있음**(`1` = 켜졌지만 안 돎, `0` = 안 켜짐).
- `SecurityServicesConfigured {1, 2}` — 정책이 요구한 것. `1` = Credential Guard, `2` = 메모리 무결성(HVCI, 하이퍼바이저로 보호되는 코드 무결성).
- `SecurityServicesRunning {1, 2}` — 실제로 돌고 있는 것. *Configured*에는 `1`이 있는데 *Running*에 없으면, 정책은 걸렸지만 Credential Guard는 아무것도 지키고 있지 않은 겁니다. 보고해야 할 건 바로 그 차이입니다.

빠른 확인 두 가지 더:

```
C:\> tasklist /fi "imagename eq lsaiso.exe"

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
LsaIso.exe                     812 Services                   0      1,820 K
```

- `tasklist /fi "imagename eq lsaiso.exe"` — 실행 중인 프로세스 중에서 이름이 `lsaiso.exe`인 것만 거릅니다(`/fi` = 필터). `LsaIso.exe`가 보이면 격리된 LSA 트러스트릿이 시작된 겁니다. 이 프로세스가 없으면 Credential Guard도 없습니다.

**System** 이벤트 로그의 출처 `Microsoft-Windows-Wininit`, **이벤트 13**은 Credential Guard(`LsaIso.exe`)가 시작됐고 LSA 자격 증명을 보호한다는 뜻입니다. 시작에 실패했다거나 설정을 못 읽었다는 이벤트가 있으면 설정 문제입니다. 이 이벤트를 전체 PC에서 모으면 "정말로 보호되는 PC는 어디인가?" 보고서를 거의 공짜로 얻습니다. PC 한 대라면 `msinfo32`(시스템 요약 → *실행 중인 가상화 기반 보안 서비스*)에서도 같은 걸 볼 수 있습니다.

### Credential Guard가 못 지키는 것 { #cg-limits }

사람들이 Credential Guard를 과대평가하는 부분입니다. Credential Guard가 지키는 건 **LSA가 도메인 계정을 위해 들고 있는 비밀**입니다. 아래는 못 지킵니다.

- **SAM에 있는 로컬 계정.** 로컬 계정의 비밀번호 해시는 레지스트리와 디스크에 저장돼 있고, LSA의 격리 저장소 밖입니다. 관리자 권한으로 덤프하는 것(**T1003.002 Security Account Manager**)은 여전히 됩니다. 그래서 PC마다 다른 로컬 관리자 비밀번호(LAPS)가 여전히 중요합니다.
- **키 입력과 화면.** 키로거(**T1056.001**)는 비밀번호를 치는 순간 봅니다.
- **악성 보안 패키지가 잡는 새 로그온.** 관리자 권한이 있는 공격자는 가짜 <strong>보안 지원 공급자(SSP, Security Support Provider)</strong>를 등록할 수 있습니다(**T1547.005**). 그러면 그게 설치된 *뒤에* 로그온하는 사용자의 평문 비밀번호를 받습니다. Credential Guard는 저장된 것을 지키지, 앞으로 입력될 것까지 지키지는 않습니다.
- **다른 앱에 입력하는 비밀번호**, 브라우저에 저장된 비밀번호, 다른 프로토콜용으로 캐시된 자격 증명, 파일·스크립트에 적혀 있는 자격 증명.
- **계정 그 자체.** 공격자가 그 세션을 쓸 수 있다면(로그온한 사용자로 명령을 돌릴 수 있다면) 해시가 필요 없습니다. 그 PC에 있는 동안 그 사용자로 행동하면 되니까요.

그리고 배포하기 전에 알아야 할 부작용이 있습니다. 보호된 자격 증명으로는 NTLMv1, MS-CHAPv2, Digest 싱글 사인온, Kerberos 제약 없는 위임(unconstrained delegation), DES 암호화가 막힙니다. 현장에서 가장 흔한 불만은 저장된 자격 증명으로 PEAP-MSCHAPv2를 쓰는 Wi-Fi나 VPN이 깨지는 겁니다.

<strong>[보충] Credential Guard와 LSA 보호는 다르다.</strong> 이 둘은 늘 헷갈립니다.

| | LSA 보호(`RunAsPPL`) | Credential Guard |
| --- | --- | --- |
| 하는 일 | `lsass.exe`를 *보호된 프로세스(PPL, Protected Process Light)*로 돌림. 보호되지 않은 프로세스는 메모리를 읽으려고 열거나 코드를 주입할 수 없음 | 비밀 자체를 `lsass.exe` 밖, VTL1로 옮김 |
| 막는 것 | 관리자 권한이라도 사용자 모드 도구가 LSASS를 여는 것 | 커널 수준 공격자까지. VTL0 커널은 VTL1을 못 읽기 때문 |
| 약점 | 커널 드라이버(흔히 취약한 *서명된* 드라이버)를 올린 공격자는 보호를 벗길 수 있음 | 로컬 SAM 계정, 키로거, 가짜 SSP 등 위에서 말한 한계 |
| 필요한 것 | 특별한 하드웨어 필요 없음 | VBS 하드웨어, Enterprise/Education |

둘 다 씁니다. LSA 보호는 막은 시도를 기록하고(`Microsoft-Windows-CodeIntegrity/Operational` 로그, 예를 들어 LSASS에 올라가려다 실패한 드라이버나 DLL), [앞 페이지](inventory-vulns-patching.md#emet-exploit-guard)의 ASR 규칙 *Block credential stealing from the Windows local security authority subsystem*이 세 번째 겹을 더하면서 Defender 이벤트도 남깁니다.

**SOC가 챙길 것:** Credential Guard가 도는 PC에서도 LSASS 접근 경보는 조사할 가치가 있습니다. 공격자가 *시도했다*는 뜻이니까요. 다만 피해 범위가 작아집니다. 거꾸로, 침해 범위를 정할 때 "공격자가 관리자 권한을 가졌던 PC에서 Credential Guard가 돌고 있었나?"가 어떤 계정을 털린 것으로 봐야 하는지를 바꿉니다.

## Application Guard — 위험한 웹 서핑과 문서를 가둬 두기 { #application-guard }

Credential Guard는 *비밀*을 가둡니다. <strong>Microsoft Defender Application Guard(MDAG)</strong>는 같은 하드웨어 격리를 *위험한 행동*에 적용했습니다. 생각은 이렇습니다. 모르는 웹사이트나 인터넷에서 온 문서를 전부 막을 수는 없지만, 쓰고 나면 통째로 버리는 일회용 방에서 열게 할 수는 있다.

- **Edge용 Application Guard.** 엔터프라이즈 모드에서는 조직이 믿을 수 있는 사이트(사내망, 잘 아는 클라우드 서비스) 목록을 정합니다. 사용자가 그 밖의 사이트로 가면 Edge가 그 사이트를 격리된 **Hyper-V 컨테이너** — 자기 커널을 가진 가벼운 가상 머신 — 안에서 엽니다. 브라우저 익스플로잇이 성공해도 진짜 노트북이 아니라 컨테이너 안에 떨어지고, 세션이 끝나면 컨테이너는 버려집니다. Pro 에디션용 단독 모드도 있었고, 확장 프로그램으로 Chrome과 Firefox에도 같은 격리를 붙일 수 있었습니다.
- **Office용 Application Guard.** Enterprise 라이선스에서 Word, Excel, PowerPoint가 믿을 수 없는 파일 — 인터넷에서 내려받은 파일, 임시 폴더 같은 위험한 위치의 파일, **파일 차단(File Block)** 대상 파일 — 을 컨테이너 안에서 열었습니다.
- <strong>파일 차단(File Block)</strong>은 별개의 Office 기능이고, 지금도 알아 둘 만합니다. 관리자가 오래되거나 잘 안 쓰는 파일 형식(예: 오래전 은퇴한 Office 버전의 옛 바이너리 형식)을 아예 못 열게 하거나, 보호된 보기(Protected View)로만 열리게 할 수 있습니다. 옛 형식은 오래되고 덜 단단한 코드가 해석하기 때문에 공격자가 좋아합니다.

<strong>[변경됨] Application Guard는 은퇴했다.</strong> Microsoft는 Edge용 Application Guard(Chrome/Firefox 확장 포함)를 지원 중단했고, Windows 11 24H2부터는 쓸 수 없습니다. Office용 Application Guard도 지원 중단됐습니다. Microsoft는 이제 다른 통제를 권합니다. Edge 자체 보안 기능과 SmartScreen, Office **보호된 보기**와 인터넷 매크로 차단, Microsoft Defender for Office 365의 안전한 첨부 파일(Safe Attachments)·안전한 링크(Safe Links), 거기에 ASR 규칙과 애플리케이션 제어. 옛 환경에서 MDAG를 보면 곧 사라질 통제로 보고, 믿을 수 없는 문서와 웹 서핑을 다른 무언가가 확실히 덮고 있는지 확인하세요. 다만 *생각* 자체 — 위험한 콘텐츠는 일회용 격리 환경에서 연다 — 는 원격 브라우저 격리(RBI) 제품과 샌드박스 기능 속에 살아 있습니다.

## 호스트 방화벽 — 모든 PC를 문이자 센서로 { #host-firewalls }

### 무엇이고, 왜 생각보다 많은 일을 하나 { #host-firewall-role }

<strong>호스트 방화벽(host firewall)</strong>은 엔드포인트 자기 자신 위에서 도는 패킷 필터입니다. Windows 방화벽(그 아래에 Windows 필터링 플랫폼, WFP), Linux의 `nftables`/`iptables`와 그 앞단인 `ufw`·`firewalld`, macOS의 애플리케이션 방화벽 같은 것들이죠. 보통 "익스플로잇 방지" 칸에 들어갑니다. 포트를 막으면 취약한 서비스에 닿을 수 없으니까요. 하지만 잘 설정한 호스트 방화벽은 공격 단계 네 곳에 손을 댑니다.

- **익스플로잇** — 닿으면 안 되는 서비스로 들어오는 연결을 버립니다.
- **옆으로 이동** — 감염된 이웃 PC에서 SMB, RDP, WinRM, SSH로 들어오는 연결을 버립니다([SMB](../other-protocols/smb.md), [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md), [PowerShell 원격](../other-protocols/psremoting-ftp-icmp.md)).
- **명령·제어(C2)** — 예상 밖의 포트로, 또는 예상 밖의 프로그램이 나가는 연결을 막습니다.
- **유출** — 그 PC가 쓸 일이 없는 프로토콜(재무팀 노트북의 SSH, FTP)로 나가는 걸 막습니다.

그리고 이 차단 하나하나를 기록할 수 있습니다. 사람들이 잊는 게 이 부분입니다. 호스트 방화벽은 *모든* 엔드포인트를 네트워크 센서로 바꿉니다. 네트워크 방화벽을 아예 지나가지 않는 트래픽까지 포함해서요.

### 프로필, 기본 차단, 나가는 규칙 { #profiles }

Windows는 지금 어떤 네트워크에 있다고 생각하는지에 따라 세 가지 <strong>프로필(profile)</strong> 중 하나를 씁니다.

- **도메인(Domain)** — 자기 도메인의 도메인 컨트롤러에 닿을 수 있음(회사망이나 VPN에 있음). 보통 원격 관리 포트가 열려 있는 유일한 프로필이고, 그것도 *관리 서버에서 오는 것만* 허용해야 합니다.
- **개인(Private)** — 사용자가 믿을 수 있다고 표시한 네트워크(집).
- **공용(Public)** — 그 밖의 전부. 카페, 호텔, 공항. 들어오는 연결은 완전히 닫혀 있어야 합니다.

기본 원칙은 네트워크 방화벽과 같습니다. **들어오는 연결 기본 차단(default-deny inbound)** — 필요한 것만, 필요한 출발지에서만 허용 — 그리고 정의할 수 있는 곳이라면 허용 목록을 둔 **나가는 연결 기본 차단(default-deny outbound)**. 나가는 연결 차단은 손이 많이 가서(어떤 프로그램이 어디와 통신해야 하는지 알아야 하니까) 덜 흔하지만, C2를 막는 가장 강력한 통제 중 하나입니다.

현재 설정 읽기:

```powershell
Get-NetFirewallProfile |
  Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogAllowed, LogFileName
```

```
Name    Enabled DefaultInboundAction DefaultOutboundAction LogBlocked LogAllowed LogFileName
----    ------- -------------------- --------------------- ---------- ---------- -----------
Domain     True                Block                 Allow       True      False %systemroot%\system32\LogFiles\Firewall\pfirewall.log
Private    True                Block                 Allow      False      False %systemroot%\system32\LogFiles\Firewall\pfirewall.log
Public     True                Block                 Allow      False      False %systemroot%\system32\LogFiles\Firewall\pfirewall.log
```

- `Get-NetFirewallProfile`은 세 프로필을 보여 주고, `Select-Object`로 쓸모 있는 칸만 남깁니다.
- `Enabled True` — 모든 프로필에서 방화벽이 켜져 있습니다. 어느 하나라도 `False`면 발견 사항입니다.
- `DefaultInboundAction Block` — 좋습니다. 들어오는 연결은 기본 차단. `DefaultOutboundAction Allow` — 흔한 기본값으로, 규칙이 막지 않는 한 나가는 연결은 열려 있습니다.
- `LogBlocked True`는 *Domain*에만 있음 — 버려진 패킷이 회사망에서는 기록되지만, 노트북이 집이나 호텔에 있을 때는 안 됩니다. 노트북이 가장 위험한 곳이 바로 회사 밖이니, Private과 Public에도 `LogBlocked`를 켜면 밖에 있을 때도 보입니다.
- `LogAllowed False` — 허용된 연결은 기록 안 함. 텍스트 로그에서는 보통 이게 맞습니다. 허용된 패킷까지 다 기록하는 게 아래에서 경고할 홍수입니다.
- `LogFileName` — 기본 텍스트 로그 위치.

### Windows 방화벽 텍스트 로그 읽기 { #pfirewall-log }

```
#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path

2026-11-19 10:14:03 DROP TCP 10.30.5.41 10.30.5.42 51544 445 52 S 3871632402 0 64240 - - - RECEIVE
2026-11-19 10:14:03 DROP TCP 10.30.5.41 10.30.5.42 51545 135 52 S 1209847712 0 64240 - - - RECEIVE
2026-11-19 10:14:04 DROP TCP 10.30.5.41 10.30.5.42 51546 5985 52 S 2650012931 0 64240 - - - RECEIVE
```

먼저 머리말:

- `#Version`, `#Software` — 로그 형식 버전과 만든 프로그램.
- `#Time Format: Local` — 시각이 UTC가 아니라 **그 PC의 현지 시각**입니다. SIEM 데이터와 맞춰 볼 때 꼭 기억하세요.
- `#Fields:` — 칸 이름을 순서대로. 아래 한 줄이 패킷 하나에 대한 결정입니다.

이제 첫 데이터 줄을 칸별로:

- `2026-11-19 10:14:03` — 날짜와 현지 시각.
- `DROP` — 동작(`ALLOW` 또는 `DROP`).
- `TCP` — 프로토콜.
- `10.30.5.41` → `10.30.5.42` — 출발지와 목적지 IP. 이 로그는 `.42`에 있으니, `.41`이 *이 PC로* 들어오려 한 겁니다.
- `51544` → `445` — 출발지 포트(아무렇게나 고른 높은 번호)와 목적지 포트. 445는 SMB입니다.
- `52` — 패킷 크기(바이트).
- `S` — TCP 플래그. SYN만 있음, 즉 새 연결 시도의 첫 패킷입니다.
- `3871632402` / `0` / `64240` — TCP 순서 번호, 확인 번호, 윈도 크기. 분류 단계에서는 거의 안 봅니다.
- `- - -` — ICMP 유형, ICMP 코드, 정보 칸. TCP라서 비어 있습니다.
- `RECEIVE` — 방향. 들어온 패킷입니다(`SEND`면 나가는 것).

세 줄을 같이 읽으면 이야기가 나옵니다. 2초 안에 `10.30.5.41`이 옆 PC의 SMB(445), RPC 엔드포인트 매퍼(135), WinRM(5985)을 차례로 두드렸습니다. 원격 실행의 세 가지 고전적인 길입니다(SMB를 통한 PsExec식 서비스 생성, RPC를 통한 WMI/DCOM, WinRM을 통한 PowerShell 원격). `.41`이 평범한 업무용 PC라면, 그 PC에 있는 누군가가 옆으로 이동하려는 겁니다. ATT&CK **T1021.002 SMB/Windows Admin Shares**, **T1047 WMI**, **T1021.006 Windows Remote Management**. 그리고 시도는 전부 실패했고, 기록이 남았습니다.

텍스트 로그에는 한계가 있습니다. 기본 크기(4MB)가 작아서 금방 덮어쓰고, 어떤 프로세스인지 정보가 없습니다. SIEM으로 모을 때는 보통 **보안(Security) 이벤트 로그** 쪽이 낫습니다.

### Windows 필터링 플랫폼 이벤트 { #wfp-events }

감사 하위 범주 *필터링 플랫폼 연결(Filtering Platform Connection)*을 켜면 Windows가 연결 결정을 보안 로그에 남깁니다.

- **5157** — Windows 필터링 플랫폼이 연결을 **막음**.
- **5156** — WFP가 연결을 **허용함**. 양이 엄청나서 대부분 조직은 모든 PC에서 모으지 않습니다.
- **5152 / 5153** — 패킷이 버려짐/막힘(패킷 단위, *Filtering Platform Packet Drop* 하위 범주).

```
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
```

- `auditpol /set`은 감사 정책을 바꿉니다. `/subcategory:"Filtering Platform Connection"`은 연결 단위 감사를 고르고, `/failure:enable`은 **실패** — 막힌 연결(5157) — 만 기록하고 성공(5156)의 홍수는 기록하지 않게 합니다. 도메인에서는 그룹 정책의 *고급 감사 정책 구성*으로 같은 걸 겁니다.

위 첫 시도에 대해 `.42`에 남은 5157 이벤트(EventData 부분만, 지어낸 값):

```xml
<EventData>
  <Data Name="ProcessID">4</Data>
  <Data Name="Application">System</Data>
  <Data Name="Direction">%%14592</Data>
  <Data Name="SourceAddress">10.30.5.42</Data>
  <Data Name="SourcePort">445</Data>
  <Data Name="DestAddress">10.30.5.41</Data>
  <Data Name="DestPort">51544</Data>
  <Data Name="Protocol">6</Data>
  <Data Name="FilterRTID">0</Data>
  <Data Name="LayerName">%%14610</Data>
  <Data Name="LayerRTID">44</Data>
</EventData>
```

- `ProcessID 4` / `Application System` — 그 포트를 가진 로컬 프로세스. PID 4는 커널의 `System` 프로세스이고, 445의 SMB를 담당합니다. 나가는 연결 차단에서는 이 칸이 보물입니다. 접속하려던 프로그램 이름(`\device\harddiskvolume3\users\public\rdr.exe` 같은)이 나오니까요.
- `Direction %%14592` — <strong>들어옴(Inbound)</strong>을 뜻하는 메시지 코드입니다(`%%14593` = 나감). 이벤트 뷰어는 글자로 보여 주지만 SIEM의 원본 XML에는 코드가 남으니, 파서가 번역해 줘야 합니다.
- `SourceAddress / SourcePort`와 `DestAddress / DestPort` — 조심하세요. **들어오는** 이벤트에서 WFP는 *로컬* 쪽을 "Source"에, *원격* 쪽을 "Dest"에 넣습니다. 그러니 여기서는 로컬 PC `10.30.5.42:445`가 과녁이었고, 원격 `10.30.5.41`이 연결을 시작한 쪽입니다. 이걸 거꾸로 읽는 건 분석가의 고전적인 실수입니다.
- `Protocol 6` — IP 프로토콜 번호. 6 = TCP, 17 = UDP, 1 = ICMP.
- `LayerName %%14610` — 결정이 내려진 WFP 계층(여기서는 들어오는 연결을 받는 계층). `FilterRTID`는 결정한 필터를 가리키고, `0`은 보통 특정 규칙이 아니라 기본 차단이라는 뜻입니다.

<strong>[보충] 방화벽 자체를 지켜본다.</strong> 공격자는 방화벽을 끄거나 허용 규칙을 더하는 일이 잦습니다(**T1562.004 Impair Defenses: Disable or Modify System Firewall**). 예를 들어 `netsh advfirewall set allprofiles state off`나, 자기 도구용 새 인바운드 규칙. Windows는 이걸 기록합니다. *MPSSVC 규칙 수준 정책 변경* 감사가 켜져 있으면 보안 이벤트 **4946**(규칙 추가), **4947**(규칙 수정), **4948**(규칙 삭제), **4950**(방화벽 설정 변경)이 남고, `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` 로그에는 규칙 추가·변경·삭제(예: 2004, 2005, 2006)와 프로필 설정 변경이, 어떤 애플리케이션이 했는지까지 남습니다. 변경 작업 시간이 아닌데 업무용 PC에서 방화벽이 꺼졌다면 경보감입니다.

### 어디서나가 아니라 전술적으로 { #tactical-logging }

호스트 방화벽은 양이 엄청날 수 있어서, "모든 PC에서 전부 기록"은 SIEM 라이선스는 꽉 차고 아무도 안 보는 걸로 끝납니다. 실무에서는 이렇게 합니다.

1. 중앙으로 보내는 건 최소한 **허용 말고 차단만** 기록합니다.
2. 익스플로잇과 옆으로 이동에 **공격자가 쓰는 포트**에 집중합니다. 445(SMB), 135와 RPC 대역, 3389(RDP), 5985/5986(WinRM), 22(SSH), 웹을 서비스하면 안 되는 PC의 80/443.
3. **알려진 정상 잡음은 뺍니다.** 취약점 스캐너, 관리 서버, 모니터링 시스템. 매주 일요일 `10.10.1.50`의 스캐너가 모든 걸 건드리는 게 정상이라면 걸러 내세요. 안 그러면 스캔이 있을 때마다 진짜 시도가 파묻힙니다.
4. 남은 것에 **짧고 날카로운 경보**를 겁니다(다음 절).

잡음을 걷어 내면 보상이 큽니다. 공격자가 감염된 PC에서 주변을 살피며 하는 거의 모든 행동이 어딘가의 닫힌 포트에 부딪히고 흔적을 남깁니다.

## 호스트 방화벽 vs 네트워크 방화벽 { #host-vs-network }

네트워크 방화벽 뒤에 업무용 PC 서브넷 `10.30.5.0/24`가 있다고 해 봅시다. 공격자가 `PC-1`(`10.30.5.41`)을 장악했고, 바로 옆 `PC-2`(`10.30.5.42`)를 노립니다.

| | 네트워크 방화벽만 | 네트워크 + 호스트 방화벽 |
| --- | --- | --- |
| PC-1에서 PC-2 익스플로잇 | 못 막음 — 트래픽이 네트워크 방화벽을 지나가지 않음 | PC-2에서 막히고 기록됨 |
| PC-1 → PC-2 옆으로 이동 | 못 막고, SOC에 **안 보임** | 막힘. "PC-1이 PC-2에 SMB 시도"가 SIEM에 남음 |
| PC-1의 C2 / 유출 | 네트워크 경계에서만 보임(어쩌면 막힘) | PC-1 자신에서도 막히고, 프로세스 이름과 함께 기록됨 |

왼쪽 칸이 왜 그렇게 나쁠까요? 같은 서브넷 안 두 PC 사이의 트래픽은 방화벽이 아니라 근처 스위치를 거쳐 갑니다. 네트워크 방화벽, 프록시, 대부분의 네트워크 센서가 그걸 못 봅니다. 공격자는 이웃 PC를 하나하나, 몇 번이고, 조용히 시도할 수 있습니다. 아파트 단지 정문에 경비원이 있어도, 같은 층 이웃집 문을 두드리는 사람은 경비원 눈에 안 보이는 것과 같습니다.

오른쪽처럼 호스트 방화벽이 있으면 두 가지가 바뀝니다. 첫째, 업무용 PC는 다른 업무용 PC에서 오는 SMB/RDP/WinRM을 아예 받지 않습니다. 실제로 관리하는 관리 서버에서 오는 것만 받습니다. 둘째, 모든 시도가 로그 한 줄이 됩니다. 업무용 PC끼리는 보통 이 포트로 서로 통신할 **이유가 없으니**, 탐지 논리가 짧아집니다.

> 업무용 PC 대역의 호스트가, 업무용 PC 대역의 다른 호스트의 TCP 445, 135, 3389, 5985/5986으로 연결을 시도해서 막히면(또는 연결이 생기면) 경보. 관리 서버와 스캐너는 제외.

이 규칙 하나로 서브넷 안에서 조용히 옆으로 이동하기가 아주 어려워집니다.

나가는 규칙은 사슬의 반대쪽 끝을 돕습니다.

- **흔치 않은 포트의 C2.** 업무용 PC가 갑자기 TCP 4444(잘 알려진 몇몇 공격 프레임워크의 기본값) 같은, 한 번도 안 쓰던 포트로 나가려 하면 의심스럽습니다. 나가는 연결을 막아 두면 공격자는 우리가 허용한 몇 안 되는 포트(보통 프록시를 거치는 80/443)로 몰리고, 거기서는 웹 프록시와 TLS 검사가 볼 수 있습니다. ATT&CK **T1571 Non-Standard Port**.
- **유출.** 사용자 PC에서 밖으로 나가는 SSH, FTP 같은 프로토콜을 막으면 손쉬운 유출 통로가 닫히고(**T1048 Exfiltration Over Alternative Protocol**), 기록된 시도가 누군가 해 봤다는 걸 알려 줍니다.

<strong>[보충]</strong> 같은 생각을 크게 키운 게 <strong>마이크로 세그멘테이션(micro-segmentation)</strong>입니다. EDR, 방화벽 정책 관리 도구, 제로 트러스트 제품이 내려 주는 신원·태그 기반 규칙으로 어떤 *역할*이 어떤 역할과 통신할 수 있는지 정합니다. 호스트 방화벽은 그걸 시작하는 가장 싸고, 이미 내장된 방법입니다.

## 백신 — 설치 단계 막기 { #antivirus }

### 하는 일과 약한 곳 { #av-role }

<strong>백신(AV, antivirus)</strong>은 가장 오래된 보안 도구 중 하나입니다. 주된 일은 **설치** 단계입니다. 파일이 실행되기 전이나 실행되는 순간 살펴보고, 악성이면 멈춥니다. 문 앞에 "수배 전단" 뭉치를 든 경비원을 떠올리면 됩니다. 전단에 있는 사람은 아주 잘 막지만, 새로 변장한 사람은 훨씬 덜 잘 막습니다.

<strong>시그니처 기반(signature-based)</strong> 탐지가 그 전단 뭉치입니다. 알려진 악성코드 샘플에서 뽑은 바이트 패턴, 문자열, 해시. *알려진* 나쁜 파일은 확실히 없애 줍니다. 대신 이런 데 약합니다.

- **알려지지 않은 악성코드** — 아직 아무도 전단을 안 만들었습니다.
- **난독화·패킹된 파일**(**T1027 Obfuscated Files or Information**) — 같은 악성코드를 포장해서 바이트가 달라 보이게 한 것.
- **다형성(polymorphic) 악성코드** — 감염할 때마다 자기를 바꿔서, 복사본마다 해시도 바이트도 다릅니다.
- **메모리에만 있는(파일 없는, fileless) 악성코드** — 스크립트가 코드를 RAM으로 바로 내려받아 실행하고 파일을 한 번도 쓰지 않습니다(**T1620 Reflective Code Loading**, PowerShell 다운로드 크래들). 디스크의 파일만 검사하는 엔진은 영영 못 봅니다.

이걸 이기려고 제품들은 <strong>시그니처 없는 머신러닝(signatureless, machine learning)</strong> 탐지로 옮겨 갔습니다. 정상·악성 샘플을 엄청나게 많이 학습한 모델이 악성 프로그램의 *특징*(구조, 가져다 쓰는 함수, 엔트로피, 행동)을 배워서, 한 번도 본 적 없는 파일에도 점수를 매깁니다. 요즘 엔진은 대부분 섞어 씁니다. 빠르고 확실한 시그니처, 새로운 것에는 머신러닝과 클라우드 조회, 그리고 프로그램이 시작된 뒤 무엇을 하는지 지켜보는 **행동 감시(behaviour monitoring)**.

<strong>[보충] Windows에서 파일 없는 공격의 빈틈을 메우는 AMSI.</strong> <strong>AMSI(Antimalware Scan Interface, 악성코드 검사 인터페이스)</strong>는 스크립트를 실행하는 프로그램들 — PowerShell, Windows Script Host(VBScript/JScript), Office VBA 매크로, .NET — 이 곧 실행할 내용을 *난독화가 풀린 상태로* 백신 엔진에 넘기게 해 줍니다. 그래서 Defender는 디스크에 한 번도 안 쓰인 스크립트도, 인코딩 껍질을 다 벗긴 뒤에 잡을 수 있습니다. 공격자도 이걸 알아서 메모리 안의 AMSI를 끄거나 고치려 하는데, 그 시도 자체가 EDR과 Defender에 탐지됩니다.

그럼 백신은 여전히 쓸 가치가 있을까요? 있습니다. 실력 있는 표적 공격자는 자주 백신을 지나가겠지만, 백신은 흔한 악성코드를 대량으로 자동 제거해서 SOC가 중요한 일에 시간을 쓰게 해 줍니다. 그리고 백신 로그는 귀한 센서입니다.

### 공격자가 백신을 끌 때 { #av-tamper }

백신은 방해가 되니까 공격자는 자주 끄려 합니다. **T1562.001 Impair Defenses: Disable or Modify Tools** — 서비스를 멈추거나, 자기 폴더를 예외로 넣거나, 실시간 보호를 끕니다. Defender 운영 로그(`Microsoft-Windows-Windows Defender/Operational`)에 이런 게 남습니다.

- **5001** — 실시간 보호가 **꺼짐**.
- **5007** — Defender **설정 변경**(새로 생긴 예외 경로를 찾으세요. 예: `Exclusions\Paths\C:\Users\Public`).
- **5013** — 변조 방지(Tamper Protection)가 Defender 설정 변경을 **막음**.
- **1116 / 1117** — 악성코드 탐지 / 조치 실행(아래).

새벽 2시에 스크립트가 `C:\Users\Public`이나 `C:\ProgramData\<아무 이름>`을 예외로 넣었다면, 사람이 직접 키보드를 잡고 있다는 가장 확실한 신호 중 하나입니다. 자세한 건 [방어 무력화와 로그 삭제](../../../adversary/impair-defenses-log-clearing.md)에 있습니다.

### 탐지 이벤트 읽기 { #av-detection-event }

```
Log Name:  Microsoft-Windows-Windows Defender/Operational
Event ID:  1116
Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
 Name: Trojan:Win32/Generic!ml
 ID: 2147xxxxxx
 Severity: Severe
 Category: Trojan
 Path: file:_C:\Users\j.park\AppData\Roaming\Microsoft\Teams\upd\teamsupd.exe
 Detection Origin: Local machine
 Detection Type: Concrete
 Detection Source: Real-Time Protection
 User: CORP\j.park
 Process Name: C:\Windows\System32\rundll32.exe
 Security intelligence Version: 1.4xx.xxx.0
```

칸별로 보면:

- `Event ID 1116` — Defender가 무언가를 **탐지함**. 뒤따르는 **1117**은 어떤 *조치*를 했는지(격리, 삭제, 차단) 알려 주고, **1118/1119**는 조치가 실패했다는 뜻입니다. 1116만 있고 1117이 없거나, 1118이 있으면 파일이 아직 남아 있을 수 있습니다.
- `Name: Trojan:Win32/Generic!ml` — 탐지 이름. 종류(`Trojan`), 플랫폼(`Win32`), 계열(`Generic`), 꼬리표. `!ml`은 특정 시그니처가 아니라 **머신러닝** 모델이 잡았다는 뜻입니다. "Generic"은 시시해 보이지만 실제로는 "어떤 계열인지 모르겠다"는 뜻입니다. 새롭거나 표적형인 무언가라면 딱 이렇게 나옵니다.
- `Severity: Severe`, `Category: Trojan` — 제조사 분류. 정렬할 때는 쓸모 있지만, 중요도를 정하는 기준은 아닙니다.
- `Path` — 파일 위치. `AppData\Roaming\Microsoft\Teams\upd\teamsupd.exe`는 애플리케이션 폴더를 흉내 내지만, 진짜 협업 앱은 거기에 업데이트 프로그램을 두지 않습니다. 정상처럼 보이는 경로로 위장하기(**T1036.005 Match Legitimate Name or Location**)는 고전입니다.
- `Detection Source: Real-Time Protection` — 파일에 접근하거나 실행할 때 잡혔습니다(다른 출처: 예약 검사, AMSI, 행동 감시, 다운로드·첨부 파일).
- `Process Name: rundll32.exe` — 그 파일을 건드린 프로세스. 시스템 프로그램이 AppData의 모르는 실행 파일을 띄우려 했다는 건, 무언가가 *이미 돌고 있다가* 이 두 번째 단계를 시작하려 했다는 뜻입니다. 그러니 질문은 "이 파일 지워졌나?"만이 아니라 "누가 이걸 띄웠나?"입니다.
- `Security intelligence Version` — 시그니처/모델 버전. 이미 있던 파일이 업데이트 직후에 잡혔을 때 쓸모 있습니다.

### 진짜 흥미로운 바늘 찾기 { #av-outliers }

큰 조직의 백신 탐지는 대부분 지루합니다. 무료 프로그램에 끼어 온 광고 프로그램, 메일 첨부 파일 속 흔한 트로이 목마(누가 열기 전에 격리됨), 원치 않는 툴바. 요령은 <strong>튀는 것(outlier)</strong>을 찾는 겁니다. 일주일 치 탐지를 요약하면:

```
Count  Detection name                    Path pattern                               Hosts
  214  PUA:Win32/Bundler.Toolbar         C:\Users\*\Downloads\*setup*.exe             97
   61  Trojan:Script/Phish.Html          Outlook temp (attachments)                   58
    9  HackTool:Win32/Keygen             C:\Users\*\Downloads\*crack*                  7
    1  Trojan:Win32/Generic!ml          C:\Users\j.park\AppData\Roaming\...\upd\      1
```

- 위 세 줄은 양이 많고, 여러 PC에 퍼져 있고, 전형적인 "사용자가 뭘 잘못 받았네" 위치입니다. 치우고, 교육하고, 튜닝합니다.
- 마지막 줄을 가장 먼저 조사합니다. **탐지 단 하나**, 우리 환경에서 처음 보는 이름, 다른 탐지가 한 번도 안 나온 **위치**, 그리고 `rundll32.exe`가 띄움. 이런 일회성 탐지는 더 깊은 침입이 겉으로 드러난 끝부분인 경우가 많습니다. 공격자 도구 중 하나가 우연히 잡혔고, 나머지는 안 잡혔다는 거죠.

탐지에 순위를 매기는 방법:

- **이름의 희귀성** — 이 탐지 이름이 우리 환경에 처음 나왔나.
- **경로의 희귀성** — 이 폴더에서 무언가 탐지된 게 처음인가, 정상 프로그램 경로를 흉내 냈나.
- **파일의 보급도와 평판** — 대부분의 백신·EDR 제품은 제조사 클라우드에 "이 파일을 본 다른 조직이 몇 곳인가"를 묻습니다. **세상 누구도** 본 적 없는 파일은 아주 의심스럽습니다. 정상 소프트웨어가 우리 회사에만 있는 경우는 거의 없거든요. (Defender for Endpoint 등은 이걸 "보급도(prevalence)"나 "처음 본 시각(first seen)"으로 보여 줍니다. VirusTotal 같은 서비스에 *해시*를 조회하는 것도 비슷한 신호를 줍니다. 민감한 파일 자체를 올리지는 마세요.)
- **맥락** — 무엇이 띄웠나, 어떤 사용자인가, 어떤 역할의 PC인가(키오스크보다 서버나 도메인 관리자의 PAW가 훨씬 중요).

<strong>[주의]</strong> 탐지 이름이 위협을 제대로 설명해 줄 거라고 믿지 마세요. 엔진은 이름을 대충 붙이고, 같은 파일도 제조사마다 이름이 다릅니다. 이름이 얼마나 무섭게 들리는지가 아니라 경로, 부모 프로세스, 해시, 보급도로 조사합니다.

## 정리 — SOC가 이 방어선들에서 챙길 것 { #soc-use }

- **PC별 Credential Guard 상태** — `Win32_DeviceGuard` / Wininit 13을 자산 데이터에 모읍니다. 사고가 나면 어떤 자격 증명을 털린 것으로 봐야 하는지를 이게 정합니다.
- **LSASS 접근 시도** — Credential Guard가 도는 곳에서도 경보를 유지합니다. *시도* 자체가 공격자가 관리자 권한을 가졌다는 뜻입니다.
- **업무용 PC끼리 옆으로 이동 포트에서 생긴 호스트 방화벽 차단** — 만들 수 있는 탐지 중 가장 가치 크고 잡음 적은 것 하나. 스캐너와 관리 서버부터 걸러 내세요.
- **방화벽·백신 변조** — 4946/4947/4950, 방화벽 꺼짐, Defender 5001/5007 예외 추가, 5013 변조 차단. 변경 작업 시간 밖이면 경보.
- **희귀성으로 본 백신 탐지** — 하나뿐인 것부터 분류하고, 늘 "누가 띄웠나?"와 "조치가 성공했나(1117인가 1118인가)?"를 묻습니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    VBS로 비밀 격리하기, "설정됐나가 아니라 돌고 있나를 확인", Credential Guard의 한계(로컬 SAM, 키로거, 가짜 SSP), 익스플로잇·옆으로 이동·C2·유출에 걸쳐 통제이자 센서인 호스트 방화벽, 들어오는 연결 기본 차단, 옆으로 이동 포트의 차단만 전술적으로 기록하기, 서브넷 안에서의 호스트 vs 네트워크 방화벽 가시성 차이, 흔한 악성코드를 거르는 필터로서의 백신과 그 희귀한 탐지에 주목하기 — 모두 설명한 그대로입니다. Defender 이벤트 ID(1116/1117, 5001/5007/5013)와 WFP 이벤트(5156/5157)도 그대로입니다.

!!! info "[변경됨] 바뀐 점"
    - **Credential Guard가 이제 많은 PC에서 기본으로 켜진다.** Windows 11 22H2부터 조건을 만족하고 도메인 컨트롤러가 아닌 Enterprise·Education 기기에서 기본으로 켜지고, Windows Server 2025도 조건을 만족하는 도메인 가입 서버(DC 제외)에서 기본으로 켭니다. 메모리 무결성(HVCI)도 새 Windows 11 기기 상당수에서 기본으로 켜져 있습니다. 그래도 확인은 하세요. 옛 하드웨어, 업그레이드한 PC, 펌웨어 설정 때문에 빈틈이 남습니다.
    - **LSA 보호도 기본값인 경우가 늘었다.** 최신 Windows 11 설치에서는 여러 구성에서 LSA 보호(`RunAsPPL`)가 켜집니다. 공격자는 자기 **취약한 서명 드라이버**를 들고 와서 보호를 벗기는 식으로 대응했습니다. 그래서 Microsoft의 취약 드라이버 차단 목록과 그에 맞는 ASR 규칙이 중요합니다.
    - **Application Guard는 사라졌다.** Edge용 MDAG는 지원 중단되어 Windows 11 24H2부터 쓸 수 없고, Office용 MDAG도 지원 중단됐습니다. 그 역할은 이제 보호된 보기, 인터넷 매크로 기본 차단, Defender for Office 365, SmartScreen, ASR, 애플리케이션 제어, 또는 서드파티 브라우저 격리가 나눠 맡습니다.
    - **이름.** "Windows Defender 방화벽"은 Microsoft 문서에서 이제 그냥 <strong>Windows 방화벽(Windows Firewall)</strong>이고, Windows 내장 백신은 <strong>Microsoft Defender 백신(Microsoft Defender Antivirus)</strong>입니다. 옛 "Defender ATP" 콘솔은 이제 Microsoft Defender XDR 안의 **Microsoft Defender for Endpoint**입니다.
    - **백신은 EDR/XDR 속으로 합쳐졌다.** 단독 시그니처 백신은 대부분 시그니처, 머신러닝, 클라우드 평판, AMSI, 행동 감시를 섞고 중앙 보급도 데이터를 갖춘 EDR/XDR 플랫폼의 한 부품이 됐습니다. 2024년 7월 보안 제품 업데이트 오류로 생긴 대규모 장애 뒤, Microsoft는 백신·EDR 제조사가 더 많은 코드를 Windows 커널 밖에서 돌릴 수 있게 하는 작업을 시작했습니다. 어디까지 진행될지는 아직 바뀌는 중이니, 쓰는 제품의 현재 상태를 확인하세요.
    - **양쪽 모두 AI.** 제조사는 더 큰 머신러닝 모델로 분류하고 AI 도우미로 분류 작업을 돕습니다. 공격자는 AI로 서로 다른 변종과 난독화 스크립트를 빠르게 대량으로 만듭니다. 그래서 해시·시그니처만의 탐지는 더 약해지고, 보급도와 행동 신호가 더 중요해졌습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **Credential Guard를 "자격 증명 탈취 해결"로 여기지 마세요.** 로컬 관리자 해시(LAPS로 대응), 키로거, 가짜 SSP, 살아 있는 세션 악용은 여전히 됩니다. 보호된 PC라고 LSASS 경보를 빼지도 마세요.
    - **새 통제를 Application Guard 중심으로 설계하지 마세요.** 은퇴했습니다. 대체 수단을 계획하세요.
    - **모든 PC의 허용된 연결을 전부 SIEM에 넣지 마세요.** 잡음에 돈을 쓰고 신호는 놓칩니다. 맞는 포트의 차단만 기록하고, 스캐너는 거르고, 5156은 필요한 곳에만 씁니다.
    - **WFP 5156/5157의 Source/Dest를 글자 그대로 읽지 마세요.** 들어오는 이벤트에서 "Source"는 로컬 PC입니다.
    - **방화벽 로그를 도메인 프로필에서만 켜 두지 마세요.** 노트북은 회사 밖에서 가장 위험합니다. 공용·개인 프로필에도 차단 기록을 켭니다.
    - **표적 공격자에 맞서는 큰 장벽으로 시그니처 백신에 기대지 마세요.** 그리고 이름에 "Generic"이 붙었다고 탐지를 무시하지 마세요. 낯선 경로의 일회성 탐지는 단서입니다.
    - **민감하거나 표적형인 파일을 공개 검사 서비스에 올리지 마세요.** 해시만 조회합니다. 올리면 공격자에게 들킬 수 있고 데이터가 샐 수 있습니다.

## 확인 문제 { #quiz }

### 문제 1

사고 조사 중, 공격자가 노트북 `LT-HR-0219`에서 6시간 동안 SYSTEM 권한을 가졌던 게 확인됐습니다. 이 노트북의 `Win32_DeviceGuard`는 `SecurityServicesConfigured {1, 2}`, `SecurityServicesRunning {2}`이고, `LsaIso.exe` 프로세스가 없습니다. 동료가 "Credential Guard는 GPO로 전부 배포했으니까, 거기 로그온했던 도메인 사용자들은 안전해요"라고 말합니다. 맞는 말인가요? 결과가 `{1, 2}` / `{1, 2}`였다면 무엇이 달라지고, 그래도 노출된 것으로 봐야 하는 자격 증명은 무엇인가요?

??? success "정답과 해설"
    **틀렸습니다.** *Configured* `{1, 2}`는 정책이 Credential Guard(1)와 메모리 무결성(2)을 요구했다는 뜻이지만, *Running* `{2}`는 메모리 무결성만 돌고 있다는 뜻입니다. `LsaIso.exe`가 없는 것도 그걸 확인해 줍니다. 비밀은 여전히 보통의 `lsass.exe` 메모리에 있었고, SYSTEM 권한이면 로그온한 모든 사람의 NT 해시와 Kerberos 티켓을 덤프할 수 있었습니다. 그러니 **그 6시간 동안 그 노트북에 세션이 있던 모든 도메인 계정**을 털린 것으로 봅니다(비밀번호 재설정, 특권 계정은 티켓 무효화 등 필요한 조치). 그리고 Credential Guard가 왜 안 켜졌는지(펌웨어 가상화 꺼짐, 보안 부팅, 호환 안 되는 드라이버) 찾습니다.

    **`{1, 2}` / `{1, 2}`였다면:** 저장된 도메인 해시와 TGT 키는 VTL1에 격리돼 있었을 테니, LSASS를 덤프해도 다시 쓸 수 있는 도메인 해시나 티켓은 안 나왔을 겁니다. 하지만 그래도 노출된 것으로 봐야 할 것: SAM의 **로컬 계정**(특히 로컬 관리자 — LAPS를 쓰고 있나?), **그 6시간 동안 로그온한 모든 사람**(가짜 SSP나 키로거가 입력한 비밀번호를 잡았을 수 있음), 그리고 그 PC의 파일·브라우저·스크립트에 저장된 자격 증명. Credential Guard는 피해 범위를 줄여 주지, SYSTEM을 무해하게 만들지는 않습니다.

### 문제 2

SIEM에 업무용 PC `10.30.5.42`에서 모은(로그는 `.42`에 있음) 아래 Windows 방화벽 기록이 보이고, 다른 날에는 비슷한 게 하나도 없습니다.

```
2026-11-19 10:14:03 DROP TCP 10.30.5.41 10.30.5.42 51544 445 52 S 3871632402 0 64240 - - - RECEIVE
2026-11-19 10:14:03 DROP TCP 10.30.5.41 10.30.5.42 51545 135 52 S 1209847712 0 64240 - - - RECEIVE
2026-11-19 10:14:04 DROP TCP 10.30.5.41 10.30.5.42 51546 5985 52 S 2650012931 0 64240 - - - RECEIVE
```

`10.30.5.41`은 다른 직원의 업무용 PC이고, 스캐너도 관리 서버도 아닙니다. 무슨 일이 있었는지, 왜 네트워크 방화벽은 이걸 못 봤을지, 다음에 무엇을 할지 말하세요.

??? success "정답과 해설"
    **무슨 일:** 1초 남짓 사이에 업무용 PC `.41`이 `.42`의 **445(SMB)**, **135(RPC 엔드포인트 매퍼)**, <strong>5985(WinRM)</strong>로 새 TCP 연결(SYN, `S`)을 시도했습니다. 원격 실행의 세 가지 주요 길(SMB/관리 공유를 통한 서비스 생성, WMI/DCOM, PowerShell 원격)입니다. `.42`의 호스트 방화벽이 셋 다 버렸습니다(`DROP`, `RECEIVE` = 들어옴). 업무용 PC끼리는 서로를 관리하지 않으니, `.41`에 있는 누군가가 **옆으로 이동**(T1021.002, T1047, T1021.006)을 시도한 것으로 보입니다.

    **네트워크 방화벽이 못 보는 이유:** 두 PC가 같은 서브넷에 있어서 패킷이 근처 스위치만 거치고 네트워크 방화벽을 지나가지 않습니다. 호스트 방화벽 로그가 없었다면 이 시도는 아예 안 보였을 겁니다.

    **다음 할 일:** `.41`을 감염됐을 가능성이 높은 PC로 봅니다. 10:14 전후 `.41`의 프로세스 생성 로그/EDR에서 그 연결을 만든 게 무엇인지(도구나 원격 호출을 하는 `powershell.exe` 등), 누가 로그온해 있었는지, 최근 로그온(4624)과 최근 백신·ASR 이벤트를 봅니다. 같은 출발지가 다른 이웃도 시도했는지(다른 PC의 방화벽 로그) 확인하고, 방화벽이 약한 곳(서버, 규칙 없는 PC)에서 성공한 시도가 있는지 찾습니다. 그다음 `.41`을 격리하고 거기서 쓰인 자격 증명을 재설정합니다. 그리고 이걸 상시 경보로 만듭니다: 업무용 PC → 업무용 PC, 445/135/3389/5985.

### 문제 3

일주일 치 Defender 탐지에 다운로드 폴더의 `PUA:Win32/Bundler.Toolbar` 214건, HTML 피싱 첨부 파일 61건, 그리고 파일 서버의 `1116` 이벤트 하나가 있습니다. `Trojan:Win32/Generic!ml`, 경로 `C:\ProgramData\SysCache\svcupd.exe`, Process Name `C:\Windows\System32\wbem\WmiPrvSE.exe`. 1초 뒤 같은 파일에 대한 `1118` 이벤트가 있고, 그 두 시간 전에 `C:\ProgramData\SysCache`를 예외 경로로 추가한 `5007` 이벤트가 있습니다. 무엇부터 보고, 이 세 이벤트를 합치면 무엇을 알 수 있나요?

??? success "정답과 해설"
    **`Generic!ml` 탐지 하나부터 봅니다.** PUA와 피싱 탐지는 양 많고, 여러 PC에 퍼진, 전형적인 위치의 흔한 잡음입니다. 일회성 탐지는 이름·경로·PC 역할(서버) 모두 희귀하고, 머신러닝 모델이 잡았고(`!ml` — 알려진 시그니처 없음, 새롭거나 표적형일 수 있음), 시스템 캐시를 흉내 낸 폴더에 있습니다.

    **세 이벤트를 합치면:**

    - 두 시간 전 **5007** — 누군가 Defender 설정을 바꿔 `C:\ProgramData\SysCache`를 **예외**로 넣었습니다. 자기 도구를 안 보이게 하려는 전형적인 공격자 행동(T1562.001)입니다.
    - **1116** — 그래도 Defender가 `svcupd.exe`를 잡았고(예외가 덮지 못한 경로, 행동 감시, 클라우드 판정 등으로), 그걸 띄운 건 WMI 공급자 호스트 **`WmiPrvSE.exe`**입니다. **WMI**를 통한 원격 실행(T1047), 즉 파일 서버로 옆으로 이동해 왔다는 신호입니다.
    - **1118** — 조치가 **실패**했습니다. 파일이 아직 있을 수 있고, 실행됐을 수도 있습니다.

    그러니 이건 떠도는 악성코드 한 조각이 아니라, 서버에서 사람이 직접 움직이는 침입일 가능성이 매우 높습니다. 서버를 격리하고, 파일과 해시를 수집하고, 예외를 넣은 게 누구인지(5007 이벤트의 프로세스/사용자, 그 시각 전후 서버의 로그온 이벤트) 찾고, WMI를 보낸 출발지 PC를 찾고, 예외를 지우고, 같은 경로·예외·해시가 다른 PC에도 있는지 범위를 넓혀 봅니다. 이름이 "Generic"이라 시시해 보인다고 우선순위를 낮추면 안 됩니다.

## 관련 레퍼런스 { #related }

- [자산 목록, 취약점 스캔, 패치, 익스플로잇 보호](inventory-vulns-patching.md) — 앞 방어선, ASR과 제어된 폴더 액세스 포함
- [자격 증명 덤프와 Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) · [옆으로 이동, 수집, 유출](../endpoint-attacks/lateral-collection-exfil.md)
- [LSASS 자격증명 덤프](../../../adversary/lsass-dumping.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [PsExec와 SMB 횡적 이동](../../../adversary/psexec-smb.md) · [WMI와 WinRM 실행](../../../adversary/wmi-winrm.md)
- [방어 무력화와 로그 삭제](../../../adversary/impair-defenses-log-clearing.md) · [PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md)
- [SMB](../other-protocols/smb.md) · [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md) · [잘 알려진 포트](../../../basics/well-known-ports.md)
