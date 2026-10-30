---
title: 초기 침투 (Initial Access)
tags:
  - redteam
  - initial-access
  - phishing
---

# 초기 침투 (Initial Access) 마스터 매뉴얼

!!! abstract "이 문서에 대하여"
    CRTO(Certified Red Team Operator) 교재의 초기 침투(Initial Access) 챕터를 기반으로,
    **Windows 10 / Windows 11 버전별(22H2·23H2·24H2) 보안 패치 현황**, **현실적 작동 가능성**,
    그리고 **최신 우회 트렌드와 OPSEC, Blue Team/DFIR 탐지 전략**까지 보강해 재정리한 학습용 레퍼런스입니다.
    실제 무기화(weaponization) 명령어보다 **작동 원리 · 패치 제약 · 탐지/방어**에 초점을 둡니다.

!!! note "구성 (총 4개 파트)"
    - **Part 1** — 피싱 구조학(Taxonomy) & 호스트 기반 페이로드 (DLL Side-Loading, .NET AppDomainManager)
    - **Part 2** — 인스톨러 및 오피스 기반 페이로드 (MSI, Excel Add-In, 코드 서명 정책 변화, GadgetToJScript 드로퍼)
    - **Part 3** — 트리거(Triggers)의 진화와 안티 샌드박스 (Batch 트릭, LNK 취약점과 패치, GrimResource/MSC)
    - **Part 4** — 컨테이너(MotW 우회 매트릭스) & 딜리버리 (HTML/SVG Smuggling, 사이트 클로닝) + 최신 트렌드 총정리

## 목차

- [1. 개요 및 피싱 페이로드 분류학](#overview)
- [2. Payloads — DLL Side-Loading / AppDomainManager](#payloads)
- [2.3~2.6 인스톨러 · 오피스 · 코드 서명 · 드로퍼 (Part 2)](#part2)
- [3. Triggers — Batch / LNK / GrimResource (Part 3)](#triggers)
- [4. Containers — MotW 우회 매트릭스 (Part 4)](#containers)
- [5. Delivery — HTML/SVG Smuggling · 사이트 클로닝](#delivery)
- [6. 부록 — 2025~2026 최신 초기 침투 트렌드](#trends)

---

<a id="overview"></a>

# Initial Access (Part 1)

## 1. 개요 및 피싱 페이로드 분류학 (Phishing Taxonomy)

### 1.1 초기 침투(Initial Access)의 현대적 정의

Initial Access (MITRE ATT&CK: TA0001)는 타겟 네트워크 내부에 최초의 거점(Foothold)을 확보하기 위한 전술입니다. 외부 노출 서버(VPN, 웹 서버 등)의 취약점을 공략하거나 공급망 공격(Supply-chain compromise)을 수행하기도 하지만, 여전히 가장 보편적이고 효과적인 수단은 **스피어 피싱(Spear Phishing)을 통한 사회공학적 공격**입니다.

과거에는 단순히 `report.exe`나 매크로가 포함된 `.doc` 파일을 이메일에 첨부해 보냈지만, 현대의 다층 방어 체계(이메일 샌드박스, MotW, EDR, ASR 규칙) 앞에서는 즉시 차단됩니다. 따라서 현대의 레드팀은 여러 기술적 요소를 조합하여 보안 솔루션의 자동 분석을 교란하고 분석가(DFIR)의 역분석을 지연시키는 복합 감염 체인(Multi-stage Infection Chain)을 설계해야 합니다.

### 1.2 피싱 패키지의 5대 구성 요소

보안 연구원 Mariusz Banach가 정립한 피싱 페이로드 분류 체계는 레드팀이 초기 침투 패키지를 설계할 때 가장 표준적인 프레임워크를 제공합니다.

```
DELIVERY( CONTAINER( TRIGGER + PAYLOAD + DECOY ) )
```

| 구성 요소 | 역할 및 설명 | 전통적 방식 (과거) | 현대적 레드팀 트렌드 (현재) |
| --- | --- | --- | --- |
| **1. Delivery** (전달 기법) | 패키지를 경계 보안(방화벽, 웹 프록시, 이메일 게이트웨이)을 우회하여 피해자에게 전달하는 수단 | 이메일 직접 첨부, 단순 HTTP 다운로드 링크 | **HTML Smuggling, SVG Smuggling**, 합법적 클라우드 스토리지(OneDrive, SharePoint) 악용, 메신저(Teams) 피싱 |
| **2. Container** (컨테이너) | 여러 파일(트리거, 페이로드, 디코이)을 하나로 묶어 전달을 쉽게 하고, **MotW(Mark-of-the-Web) 전파를 차단**하거나 암호화를 제공하는 압축/디스크 포맷 | `.zip`, `.rar` | `.iso`, `.img`, `.vhd/.vhdx`, `.wim`, `.7z`, WebDAV 공유 폴더 |
| **3. Trigger** (트리거) | 피해자가 컨테이너를 연 후 직접 상호작용(더블 클릭)하여 페이로드 실행을 유도하는 방아쇠 | `.exe`, 워드/엑셀 매크로(`.docm`, `.xlsm`) | **`.lnk`(바로가기)**, `.bat/.cmd`, `.msc`, 정상 서명된 실행 파일(LOLBin/Sideloading 호스트) |
| **4. Payload** (페이로드) | 피해자 시스템에서 실제로 실행될 악성 코드 (또는 최종 페이로드를 가져오는 드로퍼/로더) | 단일 악성 `.exe`, PowerShell 원라이너 | **악성 `.dll` (Side-loading용)**, `.xlam`, 암호화된 쉘코드 파일(`.bin`, `.dat`), .NET 어셈블리 |
| **5. Decoy** (미끼 파일) | 트리거 작동 직후 화면에 표시되어 피해자가 정상적인 문서를 열었다고 믿게 만드는 위장용 파일 | 없음 (실행 후 아무 반응 없거나 가짜 에러 창 출력) | 시나리오(Pretext)에 완벽히 부합하는 정상 `.pdf`, `.xlsx`, `.docx` 문서 (트리거 아이콘과 동일한 포맷 유지 필수) |

### 1.3 실전 공격 체인 분석 (Case Study: Lumma Stealer 캠페인)

실제 위협 그룹들이 보안 솔루션을 우회하기 위해 어떻게 구성 요소를 조합하는지 보여주는 대표적인 체인입니다.

```
[피해자: 웹사이트에서 PDF로 위장된 파일 다운로드]
       │
       ▼
┌───────────────────┐
│  1. Trigger       │  PDF 아이콘으로 위장된 Windows 바로가기 (.LNK) 실행
└─────────┬─────────┘
          │ (호출)
          ▼
┌───────────────────┐
│  2. LOLBin (1차)  │  wmic.exe 또는 mshta.exe 가 원격 서버(80.76.51[.]231)에 접속
└─────────┬─────────┘
          │ (다운로드 및 실행)
          ▼
┌───────────────────┐
│  3. Dropper (2차) │  난독화된 JavaScript (.js) -> 난독화된 PowerShell 스크립트 호출
└─────────┬─────────┘
          │ (언패킹 및 은닉 실행)
          ▼
┌───────────────────┐
│  4. Final Payload │  Lumma Stealer (Kompass-4.1.2.exe) 실행
└─────────┬─────────┘
          │ (C2 주소 획득 - Dead Drop Resolver 기법)
          ▼
┌───────────────────┐
│  5. C2 통신       │  Steam 커뮤니티 프로필 페이지의 HTML 태그("actual_persona_name")를 파싱하여
└───────────────────┘  암호화된 실제 C2 도메인 주소를 복호화한 뒤 최종 통신 수행
```

!!! tip "매뉴얼 업데이트 노트 — 이 체인의 윈도우 버전별 유효성 평가"
    - **`WMIC` 호출:** **Windows 11 (22H2 이상) 및 차기 Windows Server**에서는 `wmic.exe`가 기본 설치에서 제거(Deprecated/Removed on demand)되었습니다. 따라서 현재 레드팀 작전에서 `wmic`을 트리거 체인에 넣으면 최신 윈도우 11 타겟에서는 공격이 실패합니다.
    - **`mshta.exe` 및 `JavaScript`:** Microsoft Defender for Endpoint(MDE) 등 최신 EDR의 기본 탐지 룰 및 ASR(공격 표면 감소) 규칙 1순위 타겟입니다. 따라서 현대 레드팀은 스크립트 엔진 대신 아래에서 다룰 **DLL Side-loading**을 주력으로 사용합니다.

---

<a id="payloads"></a>

## 2. Payloads 기법 상세 및 최신화

### 2.1 DLL Side-Loading (DLL 사이드로딩 & WinSxS 악용)

#### 핵심 원리 (DLL Hijacking vs. DLL Side-Loading)

윈도우 응용프로그램(`.exe`)이 실행될 때 필요한 동적 링크 라이브러리(`.dll`)에 대한 절대 경로가 하드코딩되어 있지 않다면, 윈도우는 정해진 DLL 검색 순서(Standard DLL Search Order)에 따라 폴더를 뒤지며 DLL을 찾습니다.

1. **애플리케이션(`.exe`)이 위치한 현재 디렉터리 (가장 중요 ⭐)**
2. 시스템 디렉터리 (`C:\Windows\System32`)
3. 16비트 시스템 디렉터리 (`C:\Windows\System`)
4. Windows 디렉터리 (`C:\Windows`)
5. 현재 작업 디렉터리 (Current Working Directory)
6. `PATH` 환경 변수에 등록된 디렉터리들

- **DLL Hijacking:** 시스템에 이미 설치된 프로그램이 존재하지 않는 DLL(`NAME NOT FOUND`)을 찾으려 할 때, 일반 사용자가 쓰기 가능한 경로(예: `PATH`에 포함된 하위 폴더 등)에 악성 DLL을 심어두는 기법입니다(주로 권한 상승 및 지속성 유지에 사용).
- **DLL Side-Loading:** **초기 침투(Initial Access)에 최적화된 기법**입니다. 마이크로소프트 등 신뢰할 수 있는 기관의 디지털 서명이 된 정상 `.exe` 파일과, 그 파일이 로드하는 이름과 똑같이 만든 악성 `.dll` 파일을 같은 폴더(컨테이너 내부)에 묶어서 피해자에게 보냅니다. 검색 순서 1번(애플리케이션이 위치한 디렉터리)에 의해 정상 `.exe`가 실행되는 즉시 같은 폴더에 있는 악성 `.dll`을 무조건 로드하게 됩니다.

#### 왜 `C:\Windows\WinSxS`를 노리는가?

최신 윈도우의 기본 시스템 폴더(`System32` 등)에 있는 실행 파일들은 패치가 거듭되면서 DLL을 로드할 때 안전한 경로(예: 자기 자신의 원래 폴더나 GAC 등)만 검색하도록 수정되었습니다. 하지만 `C:\Windows\WinSxS` (Windows Component Store)는 응용프로그램 간의 호환성(Side-by-Side 어셈블리)과 업데이트 롤백을 위해 **패치 이전의 구버전 바이너리들을 그대로 보관하는 거대한 창고**입니다. 즉, 메인 OS에서는 패치된 취약한 버전의 마이크로소프트 정품 서명 바이너리가 `WinSxS` 안에는 여전히 남아 있습니다.

#### [분석 가이드] WinSxS에서 취약한 바이너리 식별하기

**Step 1. 최신 버전 바이너리의 동작 확인 (`ngentask.exe`)** — 먼저 기본 경로에 설치된 최신 버전의 `ngentask.exe`를 실행하고 Sysinternals의 Process Monitor (ProcMon)로 관찰합니다.

- ProcMon 필터 설정:
    - `Process Name` `is` `ngentask.exe`
    - `Path` `ends with` `.dll`
    - `Result` `is` `NAME NOT FOUND`

```
C:\Users\Analyst> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe
```

> **결과:** 찾을 수 없는 DLL들이 보이지만, 오직 `C:\Windows\Microsoft.NET\Framework64\...` 내부와 GAC(Global Assembly Cache) 경로만 검색할 뿐 외부 폴더를 뒤지지 않아 하이재킹이 어렵습니다.

**Step 2. `WinSxS`에서 구버전 `ngentask.exe` 찾기** — PowerShell로 `WinSxS` 디렉터리 내부에 보관된 이전 버전의 바이너리를 검색합니다.

```powershell
PS C:\> Get-ChildItem -Path C:\Windows\WinSxS -Recurse -Filter ngentask.exe | Select-Object -ExpandProperty FullName

C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_..._4.0.15805.0_...\ngentask.exe
C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_..._4.0.15805.285_...\ngentask.exe
...
```

**Step 3. 구버전 실행 및 DLL 검색 순서 확인** — 찾아낸 구버전을 실행하고 다시 ProcMon을 확인합니다. 구버전은 `mscorsvc.dll`을 찾기 위해 표준 검색 순서를 그대로 따르며, 현재 작업 디렉터리에서 DLL을 로드하려고 시도(`NAME NOT FOUND`)하는 것이 확인됩니다. → 이 경로가 사이드로딩에 취약한 지점입니다.

#### [심화] 실전 레드팀을 위한 고급 DLL Side-Loading 개념

단순히 `DllMain`에서 동작하는 것을 넘어, 실제 작전에서 성공률과 안정성을 높이려면 다음 두 가지 개념이 중요합니다.

1. **DLL 프록싱 / 포워딩 (DLL Proxying / Forwarding):** 정상 프로그램이 DLL을 로드한 직후 특정 Export 함수를 호출하려 할 때, 대체 DLL에 그 함수가 없으면 프로그램이 비정상 종료(Crash)되어 피해자가 눈치채고 EDR에 크래시 덤프가 남습니다. 따라서 원래 프로그램이 요청하는 정상 함수 호출은 진짜 시스템 DLL(`C:\Windows\System32\...`)로 포워딩(Forwarding)해 주는 프록시 DLL(예: `SharpDllProxy`)을 사용해 프로그램이 에러 없이 정상 동작하도록 만듭니다.
2. **서드파티(3rd-Party) 서명 바이너리의 활용:** 마이크로소프트 기본 바이너리(`ngentask.exe` 등)가 비정상 경로(예: `Downloads`)에서 실행되면 최신 EDR이 의심합니다. 따라서 최근에는 NVIDIA, Adobe, Cisco, VLC 등의 서명된 구버전 실행 파일을 호스트로 활용합니다. 서드파티 프로그램은 원래 다양한 경로에 설치될 수 있어 EDR의 경로 기반 휴리스틱을 더 잘 우회합니다. (참고 데이터베이스: **HijackLibs.net**)

### 2.2 .NET AppDomainManager Injection (앱도메인 매니저 하이재킹)

#### 핵심 원리

DLL 검색 순서와 무관하게, **.NET Framework로 작성된 모든 애플리케이션**은 실행될 때 자신이 사용할 `AppDomainManager`를 지정할 수 있는 공식 기능을 가지고 있습니다. `System.AppDomainManager` 클래스를 상속받는 .NET 어셈블리(DLL)를 만든 뒤, 환경 변수나 `.config` 파일을 통해 정상 .NET 실행 파일에게 "실행될 때 이 DLL을 매니저로 불러와라"라고 지시하는 기법입니다.

#### [개념 예시] Custom AppDomainManager 구조

**Step 1. .NET Framework 클래스 라이브러리 (PoC 수준, MessageBox만 출력)**

```csharp
using System;
using System.Windows.Forms;

namespace AppDomainHijack
{
    // AppDomainManager를 상속받는 공개 클래스 정의
    public sealed class DomainManager : AppDomainManager
    {
        // 도메인이 초기화될 때 자동으로 호출되는 메서드를 오버라이드
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            // PoC — 실제 작전에서는 이 자리에 로더 코드가 들어가지만, 본 문서는 원리 설명용
            MessageBox.Show("Hello World", "Success");
        }
    }
}
```

**Step 2. 정상 .NET 바이너리와 DLL을 같은 폴더에 배치** — 윈도우에 기본 내장된 서명된 .NET 실행 파일(예: `ngentask.exe`, `dfsvc.exe`, `UEVAppMonitor.exe` 등) 중 하나를 고르고, 같은 폴더에 컴파일한 DLL을 둡니다. 이때 config/환경 변수에 지정할 **어셈블리 이름과 실제 DLL 파일명이 반드시 일치**해야 정상 로드됩니다.

**Step 3. 트리거 방식 (2가지)**

- **방법 A — 환경 변수** (배치 파일이나 LNK 트리거에서 주로 사용):

```powershell
PS C:\> $env:APPDOMAIN_MANAGER_ASM  = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
PS C:\> $env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
PS C:\> .\ngentask.exe
```

- **방법 B — 애플리케이션 구성 파일(`.config`)** (컨테이너 패키징 시 가장 깔끔함 ⭐): 실행 파일 이름 뒤에 `.config`를 붙인 텍스트 파일(예: `ngentask.exe.config`)을 같은 폴더에 두면, 환경 변수 설정 없이 `.exe`만 실행해도 작동합니다.

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="AppDomainHijack.DomainManager" />
  </runtime>
</configuration>
```

### [호환성 및 보안 업데이트 매트릭스] Part 1 기법 평가

| 공격 기법 | 대상 OS/프레임워크 호환성 | 최신 보안 업데이트 영향 (Win 10 / Win 11 23H2~24H2) | 실전 작동 가능성 및 우회 팁 (OPSEC) |
| --- | --- | --- | --- |
| WinSxS 기반 DLL Side-Loading | **모든 Windows 버전** (Win 10 / Win 11 / Server 공통) | OS 차원에서 `WinSxS` 구조는 그대로 유지됨. 단, 최신 EDR은 **시스템 기본 바이너리가 비정상 경로에서 실행되는 것**을 행위 기반으로 탐지함. | **[높음 — 단, 호스트 변경 권장]** MS 기본 바이너리 대신 **서드파티 정상 서명된 실행 파일**을 호스트로 사용하면 최신 Win 11 + EDR 환경에서도 높은 성공률. |
| AppDomainManager Injection | **.NET Framework (v2.0 ~ v4.8.1)** 전용 (모든 Win 10/11 기본 내장) | **.NET Core 3.1+ 및 .NET 5~9** 기반 앱에서는 작동하지 않음 (대신 `DOTNET_STARTUP_HOOKS` 사용). **ETW**로 .NET 어셈블리 로드 이벤트가 EDR에 기록됨. | **[중상 — 여전히 강력]** `.config` 방식은 디스크에 스크립트를 남기지 않아 정적 탐지에 강함. 단, DLL 내부 코드가 **AMSI/ETW**에 걸리지 않도록 난독화·동적 API 호출(D/Invoke) 필요. |

### [Blue Team / DFIR] 탐지 및 방어 가이드

1. **PE 헤더의 `OriginalFilename` 불일치 탐지 (Sysmon Event ID 1 & 7):** 공격자가 `ngentask.exe`의 이름을 `PDFViewer.exe`로 바꿔도 PE 헤더의 `OriginalFilename`에는 여전히 `ngentask.exe`가 남습니다. EDR은 현재 파일명과 원본 헤더명이 다르거나, 원래 `System32`/`Framework64`에 있어야 할 파일이 `Downloads`나 마운트된 가상 드라이브(`D:\`, `E:\`)에서 실행될 때 알람을 발생시킵니다.
2. **비정상 `.config` 생성 및 미서명 DLL 로드 감시:** Sysmon Event ID 11(FileCreate)로 `*.exe.config` 파일 생성을 모니터링하고, 서명된 MS 바이너리가 미서명 DLL을 로드하는 이벤트를 추적합니다.

---

<a id="part2"></a>

# Initial Access (Part 2)

### 2.3 Windows Installer (.MSI) 패키지 분석

#### 핵심 원리 및 메커니즘

Windows Installer(`.msi`)는 설치에 필요한 파일과 단계별 작업(Action) 정보를 내부 관계형 데이터베이스(테이블 구조)로 저장합니다. 따라서 분류 체계상 **컨테이너(Container)이자 동시에 트리거/실행기(Trigger/Payload)** 역할을 할 수 있습니다.

- **패키징 구조:** Visual Studio의 'Setup Project'로 대상 파일을 `Program Files`·바탕화면 등에 배치하도록 지정하고, 드롭 시 파일명 변경(`TargetName`)이나 숨김(`Hidden: True`)이 가능합니다.
- **Custom Actions 악용:** MSI가 위험한 가장 큰 이유는 설치/커밋/롤백/제거 단계에 임의의 `.exe`, DLL, 스크립트(`.vbs`, `.js`)를 연동할 수 있는 **Custom Actions** 기능 때문입니다.
- **위장 및 은닉:** `Run64Bit` 속성을 켜고 `/install /quiet` 같은 정상 인자를 넘기며, 정상 기업명(`Manufacturer`)·제품명(`ProductName`)을 기입해 제어판·설치 경로에서 정상 소프트웨어처럼 보이게 위장합니다.

#### 최신 보안 업데이트 및 제약 사항

1. **부모-자식 프로세스 행위 탐지 (EDR):** 과거에는 `msiexec.exe`가 백그라운드에서 페이로드를 실행해 일반 AV를 우회했으나, 현재 Win 10/11의 최신 EDR(MDE, CrowdStrike 등)은 `msiexec.exe`가 미서명 바이너리나 스크립트 엔진(`wscript.exe`, `powershell.exe`, `rundll32.exe`)을 자식 프로세스로 생성하는 행위를 고위험으로 분류해 즉시 차단합니다.
2. **관리자 권한(UAC) 요구 문제:** `C:\Program Files`에 드롭하도록 구성하면 표준 사용자 환경에서 UAC 프롬프트가 발생합니다. 그래서 실제 위협 그룹은 UAC를 피하려 단일 사용자 설치 모드(Per-user, `%LocalAppData%` 경로 등)로 MSI 테이블을 수정해 배포합니다.

### 2.4 Excel Add-In (.XLAM)과 신뢰할 수 있는 위치(Trusted Locations)

#### 핵심 원리 및 메커니즘

일반 매크로 문서(`.docm`, `.xlsm`)는 MotW 태그와 오피스의 제한된 보기(Protected View)로 매크로 실행이 차단됩니다. 이를 우회하기 위해 Excel 추가 기능(`.xlam`)과 오피스의 신뢰할 수 있는 위치(Trusted Locations)를 결합합니다.

- **Trusted Locations의 허점:** 오피스는 신뢰 센터에 등록된 특정 폴더의 파일에 대해 보안 검사를 건너뛰고 매크로를 즉시 활성화합니다.
    - `%ProgramFiles%\Microsoft Office\root\Office16\XLSTART\` (일반 사용자 쓰기 불가)
    - **`%APPDATA%\Microsoft\Excel\XLSTART\` (일반 사용자 쓰기 가능 ⭐)**
    - `%APPDATA%\Microsoft\Templates\` (일반 사용자 쓰기 가능)
- **자동 실행 메커니즘:** `XLSTART` 폴더는 엑셀 시작 시 폴더 안의 모든 통합 문서/추가 기능(`.xlam`)을 사용자 동의 없이 자동 로드합니다. `Auto_Open()` 서브루틴이 포함된 `.xlam`이 이 경로에 복사되면, 엑셀을 열 때마다 매크로가 작동하므로 **지속성(Persistence)** 기법으로도 쓰입니다.

#### 최신 보안 업데이트 및 제약 사항

1. **ASR (Attack Surface Reduction) 규칙에 의한 차단:** MotW를 제거하고 `XLSTART`로 자동 실행에 성공해도, Enterprise 환경에서 Defender ASR이 켜져 있으면 매크로 이후 단계가 차단됩니다. (주요 규칙: "모든 Office 앱의 자식 프로세스 생성 차단", "Office 앱의 실행 콘텐츠 생성 차단", "Office 매크로의 Win32 API 호출 차단")
2. **Excel 4.0(XLM) 및 XLL 통제 강화:** VBA 기반 `.xlam` 외에 C/C++ DLL 기반 추가 기능인 `.xll`도 악용되었으나, 최근 M365 업데이트로 인터넷 유입 추가 기능 블록 정책과 AMSI의 매크로 런타임 메모리 스캔이 대폭 강화되었습니다.

### 2.5 코드 서명(Code Signing)과 SmartScreen 신뢰 모델의 변화

#### 핵심 원리 및 메커니즘

코드 서명은 실행 파일/설치 패키지에 디지털 서명을 추가해 게시자 신원과 무결성을 보장하는 기술입니다. **Microsoft Defender SmartScreen**은 서명 여부를 신뢰 모델의 핵심 지표로 삼으며, 서명된 파일은 경고가 적고 정적 탐지에서도 유리합니다.

- **Standard vs. EV 인증서 (교재 기준):**
    - **Standard:** 서명은 하지만 평판(Reputation)을 쌓기 전까지는 여전히 SmartScreen 경고가 발생.
    - **EV (Extended Validation):** 엄격한 실사를 거쳐 발급되며, 과거에는 발급 직후 즉시 SmartScreen 신뢰를 얻어 '알 수 없는 게시자' 경고를 제거해 주던 강력한 수단.
- **인증서 조달 방식:** 자기 회사명으로 서명하면 즉시 정체가 드러나고 폐기되므로, 유령 회사 설립이나 공개 저장소·버킷에 유출된 타 기업 인증서 탈취 등이 악용되었습니다.

#### [필수 업데이트] 코드 서명 및 SmartScreen 정책의 대격변 (2023~2026)

원본 교재와 현재 환경의 차이가 가장 큰 부분입니다.

1. **하드웨어 토큰(HSM) 보관 의무화 (CA/Browser Forum 규정 변경):** 2023년 6월부터 **일반(Standard) 코드 서명 인증서조차 `.pfx`/`.p12` 파일로 발급되지 않습니다.** 모든 개인키는 물리 하드웨어 토큰(FIPS 140-2 Level 2 이상) 또는 클라우드 HSM(Azure Key Vault, AWS KMS)에만 저장되도록 강제됩니다. 이로 인해 `.pfx`를 훔쳐 로컬 서명하는 기법은 급감하고, 클라우드 CI/CD 서명 권한 탈취로 위협이 이동했습니다.
2. **EV 인증서의 '즉시 SmartScreen 우회' 특권 폐지:** 악용 급증에 따라 MS가 평가 알고리즘을 전면 수정했습니다. **현재 Win 10/11 최신 환경에서는 EV 서명이라도 자동 즉시 평판을 부여하지 않으며**, 파일·서명자 이력과 배포 규모 등을 종합해 평판이 확인될 때까지 경고를 띄웁니다.

### 2.6 드로퍼(Droppers)와 .NET 역직렬화 (GadgetToJScript)

#### 핵심 원리 및 메커니즘

드로퍼는 최종 페이로드를 컨테이너에 직접 노출하지 않고, 자기 내부 리소스(Embedded Resource)에 숨겼다가 실행 시점에 디스크에 풀거나 외부에서 다운로드하는 중간 매개체입니다.

```
[GadgetToJScript 기반 드로퍼의 작동 구조]

1. .NET DLL 제작 (C#)        2. 직렬화 및 스크립트 변환       3. 피해자 PC에서 실행
┌──────────────────────┐    ┌──────────────────────────┐    ┌────────────────────────┐
│ MyDropper.dll        │    │ GadgetToJScript 도구     │    │ dropper.js 더블 클릭   │
│  └─ Embedded Resource│ ──>│  └─ .NET 가젯 체인 생성  │ ──>│  └─ wscript.exe 실행   │
│     (http_x64.exe)   │    │  └─ Base64 인코딩 (JS화) │    │  └─ 메모리 역직렬화    │
└──────────────────────┘    └──────────────────────────┘    └───────────┬────────────┘
                                                                        │
                                                                        ▼
                                                            ┌────────────────────────┐
                                                            │ C# 생성자 코드 자동실행│
                                                            │  └─ C:\ProgramData\... │
                                                            │     경로에 EXE 드롭/실행│
                                                            └────────────────────────┘
```

- **리플렉션 및 리소스 추출:** C# 라이브러리에 실행 파일을 리소스로 포함한 뒤, 생성자에서 `Assembly.GetExecutingAssembly().GetManifestResourceStream()`으로 메모리에 읽어 들입니다.
- **드롭 위치 선정 (OPSEC):** `%TEMP%`·홈 디렉터리 드롭은 즉시 탐지됩니다. 그래서 표준 사용자도 쓰기/폴더 생성이 가능한 **`C:\ProgramData\*`** 하위에 폴더를 만들어 파일을 생성합니다.
- **GadgetToJScript를 통한 스크립트화:** 컴파일된 .NET DLL 자체는 실행할 수 없으므로, <strong>.NET 역직렬화(Deserialization)</strong>를 악용하는 `GadgetToJScript`로 어셈블리를 `.js`/`.vbs`/VBA/HTA 스크립트로 변환합니다. 피해자가 `.js`를 실행(`wscript.exe`)하면 메모리에서 역직렬화되며 생성자 안의 드로퍼 코드가 작동합니다.

#### 최신 보안 업데이트 및 제약 사항

1. **AMSI 완벽 통합:** `wscript.exe`/`cscript.exe`가 `.js`/`.vbs`를 실행할 때 스크립트 엔진은 실행 직전 **AMSI**로 평문을 백신에 전달합니다. `GadgetToJScript`가 생성하는 직렬화 가젯 패턴은 현재 모든 상용 AV/EDR에 시그니처가 있어, 난독화·AMSI 우회 없이는 즉시 차단됩니다.
2. **.NET `BinaryFormatter`의 퇴출:** `BinaryFormatter` 역직렬화는 보안 위험으로 최신 .NET에서 기본 비활성화되었고, 4.8.1 환경에서도 EDR의 ETW 텔레메트리가 메모리 내 `Assembly.Load`를 실시간 감시합니다.
3. **Win 11의 JScript/VBScript 제한:** 레거시 스크립트 엔진 감염을 막기 위해 WSH 및 VBScript의 기본 동작을 제한하거나 선택적 기능(FOD)에서 제거하는 정책이 진행 중입니다.

### [호환성 및 보안 업데이트 매트릭스] Part 2 기법 평가

| 분류 및 기법 | 대상 OS/환경 호환성 | 최신 보안 업데이트 영향 | 방어 및 탐지(Blue Team) 핵심 포인트 |
| --- | --- | --- | --- |
| Windows Installer (`.msi`) | **모든 Windows 버전** (`msiexec.exe` 내장) | `Program Files` 지정 시 UAC 발생. `msiexec.exe`의 비정상 자식 프로세스 생성 시 EDR 탐지. | **Sysmon ID 1:** 부모가 `msiexec.exe`이고 자식이 미서명 바이너리이거나 `C:\ProgramData` 등에서 실행되는 로그 감시. MSI CustomAction 테이블 정적 분석(Orca). |
| Excel Add-In (`.xlam`) | **MS Office 환경** (2016/2019/M365) | `XLSTART`는 여전히 신뢰 위치로 작동. 단, ASR 활성화 시 매크로 내 프로세스 생성·Win32 API 호출 차단. | **Sysmon ID 11:** `%APPDATA%\Microsoft\Excel\XLSTART\` 및 `AddIns` 경로 신규 파일 생성 실시간 모니터링(최우선 룰). |
| Code Signing (EV 인증서) | **모든 Windows 버전** (SmartScreen 연동) | **HSM 보관 의무화**로 인증서 파일 유출 감소. **EV 즉시 우회 특권 폐지**(평판 기반 통합). | 서명된 바이너리라도 인증서 발급일·생소한 게시자·조직 내 최초 등장 여부(Prevalence)를 교차 검증. |
| GadgetToJScript (`.js`/`.vbs` 드로퍼) | **.NET Framework 4.8.x** (Win 10/11 내장) | **AMSI 및 .NET ETW**로 직렬화 가젯 패턴이 높은 확률로 탐지. 디스크에 `.exe` 드롭 후 `Process.Start` 방식은 EDR에 취약. | `wscript.exe`/`cscript.exe`가 `.NET CLR` DLL(`clr.dll`, `mscoree.dll`)을 로드하는 비정상 행위(Sysmon ID 7) 탐지. `C:\ProgramData` 하위 신규 실행 파일 생성 감시. |

---

<a id="triggers"></a>

# Triggers (초기 실행 유도 및 안티 샌드박스)

트리거(Trigger)는 피해자가 컨테이너를 마운트/해제한 뒤 최초로 상호작용(보통 더블 클릭)하는 파일입니다. 핵심 목표는 익숙한 파일로 위장해 의심을 피하고, 백그라운드에서 페이로드와 미끼 파일(Decoy)을 동시에 실행하는 것입니다.

### 3.1 Batch 스크립트 (`.bat`, `.cmd`)와 환경 변수 기반 샌드박스 우회

#### 핵심 원리 및 메커니즘

`cmd.exe`로 명령어를 순차 실행하는 텍스트 스크립트 포맷입니다(`.bat`, `.cmd`, `.btm`).

- **실행 화면 은닉:** 최상단에 `@echo off`, 명령어 끝에 `> nul 2>&1`을 붙여 표준 출력·에러를 숨깁니다.
- **안티 샌드박스 환경 변수 검증 트릭:** 자동 AV 에뮬레이터/샌드박스를 회피하려고, 배치가 '실제 더블 클릭'으로 실행됐는지 '분석 CLI 호출'로 실행됐는지를 환경 변수로 판별합니다.

```
[배치 파일 실행 방식에 따른 환경 변수 비교 원리]

1. 사용자가 탐색기에서 더블 클릭한 경우:
   • %cmdcmdline% : C:\Windows\system32\cmd.exe /c ""C:\Users\Victim\Desktop\test.bat" "
   • %~f0         : C:\Users\Victim\Desktop\test.bat
   ▶ %cmdcmdline% 안에 %~f0(스크립트 경로)가 포함됨 -> 정상 실행 진행

2. 샌드박스/분석가가 열린 CMD에서 직접 입력 실행한 경우:
   • %cmdcmdline% : "C:\Windows\System32\cmd.exe"
   • %~f0         : C:\Users\Victim\Desktop\test.bat
   ▶ %cmdcmdline% 안에 스크립트 경로가 없음 -> 분석 환경으로 간주, 즉시 종료(exit)
```

즉 `%cmdcmdline%`을 파이프(`|`)로 넘겨 `find /i "%~f0"`로 현재 배치 경로를 검색하고, 일치하지 않으면(`||`) 즉시 `exit`해 자동 분석을 무력화합니다.

#### 최신 보안 업데이트 및 제약 사항

1. **기본 아이콘 변경 불가로 인한 사회공학적 한계:** `.bat`/`.cmd`는 자체 아이콘 리소스를 포함할 수 없어 항상 기본 배치 아이콘으로 표시됩니다. 따라서 단독 트리거로는 들키기 쉽고, 주로 `.lnk` 등 다른 트리거가 숨김 상태로 호출하는 2차 스테이지로 쓰입니다.
2. **EDR 명령줄 감사 및 AMSI:** `cmd.exe /c`로 생성되는 모든 하위 프로세스 생성 이벤트는 명령줄 인자 전체가 보안 로그(Event ID 4688, Sysmon ID 1)에 기록됩니다. 최신 Defender/EDR은 난독화 패턴(예: `%var:~0,1%` 부분 문자열 조합)을 정적·동적으로 탐지합니다.

### 3.2 Windows Shell Link (`.lnk` 바로가기 파일)

#### 핵심 원리 및 메커니즘

`.lnk`(Shell Link)는 초기 침투에서 가장 널리 쓰이는 기만적 트리거입니다.

- **NeverShowExt를 통한 확장자 은닉:** '파일 확장명 표시' 옵션을 켜도 `.lnk` 확장자는 레지스트리의 `NeverShowExt` 속성 때문에 화면에 **절대 표시되지 않습니다.** `report.pdf.lnk`로 지정하면 화면에는 `report.pdf`로만 보입니다.
- **아이콘 위장 및 복합 명령 실행:** `WScript.Shell` COM 객체로 대상 경로(`TargetPath`)를 `%COMSPEC%`(`cmd.exe`)로 지정하면서, 아이콘(`IconLocation`)은 Edge(`msedge.exe, 13` — 내장 PDF 아이콘)나 Excel(`EXCEL.EXE, 0`) 아이콘으로 덮어쓸 수 있습니다.
- **숨김 파일 제어 연동:** 컨테이너 내부 페이로드(예: `macros.xlam`)가 숨김 속성이면, `.lnk` 인자(`Arguments`)로 `xcopy /H`로 `%APPDATA%\Microsoft\Excel\XLSTART\`에 복사 → `attrib -H`로 숨김 해제 → 미끼 문서(`sales.xlsx`) 실행까지 단 한 번의 클릭으로 처리합니다.

#### 최신 보안 업데이트 및 제약 사항

1. **SmartScreen 및 MotW 검증 강화 (CVE-2022-44698, CVE-2023-36025, CVE-2024-21412 패치):** 과거엔 MotW가 붙어도 SmartScreen을 우회하는 취약점이 있었으나, 집중 패치로 **현재 Win 10/11 최신 빌드는 외부 유입 `.lnk` 실행 시 대상 경로·인자에 대해 엄격한 SmartScreen/Defender 검사**를 수행합니다.
2. **`explorer.exe` → `cmd.exe`/`powershell.exe` 프로세스 트리 탐지:** `.lnk` 클릭으로 `cmd`/`powershell`이 실행되면 부모가 `explorer.exe`로 기록되고 명령줄에 `&&`, `start`, `xcopy` 등이 나타납니다. 이는 현대 EDR·ASR의 기본 차단 조건입니다.
3. **최신 트렌드 (LNK + LOLBins/Sideloading):** 탐지율 높은 `cmd`/`powershell`을 `TargetPath`에 직접 넣지 않고, 컨테이너에 함께 숨긴 정상 서명 실행 파일(DLL Side-loading 호스트)을 직접 가리키게 해 스크립트 인터프리터 호출 자체를 생략하는 방식으로 진화했습니다.

### 3.3 Microsoft Saved Console (`.msc` — GrimResource 기법)

#### 핵심 원리 및 메커니즘

2024년 Elastic Security Labs가 발견해 'GrimResource'로 명명한 기법으로, 윈도우 관리 콘솔(`mmc.exe`)의 설정 저장 파일인 **`.msc`** 포맷을 악용합니다.

```
[GrimResource (.msc) 실행 흐름도]

[피해자: 악성 .msc 파일 더블 클릭]
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ 1. mmc.exe 실행 (자동 권한 상승 - Auto-elevating)       │
│    └─ 로컬 관리자인 경우 High Integrity 획득            │
└───────────────────────────┬────────────────────────────┘
                            │ (.msc 내부 XML 파싱)
                            ▼
┌────────────────────────────────────────────────────────┐
│ 2. apds.dll 의 XSS 취약점 트리거 (StringTable 조작)     │
│    └─ URL 인코딩된 XSL 스타일시트(xsl.loadXML) 로드     │
└───────────────────────────┬────────────────────────────┘
                            │ (XSLT 스크립트 엔진 호출)
                            ▼
┌────────────────────────────────────────────────────────┐
│ 3. 내장된 VBScript / JScript 실행                       │
│    └─ WScript.Shell 또는 DotNetToJScript 페이로드 작동  │
└────────────────────────────────────────────────────────┘
```

- **APDS.DLL의 XSS 및 XSLT 실행:** `.msc`는 본질적으로 XML 텍스트입니다. `StringTable` 섹션을 조작해 윈도우 도움말 라이브러리 `apds.dll`의 XSS 결함을 트리거하고, URL 인코딩된 XSL(`ms:script` 태그 내 VBScript/JScript)을 `xsl.loadXML(unescape(...))` 형태로 로드해 임의 코드를 실행합니다.
- **자동 권한 상승(Auto-Elevation):** `mmc.exe`는 매니페스트상 자동 권한 상승 바이너리라, 피해자가 로컬 관리자 그룹이면 초기 침투와 동시에 High-integrity(관리자)로 페이로드를 실행할 수 있습니다.

#### [필수 업데이트] GrimResource 패치 현황 및 제약

1. **MS 공식 보안 패치 완료 (최신 빌드 작동 불가):** 공개 후 MS는 정기 보안 업데이트(2024년 하반기 누적 업데이트 등)로 `mmc.exe`·`apds.dll`이 비정상 외부 리소스/인라인 스크립트를 처리하지 못하도록 패치했습니다. 따라서 **최신 패치가 적용된 Win 10(22H2) 및 Win 11(23H2/24H2)에서는 더 이상 작동하지 않습니다.**
2. **EDR의 완벽한 탐지:** 사무직 사용자가 `.msc`를 실행하는 것 자체가 이례적이며, `mmc.exe`가 `apds.dll`을 로드한 뒤 자식 프로세스(`cmd.exe` 등)를 만들거나 `.NET CLR`을 로드하는 행위는 주요 EDR에서 즉시 차단됩니다.

### [호환성 및 보안 업데이트 매트릭스] Part 3 기법 평가

| 트리거 포맷 | 대상 OS 호환성 | 최신 보안 업데이트 영향 | 방어 및 탐지(Blue Team/DFIR) 핵심 |
| --- | --- | --- | --- |
| Batch (`.bat`, `.cmd`) | **모든 Windows 버전** | `%cmdcmdline%` 검증 트릭은 여전히 구형 샌드박스를 우회 가능. 단, 최신 EDR 샌드박스는 Explorer 클릭 이벤트를 시뮬레이션해 파훼. | **Event ID 4688 / Sysmon 1:** 명령줄에 `find /i` + 환경 변수 조합이 포함된 `cmd.exe` 감시. ISO/압축 마운트 경로(`D:\`, `E:\`, `%TEMP%`)에서 실행되는 배치 차단. |
| Shell Link (`.lnk`) | **모든 Windows 버전** (탐색기 기본) | `NeverShowExt` 확장자 숨김은 모든 버전 동일. **CVE-2023-36025 / CVE-2024-21412** 패치로 SmartScreen 우회 버그 대거 수정. | `.lnk` 내부 `Target`이 시스템 인터프리터(`cmd`, `powershell`, `mshta`, `rundll32`)를 가리키면 경고. `.lnk` 내부 타임스탬프 및 공격자 `MachineID`/`MAC` 아티팩트 추출(DFIR). |
| MS Saved Console (`.msc` — GrimResource) | 구형 패치 미적용 Win 10/11 한정 | **최신 누적 패치 적용 시 취약점 패치되어 작동 불가.** VBScript 단계적 퇴출 정책의 직접 영향. | **Sysmon ID 7(ImageLoad):** `mmc.exe`가 비정상적으로 `apds.dll`, `mshtml.dll`, `vbscript.dll`, `jscript.dll`을 연달아 로드하는 행위 탐지. `.msc` XML 내 `apds://`·`loadXML` 문자열 정적 탐지(YARA). |

### [Blue Team / DFIR 심화] LNK 파일 포렌식 아티팩트 (OPSEC)

PowerShell(`WScript.Shell`)로 `.lnk`를 생성하면, 윈도우는 `.lnk` 바이너리 구조(`ExtraData`의 `DistributedLinkTrackerBlock`)에 **생성 컴퓨터의 호스트 이름(NetBIOS), 볼륨 시리얼, MAC 주소까지 자동 기록**합니다.

- **방어자(DFIR) 관점:** 확보한 `.lnk`를 `LECmd`(Eric Zimmerman 도구)로 분석하면 공격자 개발 환경의 컴퓨터 이름·타임스탬프를 특정할 수 있습니다.
- **공격자(OPSEC) 관점:** `.lnk` 생성 시 메타데이터(TrackerDataBlock)를 제거하는 도구를 쓰거나 일회용 클린 VM에서 생성해야 내부 인프라 정보 노출을 막습니다.

---

<a id="containers"></a>

# Containers (컨테이너와 MotW 우회)

### 4.1 Mark of the Web (MotW)의 내부 구조와 역할

MotW은 인터넷/신뢰할 수 없는 외부에서 다운로드된 파일에 윈도우(또는 브라우저·메일 클라이언트)가 자동으로 부착하는 보안 식별자입니다.

- **NTFS 대체 데이터 스트림(ADS):** NTFS는 본래 데이터(`:$DATA`) 외에 숨겨진 부가 스트림을 저장할 수 있습니다. 다운로드 시 브라우저가 `Zone.Identifier` ADS를 만들어 출처를 기록합니다.

```powershell
PS C:\Users\Analyst\Downloads> Get-Content -Stream Zone.Identifier .\test.pdf

[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://.../test.pdf
HostUrl=https://.../test.pdf
```

- **`ZoneId` 값의 의미:** `0` 로컬 컴퓨터 · `1` 로컬 인트라넷 · `2` 신뢰할 수 있는 사이트 · **`3` 인터넷(외부 다운로드에 부여) ⭐** · `4` 제한된 사이트

`ZoneId=3` 태그가 있으면 파일 속성 창에 "다른 컴퓨터에서 왔으며 차단되었을 수 있습니다" 경고가 뜨고, 윈도우는 실행 파일 구동 시 **SmartScreen**을 강제하며, 오피스 문서는 제한된 보기(Protected View)로 매크로를 차단합니다.

### 4.2 컨테이너(Containers)의 목적과 패키징

1. **다중 파일의 단일화 및 은닉:** 트리거(`.lnk`), 페이로드(`.dll`/`.xlam`), 디코이(`.pdf`/`.xlsx`) 등 의존 파일을 한 패키지로 묶습니다. `PackMyPayload` 같은 도구의 `-H` 옵션으로 내부 파일에 **숨김 속성**을 부여해, 피해자가 컨테이너를 열면 트리거 하나만 보이게 조작할 수 있습니다.
2. **MotW 전파 차단:** 컨테이너 자체(예: `test.iso`)는 다운로드되어 MotW(`ZoneId=3`)를 갖지만, 구형 압축/마운트 도구로 해제될 때 **내부 개별 파일에 `Zone.Identifier`를 복사(전파)하지 않는 허점**을 이용해 MotW를 세탁(Stripping)하는 것이 전통적 핵심이었습니다.

### 4.3 [필수 업데이트] 컨테이너 포맷별 MotW 전파 패치 현황 (Win 10 / 11 최신 빌드)

원본 교재는 `.iso`/`.img` 마운트 시 내부 파일의 MotW가 사라진다고 설명하지만, **이 영역은 MS 보안 패치로 가장 극적으로 바뀌었습니다.**

| 컨테이너 포맷 | 윈도우 기본 지원 | 과거 동작 (교재 기준) | 최신 OS 동작 (Win 10 22H2 / Win 11 22H2~24H2) | 현재 작전 유효성 |
| --- | --- | --- | --- | --- |
| `.iso`, `.img` (광학 디스크 이미지) | O (더블 클릭 시 가상 DVD 마운트) | ISO 내부가 ISO-9660/UDF라 ADS 미지원 → 내부 파일 MotW 소멸. | **[패치됨 — CVE-2022-41091 등]** 커널 드라이버가 마운트된 ISO/IMG 원본에 MotW가 있으면 **내부 모든 파일에도 MotW(`ZoneId=3`)를 자동 상속**. | **[MotW 우회 불가]** 여러 파일 묶기·숨김 용도로는 가능하나, MotW 세탁용으로는 더 이상 작동 안 함. |
| `.vhd`, `.vhdx` (가상 하드 디스크) | O (더블 클릭 시 가상 디스크 마운트) | 별도 로컬 디스크로 인식되어 MotW 미전파 우회 수단으로 각광. | **[패치됨]** VHDMP 드라이버 업데이트로 원본 VHD의 MotW가 마운트 볼륨 내부 파일에 전파되도록 패치. | **[낮음]** 일반 사무 환경에서 VHD 마운트 시 즉각 EDR 알람. |
| `.zip` (표준 압축) | O (탐색기 내장) | 기본 탐색기 해제 시 MotW 전파, 7-Zip/WinRAR로 풀면 소멸. | **[강화됨]** 기본 탐색기는 전파. 최신 WinRAR·7-Zip(옵션 활성화 시)도 패치로 MotW를 전파하도록 업데이트. | **[중간]** MotW 우회보다는 이메일 게이트웨이 정적 스캔 회피를 위한 **비밀번호 걸린 ZIP** 형태로 여전히 널리 쓰임. |
| `.7z`, `.rar`, `.tar`, `.gz` | **O (Win 11 23H2부터 기본 내장 ⭐)** | 과거엔 기본 미지원 → 별도 압축 프로그램 없으면 열지 못함. | **[Win 11의 대변화]** Win 11(23H2+)부터 오픈소스 `libarchive`가 탐색기에 기본 통합되어 **별도 프로그램 없이 기본 해제** 가능. | **[높음 — 신규 연구 타겟]** `libarchive` 통합 초기에 특수 포맷 해제 시 MotW 누락 버그 다수 발견(지속적 패치 대상). |
| `.wim` (Windows Imaging) | △ (7-Zip 등으로 열람) | 파일 패키징에 활용 가능. | 일반 사용자가 더블 클릭만으로 마운트 불가, 서드파티 아카이버 설치 환경에서만 유효. | **[낮음]** 사용자 편의성이 떨어져 제한적 타겟에만 사용. |

---

<a id="delivery"></a>

# Delivery (경계 보안 우회 및 전달)

딜리버리는 완성된 패키지를 타겟 기업의 다층 경계 보안(방화벽, 이메일 게이트웨이, 웹 프록시, 네트워크 샌드박스)에 발각되지 않고 엔드포인트까지 도달시키는 기술입니다.

### 5.1 HTML Smuggling (HTML 밀수 기법)

#### 핵심 원리 및 메커니즘

전통적 방식은 웹 서버에 악성 파일을 올려두고 다운로드시키는데, 이때 네트워크 패킷의 MIME 타입과 바이너리 본문이 웹 프록시/보안 장비에 그대로 노출되어 차단됩니다. **HTML Smuggling**은 HTML5(`download` 속성) + JavaScript(`Blob` API)를 결합해 **네트워크에 바이너리 전송 트래픽을 전혀 발생시키지 않고, 피해자 브라우저 메모리 내부에서 직접 파일을 조립**하는 기법입니다.

```
[전통적 다운로드 vs. HTML Smuggling 네트워크 트래픽 비교]

❌ 전통적 다운로드:
[공격자 웹서버] ─(HTTP: application/octet-stream + 악성 바이너리)─> [웹 프록시/방화벽] 💥 차단

✅ HTML Smuggling:
[공격자 웹서버] ─(HTTP: text/html + 평범한 텍스트/JS 문자열)─> [웹 프록시 통과] ─> [피해자 브라우저 도착]
                                                                                │
                                                        ┌───────────────────────┘
                                                        ▼
                                             [브라우저 내부 JS 실행]
                                             1. Base64/암호화 문자열 복호화 (atob / Web Crypto API)
                                             2. Uint8Array로 변환 후 Blob 객체 생성
                                             3. 가상 <a> 태그 생성 및 자동 클릭으로 로컬에 파일 드롭
```

작동 흐름: ① 전달할 컨테이너(예: `.iso`/`.zip`)를 Base64로 인코딩해 HTML 내 JS 변수에 텍스트로 삽입 → ② 프록시는 단순 텍스트(HTML/JS)로 인식해 통과 → ③ 브라우저에서 `atob()`로 디코딩, `Uint8Array`로 변환 후 `new Blob(...)` 생성 → ④ `URL.createObjectURL()`로 로컬 객체 URL을 만들고 보이지 않는 `<a>`를 자동 클릭해 다운로드 폴더에 파일을 드롭.

#### [심화] 최신 보안 장비의 탐지와 우회

- **탐지 현황:** 최신 이메일 게이트웨이·NGFW는 `atob`, `Uint8Array`, `Blob`, `msSaveOrOpenBlob`, `createObjectURL` 등의 키워드 조합이 나타나면 HTML Smuggling으로 판단해 정적 차단하고, Base64 문자열을 직접 디코딩해 보기도 합니다.
- **우회 전략:** ① 단순 Base64 대신 **AES-GCM 등으로 암호화**해 넣고 브라우저에서 `crypto.subtle.decrypt()`로 런타임 복호화 → 복호화 키 없이는 내용 식별 불가. ② 핵심 API 문자열을 난독화하거나 페이로드를 여러 조각으로 쪼개 외부 JSON/이미지 메타데이터에서 불러와 합쳐 정적 시그니처 회피.

### 5.2 SVG Smuggling (벡터 그래픽 이미지 밀수)

SVG는 **XML 기반 텍스트 이미지 포맷**인데, 표준 규격상 이미지 내부에 `<script>` 태그로 실행 가능한 JavaScript를 직접 삽입할 수 있습니다.

```xml
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40" stroke="black" stroke-width="4" fill="none" />
  <script>
    // SVG가 브라우저에서 열리는 순간 내부 JS(예: HTML Smuggling 로직)가 실행됨 — PoC
    alert('Hello World');
  </script>
</svg>
```

- **전달·실행상의 이점:** 이메일 필터에서 `.html`/`.htm`은 차단하는 기업이 많지만, `.svg`는 이미지로 분류되어 통과하는 경우가 많습니다. 윈도우에서 `.svg` 기본 연결 프로그램은 **Microsoft Edge**라, 피해자가 이미지인 줄 알고 더블 클릭하면 Edge가 열리며 내부 자바스크립트가 실행됩니다.

### 5.3 Cobalt Strike Site Clone & Drive-By Download

직접 Apache/Nginx를 세우는 대신, C2 프레임워크 **Cobalt Strike**의 내장 웹 서버와 **Site Cloner** 기능으로 피싱 사이트와 자동 다운로드(Drive-by) 환경을 구축하는 기법입니다.

구축 흐름 요약: ① **Host File**로 패키지를 팀 서버 웹 서버에 업로드하되 실제 다운로드 경로처럼 보이는 `Local URI`와 타이포스쿼팅 도메인을 설정 → ② **Clone Site**로 정상 사이트를 복제하고 `Attack`에 악성 파일 URL 지정(로그인 페이지 복제 시 키 입력 가로채기 옵션도 존재) → ③ 복제 페이지 하단에 크기 `0`의 보이지 않는 `<IFRAME>`을 삽입해 접속만 해도 파일이 다운로드되게 함.

```html
<IFRAME SRC="http://.../GPU-Z.2.22.0.exe?id=null" WIDTH="0" HEIGHT="0"></IFRAME>
```

#### 최신 보안 업데이트 및 OPSEC (매우 중요 ⭐)

원본 교재 실습을 실전에 그대로 적용하면 거의 실패하거나 즉시 차단됩니다.

1. **HTTP(80) 종말과 혼합 콘텐츠 차단:** 최신 Chrome/Edge는 평문 HTTP 접속에 경고를 띄우고, HTTPS 페이지 내 숨겨진 HTTP `<iframe>`에서 실행 파일을 자동 다운로드하려는 시도를 '안전하지 않은 다운로드' 및 '드라이브 바이'로 간주해 조용히 차단합니다. 따라서 유효한 SSL/TLS 인증서(Let's Encrypt 등)로 HTTPS(443) 구성이 필수입니다.
2. **팀 서버 핑거프린팅과 리다이렉터 필수:** Cobalt Strike 내장 웹 서버는 고유 HTTP 응답 헤더/기본 에러 페이지 특징이 있어 Shodan·Censys나 위협 인텔리전스에 IP가 즉시 노출됩니다. 팀 서버를 직접 노출하지 말고 앞단에 Apache/Nginx 또는 Cloudflare Workers 기반 리다이렉터를 두어 정상 트래픽만 필터링·전달하도록 인프라를 은닉해야 합니다.

---

<a id="trends"></a>

# 부록. 2025~2026 최신 초기 침투 트렌드 총정리

파일 기반 피싱을 넘어, 현재 현업 레드팀과 실제 위협 그룹(APT·랜섬웨어)이 가장 활발히 쓰는 최신 기법 3가지입니다.

### 6.1 Device Code Phishing & AiTM (다중 인증 우회 피싱)

- **배경:** 클라우드(Microsoft 365, Entra ID) 전환과 MFA 도입으로, 악성코드 실행보다 **클라우드 세션 토큰 탈취**로 초기 침투를 달성하는 비중이 폭증했습니다.
- **AiTM (Adversary-in-the-Middle):** `Evilginx` 같은 리버스 프록시 피싱으로 피해자가 가짜 로그인에서 MFA까지 완료하는 순간 발급되는 세션 쿠키(`ESTSAUTH` 등)를 가로채 MFA를 무력화합니다.
- **Device Code Phishing:** 스마트 TV/IoT 로그인에 쓰는 OAuth 2.0 디바이스 인증 흐름을 악용합니다. 공격자가 먼저 인증 코드를 발급받고, 피해자에게 "마이크로소프트 공식 인증 페이지에 접속해 이 코드를 입력하라"고 유도합니다. 피해자는 **실제 MS 정상 도메인**에서 코드를 입력하므로 프록시·피싱 탐지를 우회하며, 인증 완료 즉시 공격자 도구(`TokenTactics` 등)로 액세스·리프레시 토큰이 들어옵니다.

### 6.2 Microsoft Teams(외부 테넌트) 피싱 & ClickFix

- **Teams 피싱:** 이메일 게이트웨이가 강력해지자, 외부 테넌트 채팅이 기본 허용된 **Teams**로 사내 헬프데스크를 위장해 직접 메시지를 보내 악성 링크/페이로드를 전달합니다.
- **ClickFix(클릭픽스):** 최근 대유행하는 기법으로, "문서를 보려면 업데이트가 필요하다" 등의 가짜 안내창을 띄워 피해자가 `Win + R` 실행 창에 클립보드에 복사된 난독화된 PowerShell/Mshta 명령을 직접 붙여넣어 실행하게 만듭니다. **사용자가 직접 입력한 명령은 파일 다운로드(MotW)·메일 첨부 검사를 전혀 거치지 않아** 경계 보안을 완벽히 무력화합니다.

### 6.3 엣지 디바이스 제로데이 및 원격 RMM 도구 악용

- **경계 장비 익스플로잇:** 피싱 대신 외부 노출된 VPN·방화벽·파일 전송 어플라이언스(Ivanti, Fortinet, Palo Alto, Citrix 등)의 취약점을 직접 타격해 EDR이 없는 리눅스 어플라이언스에 웹쉘/백도어를 심고 내부망으로 피벗(Pivot)합니다.
- **정상 RMM 설치 유도:** C2 비콘은 EDR에 탐지될 위험이 있으므로, 초기 침투 시 합법 서명된 상용 원격 제어(RMM) 설치 파일(AnyDesk, ScreenConnect, Atera, Action1 등)을 내려보내 실행하게 한 뒤 정식 채널로 거점을 확보합니다.

---

## [최종 요약] Blue Team / DFIR 초기 침투 방어 체크리스트

| 방어 계층 | 대응 대상 공격 | 핵심 방어 및 탐지 전략 (Actionable) |
| --- | --- | --- |
| 1. 네트워크 및 브라우저 | HTML/SVG Smuggling, Drive-by, AiTM/Device Code 피싱 | 이메일 첨부·웹 프록시에서 `.svg`, `.iso`, `.img`, `.vhd`, `.lnk`, `.msc` 확장자 원천 차단. 엔터프라이즈 브라우저 정책(GPO/Intune)으로 비업무 사이트 실행 파일 자동 다운로드 차단. **FIDO2 기반 피싱 저항성 MFA(Passkey·하드웨어 키)** + 조건부 액세스(등록 기기에서만 로그인). |
| 2. 운영체제 및 컨테이너 | ISO/VHD 마운트, LNK/BAT/MSC 트리거, ClickFix(`Win+R`) | GPO로 일반 사용자의 `.iso`/`.vhd` 자동 마운트 연결 해제 및 `Microsoft-Windows-VHDMP-Operational`(Event ID 1, 12) 중앙 수집. 레지스트리 `RunMRU` 모니터링으로 `Win+R`에 `powershell`/`mshta`/`cmd`/`curl` 직접 입력(ClickFix) 실시간 탐지. |
| 3. 엔드포인트 및 프로세스 | DLL Side-Loading, AppDomainManager, MSI/XLAM/RMM 악용 | **Defender ASR 규칙** 전면 활성화(오피스 자식 프로세스 생성 차단, WMI/PsExec 제한 등). **WDAC** 또는 AppLocker로 `C:\ProgramData`, `%APPDATA%`, `%TEMP%` 등 쓰기 가능 경로에서 미서명 바이너리·비승인 RMM 실행 차단. 서명됐더라도 `OriginalFilename`과 현재 프로세스명이 다르거나 비정상 경로에서 미서명 DLL을 로드하는 이벤트(Sysmon ID 7) 중점 헌팅. |

---

*본 문서는 CRTO 학습 노트를 기반으로 재정리한 개인 레퍼런스이며, 방어·탐지(Blue Team/DFIR) 학습 목적입니다.*
