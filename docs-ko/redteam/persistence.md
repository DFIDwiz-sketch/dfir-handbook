---
title: 지속성 유지 (Persistence)
tags:
  - redteam
  - persistence
---

# 지속성 유지 (Persistence) 마스터 매뉴얼

!!! abstract "이 문서에 대하여"
    CRTO(Certified Red Team Operator) 교재의 Persistence 챕터를 기반으로, **Windows 10 / 11 버전별 동작**, **일부 레거시 기법이 왜 더 이상 작동하지 않는지**, 그리고 최신 **EDR/DFIR 탐지 매트릭스**까지 보강해 재정리한 학습용 레퍼런스입니다.
    이 핸드북의 다른 부분처럼 **작동 원리와 탐지 아티팩트** — 공격자가 무엇을 건드리고 어떤 흔적이 남는지 — 에 초점을 둡니다. 예시는 무기화 코드가 아니라 개념 수준(레지스트리 경로, 흐름도)으로 유지합니다.

!!! note "구성 (총 3개 파트)"
    - **Part 1** — 지속성의 개념, OPSEC 원칙, 사용자 권한(User-Land) 지속성 (레지스트리 Run 키, 시작프로그램 폴더, 예약된 작업)
    - **Part 2** — 고급 은닉 지속성 (COM Hijacking, WMI Event Subscription, Windows Services)
    - **Part 3** — 시스템 후킹, 기존 자원 변조, 애플리케이션 레벨 지속성 (`.lnk` 변조, IFEO/SilentProcessExit, Winlogon, ServiceDll 하이재킹, Office/PowerShell/개발도구 지속성, RID Hijacking)

## 목차

- [1. 개요 및 OPSEC 원칙](#overview)
- [2. User-Land 지속성](#userland)
- [3. 고급 은닉 지속성 (Part 2)](#advanced)
- [4. 시스템 후킹 및 기존 자원 변조 (Part 3)](#part3)

---

<a id="overview"></a>

# 지속성 유지 — 개요 및 OPSEC

## 1. 지속성(Persistence)의 개요 및 작전 보안(OPSEC) 원칙

### 1.1 Persistence란 무엇인가?

Persistence(MITRE ATT&CK: TA0003)는 초기 침투(Initial Access)를 통해 어렵게 확보한 타겟 시스템의 접근 권한을 유지하기 위한 전술입니다. 피해자가 컴퓨터를 끄거나(Reboot), 로그오프하거나, 실행 중이던 프로세스가 크래시(Crash)되더라도 공격자의 C2 비콘(Beacon)이 다시 살아나 연결을 복구할 수 있도록 시스템 곳곳에 '뒷문(Backdoor)'이나 '자동 실행 트리거'를 심어두는 작업입니다.

### 1.2 레드팀의 지속성 설계 3대 원칙

1. **권한 수준(Privilege Level)의 구분:** 현재 확보한 권한이 일반 표준 사용자(Standard User / Medium Integrity)인지, 로컬 관리자(Local Admin / High Integrity)인지에 따라 사용할 수 있는 기법이 완전히 달라집니다. 초기 침투 직후에는 일반 사용자 권한인 경우가 많으므로 **User-Land Persistence**가 먼저 수행됩니다.
2. **페이로드와 트리거의 분리(OPSEC):** 지속성 위치(예: 레지스트리 Run 키)에 `powershell.exe -enc ...` 같은 노골적인 명령어나 서명되지 않은 악성 `.exe`를 직접 등록하면 백신(AV)과 블루팀의 `Autoruns` 점검에 1초 만에 발각됩니다. Initial Access에서 다룬 **DLL Side-Loading**이나 **.NET AppDomainManager** 기법을 지속성 트리거와 결합하여 마치 정상 프로그램이 자동 실행되는 것처럼 위장해야 합니다.
3. **생존성(Resilience)과 정리(Cleanup):** 너무 잦은 주기로 실행되면 네트워크 트래픽과 프로세스 생성 로그가 과도하게 발생하여 탐지됩니다. 반대로 너무 흔한 기본 경로를 쓰면 쉽게 제거됩니다.

---

<a id="userland"></a>

# User-Land 지속성

초기 침투 직후 로컬 관리자 권한(UAC 통과 전)이 없을 때, 현재 로그인한 사용자의 컨텍스트 내에서 재부팅이나 재로그인 시 페이로드를 다시 실행시키는 기본이자 핵심 기법들입니다.

### 2.1 레지스트리 자동 실행 키 (Run / RunOnce)

#### 핵심 원리 및 메커니즘

윈도우는 사용자가 로그인할 때 특정 레지스트리 경로에 등록된 프로그램들을 자동으로 실행합니다. 일반 사용자 권한에서는 시스템 전체 설정인 `HKLM(HKEY_LOCAL_MACHINE)`은 수정할 수 없지만, 현재 사용자 설정인 **`HKCU(HKEY_CURRENT_USER)`** 하이브는 자유롭게 수정할 수 있습니다.

- **주요 레지스트리 경로:**
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (로그인할 때마다 매번 실행)
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` (다음 로그인 시 1회 실행 후 값 자동 삭제)
    - *(관리자 권한 필요)* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (모든 사용자 로그인 시 실행)

```
[레지스트리 Run 키 작동 흐름]

[사용자 Windows 로그인]
       │
       ▼
[userinit.exe -> explorer.exe 초기화]
       │
       ▼
[HKCU\...\CurrentVersion\Run 레지스트리 조회]
       │
       ▼
[등록된 값(데이터) 실행: 예) C:\ProgramData\LegitApp\Updater.exe]
       │
       ▼
[DLL Side-Loading 작동 -> 같은 폴더의 악성 DLL 로드 -> C2 재연결]
```

#### 최신 보안 업데이트 및 제약 사항 (Win 10 / Win 11)

1. **작업 관리자 및 시작 앱 알림:** Win 10/11에서는 `HKCU\...\Run`에 새 항목이 등록되면 시스템 트레이에 "새 시작 앱이 추가되었습니다" 토스트 알림이 뜰 수 있으며, `작업 관리자 -> 시작프로그램(Startup apps)` 탭 목록에 그대로 노출됩니다.
2. **EDR의 실시간 레지스트리 모니터링:** 모든 상용 EDR과 Microsoft Defender는 `CurrentVersion\Run` 키에 값이 쓰여지는 순간(Registry Value Set) 그 대상 경로의 파일을 즉시 정적/동적 스캔합니다. 따라서 드로퍼나 C2 비콘 `.exe`를 직접 연결하는 것은 금물이며, 반드시 **정상 서명된 바이너리(DLL Side-loading 호스트)나 스크립트가 숨겨진 정상 루틴**을 가리키도록 구성해야 합니다.

### 2.2 시작프로그램 폴더 (Startup Folder)

#### 핵심 원리 및 메커니즘

레지스트리 Run 키와 유사하게, 윈도우 탐색기(`explorer.exe`)가 시작될 때 특정 특수 폴더 안의 모든 파일이나 바로가기(`.lnk`)를 자동으로 실행하는 기능입니다.

- **주요 경로:**
    - **현재 사용자 전용 (표준 권한 쓰기 가능):** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` (전체 경로: `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
    - **모든 사용자 공통 (관리자 권한 필요):** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
- **운용 메커니즘:** 이 폴더에 실행 파일(`.exe`)을 직접 넣는 대신, 실제 페이로드(예: DLL 사이드로딩 패키지)는 `%LocalAppData%`나 `C:\ProgramData` 깊숙한 곳에 숨겨두고, 시작프로그램 폴더에는 그 파일을 가리키는 **바로가기(`.lnk`) 파일**만 생성해 두는 것이 일반적입니다.

#### 최신 보안 업데이트 및 방어 포인트

- **탐지 취약성:** 시작프로그램 폴더는 블루팀과 백신이 가장 먼저 검사하는 1순위 경로입니다. Sysmon Event ID 11(FileCreate)에서 경로에 `\Start Menu\Programs\Startup\`이 포함된 파일 생성 이벤트는 거의 모든 SOC(보안관제센터)에서 기본 알람으로 설정되어 있습니다.

### 2.3 예약된 작업 (Scheduled Tasks)

#### 핵심 원리 및 메커니즘

윈도우의 작업 스케줄러(Task Scheduler)는 특정 시간이나 특정 시스템 이벤트가 발생할 때 프로그램을 실행합니다. 많은 이들이 관리자 권한이 있어야만 예약된 작업을 만들 수 있다고 오해하지만, **일반 표준 사용자(Standard User)도 자신의 권한으로 실행되는 예약된 작업을 생성할 수 있습니다.**

- **권한에 따른 트리거(Trigger) 제약 사항 비교:**

| 트리거 유형 (실행 조건) | 필요 권한 | 특징 및 활용도 |
| --- | --- | --- |
| **특정 시간 / 주기적 반복** (Daily, Weekly, Every X hours) | 일반 사용자 | 가장 무난하게 사용 가능. 예: 매일 오전 9시 30분(출근 시간)이나 1시간마다 실행하여 비콘이 죽어도 다시 살아나게 구성. |
| **시스템 유휴 상태 시** (On Idle) | 일반 사용자 | 사용자가 자리를 비웠을 때 실행되어 눈치채기 어려움. |
| **사용자 로그온 시** (At Logon) | 관리자 권장 (특정 조건 시 일반 사용자 가능하나 제한적) | 전체 사용자 로그온 트리거는 기본적으로 High Integrity 권한 요구. |
| **시스템 시작 시** (At Startup) | 관리자 (High Integrity / SYSTEM) | 사용자가 로그인하기 전 부팅 단계에서 `SYSTEM` 권한으로 실행. |

- **작동 구조:** `schtasks.exe`, PowerShell의 `New-ScheduledTask` cmdlet, 또는 Task Scheduler COM 객체(`Schedule.Service`)로 작업을 등록합니다. 작업이 생성되면 `C:\Windows\System32\Tasks\` 경로에 XML 파일 형태로 정의가 저장되며, 레지스트리 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`에 캐시 정보가 등록됩니다.

#### 최신 보안 업데이트 및 OPSEC 포인트

1. **`schtasks.exe` 프로세스 생성 탐지 회피:** 명령줄에서 `schtasks.exe /create ...`를 실행하면 프로세스 생성 로그(Event ID 4688, Sysmon ID 1)에 명령줄 인자가 그대로 찍혀 EDR에 즉시 발각됩니다. 따라서 현대 레드팀(및 Cobalt Strike 등의 BOF)은 `schtasks.exe`를 호출하지 않고, 메모리상에서 직접 **COM API(`ITaskService`)나 RPC(`ATSvc` / `ITaskSchedulerService`)를 호출**하여 프로세스 생성 없이 조용히 작업을 등록합니다.
2. **Windows 보안 이벤트 로그 (Event ID 4698):** COM/RPC로 `schtasks.exe` 실행을 숨기더라도, 작업 스케줄러 서비스 자체가 새 작업 등록 시 **Security 로그의 Event ID 4698(예약된 작업 생성됨)** 및 **`Microsoft-Windows-TaskScheduler/Operational` 로그의 Event ID 106**을 기록합니다. 따라서 작업 이름을 `Updater`나 `Maintenance`처럼 어색하게 짓는 대신, 기존 마이크로소프트나 크롬/엣지의 정상 업데이트 작업 이름 및 폴더 구조와 유사하게 위장(Masquerading)하는 것이 핵심입니다.

### [Part 1 요약] User-Land 지속성 기법 비교

| 지속성 기법 | 필요 권한 | 실행 시점 (Trigger) | 남는 주요 흔적 | 은닉성 |
| --- | --- | --- | --- | --- |
| **Registry Run Keys** (`HKCU\...\Run`) | 일반 사용자 | 사용자 로그인 시 (`explorer.exe` 구동 시) | 레지스트리 값 변경(Sysmon ID 13); 작업 관리자 '시작프로그램' 탭 노출 | ★★☆☆☆ (매우 흔하고 잘 알려짐; DLL Sideloading 결합 필수) |
| **Startup Folder** (`...\Programs\Startup`) | 일반 사용자 | 사용자 로그인 시 | 폴더 내 `.lnk` 또는 파일 생성(Sysmon ID 11) | ★☆☆☆☆ (파일 시스템에 직접 노출; 탐지율 매우 높음) |
| **Scheduled Tasks** | 일반 사용자 / 관리자 모두 | 시간 주기, 유휴, 로그온, 부팅 등 | `C:\Windows\System32\Tasks\` 내 XML 생성; Security Event ID 4698 / TaskScheduler ID 106 | ★★★☆☆ (COM/BOF로 생성하고 정상 작업으로 위장 시 매우 유용) |

---

<a id="advanced"></a>

# 고급 은닉 지속성

User-Land 권한에서 레지스트리 Run 키나 시작프로그램 폴더에 등록하는 방식은 블루팀의 `Autoruns` 스캔에 쉽게 노출됩니다. 공격자는 AV/EDR의 정적 점검을 우회하기 위해 운영체제의 정상적인 내부 컴포넌트나 관리 기능을 가로채는(Hijacking) 고급 지속성 기법을 활용합니다.

### 3.1 COM Hijacking (Component Object Model)

#### 핵심 원리 및 메커니즘

윈도우의 COM(Component Object Model)은 소프트웨어 부품들이 서로 통신하고 기능을 공유하는 핵심 아키텍처입니다. 수많은 정상 응용프로그램과 시스템 서비스가 실행될 때 특정 COM 클래스 ID(**CLSID**)를 가진 객체를 호출합니다.

- **CLSID 검색 순서:** 윈도우가 특정 CLSID 객체를 요청할 때, 시스템 전역 설정인 `HKCR(HKEY_CLASSES_ROOT)`나 `HKLM`을 뒤지기 전에 **현재 로그인한 사용자의 레지스트리 경로인 `HKCU\Software\Classes\CLSID`를 먼저 참조**합니다.
- **하이재킹 구조:** 정상 프로그램이 부팅이나 특정 이벤트 때 자주 호출하는 고유 CLSID가 있다면, 공격자는 `HKCU\Software\Classes\CLSID\{대상-CLSID}\InprocServer32`(또는 `LocalServer32`) 경로를 수동 생성하고, 그 값에 정상 DLL 대신 **악성 페이로드(또는 사이드로딩용 DLL)의 경로**를 등록합니다.

```
[정상 프로그램 실행 시점]
       │
       ▼
[특정 CLSID 객체 호출] ──> [HKCU(사용자 레지스트리) 우선 검색] ──> [공격자가 등록한 악성 DLL 경로 발견]
                                                                       │
                                                                       ▼
                                                         [정상 프로그램 내부로 악성 DLL 강제 로드]
```

- **대표적인 타겟 선정:** 사용자가 로그인할 때 자동 실행되는 백그라운드 앱(예: OneDrive 설정 유틸리티, 작업 표시줄 알림 프로그램)이 부팅 직후 빈번하게 로드하려다 실패하는(`NAME NOT FOUND`) COM 객체를 타겟으로 삼으면 시스템 충돌 없이 자연스럽게 비콘을 살려냅니다.

#### 최신 보안 업데이트 및 방어 포인트

- **EDR 탐지 메커니즘:** 최신 EDR은 `HKCU\Software\Classes\CLSID` 경로에 새 키가 생성되거나, 하위 `InprocServer32` 값이 비정상 경로(`.exe`, `.dll`)나 스크립트 핸들러를 가리키도록 수정되는 행위를 실시간 감시·차단합니다.

### 3.2 WMI Event Subscription (WMI 이벤트 구독)

#### 핵심 원리 및 메커니즘

WMI(Windows Management Instrumentation)는 윈도우 관리 정보를 조회·제어하는 강력한 내장 프레임워크입니다. **이벤트 구독(Event Subscription)** 기능을 이용하면 "특정 시간이 되었을 때"나 "특정 프로세스가 실행될 때" 같은 조건(Event)이 충족되면 지정된 페이로드(Consumer)를 자동 실행하도록 설정할 수 있습니다.

- **WMI 지속성의 3가지 핵심 요소:**
    1. **`__EventFilter` (조건 필터):** 어떤 시스템 이벤트에 반응할지 조건을 정의 (예: 부팅 후 180분 경과, 특정 관리자 도구 실행 시).
    2. **`__EventConsumer` (실행 소비자):** 조건 만족 시 **무엇을 할지** 정의. 주로 `CommandLineEventConsumer`로 지정 명령어·스크립트를 은밀하게 호출.
    3. **`__FilterToConsumerBinding` (연결 바인딩):** 위 필터와 소비자를 연결해 짝을 지음.
- **디스크 없는(Fileless) 저장:** WMI 객체는 디스크에 `.exe` 형태로 존재하지 않고 WMI 리포지토리 DB(`C:\Windows\System32\wbem\Repository\OBJECTS.DATA`) 내부에 저장됩니다. 파일 스캔 기반 백신은 쉽게 찾아내지 못합니다.

#### 최신 보안 업데이트 및 방어 포인트

- **로컬 관리자 권한 필수:** WMI 이벤트 구독의 생성·수정은 기본적으로 **로컬 관리자(High Integrity) 또는 SYSTEM 권한**이 필요합니다. (초기 침투 직후 일반 사용자 권한으로는 생성 불가.)
- **방어자(DFIR) 탐지 전략:** PowerShell로 등록된 모든 필터·소비자를 조회(`Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer`)하거나, Sysmon Event ID 19·20·21(WMI 모니터링)로 스크립트가 포함된 WMI 소비자 생성 로그를 탐지합니다.

### 3.3 Windows Services (윈도우 서비스)

#### 핵심 원리 및 메커니즘

백그라운드에서 상시 구동되는 윈도우 서비스를 이용하는 전통적이면서 가장 확실한 시스템 지속성 기법입니다.

- **권한 요건 및 작동 방식:** 새 서비스를 등록하려면 **로컬 관리자 또는 SYSTEM 권한**이 필수입니다. 등록되면 부팅 시(`Automatic` 시작 유형) 사용자 로그인 여부와 무관하게 `Scm.exe`(Service Control Manager)에 의해 즉시 구동됩니다.
- **OPSEC 은닉 전략:** 새 서비스의 이름·설명을 마이크로소프트 정상 서비스(예: `Windows Update Medic Service`)와 유사하게 짓고, 실행 파일 경로(`BinPath`)도 정상처럼 위장된 경로와 DLL Side-loading 호스트를 가리키도록 설정합니다.

### [Part 2 요약] 고급 은닉 지속성 기법 비교

| 지속성 기법 | 필요 권한 | 저장 위치 | AV/EDR 탐지 난이도 | 특징 및 한계 |
| --- | --- | --- | --- | --- |
| **COM Hijacking** | 일반 사용자 / 관리자 모두 | `HKCU\Software\Classes\CLSID\` | 중상 | 디스크에 악성 파일이 없어도 정상 프로그램을 매개로 로드. 타겟 CLSID 분석 필요. |
| **WMI Event Subscription** | 로컬 관리자 필수 (High / SYSTEM) | WMI 리포지토리 (`OBJECTS.DATA`) | 상 (Fileless) | 파일이 아니라 DB 내부에 숨겨져 정적 스캔 우회. 단 관리자 권한 선행 필요. |
| **Windows Services** | 로컬 관리자 필수 (High / SYSTEM) | 레지스트리 `HKLM\SYSTEM\CurrentControlSet\Services\` | 하~중 | 부팅 시 무조건 실행되나 `Autoruns`·서비스 툴에 쉽게 노출되어 위장 필수. |

---

<a id="part3"></a>

# 시스템 후킹, 기존 자원 변조 및 애플리케이션 레벨 지속성

새 파일이나 레지스트리 키를 '생성'하는 방식은 보안 이벤트 로그와 EDR에 쉽게 포착됩니다. 따라서 숙련된 레드팀은 시스템에 이미 존재하는 정상 설정·바로가기·서비스·업무용 프로그램을 은밀하게 '수정'하여 지속성을 확보합니다.

### 4.1 기존 바로가기(`.lnk`) 변조 및 `StartIn` 디렉터리 하이재킹

#### 왜 '새로 만드는 것'보다 '기존 것을 고치는 것'이 유리한가?

시작프로그램 폴더에 새 `.lnk`를 생성하면 부팅 시 실행되지만 블루팀 감시망(Sysmon Event ID 11)에 즉시 걸립니다. 반면 피해자가 매일 자발적으로 클릭하는 **바탕화면이나 작업 표시줄에 이미 고정된 브라우저(Chrome, Edge)·메신저(Teams, Slack) 바로가기**를 수정하면 부팅 시점의 자동 실행 검사를 완전히 피할 수 있습니다.

- **주요 타겟 경로 (일반 사용자 권한 수정 가능):**
    - 바탕화면: `%USERPROFILE%\Desktop\`
    - 작업 표시줄 고정 아이콘: `%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\`

```
[기존 바로가기(.LNK) 변조의 2가지 접근법과 OPSEC 차이]

방식 A: 대상 경로(TargetPath) 직접 변조 (과거 방식 - 탐지 위험 높음 ⚠️)
  • 수정 전: "C:\Program Files\Google\Chrome\Application\chrome.exe"
  • 수정 후: "C:\Windows\System32\cmd.exe /c start payload.exe && start chrome.exe"
  ▶ 문제점: explorer.exe -> cmd.exe 프로세스 트리 발생, 깜빡이는 검은 창, EDR 명령줄 탐지에 발각.

방식 B: 시작 위치(WorkingDirectory / StartIn) 변조 + DLL Side-Loading (최신 고급 OPSEC ⭐)
  • 대상 경로(TargetPath): "C:\...\App.exe" (원본 그대로 유지! 명령줄 인자 변조 없음!)
  • 시작 위치(StartIn)   : "C:\Users\Victim\AppData\Local\CustomFolder\" (공격자 악성 DLL이 숨겨진 폴더)
  ▶ 작동 원리: 피해자가 아이콘을 클릭하면 정상 App.exe가 실행되면서, '현재 작업 디렉터리'로 지정된
    CustomFolder에서 DLL을 먼저 찾아 로드함.
```

#### 최신 보안 업데이트 및 제약 사항

1. **DLL 검색 순서와 `SafeDllSearchMode`:** 윈도우 XP SP2 이후 모든 최신 Win 10/11에는 `SafeDllSearchMode`가 기본 활성화되어 있습니다. 이 모드에서 '현재 작업 디렉터리(`StartIn`)'는 시스템 폴더(`System32`)보다 검색 우선순위가 밀립니다(5순위). 따라서 `StartIn` 변조 기법은 타겟 프로그램이 **`System32`에는 없는 고유 이름의 DLL을 로드하려 시도(`NAME NOT FOUND`)하는 경우**에만 작동합니다.
2. **`%LocalAppData%` 기반 설치 앱의 직접 사이드로딩 (Teams, OneDrive, Slack, Discord):** 최근 많은 엔터프라이즈 앱은 관리자 권한 없이 업데이트하기 위해 `C:\Program Files`가 아닌 **`%LOCALAPPDATA%\Microsoft\OneDrive`, `%LOCALAPPDATA%\Discord` 등 일반 사용자 쓰기 가능 경로에 설치**됩니다. 이 경우 `.lnk`를 건드릴 필요 없이, 해당 프로그램 설치 폴더 안에 프록시 처리된 악성 DLL을 넣어두면 사용자가 앱을 켤 때마다 1순위 검색 경로(애플리케이션 폴더)에서 무조건 로드됩니다.

### 4.2 IFEO(`Image File Execution Options`)와 `SilentProcessExit`

#### 핵심 원리 및 메커니즘

**IFEO**는 원래 개발자가 애플리케이션의 메모리 힙(Heap) 설정을 조정하거나 실행 즉시 디버거를 연결하기 위해 만든 윈도우 커널/로더 기능입니다. **(로컬 관리자 권한 필수)**

1. **기본 `Debugger` 후킹:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe` 경로에 문자열 값 `Debugger`를 만들고 페이로드 경로를 넣으면, 사용자가 메모장(`notepad.exe`)을 실행할 때 커널이 이를 가로채어 페이로드를 대신 실행합니다. (원래 메모장이 열리지 않아 눈치채기 쉬우므로 페이로드가 메모장을 다시 실행해 주어야 함.)
2. **고급 `SilentProcessExit`:** 프로그램이 '실행될 때'가 아니라 **사용자가 다 쓰고 '창을 닫을 때(종료될 때)'** 윈도우 오류 보고 시스템(`werfault.exe`)을 통해 백그라운드에서 페이로드를 실행하는 훨씬 은밀한 기법입니다.

```
[SilentProcessExit 작동 아키텍처 및 필수 레지스트리 설정]

[사전 설정: 2개의 레지스트리 키 조작 (관리자 권한)]
  ① HKLM\...\Image File Execution Options\notepad.exe
     └─ GlobalFlag (DWORD) = 0x00000200 (FLG_MONITOR_SILENT_PROCESS_EXIT 비트마스크 활성화)
  ② HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe
     ├─ ReportingMode (DWORD) = 1 (LAUNCH_MONITORPROCESS 활성화)
     └─ MonitorProcess (REG_SZ) = "C:\ProgramData\LegitUpdater\updater.exe"

[실제 트리거 흐름]
[피해자가 메모장(notepad.exe)을 열고 작업 수행 (정상 동작)]
       │
       ▼
[피해자가 메모장 창을 닫음 (ExitProcess / NtTerminateProcess 호출)]
       │
       ▼
[커널이 GlobalFlag(0x200)를 확인하고 WerSvc(오류 보고 서비스)에 신호 전달]
       │
       ▼
[werfault.exe 실행] ──> [SilentProcessExit 레지스트리 참조] ──> [MonitorProcess에 등록된 페이로드 조용히 실행]
```

#### 최신 보안 업데이트 및 방어 포인트

- **프로세스 트리(Process Lineage)의 비정상성:** `SilentProcessExit`가 작동하면 부모 프로세스가 `svchost.exe(WerSvc)` 또는 `werfault.exe`로 찍히면서 공격자 바이너리가 자식 프로세스로 생성됩니다. 최신 EDR(CrowdStrike, MDE)은 오류 보고 유틸리티 `werfault.exe`가 비표준 경로 실행 파일이나 쉘을 실행하는 행위를 즉각적인 침해 지표(IoC)로 탐지합니다.
- **방어자(DFIR) 탐지 룰:** Sysmon Event ID 12·13으로 `Image File Execution Options` 내 `Debugger`·`GlobalFlag` 값 변경과 `SilentProcessExit` 키 생성을 모니터링해야 합니다.

### 4.3 Winlogon Helper와 레거시 기법(`AppInit_DLLs`)의 사멸 분석

#### Winlogon Helper (`Shell`, `Userinit`, `Notify`)

사용자 로그인 시 세션 초기화를 담당하는 `winlogon.exe`가 참조하는 레지스트리(`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`)입니다. **(로컬 관리자 권한 필수)**

- **`Userinit`:** 기본값 `C:\Windows\system32\userinit.exe,` 뒤에 쉼표(`,`)로 실행 파일 경로를 추가하면 로그온 시 순차적으로 함께 실행됩니다.
- **`Shell`:** 기본값 `explorer.exe` 뒤에 함께 실행할 프로그램을 지정할 수 있습니다.
- **`Notify` (버전별 사멸 ❌):** 과거 Windows XP/Server 2003 시절 `Winlogon\Notify` 하위 키에 DLL을 등록해 로그온 이벤트를 가로채던 기법이나, **Windows Vista/7 이후 모든 Win 10/11에서는 아키텍처가 변경되어 `Notify` 키 자체가 완전히 제거되었으며 작동하지 않습니다.**

#### [필수 업데이트] `AppInit_DLLs`가 최신 Win 10/11에서 작동하지 않는 이유

많은 구형 교재가 소개하는 `AppInit_DLLs`는 레지스트리(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`)에 DLL 경로를 적어두면 `user32.dll`을 로드하는 거의 모든 프로세스에 해당 DLL을 강제 인젝션하는 강력한 기능이었습니다.

> **왜 현재 실전에서는 실패하는가? (UEFI Secure Boot와의 연동)**
> 마이크로소프트는 무분별한 DLL 인젝션을 막기 위해 Windows 8 및 Win 10/11부터 **UEFI 보안 부팅(Secure Boot)이 활성화되어 있으면 `LoadAppInit_DLLs` 값을 `1`로 설정해도 OS 커널이 무조건 무시하고 비활성화**하도록 패치했습니다. 특히 **Windows 11은 설치 최소 요구사항으로 UEFI Secure Boot를 강제**하므로, 현대 엔터프라이즈 환경에서 `AppInit_DLLs` 기법은 사실상 **사멸(Dead)**했습니다.

### 4.4 기존 Windows 서비스 변조 및 `svchost.exe` ServiceDll 하이재킹

Part 2에서는 새 서비스를 '생성'하는 방법을 다루었습니다. 하지만 새 서비스를 만들면 System Event ID 7045 로그가 남아 쉽게 발각되므로, 로컬 관리자 권한을 얻은 공격자는 **기존 서비스를 변조**하는 방식을 선호합니다.

#### 메커니즘 1: 비활성 기본 서비스의 `ImagePath` 변조

윈도우에 기본 설치되어 있지만 평소 중지(Disabled/Manual)된 서비스(예: `Fax`, `Spooler`, 서드파티 구형 서비스)를 찾아, 시작 유형을 자동(`Auto`)으로 바꾸고 레지스트리 `ImagePath` 값을 공격자 서비스 바이너리로 교체합니다. 신규 서비스 생성 로그(ID 7045)를 피할 수 있습니다.

#### 메커니즘 2: `svchost.exe` 기반 서비스의 `ServiceDll` 하이재킹 (고급 은닉 ⭐)

윈도우의 수많은 기본 서비스는 개별 `.exe`가 아니라 `.dll` 형태로 만들어져 시스템 프로세스 **`svchost.exe -k <그룹명>`** 내부에 얹혀(Hosting) 실행됩니다.

- **레지스트리 구조:**
    - `HKLM\SYSTEM\CurrentControlSet\Services\<서비스명>\ImagePath` → `%SystemRoot%\System32\svchost.exe -k netsvcs`
    - `HKLM\SYSTEM\CurrentControlSet\Services\<서비스명>\Parameters\ServiceDll` → **실제 로드될 DLL 경로가 이곳에 정의됨**
- **은닉 효과:** 공격자가 서비스 진입 함수(`ServiceMain`)를 구현한 악성 DLL을 만들고 기존 서비스의 `Parameters\ServiceDll` 경로를 자신의 DLL로 바꾸면, 작업 관리자나 프로세스 목록에 수상한 `.exe`가 전혀 나타나지 않고 **정상 시스템 프로세스 `svchost.exe` 내부 스레드로 은닉되어 실행**됩니다.
- **Win 10/11 최신 방어 패치 (Signature Mitigation):** 마이크로소프트는 최근 주요 `svchost.exe` 프로세스에 **'Microsoft 서명된 바이너리만 로드 허용(Microsoft Signed Only mitigation)'** 정책을 적용하기 시작했습니다. 따라서 핵심 보안 그룹의 `svchost`에 서명되지 않은 `ServiceDll`을 넣으면 로드가 차단(Event ID 7023 및 CodeIntegrity 로그 발생)될 수 있으므로, 서명 강제 정책이 적용되지 않은 일반 서비스 그룹이나 서드파티 서비스를 타겟팅해야 합니다.

### 4.5 애플리케이션 및 최신 개발자 환경 기반 지속성 (2025~2026 트렌드)

관리자 권한 없이, 보안 솔루션이 잘 감시하지 않는 업무용/개발용 프로그램의 설정 파일을 변조하는 최신 지속성 기법들입니다.

#### ① Microsoft Office 지속성 (Word, Excel, COM Add-ins)

| 세부 기법 | 타겟 경로/레지스트리 (일반 사용자) | 작동 메커니즘 및 제약 |
| --- | --- | --- |
| **Excel `XLSTART`** | `%APPDATA%\Microsoft\Excel\XLSTART\` | 엑셀 실행 시 폴더 내 `.xlam`, `.xll` 자동 로드. |
| **Word `STARTUP`** | `%APPDATA%\Microsoft\Word\STARTUP\` | 워드 실행 시 폴더 내 글로벌 템플릿(`.dotm`)이나 Word 추가 기능(`.wll` — 본질적으로 DLL)을 경고 없이 자동 로드. |
| **Office COM Add-in 레지스트리** | `HKCU\Software\Microsoft\Office\<버전>\<앱>\Addins\<CLSID>` | `LoadBehavior` 값을 `3`(시작 시 자동 로드)으로 설정해 COM DLL 연결. (주의: 애드인 로드에 약 1초 이상 지연되면 Office가 '성능 저하 애드인'으로 판단해 사용자에게 알림을 띄우고 `Resiliency\DisabledItems`로 보내므로, 페이로드는 반드시 비동기 스레드로 즉시 반환되어야 함.) |

#### ② PowerShell 프로필(`$PROFILE`) 인젝션

관리자·개발자가 PowerShell을 실행할 때마다 자동으로 먼저 실행되는 초기화 스크립트입니다. 기본적으로는 파일이 없으나, 공격자가 해당 경로에 파일을 생성하면 즉시 작동합니다.

| 프로필 종류 | 변수명 | 실제 파일 경로 | 필요 권한 |
| --- | --- | --- | --- |
| 현재 사용자 / 현재 호스트 | `$PROFILE.CurrentUserCurrentHost` | `%USERPROFILE%\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` (PowerShell 7+: `\Documents\PowerShell\...`) | 일반 사용자 |
| 현재 사용자 / 모든 호스트 | `$PROFILE.CurrentUserAllHosts` | `%USERPROFILE%\Documents\WindowsPowerShell\profile.ps1` | 일반 사용자 |
| 모든 사용자 / 모든 호스트 | `$PROFILE.AllUsersAllHosts` | `$PSHOME\profile.ps1` (`C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1`) | 관리자 |

- **최신 제약 사항:** 기업 환경에서 WDAC/AppLocker로 PowerShell이 CLM(Constrained Language Mode)으로 강제되거나 `ExecutionPolicy`가 `AllSigned`로 GPO에 묶여 있으면 프로필 스크립트 실행이 차단됩니다.

#### ③ 최신 개발 도구 악용: Windows Terminal & VS Code (최신 트렌드 ⭐)

IT 기업·클라우드 엔지니어·개발자 PC를 타겟으로 할 때 각광받는 User-Land 지속성 기법입니다.

- **Windows Terminal (`settings.json`):** Windows 11 기본 터미널의 설정 파일(`%LOCALAPPDATA%\Packages\Microsoft.WindowsTerminal_...\LocalState\settings.json`)은 일반 사용자 권한으로 수정 가능합니다. 프로필의 `"commandline": "powershell.exe"` 항목에 백그라운드 페이로드 실행 인자를 덧붙이면 사용자가 터미널을 켤 때마다 실행됩니다.
- **Visual Studio Code (`tasks.json` & 확장):** 프로젝트 폴더 내 `.vscode\tasks.json`에 `"runOptions": { "runOn": "folderOpen" }` 옵션과 쉘 명령어를 넣으면, 개발자가 VS Code로 그 폴더를 여는 순간 백그라운드 작업이 자동 실행됩니다. (최근 VS Code 패치로 첫 폴더 오픈 시 '작업 자동 실행 허용'을 묻지만, 이미 신뢰된 워크스페이스에서는 무리 없이 작동.)

### 4.6 계정 조작(RID Hijacking) 및 보안 식별자(SDDL) 백도어

#### RID Hijacking (상대 식별자 하이재킹)

명령줄에서 `net user hacker /add` 및 `net localgroup administrators hacker /add`를 실행하면 Windows Security Event ID 4720, 4732가 발생하여 SOC에 100% 적발됩니다.
이를 피하기 위해 공격자는(`SYSTEM` 권한 필요) 레지스트리 `HKLM\SAM\SAM\Domains\Account\Users\000001F5`(`1F5` = 10진수 501, 즉 기본 내장 **Guest 계정**)의 바이너리 데이터인 **`F` 값** 내부에서 사용자 고유 번호(RID)를 정의하는 바이트(`F5 01`)를 `F4 01`(10진수 500 = 내장 Administrator)로 덮어씁니다.

- **효과:** `net user guest`나 제어판에서는 여전히 권한 없는 평범한 `Guest` 계정으로 보이지만, 실제 이 계정으로 로그인하면 커널이 RID를 `500`으로 인식하여 **완전한 로컬 관리자(Administrator) 토큰**을 부여합니다.

#### 서비스 및 레지스트리 SDDL(보안 설명자) 백도어

관리자 권한을 잠시 획득했을 때, 당장 악성 파일을 심는 대신 특정 시스템 서비스(예: 원격 레지스트리 서비스)나 레지스트리 키의 접근 제어 목록(ACL/SDDL)을 수정해 일반 표준 사용자 계정에게도 '모든 권한(Full Control)'을 열어둡니다. 나중에 관리자 비밀번호가 바뀌어 권한을 잃더라도, 일반 사용자 계정으로 들어와 권한이 열린 서비스를 조작함으로써 언제든 다시 `SYSTEM` 권한을 복구할 수 있는 '권한 백도어' 역할을 합니다.

---

## [최종 요약] Blue Team / DFIR 지속성 헌팅 체크리스트

| 계층 | 대응 대상 기법 | 핵심 탐지 전략 |
| --- | --- | --- |
| 레지스트리 & 시작 | Run/RunOnce 키, 시작프로그램 폴더, COM 하이재킹, Office 애드인, IFEO | `CurrentVersion\Run`, `HKCU\Software\Classes\CLSID\...\InprocServer32`, `Image File Execution Options`(`Debugger`/`GlobalFlag`), `SilentProcessExit` 값 변경 감시(Sysmon ID 12/13). 시작프로그램·`XLSTART`·`Word\STARTUP` 파일 생성 알람(Sysmon ID 11). |
| 예약 작업 & WMI | 예약된 작업, WMI 이벤트 구독 | 작업 생성 시 Security Event ID 4698 + TaskScheduler ID 106. WMI 구독은 Sysmon ID 19/20/21; `root\subscription` 소비자 주기적 조회. |
| 서비스 & 계정 | 신규/변조 서비스, ServiceDll 하이재킹, RID 하이재킹, SDDL 백도어 | System Event ID 7045(신규 서비스) / 7023 + CodeIntegrity(미서명 ServiceDll 차단). `Services\...\Parameters\ServiceDll` 변경 감시. SAM `F` 값 변조 및 서비스·레지스트리 ACL(SDDL) 변경 감사. |
| 개발도구 / User-Land | `.lnk` 변조, PowerShell 프로필, Windows Terminal, VS Code | 엔지니어 워크스테이션에서 `.lnk`의 `StartIn`/작업 디렉터리 변경, `$PROFILE` 스크립트 생성, `settings.json`/`.vscode\tasks.json` 수정을 기준선 설정 후 모니터링. |

---

*본 문서는 CRTO 학습 노트를 기반으로 재정리한 개인 레퍼런스이며, 방어·탐지(Blue Team/DFIR) 학습 목적입니다.*
