---
title: "Day 3 — EDR, 위협 에뮬레이션, 호스트 방화벽"
tags:
  - training
  - antisyphon
  - edr
  - sysmon
  - adversary-emulation
  - host-firewall
---

# Day 3 — EDR, 위협 에뮬레이션, 호스트 방화벽 { #day-3 }

<div class="dfir-meta" markdown>
**과정:** Information Security Core Skills · **강사:** John Strand (BHIS) · **3일차 범위:** Sysmon 실습 해설 → Pass-the-Hash → EDR·심층 방어 → 위협 에뮬레이션·Atomic Red Team → AI 탐지 규칙 → BloodHound → 갭 분석 실습 → 호스트 방화벽
</div>

!!! abstract "3일차 한눈에"
    2일차에 미뤄 둔 **Sysmon 실습 해설**로 시작해, 해시만으로 로그인하는 **Pass-the-Hash**가 로그에 어떻게 보이는지 봅니다. 이어서 **EDR**은 강력하지만 혼자서는 부족하다는 것 — 시야가 겹치는 통제들은 효과가 **곱해진다** — 과, 벤더 말을 믿지 말고 **Atomic Red Team** 같은 도구로 직접 **검증**하는 방법(갭 분석)을 다룹니다. 마지막으로 워크스테이션끼리의 통신을 막는 **호스트 방화벽**으로 횡적 이동이라는 공격 범주를 통째로 없애는 법을 실습합니다.

!!! note "표기 규칙"
    **💡 보충 (강의 외)** = 강의에 없던 제 추가 설명. **(재구성)** = 강사가 화면으로만 보여 줘 제가 일반적인 형태로 복원한 내용. 공격 도구를 쓰는 실습은 **무엇을 보여 주는지와 방어·탐지 포인트** 위주로 정리했고, 공격 명령어 세부는 생략했습니다.

---

## 1. Sysmon 실습 해설 { #sysmon-lab-review }

### 실습 다시 보기 { #lab-recap }

1. **Windows(피해자):** 실시간 보호·방화벽을 끄고 관리자 패스워드를 `password1234`로 변경(원격 로그인 실습용).
2. **Kali(공격자):** 테스트용 악성 파일 `trustme.exe`를 만들어 피해자 쪽으로 옮기고 연결을 기다림.
3. **Windows에 Sysmon 설치** 후 `trustme.exe` 실행 → 공격자가 원격 세션을 얻고, 해시를 뽑고, 키로거를 시연.

파일을 만들 때 **"No encoder specified"** 메시지가 뜹니다. 백신 우회를 위한 인코딩을 **일부러 하지 않았다**는 뜻입니다. 이 실습의 목적은 백신 우회가 아니라 **Sysmon 로그를 보는 것**이기 때문입니다.

John이 짚은 숫자: **페이로드는 354바이트**인데 **최종 파일은 약 73KB**입니다. 1일차의 **스테이저(stager)** 때문입니다. 354바이트 조각은 실행되면 공격자 서버에서 본체(stage)를 내려받는 심부름꾼이고, 그 조각을 정상 프로그램 **Apache Bench(`ab.exe`)** 안에 끼워 넣었기 때문에 최종 파일은 정상 프로그램 크기가 됩니다.

### Sysmon에 남은 흔적 { #sysmon-artifacts }

이벤트 뷰어 → 응용 프로그램 및 서비스 로그 → Microsoft → Windows → **Sysmon → Operational**

| Sysmon 이벤트 | 보인 것 | 의미 |
|---|---|---|
| **1** 프로세스 생성 | `trustme.exe` 실행, 설명 Apache Bench, **OriginalFileName `ab.exe`**, 실행자 administrator, 해시, **부모 `cmd.exe`** | 파일 이름 ≠ 원래 이름 = 강력한 단서. 명령 프롬프트에서 직접 실행됨 |
| **22** DNS 질의 | `trustme.exe`의 DNS 질의 | 어디로 연락하려 했는지 |
| **8** CreateRemoteThread | `trustme.exe`가 **LSASS**에 원격 스레드 생성 | **해시 덤프의 신호** — 공격자가 해시를 뽑은 순간 |
| **1** 프로세스 생성 | `notepad.exe`, 이벤트 뷰어 스냅인 등 | 키로거 시연과 분석 동작까지 시간 순으로 보임 |

**LSASS(Local Security Authority Subsystem Service)**는 로그인과 자격 증명을 다루는 핵심 프로세스로, 메모리에 패스워드 해시 같은 민감한 정보를 들고 있습니다. 평범한 프로그램이 LSASS에 스레드를 만들 일은 거의 없습니다.

!!! note "💡 보충 (강의 외)"
    자격 증명 덤프의 대표 탐지 포인트는 Sysmon **8**(LSASS에 원격 스레드)과 **10**(LSASS 프로세스 접근)입니다. 이벤트 10의 `GrantedAccess` 값(예: `0x1010`, `0x1410`)으로 메모리 읽기 권한 요청 여부를 볼 수 있습니다. 탐지 쿼리: [LSASS 덤프](../../../adversary/lsass-dumping.md).

---

## 2. Pass-the-Hash — 패스워드를 몰라도 로그인한다 { #pass-the-hash }

### 상황 설정 { #pth-setup }

John은 관리자 패스워드를 `password1234`에서 "양자 컴퓨터가 아니면 못 깨는" **아주 긴 패스워드**로 바꿉니다. 다시 해시를 뽑으면 관리자 계정의 해시가 바뀐 것이 보입니다.

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NT 해시>:::
```

- **`aad3b4…` 앞부분 = LM(LAN Manager) 해시.** 아주 오래된 방식이라 요즘은 쓰지 않아 **비어 있는 값**이고, 그래서 모든 계정에서 같습니다. 무시해도 됩니다.
- **뒷부분 = NT 해시.** 패스워드를 바꾸자 완전히 다른 값이 되었습니다.

### 핵심 — 해시만 있으면 된다 { #pth-core }

"이 해시는 절대 크래킹할 수 없다"고 가정해도, 공격자는 **패스워드 대신 해시 자체를 내밀어** 인증할 수 있습니다. John은 1일차 패스워드 스프레이 때 쓴 원격 실행 방식(PsExec)에 패스워드 대신 해시를 넣어, 패스워드를 전혀 모르는 상태로 새 세션을 엽니다.

> 패스워드가 아무리 길고 강해도, 공격자가 **해시를 손에 넣으면** 그 사람으로 로그인할 수 있다.

1일차에서 본 NT 해시의 약점 — **솔트(salt)가 없다** — 때문에, 해시가 사실상 "패스워드와 같은 열쇠"가 됩니다.

!!! note "💡 보충 (강의 외) — 방어는 패스워드 강화가 아니다"
    - **로컬 관리자 패스워드를 PC마다 다르게** — **LAPS**를 쓰면 한 대에서 뽑은 해시가 다른 PC에서 통하지 않습니다.
    - **횡적 이동 경로 차단** — 이 페이지 마지막의 [호스트 방화벽](#host-firewalls)(워크스테이션끼리 SMB 445 차단).
    - **자격 증명 보호** — Credential Guard, Protected Users 그룹, 관리자 계정 계층화(tiering).

    자세한 흔적과 탐지: [Pass-the-Hash](../../../adversary/pass-the-hash.md).

### Pass-the-Hash는 Sysmon에 어떻게 보이나 { #pth-in-sysmon }

앞의 공격은 `trustme.exe`라는 **파일 실행** 흔적이었지만, 이번 원격 공격은 **심하게 난독화된 PowerShell**로 인증한 뒤 악성코드를 올리고 실행한 흔적입니다. 같은 공격자라도 **들어오는 방법에 따라 로그 모양이 다릅니다** — 파일 실행만 보는 탐지는 이번 공격을 놓칠 수 있습니다.

!!! note "💡 보충 (강의 외) — 원격 실행이 남기는 흔적"
    - 보안 로그 **4624** — 로그온 유형 **3**(네트워크), 인증 패키지 **NTLM**
    - 시스템 로그 **7045** — 새 서비스 설치(PsExec 방식은 서비스를 만들어 명령 실행)
    - Sysmon **1** — 서비스가 띄운 PowerShell(부모 `services.exe`), 긴 인코딩 명령줄
    - PowerShell **4104** — 난독화가 풀린 실제 스크립트 내용

    관련: [PsExec와 SMB](../../../adversary/psexec-smb.md) · [PowerShell 크래들](../../../adversary/powershell-cradles.md)

### Metasploit은 실무에서 쓰일까? { #metasploit-in-practice }

전문 펜테스트에서는 Metasploit을 **그리 많이 쓰지 않습니다.** 많은 팀이 **Cobalt Strike, Brute Ratel, Nighthawk** 같은 도구를 씁니다. 하지만 **기능의 폭**은 Metasploit을 따라올 도구가 없고, 약점은 **팀 협업**(상용 도구는 팀 작업·백신 우회·BOF 확장이 좋음)입니다.

> 일상적인 보안 업무를 하는 **내부 팀**이라면, Metasploit은 **무료**이고 그게 엄청난 장점이다.

---

## 3. EDR — 가장 강력하지만, 그것만 믿으면 안 된다 { #edr }

**EDR(Endpoint Detection and Response)**은 PC·서버에서 프로세스·파일·네트워크·레지스트리 활동을 계속 감시하고 대응합니다. Back Doors & Breaches의 **"엔드포인트 보안 분석"** 카드는 소셜 엔지니어링, 웹 서버 침해, 접근성 기능 악용, 로그온 스크립트, 횡적 이동, 권한 상승, AD 악용, C2·데이터 반출까지 막아서 **4 리소스 포인트**로 비쌉니다. 실제로도 EDR은 가장 비싼 축의 보안 도구입니다. (John은 이 단원으로 넘어가며 BHIS가 아끼는 도구로 **Velociraptor**도 짧게 언급했습니다.)

문제는 많은 조직이 **거의 100% EDR 하나에만 의존**한다는 점입니다.

> "솔직히 말하면, 많은 벤더가 거짓말을 한다." — "모든 공격을 막고 오탐도 0"이라고 장담한다.

### 심층 방어는 덧셈이 아니라 곱셈 { #defense-in-depth }

"보안에 돈을 이만큼 썼다", "EDR을 10만 대에 깔았다"는 심층 방어가 아닙니다. 서로 **겹치지 않는** 통제는 효과가 **더해질** 뿐이고, 같은 자산을 **겹쳐서** 지키는 통제는 효과가 **곱해집니다.**

PC 한 대를 **AV/EDR + 네트워크 보안 모니터링(2일차 Zeek·RITA) + SIEM + UEBA**가 동시에 지키면, 하나가 뚫려도 나머지가 잡고, 공격자는 **모두를 동시에** 피해야 하므로 비용이 급격히 커집니다.

> 국가 단위 작전 경험에서 — 이런 수준의 방어가 깔린 시스템에 들어가면 계속 진행해도 되는지 지휘 계통에 허락을 구해야 했고, 대부분 **"중단하라"**는 답이 왔다. 비싼 TTP가 노출될 위험이 너무 크기 때문이다.

> **공격자가 "여긴 너무 비싸다"며 포기하게 만드는 것** — 그것이 목표다.

전통적인 차단 목록 AV는 "거의 쓰레기"이고, EDR은 드디어 시스템을 **전체적으로** 보게 해 줍니다. 대표 기능이 **프로세스 트리**(어떤 프로세스가 어떤 프로세스를 낳았나)이며, 메모리 분석에서도 중요해집니다.

!!! note "💡 보충 (강의 외)"
    `WINWORD.EXE → cmd.exe → powershell.exe → rundll32.exe` 같은 줄기는 "워드 매크로가 명령을 실행했다"는 전형적인 피싱 침해 흐름입니다. Sysmon 이벤트 1의 `ParentImage`가 이 트리의 재료이고, 메모리 포렌식에서도 같은 개념을 씁니다(Volatility `pstree`).

### EDR을 고를 때 — AI는 학습 데이터만큼만 좋다 { #edr-ai-data }

> "우리는 새로 생긴 패기 넘치는 EDR 회사이고, 아무도 본 적 없는 독자적인 AI를 씁니다." → John: **대개 형편없다.** 학습 데이터가 충분히 크지 않기 때문.

**CrowdStrike, Microsoft Defender(+ Sentinel), SentinelOne**은 **수십억 대의 엔드포인트**에서 데이터를 받아 AI를 학습시키고, 그것을 처리할 컴퓨팅 자원도 갖췄습니다. 신생 회사가 따라잡기는 거의 불가능합니다. John의 추천은 **CrowdStrike**와 **Windows Defender + Sentinel**(좋은 등급은 유료)입니다.

### Blue Spawn — 실습용 EDR 대역 { #bluespawn }

대학 사이버 방어 대회(**CCDC**)에서 백신 반입이 금지되자, 버지니아의 학생들이 직접 AV/EDR을 만들어 대회에서 효과를 본 오픈소스 도구입니다. 다만 **MITRE 커버리지가 낮아 실제 EDR로 쓰지는 말라**고 합니다. 실습 목적은 **"우리 EDR을 어떻게 시험해야 하는가"**를 배우는 것입니다.

---

## 4. 믿되, 검증하라 — 위협 에뮬레이션 { #trust-but-verify }

벤더 마케팅만 믿으면 안 되지만, **전부 벤더 탓도 아닙니다.** 우리 쪽 **설정 실수**도 성능을 크게 떨어뜨립니다.

- **PowerShell을 전체 환경에서 무조건 허용하는 규칙** — 멍청하지만 정말 자주 봄
- **EDR을 환경의 90%에만 설치** — 남은 **10%는 아주 큰 10%**

해결책은 **보안 통제의 지속적 검증**입니다. BHIS SOC도 탐지 체계가 기대대로 동작하는지, 커버리지가 기대만큼인지를 계속 평가합니다.

### 에뮬레이션 vs 시뮬레이션 { #emulation-vs-simulation }

| | 시뮬레이션 | 에뮬레이션 |
|---|---|---|
| 방식 | **여러 스크립트**로 공격 행동을 흉내 | **실행 파일 하나 + C2 서버**로 실제 악성코드처럼 동작 |
| 예 | **Atomic Red Team** | Caldera 에이전트, Metasploit 등 |
| 수준 | 입문 | 더 발전된 단계 |

John의 의견은 "솔직히 **큰 차이는 없다**, 둘 다 하라"입니다.

**도구들:** **Caldera**(MITRE가 만든 적대적 시뮬레이션 환경 — 여러 시스템에 에이전트를 깔고 ATT&CK 기법 시험), **Infection Monkey**, **Atomic Red Team**(Red Canary — ATT&CK 기법별 작은 테스트로 무엇이 탐지됐는지 정리, 이 과정의 메인 실습 도구).

!!! warning "시험할 때는 '알림만, 차단 없음' 모드로"
    Caldera는 악용을 막으려고 **자기 바이너리의 AV 시그니처를 공개**하므로 어떤 AV든 바로 잡습니다. 그리고 시뮬레이션 도구는 대부분 **PowerShell 스크립트**로 공격을 재현하는데, EDR이 PowerShell 실행 자체를 막으면 나머지 테스트가 하나도 돌지 않습니다. 그래서 EDR 평가는 **알림은 내되 차단하지 않는(alerting, non-blocking) 모드**로 해야 "무엇을 탐지하고 무엇을 놓치는지"를 정확히 알 수 있습니다.

### 탐지 규칙을 너무 구체적으로 쓰지 마라 { #signature-specificity }

Atomic Red Team은 각 테스트(예: `regsvr32` 테스트)의 일반 명령 형태와 실제 입력값이 들어간 명령을 모두 보여 줍니다. 게으른 탐지 엔지니어가 Atomic Red Team이 쓴 **명령 문자열 전체**(Atomic 폴더의 전체 경로까지)를 규칙에 넣으면:

- Atomic Red Team을 돌릴 때는 **매번** 울리지만
- 실제 공격이나 펜테스트에서는 **절대 안 울립니다** — 실제 공격자가 그 경로를 그대로 쓸 리 없으니까.

올바른 방법은 **변하는 부분은 변수로, 변하지 않는 핵심 조합**을 잡는 것입니다. 이 예라면 "`regsvr32`가 `/s` `/u` `/i:` 스위치와 `scrobj.dll`을 **함께** 쓰면" 울리게 하고, 대소문자는 구분하지 않습니다.

!!! note "💡 보충 (강의 외)"
    이 기법은 **Squiblydoo**로 유명합니다(MITRE **T1218.010**, Regsvr32). 서명된 `regsvr32.exe`로 원격 스크립트를 실행하는 LOLBin 기법 — [LOLBins](../../../adversary/lolbins.md).

### AI로 탐지 규칙 만들기 — 그리고 사람이 할 일 { #ai-detections }

John은 ChatGPT(무료 버전)에 "다음 탐지에 대한 Sigma 알림 규칙을 만들어 줘"라고 요청합니다. **Sigma**는 한 번 쓰면 여러 SIEM용으로 변환되는 탐지 규칙 공용 언어입니다.

```yaml
title: Suspicious Regsvr32 Scriptlet DLL Execution
status: experimental
description: Detects suspicious use of regsvr32 with scrobj.dll
references:
  - https://attack.mitre.org/techniques/T1218/010/
author: OpenAI
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains|all:
      - 'scrobj'
      - '/i:'
  condition: selection
falsepositives:
  - Legitimate administrator software registration activity
level: high
```

*(재구성 — 강의 화면 내용을 일반적인 형태로 옮김)*

- **`status: experimental`** — 아직 시험 단계.
- **`references`** — 근거가 되는 ATT&CK 기법.
- **`author: OpenAI`** — AI가 **자기 이름을 작성자로** 넣어서 John이 웃은 부분.
- **`logsource`** — Windows **프로세스 생성** 로그(Sysmon 1 또는 보안 로그 4688).
- **`Image|endswith: '\regsvr32.exe'`** — 경로가 `regsvr32.exe`로 **끝나면**. 전체 경로를 고정하지 않으니 어디서 실행되든 잡음.
- **`CommandLine|contains|all`** — 명령줄에 나열한 값이 **모두** 들어 있으면.
- **`condition: selection`** — 위 조건을 만족하면 경보.
- **`falsepositives`** — "정상적인 관리자의 소프트웨어 등록". John은 실제로 정상 소프트웨어가 같은 기법을 쓰는 경우도 봤다고 합니다.

ChatGPT는 앞의 실수를 피해 **일반화된 조건**으로 썼습니다. John은 같은 탐지를 **Elastic**용, **LimaCharlie**용으로도 만들게 했습니다.

**그럼 사람은 무엇을 하나?** "튜닝"이라는 답에 John은 **"튜닝하기 전에 먼저 테스트"**라고 합니다. BHIS의 순서:

1. **초안** — AI나 분석가가 규칙 초안을 만듦.
2. **과거 데이터로 백테스트** — BHIS 도구 **Detection Forge**로 "과거에 몇 번 울렸을까?"를 봄. **10만 번**이면 오탐이 너무 많은 것. 오탐을 마구 만드는 규칙을 만들면 동료들이 당신을 싫어하게 됩니다.
3. **튜닝** — 적절한 수준으로 줄임.
4. **현재 공격으로 시험** — 샌드박스에서 **Atomic Red Team으로 실제 공격**을 일으켜 제대로 울리는지 확인.

> 과거 데이터로 "오탐이 너무 많지 않은지", 현재 공격으로 "제대로 잡는지" — **두 방향 모두** 시험해야 한다.

!!! note "💡 보충 (강의 외) — Splunk로 백테스트하는 개념"
    규칙 조건을 그대로 SPL로 옮겨 과거 기간에 돌려 보고 건수를 세는 것과 같습니다.

    ```spl
    index=* EventCode=1 Image="*\\regsvr32.exe" CommandLine="*scrobj*" CommandLine="*/i:*"
    | timechart span=1d count
    ```

    `EventCode=1`은 Sysmon 프로세스 생성 이벤트입니다. `Image="*\\regsvr32.exe"`는 경로가 regsvr32.exe로 끝나는 것만, 이어지는 두 `CommandLine` 조건은 명령줄에 `scrobj`와 `/i:`가 **모두** 들어간 것만 남깁니다(SPL은 공백으로 나열한 조건을 AND로 처리). `timechart span=1d count`는 하루 단위로 건수를 세어 시간 그래프로 보여 줍니다. 매일 수백 건이면 튜닝이 필요한 규칙입니다.

**이런 도구를 돌리는 게 무섭다면?** Metasploit이나 Atomic Red Team은 환경에서 제멋대로 퍼지지 **않습니다.** **정해진 호스트에서 정해진 테스트**만 실행합니다.

---

## 5. BloodHound — 도메인 관리자까지 가는 길 { #bloodhound }

**BloodHound**(SpecterOps)는 **일반 사용자 계정 하나**에서 출발해 **도메인 관리자까지 가는 모든 경로**를 찾는 무료 도구입니다.

1. 공격자가 내 PC에 들어왔다(내가 워드 문서를 잘못 열었다). 이제 공격자는 사실상 **나**다.
2. 많은 AD 환경에서는 **어떤 사용자든 어떤 워크스테이션에나** 자기 도메인 계정으로 로그인할 수 있다.
3. 도구는 내 계정으로 **수천 대에 접속을 시도**하며 "여기서 나는 관리자인가?"를 묻는다.
4. **1만 5천 번째 PC**에서 관리자 권한을 찾는다.

**그 PC는 왜?** 회계팀 PC에 평판 스캐너가 있는데, 그 소프트웨어가 이상하게도 **로컬 관리자 권한이 있어야만** 동작합니다. 그래서 헬프데스크가 "이 팀 누구나 써야 하니까 **Domain Users를 로컬 Administrators에 넣자.** 누가 알겠어?"라고 처리합니다.

> **BloodHound가 알려 준다.** 그리고 공격자는 자동화 도구로 **아주 빨리** 알아낸다.

공격자는 그 PC에서 관리자 권한을 얻고, 서비스·다른 계정의 **도메인 수준 자격 증명**을 훔쳐 도메인 관리자로 올라갑니다. 방어자도 반드시 이런 시험을 해야 합니다 — 워크스테이션 한 대가 아니라 **AD 환경 전체**를 공격자의 눈으로.

!!! note "💡 보충 (강의 외)"
    BloodHound 수집기(SharpHound)는 도메인 컨트롤러에 **대량 LDAP 질의**를 일으키고, 여러 PC에 SMB 세션 열거·로컬 그룹 조회를 이어 갑니다. 탐지 쪽에서는 짧은 시간에 한 계정이 **아주 많은 호스트에 네트워크 로그온(4624, 유형 3)**을 하는 패턴과 DC의 대량 LDAP 질의(Zeek `ldap.log` 등)를 봅니다. 방어의 핵심은 **Domain Users를 로컬 관리자 그룹에 넣지 않는 것**.

### 상용 도구와 AI에 대한 John의 생각 { #ai-augment }

**Scythe, AttackIQ, XM Cyber** 같은 상용 에뮬레이션 도구는 좋지만, 많은 업체가 "**이제 펜테스트는 필요 없다**"며 완전한 대체품처럼 팝니다. John은 이것이 AI를 **기존 방식에 그대로 덧붙여** "펜테스터·SOC 분석가가 덜 필요하다, 돈을 아낀다"로 결론 내는 잘못된 접근이라고 봅니다.

> 업계는 취약점·탐지 규칙·SIEM·로그 분석에 **빠져 허우적대고** 있었다. 그때 AI가 나타났다 — **드디어 공격자를 앞지를 기회**였다. 그런데 업체들은 그걸 **"돈을 아낄 수 있다"**로만 봤다.

올바른 관점은 **80/20 법칙** — 도구와 AI로 **20%의 노력으로 80%의 취약점**을 처리하고, 사람은 비즈니스 맥락과 그 환경 고유의 공격 경로처럼 **사람이 잘하는 일**에 집중합니다. **AI는 대체가 아니라 증강**입니다.

> **"공격자도 한 표를 갖고 있다."** — 공격자도 같은 도구를, 그것도 **비대칭적으로** 더 빠르게 쓴다.

최근 Windows 권한 상승 제로데이(**BlueHammer**)의 제작자가 몇 개를 더 공개했고, Linux에서도 권한 상승 취약점이 쏟아지며 한 업체는 "AI로 찾았다"고 밝혔습니다. 취약점은 아주 빠르게 늘어날 것이고, 조직들이 **지금 무엇이 오고 있는지** 깨달아야 합니다.

**MITRE 평가 — "모두가 우승자":** MITRE ATT&CK Evaluations 결과가 나오면 거의 모든 벤더가 "우리가 이겼다"고 씁니다. 그래서 **Josh Lemon**이 직접 채점 도구를 만들었고, 초기 결과에서 McAfee 268, Carbon Black 259, RSA 78처럼 **제품 간 차이가 컸습니다.** 그는 각 도구가 **놓친 기법**도 정리했습니다.

!!! note "💡 보충 (강의 외)"
    MITRE ATT&CK Evaluations 원본 결과는 공개되어 있습니다. 벤더 발표보다 원본에서 **"놓친 것(miss)"과 "설정 변경 후 탐지"**를 직접 보는 것이 정확합니다.

---

## 6. 실습 — Blue Spawn + Atomic Red Team과 갭 분석 { #bluespawn-art-lab }

이 실습은 사실상 두 개입니다. **① Atomic Red Team으로 정해진 기법을 돌려 Blue Spawn이 무엇을 잡는지 보기**, **② 테스트가 없는 새 공격을 직접 재현해 확인하기.**

> Blue Spawn은 **모든 걸 잡지 못한다. 그게 이 실습의 요점이다.** 목표는 **갭 분석** — 방어의 구멍이 어디인지 찾는 것.

### 준비 { #art-setup }

화면 오른쪽에 **Blue Spawn**(탐지가 실시간으로 뜸), 왼쪽에 **PowerShell**을 띄웁니다. 실시간 보호는 끕니다.

```powershell
# (재구성) Invoke-AtomicRedTeam 실행 프레임워크와 테스트 모음(atomics) 설치
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# 모듈 불러오기
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

- **`IWR`**(`Invoke-WebRequest`) — 인터넷에서 설치 스크립트를 받아 옴.
- **`IEX`**(`Invoke-Expression`) — 받아 온 스크립트를 실행. 2일차 Deep Blue CLI에서 "난독화 명령이 IEX로 실행된다"던 그 명령 — 정상 설치에도, 공격에도 쓰입니다.
- **`Install-AtomicRedTeam -getAtomics`** — 실행 프레임워크와 **테스트 정의 모음(atomics)**까지 내려받음.
- **`Import-Module ... .psd1`** — 모듈을 불러와 `Invoke-AtomicTest`를 쓸 수 있게 함.

설치 중 PowerShell YAML 모듈 관련 질문에는 **"모두 예(Yes to All)"**. (Atomic Red Team 유지 관리자 중 한 명이 예전 BHIS 직원이자 현 Antisyphon 강사인 **Carrie Roberts**입니다.)

### 테스트 돌려 보기 { #art-tests }

```powershell
Invoke-AtomicTest T1547.004
```

- **`Invoke-AtomicTest`** — 지정한 기법의 테스트 실행.
- **`T1547.004`** — 부팅·로그온 자동 실행 → **Winlogon 도우미 DLL**(로그온 시 실행되는 Winlogon 레지스트리 값 악용 지속성).

!!! note "💡 보충 (강의 외) — 실행 전후에 쓰면 좋은 옵션"
    - `-ShowDetailsBrief` — 이 기법에 어떤 테스트가 있는지 목록만 보기
    - `-CheckPrereqs` — 실행 조건이 갖춰졌는지 확인
    - `-Cleanup` — 테스트가 만든 변경을 **되돌리기**(실습 후 꼭 실행)

| 테스트 | Blue Spawn 결과 | 교훈 |
|---|---|---|
| **T1547.004** (Winlogon 도우미 DLL) | 실행 즉시 탐지 | 이 기법의 탐지가 동작함을 **이제 안다** |
| **T1543** (시스템 프로세스·서비스 생성/수정) | 기법 탐지 **8건**(잡은 문자열까지 표시) / "서비스 수정" 일반 항목은 **0건** | 알려진 패턴과 정확히 안 맞으면 EDR은 "뭔가 일어났다" 수준의 **중간 등급** 알림만 냄 → **기법을 특정한 탐지**에 집중 |
| 레지스트리 키 테스트 | 처음엔 아무것도 없다가 **몇 초 뒤 한꺼번에** 도착 | **지연 자체가 테스트의 일부** |
| 명령 프롬프트 테스트 | 레지스트리 키 탐지가 "비처럼 쏟아짐" | — |

**왜 늦게 오나?** 실제 업계에서도 아주 흔합니다.

- 많은 EDR은 이벤트를 **모아 두었다가 보내는(store and forward)** 방식이라, 이벤트가 몰리면 파이프라인이 잠시 막혔다가 한꺼번에 처리합니다.
- **WEC/WEF**(Windows 이벤트 수집기/전달기), **Elastic 수집기**도 과부하로 한동안 멈추는 것을 봤습니다.
- **클라우드 서비스**는 더해서, 특히 Microsoft는 사건 발생부터 로그 도착까지 **1시간**이 걸리기도 합니다.

> "우리 탐지가 효과적인가?"를 판단할 때는 **탐지가 되는지**뿐 아니라 **얼마나 늦게 도착하는지**도 계산에 넣어야 한다.

!!! note "💡 보충 (강의 외) — Splunk로 수집 지연 재기"
    ```spl
    index=* earliest=-24h
    | eval lag_sec = _indextime - _time
    | stats avg(lag_sec) AS avg_lag max(lag_sec) AS max_lag BY sourcetype
    ```

    `_time`은 이벤트가 **발생한** 시각, `_indextime`은 Splunk에 **색인된** 시각입니다. `eval lag_sec = _indextime - _time`으로 두 시각의 차이(초)를 새 필드로 만들고, `stats ... BY sourcetype`으로 데이터 종류별 평균·최대 지연을 표로 봅니다. 예를 들어 `max_lag`가 3600 근처인 sourcetype이 있다면 최대 1시간 늦게 들어오는 로그라는 뜻입니다.

MITRE ATT&CK은 버전이 바뀌며 **기법 번호가 바뀌기도** 해서, 강의 자료에 **옛 번호 → 새 번호 crosswalk JSON**이 함께 제공됩니다.

### 맞춤형 에뮬레이션 — 테스트가 없는 새 공격이라면? { #adhoc-emulation }

> 새 공격이 등장했다. **Atomic Red Team에는 아직 테스트가 없다.** 경영진은 "당장 탐지되는지 확인하라"고 압박하고, CISA에서도 경고가 나왔다.

이럴 때 필요한 것이 **즉석 맞춤형 적대적 시뮬레이션** — 정해진 테스트가 없으면 **손으로 직접 공격 행동을 재현**할 수 있어야 합니다. John은 앞과 같은 방식으로 테스트 VM에 원격 세션을 다시 열고, 행동을 하나씩 시험합니다.

| 시험한 행동 | Blue Spawn 결과 |
|---|---|
| **키 입력 기록(키로거)** — 메모장에 입력하며 시험 | **탐지 못 함** (명백한 탐지 실패) |
| **레지스트리 지속성 ①** — 자동 실행 레지스트리 키 추가 | **탐지 못 함** |
| **레지스트리 지속성 ②** — 다른 방식의 레지스트리 키 추가 | **탐지함** |

(키 입력 자체가 제대로 기록되지 않은 것은 이번에 악성코드를 PowerShell 방식으로 실행했기 때문이라고 John은 설명합니다 — 실행 방식에 따라 결과가 달라질 수 있습니다.)

> **우리 EDR이 무엇을 탐지하고 무엇을 놓치는가?** — 이제 **어디에 탐지 규칙을 추가해야 하는지** 안다.

!!! note "💡 보충 (강의 외) — 놓친 항목을 메울 로그 소스"
    - **레지스트리 자동 실행 지속성**(MITRE **T1547.001**, Run 키 등) — Sysmon **13**(레지스트리 값 설정)에서 `\CurrentVersion\Run`, `\RunOnce` 경로 감시. [지속성](../../../adversary/persistence.md)
    - **키로깅**(MITRE **T1056.001**) — 키 입력 가로채기 API는 기본 로그에 잘 안 남아 EDR 행위 탐지나 메모리 분석에 의존하는 경우가 많고, **탐지 공백이 생기기 쉬운** 영역입니다.

실습이 끝나면 VM이 "완전히 너덜너덜해지므로" **랩을 Destroy하고 다시 시작**합니다.

---

## 7. 호스트 방화벽과 횡적 이동 차단 { #host-firewalls }

호스트 방화벽을 잘 잠그면 상대할 수 있는 영역은 MITRE ATT&CK의 거의 **횡적 이동 열 전체**입니다. 이 과정의 철학이 다시 나옵니다.

> 공격 기법 **하나하나**를 쫓지 말고, 공격의 **범주 전체**를 없애라.

핵심 개념은 **분할(segmentation)** — 내부 네트워크를 가능하면 **호스트 단위까지** 나누는 것. 그 이유가 바로 앞에서 본 **Pass-the-Hash**입니다.

### "뚫리는 건 받아들일 수 있다. 하지만…" { #acceptable-compromise }

> 침해당하는 것은 **받아들일 수 있다** — 언젠가는 일어나니까. 죽음과 세금, 양치질처럼.

받아들일 수 **없는** 것은 공격자가 **몇 달 동안** 머무는 것, 그리고 **한 대에서 몇 분 만에 환경 전체**로 퍼지는 것입니다. 이것은 **호스트 방화벽**(또는 **사설 VLAN**)으로 막을 수 있습니다.

**공격자가 퍼지는 방법:** 클라이언트 쪽 익스플로잇이나 드라이브 바이 다운로드로 한 대가 뚫림 → 공격자는 한 대가 아니라 **횡적 이동**을 원함 → 가능하면 **Windows에 원래 있는 프로토콜**(PsExec, 토큰 재사용, 원격 데스크톱, Pass-the-Hash)을 씀 → **도메인 전체** 장악.

### 내부 네트워크를 "적대적"으로 대하라 { #hostile-internal }

방화벽을 켠다는 것은 내부 네트워크를 적대적으로 대한다는 뜻입니다 — "실제로 적대적이니까." 내부 시스템의 방화벽을 **커피숍에 있을 때와 같은 수준**으로 설정합니다.

> 네트워크 관점에서, 회사 PC가 **자기 회사 네트워크보다 스타벅스에서 더 안전하다**는 건 말도 안 되는 일이다.

더 나아가 **사업 부서 사이**에도 내부 분할을 둘 수 있습니다(호스트 방화벽 + 부서 간 분할).

| 출발 | 도착 | 허용 여부 |
|---|---|---|
| **서버, 헬프데스크, 점프 호스트** | 워크스테이션 | **허용** (관리·지원에 필요) |
| **워크스테이션** | 워크스테이션 | **차단** (서로 대화할 이유가 없음) |

이렇게 하면 한 대를 뚫어도 다른 PC들이 잠겨 있어 횡적 이동이 막히고, AV·EDR·네트워크 모니터링·UEBA·SIEM 중 하나가 실패해도 두세 개가 더 받쳐 주는 **겹치는 시야** 구조가 됩니다. 설정은 상용 AV에 내장된 방화벽을 써도 되고, Windows 기본 **`netsh advfirewall`**("끔찍하지만 무료", **그룹 정책으로 설정 가능**)도 있습니다.

!!! note "💡 보충 (강의 외)"
    실무에서는 GPO의 **"고급 보안이 포함된 Windows Defender 방화벽"**에서 인바운드 규칙을 만듭니다. 워크스테이션끼리 막아야 할 대표 포트는 **SMB 445**, **RPC 135**(+ 동적 RPC), **NetBIOS 139**, **WinRM 5985/5986**, **RDP 3389**. "모두 차단" 후 **관리 서버·점프 호스트 IP 대역만 허용**하는 방식이 깔끔합니다.

### 실습 — Nmap으로 보는 방화벽 전후 { #firewall-lab }

새 실습 환경(**antilab**)에서 진행합니다. Windows VM의 IP를 확인한 뒤, 공격자 VM에서 스캔합니다.

**① 방화벽 꺼진 상태**

```bash
nmap 10.10.222.41
```

- **`nmap`** — 대상에 어떤 포트가 열려 있는지 확인하는 스캐너.
- **`10.10.222.41`** — 실습 Windows VM의 IP(환경마다 다름).

```text
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
```

**135** RPC · **139** NetBIOS 세션 · **445** SMB 파일 공유 · **3389** 원격 데스크톱 · **5985** WinRM(원격 관리)

**② 방화벽 켜고 다시 스캔**

```cmd
netsh advfirewall set allprofiles state on
```

- **`netsh advfirewall`** — Windows 방화벽을 명령줄로 다루는 도구.
- **`set allprofiles`** — 도메인·개인·공용 **모든 프로필**에 적용.
- **`state on`** — 켜기(`state off`면 끄기).

다시 스캔하면 **RPC 포트들이 사라집니다**(원격 접속 유지를 위해 터미널 서비스·WSMan 허용 규칙만 남김). John: 이 포트들이 열려 있으면 **횡적 이동이 가능**해지고 Pass-the-Hash가 아주 잘 통하게 된다.

**③ Pass-the-Hash로 확인**

- **방화벽 꺼짐** → 원격 세션 성공. 해시를 뽑아 패스워드 대신 **해시로** 다시 인증하는 것도 성공. "상대 패스워드가 얼마나 강하든, 해시만 있으면 그 사람으로 인증할 수 있다."
- **방화벽 켜짐** → 같은 공격이 **445 포트에 연결하려다 그대로 멈춤(dead in the water).**

> 445 포트 하나를 막는 것만으로 그 시스템의 **횡적 이동 가능성을 크게 줄인다** — 정확히 **Pass-the-Hash 방식의 횡적 이동**을.

!!! note "💡 보충 (강의 외)"
    Windows 방화벽 감사를 켜면 차단 시 보안 로그 **5157**(Windows 필터링 플랫폼이 연결 차단)이 남습니다. 다만 2일차에 John이 "방화벽 로그는 너무 시끄럽다"고 했듯, 실무에서는 **워크스테이션 간 445/135 차단처럼 의미 있는 규칙만** 기록하거나 네트워크 쪽(Zeek `conn.log`의 내부↔내부 SMB 연결)에서 보는 편이 낫습니다. 관련: [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [PsExec와 SMB](../../../adversary/psexec-smb.md).

### 방화벽만으로 끝이 아니다 — Responder 실습 준비 { #responder-prep }

같은 네트워크에 있으면 **ARP 캐시 포이즈닝**, **LLMNR**, **WPAD**로 대상 PC의 트래픽을 공격자 쪽으로 돌린 뒤 인증을 가로챌 수 있습니다 — 1일차에서 개념을 본 **Responder**. 오랫동안 못 쓰던 이 실습이 새 환경 덕분에 되살아났습니다.

- MetaCTF → **Cloud Labs** → 코드 **`antilab`** → Submit. **매주 2시간 무료 실습 시간**("Free Lab Fridays"의 첫 실습).
- 공격자 VM이 **Kali → Ubuntu**로 바뀜(Docker·허니팟 등 앞으로의 실습에 더 유연하고, Kali 공격 도구도 쉽게 설치됨). Windows VM은 **Windows Server 2025**(AD 기능, 중첩 가상화·Docker 예정).
- 흐름: Ubuntu에서 Responder를 이더넷 어댑터 **`ens5`**로 실행 → Windows 탐색기에 `\\<Linux IP>` 입력, 자격 증명에 `password`(소문자) → Responder에 **가로챈 자격 증명** 표시 → 이어서 크래킹.

해설은 **4일차 아침**으로 미뤄졌고, John은 크래킹 단계까지 포함된 수정판 실습 안내를 다시 올렸습니다.

!!! note "💡 보충 (강의 외)"
    해답은 1일차의 방어책 그대로 — **LLMNR·NBT-NS 끄기**, **SMB 서명 강제**, 그리고 이 단원의 **워크스테이션 간 통신 차단**. [LLMNR과 NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md)

---

## 8. AMA에서 나온 이야기 { #ama }

- **로그인 화면 접근성 도구(Utilman·고정 키 sethc·돋보기)를 명령 프롬프트로 바꿔치기하는 오래된 기법이 아직 되나?** → **된다.** 이렇게 들어가면 **SYSTEM 권한**이라는 점이 특징. (EDR 카드의 "접근성 기능"에 해당)
- **Kali를 계속 쓰나?** → John은 특정 목적용 Kali를 좋아하는 "옛날 사람"이지만, BHIS 테스터들은 점점 **직접 만든 자체 환경**을 많이 씀.
- **이 과정 다음엔?** → 시리즈 다음 순서인 **Active Defense and Cyber Deception**.
- **사이버 뉴스는?** → BHIS 내부에서 뉴스를 계속 공유하는 팀과 Teams 방, 그리고 **Simply Cyber(Jerry)의 Daily Cyber Threat Brief**.
- **집에서 쓸 백신은?** → "믿기 어렵겠지만 그냥 **Windows Defender**가 거의 최선."

!!! note "💡 보충 (강의 외) — 접근성 기능 악용 탐지·방어"
    MITRE **T1546.008**. 주로 디스크에 직접 접근할 수 있을 때(물리 접근, 부팅 매체) 쓰입니다.

    - `C:\Windows\System32\`의 `sethc.exe`, `utilman.exe`, `osk.exe`, `Magnify.exe` **해시가 원본과 다른지** 확인(원래 이름이 `cmd.exe`면 확정적)
    - 레지스트리 **Image File Execution Options**에 이 파일들의 `Debugger` 값이 생겼는지 감시(Sysmon **13**)
    - **BitLocker** 등 전체 디스크 암호화로 오프라인 파일 교체 차단
    - 로그인 화면에서 `winlogon.exe`의 자식으로 `cmd.exe`가 뜨는 것(Sysmon **1**)은 강력한 신호

---

## 3일차 정리 { #summary }

| 주제 | 핵심 |
|---|---|
| Sysmon 실습 해설 | 이름 ≠ 원래 이름(1), DNS 질의(22), LSASS에 원격 스레드(8 = 해시 덤프 신호) |
| Pass-the-Hash | 해시만 있으면 패스워드 없이 로그인 — 방어는 LAPS·횡적 이동 차단·자격 증명 보호 |
| EDR과 심층 방어 | 겹치는 통제는 효과가 **곱해진다**, AI는 학습 데이터만큼만 좋다 |
| 위협 에뮬레이션 | 믿되 검증, 시험은 **알림만·차단 없음** 모드, 규칙은 너무 구체적이지 않게 |
| AI로 탐지 규칙 | 초안은 AI, **과거 데이터 백테스트 + 실제 공격 테스트**는 사람 |
| BloodHound | 일반 사용자 → 도메인 관리자 경로, Domain Users를 로컬 관리자로 넣지 마라 |
| Atomic Red Team 실습 | 기법 특정 탐지 vs 일반 알림, **로그 지연**도 평가, 갭 분석 |
| 호스트 방화벽 | 워크스테이션끼리 차단 → 횡적 이동 범주를 통째로 제거 |

!!! quote ""
    EDR은 강력하지만 혼자서는 부족하다 — 겹치는 통제로 공격 비용을 곱하고, Atomic Red Team과 직접 재현으로 우리 탐지의 구멍을 계속 찾아 메워라. 그리고 해시 하나로 퍼지는 횡적 이동은 워크스테이션 간 통신을 막는 호스트 방화벽으로 범주째 차단하라.

## 참고 자료 { #references }

- [Antisyphon Training](https://www.antisyphontraining.com/) · [Black Hills Information Security](https://www.blackhillsinfosec.com/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) · [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) · [MITRE Caldera](https://caldera.mitre.org/) · [BloodHound](https://github.com/SpecterOps/BloodHound) · [Sigma](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK — T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) · [T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010/) · [T1546.008 Accessibility Features](https://attack.mitre.org/techniques/T1546/008/)
- 관련 페이지: [LSASS 덤프](../../../adversary/lsass-dumping.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [PsExec와 SMB](../../../adversary/psexec-smb.md) · [지속성](../../../adversary/persistence.md) · [LOLBins](../../../adversary/lolbins.md) · [LLMNR과 NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md) · [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
