---
title: "Windows 이벤트 로깅의 원리 — 공급자, 채널, 로그가 지나가는 길, 감사 설정, 한 이벤트의 세 가지 보기"
tags:
  - training
  - blue-team
  - windows
  - logging
  - event-logs
---

# Windows 이벤트 로깅의 원리 — 공급자, 채널, 로그가 지나가는 길, 감사 설정, 한 이벤트의 세 가지 보기 { #how-event-logging-works }

!!! abstract "이 페이지에서 다루는 것"
    로그 수집을 "다른 팀"이 맡고 있어도 분석가가 그 원리를 알아야 하는 이유, 그리고 우리가 매일 검색하는 이벤트를 Windows가 실제로 어떻게 만드는지. 로그가 지나가는 길 — 프로그램(공급자) → Windows Event Log 서비스 → 채널 → `.evtx` 파일 → 이벤트 뷰어, `Get-WinEvent`, `wevtutil`, 수집 에이전트 — 과 각 단계가 분석가에게 뜻하는 것. `.evtx` 파일을 메모장으로 못 여는 이유, 파일이 있는 곳, 파일 이름에 `%4`가 들어가는 이유. 채널 종류(Admin, Operational, Analytic, Debug). 어떤 보안 이벤트가 *생기기라도 할지*를 정하는 것들: 감사 정책(옛 방식 vs 고급, 성공 vs 실패, SACL), Sysmon 같은 추가 도구, 스크립트로 만드는 사용자 채널, 따로 텍스트 로그를 쓰는 애플리케이션. 모든 이벤트에 붙는 메타데이터 — 수준, 공급자(원본), 이벤트 ID, 작업 범주, 키워드 — 와 "이벤트 ID는 공급자와 함께여야 의미가 있다"는 중요한 정정. 마지막으로 같은 이벤트를 세 가지로 보기(일반, 쉬운 보기, XML), "메시지" 문장이 템플릿으로 만들어지는 방식, 그리고 SIEM에는 구조화된 필드를 보내야 하는 이유. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름, 해시는 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 분석가에게 <strong>로그 수집은 "남의 일"이 아니다.</strong> 로그가 어디서 오고, 무엇이 담길 수 있고, 오는 길에 무엇이 사라지는지 모르면 "공격자가 안 했다"와 "우리가 기록을 안 했다"를 구분할 수 없다.
2. Windows 프로그램은 로그 파일을 직접 쓰지 않는다. 이벤트를 <strong>Windows Event Log 서비스</strong>에 넘기면, 서비스가 각 이벤트를 <strong>채널(Channel)</strong>(Security, System, Application, 그 밖의 수백 개)로 나누고, 채널마다 `C:\Windows\System32\winevt\Logs` 아래 자기 <strong>`.evtx`</strong> 파일에 저장한다.
3. `.evtx`는 <strong>이진(binary)으로 인코딩된 XML</strong> 형식이다. 읽으려면 도구가 필요하다 — 이벤트 뷰어, `Get-WinEvent`, `wevtutil`, 포렌식 파서, 로그 에이전트. 메모장으로는 안 된다.
4. 어떤 보안 이벤트가 생길지는 일이 벌어지기 <strong>전에</strong> 정해진다. <strong>감사 정책(Audit Policy)</strong>(무엇을, 성공·실패 중 언제 기록할지), 그리고 <strong>Sysmon</strong> 같은 추가 도구와 사용자 채널. 감사 설정이 꺼져 있었다면 나중에 찾을 이벤트가 아예 없다.
5. 모든 게 이벤트 로그로 가지는 않는다. 많은 애플리케이션과 네트워크 서비스(웹 서버, DNS 서버, 데이터베이스)는 <strong>자기만의 텍스트 로그</strong>를 쓰거나, 쓸 만한 걸 아예 안 남긴다. 그래서 따로 설정하거나, Zeek·Suricata 같은 센서로 네트워크에서 잡는다.
6. 모든 이벤트에는 메타데이터가 붙는다. <strong>수준(Level)</strong>(얼마나 심각한가), <strong>공급자/원본(Provider/Source)</strong>(어느 프로그램이 썼나), <strong>이벤트 ID</strong>(어떤 종류의 이벤트인가), <strong>작업 범주(Task Category)</strong>, <strong>키워드(Keywords)</strong>(Security에서는 감사 성공/감사 실패).
7. <strong>[정정]</strong> 이벤트 ID는 전체에서 하나뿐인 번호가 아니라 <strong>공급자마다</strong> 따로 정해진 번호다. 그리고 한 채널에 여러 공급자가 들어 있을 수 있다. 같은 "이벤트 ID 1"도 공급자가 다르면, 같은 채널 안이라도 뜻이 다르다. 항상 공급자(또는 채널 *과* 공급자)와 ID를 같이 걸러야 한다.
8. 이벤트 하나, <strong>보기는 셋</strong>. 읽기 쉬운 <strong>일반(General, 메시지)</strong> 보기, <strong>쉬운 보기(Friendly View)</strong>, 원본 <strong>XML 보기</strong>. 메시지는 XML 필드를 문장 틀(템플릿)에 끼워 넣어 만든 것이다. SIEM에는 구조화된 XML 필드를 보내야 한다. 메시지 문장은 사람용이고, 언어마다 바뀌며, 파싱하기 어렵다.

## 분석가가 로그 수집을 알아야 하는 이유 { #why-it-matters }

### "그건 다른 팀 일 아닌가요?" { #someone-elses-job }

많은 조직에서 로그 에이전트를 깔고, SIEM을 만들고, 무엇을 보낼지 정하는 일은 다른 팀이 합니다. 그러다 보니 로그를 수돗물처럼 여기기 쉽습니다. SIEM을 열면 데이터가 나오니까요. 문제는 처음으로 뭔가를 검색했는데 <strong>결과가 0건</strong>일 때 드러납니다. 0건은 서로 아주 다른 세 가지를 뜻할 수 있습니다.

1. 정말 그런 일이 없었다.
2. 일은 있었지만, Windows가 그걸 기록하도록 설정돼 있지 않았다(감사 정책 꺼짐, Sysmon 없음, 명령줄 기록 꺼짐).
3. 호스트에는 기록됐지만 SIEM까지 오지 않았다(그 채널을 수집하지 않음, 에이전트가 죽어 있었음, 수집 전에 로컬 로그가 덮어써짐, 파서가 필드를 버림).

진짜 "없음"은 1번뿐입니다. 수집 과정을 모르는 분석가는 2번이나 3번을 "침해 증거 없음"으로 보고합니다. SOC에서 가장 비싼 실수 중 하나입니다.

로그를 <strong>건물 CCTV</strong>라고 생각해 보세요. 어느 복도에 카메라가 있는지, 밤에도 녹화하는지, 녹화본을 며칠 보관하는지 모르면 "녹화본에 아무것도 없다"는 건 아무것도 증명하지 못합니다. 카메라 배치도를 아는 건 설치 기사만이 아니라 조사관의 일이기도 합니다.

### 모든 로그 소스에 대해 알아야 할 세 가지 { #three-things }

믿고 쓰는 로그 소스마다 다음 세 가지에 답할 수 있어야 합니다.

- <strong>형식(Format)</strong> — 어떻게 저장되고 어떤 구조인가? (Windows는 이진 XML, 전통적인 Linux syslog는 텍스트 줄, 많은 클라우드·EDR 소스는 JSON.) 이게 어떻게 파싱할 수 있는지, 무엇이 잘못될 수 있는지를 정합니다.
- <strong>내용(Content)</strong> — 어떤 필드가 있고, 그게 실제로 무슨 뜻인가? (이 4688에 명령줄이 들어 있나? 저 IP는 클라이언트인가 프록시인가?)
- <strong>수집(Collection)</strong> — 호스트에서 나에게 어떻게 오고, 얼마나 빨리 오며, 오는 길에 무엇이 빠지거나 바뀌나?

로그를 읽는 건 분석가의 매일 일입니다. 수집 과정을 이해하면 "들어오는 걸 그냥 쳐다보기"에서 "원래 무엇이 보여야 하는지 알고, 없으면 개선을 요청하기"로 바뀝니다. 이 페이지의 나머지는 Windows에 대해 이 세 질문에 답합니다.

## Windows 이벤트 로깅은 어떻게 돌아가나 { #how-it-works }

### Linux와 무엇이 다른가 { #windows-vs-linux }

전통적인 Linux 시스템에서 로그는 대부분 그냥 텍스트입니다. 데몬이 syslog에 한 줄을 보내면, syslog가 `/var/log/auth.log` 같은 파일 끝에 붙입니다. 바로 `cat`이나 `grep`으로 볼 수 있습니다(이건 다음 섹션인 Linux 로그에서 systemd 저널과 함께 다룹니다).

Windows는 더 구조화된 — 그리고 더 복잡한 — 길을 갑니다.

- 운영체제와 애플리케이션이 이벤트를 <strong>로그 채널</strong>에 씁니다.
- 채널마다 <strong>`.evtx` 파일</strong>에 저장되는데, 이 파일에는 <strong>XML 레코드가 이진 형태로 인코딩</strong>되어 들어 있습니다.
- 그래서 `.evtx` 파일은 텍스트 편집기로 그냥 열 수 없습니다. 이 형식을 아는 도구가 해석해 줘야 합니다.
- 가장 익숙한 도구는 <strong>이벤트 뷰어(Event Viewer, `eventvwr.msc`)</strong>입니다. 왼쪽 창에 채널 목록이 나옵니다.

비유하면, Linux 텍스트 로그는 펼치기만 하면 읽을 수 있는 공책입니다. Windows `.evtx` 파일은 <strong>데이터베이스 파일</strong>에 더 가깝습니다. 데이터는 다 있고 잘 정리돼 있지만, 열려면 맞는 프로그램이 필요합니다. 복잡한 대신 얻는 것이 있습니다. Windows 이벤트는 모든 값에 이름 붙은 필드가 있어서, 아무렇게나 쓰인 텍스트보다 훨씬 믿을 만하게 파싱할 수 있습니다.

### 이벤트 뷰어를 열면 보이는 채널들 { #channels-overview }

이벤트 뷰어를 열면 왼쪽에 두 묶음이 보입니다.

- <strong>Windows 로그(Windows Logs)</strong> — 누구나 아는 전통적인 채널들. <strong>Application</strong>, <strong>Security</strong>, <strong>Setup</strong>, <strong>System</strong>, 그리고 <strong>Forwarded Events</strong>(Windows 이벤트 전달이 도착하는 곳).
- <strong>응용 프로그램 및 서비스 로그(Applications and Services Logs)</strong> — 더 세분화된 채널 수백 개. 대부분 `Microsoft → Windows → <구성 요소> → <종류>` 아래에 있습니다. 예를 들면 `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`, 설치했다면 `Microsoft-Windows-Sysmon/Operational`.

많은 사람이 Application, Security, System에서 멈춥니다. 그건 실수입니다. 공격을 잡는 데 가장 쓸모 있는 소스 몇 개(PowerShell 스크립트 블록, 예약 작업 변경, RDP 세션 기록, Defender 탐지, Sysmon)가 두 번째 묶음에 있습니다. 물론 나머지 상당수는 잡음입니다. SOC가 실제로 어떤 채널을 모아야 하는지는 이 섹션의 다음 페이지에서 다룹니다.

<strong>[보충] 채널 종류.</strong> 채널마다 용도를 알려 주는 종류가 있습니다.

| 종류 | 누구를 위한 것 | 기본으로 켜져 있나? | 예 |
| --- | --- | --- | --- |
| Admin | 관리자 — 보통 조치가 필요한 이벤트 | 예 | `Microsoft-Windows-PrintService/Admin` 같은 `…/Admin` 채널들 |
| Operational | 구성 요소의 분석·문제 해결 | 대개 예 | `Microsoft-Windows-PowerShell/Operational` |
| Analytic | 양이 많은 상세 추적 | 아니요(숨겨짐) | 여러 `…/Analytic` 채널 |
| Debug | 개발자 | 아니요(숨겨짐) | 여러 `…/Debug` 채널 |

Analytic과 Debug 채널은 <strong>보기 → 분석 및 디버그 로그 표시</strong>를 켜야 보이고, 켜기 전에는 아무것도 기록하지 않습니다. 양이 너무 많아서 중앙에 모을 가치는 거의 없습니다.

<strong>[보충] Security 채널은 특별합니다.</strong> 감사 하위 시스템을 통해 로컬 보안 기관(LSA)만 여기에 쓸 수 있습니다. 일반 프로그램은 Security에 이벤트를 넣을 수 없고, 그래서 이 채널을 더 믿을 수 있습니다. (읽는 데도 관리자 권한이나 "감사 및 보안 로그 관리" 특권이 필요합니다.)

### 로그가 지나가는 길, 한 단계씩 { #log-path }

무슨 일이 벌어진 순간부터 우리가 읽는 순간까지, 이벤트 하나의 여정입니다.

```
[program / OS component]           e.g. LSA, Service Control Manager, PowerShell, Sysmon
        |  "provider" writes an event (ID + fields) via the Event Log / ETW API
        v
[Windows Event Log service]        svchost.exe hosting the "EventLog" service
        |  uses the provider's metadata (manifest) to pick the channel
        v
[log channels]                     Security, System, Application, …/Operational
        |  each channel = one file
        v
C:\Windows\System32\winevt\Logs\*.evtx
        |
        +--> Event Viewer (eventvwr.msc)
        +--> PowerShell Get-WinEvent / wevtutil.exe
        +--> forensic parsers (EvtxECmd, Hayabusa, Chainsaw, …)
        +--> collection agents / Windows Event Forwarding --> SIEM
```

단계별로 보면 이렇습니다.

1. <strong>공급자가 이벤트를 쓴다.</strong> <strong>공급자(Provider)</strong>는 이벤트를 정의하고 내보내는 소프트웨어 구성 요소입니다. 예를 들어 `Microsoft-Windows-Security-Auditing`(LSA 감사), `Service Control Manager`, `Microsoft-Windows-PowerShell`, `Microsoft-Windows-Sysmon`. 공급자가 이벤트 ID와 그 이벤트 필드의 값을 줍니다.
2. <strong>Windows Event Log 서비스가 받는다.</strong> 이 서비스(`svchost.exe` 안에서 도는 `EventLog`)는 이벤트의 단 하나뿐인 우체국입니다. 공급자가 등록해 둔 정보(<strong>매니페스트(manifest)</strong>)를 보고 이 이벤트가 어느 채널로 갈지 압니다.
3. <strong>이벤트가 채널에 쓰인다.</strong> 채널마다 자기 `.evtx` 파일이 있고, 최대 크기와 보관 방식도 채널마다 있습니다(기본은 가득 차면 가장 오래된 이벤트부터 덮어쓰기).
4. <strong>무언가가 파일을 읽는다.</strong> 보통은 이벤트 뷰어지만, PowerShell, `wevtutil`, 포렌식 도구, 로그 에이전트도 같은 파일을 같은 Windows API로 읽습니다(오프라인 포렌식 파서는 이진 형식을 직접 풀어서 읽습니다).

파일 자체를 봅시다.

```
PS C:\> Get-ChildItem C:\Windows\System32\winevt\Logs |
>>   Sort-Object Length -Descending | Select-Object -First 6 Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}

Name                                                        MB
----                                                        --
Microsoft-Windows-Sysmon%4Operational.evtx                64.1
Security.evtx                                             20.1
System.evtx                                               20.1
Application.evtx                                          20.1
Microsoft-Windows-PowerShell%4Operational.evtx            15.1
Microsoft-Windows-TaskScheduler%4Operational.evtx         10.1
```

- `Get-ChildItem C:\Windows\System32\winevt\Logs` — 모든 채널의 `.evtx` 파일이 있는 폴더를 나열합니다.
- `Sort-Object Length -Descending | Select-Object -First 6 …` — 가장 큰 파일 6개를 MB 크기와 함께 보여 줍니다(`@{n='MB';e={…}}`는 계산해서 만든 열입니다).
- `Microsoft-Windows-Sysmon%4Operational.evtx 64.1` — `Microsoft-Windows-Sysmon/Operational` 채널. 파일 이름에는 `/`를 쓸 수 없어서 Windows가 <strong>`%4`</strong>로 바꿔 씁니다. 포렌식 이미지에서 채널 파일을 찾을 때는 `/`를 `%4`로 바꿔서 찾으세요. Sysmon은 기록이 많아서 보통 기본값보다 큰 최대 크기를 줍니다.
- `Security.evtx 20.1` — Security 채널. 약 20MB는 여러 Windows 버전에서 오래된 기본 최대 크기입니다. 바쁜 서버에서는 겨우 몇 시간 치밖에 안 담길 수 있어서, 보안 기준(baseline)들이 이 크기를 크게 늘리라고 하고, 중앙 수집도 빨라야 합니다.

<strong>공격자가 이 길에 관심 갖는 이유.</strong> 모든 단계가 방어자의 눈을 가릴 수 있는 곳입니다. EventLog 서비스를 멈추거나 죽이기, `auditpol`로 감사 끄기, 채널 크기를 줄여서 금방 덮어써지게 하기, `.evtx` 파일을 지우거나 망가뜨리기, 채널 비우기(MITRE ATT&CK <strong>T1070.001</strong> Windows 이벤트 로그 지우기, <strong>T1562.002</strong> Windows 이벤트 로깅 끄기). Security 로그 자체를 지우면 <strong>Security 1102</strong>("감사 로그를 지웠습니다")가 남고, 다른 채널을 지우면 <strong>System 104</strong>가 남습니다. 그래서 로그는 빨리 호스트 밖으로 나가야 합니다. SIEM에 있는 사본은 엔드포인트에서 무슨 일이 벌어져도 살아남습니다. [방어 무력화와 로그 삭제](../../../adversary/impair-defenses-log-clearing.md)를 참고하세요.

### 명령줄로 이벤트 읽기 { #reading-events }

이벤트 하나 볼 때는 이벤트 뷰어로 충분하지만, 분류(triage)와 헌팅에서는 PowerShell을 씁니다. 먼저, 어떤 채널이 있고 얼마나 차 있을까요?

```
PS C:\> Get-WinEvent -ListLog Security, System, 'Microsoft-Windows-PowerShell/Operational' |
>>   Format-Table LogName, RecordCount, MaximumSizeInBytes, LogMode -AutoSize

LogName                                  RecordCount MaximumSizeInBytes   LogMode
-------                                  ----------- ------------------   -------
Security                                       41873           20971520  Circular
System                                         18240           20971520  Circular
Microsoft-Windows-PowerShell/Operational        9311           15728640  Circular
```

- `Get-WinEvent -ListLog …` — 이름을 준 채널들의 이벤트가 아니라 *설정*을 돌려줍니다. `-ListLog *`이면 그 PC의 모든 채널(수백 개)이 나옵니다.
- `RecordCount` — 지금 그 채널에 들어 있는 이벤트 수.
- `MaximumSizeInBytes 20971520` — 20MB. 가득 차면 `LogMode Circular`, 즉 가장 오래된 이벤트부터 덮어씁니다. 그러니 "Security에서 가장 오래된 이벤트"가 로컬 증거가 얼마나 과거까지 남아 있는지를 알려 줍니다.

이제 이벤트 자체 — 가장 최근 로그온 실패 세 건입니다.

```
PS C:\> Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 3

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
20/11/2026 02:14:09 AM        4625 Information      An account failed to log on....
20/11/2026 02:14:07 AM        4625 Information      An account failed to log on....
20/11/2026 02:14:05 AM        4625 Information      An account failed to log on....
```

- `-FilterHashtable @{LogName='Security'; Id=4625}` — 거르는 조건을 Event Log 서비스에 넘겨서, 맞는 이벤트만 돌려받습니다. 전부 가져와서 `Where-Object`로 거르는 것보다 훨씬 빠릅니다.
- `-MaxEvents 3` — 최신 것부터 세 건만.
- `ProviderName: Microsoft-Windows-Security-Auditing` — 이 이벤트들을 쓴 공급자(LSA 감사 공급자).
- `Id 4625` — <strong>4625 = "계정이 로그온하지 못했습니다"</strong>. 로그온을 *시도당한* PC에서, 로그온이 실패할 때마다(틀린 비밀번호, 없는 사용자, 사용 중지된 계정, 허용되지 않은 로그온 유형) 생깁니다. 공격자가 비밀번호를 추측하거나 뿌릴 때(T1110) 생기기 때문에, 4625가 몰려서 나오는 것 — 여기서는 4초에 세 건 — 은 전형적인 탐지 대상입니다.
- `LevelDisplayName Information` — *실패한* 로그온인데도 "정보"로 나오는 데 주목하세요. Security 감사 이벤트에서는 성공·실패가 수준이 아니라 <strong>키워드</strong>(감사 성공/감사 실패)에 담깁니다. 뒤에서 더 봅니다.
- `Message` — 사람이 읽게 만든 설명. 여기서는 잘렸습니다. 곧 보게 될 "일반" 보기가 이것입니다.

`wevtutil`은 Windows에 들어 있는 명령줄 도구로, XML을 빨리 뽑을 때 편합니다.

```
C:\> wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:1 /rd:true /f:xml
```

- `qe Security` — Security 채널에서 이벤트를 *조회(query events)*합니다.
- `/q:"*[System[(EventID=4625)]]"` — 이벤트의 System 부분에 거는 XPath 필터(이벤트 뷰어의 "현재 로그 필터링 → XML"과 같은 문법).
- `/c:1` — 한 건만. `/rd:true` — 거꾸로, 즉 최신 것부터. `/f:xml` — 원본 XML로 출력(`/f:text`이면 메시지 보기).

여기서 나오는 XML은 아래 [세 가지 보기](#three-views)에서 봅니다.

<strong>[보충] 모든 프로그램이 이벤트 로그를 쓰지는 않습니다.</strong> 어떤 애플리케이션은 자기 폴더에 텍스트나 다른 형식으로 자기 로그를 씁니다. IIS는 `C:\inetpub\logs\LogFiles` 아래 W3C 로그를, Windows DNS 서버는 텍스트 디버그 로그를 쓸 수 있고, 많은 외부 제품이 `C:\ProgramData\<업체>` 아래 로그를 둡니다. 이런 건 이벤트 뷰어에 절대 안 나오니, "모든 이벤트 채널 수집" 정책은 이것들을 소리 없이 놓칩니다.

## 어떤 보안 이벤트가 생길지 정하기 { #audit-settings }

켜지 않은 카메라는 녹화하지 않습니다. Windows 로그로 말하면, 일이 벌어지기 *전에* 뭔가가 그 이벤트를 만들도록 설정돼 있어야 이벤트가 존재합니다. 정하는 곳은 세 군데입니다.

### 1. 기본 기능: Windows 감사 정책 { #audit-policies }

운영체제 보안 이벤트의 주 스위치는 <strong>감사 정책</strong>입니다. 아주 세분화된 설정들 — "하위 범주(subcategory)" — 의 모음이고, 하나하나를 <strong>성공(Success)</strong>, <strong>실패(Failure)</strong>, 둘 다, 또는 아무것도 기록 안 함으로 정합니다. 예: 로그온, 로그오프, 프로세스 생성, 사용자 계정 관리, 보안 그룹 관리, 파일 시스템, 레지스트리, Kerberos 인증 서비스.

```
C:\> auditpol /get /subcategory:"Logon","Process Creation","File System"
System audit policy
Category/Subcategory                      Setting
Logon/Logoff
  Logon                                   Success and Failure
Detailed Tracking
  Process Creation                        Success
Object Access
  File System                             No Auditing
```

- `auditpol /get /subcategory:…` — 이름을 준 하위 범주들의 *실제 적용 중인* 고급 감사 정책을 보여 줍니다(`/category:*`이면 전부). 관리자로 실행합니다.
- `Logon … Success and Failure` — 성공한 로그온은 <strong>4624</strong>, 실패는 <strong>4625</strong>를 만듭니다. 성공만 켜 두면 비밀번호 추측이 안 보이게 됩니다.
- `Process Creation … Success` — 프로그램이 시작될 때마다 <strong>4688</strong>("새 프로세스를 만들었습니다")을 만듭니다. 여기서 실패는 별 의미가 없어서 보통 성공만 켭니다. "프로세스 생성 이벤트에 명령줄 포함"이라는 별도 정책도 켜야 한다는 걸 잊지 마세요. 안 그러면 4688에 인자가 안 나옵니다.
- `File System … No Auditing` — 파일 접근 이벤트(<strong>4663</strong>) 없음. 개체 접근은 하위 범주를 켜는 게 절반일 뿐입니다. 관심 있는 폴더나 레지스트리 키에 감사 항목(<strong>SACL</strong>, 시스템 접근 제어 목록)도 걸어야 합니다. 디스크의 모든 파일을 감사하면 기록에 파묻힙니다.

<strong>[보충] 옛 방식 vs 고급 감사 정책.</strong> Windows에는 두 층이 있습니다. 옛 "기본" 범주 9개(로컬 정책 → 감사 정책)와, 새 "고급" 하위 범주 약 60개(고급 감사 정책 구성). 그룹 정책으로 둘 다 설정하면 헷갈리게 서로 덮어쓸 수 있습니다. 실무 원칙은 고급 정책만 쓰고, <strong>"감사: 감사 정책 하위 범주 설정이 감사 정책 범주 설정을 무시하도록 강제"</strong>(`SCENoApplyLegacyAuditPolicy`)를 켜는 것입니다. 그리고 GPO 화면을 믿지 말고 실제 호스트에서 `auditpol`로 결과를 확인하세요.

<strong>공격자가 관심 갖는 이유:</strong> `auditpol /clear`나 `auditpol /set /subcategory:"Logon" /success:disable`은 아무것도 지우지 않고 기록만 끕니다. 로그를 지우는 것보다 조용합니다. 감사 정책 변경 자체는 <strong>4719</strong>("시스템 감사 정책이 변경되었습니다")로 남으니, 경보를 걸 만합니다. (감사 정책 설계는 [PAW, 권한과 특권, EDR, DLP, UEBA, 감사 로깅](../endpoint-defense/paw-edr-dlp-ueba.md#audit-logging)에서도 다뤘습니다.)

### 2. 추가 도구: Sysmon과 사용자 스크립트 { #add-ons }

기본 감사 정책에는 빈틈이 있습니다. 프로세스별 나가는 네트워크 연결을 자세히, 실행 파일 해시, DLL 로드, 명명된 파이프, 프로세스별 DNS 질의 같은 건 기록하지 않습니다. 그래서 많은 조직이 <strong>Sysmon(System Monitor)</strong>을 더합니다. Microsoft Sysinternals의 무료 도구로, 드라이버와 서비스를 설치하고 자기 채널 `Microsoft-Windows-Sysmon/Operational`에 풍부한 이벤트를 씁니다. 해시와 부모 명령줄이 붙은 프로세스 생성(Sysmon 1), 네트워크 연결(3), 드라이버·이미지 로드(6, 7), LSASS 열기 같은 프로세스 접근(10), 파일 생성(11), 레지스트리 변경(12~14), DNS 질의(22) 등입니다. 일반 이벤트 채널에 쓰기 때문에, Security를 모으는 에이전트가 그대로 같이 모을 수 있습니다. 가치는 거의 전적으로 <strong>설정 파일</strong> — 무엇을 넣고 뺄지 — 에 달려 있습니다.

<strong>나만의 채널</strong>을 만들 수도 있습니다. 짧은 PowerShell 스크립트로 새 로그를 등록하고 아무 텍스트나 쓸 수 있습니다. 예를 들어 매일 밤 로컬 관리자 구성원을 점검한 결과를 써 두면, 로그 에이전트가 다른 것과 함께 실어 보냅니다.

```
PS C:\> New-EventLog -LogName 'SOC-Checks' -Source 'LocalAdminAudit'
PS C:\> Write-EventLog -LogName 'SOC-Checks' -Source 'LocalAdminAudit' -EventId 100 `
>>   -EntryType Information -Message 'Local Administrators: CORP\Domain Admins, CORP\ws-admins, WS-FIN-0217\Administrator'
```

- `New-EventLog -LogName 'SOC-Checks' -Source 'LocalAdminAudit'` — `SOC-Checks`라는 새 전통형 채널과, 거기에 쓸 수 있는 원본(공급자) 이름을 등록합니다. 관리자 권한이 필요하고, PC마다 한 번만 하면 됩니다.
- `Write-EventLog … -EventId 100 -EntryType Information -Message '…'` — 이벤트 하나를 씁니다. ID 체계는 우리가 정하니(여기서 100 = "로컬 관리자 스냅숏"), 문서로 남겨 두세요.
- 이제 SIEM에서 구성원 목록이 바뀌면 경보를 걸 수 있습니다. <strong>[주의]</strong> 이 두 cmdlet은 <strong>Windows PowerShell 5.1</strong>에만 있고, PowerShell 7에서는 빠졌습니다. PowerShell 7에서는 `eventcreate.exe`나 짧은 .NET 호출을 쓰거나, 스크립트를 `powershell.exe` 5.1로 돌리세요.

### 3. 스스로 로그를 쓰는 애플리케이션 { #app-logging }

Windows 이벤트 로그를 쓰지 *않는* 애플리케이션은, 무엇이 기록될지가 전적으로 그 애플리케이션의 설정과 능력에 달려 있습니다. 웹 서버, DNS 서버, 프록시 같은 네트워크 서비스라면 좋은 방법이 두 가지 있습니다.

- <strong>서비스 자체 로깅을 설정해서</strong> 보안에 필요한 필드를 모두 넣고(IIS라면 클라이언트 IP, `X-Forwarded-For`, 사용자 에이전트, URI 쿼리, 상태 코드, 바이트 수. DNS라면 질의와 응답), 그 파일을 에이전트로 모읍니다.
- <strong>네트워크에서 잡기.</strong> <strong>Zeek</strong>나 <strong>Suricata</strong> 같은 네트워크 센서는 서버 설정과 상관없이 일정한 형식의 `http.log`, `dns.log` 같은 기록을 씁니다. [SMB](../other-protocols/smb.md) 같은 앞의 네트워크 페이지에서 그런 기록이 어떻게 생겼는지 봤습니다.

보통은 둘 다 원합니다. 서버 로그는 애플리케이션이 무엇을 *결정했는지*, 네트워크 로그는 실제로 무엇이 *오갔는지*를 보여 줍니다.

## 모든 Windows 이벤트에 붙는 것: 메타데이터 { #log-breakdown }

채널 안에서 각 이벤트는 여러 메타데이터 필드와 함께 쓰입니다. 이벤트 뷰어 일반 탭 아래쪽에 보이고, 가장 먼저 거르는 기준이 됩니다.

### 수준(Level) — 얼마나 심각한가? { #level }

수준은 메시지의 중요도를 나타냅니다. XML에서는 숫자이고, 이벤트 뷰어는 낱말로 보여 줍니다.

| XML `Level` | 보이는 이름 | 뜻 |
| --- | --- | --- |
| 0 | 정보(LogAlways) | 항상 기록. Security 감사 이벤트가 이 값을 씀 |
| 1 | 위험(Critical) | 심각한 실패. 예: 예기치 않은 재부팅(Kernel-Power 41) |
| 2 | 오류(Error) | 문제. 예: 서비스 시작 실패 |
| 3 | 경고(Warning) | 눈여겨볼 만한 가능성 있는 문제 |
| 4 | 정보(Information) | 정상 동작 |
| 5 | 자세한 정보(Verbose) | 상세 추적 |

대부분의 이벤트는 정보 수준입니다. 충돌이나 실패를 찾을 때(변조 뒤 보안 제품이 죽음, 실행 파일이 바꿔치기돼서 서비스가 안 뜸) 수준 1~3으로 거르면 쓸모 있습니다. 하지만 <strong>Security 이벤트에서 수준은 아무것도 말해 주지 않습니다.</strong> 성공도 실패도 0입니다. 둘을 가르는 건 <strong>키워드</strong> 필드입니다. `Audit Success`(`0x8020000000000000`) 또는 `Audit Failure`(`0x8010000000000000`). 이벤트 뷰어 Security 로그의 "키워드" 열에 나옵니다.

### 원본(공급자) — 누가 썼나? { #source }

어떤 채널은 쓰는 프로그램이 하나뿐입니다. 하지만 <strong>Application</strong>이나 <strong>System</strong> 같은 채널에는 여러 프로그램이 함께 씁니다. <strong>원본(Source)</strong> 필드(XML에서는 `Provider Name`)로 어느 이벤트를 어느 프로그램이 만들었는지 구분합니다. 예를 들어 System에는 `Service Control Manager`(서비스 설치와 상태 변경), `Microsoft-Windows-Kernel-General`(시간 변경, 부팅), `Microsoft-Windows-Eventlog`(로그 지움, 104) 등이 나란히 섞여 있습니다.

### 이벤트 ID — 어떤 종류의 이벤트인가? { #event-id }

이벤트 ID는 Windows 로그에서 가장 중요한 필드입니다. 공급자마다 정해진 이벤트 ID 목록이 있어서, 같은 종류의 이벤트는 늘 같은 번호를 갖고 찾기 쉽습니다. Security에서 성공한 로그온은 어느 PC에서든 모두 <strong>4624</strong>, 실패한 로그온은 모두 <strong>4625</strong>입니다.

<strong>[정정] 이벤트 ID는 채널마다도, 전체에서도 아니라 공급자마다 하나뿐입니다.</strong> 흔한 단순화는 "채널 안에서 이벤트 ID는 하나뿐"이라는 말입니다. 엄밀히는 ID를 정하는 건 *공급자*이고, 한 채널에 여러 공급자가 들어 있을 수 있으니, 같은 채널 안에서도 같은 번호가 다른 뜻일 수 있습니다. **System** 채널의 실제 예입니다.

```
PS C:\> Get-WinEvent -FilterHashtable @{LogName='System'; Id=1} -MaxEvents 4 |
>>   Format-Table TimeCreated, Id, ProviderName -AutoSize

TimeCreated            Id ProviderName
-----------            -- ------------
19/11/2026 07:58:31     1 Microsoft-Windows-Power-Troubleshooter
19/11/2026 07:58:30     1 Microsoft-Windows-Kernel-General
18/11/2026 23:10:02     1 Microsoft-Windows-Kernel-General
18/11/2026 17:42:55     1 Microsoft-Windows-Power-Troubleshooter
```

- 네 줄 모두 `Id 1`이고, 모두 System 채널입니다.
- `Microsoft-Windows-Power-Troubleshooter`의 ID 1은 "시스템이 저전력 상태에서 다시 시작되었습니다"(절전에서 깨어남)라는 뜻입니다.
- `Microsoft-Windows-Kernel-General`의 ID 1은 "시스템 시간이 변경되었습니다"라는 뜻입니다. 시계를 바꾸는 건 타임라인을 헷갈리게 하는 반(反)포렌식 수법이라, 이건 중요할 수 있습니다.
- 그리고 Sysmon 채널의 ID 1은 "프로세스 생성"입니다. `EventID=1`만으로 짠 탐지는 이 셋을 다 섞습니다.

그러니 믿을 수 있는 열쇠는 <strong>공급자 + 이벤트 ID</strong>입니다(수집 필터를 분명히 하려면 채널까지). 채널을 넘나들어도 잘 알려진 보안 ID(4624, 4688, 7045 등)는 사실상 하나뿐이라서 사람들이 지름길을 써도 대개 괜찮습니다 — 안 괜찮아질 때까지는요.

### 작업 범주(Task Category) — 설명 한 줄 더 { #task-category }

작업 범주도 메타데이터 필드입니다. 공급자마다 번호 붙은 범주와 이름표를 따로 정할 수 있습니다. Security에서는 감사 하위 범주별로 이벤트를 묶습니다. 4624와 4625의 작업 범주는 <strong>Logon</strong>(XML에서 `<Task>12544</Task>`), 4688은 <strong>Process Creation</strong>(13312), 4720은 <strong>User Account Management</strong>(13824)입니다. 넓게 거를 때("로그온 관련 전부 보여 줘") 쓸모 있지만, 이벤트 ID가 더 정확합니다.

<strong>[보충]</strong> 앞으로 만날 다른 System 필드들 — `Opcode`, `Version`, `EventRecordID`, `Execution ProcessID/ThreadID`, `Correlation`, `Computer`, `TimeCreated` — 은 다음 페이지에서 칸별로 뜯어봅니다. 지금 팁 하나만: `EventRecordID`는 채널마다 매기는 일련번호입니다. 내보낸 로그에서 번호가 건너뛰면(51203 다음이 51890이고 그 사이가 없음) 이벤트가 지워졌다는 표시일 수 있습니다.

## 같은 로그, 다른 보기 { #three-views }

Windows 로그는 속은 XML이지만, 이벤트 뷰어는 세 가지로 보여 줄 수 있습니다. 읽기 쉽지만 구조가 덜한 것부터 원본 XML까지. `WS-FIN-0217`의 로그온 실패 하나를 봅시다.

### 보기 1: 일반("메시지") { #general-view }

이벤트를 클릭하면 보이는 화면입니다. 사람이 읽기 가장 쉽고, 분석가가 보통 읽는 게 이겁니다.

```
An account failed to log on.

Subject:
	Security ID:		NULL SID
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		NULL SID
	Account Name:		svc-sql
	Account Domain:		CORP

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Process Information:
	Caller Process ID:	0x0
	Caller Process Name:	-

Network Information:
	Workstation Name:	WS-MKT-0088
	Source Network Address:	10.20.7.54
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	...
```

편지처럼 읽힙니다. `WS-MKT-0088`(`10.20.7.54`)에서 온 NTLM 네트워크 로그온(유형 3)이 `CORP\svc-sql` 계정으로 시도됐다가 비밀번호가 틀려서 실패했습니다(`0xC000006A` = 있는 계정인데 비밀번호 틀림, `0xC0000064`라면 사용자가 없음). 그런데 탭과 공백이 들쭉날쭉하고, 이름표가 반복되며("Security ID"가 두 번, 뜻은 다름), 문장이 <strong>운영체제 표시 언어로 번역</strong>됩니다. 한국어로 설치한 Windows에서는 같은 이벤트가 "계정에 로그온하지 못했습니다."로 나옵니다. 사람에게는 좋지만 파서에게는 고역입니다.

### 보기 2: 자세히 → 쉬운 보기 { #friendly-view }

<strong>자세히(Details)</strong> 탭을 누르고 <strong>쉬운 보기(Friendly View)</strong>를 고르면, 이벤트를 만든 실제 데이터가 XML 태그를 숨긴 나무 모양으로 보입니다.

```
- System
    - Provider  [ Name]  Microsoft-Windows-Security-Auditing
                [ Guid]  {54849625-5478-4994-a5ba-3e3b0328c30d}
      EventID   4625
      Level     0
      Task      12544
      Keywords  0x8010000000000000
    - TimeCreated [ SystemTime] 2026-11-20T02:14:09.4371152Z
      EventRecordID 51207
      Channel   Security
      Computer  WS-FIN-0217.corp.example
- EventData
      TargetUserName      svc-sql
      TargetDomainName    CORP
      Status              0xc000006d
      SubStatus           0xc000006a
      LogonType           3
      LogonProcessName    NtLmSsp
      AuthenticationPackageName NTLM
      WorkstationName     WS-MKT-0088
      IpAddress           10.20.7.54
      IpPort              0
```

### 보기 3: 자세히 → XML 보기 { #xml-view }

그리고 전체 XML — 이벤트가 실제로 저장된 진짜 모습입니다.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-20T02:14:09.4371152Z" />
    <EventRecordID>51207</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WS-FIN-0217.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">svc-sql</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="LogonProcessName">NtLmSsp </Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="WorkstationName">WS-MKT-0088</Data>
    <Data Name="IpAddress">10.20.7.54</Data>
    <Data Name="IpPort">0</Data>
  </EventData>
</Event>
```

지금 중요한 부분만 읽어 봅니다(System과 EventData 전체를 칸별로 뜯어보는 건 다음 페이지에서 합니다).

- `<Provider Name="Microsoft-Windows-Security-Auditing" …/>`와 `<EventID>4625</EventID>` — 이벤트 종류를 정하는 공급자 + ID 짝.
- `<Level>0</Level>`과 `<Keywords>0x8010000000000000</Keywords>` — 모든 감사 이벤트처럼 수준은 0이고, 키워드 값이 <strong>감사 실패(Audit Failure)</strong>입니다.
- `<Task>12544</Task>` — 작업 범주 Logon.
- `<TimeCreated SystemTime="…Z" />` — 항상 <strong>UTC</strong>(끝의 `Z`)로 저장됩니다. 이벤트 뷰어 일반 탭은 보는 사람의 현지 시간으로 바꿔 보여 줘서, 타임라인 실수의 단골 원인입니다. SIEM에서는 UTC를 유지하세요.
- `<Computer>WS-FIN-0217.corp.example</Computer>` — 이벤트를 *기록한* PC. 로그온 시도가 출발한 곳이 아니라 시도당한 곳입니다.
- `TargetUserName` / `TargetDomainName` — 누군가 쓰려고 한 계정.
- `FailureReason %%2313` — 문장이 아니라 <strong>메시지 문자열 자리표시자</strong>입니다. `%%2313`을 메시지 표에서 찾아서 일반 보기에서는 "Unknown user name or bad password."로 바꿔 보여 줍니다. XML 값 일부가 암호처럼 보이는 이유입니다.
- `LogonType 3`, `IpAddress 10.20.7.54`, `WorkstationName WS-MKT-0088` — 시도가 어디서 왔는지. 한 IP에서 여러 사용자 이름으로 이런 게 몰려 나오면 비밀번호 뿌리기(T1110.003)입니다.

### 메시지는 어떻게 만들어지나 — SIEM에 왜 중요한가 { #message-template }

일반 보기는 파일에 저장돼 있지 않습니다. 공급자가 이벤트 ID마다 번호 붙은 빈칸이 있는 <strong>메시지 템플릿(문장 틀)</strong>을 함께 가지고 있고, 대략 이렇게 생겼습니다.

```
An account failed to log on.
...
Account For Which Logon Failed:
	Account Name:		%6
	Account Domain:		%7
...
Network Information:
	Workstation Name:	%14
	Source Network Address:	%20
```

이벤트를 열면 Windows가 EventData 값을 순서대로 빈칸에 채우고(`%6` ← `TargetUserName`, `%7` ← `TargetDomainName` …), `%%` 자리표시자를 풀어서 결과를 보여 줍니다. Windows와 대부분의 로그 에이전트는 이렇게 만든 문장을 <strong>`Message`</strong> 필드라고 부릅니다. 비유하면 메일 병합 편지입니다. XML은 엑셀 한 줄, 템플릿은 편지 양식, 일반 보기는 인쇄된 편지입니다.

실무에서 세 가지가 따라 나옵니다.

1. <strong>문장을 만들려면 읽는 PC에 그 공급자의 템플릿이 있어야 합니다.</strong> 내보낸 `.evtx`를 그 공급자가 설치되지 않은 PC(예: 분석용 노트북에서 Sysmon이나 다른 업체 로그)에서 열면 이벤트 뷰어는 "원본 …의 이벤트 ID …에 대한 설명을 찾을 수 없습니다"라고 나옵니다. 데이터가 사라진 건 아닙니다. XML/자세히 보기에는 그대로 있습니다.
2. <strong>무엇을 보여 줄지는 템플릿이 정합니다.</strong> 로그를 만든 쪽이 메시지에 어떤 필드를 넣을지 고릅니다. 어떤 EventData 값은 일반 보기에 아예 안 나오니, 메시지만 읽으면 필드를 놓칠 수 있습니다.
3. <strong>SIEM에는 구조화된 필드를 보냅니다.</strong> 로그를 모아서 보낼 때 에이전트는 XML 데이터, 만든 메시지, 또는 둘 다를 보낼 수 있고, 이 선택이 받는 쪽에서 어떻게 파싱될지를 정합니다.
    - <strong>XML / EventData 필드</strong>는 형식이 잘 잡혀 있고, 이름이 붙어 있으며, 언어와 상관없고, SIEM이 믿을 만하게 뽑기 쉽습니다(`TargetUserName`, `IpAddress`, `LogonType` …). 이건 늘 보내야 합니다.
    - <strong>메시지</strong>는 사람이 읽기 쉽고, XML 필드 이름이 밋밋한 이벤트(어떤 공급자는 `param1`, `param2` …만 줌)에서 쓸모 있습니다. 하지만 탭과 공백이 들쭉날쭉한 자유 텍스트이고, 언어마다 바뀌며, 이벤트 크기를 몇 배로 키웁니다. 많은 팀이 수집 단계에서 버리거나 일부 이벤트에만 남깁니다.

<strong>[보충]</strong> 여러 나라에 걸친 환경에서 실제로 일어나는 실패: SIEM 파서가 메시지의 `Account Name:`에 정규식을 걸어 사용자 이름을 뽑습니다. 영어로 설치한 호스트에서는 되는데, 한국어·일본어·독일어로 설치한 호스트에서는 소리 없이 빈 값을 돌려줍니다. EventData 필드를 파싱하면 이 문제가 아예 없습니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    구조는 그대로입니다. 공급자가 이벤트를 쓰고, Windows Event Log 서비스가 채널로 나누고, 채널은 `C:\Windows\System32\winevt\Logs`에 이진 XML `.evtx` 파일로 있고, 이벤트 뷰어·`Get-WinEvent`·`wevtutil`이 읽습니다. 감사 정책이 어떤 Security 이벤트가 생길지 정하는 것도, 일반/쉬운 보기/XML 세 가지 보기, 메시지 템플릿 방식, "공급자 + 이벤트 ID"로 이벤트를 구분하는 것도 같습니다. 이벤트 ID 4624, 4625, 4688, 4719, 1102도 바뀌지 않았고, 메시지 문장 대신 구조화된 필드를 모으라는 조언은 SIEM들이 공통 스키마로 정규화하는 지금 오히려 더 중요해졌습니다.

!!! info "[변경됨] 바뀐 점"
    - **Sysmon이 이제 Windows에 들어 있습니다.** Windows 11의 2026년 2월 선택 업데이트(KB5077241)부터 Sysmon 기능이 기본 제공 선택적 기능으로 들어왔습니다. **기본은 꺼져 있습니다.** 기능을 켜고 설정 파일도 따로 줘야 하며, 이벤트는 여전히 수집해야 합니다. 서버 지원과 세부 동작은 차례로 나오는 중이니, 짐작하지 말고 우리 빌드에 맞는 최신 Microsoft 문서를 확인하세요.
    - **에이전트가 바뀌었습니다.** Microsoft의 옛 Log Analytics 에이전트(MMA)는 2024년에 은퇴했고, Microsoft Sentinel용으로는 데이터 수집 규칙(DCR)을 쓰는 Azure Monitor Agent가 대신합니다. Elastic, Splunk 등도 통합 에이전트로 옮겨 갔습니다. Windows 이벤트 전달(WEF/WEC)은 여전히 기본 기능이고, 무료 수집 계층으로 널리 쓰입니다.
    - **중요한 신호의 상당 부분이 더는 로컬 채널에 없습니다.** 클라우드 로그인(Entra ID), Microsoft 365 감사 데이터, EDR 텔레메트리는 `.evtx` 파일이 아니라 API로 모읍니다. 엔드포인트 이벤트 로그는 여전히 꼭 필요하지만, 여러 소스 중 하나입니다.
    - **오프라인 분류 도구가 성숙했습니다.** EvtxECmd 같은 파서와, `.evtx` 위에서 Sigma 규칙을 바로 돌리는 Hayabusa·Chainsaw 같은 규칙 기반 스캐너가 이제 DFIR 기본 도구이고, SIEM에 한 번도 수집되지 않은 호스트를 볼 때 특히 쓸모 있습니다.
    - Microsoft 문서 주소가 docs.microsoft.com에서 **learn.microsoft.com**으로 옮겨 갔습니다. 예전 자료가 가리키던 이벤트 스키마 페이지들은 새 주소에 그대로 있습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **기본 로그 크기로 충분하다고 생각하지 마세요.** 채널당 약 20MB면 바쁜 서버에서는 몇 시간 만에 Security가 덮어써질 수 있습니다. 크기를 늘리고(기준들은 보통 Security에 수백 MB를 요구) *그리고* 이벤트를 빨리 호스트 밖으로 보내세요.
    - **탐지를 `EventID = N` 하나로만 짜지 마세요.** 공급자(또는 채널)도 꼭 같이 고정하지 않으면, 번호만 같은 엉뚱한 이벤트가 섞입니다.
    - **여러 언어·여러 버전이 섞인 환경에서 Message 필드를 정규식으로 파싱하지 마세요.** EventData 필드를 쓰세요.
    - **결과 0건을 "안 일어났다"로 읽지 마세요.** 그 시간대의 감사 정책, 채널 수집 여부, 보관 기간을 먼저 확인하세요.
    - **PowerShell 7에서 `New-EventLog`/`Write-EventLog`에 기대지 마세요.** 거기엔 없습니다.
    - **감사 설정을 GPO 화면만 보고 믿지 마세요.** 실제 호스트에서 `auditpol`로 적용된 정책을 확인하고, **4719**와 **1102**/**104**에 경보를 거세요.

## 확인 문제 { #quiz }

### 문제 1

동료가 `EventID = 1`인 이벤트를 세어서 "호스트별 프로세스 생성 수" SIEM 대시보드를 만들었습니다. 그런데 Sysmon이 설치되지 않은 노트북들에도 매일 아침 "프로세스 생성"이 몇 건씩 잡히고, 모두 프로세스 이름이 비어 있습니다. 무슨 일이고, 쿼리를 어떻게 짜야 할까요?

??? success "정답과 해설"
    **무슨 일인가:** 이벤트 ID는 **공급자마다** 하나뿐입니다. Sysmon이 없는 노트북에도 ID 1인 이벤트는 있습니다. 예를 들어 System 채널의 `Microsoft-Windows-Power-Troubleshooter`(절전에서 깨어남 — 매일 아침)나 `Microsoft-Windows-Kernel-General`(시간 변경). 쿼리가 이벤트 종류가 아니라 번호에 걸려 있고, 이 이벤트들에는 프로세스 이름 필드가 없으니 값이 비어 나옵니다.

    **고치는 법:** ID와 함께 출처를 고정합니다 — 채널 `Microsoft-Windows-Sysmon/Operational` *그리고* 공급자 `Microsoft-Windows-Sysmon` *그리고* `EventID = 1` — 그다음에 셉니다. Sysmon이 없는 곳도 보고 싶다면, `Microsoft-Windows-Security-Auditing`의 Security **4688**(명령줄 기록을 켠 상태)로 두 번째 갈래를 더합니다.

### 문제 2

SIEM이 로그온 실패의 사용자 이름을 메시지 문장의 `Account Name:`에 걸어서 뽑습니다. 회사 인수 뒤, 새 자회사의 서버(한국어로 설치)에서 오는 4625는 사용자 필드가 비어 있습니다. 또 따로, 분석용 노트북에서 내보낸 Sysmon `.evtx`를 열었더니 이벤트 뷰어가 "원본 Microsoft-Windows-Sysmon의 이벤트 ID 1에 대한 설명을 찾을 수 없습니다"라고 합니다. 두 문제를 생각 하나로 설명하고, 해결책을 말해 보세요.

??? success "정답과 해설"
    **생각 하나:** 읽기 좋은 메시지는 **이벤트 안에 저장돼 있지 않습니다.** 보여 줄 때(또는 에이전트가 만들 때) EventData 값을 공급자의 **메시지 템플릿**에 채워서 만들고, 그 템플릿은 언어마다 다르며 문장을 만드는 PC에 있어야 합니다.

    - 한국어 서버에서는 템플릿이 한국어라서, 문장에 `Account Name:`이 없고 정규식이 아무것도 못 찾습니다.
    - 분석용 노트북에는 Sysmon 공급자(와 템플릿)가 설치돼 있지 않아서, 이벤트 뷰어가 메시지를 못 만듭니다. 데이터는 **자세히 → XML**에 그대로 있습니다.

    **해결책:** 어느 언어에서나 이름이 같은 구조화된 **EventData** 필드(`TargetUserName`, `IpAddress`, `LogonType` …)를 파싱하고, 에이전트가 그걸 꼭 보내게 합니다. 메시지는 사람을 위한 편의로만 두거나(양을 줄이려면 버리기도 합니다), 오프라인 작업에서는 이벤트 뷰어의 문장 만들기에 기대지 말고 XML 필드를 읽는 파서를 쓰거나 공급자를 설치합니다.

### 문제 3

사고 대응 중, 2주 전 비밀번호 뿌리기가 의심되는 시간대의 파일 서버 `FS-02` 4625를 SIEM에서 찾았더니 **0건**입니다. 팀장은 "로그온 실패 없음"이라고 쓰자고 합니다. 동의하기 전에 무엇을, 어떤 순서로 확인하겠나요?

??? success "정답과 해설"
    0건은 "안 일어났다", "기록 안 됐다", "기록됐지만 안 모였다" 중 하나일 수 있습니다. 대략 이 순서로 확인합니다.

    1. **기록됐나?** `FS-02`에서 `auditpol /get /subcategory:"Logon"`을 돌리고(GPO 변경 이력도 확인), 그 시점에 실패 기록이 꺼져 있었다면 4625는 있을 수가 없습니다. 그 시간대 근처의 **4719** 감사 정책 변경을 찾아보세요. 공격자가 껐을 수도 있습니다.
    2. **로컬 증거가 아직 있나?** `Get-WinEvent -ListLog Security` → `MaximumSizeInBytes`, `LogMode`, 가장 오래된 이벤트 시간. 작은 순환 로그라면 2주 전 이벤트는 이미 덮어써졌을 가능성이 큽니다. **1102**(Security 로그 지움)나 **104**(다른 로그 지움)도 찾습니다.
    3. **모였나?** `FS-02`의 에이전트 설정에 Security 채널이 들어 있나? 그 시간대에 에이전트가 살아서 보내고 있었나(하트비트, 또는 그 호스트의 모든 이벤트 종류에 빈 구간이 있는지)? 필터나 파서가 4625나 검색한 필드를 버리지 않았나?
    4. **검색을 제대로 했나?** 호스트 이름 형식(`Computer`의 짧은 이름 vs FQDN), 시간대(이벤트는 UTC), 맞는 인덱스/공급자.
    5. **FS-02가 맞는 곳인가?** 4625는 로그온을 시도당한 PC에 남습니다. 도메인 계정 실패는 도메인 컨트롤러에 Kerberos(4771)나 NTLM 자격 증명 검증(4776) 실패로도 남을 수 있습니다.

    이걸 다 확인한 뒤에야 "로그온 실패 없음"이라고 쓸 수 있습니다. 그렇지 않으면 "해당 기간 데이터 없음"이라고 쓰고, 로깅 빈틈을 발견 사항으로 기록합니다.

## 관련 레퍼런스 { #related }

- [Windows 로그](index.md) — 이 섹션 개요
- [PAW, 권한과 특권, EDR, DLP, UEBA, 감사 로깅](../endpoint-defense/paw-edr-dlp-ueba.md) — 방어 쪽에서 본 감사 정책과 중앙 수집
- [Windows 이벤트 로그 (EVTX)](../../../windows/event-logs.md) · [Windows 이벤트 ID](../../../basics/windows-event-ids.md) · [방어 무력화와 로그 삭제](../../../adversary/impair-defenses-log-clearing.md)
