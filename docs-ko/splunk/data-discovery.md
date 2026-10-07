---
title: 데이터 탐색과 시간
tags:
  - concept
  - splunk
---

# 데이터 탐색과 시간 다루기 { #data-discovery-working-with-time }

<div class="dfir-meta" markdown>
**분류:** Splunk · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    헌팅을 하려면 먼저 **어떤 데이터가, 어떤 이름으로, 어떤 필드를 갖고, 어떤 시간 범위에 걸쳐 있는지** 알아야 합니다. 이 페이지는 새 Splunk 인스턴스(또는 BOTSv3 같은 새 데이터셋)에서 돌리는 10분짜리 정찰과, 엉뚱한 날짜를 검색하지 않게 해 주는 시간 규칙입니다.

## 1단계 — 어떤 인덱스와 소스타입이 있나? { #step-1-what-indexes-and-sourcetypes-exist }

```spl
| eventcount summarize=false index=* | table index, count
```

`eventcount`는 인덱스 메타데이터만 읽기 때문에 여기서는 `index=*`가 가볍고 써도 됩니다 — 이벤트를 건드리지 않고 모든 인덱스와 이벤트 수를 나열합니다.

```spl
| metadata type=sourcetypes index=botsv3
| eval first=strftime(firstTime,"%Y-%m-%d %H:%M"), last=strftime(lastTime,"%Y-%m-%d %H:%M")
| table sourcetype, totalCount, first, last
| sort - totalCount
```

`metadata`는 각 소스타입의 전체 개수와 처음/마지막 이벤트 시각을 인덱스에서 바로 돌려줍니다(즉시, 시간 범위 무관). `strftime`은 epoch 숫자를 읽기 쉬운 날짜로 바꿉니다. `first`/`last` 열이 **검색해야 할 시간 창**을 알려 줍니다 — BOTSv3 데이터는 2018년 8월에 있으므로 "최근 24시간" 검색은 아무것도 돌려주지 않습니다.

더 빠르고 유연한 대안:

```spl
| tstats count, min(_time) as first, max(_time) as last where index=botsv3 by sourcetype, host
| convert ctime(first) ctime(last)
| sort - count
```

`tstats`는 원시 이벤트를 읽지 않고 색인된 필드(`sourcetype`, `host`, `source`, `_time`)로 돌아갑니다 — "호스트별로 X가 얼마나 있나" 같은 질문에 쓰세요.

## 2단계 — 이벤트 하나는 어떻게 생겼나? { #step-2-what-does-one-event-look-like }

```spl
index=botsv3 sourcetype=WinEventLog earliest=0 | head 5
```

`earliest=0` = 인덱스의 맨 처음부터. 데이터셋의 날짜 범위를 아직 모를 때 유용합니다. 이벤트를 펼치고 왼쪽 **Interesting Fields** 패널을 보세요 — Splunk가 이미 추출한 필드들입니다. 필드를 클릭하면 상위 값 10개가 나옵니다.

```spl
index=botsv3 sourcetype=WinEventLog earliest=0
| fieldsummary maxvals=10
| table field, count, distinct_count, values
| sort - count
```

`fieldsummary`는 필드마다 한 행을 줍니다: 몇 개 이벤트에 있는지, 고유 값이 몇 개인지, 개수와 함께 값 샘플. 소스타입마다 한 번 돌리면 무엇으로 `stats by`를 할 수 있는지 알게 됩니다.

## 3단계 — 침해사고 대응에 중요한 소스타입 { #step-3-the-sourcetypes-that-matter-for-ir }

| 소스타입 (흔한 이름) | 무엇 | 주요 필드 |
|---|---|---|
| `WinEventLog` / `WinEventLog:Security` / `XmlWinEventLog:Security` | Windows Security 로그 | `EventCode`, `Account_Name`, `Logon_Type`, `Source_Network_Address`, `Logon_ID`, `New_Process_Name`, `Process_Command_Line`, `host` |
| `WinEventLog:System`, `WinEventLog:Application` | System/App 로그 | `EventCode`, `Service_Name`, `Service_File_Name` (7045), `Message` |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon | `EventID` (또는 `EventCode`), `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes`, `DestinationIp`, `DestinationPort`, `TargetFilename`, `TargetObject`, `QueryName`, `ProcessGuid` |
| `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` | PowerShell 스크립트 블록 `4104` | `ScriptBlockText`, `Path`, `EventCode` |
| `WinEventLog:Microsoft-Windows-TaskScheduler/Operational`, `…TerminalServices-LocalSessionManager/Operational` | 작업, RDP 세션 | |
| `stream:tcp`, `stream:http`, `stream:dns`, `stream:smb` | Splunk Stream (BOTS의 와이어 데이터) | `src_ip`, `dest_ip`, `dest_port`, `site`, `uri_path`, `http_user_agent`, `query`, `bytes_in/out` |
| `zeek:conn`, `zeek:dns`, `zeek:http`, `zeek:ssl`, `zeek:files` (또는 `bro:*:json`, `corelight_*`) | Zeek | [네트워크](../network/zeek/index.md) 참고 |
| `suricata` | IDS 경보 | `alert.signature`, `alert.severity`, `src_ip`, `dest_ip` |
| `osquery:results`, `osquery_results` | osquery | `name`, `columns.*` |
| `aws:cloudtrail` | AWS API | `eventName`, `userIdentity.arn`, `sourceIPAddress`, `errorCode` |
| `o365:management:activity`, `ms:aad:signin`, `ms:o365:reporting:messagetrace` | M365 / Entra | `Operation`, `UserId`, `ClientIP`, `ResultStatus` |
| `linux_secure`, `syslog`, `linux_audit`, `auditd` | Linux 인증/감사 | `process`, `user`, `src_ip` |
| `iis`, `access_combined`, `nginx:plus:access` | 웹 서버 | `cs_uri_stem`, `sc_status`, `c_ip`, `cs_User_Agent` |
| `symantec:ep:*`, `ms:defender:atp:*`, `crowdstrike:events:sensor`, `carbonblack:*` | EDR/AV | 벤더별 |
| `pan:traffic`, `pan:threat`, `cisco:asa`, `fortigate_traffic` | 방화벽 | `src`, `dest`, `dest_port`, `action`, `bytes_out` |

내 인스턴스에서 `metadata`를 돌려서 *나만의* 표를 만들어 두세요 — 이름은 애드온마다 다릅니다.

!!! warning "애드온 없는 Sysmon XML"
    Sysmon 소스타입에 `Image`, `CommandLine`, `EventID`가 없다면 **Splunk Add-on for Sysmon**(또는 같은 역할의 props/transforms)이 설치되지 않은 것입니다 — Splunk는 큰 XML 덩어리 하나로 봅니다. 랩에서 빠른 해결: 애드온 설치. 검색 안에서 급한 해결: `| spath` 또는 `| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"` — [rex와 필드](rex-and-fields.md) 참고.

## 4단계 — 필드 이름: `Account_Name` vs `user`, 그리고 CIM { #step-4-field-names-account_name-vs-user-and-cim }

원시 Windows 필드는 `Account_Name`이고, **Common Information Model(CIM)** 이름은 `user`입니다. 애드온이 검색 시점에 원시 → CIM으로 매핑하므로(필드 별칭과 계산 필드로), 잘 설정된 인스턴스에서는 둘 다 동작합니다. 아무것도 안 나올 때는 어느 이름이 있는지 확인하세요:

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 | head 100
| stats count(Account_Name) as raw, count(user) as cim, count(src_ip) as cim_ip, count(Source_Network_Address) as raw_ip
```

다중값 함정: `4624`와 `4688`에는 `Account_Name` 값이 **두 개**(Subject와 Target) 있습니다. `Account_Name`만 쓰면 둘 다 나옵니다. 대상 계정은 `mvindex(Account_Name, 1)`이나 애드온의 `user`/`src_user` 구분을 쓰세요.

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624
| eval subject=mvindex(Account_Name,0), target=mvindex(Account_Name,1)
| stats count by target, Logon_Type, host
```

`mvindex(field, n)`은 다중값 필드에서 n번째 값(0부터 시작)을 고릅니다. `4624`에서 0번 값은 로그온을 *수행한* 계정(대개 `-`나 컴퓨터), 1번 값은 *로그온한* 계정입니다.

## 시간 다루기 { #working-with-time }

| 수식어 | 의미 |
|---|---|
| `earliest=-24h` | 지금부터 24시간 전 |
| `earliest=-7d@d latest=@d` | 7일 전 자정부터 지난 자정까지 (하루 단위) |
| `earliest=@w1` | 이번 주 시작 (월요일) |
| `earliest=-1mon@mon latest=@mon` | 지난 달력 월 |
| `earliest=0` | 지금까지 색인된 전부 (랩 데이터는 괜찮지만 운영 환경에서는 절대 금지) |
| `earliest="08/20/2018:00:00:00" latest="08/21/2018:00:00:00"` | 절대 시각, `%m/%d/%Y:%H:%M:%S` |
| `_index_earliest=-1h` | **색인** 시각 기준 (Splunk가 받은 시각) — 늦게 도착한 이벤트 찾기 |
| `\| where _time > relative_time(now(), "-1h")` | 파이프라인 안에서 같은 일 |

맞춤(`@`) 단위: `s m h d w mon q y`, 요일은 `@w0`…`@w6` (`@w1` 월요일). 수식어는 왼쪽에서 오른쪽으로 이어집니다: `-7d@d+9h` = 7일 전 09:00.

**시간대:** Splunk는 `_time`을 UTC epoch으로 저장하고 **사용자 시간대**(Settings → Account → Time zone)로 *표시*합니다. Windows 이벤트는 이미 UTC이고, Zeek `ts`는 UTC epoch이며, 일부 앱 로그는 시간대 표시 없이 로컬 시간입니다 — `props.conf`의 `TZ`를 확인하세요. 사고 보고서에는 시간대를 명시하세요. 프로필과 상관없이 UTC로 보이려면:

```spl
| eval utc=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
```

**`_time` vs `_indextime`:** `_time`은 이벤트가 *일어난* 시각, `_indextime`은 Splunk가 받은 시각입니다. 차이(`eval lag=_indextime-_time`)는 포워더 지연, 또는 침해 상황에서 로그 전송을 멈췄다가 밀린 것을 한꺼번에 보낸 호스트를 보여 줍니다.

**시간으로 묶기:**

```spl
| bin _time span=1h        →  then  | stats count by _time, host        (table)
| timechart span=1h count by host                                       (chart, one column per host, top 10 + OTHER)
| timechart span=1h limit=0 useother=f count by host                   (all hosts, no OTHER bucket)
```

`timechart` = `bin` + `stats` + 피벗을 한 번에, 항상 `_time`으로 구간을 나눕니다. `span=`은 생략하면 자동으로 정해지니 일관된 보고서를 위해 명시하세요.

**레시피**

```spl
# Log gap detection: hosts that stopped logging (last event per host older than 2 hours)
| tstats latest(_time) as last where index=botsv3 sourcetype=WinEventLog by host
| eval age_h=round((now()-last)/3600,1)
| where age_h > 2
| convert ctime(last)
```

`tstats latest(_time)`은 원시 데이터를 훑지 않고 인덱스에서 읽은 호스트별 최신 이벤트이고, `age_h`는 그게 몇 시간 전인지입니다.

```spl
# Business hours vs after hours
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10
| eval hour=tonumber(strftime(_time,"%H")), dow=strftime(_time,"%a")
| eval when=if(hour>=8 AND hour<18 AND NOT dow IN ("Sat","Sun"),"business","after-hours")
| stats count by when, Account_Name
| sort when, - count
```

`strftime(_time,"%H")`는 시를 텍스트로 주고, `tonumber`는 비교할 수 있게 숫자로 바꾸며, `%a`는 요일 약어를 주고, `if`가 로그온마다 레이블을 붙입니다.

```spl
# Sort a specific day's events into a clean timeline
index=botsv3 (sourcetype=WinEventLog OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational") host=FYODOR-L
        earliest="08/20/2018:00:00:00" latest="08/21/2018:00:00:00"
| eval what=coalesce(CommandLine, Process_Command_Line, New_Process_Name, Message)
| table _time, sourcetype, EventCode, EventID, User, Account_Name, what
| sort 0 _time
```

`coalesce`는 여러 후보 중 존재하는 첫 필드를 골라서 서로 다른 소스타입이 `what` 열 하나를 공유하게 하고, `sort 0 _time`은 1만 행 제한 없이 모든 것을 시간순으로 정렬합니다.

## 참고 자료 { #references }

- [Splunk — Search time modifiers](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchTimeModifiers)
- [Splunk — About the Common Information Model](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709) · [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742)
- [BOTSv3 dataset](https://github.com/splunk/botsv3)
