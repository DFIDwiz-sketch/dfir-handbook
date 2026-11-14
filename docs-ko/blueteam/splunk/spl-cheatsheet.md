---
title: SPL 치트시트
tags:
  - tool
  - splunk
  - cheatsheet
---

# SPL 치트시트 { #spl-cheat-sheet }

<div class="dfir-meta" markdown>
**분류:** Splunk · **수준:** 기초 → 중급 · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    SPL은 파이프라인입니다: 첫 부분이 **이벤트를 찾고**(인덱스, 소스타입, 키워드), 그 뒤의 모든 `|`가 앞에서 온 것을 **변환**합니다 — 거르기, 계산, 묶기, 세기, 정렬, 표시. 명령 25개 정도만 익히면 침해사고 대응 작업의 95%를 할 수 있습니다.

## 검색의 구조 { #anatomy-of-a-search }

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4625 earliest=-24h latest=now
| eval user=lower(Account_Name)
| stats count by user, src_ip
| where count > 10
| sort - count
| head 20
```

위에서 아래로 읽으세요: **1)** `botsv3` 인덱스에서 최근 24시간의 로그온 실패 이벤트(`4625`)를 가져오고; **2)** 소문자 `user` 필드를 만들고; **3)** 사용자 + 출발지 IP별로 이벤트를 세고; **4)** 10개를 넘는 쌍만 남기고; **5)** 큰 것부터; **6)** 상위 20개. 각 줄은 앞 줄이 만든 행을 받습니다.

경험칙: **항상 인덱스를 지정하세요** (`index=*`는 느리고 운영 환경에서는 금지되는 경우가 많음); 가장 많이 걸러 내는 조건을 앞에 두세요 (자유 텍스트보다 `EventCode=4625` 먼저); `where`로 늦게 거르지 말고 검색창에서 일찍 거르세요; 결과가 많으면 `table` 대신 `stats`를 쓰세요.

## 검색 시점 필터링 (첫 `|` 앞) { #search-time-filtering-before-the-first }

| 문법 | 의미 |
|---|---|
| `index=botsv3` | 어느 인덱스 |
| `sourcetype=WinEventLog` · `source="WinEventLog:Security"` · `host=FYODOR-L` | 메타데이터 필드 |
| `EventCode=4688` | 필드 = 값 (문자열 값은 대소문자 무시) |
| `EventCode IN (4624, 4625, 4648)` | 목록 중 하나 |
| `user=admin*` | 와일드카드 (끝에 쓰면 빠름; 앞에 쓴 `*admin`은 느림) |
| `NOT user=SYSTEM` · `user!=SYSTEM` | 제외 (`NOT field=x`는 필드가 *없는* 이벤트도 남기고; `field!=x`는 그런 이벤트를 버림) |
| `"cmd.exe /c"` | 구문 (따옴표) |
| `mimikatz OR procdump` · `A AND B` (AND is implicit) | 논리 연산 |
| `earliest=-7d@d latest=@d` | 시간 수식어 — `@d`는 자정에 맞춤; `-7d@d` = 7일 전 자정 |
| `earliest="09/15/2026:00:00:00"` | 절대 시각 |
| `src_ip=10.0.0.0/24` | IP 필드에는 CIDR 사용 가능 |
| `TERM(10.0.0.5)` | 원시 토큰을 정확히 일치, 빠르고 분할(segmentation) 문제를 피함 |
| `CASE(Mimikatz)` | 대소문자 구분 키워드 |

## 명령 — 매일 쓰는 것들 { #commands-the-ones-you-use-daily }

각 행: 하는 일, 그리고 바로 복사해 쓸 수 있는 예시.

### 행 거르기와 다듬기 { #filter-shape-rows }

| 명령 | 하는 일 | 예시 |
|---|---|---|
| `search` | 파이프라인 중간에 다시 거르기 (검색창과 같은 문법) | `… \| search count > 5 user!=svc*` |
| `where` | **식**으로 거르기 (함수, 필드 간 비교) | `\| where bytes_out > 10*bytes_in AND like(dest, "10.%")` |
| `dedup` | 고유 값마다 첫 이벤트만 남기기 | `\| dedup user, host` · `\| dedup 3 host sortby -_time` |
| `head` / `tail` | 처음 / 마지막 N행 | `\| head 50` |
| `sort` | 행 정렬 (`-` = 내림차순; `0` = 1만 행 제한 없음) | `\| sort 0 - count, +user` |
| `reverse` | 순서 뒤집기 | |
| `fields` | 열 남기기 (또는 `-`로 제거) — 속도를 높임 | `\| fields _time, host, user, CommandLine` · `\| fields - _raw` |
| `table` | 열을 표로 보여 주기 (표시 전용) | `\| table _time host user CommandLine` |
| `rename` | 필드 이름 바꾸기 (와일드카드 가능) | `\| rename Account_Name as user, "Source Network Address" as src_ip` |
| `regex` | 필드에 정규식을 걸어 행 거르기 | `\| regex CommandLine="(?i)-enc\|-e\s+[A-Za-z0-9+/]{20,}"` |

### 새 필드 계산 { #compute-new-fields }

| 명령 | 하는 일 | 예시 |
|---|---|---|
| `eval` | 함수로 필드 만들기/수정 | `\| eval MB=round(bytes/1024/1024,2), user=lower(user)` |
| `eval` + `if` / `case` | 조건에 따른 값 | `\| eval type=case(Logon_Type==10,"RDP", Logon_Type==3,"Network", true(),"Other")` |
| `eval` + `coalesce` | 여러 필드 중 처음으로 null이 아닌 값 | `\| eval user=coalesce(Account_Name, user, User)` |
| `eval` + 문자열 함수 | `len`, `upper`, `lower`, `substr`, `replace`, `split`, `mvindex`, `trim`, `urldecode` | `\| eval domain=mvindex(split(query,"."),-2)` |
| `eval` + 시간 함수 | `strftime`, `strptime`, `relative_time`, `now()` | `\| eval day=strftime(_time,"%Y-%m-%d")` |
| `eval` + `match` / `like` / `cidrmatch` | 패턴 검사 (true/false 반환) | `\| eval internal=if(cidrmatch("10.0.0.0/8",dest_ip),"yes","no")` |
| `rex` | 정규식 이름 그룹으로 필드 추출 | `\| rex field=CommandLine "-enc\s+(?<b64>[A-Za-z0-9+/=]+)"` — [rex와 필드](rex-and-fields.md) 참고 |
| `rex mode=sed` | 필드 안에서 찾아 바꾸기 | `\| rex field=user mode=sed "s/^CORP\\\\//"` |
| `spath` | JSON/XML에서 필드 꺼내기 | `\| spath input=_raw path=Event.EventData.Data{@Name}` |
| `lookup` | CSV/KV 룩업으로 보강 | `\| lookup asset_inventory ip as dest_ip OUTPUT owner, criticality` |
| `iplocation` | GeoIP 위치 | `\| iplocation src_ip` |
| `fillnull` | null 값 채우기 | `\| fillnull value="-" user, src_ip` |
| `makemv` / `mvexpand` | 문자열을 다중값으로 쪼개기 / 값마다 한 행으로 | `\| makemv delim="," answers \| mvexpand answers` |
| `convert` | 포맷 변환 (epoch → 읽기 쉬운 형식 등) | `\| convert ctime(first) ctime(last)` |

### 묶기, 세기, 요약 (SPL의 핵심) { #group-count-summarise-the-heart-of-spl }

| 명령 | 하는 일 | 예시 |
|---|---|---|
| `stats` | 모든 행을 집계, `by`로 묶음 지정 가능 | `\| stats count, dc(dest) as hosts, values(CommandLine) as cmds by user` |
| `stats` 함수 | `count`, `dc` (고유 개수), `sum`, `avg`, `min`, `max`, `stdev`, `median`, `perc95`, `values` (고유 목록), `list` (전부, 순서대로), `first`, `last`, `earliest`, `latest`, `range` | `\| stats earliest(_time) as first, latest(_time) as last, count by host` |
| `eventstats` | `stats`와 같지만 **모든 행을 유지**하고 결과를 덧붙임 | `\| eventstats avg(count) as avg_count by user` |
| `streamstats` | 행 순서대로 누적/이동 계산 | `\| streamstats current=f last(_time) as prev by src, dest \| eval gap=_time-prev` |
| `timechart` | 시간 구간으로 집계 (차트용) | `\| timechart span=1h count by EventCode` |
| `bin` (a.k.a. `bucket`) | `_time`(또는 숫자)을 구간으로 반올림한 뒤 `stats` | `\| bin _time span=10m \| stats count by _time, src_ip` |
| `chart` | 2차원 피벗 표 | `\| chart count over user by Logon_Type` |
| `top` / `rare` | 가장 흔한 / 가장 드문 값과 개수, 비율 | `\| top limit=20 Image` · `\| rare limit=20 parent_process` |
| `tstats` | 색인된 필드 / 데이터 모델 / 가속 데이터에 대한 **빠른** 통계 | `\| tstats count where index=botsv3 sourcetype=WinEventLog by _time span=1h, host` |
| `transaction` | 필드 + 시간 간격으로 이벤트를 세션으로 묶기 (**느림**; `stats` 선호) | `\| transaction Logon_ID maxspan=8h` |
| `addtotals` / `addcoltotals` | 행/열 합계 | |

### 검색 합치기 { #combine-searches }

| 명령 | 하는 일 | 예시 |
|---|---|---|
| `append` | 서브서치 결과를 아래에 붙이기 | `\| append [search index=zeek sourcetype=zeek:conn …]` |
| `join` | 필드로 SQL식 조인 (제한: 5만 행, 느림) | `\| join type=left uid [search index=zeek sourcetype=zeek:http \| fields uid, host, uri]` |
| 검색창의 `[ subsearch ]` | 한 검색의 결과를 다른 검색의 필터로 사용 (1만 행 제한) | `index=botsv3 sourcetype=WinEventLog [search index=botsv3 EventCode=1102 \| fields host]` |
| `OR`와 함께 쓰는 `stats … by` | `join`의 *빠른* 대안: 두 소스타입을 한 번에 검색하고 공통 키로 `stats values()` | `(sourcetype=zeek:conn OR sourcetype=zeek:http) \| stats values(host) as http_host, sum(orig_bytes) as up by uid` |
| `inputlookup` / `outputlookup` | 룩업 테이블 읽기 / 쓰기 | `\| inputlookup known_admins.csv` · `\| outputlookup baseline_ua.csv` |
| `map` | 결과 행마다 검색 실행 (느림, 특수 용도) | |

### 표시와 관리 { #presentation-housekeeping }

| 명령 | 하는 일 |
|---|---|
| `fieldsummary` | 필드별 통계 (개수, 고유 값, 상위 값) — 모르는 데이터를 처음 볼 때 |
| `metadata type=sourcetypes index=botsv3` | 소스타입 목록과 처음/마지막 시각, 개수 (즉시) |
| `\| tstats count where index=botsv3 by sourcetype` | 같은 일, 더 빠르고 유연함 |
| `eventcount summarize=false index=*` | 인덱스별 이벤트 수 (`*`를 써도 되는 경우 — 메타데이터만) |
| `rest /services/data/indexes` | 인덱스 목록 |
| `typeof`, `isnull`, `isnotnull` | `eval`/`where` 안에서 타입/null 검사 |
| `format` | 서브서치 행을 `(a OR b OR c)` 식으로 바꾸기 |
| `collect` | 결과를 요약 인덱스에 쓰기 |

## 재사용할 패턴 { #patterns-you-will-reuse }

**기준선 vs. 오늘 (새로운 것 찾기)**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4688 earliest=-30d@d latest=@d
| stats count by New_Process_Name
| eval period="baseline"
| append [ search index=botsv3 sourcetype=WinEventLog EventCode=4688 earliest=@d
           | stats count by New_Process_Name | eval period="today" ]
| stats values(period) as seen by New_Process_Name
| where mvcount(seen)=1 AND seen="today"
```

첫 검색은 오늘 이전 30일 동안 본 모든 프로세스 이름을 `baseline` 레이블로 나열합니다; `append`는 오늘 목록을 `today` 레이블로 더합니다; `stats values(period)`는 이들을 프로세스마다 레이블 집합을 가진 한 행으로 합칩니다; 레이블이 `today`뿐인 프로세스는 기준선에 한 번도 나타나지 않은 것입니다.

**희소성 (긴 꼬리)**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| stats dc(host) as hosts, count by Image
| where hosts <= 2
| sort count
```

`dc(host)`는 각 바이너리를 실행한 *서로 다른* 머신 수를 셉니다; 전체 중 한두 대에만 있는 프로그램은 볼 가치가 있고, `sort count`(오름차순) 후 가장 드문 것이 맨 위에 옵니다.

**시간 구간별 급증**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4625
| bin _time span=5m
| stats count, dc(Account_Name) as users by _time, Source_Network_Address
| where count > 20
```

`bin`은 각 이벤트 시각을 속하는 5분 구간으로 내림합니다; 그다음 `stats`가 구간별·출발지별로 실패 수와 고유 계정 수를 셉니다; 한 IP에서 5분에 20회 넘는 실패는 무차별 대입입니다 (사용자가 많으면 = 스프레이).

**처음/마지막으로 본 시각**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10
| stats earliest(_time) as first, latest(_time) as last, count by Account_Name, Source_Network_Address, host
| convert ctime(first) ctime(last)
| sort first
```

`earliest`/`latest`는 묶음마다 처음과 마지막 타임스탬프를 돌려줍니다; `convert ctime()`이 읽기 쉽게 바꿉니다; `first`로 정렬하면 RDP 출발지/계정 쌍이 처음 나타난 시점이 보입니다 — 사고 시간대에 새로 생긴 쌍이 흥미로운 행입니다.

## 속도와 예절 { #speed-etiquette }

- 인덱스와 소스타입을 지정하고, 시간 범위를 좁히고, 키워드는 `where`가 아니라 검색창에 넣으세요.
- `fields`는 일찍, `table`은 늦게. `stats`가 `transaction`보다 낫고; `stats … by key`가 `join`보다 낫습니다.
- 색인된 필드(`host`, `source`, `sourcetype`, `_time`, 가속 데이터 모델의 모든 필드)로 셀 때는 `tstats` — 몇 자릿수 더 빠릅니다.
- 앞쪽 와일드카드(`*admin`)와 `index=*`는 피하세요.
- 유용한 검색은 **Reports**로 저장하고, 자리표시자를 넣은 패턴을 이 핸드북에 적어 두세요.

## 참고 자료 { #references }

- [Splunk Search Reference — command list](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands)
- [Splunk Quick Reference Guide (PDF)](https://www.splunk.com/en_us/resources/splunk-quick-reference-guide.html)
- [eval functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonEvalFunctions) · [stats functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonStatsFunctions)
- 관련 페이지: [데이터 탐색](data-discovery.md) · [rex와 필드](rex-and-fields.md) · [보안 검색](security-searches.md) · [헌팅 패턴](hunting-patterns.md)
