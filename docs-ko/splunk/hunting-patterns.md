---
title: SPL 헌팅 패턴
tags:
  - concept
  - splunk
  - hunting
---

# SPL 헌팅 패턴 { #hunting-patterns-in-spl }

<div class="dfir-meta" markdown>
**분류:** Splunk · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    탐지 규칙은 *알려진 악성*을 찾고, 헌팅은 *이상한 것*을 찾습니다 — 그리고 SPL에서 "이상함"은 언제나 몇 가지 통계적 모양 중 하나입니다: 드묾, 새로움, 급증, 규칙적, 긴 꼬리, 동료 집단 밖. 모양을 한 번 익히면 어떤 로그의 어떤 필드에도 적용할 수 있습니다.

## 여섯 가지 모양 { #the-six-shapes }

| 모양 | 질문 | 핵심 SPL |
|---|---|---|
| **드묾** | 아주 적은 호스트 / 아주 적은 횟수로만 나오는 값은? | `stats dc(host) count by X \| where dc <= 2` |
| **새로움** | 기준선에 없다가 오늘 나타난 것은? | 기준선 `stats … by X` + 오늘을 `append` + `where seen=="today"` (또는 기준선 `outputlookup`) |
| **급증** | 자기 평소보다 훨씬 높은 것은? | `timechart` + `eventstats avg stdev` + `where value > avg + 3*stdev` |
| **규칙적** | 일정한 간격으로 반복되는 것은? | `streamstats` 간격 + 낮은 `stdev(gap)/avg(gap)` |
| **긴 꼬리** | 잡음이 많은 필드에서 가장 드문 값 | `rare` / `stats count by X \| sort count` |
| **동료 집단 내 이상치** | 동료와 다르게 행동하는 호스트/사용자는? | `stats by entity` → `eventstats` 집단 통계 → z-점수 |

## 1. 희소성 (가장 드문 값) { #1-rarity-least-common-value }

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval proc=lower(replace(Image,".*\\\\","")), parent=lower(replace(ParentImage,".*\\\\",""))
| stats dc(host) as hosts, count, values(host) as where, earliest(_time) as first by parent, proc
| where hosts <= 2 AND count <= 5
| convert ctime(first)
| sort first
```

모든 부모→자식 쌍을 묶고 고유 호스트 수를 셉니다. 2대 이하에 있고 5번 이하로 실행된 쌍은 이 환경에서 드뭅니다. `values(host)`가 머신 이름을 알려 주므로 바로 갈 수 있습니다. `http_user_agent`, `tls.ja3`, `Service_File_Name`, `TargetObject`(레지스트리 경로), `dest_port`, `query` 도메인에도 똑같이 적용하세요.

## 2. 이번 기간에 새로 나타남 (기준선 비교) { #2-new-this-period-baseline-comparison }

**인라인 (작은 데이터)**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10 earliest=-30d@d latest=-1d@d
| eval user=mvindex(Account_Name,1)
| stats count by user, host
| eval period="baseline"
| append [ search index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10 earliest=-1d@d
           | eval user=mvindex(Account_Name,1) | stats count by user, host | eval period="today" ]
| stats values(period) as seen, sum(count) as total by user, host
| where mvcount(seen)==1 AND seen=="today"
```

검색 두 개(30일 기준선, 최근 하루)를 각각 `user, host` 쌍으로 줄이고 레이블을 붙입니다; `append`가 쌓고; 쌍별 `stats values(period)`가 그 쌍이 어느 쪽에, 양쪽에, 또는 오늘만 있었는지 보여 줍니다. 오늘만 있는 쌍 = **이 사용자가 이 호스트에 처음으로 한 RDP 로그온**.

**룩업 사용 (운영 환경 패턴)**

```spl
# nightly saved search
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10 earliest=-1d@d latest=@d
| eval user=mvindex(Account_Name,1)
| stats min(_time) as first_seen by user, host
| inputlookup append=t rdp_baseline.csv
| stats min(first_seen) as first_seen by user, host
| outputlookup rdp_baseline.csv

# hunting search
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10 earliest=-1d@d
| eval user=mvindex(Account_Name,1)
| lookup rdp_baseline.csv user, host OUTPUT first_seen
| where isnull(first_seen)
```

야간 검색이 오늘의 쌍을 CSV에 합치고(가장 이른 날짜 유지), 헌팅 검색이 CSV가 모르는 쌍을 표시합니다. 새 서비스, 새 예약 작업, 새 User-Agent, 새 목적지 ASN, 새 부모/자식 쌍에도 같은 패턴을 씁니다.

## 3. 급증 (자기 기준선) { #3-spikes-self-baseline }

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4625
| timechart span=1h count by host limit=0 useother=f
| untable _time host count
| eventstats avg(count) as avg, stdev(count) as sd by host
| eval z=round((count-avg)/if(sd=0,1,sd),1)
| where count > 20 AND z > 3
| sort - z
```

`timechart`는 호스트마다 열 하나, 시간마다 행 하나를 만들고; `untable`은 그 넓은 표를 다시 긴 행(`_time, host, count`)으로 바꾸며; `eventstats`는 호스트마다 전체 시간에 걸친 평균과 표준편차를 계산해 모든 행에 적고; `z`는 이번 시간이 그 호스트의 평소보다 표준편차 몇 배만큼 높은지입니다. 절대 최솟값(`count > 20`)과 `z > 3`을 둘 다 요구하면 2 → 6 같은 것에 경보가 울리지 않습니다.

같은 뼈대를 이런 데 쓰세요: 호스트별·시간별 나가는 바이트, 호스트별 DNS 쿼리, 호스트별 4688 개수(스크립트 폭풍), 사용자별 5145 공유 접근, 출발지별 HTTP 404.

## 4. 규칙성 (비코닝) { #4-regularity-beaconing }

```spl
index=botsv3 sourcetype=stream:tcp dest_port IN (80, 443, 8080, 8443)
| eval pair=src_ip.">".dest_ip.":".dest_port
| sort 0 pair, _time
| streamstats current=f last(_time) as prev by pair
| eval gap=_time-prev
| where gap > 0
| stats count, avg(gap) as avg_gap, stdev(gap) as sd_gap, dc(src_ip) as srcs by pair, dest_ip
| eventstats dc(pair) as pairs_to_dest by dest_ip
| eval jitter=round(100*sd_gap/avg_gap,1)
| where count >= 20 AND jitter < 25 AND pairs_to_dest <= 3
| sort jitter
```

`sort 0 pair, _time`은 쌍별로 연결을 시간순 정렬하고; `streamstats current=f last(_time)`은 각 행에 이전 연결의 시각을 가져오며; `gap`이 간격이고; `stats`가 쌍별로 간격을 요약하며; `eventstats dc(pair) by dest_ip`는 그 목적지와 통신하는 내부 호스트가 몇 대인지(희소성) 셉니다; 낮은 지터 + 적은 쌍 = 비콘. 자세한 설명은 [비코닝과 C2](../network/beaconing-c2.md).

## 5. 긴 꼬리와 스태킹 { #5-long-tail-stacking }

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval cmd=lower(CommandLine)
| eval cmd=replace(cmd, "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<guid>")
| eval cmd=replace(cmd, "\d+", "<n>")
| eval cmd=replace(cmd, "c:\\\\users\\\\[^\\\\]+", "c:\\users\\<user>")
| stats count, dc(host) as hosts, values(host) as where by cmd
| sort count
| head 100
```

"스태킹" = 정규화하고, 세고, 아래부터 읽기. `replace` 호출이 GUID, 숫자, 사용자명을 뭉개서 500대에 있는 `svchost.exe -k netsvcs -p -s Schedule`이 한 줄이 되고, 이상한 일회성 명령이 오름차순 정렬의 맨 위로 떠오릅니다. `TargetObject`, `Service_File_Name`, `uri_path`, `query`에도 똑같이 하세요.

## 6. 동료 집단 이상치 { #6-peer-group-outliers }

```spl
index=botsv3 sourcetype=stream:tcp
| stats sum(bytes_out) as out by src_ip
| eventstats median(out) as med, perc90(out) as p90, avg(out) as avg, stdev(out) as sd
| eval z=round((out-avg)/sd,1), MB=round(out/1048576,1)
| where out > p90 AND z > 2
| sort - out
```

각 호스트를 전체와 비교합니다: `eventstats`가 전체의 중앙값, 90번째 백분위수, 평균, 표준편차를 모든 행에 붙이고; 90번째 백분위수보다 높*고* 평균에서 표준편차 두 배 이상 떨어진 호스트가 이상치입니다. 동료 집단을 더 좁힐 수도 있습니다: 룩업 후 `by role`(`workstation` vs `server`), `by department`, `by subnet`.

## 7. 순서 (A 다음 N분 안에 B) { #7-sequences-a-then-b-within-n-minutes }

```spl
index=botsv3 (sourcetype=WinEventLog EventCode=4720) OR (sourcetype=WinEventLog EventCode=4732)
| eval acct=coalesce(Member_Name, Account_Name)
| sort 0 host, _time
| streamstats current=f last(EventCode) as prev_code, last(_time) as prev_time by host
| where EventCode==4732 AND prev_code==4720 AND _time-prev_time < 300
| table _time, host, Subject_Account_Name, acct, Group_Name
```

`streamstats`는 호스트별로 이전 이벤트의 코드와 시각을 기억합니다; 같은 호스트에서 `4720`(사용자 생성) 후 5분 안에 나온 `4732`(로컬 그룹에 추가)는 백도어 계정 순서입니다. `transaction`보다 이걸 쓰세요 — 규모가 커져도 됩니다. 다른 순서들: `4625`×N 다음 `4624`(성공한 무차별 대입), `5145 ADMIN$` 다음 `7045`(PsExec), Sysmon `11` 파일 생성 다음 같은 경로의 `1` 프로세스 생성(떨어뜨리고 실행), `4104` 다음 Sysmon `3`(스크립트 다음 네트워크).

## 8. 떨어뜨리고 실행 (stats로 공통 키 결합) { #8-drop-and-run-join-on-a-shared-key-with-stats }

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=11 OR EventID=1)
| eval path=lower(coalesce(TargetFilename, Image))
| where match(path, "\\.(exe|dll|ps1|bat|vbs|js|hta|scr)$")
| stats min(eval(if(EventID==11,_time,null()))) as dropped, min(eval(if(EventID==1,_time,null()))) as executed, values(eval(if(EventID==11,Image,null()))) as dropper, values(User) as users by host, path
| where isnotnull(dropped) AND isnotnull(executed) AND executed-dropped < 600
| eval delay_s=executed-dropped
| convert ctime(dropped) ctime(executed)
| sort dropped
```

`join` 대신 두 이벤트 유형을 함께 검색하고 집계 함수 안에 `eval(if(...))`를 넣은 `stats`를 씁니다: `min(eval(if(EventID==11,_time,null())))`는 "파일 생성 이벤트 중 가장 이른 시각"이고 프로세스 생성도 마찬가지입니다; `host, path`로 묶으면 둘이 나란히 놓입니다. 쓰인 지 10분 안에 실행된 파일과 `dropper` 프로세스 이름이 곧 페이로드 체인입니다.

## 9. 보강한 뒤 판단 { #9-enrich-then-decide }

```spl
… | lookup assets ip as src_ip OUTPUTNEW hostname, owner, role
    | lookup threat_ips ip as dest_ip OUTPUTNEW threat_name
    | iplocation dest_ip
    | eval score=0
    | eval score=score+if(isnotnull(threat_name),50,0)
    | eval score=score+if(role="server" AND Logon_Type=10,20,0)
    | eval score=score+if(match(Country,"^(?!Australia$)"),10,0)
    | where score >= 30
```

점수를 더하는 방식은 헌팅 결과를 트리아지할 수 있게 만듭니다: 각 `eval score=score+if(...)`가 조건마다 점수를 더하고, `where score >= 30`이 임계값입니다. 조건들이 탐지 규칙으로 무르익는 동안 핸드북에 적어 두세요.

## 헌팅을 반복 가능하게 만들기 { #making-hunts-repeatable }

- 각 헌팅을 검색 이름 = 질문으로 **Report**에 저장하세요 ("새 RDP 출발지→호스트 쌍, 매일").
- 안정된 허용 목록은 SPL 안이 아니라 **룩업**에 두세요.
- 헌팅이 계속 진짜 양성을 찾으면 예약된 **Alert**(또는 Sigma 규칙)로 바꾸고 수동 목록에서 빼세요.
- 핸드북에 기록하세요: 질문 → SPL → 예상되는 잡음 → 걸렸을 때 어떻게 보였는지.

## 참고 자료 { #references }

- [Splunk — streamstats / eventstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Streamstats)
- [SANS — Threat Hunting with Splunk (whitepapers/webcasts)](https://www.sans.org/webcasts/)
- [Splunk Security Essentials — hunting content](https://splunkbase.splunk.com/app/3435)
- [Active Countermeasures — beacon analysis](https://www.activecountermeasures.com/)
- 관련 페이지: [SPL 치트시트](spl-cheatsheet.md) · [보안 검색](security-searches.md) · [비코닝과 C2](../network/beaconing-c2.md)
