---
title: rex, 필드 추출, eval
tags:
  - concept
  - splunk
  - regex
---

# `rex`, 필드 추출, `eval` { #rex-field-extraction-eval }

<div class="dfir-meta" markdown>
**분류:** Splunk · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    필요한 필드가 없으면 만드세요: `rex`는 정규식 이름 그룹으로 텍스트에서 값을 꺼내고, `spath`는 JSON/XML을 따라가며, `eval`은 가진 것을 다시 다듬습니다 — 그리고 검색에서 검증된 패턴은 영구 추출로 승격시켜 아무도 다시 입력하지 않게 하세요.

## `rex` 핵심 { #rex-essentials }

```spl
| rex field=<source field> "<regex with (?<name>...) groups>"
```

- 기본값은 `field=_raw`. 캡처마다 `(?<fieldname>…)`으로 이름을 붙이면 그게 새 필드가 됩니다.
- 정규식 방언은 **PCRE**입니다. Splunk는 `"…"` 안의 백슬래시를 두 번 해석합니다: 패턴이 큰따옴표 안에 있으면 `\d`를 `\\d`로 쓰세요 — 더 간단하게는, 패턴을 짧게 유지하고 대개 그대로 살아남는 `\d`, `\s`, `\w`를 쓰고 UI에서 시험해 보세요.
- `max_match=0`을 추가하면 일치하는 **모든** 것을 다중값 필드로 캡처합니다 (기본값 1).
- 맨 앞의 `(?i)` = 대소문자 무시.
- `mode=sed`는 `rex`를 찾아 바꾸기로 만듭니다: `| rex field=x mode=sed "s/old/new/g"`.

### 실제 예시 { #worked-examples }

**Base64로 인코딩된 PowerShell**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*powershell.exe"
| rex field=CommandLine "(?i)-(?:e|en|enc|encodedcommand)\s+(?<b64>[A-Za-z0-9+/=]{20,})"
| where isnotnull(b64)
| eval decoded=replace(base64decode(b64),"\x00","")
| table _time, host, User, decoded
```

정규식은 `-e`, `-en`, `-enc`, `-encodedcommand` 중 아무거나(대소문자 무시), 공백, 그리고 20자 이상의 base64 문자를 `b64`로 캡처합니다. `where isnotnull(b64)`는 캡처에 성공한 행만 남깁니다. `base64decode`(Splunk 8+; 구버전은 사용자 정의 명령 필요)가 텍스트로 되돌리고, `replace`는 PowerShell이 글자 사이에 넣는 UTF-16 널 바이트를 지웁니다.

**도메인 없는 사용자명**

```spl
| rex field=User "^(?<domain>[^\\\\]+)\\\\(?<username>.+)$"
```

`CORP\jsmith`를 `domain=CORP`, `username=jsmith`로 캡처합니다. 백슬래시 네 개는 Splunk의 따옴표 해석 후 정규식 `\\`(백슬래시 문자 하나)가 됩니다.

**자유 텍스트에서 IP + 포트**

```spl
| rex field=Message "Source Network Address:\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+Source Port:\s+(?<src_port>\d+)"
```

**이벤트 안의 모든 IP (다중값)**

```spl
| rex max_match=0 "(?<ips>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
| mvexpand ips
| search ips!=127.0.0.1 ips!=0.0.0.0
```

`max_match=0`이 모든 IP를 `ips`에 모으고, `mvexpand`가 IP마다 한 행씩 만들어서 거르고 셀 수 있게 합니다.

**경로에서 파일명과 확장자**

```spl
| rex field=TargetFilename "(?<fname>[^\\\\]+)$"
| rex field=fname "\.(?<ext>[^.]+)$"
```

**URL / SNI에서 도메인**

```spl
| rex field=url "^(?:https?://)?(?<fqdn>[^/:]+)"
| eval domain=mvindex(split(fqdn,"."),-2).".".mvindex(split(fqdn,"."),-1)
```

`split`은 FQDN을 점 기준으로 다중값 목록으로 쪼개고, `mvindex(...,-2)`와 `-1`은 마지막 레이블 두 개를 고르며, `.`이 이어 붙입니다 (`mail.evil-example.com` → `evil-example.com`). 대부분의 TLD에 충분하지만 `co.uk` 같은 경우는 룩업이 필요합니다.

**애드온 없는 Sysmon XML**

```spl
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
```

`rex` 하나가 `<Data Name='…'>value</Data>` 요소 하나를 잡습니다. 더 나은 방법: 아래 `spath`, 또는 애드온 설치.

## JSON / XML에는 `spath` { #spath-for-json-xml }

```spl
| spath                                            # auto-extract everything (JSON) — fine for small results
| spath path=userIdentity.arn output=who           # one path, renamed
| spath path=Event.EventData.Data{@Name}           # XML attributes → multivalue
| spath input=Message path=alert.signature         # spath on a field that contains JSON
```

Sysmon XML이라면 보통 `spath`에 `mvzip`/`mvexpand`를 함께 쓰거나 그냥 애드온을 설치합니다 — XML 모양(`<Data Name="X">value`) 때문에 여기서는 `spath`보다 `rex`가 더 간단합니다.

## 이미 있는 자동 추출 { #auto-extraction-that-already-exists }

`rex`를 쓰기 전에 Splunk가 이미 주는 것을 확인하세요: **Interesting Fields** 패널; `| fieldsummary`; 원시 텍스트의 `key=value` 쌍은 자동으로 추출됨(`user=admin` → `user`); **Field Extractor**(Extract New Fields → 텍스트 강조 → Splunk가 정규식을 작성)는 `rex`를 만들고 저장하는 GUI 방식입니다.

## `eval` — 실제로 쓰는 함수 { #eval-the-functions-you-actually-use }

| 필요 | 함수 |
|---|---|
| 조건 | `if(cond, a, b)` · `case(c1, v1, c2, v2, true(), default)` · `coalesce(a, b, c)` · `nullif(a, b)` |
| 문자열 | `lower`, `upper`, `len`, `substr(s, start, len)`, `replace(s, regex, repl)`, `trim`, `ltrim`, `rtrim`, `split(s, delim)`, `.` (이어 붙이기), `urldecode`, `md5`, `sha1`, `sha256` |
| 검사 | `like(s, "pat%")`, `match(s, "regex")`, `cidrmatch("10.0.0.0/8", ip)`, `isnull`, `isnotnull`, `in(field, "a","b")`, `searchmatch("user=admin*")` |
| 숫자 | `round(x, 2)`, `floor`, `ceil`, `abs`, `pow`, `log`, `tonumber(s)`, `tostring(n, "commas")`, `random()` |
| 시간 | `now()`, `strftime(t, fmt)`, `strptime(s, fmt)`, `relative_time(t, "-1d@d")`, `time()` |
| 다중값 | `mvcount`, `mvindex(mv, i)`, `mvjoin(mv, ",")`, `mvfilter(match(mv, "x"))`, `mvdedup`, `mvappend`, `mvzip`, `split`, `mvsort` |
| 인코딩 | `base64decode` / `base64encode` (8.1+), `printf`, `tostring(x,"hex")` |
| 타입 | `typeof(x)`, `tonumber`, `tostring` |

### 작은 `eval` 레시피 { #small-eval-recipes }

```spl
| eval user=lower(coalesce(user, Account_Name, User))                       # normalise usernames across sourcetypes
| eval is_admin=if(match(user,"(?i)admin|adm_|svc_"),1,0)
| eval logon_type_name=case(Logon_Type==2,"Interactive",Logon_Type==3,"Network",Logon_Type==10,"RemoteInteractive",Logon_Type==9,"NewCredentials",true(),"Other")
| eval internal=if(cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip),"int","ext")
| eval MB_out=round(bytes_out/1048576,2)
| eval cmd_len=len(CommandLine), has_b64=if(match(CommandLine,"[A-Za-z0-9+/]{50,}={0,2}"),1,0)
| eval entropy_hint=len(replace(lower(query),"[aeiou0-9.-]",""))/len(query)   # crude consonant ratio for DGA-ish names
| eval day=strftime(_time,"%Y-%m-%d"), hour=strftime(_time,"%H")
| eval hash_sha256=mvindex(split(mvindex(split(Hashes,"SHA256="),1),","),0)  # Sysmon Hashes field "MD5=…,SHA256=…,IMPHASH=…"
```

마지막 줄: `split(Hashes,"SHA256=")`이 문자열을 `SHA256=`에서 자르고, `mvindex(...,1)`이 그 뒤를 가져오며, 그것을 `,`로 다시 쪼개 0번을 고르면 해시만 남습니다.

## 룩업 — 보강과 허용 목록 { #lookups-enrich-and-allow-list }

```spl
# CSV with columns ip,owner,criticality uploaded as lookup "assets"
| lookup assets ip as dest_ip OUTPUTNEW owner, criticality

# Allow-list: drop rows whose process is in known_good.csv (column: process)
| lookup known_good process as Image OUTPUT process as known
| where isnull(known)

# Build a baseline once, reuse it
index=botsv3 sourcetype=stream:http earliest=-30d@d latest=@d | stats count by http_user_agent | outputlookup baseline_ua.csv
```

`OUTPUTNEW`는 비어 있는 필드만 채우고, `OUTPUT`은 덮어씁니다. 허용 목록 요령: 목록과 결합한 뒤 룩업이 **실패한**(`isnull`) 행 — 즉 목록에 없는 것 — 만 남깁니다.

## `rex`를 영구 추출로 승격하기 { #promote-a-rex-to-a-permanent-extraction }

`rex`가 동작하면 검색 시점에 자동으로 적용되도록 저장하세요: **Settings → Fields → Field extractions → New**에서 소스타입 + 같은 정규식(`field=`는 `_raw`가 아닐 때만 남기고), 또는 `props.conf`에:

```ini
[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
EXTRACT-sysmon_image = <Data Name='Image'>(?<Image>[^<]+)
EXTRACT-sysmon_cmd   = <Data Name='CommandLine'>(?<CommandLine>[^<]+)
```

함께 유용한 것: **필드 별칭**(`Account_Name` → `user`), **계산 필드**(한 번 저장한 `eval`), **이벤트 유형**(저장된 검색 조건, 예: `eventtype=win_failed_logon`), **태그**(`tag=authentication`). 애드온이 CIM 필드를 나타나게 하는 방법이 이것들입니다.

## 추출 디버깅 { #debugging-extraction }

- 아무것도 추출되지 않나요? 이벤트 하나로 정규식을 시험하세요: `| head 1 | rex … | table b64` — 그다음 조건을 느슨하게.
- 백슬래시 문제? 패턴을 Field Extractor GUI에 넣거나, 백슬래시 문자 클래스는 `[\\\\]`를 쓰세요.
- 필드 이름이 틀렸나요? 철자와 대소문자를 확인하세요 — 필드 이름은 대소문자를 구분하고(`EventCode` ≠ `eventcode`), 값은 대개 구분하지 않습니다.
- 사이드바에는 필드가 보이는데 `stats`는 null이라고 하나요? 일부 이벤트에만 있을 수 있습니다 — `| stats count(field) count`로 비율을 보세요.
- 다중값 함정: `stats by Account_Name`은 값마다 나뉩니다. 먼저 `mvindex`나 `mvjoin`을 쓰세요.

## 참고 자료 { #references }

- [Splunk — rex command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rex)
- [Splunk — About regular expressions](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/AboutSplunkregularexpressions)
- [Splunk — eval functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonEvalFunctions)
- [regex101 (PCRE flavour) for testing](https://regex101.com/)
