---
title: 질문별 보안 검색
tags:
  - playbook
  - splunk
  - windows
  - network
---

# 질문별 보안 검색 { #security-searches-by-question }

<div class="dfir-meta" markdown>
**분류:** Splunk · **데이터:** Windows Security, Sysmon, PowerShell, Zeek/Stream · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    사고 중에 돌리는 검색을 답하려는 질문별로 묶었고, 각각 SPL이 무엇을 하는지와 이벤트 코드가 무슨 뜻인지 쉬운 말로 풀었습니다 — `index=botsv3`과 소스타입 이름은 자기 환경에 맞게 바꾸세요.

약속: `SEC` = `index=botsv3 sourcetype=WinEventLog` (Security 로그; System/Application이 같은 소스타입을 쓰면 `source="WinEventLog:Security"` 사용), `SYSMON` = `index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`, `PS` = `index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"`. 이벤트 ID 의미: [Windows 이벤트 ID](../basics/windows-event-ids.md).

## 누가, 어디서 로그온했나? { #who-logged-on-from-where }

**유형과 출발지별 로그온 성공**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624
| eval user=mvindex(Account_Name,1)
| eval type=case(Logon_Type==2,"2 Interactive",Logon_Type==3,"3 Network",Logon_Type==4,"4 Batch",Logon_Type==5,"5 Service",Logon_Type==7,"7 Unlock",Logon_Type==9,"9 NewCredentials",Logon_Type==10,"10 RDP",Logon_Type==11,"11 Cached",true(),Logon_Type)
| stats count, earliest(_time) as first, latest(_time) as last by host, user, type, Source_Network_Address
| convert ctime(first) ctime(last)
| sort host, - count
```

`4624` = 로그온 성공. `Account_Name`에는 값이 두 개(subject, target) 있고, `mvindex(...,1)`이 로그온한 계정을 가져옵니다. `case`는 숫자 `Logon_Type`을 레이블로 바꿉니다 — type 3(네트워크: SMB/WinRM/PsExec), 10(RDP), 9(`runas /netonly`, pass-the-hash 도구)를 주의 깊게 보세요. `stats`는 호스트/사용자/유형/출발지마다 처음과 마지막 시각이 있는 한 행을 줍니다.

**로그온 실패 — 무차별 대입과 스프레이**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4625
| bin _time span=10m
| stats count, dc(Account_Name) as users, values(Sub_Status) as substatus by _time, Source_Network_Address, host
| where count >= 10
| eval pattern=if(users >= 5, "spraying (many users)", "brute force (few users)")
| sort - count
```

`4625` = 로그온 실패. 10분 구간으로 나누고 출발지 IP별로 세면 몰려 나온 것을 찾을 수 있고, `dc(Account_Name)`(고유 계정 수)으로 스프레이(비밀번호 하나, 사용자 여럿)와 무차별 대입(사용자 하나, 비밀번호 여럿)을 구분합니다. `Sub_Status`가 이유를 알려 줍니다: `0xC000006A` 비밀번호 틀림, `0xC0000064` 없는 사용자(단어 목록으로 스프레이), `0xC0000234` 잠김, `0xC0000072` 비활성 계정.

**명시적 자격증명 / 횡적 이동의 출발지 쪽**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4648
| stats count, values(Target_Server_Name) as targets, values(Process_Name) as procs by host, Subject_Account_Name, Account_Name
| where mvcount(targets) > 3
```

`4648` = **명시적** 자격증명으로 로그온을 시도함 (`runas`, 예약 작업 자격증명, 사용자명/비밀번호/해시를 넣는 도구). **출발지** 머신에 기록되므로 `host`가 공격자가 있는 곳이고 `targets`가 간 곳입니다. 짧은 시간에 한 계정이 많은 서버에 닿으면 횡적 이동입니다.

**출발지 IP가 포함된 RDP 세션**

```spl
index=botsv3 sourcetype=WinEventLog (EventCode=4624 Logon_Type=10) OR EventCode=4778 OR EventCode=4779 OR (sourcetype="WinEventLog:Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" EventCode IN (21,24,25))
| eval src=coalesce(Source_Network_Address, Client_Address, Source_Network_Address)
| eval user=coalesce(mvindex(Account_Name,1), Account_Name, User)
| table _time, host, EventCode, user, src
| sort 0 _time
```

`4624/10` = RDP 로그온; `4778/4779` = RDP 세션 재연결/연결 끊김 (클라이언트 이름/IP 포함); LocalSessionManager `21` = 세션 로그온 성공, `24` 연결 끊김, `25` 재연결. `coalesce`가 이름이 다른 IP 필드들을 `src` 열 하나로 합쳐서 타임라인이 깔끔하게 읽힙니다.

**관리자 로그온**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4672
| stats count by host, Account_Name
| sort - count
```

`4672` = 로그온 시 특수 권한 할당 — 사실상 "관리자급 계정이 로그온했다"는 뜻. 같은 `Logon_ID`를 가진 `4624`와 짝지어 보세요.

## 무엇이 실행됐나? { #what-ran }

**명령줄이 포함된 프로세스 생성 (Security 4688)**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4688
| eval user=mvindex(Account_Name,0)
| stats count by host, user, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort - count
```

`4688` = 새 프로세스 생성. `Process_Command_Line`은 정책에서 "프로세스 생성 이벤트에 명령줄 포함"을 켰을 때만 있고, `Creator_Process_Name`(부모)은 Win10+/2016+에 있습니다.

**Sysmon 프로세스 트리 — 수상한 부모**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval parent=lower(replace(ParentImage,".*\\\\","")), child=lower(replace(Image,".*\\\\",""))
| search (parent IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe","msedge.exe","chrome.exe") AND child IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","msiexec.exe"))
   OR (parent="wmiprvse.exe" AND child IN ("cmd.exe","powershell.exe"))
   OR (parent="services.exe" AND child IN ("cmd.exe","powershell.exe"))
   OR (parent IN ("w3wp.exe","httpd.exe","tomcat*.exe") AND child IN ("cmd.exe","powershell.exe","whoami.exe"))
| table _time, host, User, parent, child, CommandLine
```

Sysmon `1` = 부모/자식 전체와 해시가 포함된 프로세스 생성. `replace(ParentImage,".*\\\\","")`는 경로를 떼고 파일명만 남깁니다. `search`는 전형적인 나쁜 부모→자식 쌍을 나열합니다: 셸을 띄우는 Office (매크로), 셸을 띄우는 WMI 프로바이더 호스트 (원격 WMI 실행), 셸을 띄우는 `services.exe` (PsExec 방식 서비스), 셸을 띄우는 웹 서버 (웹셸).

**LOLBin과 수상한 명령줄**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| where match(CommandLine, "(?i)(-enc|-encodedcommand|frombase64string|iex\s*\(|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|certutil.*-urlcache|certutil.*-decode|bitsadmin.*transfer|mshta.*http|regsvr32.*/i:http|rundll32.*javascript|vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|wevtutil\s+cl|schtasks.*/create|sc\s+create|reg\s+add.*\\run|whoami|net\s+(user|group|localgroup)|nltest|dsquery|adfind|mimikatz|sekurlsa|procdump.*lsass|comsvcs.*minidump|ntdsutil|esentutl.*ntds)")
| stats count, values(CommandLine) as cmds, earliest(_time) as first by host, User, Image
| convert ctime(first)
| sort first
```

대소문자를 무시하는 긴 정규식 하나가 다운로드 크래들, 인코딩된 PowerShell, LOLBin 다운로더, 섀도 복사본/백업 삭제(랜섬웨어 준비), 로그 삭제, 지속성 명령, 탐색 명령, 자격증명 덤프를 다룹니다. `values(CommandLine)`이 호스트/사용자/바이너리마다 일치하는 모든 명령을 모아 한 행에서 읽게 해 줍니다.

**PowerShell 스크립트 블록**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where len(ScriptBlockText) > 500 OR match(ScriptBlockText,"(?i)frombase64string|invoke-mimikatz|amsi|bypass|-nop|hidden|downloadstring|reflection\.assembly|virtualalloc|kernel32")
| stats count, min(_time) as first, values(Path) as paths by host, ScriptBlockText
| convert ctime(first)
| sort first
```

`4104` = `-enc` 페이로드까지 포함한 실제 디코딩된 스크립트 텍스트 — 가장 좋은 PowerShell 아티팩트입니다. 긴 블록과 키워드 집합(AMSI 우회, 리플렉션, 메모리 할당, 다운로드 크래들)이 공격 도구를 드러냅니다.

**이름을 바꿨거나 엉뚱한 곳에 있는 바이너리 (Sysmon)**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval fname=lower(replace(Image,".*\\\\","")), orig=lower(OriginalFileName)
| where isnotnull(orig) AND orig!="?" AND fname!=orig AND NOT (fname="powershell.exe" AND orig="powershell.exe")
| stats count by host, Image, OriginalFileName, CommandLine
```

Sysmon은 PE 헤더의 `OriginalFileName`을 기록합니다. 디스크의 파일은 `svchost.exe`인데 헤더가 `mimikatz.exe`라고 하면 공격자가 이름을 바꾼 것입니다. 함께 유용한 것: `\Users\Public\`, `\ProgramData\`, `\Windows\Temp\`, `\AppData\Local\Temp\`, `\PerfLogs\` 아래의 `Image`.

## 어떻게 지속성을 유지하나? { #how-do-they-persist }

**새 서비스**

```spl
index=botsv3 sourcetype="WinEventLog:System" EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Account_Name
| sort 0 _time
```

System `7045` = 서비스 설치됨. `PSEXESVC` = PsExec; `%COMSPEC% /b /c start /b /min powershell -nop -w hidden -enc`가 붙은 무작위 8자 이름 = Cobalt Strike/Metasploit 서비스 페이로드; 바이너리가 사용자 폴더에 있는 서비스는 지속성입니다.

**예약 작업**

```spl
index=botsv3 sourcetype=WinEventLog EventCode IN (4698, 4702)
| rex field=Task_Content "<Command>(?<cmd>[^<]+)</Command>"
| rex field=Task_Content "<Arguments>(?<args>[^<]+)</Arguments>"
| table _time, host, Subject_Account_Name, Task_Name, cmd, args
```

`4698` = 작업 생성, `4702` = 작업 업데이트 (감사 정책 필요). 작업 XML은 `Task_Content`에 있고, `rex`가 거기서 명령과 인수를 꺼냅니다.

**레지스트리 Run 키와 그 밖의 ASEP (Sysmon)**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (12, 13, 14)
| where match(TargetObject, "(?i)\\\\CurrentVersion\\\\Run|\\\\RunOnce|\\\\Winlogon\\\\(Shell|Userinit)|\\\\Image File Execution Options|\\\\Services\\\\[^\\\\]+\\\\ImagePath|\\\\AppInit_DLLs|\\\\Command Processor\\\\AutoRun|\\\\Environment\\\\UserInitMprLogonScript|\\\\Classes\\\\CLSID\\\\[^\\\\]+\\\\InprocServer32|\\\\Policies\\\\Explorer\\\\Run|\\\\Active Setup")
| table _time, host, User, Image, EventID, TargetObject, Details
```

Sysmon `12` = 키 생성/삭제, `13` = 값 설정, `14` = 키/값 이름 변경. `TargetObject`가 레지스트리 경로이고 `Details`가 쓰인 값입니다. 정규식은 [레지스트리 키](../windows/registry-keys.md#autostart-persistence-asep) 페이지의 자동 시작 위치를 나열합니다.

**WMI 지속성**

```spl
index=botsv3 (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (19,20,21)) OR (sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" EventCode=5861)
| table _time, host, sourcetype, EventID, EventCode, User, EventNamespace, Name, Query, Destination, Consumer, Filter, Message
```

Sysmon `19/20/21` = WMI 이벤트 필터 / 컨슈머 / 바인딩 생성 — 셋이 함께 있으면 = 지속성. WMI-Activity `5861`은 새 영구 컨슈머에 대한 OS 자체 기록입니다.

**새 로컬 사용자와 그룹 변경**

```spl
index=botsv3 sourcetype=WinEventLog EventCode IN (4720, 4722, 4724, 4728, 4732, 4756)
| eval action=case(EventCode==4720,"user created",EventCode==4722,"user enabled",EventCode==4724,"password reset",EventCode==4728,"added to global group",EventCode==4732,"added to local group",EventCode==4756,"added to universal group")
| table _time, host, Subject_Account_Name, action, Account_Name, Member_Name, Group_Name
| sort 0 _time
```

`4720` 생성, `4722` 활성화, `4724` 관리자의 비밀번호 재설정, `4728/4732/4756` 보안 그룹(전역/로컬/유니버설)에 멤버 추가. `4720` 몇 초 뒤 `Administrators`로의 `4732`는 교과서적인 백도어 계정 생성입니다.

## 횡적 이동 (대상 쪽) { #lateral-movement-target-side }

**PsExec / SMB 관리 공유 패턴**

```spl
index=botsv3 (sourcetype=WinEventLog EventCode IN (4624, 5140, 5145)) OR (sourcetype="WinEventLog:System" EventCode=7045)
| eval share=coalesce(Share_Name, Relative_Target_Name)
| where EventCode!=4624 OR Logon_Type=3
| eval src=coalesce(Source_Network_Address, Source_Address)
| stats values(EventCode) as codes, values(share) as shares, values(Service_Name) as services, values(Account_Name) as accounts, min(_time) as first, max(_time) as last by host, src
| where match(mvjoin(codes,","),"5140|5145") AND match(mvjoin(codes,","),"7045")
| convert ctime(first) ctime(last)
```

**대상**에서의 PsExec 체인: `4624 type 3`(네트워크 로그온) → `5140/5145`(공유 `ADMIN$`/`IPC$` 접근, `PSEXESVC.exe` 파일 쓰기) → `7045`(서비스 설치). 모든 것을 대상 호스트와 출발지 IP로 묶은 뒤, 같은 묶음에 공유 접근 코드와 서비스 설치 코드가 모두 있어야 한다는 조건을 걸면 도구 이름을 몰라도 체인을 찾습니다.

**WMI / WinRM 원격 실행**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 (ParentImage="*\\wmiprvse.exe" OR ParentImage="*\\wsmprovhost.exe")
| table _time, host, User, ParentImage, Image, CommandLine
```

대상에서 원격 WMI는 자식을 `wmiprvse.exe` 아래에서, PowerShell Remoting은 `wsmprovhost.exe` 아래에서 실행합니다. 둘 다 평소에는 `cmd`/`powershell`을 띄우지 않아야 합니다.

**Pass-the-Hash 지표**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=9 Logon_Process=seclogo Authentication_Package=Negotiate
| table _time, host, Account_Name, Logon_ID, Process_Name
```

Mimikatz `sekurlsa::pth` 등은 *공격자* 머신에 **Logon Type 9**(NewCredentials), 로그온 프로세스 `seclogo`, 패키지 `Negotiate`인 `4624`를 만듭니다. *대상*에서 PtH는 평범한 type 3 NTLM 로그온처럼 보이므로 — Kerberos 도메인에서 워크스테이션 간 `4624 Logon_Type=3 Authentication_Package=NTLM`도 헌팅하세요.

**Kerberoasting (DC에서)**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4769 Ticket_Encryption_Type=0x17 Failure_Code=0x0
| where NOT match(Service_Name, "\\$$|krbtgt")
| bin _time span=10m
| stats dc(Service_Name) as spns, values(Service_Name) as services by _time, Account_Name, Client_Address
| where spns >= 5
```

`4769` = 서비스 티켓 요청. 암호화 유형 `0x17` = RC4 — 크래킹 도구가 요청하는 것. 컴퓨터 계정(`$`)과 `krbtgt`를 빼고, 한 사용자가 10분 안에 서로 다른 SPN을 다섯 개 이상 요청하면 Kerberoasting입니다.

## 네트워크 쪽 (Splunk의 Zeek / Stream) { #network-side-zeek-stream-in-splunk }

**비콘 후보** — 전체 `streamstats` 버전은 [비코닝과 C2](../network/beaconing-c2.md) 참고.

**드문 User-Agent**

```spl
index=botsv3 sourcetype=stream:http
| stats dc(src_ip) as hosts, count, values(site) as sites by http_user_agent
| where hosts <= 2
| sort count
```

`dc(src_ip)` = 각 UA를 쓰는 클라이언트 수; 한두 대 = 맞춤 도구나 악성코드; `values(site)`는 어디로 가는지 보여 줍니다.

**실행 파일 다운로드**

```spl
index=botsv3 sourcetype=stream:http (http_content_type="application/x-msdownload" OR http_content_type="application/x-dosexec" OR uri_path="*.exe" OR uri_path="*.dll" OR uri_path="*.ps1")
| table _time, src_ip, dest_ip, site, uri_path, http_user_agent, bytes_in
```

**DNS 이상**

```spl
index=botsv3 sourcetype=stream:dns record_type=A
| eval qlen=len(query), first=mvindex(split(query,"."),0)
| where qlen > 50 OR len(first) > 30 OR record_type IN ("TXT","NULL")
| stats count, dc(query) as uniq by src_ip, dest_ip
| sort - uniq
```

**큰 업로드**

```spl
index=botsv3 sourcetype=stream:tcp
| stats sum(bytes_out) as out, sum(bytes_in) as in by src_ip, dest_ip, dest_port
| eval out_MB=round(out/1048576,1), ratio=round(out/(in+1),1)
| where out_MB > 50 AND ratio > 5
| sort - out_MB
```

`ratio` = 보낸 바이트 ÷ 받은 바이트; 받는 것보다 5배 넘게, 수십 MB를 보내는 클라이언트는 업로드 중입니다.

## 로그 변조 { #log-tampering }

```spl
index=botsv3 (sourcetype=WinEventLog EventCode IN (1102, 4719, 4616)) OR (sourcetype="WinEventLog:System" EventCode=104)
| eval what=case(EventCode==1102,"Security log cleared",EventCode==104,"Event log cleared",EventCode==4719,"Audit policy changed",EventCode==4616,"System time changed")
| table _time, host, what, Account_Name, Subject_Account_Name, Message
| sort 0 _time
```

`1102` = Security 로그 삭제 (누가 했는지 기록), `104` = 그 밖의 로그 삭제, `4719` = 감사 정책 변경 (행동 전에 로깅을 끔), `4616` = 시스템 시간 변경 (타임라인 혼란). 로그 양이 0으로 떨어진 호스트도 확인하세요 — [데이터 탐색 → 로그 공백 탐지](data-discovery.md#working-with-time).

## 호스트 타임라인 만들기 (한 머신의 모든 것) { #build-a-host-timeline-everything-about-one-machine }

```spl
index=botsv3 host=FYODOR-L earliest="08/20/2018:00:00:00" latest="08/21/2018:00:00:00"
  (sourcetype=WinEventLog EventCode IN (4624,4625,4648,4672,4688,4698,4720,4732,7045,1102))
  OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (1,3,11,12,13,22))
  OR (sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
| eval code=coalesce(EventCode, EventID)
| eval who=coalesce(User, mvindex(Account_Name,1), Account_Name)
| eval what=coalesce(CommandLine, Process_Command_Line, ScriptBlockText, TargetFilename, TargetObject, QueryName, DestinationIp." :".DestinationPort, Service_File_Name, Task_Name, Message)
| eval what=substr(what,1,300)
| table _time, sourcetype, code, who, what
| sort 0 _time
```

검색 하나, 소스타입 셋, 이벤트 코드 몇 개; `coalesce`가 이벤트마다 가장 설명적인 필드를 고르고 `substr`이 잘라서 표를 읽기 쉽게 유지합니다. 보고서 타임라인에 붙여 넣는 표가 바로 이것입니다.

## 참고 자료 { #references }

- [Windows 이벤트 ID](../basics/windows-event-ids.md) · [레지스트리 키 — ASEP](../windows/registry-keys.md#autostart-persistence-asep)
- [Splunk Security Essentials (free app — hundreds of searches with explanations)](https://splunkbase.splunk.com/app/3435)
- [Sigma rules — convert to SPL with sigma-cli / uncoder.io](https://github.com/SigmaHQ/sigma)
- [JPCERT Tool Analysis Result Sheet — what each attack tool logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
