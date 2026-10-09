---
title: 시나리오별 아티팩트 식별
tags:
  - windows
  - triage
  - methodology
---

# 시나리오별 아티팩트 식별 { #identifying-artefacts-by-scenario }

<div class="dfir-meta" markdown>
**분류:** 트리아지 방법론 · **OS:** Windows · **최종 수정:** 2026-10-09
</div>

아티팩트 하나만 보고 "악성"이라고 단정하지 않습니다. 같은 흔적도 **누가, 언제, 어디서, 어떻게** 했는지에 따라 정상일 수도, 공격일 수도 있어요. 이 페이지는 아티팩트를 판단하고, 필요한 Context를 정하고, 그걸 확인할 다음 아티팩트를 고르는 방법을 정리합니다.

## 판단 3단계 { #the-three-step-method }

1. **분류하기** — *정상(Likely normal)*, *의심(Possibly suspicious)*, *확실히 의심(Definitely suspicious)* 중 어디인가?
2. **Context 묻기** — "이게 정상 행동인가?"를 판단할 질문. *알려진 관리 작업인가? 이 사용자가 원래 원격 접속을 하나?*
3. **Next Artefact 찾기** — 그 질문에 답하는 증거. *4624 로그온, VPN 로그, Prefetch, USBSTOR.*

!!! tip "핵심"
    Context는 질문이고, Next Artefact는 그 질문에 답하는 증거입니다.

베이스라인(기준 상태)이 있으면 차이를 셋으로 나눕니다: **정상 변동**(이유가 분명하고 보안 영향 없음), **설정 오류**(보안이 약해졌지만 공격 증거는 아직 없음), **의심/악성**(알려진 공격 패턴과 일치).

## 판단 체크리스트: 6가지 질문 { #six-question-checklist }

| 질문 | 정상 쪽 신호 | 의심 쪽 신호 |
| --- | --- | --- |
| **언제?** | 근무 시간, 정해진 유지보수 시간(예: 백신 스캔 02:00) | 새벽, 주말, 휴가 중, 평소 패턴과 다른 시간 |
| **어디서?** | 내부 IP, 회사 VPN, 평소 위치 | 처음 보는 외부 IP, 해외, 호스팅/VPS 대역 |
| **누가?** | 직무에 맞는 계정, 관리자의 관리 작업 | 인턴·일반 사용자가 민감 자원 접근, 서비스 계정의 대화형 로그인 |
| **어떤 경로?** | `C:\Program Files`, `C:\Windows\System32` | `%Temp%`, `%AppData%`, `Downloads`, `C:\Users\Public`, `C:\ProgramData` |
| **어떤 모양?** | 서명된 파일, 알아볼 수 있는 이름 | 이중 확장자(`invoice.doc.exe`), 무작위 이름, Base64·난독화, 사칭(`svch0st.exe`) |
| **무엇이 바뀌었나?** | 문서화된 변경, 변경 요청(CR) 있음 | 자동 실행 추가, 보안 설정 약화, 로그 삭제, 백신 중지 |

하나만 걸리면 **의심**, 두세 개가 겹치면 **확실히 의심**으로 올립니다. "새벽 3시 + %Temp% + 난독화 PowerShell"은 세 개가 겹쳐요.

아래 조합은 **단독으로도 확실히 의심**입니다.

- 자동 실행 위치(Run/RunOnce/예약 작업/서비스) + 무작위 이름 또는 임시 폴더 경로
- 인코딩·난독화된 PowerShell (`-enc`, `FromBase64String`, `IEX`)
- 보안 로그나 백신 로그를 수동으로 삭제
- 이중 확장자 실행 파일

## 시나리오별 가이드 { #scenario-guide }

### 1. 로그인과 원격 접속 { #1-logons-and-remote-access }

- **정상**: 내부 IP에서 근무 시간 로그인.
- **의심**: 새벽 로그인, 외부 IP, 불가능한 이동, 실패 후 성공.
- **Context**: 외부 IP면 *허용 IP 목록, 사용자 역할, 평소 로그인 이력*. 내부 이동(RDP, SMB)이면 *이 사용자/시스템에 원격 접속이 예상되는가?*
- **Next Artefact**: Security 4624/4625/4634/4647/4648, 로그온 유형(Type 3 네트워크, Type 10 RDP), VPN 로그, RDP 로그(`TerminalServices-LocalSessionManager` 21/24/25, `RemoteConnectionManager` 1149).

### 2. PowerShell과 스크립트 { #2-powershell-and-scripts }

- **정상**: 관리자가 서명된 스크립트를 정해진 경로에서 실행.
- **의심**: `%Temp%`에서 실행, `-enc`/`-w hidden`/`-nop`, `FromBase64String`, `IEX`, `DownloadString`.
- **Context**: 알려진 관리 작업인가? 스크립트 내용은? 부모 프로세스는?
- **Next Artefact**: 4104(스크립트 블록 — 디코딩된 실제 코드), 4103(모듈 로깅), 4688/Sysmon 1(프로세스와 명령줄), `ConsoleHost_history.txt`, process tree.

### 3. 지속성(Persistence) { #3-persistence }

- **정상**: 백신·업데이트 서비스처럼 문서화된 항목.
- **의심**: Run/RunOnce의 무작위 이름, 짧은 주기(예: 30분) 예약 작업, 임시 폴더를 가리키는 서비스.
- **Context**: 베이스라인에 있었나? 누가, 언제 만들었나? 무엇을 실행하나?
- **Next Artefact**: `HKCU/HKLM\...\CurrentVersion\Run`, `RunOnce`, `C:\Windows\System32\Tasks\`, 4698(예약 작업 생성), 7045(서비스 설치), 실행 파일 경로·해시·서명, Autoruns.

### 4. DNS와 네트워크 { #4-dns-and-network }

- **정상**: `microsoft.com`, 내부 `*.local` 도메인.
- **의심**: 무작위 문자열 도메인(DGA 의심, 예: `xf21zy.biz`), 새로 등록된 도메인, 내부 DB만 쓰던 PC의 외부 443 연결, 일정 간격 비콘.
- **Context**: 도메인 나이, WHOIS, 위협 인텔리전스 평판, 이 PC가 원래 외부와 통신하나?
- **Next Artefact**: DNS·방화벽·프록시 로그, PCAP, Zeek `conn.log`/`dns.log`/`ssl.log`, Sysmon 3·22, 연결을 만든 프로세스.

### 5. 파일과 실행 파일 { #5-files-and-executables }

- **정상**: 공식 출처의 서명된 설치 파일.
- **의심**: 이중 확장자, `Downloads`에서 실행된 `update.exe`, 서명 없음, 이름 사칭.
- **Context**: 파일 출처는? 사용자가 알고 받았나? 정상 업데이트인가?
- **Next Artefact**: 해시와 VirusTotal, 디지털 서명, `Zone.Identifier`(받은 URL), [Prefetch](prefetch.md)(실행 여부·횟수), [Amcache](amcache.md), [Shimcache](shimcache.md), 브라우저 다운로드 기록.

### 6. USB와 데이터 유출 { #6-usb-and-data-exfiltration }

- **정상**: 승인된 장치를 근무 시간에 사용.
- **의심**: USB 금지 PC에 새벽 연결, 연결 직후 대량 파일 접근, 외부 FTP·클라우드 업로드.
- **Context**: 근무 일정, USB 정책, 접근한 파일의 민감도.
- **Next Artefact**: `USBSTOR`, `MountedDevices`, `setupapi.dev.log`(최초 연결), `Partition/Diagnostic` 1006, [LNK·Jump Lists](lnk-jumplists.md), Shellbags.

### 7. 브라우저 확장 { #7-browser-extensions }

- **정상**: 허용 목록에 있는 확장.
- **판단**: 목록에 없지만 악성 증거가 없으면 먼저 *정책 위반/설정 오류*. 과도한 권한(모든 사이트 읽기, 쿠키), 외부 전송, 사이드로딩이 보이면 *악성*.
- **Context**: 출처(스토어인가 직접 설치인가), 요청 권한, 설치한 사람.
- **Next Artefact**: `...\User Data\Default\Extensions\<ID>\manifest.json`, `Preferences`/`Secure Preferences`, 확장 ID 평판, 프록시 로그.

### 8. 로그 삭제와 방어 회피 { #8-log-clearing-and-defence-evasion }

- **정상**: 보존 정책에 따른 자동 순환.
- **의심**: 수동 삭제, 백신 중지, 백신 예외 추가, 감사 정책 변경.
- **Context**: 누가 지웠나? 직전에 악성코드 탐지가 있었나?
- **Next Artefact**: 1102(보안 로그 삭제), 104(System 로그 삭제), 4719(감사 정책 변경), Defender 5001/5007, 마지막 스캔 결과, SIEM 사본.

### 9. 권한과 정책 변경 { #9-privilege-and-policy-changes }

- **정상**: 변경 요청이 있는 관리자 작업.
- **판단**: 비밀번호 복잡성 해제 같은 보안 약화는 먼저 *설정 오류*로 보고 실수인지 의도인지 확인. 일반 사용자의 로그온 스크립트 수정은 *의심*.
- **Context**: 그룹 정책 권한, 사용자 권한, 변경 기록.
- **Next Artefact**: 5136, 4728/4732, 4670, GPO 버전 기록, SYSVOL 수정 시간, 레지스트리 변경.

### 10. 민감 파일 접근 { #10-sensitive-file-access }

- **정상**: 직무에 맞는 사용자가 근무 시간에 접근(HR 담당자가 13:00에 HR 폴더 접근).
- **의심**: 인턴이 `payroll.xlsx` 접근, 짧은 시간에 많은 파일 접근.
- **Context**: 직무, 접근 권한, 그룹 소속.
- **Next Artefact**: 4663, 5140/5145, ACL, 접근 시간, 그룹 정보, LNK·Jump Lists.

## 베이스라인과 비교하기 { #comparing-against-a-baseline }

| 분류 | 판단 기준 | 예시 | 다음 조치 |
| --- | --- | --- | --- |
| **정상 변동** | 이유가 기록돼 있고 보안 영향 없음 | 네트워크 지연으로 백신 업데이트 02:00 → 07:00 | 로그와 정책이 일치하면 조치 없음 |
| **설정 오류** | 보안이 약해졌지만 공격 증거는 아직 없음 | 비밀번호 복잡성 해제, 목록에 없는 확장 | 변경 기록 확인, 실수인지 의도인지 판단 |
| **의심/악성** | 알려진 공격 기법과 일치 | 새벽 로그인, 새 Run 키, 30분 주기 PS1 작업, DGA 도메인, 새벽 USB, 백신 프로세스 사라짐 | 관련 아티팩트로 타임라인 작성 |

비교 순서:

1. **사라진 것** — 백신 프로세스가 없어진 것이 새로 생긴 것보다 중요한 신호예요.
2. **새로 생긴 것** — 자동 실행, 예약 작업, 서비스, 확장, 계정.
3. **바뀐 것** — 정책, 권한, 시간대, 연결 대상.
4. **시간을 한 줄로** — 01:12 USB → 03:14 로그인 → PowerShell → 외부 443. 따로 보면 애매해도 이어지면 공격 흐름이 보입니다.

베이스라인이 없다면 같은 역할의 다른 PC와 비교하세요.

## 2026 최신 동향과 바뀐 아티팩트 { #2026-trends-that-change-what-you-look-for }

공격자가 악성코드 대신 **사용자 손과 정상 도구**를 쓰는 흐름이 뚜렷해요. "이상한 파일"보다 "정상 도구가 이상하게 쓰인 흔적"을 찾으세요.

### ClickFix와 변종: RunMRU만 보면 놓친다 { #clickfix-variants-runmru-is-no-longer-enough }

ClickFix는 가짜 CAPTCHA나 오류 창으로 사용자가 직접 명령을 붙여넣어 실행하게 만듭니다. Win+R 방식은 `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`에 명령이 남지만, 2026년 초 변종은 Win+X → I로 Windows Terminal을 열어 RunMRU에 흔적이 없어요 ([trackr.live](https://www.trackr.live/?p=1192)).

- **확인할 것**: explorer.exe·브라우저·wt.exe가 powershell/cmd/mshta/regsvr32/rundll32를 띄운 관계(Sysmon 1, 명령줄 감사가 켜진 4688), `-w hidden`/`-enc`/`IEX`, 직후 처음 보는 도메인 연결, 4104, `ConsoleHost_history.txt`.
- **주의**: RunMRU는 "입력됐다"는 증거일 뿐 "실행 성공"의 증거가 아니에요. 공백 패딩으로 명령을 숨기기도 합니다.

### CrashFix: 브라우저 확장이 미끼 { #crashfix-a-browser-extension-as-the-lure }

2026년 1월 Huntress가 밝힌 CrashFix는 uBlock Origin Lite를 흉내 낸 가짜 확장 **NexShield**로 브라우저를 멈추게 한 뒤, "비정상 종료" 경고로 클립보드의 PowerShell 명령을 붙여넣게 만들었어요. 설치 후 1시간 동안 조용히 기다립니다 ([Cyber Security News](https://cybersecuritynews.com/crashfix-hackers-using-malicious-extensions/)).

- **교훈**: 목록에 없는 확장은 정책 위반으로 시작하되, **확장 설치 → 브라우저 충돌 → RunMRU/PowerShell 실행**이 한 줄로 이어지면 악성입니다.

### RMM 도구 악용: 정상 프로그램이 C2가 된다 { #rmm-abuse-legitimate-tools-as-c2 }

Huntress 2026 Cyber Threat Report에 따르면 RMM 악용이 전년 대비 277% 늘었고 전통적인 해킹 도구 사용은 53% 줄었어요. ScreenConnect, AnyDesk, Atera, NetSupport, PDQ Connect, Splashtop 등이 쓰입니다 ([Dark Reading](https://www.darkreading.com/application-security/rmm-abuse-explodes-hackers-ditch-malware)).

- **판단 기준**: 이 조직이 **실제로 승인한 RMM인가?** 승인된 제품도 처음 보는 테넌트·계정·릴레이로 연결되면 의심.
- **확인할 것**: 7045, 설치 경로와 서명, Prefetch·Amcache 첫 실행 시간, RMM 자체 연결 로그(`ProgramData` 아래), 외부 릴레이 도메인.

### BYOVD와 EDR 무력화 { #byovd-and-edr-killers }

2026년 6월 ESET이 분석한 **GentleKiller**(The Gentlemen 랜섬웨어)는 취약하거나 악성인 커널 드라이버를 올려 48개 보안 제품의 400개 이상 프로세스를 종료하려 해요. 보안 업체 같은 파일명, 가짜 버전 정보, 복사한 서명을 씁니다 ([Security Affairs](https://securityaffairs.com/posts/inside-gentlekiller-the-edr-killer-powering-the-gentlemen)).

- **판단 기준**: 보안 프로세스가 **사라진 것** 자체가 강한 신호예요.
- **확인할 것**: Sysmon 6(드라이버 로드), 7045/4697, `C:\Windows\System32\drivers` 밖의 `.sys`, Defender 5001, 드라이버 해시를 LOLDrivers와 대조.

### Windows 11 기본 탑재 Sysmon { #native-sysmon-in-windows-11 }

Microsoft는 2026년 2월 Windows 11 Insider 빌드에서 Sysmon 기본 탑재를 시작했어요. 기본은 꺼져 있고, 선택적 기능을 켠 뒤 `sysmon -i`로 설치하면 이벤트가 Windows 이벤트 로그에 쌓입니다 ([BleepingComputer](https://bleepingcomputer.com/news/microsoft/microsoft-rolls-out-native-windows-11-sysmon-security-monitoring)).

- **의미**: Sysmon 1·3·6·13·22가 있는 시스템이 늘어납니다. 조사 시작 때 **Sysmon이 켜져 있었는지, 어떤 설정이었는지** 먼저 확인하세요. 일부 공개 설정은 RunMRU 같은 사용자 Explorer 하위 키를 기록하지 않아요.

## 빠른 참조표 { #quick-reference }

전체 목록: [Windows 이벤트 ID](../basics/windows-event-ids.md) · [레지스트리 키](registry-keys.md) · [이벤트 로그](event-logs.md)

### 이벤트 ID { #event-ids }

| 로그 | ID | 의미 |
| --- | --- | --- |
| Security | 4624 / 4625 | 로그온 성공 / 실패 (Type 3 네트워크, Type 10 RDP) |
| Security | 4634 / 4647 | 로그오프 / 사용자가 직접 로그오프 |
| Security | 4648 | 명시적 자격 증명으로 로그온 |
| Security | 4663 | 객체(파일) 접근 |
| Security | 4688 | 새 프로세스 생성 (명령줄 감사 필요) |
| Security | 4697 / 4698 | 서비스 설치 / 예약 작업 생성 |
| Security | 4719 | 감사 정책 변경 |
| Security | 4728 / 4732 | 전역 / 로컬 그룹에 구성원 추가 |
| Security | 5136 | 디렉터리 객체 변경 (GPO 등) |
| Security | 5140 / 5145 | 공유 폴더 접근 / 공유 파일 접근 상세 |
| Security | 1102 | 보안 로그 삭제 |
| System | 7045 | 새 서비스 설치 |
| System | 104 | 이벤트 로그 삭제 |
| PowerShell | 4103 / 4104 | 모듈 로깅 / 스크립트 블록 로깅 |
| TS-LocalSessionManager | 21 / 24 / 25 | RDP 로그온 / 끊김 / 재연결 |
| TS-RemoteConnectionManager | 1149 | RDP 인증 성공 (원격 IP) |
| Defender | 5001 / 5007 | 실시간 보호 꺼짐 / 설정 변경 |
| Partition/Diagnostic | 1006 | 저장 장치 연결 (USB) |
| Sysmon | 1 / 3 / 6 / 13 / 22 | 프로세스 / 네트워크 / 드라이버 / 레지스트리 값 / DNS |

### 레지스트리 경로 { #registry-paths }

| 목적 | 경로 |
| --- | --- |
| 자동 실행 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` (HKLM 동일) |
| 실행 창 입력 기록 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` |
| USB 장치 | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `HKLM\SYSTEM\MountedDevices` |
| 서비스 | `HKLM\SYSTEM\CurrentControlSet\Services` |
| 실행 흔적 | `AppCompatCache`(Shimcache), `UserAssist`, BAM(`...\Services\bam\State\UserSettings`) |

### 파일 위치 { #file-locations }

| 목적 | 위치 |
| --- | --- |
| 실행 흔적 | `C:\Windows\Prefetch\*.pf`, `C:\Windows\AppCompat\Programs\Amcache.hve` |
| 예약 작업 | `C:\Windows\System32\Tasks\` |
| PowerShell 기록 | `%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| 이벤트 로그 | `C:\Windows\System32\winevt\Logs\*.evtx` |
| USB 최초 연결 | `C:\Windows\INF\setupapi.dev.log` |
| 연 파일 기록 | `%AppData%\Microsoft\Windows\Recent\` (LNK, `AutomaticDestinations`) |
| Chrome 확장 | `%LocalAppData%\Google\Chrome\User Data\Default\Extensions\` |
| 다운로드 출처 | `Zone.Identifier` ADS (`HostUrl`, `ReferrerUrl`) |

## 출처 { #sources }

- [ClickFix's Cleanest Artifact Is RunMRU. The 2026 Variants Walked Away From It](https://www.trackr.live/?p=1192) — trackr.live
- [CrashFix: hackers using malicious extensions](https://cybersecuritynews.com/crashfix-hackers-using-malicious-extensions/) — Cyber Security News, 2026-01-19
- [RMM Abuse Explodes as Hackers Ditch Malware](https://www.darkreading.com/application-security/rmm-abuse-explodes-hackers-ditch-malware) — Dark Reading, 2026-02-17
- [Inside GentleKiller: The EDR-Killer Powering The Gentlemen](https://securityaffairs.com/posts/inside-gentlekiller-the-edr-killer-powering-the-gentlemen) — Security Affairs, 2026-06-20
- [Microsoft rolls out native Windows 11 Sysmon security monitoring](https://bleepingcomputer.com/news/microsoft/microsoft-rolls-out-native-windows-11-sysmon-security-monitoring) — BleepingComputer, 2026-02-04
