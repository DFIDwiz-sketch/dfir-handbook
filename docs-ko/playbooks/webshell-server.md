---
title: 웹셸과 서버 침해
tags:
  - playbook
  - webshell
  - initial-access
---

# 웹셸과 서버 침해 { #web-shell-server-compromise }

<div class="dfir-meta" markdown>
**시나리오:** 웹 서버 침해 — 웹셸, 익스플로잇된 앱, 또는 웹 서비스를 통한 공격자의 명령 실행 · **최종 수정:** 2026-09-17
</div>

!!! abstract "언제 쓰나"
    인터넷에 노출된(또는 내부) 웹 서버가 이상하게 동작할 때: 웹 루트의 낯선 스크립트, 셸을 띄우는 웹 서버 프로세스(`w3wp.exe`, `httpd`, `tomcat`, `php-fpm`), 또는 앱에 대한 익스플로잇 경보. 웹셸은 흔한 **최초 침투**이자 **지속성** 발판입니다 — HTTP 요청을 서버의 명령 실행으로 바꿔 주는 작은 스크립트입니다.

## 1. 트리아지 (첫 15분) { #1-triage-first-15-minutes }

- 확인: 디스크에 **웹셸**(개발자가 넣지 않은 웹 루트의 스크립트)이 있나, 그리고/또는 **웹 서버 프로세스가 자식 프로세스**(cmd/powershell/sh)를 띄우나?
- 서버 역할과 노출 정도를 파악하세요 (인터넷에 노출? 어떤 앱/CMS/버전?). 알려진 취약 앱 + 새 스크립트 = 익스플로잇당함.
- 무언가 정리되기 전에 웹셸 파일과 관련 **웹 서버 접근 로그**를 보존하세요 — 접근 로그가 요청을 셸과 공격자 IP에 연결합니다.
- 지금 쓰이고 있다면 서버를 네트워크에서 격리하세요 (RAM/아티팩트를 위해 실행은 유지).

## 2. 수집 { #2-collect }

| 출처 | 무엇 | 어디서 |
|---|---|---|
| 웹 서버 접근/오류 로그 | 셸로의 요청, 공격자 IP, 익스플로잇 시도 | IIS (`%SystemDrive%\inetpub\logs\LogFiles`), Apache/Nginx (`/var/log/…`), Tomcat |
| 웹셸 파일 | 페이로드 자체 | 웹 루트; 해시하고 읽어 보기 |
| 호스트 트리아지 | 서버에서의 실행, 지속성, 횡적 이동 | [KAPE](../tools/kape.md) / [Velociraptor](../tools/velociraptor.md) (Linux 아티팩트도) |
| [$MFT / $UsnJrnl](../windows/mft-usn.md) | 셸이 언제 (무엇에 의해) 쓰였나 | 파일 생성 시각 = 업로드 시각 |
| 네트워크 | 익스플로잇 요청 + 후속 C2/횡적 이동 | [Zeek http.log](../network/zeek/http-log.md) / [Arkime](../network/arkime/index.md) |
| 앱/DB 로그 | SQLi, 인증 우회, 관리 작업 | 애플리케이션별 |

## 3. 분석 { #3-analyse }

- **셸 찾기**: 셸을 띄우는 웹 서버 프로세스가 가장 시끄러운 신호입니다 ([수상한 부모](../adversary/wmi-winrm.md) — `w3wp.exe`/`httpd`/`tomcat`→`cmd`/`powershell`/`sh`/`whoami`). 디스크에서는 수상한 내용(`eval`, `system(`, `exec(`, `passthru(`, `Runtime.exec`, base64 덩어리)이 든, 웹 루트에 최근 만들어진 스크립트. 해시해서 전사를 검색하세요 — 공격자는 같은 셸을 여러 서버에 떨어뜨립니다.
- **언제, 어떻게 들어왔나**: 셸의 [`$MFT`/`$UsnJrnl`](../windows/mft-usn.md) 생성 시각 = 업로드 순간; **접근 로그** 항목(그 경로로의 `PUT`/`POST`, 또는 직전의 익스플로잇 요청)과 상관분석하세요. 그러면 **최초 침투 경로**(업로드 기능, 역직렬화, RCE, 경로 탐색, 탈취된 자격증명)가 나옵니다.
- **공격자가 셸로 무엇을 했나**: 접근 로그가 셸로의 모든 요청을 보여 줍니다 — `POST` 본문(기록된다면)이나 이어진 자식 프로세스([Sysmon 1](../splunk/security-searches.md#what-ran))가 명령을 드러냅니다: `whoami`, `net user`, 도구 다운로드, [자격증명 덤프](../adversary/lsass-dumping.md), [횡적 이동](../adversary/psexec-smb.md).
- **공격자 IP와 범위**: 셸에 접속한 출발지 IP → 그들이 건드린 다른 경로, 다른 서버, 침해 전 정찰(`404` 스캔)을 검색하세요. 셸 하나는 대개 더 있다는 뜻입니다.
- **셸 외의 지속성**: [서비스/작업/Run 키](../adversary/persistence.md), 새 웹 앱 관리자 계정, 수정된 앱 설정, 추가 셸(공격자는 예비용을 심어 둠)을 확인하세요.

## 4. 봉쇄 / 제거 { #4-contain-eradicate }

- 웹셸을 **모두** 제거하고(전부 찾으세요 — 예비용을 심어 둡니다) 공격자가 추가한 계정, 작업, 서비스도 제거하세요.
- 업로드/RCE를 허용한 **취약한 앱/기능을 패치하거나 끄세요** — 경로를 막지 않고 셸만 지우면 다시 침해당할 뿐입니다.
- 서버가 갖고 있던 자격증명/비밀 정보(앱 서비스 계정, DB 자격증명, API 키, 머신 키)를 교체하세요 — 읽혔다고 가정하세요.
- 공격자가 서버에서 다른 곳으로 이동했다면 [횡적 이동 / 도메인](lateral-domain.md)으로 넘어가세요.
- 공격자 IP를 차단하고; 익스플로잇에 대한 WAF 규칙을 고려하세요.

## 5. 복구와 교훈 { #5-recover-lessons }

- 침해가 파일 하나 제거로 끝나는 수준을 넘었다면 깨끗한 매체로 서버를 재구축하세요 — 웹 서버의 모든 셸/백도어를 찾았다고 확신할 수 없습니다.
- 앱은 패치하고, 비밀 정보를 교체하고, WAF 뒤에 두고, 웹 루트 쓰기 권한을 줄여서 복원하세요 (웹 프로세스가 자기 루트에 실행 가능한 스크립트를 쓸 수 없어야 합니다).
- 강화: 최소 권한 앱 풀, 업로드 폴더에서 스크립트 실행 금지, 웹 루트 파일 무결성 모니터링, 셸을 띄우는 웹 서버 프로세스에 대한 Sysmon 규칙, 셸 같은 요청 패턴에 대한 지속적인 접근 로그 모니터링.

## 유용한 쿼리 { #useful-queries }

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval parent=lower(replace(ParentImage,".*\\\\",""))
| where parent IN ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat*.exe","java.exe","sqlservr.exe")
    AND match(lower(Image),"cmd\.exe|powershell|whoami|net1?\.exe|cscript|wscript|bitsadmin|certutil|/bin/(ba)?sh")
| table _time, host, parent, Image, CommandLine, User
| sort 0 _time
```

Sysmon `1` = 프로세스 생성. 셸이나 탐색 명령을 띄우는 웹 서버/앱 프로세스는 웹셸을 정의하는 신호입니다 — 정상 웹 앱은 거의 이러지 않습니다. 비교를 위해 `parent`는 파일명만 남겼습니다.

```spl
index=<your_web_index> sourcetype=iis
| stats count, values(c_ip) as src, values(cs_method) as methods, min(_time) as first, max(_time) as last by cs_uri_stem
| where match(cs_uri_stem,"(?i)\.(aspx?|php|jsp|jspx)$") AND match(mvjoin(methods,","),"POST")
| where count < 50
| convert ctime(first) ctime(last)
| sort first
```

요청한 페이지별로 묶은 웹 서버 접근 로그. 소수의 출발지에서 `POST`를 받고 거의 접속되지 않는(`count`가 낮은) 스크립트 엔드포인트 — 특히 파일명이 앱에 속하지 않는 것 — 는 웹셸 후보입니다; `first`/`last`가 활동 기간을, `src`가 공격자 IP를 알려 줍니다. 필드 이름(`cs_uri_stem`, `c_ip`, `cs_method`)은 [데이터 탐색](../splunk/data-discovery.md)으로 자기 로그 소스에 맞게 바꾸세요.

## 참고 자료 { #references }

- [MITRE ATT&CK — Server Software Component: Web Shell (T1505.003)](https://attack.mitre.org/techniques/T1505/003/)
- [CISA — Web shell detection & prevention](https://www.cisa.gov/) · [NSA/ASD web shell guidance](https://www.cisa.gov/resources-tools/resources/detect-and-prevent-web-shell-malware)
- 관련 페이지: [피싱/최초 침투](../adversary/phishing-delivery.md) · [지속성](../adversary/persistence.md) · [LSASS 덤프](../adversary/lsass-dumping.md) · [Zeek http.log](../network/zeek/http-log.md) · [MFT/USN](../windows/mft-usn.md)
