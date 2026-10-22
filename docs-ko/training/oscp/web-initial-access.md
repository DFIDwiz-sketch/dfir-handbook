---
title: 웹과 초기 침투
tags:
  - oscp
---

# 웹과 초기 침투 { #web-initial-access }

<div class="dfir-meta" markdown>
**배점:** standalone 대당 10점 (`local.txt`) · **최종 수정:** 2026-10-23
</div>

!!! abstract "한 문장 요약"
    standalone에서 첫 셸 얻기. 보통 웹 애플리케이션이나 노출된 서비스이고, 고쳐야 돌아가는 공개 익스플로잇인 경우가 많습니다.

!!! note "이 페이지 구성"
    초기 침투 공격면의 공부 지도입니다. 시험은 기발한 것보다 꼼꼼한 정보 수집과 단순한 발상에 점수를 줍니다 — 발판 대부분은 알려진 소프트웨어 버전, 기본 크리덴셜, 또는 애플리케이션이 허용하면 안 되는 업로드예요.

## 1. 모든 서비스 정보 수집 { #enumeration }

[Nmap](../../pentesting/recon/nmap/index.md) 출력에서 시작해, 열린 포트 하나하나를 작은 조사 과제로 다룹니다. 전체 스캔을 기다리지 말고, 나머지가 도는 동안 먼저 나온 포트부터 시작하세요.

- **버전 확인.** 서비스 배너나 웹앱 버전이 공개 익스플로잇으로 가는 가장 빠른 길입니다 — `searchsploit <product> <version>` 으로 검색.
- **전부 읽기.** 페이지 소스, 주석, robots.txt, 오류 메시지, HTTP 헤더. OSCP 박스는 눈에 보이는 곳에 많이 숨겨 둡니다.
- **웹 콘텐츠 퍼징.** 디렉터리, 파일, vhost / 서브도메인(`feroxbuster`, `ffuf`, `gobuster`). 숨은 `/admin` 이나 개발용 vhost가 흔한 입구예요.
- **첫 발견에서 멈추지 말기.** LFI 하나가 박스의 전부가 아닙니다 — 업로드, SSRF, 다른 포트의 두 번째 앱이 또 있을 수 있어요.

## 2. 웹 애플리케이션 경로 { #web-vectors }

| 경로 | 볼 것 | 단서 |
|---|---|---|
| **알려진 취약 소프트웨어** | 버전이 있는 CMS / 앱 | `searchsploit`; 실행 전에 익스플로잇을 읽고 고치기 |
| **기본 / 약한 크리덴셜** | 관리자 패널, Tomcat, Jenkins, 데이터베이스 | `admin:admin`, 제품 기본값, 그다음 짧은 스프레이 |
| **SQL injection (수동)** | 응답을 바꾸는 입력; 오류 | 인증 우회, 데이터 추출, 때로 RCE — 손으로, [아래](#sqli) 참고 |
| **파일 업로드** | 아무 업로드 폼 | 필터를 우회해 웹 셸 업로드 → 단, 플래그는 웹 셸이 아니라 **인터랙티브** 셸에서 읽기 ([시험 규칙](exam-format.md#flag-rules)) |
| **LFI / 경로 탐색** | 파일을 로드하는 파라미터 | SSH 키 / 설정 읽기; 로그 포이즈닝이나 업로드와 묶어 RCE |
| **SSRF** | 앱이 내가 통제하는 URL을 가져옴 | 내부 서비스, 클라우드 메타데이터 접근 |
| **인증 후 기능** | 로그인 후의 템플릿 / 플러그인 / 가져오기 기능 | 많은 CMS RCE는 먼저 로그인이 필요함 |

### SQL injection — 수동만 { #sqli }

sqlmap은 시험에서 **금지** 입니다. 손으로 하는 법을 익히세요: 따옴표와 boolean/time 페이로드로 탐지, `UNION SELECT` 나 error-based로 추출, 그다음 상승(파일 읽기, 웹 셸 쓰기, MSSQL이면 `xp_cmdshell`). DB 종류별로 통한 페이로드를 노트에 모아 두세요.

### 파일 업로드 → 셸 { #file-upload }

목표는 코드 실행이지만, 플래그는 **인터랙티브** 셸에서 나와야 한다는 걸 기억하세요:

1. 웹 셸 업로드 (필터 우회 — 확장자 트릭, content-type, 매직 바이트, 이중 확장자, `.htaccess`).
2. 웹 셸은 **리버스 셸** 을 핸들러로 띄우는 데만 사용.
3. 그 인터랙티브 셸에서 `local.txt` 읽기.

## 3. 공개 익스플로잇 { #public-exploits }

시험 발판 대부분은 공개 익스플로잇을 쓰고, 대부분 손이 갑니다:

- 찾기: `searchsploit <product> <version>`, Exploit-DB, GitHub.
- **실행 전에 읽기** — 뭘 하는지 이해하기; 알 수 없는 바이너리를 박스에 맹목적으로 돌리지 마세요.
- 고치기: 대상 IP/포트, 페이로드, Python 2 → 3, 깨진 URL, 오래된 오프셋.
- **리포트용으로 변경 기록:** 고친 코드, 원본 URL, 바꾼 부분마다 설명 ([시험 규칙](exam-format.md#exploit-code)).

## 4. 클라이언트 사이드 공격 { #client-side }

파일을 여는 사용자를 흉내 내는 박스라면(AD 느낌의 standalone에 흔함), 내가 심거나 보낸 파일이 나에게 콜백할 수 있습니다 — 매크로 문서, 악성 바로가기, UNC 경로로 캡처한 NetNTLMv2 해시. 해시는 대상이 **내** SMB 서버에 접속하게 만들어 캡처하고 — Responder로 이름 해석을 포이즈닝하는 방식은 금지된 스푸핑입니다 ([시험 규칙](exam-format.md#restricted)).

## 5. 웹이 아닌 서비스 { #other-services }

80/443 포트에만 매몰되지 마세요:

- **FTP (21)** — anonymous 로그인, 쓰기 가능한 디렉터리, 알려진 취약 버전.
- **SMB (445)** — null 세션, 읽기 가능한 공유, `nxc smb -u '' -p ''`.
- **SNMP (161/UDP)** — `snmpwalk` 로 사용자, 프로세스, 소프트웨어. UDP 기억하기: UDP 스캔을 돌릴 것.
- **NFS (2049)** — `showmount -e`; 잘못된 export와 no_root_squash.
- **SSH (22)** — 약한 크리덴셜, 찾은 개인 키, 버전별 이슈.

## 체크리스트 { #checklist }

- [ ] 모든 포트 정보 수집; 버전 확인하고 검색
- [ ] 웹 콘텐츠 퍼징(디렉터리, 파일, vhost); 소스와 헤더 읽기
- [ ] 모든 로그인에 기본 / 약한 크리덴셜 시도
- [ ] 각 경로를 첫 발견 너머로 밀어붙이기 (업로드 + LFI + SSRF…)
- [ ] 공개 익스플로잇 이해·수정하고 변경을 리포트용으로 기록
- [ ] UDP 서비스(SNMP)와 웹이 아닌 서비스 확인

## 관련 페이지 { #related-pages }

- [Nmap](../../pentesting/recon/nmap/index.md) · [잘 알려진 포트](../../basics/well-known-ports.md) · [HTTP 상태 코드](../../basics/http-status-codes.md)
- [레드팀: 초기 침투](../../redteam/initial-access.md) · [피싱 전달](../../adversary/phishing-delivery.md) · [방법론과 습관](methodology.md)

## 참고 자료 { #references }

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
