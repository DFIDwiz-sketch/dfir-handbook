---
title: Linux 포렌식
---

# Linux 포렌식 { #linux-forensics }

Linux 호스트(서버, 컨테이너 호스트, 가끔은 워크스테이션)의 아티팩트와 로그 소스입니다. **질문**에서 출발하세요. 동작 원리는 각 페이지에 있습니다.

## 질문 → 어디를 볼까 { #question-where-to-look }

| 질문 | 주요 출처 | 함께 확인 |
|---|---|---|
| **누가, 어디서 로그인했고, 무엇을 입력했나?** | [인증과 히스토리](auth-and-history.md) — `auth.log`/`secure`, `wtmp`/`btmp`, 셸 히스토리 | journald, auditd `execve` |
| **공격자는 재부팅 후에도 어떻게 살아남나?** | [지속성](persistence.md) — cron, systemd, SSH 키, 프로필, PAM, 모듈 | 패키지 무결성 검사 (`rpm -Va`/`dpkg --verify`) |
| **이 파일은 언제 생성/수정됐나 — 타임스톰핑됐나?** | [파일시스템과 타임스탬프](filesystem-timestamps.md) — MACB, ctime, ext4 birth | Sleuth Kit 타임라인, ext4 저널 |
| **무엇이 실행됐고 / 실행 중이고 / 리스닝 중인가?** | [로그, 프로세스, 트리아지](logs-and-triage.md) — `ps`, `ss`, `/proc`, auditd | `/proc`의 삭제됐지만 열려 있는 바이너리 |
| **무엇이 언제 설치됐나?** | [로그와 트리아지](logs-and-triage.md) — `dpkg.log`/`apt history`/`yum.log` | 패키지 무결성 |
| **Linux 웹 서버가 뚫렸다** | [웹셸 플레이북](../playbooks/webshell-server.md) | Apache/Nginx 로그, [로그와 트리아지](logs-and-triage.md) |
| **전부 수집하기** | [UAC / CatScale / Velociraptor](../tools/velociraptor.md) | [이미징](../tools/imaging-collection.md) |

## 페이지 { #pages }

<div class="grid cards" markdown>

-   **[인증과 히스토리](auth-and-history.md)** — 인증 로그, wtmp/btmp/lastlog, 셸 히스토리, 변조된 로그 교차 확인
-   **[지속성](persistence.md)** — cron, systemd, 프로필, SSH 키, PAM, LD_PRELOAD, 모듈; 패키지 무결성 검사
-   **[파일시스템과 타임스탬프](filesystem-timestamps.md)** — MACB, ctime으로 타임스톰핑 탐지, 숨김/setuid 파일, 삭제됐지만 열린 파일, ext4 저널
-   **[로그, 프로세스, 트리아지](logs-and-triage.md)** — 로그 지도, 실행 상태 스냅샷, 프로세스 트리아지, 한 번에 돌리는 스크립트

</div>

## Linux가 Windows와 다른 점 (Windows 위주 분석가를 위해) { #how-linux-differs-from-windows-for-the-windows-heavy-analyst }

조사 *방법*은 같습니다 — 타임라인, 핵심 값으로 피벗, 출처 교차 확인. 하지만 아티팩트가 다릅니다. 레지스트리가 없고(설정은 `/etc` 아래 텍스트 파일), Prefetch/Amcache도 없으며(실행 증거는 **auditd**, 셸 히스토리, 패키지 로그에서 — 있다면), `$MFT` `$FILE_NAME` 같은 두 번째 타임스탬프 세트도 없고(그래서 **ctime**이 타임스톰핑 탐지기가 됩니다), 로그는 EVTX가 아니라 일반 텍스트나 journald입니다. 가장 큰 변수는 **어떤 로깅이 켜져 있었나**입니다: auditd가 있으면 Sysmon급 실행 데이터가 있고, 없으면 히스토리 파일, journald, 파일시스템으로 재구성해야 합니다. 모든 보고서에 로깅 상태를 적으세요.

## 작업 순서 (라이브 호스트) { #order-of-work-live-host }

1. **휘발성 상태부터 스냅샷** — `ps`, `ss`, `/proc`, `lsof`, `lsmod` ([로그와 트리아지](logs-and-triage.md)) — 상태가 바뀌거나 메모리 이미징으로 시스템이 재부팅되기 전에.
2. 인증 이야기 — [누가 들어왔나](auth-and-history.md).
3. 지속성 훑기 — [어디에 숨었나](persistence.md), 패키지 무결성 포함.
4. 파일시스템 타임라인 — [무엇이 언제 바뀌었나](filesystem-timestamps.md).
5. 상관분석; 호스트가 하나 이상이면 맞는 [플레이북](../playbooks/index.md)으로 확대.

!!! info "이 섹션에 페이지 추가하기"
    `python new.py linux/<name> -t artifact` (또는 `-t concept`) — 사이드바에 자동으로 나타납니다.
