---
title: Linux 권한 상승
tags:
  - oscp
---

# Linux 권한 상승 { #linux-privilege-escalation }

<div class="dfir-meta" markdown>
**배점:** Linux standalone 대당 10점 (`proof.txt`) · **최종 수정:** 2026-10-22
</div>

!!! abstract "한 문장 요약"
    저권한 셸에서 root까지. 먼저 정보를 모으고, 흔한 설정 실수를 순서대로 확인하고, 커널 익스플로잇은 마지막에 씁니다.

!!! info "뼈대 페이지"
    지금은 구조만 있습니다 — 아래 제목이 계획이에요. 공부하면서 각 부분을 채워 나가세요.

## 셸 업그레이드 { #shell-upgrade }

- 다른 것보다 먼저 안정적인 TTY 만들기

## 정보 수집 { #enumeration }

- linpeas — 결과를 읽는 법
- 매번 돌릴 수동 명령어

## sudo { #sudo }

- `sudo -l`, GTFOBins

## SUID와 capabilities { #suid-capabilities }

## Cron과 와일드카드 { #cron }

## 쓰기 가능한 파일과 PATH { #writable-path }

## 시스템 안의 크리덴셜 { #credentials }

- 설정 파일, history, SSH 키, DB 크리덴셜

## 내부 서비스 { #internal-services }

- localhost 에서만 도는 서비스 → 포트 포워딩 후 공격

## 커널 익스플로잇 { #kernel }

- 안전하게 고르기 — 마지막 수단

## 관련 페이지 { #related-pages }

- [Linux 인증과 히스토리](../linux/auth-and-history.md) · [Linux 지속성](../linux/persistence.md) · [Linux 로그와 트리아지](../linux/logs-and-triage.md)
- [Linux 명령어](../basics/linux-commands.md)

## 참고 자료 { #references }

- [GTFOBins](https://gtfobins.github.io/)
