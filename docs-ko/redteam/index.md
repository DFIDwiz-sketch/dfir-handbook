---
title: 레드팀
---

# 레드팀 { #red-team }

레드팀 운영 공부(예: CRTO)와 관련 자료를 정리하는 섹션입니다. 이 핸드북의 다른 부분처럼, 각 주제는 방어자에게도 쓸모가 있게 정리합니다. 공격자가 무엇을 하고, 어떤 흔적이 남아서 탐지할 수 있는지를 함께 둡니다.

이 섹션의 페이지는 왼쪽 메뉴에 표시됩니다.

## Post-Exploitation

[**Post-Exploitation 학습 섹션 →**](post-exploitation/index.md)

Cobalt Strike의 접근 이후 작업을 **19개 절 · 5개 학습 페이지**로 정리했습니다. 명령어 설명과 비교표, 실행 흐름도를 함께 읽고 최신 방어 관점으로 복습합니다.

| 학습 페이지 | 주요 내용 |
| --- | --- |
| [구조와 명령어 실행 모델](post-exploitation/fundamentals.md) | Client·Team Server·Beacon, 상황 파악, API·BOF·fork & run |
| [세션과 파일 시스템](post-exploitation/sessions-files.md) | spawn/spawnas, 경로, 다운로드와 Sync Files |
| [프로세스와 정보 수집](post-exploitation/processes-collection.md) | PID/JID, 레지스트리, 키 입력·화면·VNC |
| [명령 실행과 외부 도구](post-exploitation/execution-tools.md) | shell/run, PowerShell, .NET, Aggressor |
| [최신 방어 관점과 복습](post-exploitation/modern-defense.md) | 버전 변화, 로깅, Credential Guard, SMB, 확인 문제 |