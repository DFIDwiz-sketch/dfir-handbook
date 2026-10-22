---
title: Windows 권한 상승
tags:
  - oscp
---

# Windows 권한 상승 { #windows-privilege-escalation }

<div class="dfir-meta" markdown>
**배점:** Windows standalone 대당 10점 (`proof.txt`) + AD 세트 호스트 · **최종 수정:** 2026-10-22
</div>

!!! abstract "한 문장 요약"
    저권한 사용자에서 Administrator / SYSTEM까지. 정보 수집 스크립트를 돌리고, 토큰 권한을 먼저 본 다음, 서비스·예약 작업·저장된 크리덴셜을 확인합니다.

!!! info "뼈대 페이지"
    지금은 구조만 있습니다 — 아래 제목이 계획이에요. 공부하면서 각 부분을 채워 나가세요.

## 정보 수집 { #enumeration }

- winPEAS, PrivescCheck, SharpUp, PowerUp — 각각 무엇을 확인하는지

## 토큰 권한과 potato { #token-privileges }

- `SeImpersonatePrivilege` → GodPotato / PrintSpoofer

## 서비스 { #services }

- 수정 가능한 실행 파일, 약한 레지스트리 키, unquoted path

## 예약 작업 { #scheduled-tasks }

## AlwaysInstallElevated { #alwaysinstallelevated }

## DLL 하이재킹 { #dll-hijacking }

## 저장된 크리덴셜 { #stored-credentials }

- GPP 비밀번호, 저장된 자격 증명, PowerShell 히스토리, 파일
- SAM만으로 부족할 때 LSA secrets

## UAC { #uac }

## 커널과 누락된 패치 { #kernel }

## 관련 페이지 { #related-pages }

- [토큰 가장 / Potato](../../adversary/token-impersonation-potato.md) · [UAC 우회](../../adversary/uac-bypass.md)
- [SAM / NTDS 추출](../../adversary/sam-ntds-extraction.md) · [LSASS 덤프](../../adversary/lsass-dumping.md)
- [레지스트리 키](../../windows/registry-keys.md) · [이벤트 로그](../../windows/event-logs.md)

## 참고 자료 { #references }

- [LOLBAS](https://lolbas-project.github.io/)
