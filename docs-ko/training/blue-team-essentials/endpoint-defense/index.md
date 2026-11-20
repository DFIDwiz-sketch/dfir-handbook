---
title: 엔드포인트 방어
tags:
  - training
  - blue-team
  - endpoint
  - hardening
---

# 엔드포인트 방어 { #endpoint-defense }

!!! abstract "한 줄 요약"
    앞 섹션은 호스트 위를 지나가는 공격자를 따라갔고, 이 섹션은 같은 길을 방어자 쪽에서 다시 걷습니다. 공격 단계마다 방어선이 하나씩 있습니다 — 익스플로잇에는 인벤토리·취약점 스캔·패치·익스플로잇 보호, 설치에는 하드닝·백신·애플리케이션 제어·파일 무결성 모니터링·PAW, C2에는 호스트 방화벽, 최종 목표 행동에는 감사·행동 분석·DLP·로깅. 그리고 각 방어선은 막는 동시에 SOC가 쓸 증거를 남겨야 합니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [자산 목록, 취약점 스캔, 패치, 익스플로잇 보호 — 공격이 자리 잡기 전에 막기](inventory-vulns-patching.md) | 킬 체인을 따라 겹겹이 막기(단계 → 공격자에게 필요한 것 → 엔드포인트 방어), 우리 소프트웨어 알기: Uninstall 레지스트리 인벤토리와 `dpkg-query`(백포트), `Win32_Product`를 쓰면 안 되는 이유, 능동 vs 수동 찾기, `nmap -sS -sV -O --script ftp-anon,smb-os-discovery` 스캔 한 줄씩(익명 FTP, 버전 숨긴 Tomcat, 지원 끝난 Server 2012 R2), T1046/T1595, 인증 없는 스캔 vs 인증 스캔 나란히, "reboot pending", 심각도·실제 악용(KEV/EPSS)·자산 등급으로 우선순위, OS·서버·클라이언트 패치, CIS Controls v7 → v8.1 번호, 긴급 패치 기준(Essential Eight 48시간), `Get-HotFix`·WindowsUpdateClient 19/20/43·`apt list --upgradable`·`reboot-required`로 확인, 익스플로잇 방지: DEP/ASLR/CFG/SEHOP의 원리, EMET → Exploit Guard → 지금, `Get-ProcessMitigation`, Security-Mitigations 로그, 제어된 폴더 액세스(1123/1124, T1486), 네트워크 보호(1125/1126), ASR 규칙, `Get-MpPreference` GUID와 동작, Office → PowerShell 차단 1121 칸별 해석, 라이선스와 수동 모드, 확인 문제 |

!!! info "이어서 추가될 내용"
    Credential Guard와 가상화 기반 보안, 호스트 방화벽(호스트 vs 네트워크)과 백신, 이어서 애플리케이션 제어와 그 우회, 파일 무결성 모니터링과 지속성 잡기, 그리고 PAW, Windows 권한과 특권, EDR, DLP, UEBA, 감사 정책(섹션 마무리).

## 꼭 기억할 것 { #must-know }

1. 방어는 한 겹으로 부족하다 — 공격 단계에 맞춰 방어 수단을 세우고, 모든 겹이 막는 동시에 기록하게 한다.
2. 모르는 건 지킬 수 없다 — 인벤토리(무엇이 설치됐나)와 네트워크 스캔(무엇이 드러났나)을 합친다.
3. 패치 결정은 인증 스캔으로 한다. 인증 없는 스캔의 "치명적 발견 없음"은 "안전"이 아니라 "알 수 없음"이다.
4. OS, 서버, *그리고* 클라이언트 소프트웨어를 패치하고, 긴급 패치 기준은 필요해지기 전에 합의한다. 재부팅 전까지는 "설치됨"이지 "패치됨"이 아니다.
5. 익스플로잇 방지는 특정 버그가 아니라 기법을 깨뜨린다. 그 차단 이벤트(Security-Mitigations, Defender 1121/1123/1126)는 SOC가 받는 가장 질 좋은 경보 중 하나다. 감사 모드는 아무것도 지켜 주지 않는다.

## 관련 레퍼런스 { #related }

- [엔드포인트 공격](../endpoint-attacks/index.md) — 같은 단계를 공격자 쪽에서
- [Windows 버전별 하드닝](../../../adversary/hardening-by-version.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
