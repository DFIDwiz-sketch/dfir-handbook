---
title: 학습 자료
tags:
  - learning
---

# 학습 자료 { #training-resources }

<div class="dfir-meta" markdown>
**분류:** 참고 목록 · **정리 기준:** [로드맵](roadmap.md) 기둥 · **최종 수정:** 2026-10-07
</div>

!!! abstract "요약"
    로드맵의 각 기둥에 맞는 랩, 강의, 책입니다. 무료 자료를 먼저 적었습니다. 가격과 내용은 바뀔 수 있으니 결제하기 전에 해당 사이트를 확인하세요.

## 네트워크 { #networks }

| 자료 | 유형 | 이유 |
|---|---|---|
| Wireshark sample captures & Malware-Traffic-Analysis.net exercises | 무료 pcap | 정답이 함께 있는 실제 감염 트래픽 |
| Zeek documentation & "Try Zeek" | 무료 | 이 사이트가 기반으로 삼는 로그를 배움 |
| Suricata documentation (rules chapter) | 무료 | 자신만의 규칙을 작성하고 테스트 |
| SANS FOR572 | 유료 강의 | 고급 네트워크 포렌식 |

## Windows 내부 구조와 Active Directory { #windows-internals-active-directory }

| 자료 | 유형 | 이유 |
|---|---|---|
| *Windows Internals*, 7th ed. (Yosifovich, Ionescu, Russinovich, Solomon) | 책 | 프로세스, 메모리, 보안에 대한 표준 참고서 |
| Sysinternals tools + Mark Russinovich talks | 무료 | 내부 동작을 실시간으로 관찰 |
| Microsoft Learn — Kerberos / NTLM / AD DS docs | 무료 | 프로토콜 동작에 대한 공식 자료 |
| Orange Cyberdefense / "AD mindmap", The Hacker Recipes | 무료 | 공격 경로를 그 밑바탕 메커니즘과 함께 설명 |
| GOAD (Game of Active Directory) | 무료 랩 | 연습용 취약한 멀티 도메인 AD 랩 |

## 프로그래밍 { #programming }

| 자료 | 유형 | 이유 |
|---|---|---|
| *Automate the Boring Stuff with Python* | 무료 온라인 책 | 빠르게 Python에 익숙해지기 |
| *Black Hat Python*, 2nd ed. | 책 | Python으로 만드는 보안 도구 |
| *The C Programming Language* (K&R) or *Effective C* | 책 | C 기초 |
| pwn.college | 무료 | Linux, C, 어셈블리, 저수준 보안을 단계별로 |

## 공격 (랩 전용) { #offensive-lab-only }

| 자료 | 유형 | 이유 |
|---|---|---|
| PortSwigger Web Security Academy | 무료, 랩 포함 | 최고의 무료 웹 보안 강의 |
| HTB Academy — Penetration Tester path (CPTS) | 유료 | 정찰 → 횡적 이동까지 전체 흐름 |
| Hack The Box / TryHackMe machines | 무료 + 유료 | 연습 대상 |
| Atomic Red Team | 무료 | 퍼플팀용으로 ATT&CK 기법별 작고 안전한 테스트 |

## 악성코드 분석과 리버스 엔지니어링 { #malware-analysis-reverse-engineering }

| 자료 | 유형 | 이유 |
|---|---|---|
| Malware Unicorn — RE101 / RE102 | 무료 워크숍 | Windows 악성코드, 어셈블리, 디버거, 정적/동적 분석 |
| *Practical Malware Analysis* (Sikorski & Honig) | 책 | 여전히 가장 체계적인 입문서 |
| Ghidra, x64dbg, PE-bear, FLARE-VM | 무료 도구 | 분석 환경 |
| OpenSecurityTraining2 (Architecture 1001: x86-64 assembly) | 무료 강의 | 어셈블리를 제대로 배우기 |

## DFIR, 헌팅, 탐지 엔지니어링 { #dfir-hunting-detection-engineering }

| 자료 | 유형 | 이유 |
|---|---|---|
| CyberDefenders, Blue Team Labs Online | 무료 + 유료 | 현실적인 DFIR / 헌팅 사례 |
| Splunk BOTS (v1–v3) | 무료 데이터셋 | 이 사이트의 쿼리에 쓰인 데이터 |
| SigmaHQ rules | 무료 | 보고 배울 수 있는 Detection-as-code 예시 |
| The DFIR Report | 무료 | 타임라인과 ATT&CK로 정리한 실제 침입 사례 |
| SANS FOR508 / FOR500 / FOR610 | 유료 강의 | 고급 IR, Windows 포렌식, 악성코드 리버싱 |

## 위협 인텔리전스 { #threat-intelligence }

| 자료 | 이유 |
|---|---|
| MITRE ATT&CK Groups (e.g. Lazarus G0032, Kimsuky G0094) | 에뮬레이션 계획을 세울 때 쓸 공격 절차 예시 |
| CISA / FBI joint advisories (#StopRansomware, DPRK advisories) | IOC와 완화 방안이 포함된 위협 행위자 TTP |
| Vendor blogs: Mandiant/Google, Microsoft Threat Intelligence, Unit 42, AhnLab ASEC, Genians | 위협 행위자에 대한 지속적인 보고; ASEC와 Genians는 한국을 겨냥한 활동을 깊이 있게 다룹니다 |

## 참고 자료 { #references }

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HTB Academy — Penetration Tester path](https://academy.hackthebox.com/path/preview/penetration-tester)
- [Malware Unicorn — RE101](https://malwareunicorn.org/workshops/re101)
- [pwn.college](https://pwn.college/dojos)
- [CyberDefenders](https://cyberdefenders.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [The DFIR Report](https://thedfirreport.com/)
- 관련 페이지: [로드맵](roadmap.md) · [퍼플팀 루프](purple-team-loop.md)
