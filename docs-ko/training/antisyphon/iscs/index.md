---
title: Information Security Core Skills
---

# Information Security Core Skills { #iscs }

<div class="dfir-meta" markdown>
**강사:** John Strand (Black Hills Information Security) · **제공:** [Antisyphon Training](https://www.antisyphontraining.com/) · **형식:** Pay-What-You-Can, 4일 · 매일 마지막 30분 AMA
</div>

!!! abstract "이 과정은 무엇인가"
    "기초를 다지는(bootstrap)" 보안 과정입니다. BHIS가 1년에 650건 넘는 보안 진단을 하며 **"무엇이 실제로 우리를 막았는가"**를 추적한 결과, 매번 같은 10가지 통제로 모였습니다. 이 과정은 그 10가지로 구성되고, 모든 내용은 MITRE ATT&CK에 매핑됩니다. 원칙은 하나 — 공격자를 막는 데 직접 도움이 되지 않는 내용은 넣지 않는다. 곳곳에서 AI를 보안에 어떻게 활용하는지도 함께 보여 줍니다.

## 다루는 통제 { #topics }

1. 애플리케이션 허용 목록 (Application Allow Listing)
2. 패스워드 통제
3. 나가는 트래픽 분석 (Egress Traffic Analysis)
4. UEBA (AI·머신러닝 기반 사용자 행위 분석)
5. 고급 엔드포인트 보호 (EDR)
6. 로깅
7. 호스트 방화벽
8. 인터넷 허용 목록
9. 취약점 관리
10. 액티브 디렉터리 하드닝
11. 클라우드 (일부 추가)

백업·복구는 "당연히 해야 하는 것"이라 따로 다루지 않습니다. Windows/Linux 기초, TCP/IP, 암호학 같은 기초는 같은 시리즈의 **SOC Core Skills**(YouTube)에서 다룹니다.

## 일자별 노트 { #day-by-day }

<div class="grid cards" markdown>

-   **[Day 1 — 허용 목록과 패스워드 공격](day-1.md)**

    ---

    컴플라이언스(CIS 매핑), 애플리케이션 허용 목록과 AppLocker, 백신 우회 원리(고스트 라이팅·LOLBins), 패스워드 스프레이, MFA 우회, 커버로스팅, 네트워크 인증 가로채기, 패스워드 크래킹(Hashcat).

-   **[Day 2 — 나가는 트래픽 분석](day-2.md)** *(진행 중)*

    ---

    Egress 트래픽 분석, NetFlow, 방화벽 로그 수동 분석, AI로 로그 분석, Zeek, 비컨(beaconing)·지터·롱 커넥션, RITA. (AC-Hunter·ASN·UEBA·Sysmon은 이어서 추가)

</div>

!!! info "3~4일차는 추후 추가"
    3일차(EDR·Atomic Red Team·BloodHound·Pass-the-Hash), 4일차(인터넷 허용 목록·취약점 관리·웹 테스트·Ping Castle)는 순차적으로 정리해 추가합니다.
