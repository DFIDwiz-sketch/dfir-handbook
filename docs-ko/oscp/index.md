---
title: OSCP+
tags:
  - oscp
---

# OSCP+ { #oscp }

<div class="dfir-meta" markdown>
**시험:** OffSec PEN-200 → OSCP / OSCP+ · **상태:** 준비 중 · **최종 수정:** 2026-10-22
</div>

!!! abstract "이 섹션은"
    OSCP+ 시험(PEN-200) 공부 허브입니다. 구성은 2025–2026년 합격·불합격 후기들이 공통으로 말하는 내용을 따릅니다. **Active Directory 세트를 확실히 잡고, standalone 머신은 탄탄한 기본기로 버틴다.** 이 핸드북에 이미 페이지가 있는 기법은 반복해서 쓰지 않고 링크로 연결합니다. 그래서 여기의 공격자 관점과 공격 기법 / Windows / 네트워크 섹션의 탐지 관점이 서로 이어집니다.

## 1. 시험 알기 { #1-know-the-exam }

<div class="grid cards" markdown>

-   :material-scale-balance:{ .lg .middle } **시험 구조와 점수**

    ---

    standalone 3대(60점) + AD 세트(40점), 70점 합격, 보너스 점수 없음. 2024년 11월 변경 사항과 합격 점수 조합.

    [:octicons-arrow-right-24: 시험 구조와 점수](exam-format.md)

</div>

## 2. 공부 항목 { #2-study-areas }

<div class="grid cards" markdown>

-   :material-domain:{ .lg .middle } **Active Directory**

    ---

    최우선. assumed breach 시작, 정보 수집, Kerberos 공격, 수평 이동, 도메인 장악.

    [:octicons-arrow-right-24: Active Directory](active-directory.md)

-   :material-tunnel:{ .lg .middle } **피벗팅과 터널링**

    ---

    가장 많이 막히는 곳: 내부 서브넷 접근. Ligolo-ng, Chisel, SSH 포워딩, proxychains.

    [:octicons-arrow-right-24: 피벗팅과 터널링](pivoting.md)

-   :material-linux:{ .lg .middle } **Linux 권한 상승**

    ---

    sudo, SUID, capabilities, cron, 시스템 안의 크리덴셜, 커널 익스플로잇.

    [:octicons-arrow-right-24: Linux 권한 상승](privesc-linux.md)

-   :material-microsoft-windows:{ .lg .middle } **Windows 권한 상승**

    ---

    토큰 권한과 potato, 서비스, 예약 작업, AlwaysInstallElevated, 저장된 크리덴셜.

    [:octicons-arrow-right-24: Windows 권한 상승](privesc-windows.md)

-   :material-web:{ .lg .middle } **웹과 초기 침투**

    ---

    수동 SQLi, 업로드 우회, LFI → RCE, SSRF, CMS, 공개 익스플로잇 수정, 클라이언트 사이드.

    [:octicons-arrow-right-24: 웹과 초기 침투](web-initial-access.md)

-   :material-format-list-checks:{ .lg .middle } **방법론과 습관**

    ---

    enumeration 체크리스트, 단순한 것부터, rabbit hole, Metasploit 한 대 제한, 노트.

    [:octicons-arrow-right-24: 방법론과 습관](methodology.md)

-   :material-file-document-edit:{ .lg .middle } **리포트**

    ---

    인정되는 증거 스크린샷, 시험 중 노트 구조, 템플릿, 모의 리포트.

    [:octicons-arrow-right-24: 리포트](reporting.md)

</div>

## 3. 실습 { #3-practice }

<div class="grid cards" markdown>

-   :material-flask:{ .lg .middle } **실습 랩과 머신 리스트**

    ---

    Challenge Labs(OSCP A/B/C), Proving Grounds Practice, LainKusanagi 리스트, AD 드릴, 모의 시험, 진행 기록.

    [:octicons-arrow-right-24: 실습 랩](practice-labs.md)

</div>

## 4. 시험 당일과 계획 { #4-exam-day-and-plan }

<div class="grid cards" markdown>

-   :material-timer-sand:{ .lg .middle } **시험 당일 전략**

    ---

    예약, 준비, 공격 순서(standalone 1대 → AD 세트), 휴식, 점수 기록표.

    [:octicons-arrow-right-24: 시험 당일 전략](exam-day.md)

-   :material-calendar-check:{ .lg .middle } **나의 공부 계획**

    ---

    집중 항목, 주간 계획, 약점 기록, 모의 시험 결과.

    [:octicons-arrow-right-24: 나의 공부 계획](study-plan.md)

</div>

## 준비 상태 체크리스트 { #readiness-checklist }

- [ ] PEN-200 모듈 완료 (*Assembling the Pieces* 포함)
- [ ] Challenge Labs OSCP A, B, C 완료 — 플래그만이 아니라 이해까지
- [ ] LainKusanagi 리스트의 Proving Grounds Practice 머신 → [실습 랩](practice-labs.md)
- [ ] 노트 없이 assumed breach 크리덴셜에서 DC까지 → [Active Directory](active-directory.md)
- [ ] 외워서 Ligolo-ng로 내부 서브넷 피벗 → [피벗팅](pivoting.md)
- [ ] 시간 재고 모의 시험 + 전체 리포트, 최소 3번 → [리포트](reporting.md)
- [ ] 시험 예약 (슬롯이 적으니 한 달 전쯤) → [시험 당일](exam-day.md)

## 참고 자료 { #references }

- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)
- [OffSec — OSCP Exam with AD Preparation](https://help.offsec.com/hc/en-us/articles/4547917816468-Offensive-Security-OSCP-Exam-with-AD-Preparation)
- [netguardia — OSCP in 2026: is the new format harder?](https://netguardia.com/learning-development/certifications/oscp-in-2026-is-it-still-the-gold-standard-and-is-the-new-format-harder/)
- [Aryan — OSCP+ Exam 2026: strategy, reporting, tips](https://medium.com/@contact.aryan.here/oscp-exam-2026-strategy-reporting-tips-and-lessons-484363f29f6c)
- [Jess L — Passing OSCP+ on the 3rd attempt (2026)](https://medium.com/@onyuyu.loke/passing-oscp-at-3rd-attempts-journey-and-tips-sharing-2026-afe6d669b221)
- [The Husky Hacker — OSCP notes, lock-in and tips (2026년 9월)](https://medium.com/@TheHuskyHacker/oscp-notes-lock-in-and-tips-abc6f8895e60)

!!! info "여기에 페이지 추가하기"
    ```bash
    python new.py oscp/<name> -t concept
    ```
    새 페이지는 메뉴 맨 끝에 붙습니다 (`.pages` 의 `...`). **공부 항목** 그룹 안에 넣으려면 `docs/oscp/.pages` 와 `docs-ko/oscp/.pages` 양쪽의 그 그룹에 파일 이름을 추가하세요.
