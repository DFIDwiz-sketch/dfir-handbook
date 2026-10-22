---
title: 랩 실습
tags:
  - oscp
---

# 랩 실습 { #lab-walkthroughs }

홈 랩(`lab.local`)에서 직접 돌려 본 전체 예제입니다 — 공격을 처음부터 끝까지 실행하고, 방어자 쪽(Splunk / Zeek)에서 탐지까지 합니다. 공부 지도 페이지를 실습으로 바꾼 것이고, 블루팀 탐지 자료 역할도 해요.

!!! note "랩이지 시험이 아님"
    여기서는 내 랩 대상과 일부러 약하게 만든 계정을 써서 기법을 쉽게 재현하고 탐지합니다. 시험 자체는 수동이고 도움 없이 봐야 해요 — [방법론](../methodology.md), [시험 구조](../exam-format.md) 참고.

<div class="grid cards" markdown>

-   :material-key-chain:{ .lg .middle } **Kerberoasting**

    ---

    원리 → 취약한 SPN 계정 → Kali에서 roast·크랙 → Splunk에서 Windows 이벤트 4769로 탐지.

    [:octicons-arrow-right-24: Kerberoasting](kerberoasting.md)

</div>
