---
title: Lab Walkthroughs
tags:
  - oscp
---

# Lab Walkthroughs

Full worked examples run in my home lab (`lab.local`) — the attack executed end to end, then detected from the defender side (Splunk / Zeek). They turn the study-map pages into hands-on practice, and double as blue-team detection content.

!!! note "Lab, not the exam"
    These use my own lab targets and deliberately weak accounts so the technique is easy to reproduce and to detect. The exam itself is manual and unassisted — see [Methodology](../methodology.md) and [Exam format](../exam-format.md).

<div class="grid cards" markdown>

-   :material-key-chain:{ .lg .middle } **Kerberoasting**

    ---

    Principle → vulnerable SPN account → roast & crack from Kali → detect via Windows event 4769 in Splunk.

    [:octicons-arrow-right-24: Kerberoasting](kerberoasting.md)

</div>
