---
title: 블루팀
tags:
  - blue-team
---

# 블루팀 { #blue-team }

방어자 쪽 내용을 모은 탭입니다. 실제 **패킷·로그 분석 사례**, 검색과 헌팅을 위한 **Splunk**, 대응 절차인 **플레이북**이 들어 있습니다. 증거가 *무엇인지*는 [네트워크](../network/index.md), [Windows](../windows/index.md), [공격 기법](../adversary/index.md) 같은 레퍼런스 섹션에서 설명합니다. 이 탭은 그 지식을 실제 사례에 *어떻게 쓰는지* 보여 줍니다.

<div class="grid cards" markdown>

-   :material-file-search-outline:{ .lg .middle } **분석 사례**

    ---

    PCAP과 로그 분석을 처음부터 보고서까지 단계별로 정리한 풀이입니다. 모든 명령, 실제 출력, 그 출력이 왜 답인지를 적었습니다.

    [:octicons-arrow-right-24: 분석 사례](investigations/index.md)

-   :material-magnify-scan:{ .lg .middle } **Splunk**

    ---

    SPL 치트시트, 데이터 탐색, 필드 추출, 질문별 보안 검색, 헌팅 패턴, BOTSv3 진행 방법.

    [:octicons-arrow-right-24: Splunk](splunk/index.md)

-   :material-clipboard-list:{ .lg .middle } **플레이북**

    ---

    반복 가능한 대응 절차: 랜섬웨어, 감염 PC, 계정 탈취, 내부 확산, 데이터 유출, 웹셸.

    [:octicons-arrow-right-24: 플레이북](playbooks/index.md)

</div>

## 세 가지의 관계 { #how-they-fit }

```mermaid
flowchart LR
    A["분석 사례<br/>증거로 무슨 일이 있었는지"] --> B["Splunk<br/>같은 패턴을 전체에서 찾기"]
    B --> C["플레이북<br/>봉쇄, 제거, 복구"]
    C -. 교훈 .-> A
```

분석 사례에서 패턴을 찾습니다. 예를 들면 "Word 문서를 받은 뒤 `/forum.php`로 2분마다 POST"입니다. Splunk에서는 그 패턴을 조직 전체에 돌릴 수 있는 검색으로 만듭니다. 플레이북은 걸린 호스트마다 무엇을 할지 알려 줍니다.

!!! info "페이지 추가하기"
    새 분석 사례는 `python new.py blueteam/investigations/<이름> -t playbook`, Splunk 페이지는 `python new.py blueteam/splunk/<이름>`으로 만듭니다. 사이드바에 자동으로 나타납니다.
