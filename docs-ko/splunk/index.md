---
title: Splunk
---

# Splunk { #splunk }

침해사고 대응과 위협 헌팅을 위한 SPL — 문법 노트, 재사용할 수 있는 검색, 헌팅 패턴, BOTSv3 연습 방법. 여기 있는 모든 쿼리는 인덱스와 소스타입을 명시합니다. 자기 환경에 맞게 바꿔 쓰세요.

## 질문 → 페이지 { #question-page }

| 질문 | 페이지 |
|---|---|
| **이 명령은 무엇을 하나? SPL은 어떻게 쓰나?** | [SPL 치트시트](spl-cheatsheet.md) |
| **이 인스턴스에 어떤 데이터가 있나? 어떤 필드? 어떤 시간 범위?** | [데이터 탐색과 시간](data-discovery.md) |
| **필요한 필드가 없다 / XML이 파싱되지 않았다** | [rex, 필드 추출, eval](rex-and-fields.md) |
| **누가 로그온했고, 무엇이 실행됐고, 어떻게 지속성을 남겼고, 횡적 이동을 했나?** | [질문별 보안 검색](security-searches.md) |
| **경보가 없었다 — 이상한 것을 어떻게 찾나?** | [헌팅 패턴](hunting-patterns.md) |
| **BOTSv3 (또는 어떤 CTF 데이터셋이든) 제대로 풀려면?** | [BOTSv3 조사 워크플로](botsv3-workflow.md) |
| **Splunk에서 비코닝 / C2** | [비코닝과 C2](../network/beaconing-c2.md) (네트워크 섹션, `streamstats` 설명) |
| **이벤트 ID 4xxx는 무슨 뜻인가?** | [Windows 이벤트 ID](../basics/windows-event-ids.md) |

## 페이지 { #pages }

<div class="grid cards" markdown>

-   **[SPL 치트시트](spl-cheatsheet.md)** — 검색 구조, 필터링, 예시가 달린 명령 40개, 재사용 패턴, 속도 규칙
-   **[데이터 탐색과 시간](data-discovery.md)** — 인덱스, 소스타입, `fieldsummary`, CIM 이름, 시간 수식어, 로그 공백 탐지
-   **[rex, 필드, eval](rex-and-fields.md)** — 정규식 추출, `spath`, `eval` 함수, 룩업, 영구 추출로 승격
-   **[보안 검색](security-searches.md)** — 로그온, 실행, 지속성, 횡적 이동, 네트워크, 변조, 호스트 타임라인
-   **[헌팅 패턴](hunting-patterns.md)** — 희소, 신규, 급증, 규칙성, 긴 꼬리, 동료 대비 이상치, 순서, 떨어뜨리고 실행, 점수화
-   **[BOTSv3 워크플로](botsv3-workflow.md)** — 데이터 지도, 피벗 키, 조사 루프, 첫 확인용 검색 (스포일러 없음)

</div>

## 이 핸드북의 SPL 규칙 { #house-rules-for-spl-in-this-handbook }

쿼리는 붙여 넣어 쓸 수 있게 작성했습니다: `index=`와 `sourcetype=`이 항상 있고, 블록 아래에 각 절을 설명하며, Windows 이벤트 코드는 처음 나올 때 의미를 적고, 필드 이름은 Splunk Windows/Sysmon 애드온이 만드는 이름(`Account_Name`, `Logon_Type`, `Image`, `CommandLine`)을 따르고 중요한 곳에는 CIM 대응 이름을 적었습니다.

!!! info "이 섹션에 페이지 추가하기"
    `python new.py splunk/<name> -t concept` (시나리오 정리는 `-t playbook`) — 사이드바에 자동으로 나타납니다.
