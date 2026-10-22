---
title: 실습 랩과 머신 리스트
tags:
  - oscp
---

# 실습 랩과 머신 리스트 { #practice-labs-machine-lists }

<div class="dfir-meta" markdown>
**섹션:** OSCP+ · **최종 수정:** 2026-10-23
</div>

!!! abstract "한 문장 요약"
    PEN-200 Challenge Labs 먼저, 그다음 OffSec이 직접 만든 Proving Grounds 머신 — 시험 스타일에 가장 가까운 박스 — 을 최신 머신 리스트로 풀고, 마지막에 시간 재는 모의 시험.

!!! note "이 페이지 구성"
    연습 계획과 채워 넣을 진행 기록입니다. 2025–2026 후기의 일관된 조언: 머신 수도 중요하지만 각각을 이해해야만 의미가 있어요 — 플래그만 쫓지 마세요.

## 연습 순서 { #order }

1. **PEN-200 과정 + Challenge Labs** — 공식 자료로 방법론 쌓기.
2. **Proving Grounds Practice** — 시험 머신에 가장 가까움(OffSec 제작, 은퇴한 시험 랩이 여기 있음).
3. **최신 머신 리스트**(LainKusanagi)를 PG / HTB에 걸쳐 — 폭과 패턴 인식.
4. **AD 전용 드릴** — AD 세트가 사람들이 떨어지는 곳이라서요.
5. **시간 재는 모의 시험** — 리포트까지 포함한 전체 리허설.

## PEN-200과 Challenge Labs { #challenge-labs }

- *Assembling the Pieces* 까지 과정 모듈을 진행하세요.
- **OSCP A, B, C** 는 assumed-breach 모델의 전체 AD 세트가 있는 세 Challenge Lab으로, 가장 좋은 시험 대리물입니다. 풀고 100% 이해하세요; 편해지면 준비가 거의 된 거예요.
- Secura, Medtech, Relia도 좋은 추가 멀티 머신 랩입니다.

## Proving Grounds Practice { #proving-grounds }

- 유료($19/월 정도), Windows·Linux 박스와 은퇴한 OSCP 시험 랩 포함.
- OffSec이 만들어서 OffSec 스타일과 rabbit-hole 설계를 훈련시켜 줍니다 — HTB보다 시험에 더 가깝다는 평이 많아요.
- 합격자 대부분은 전체 준비에서 대략 **40~70대** 를 풀었다고 합니다.

## 머신 리스트 { #machine-lists }

- **LainKusanagi OSCP-like 리스트** — 요즘 대세; PEN-200/OSCP 범위 밖 박스를 걸러내고 계속 업데이트됩니다. 커뮤니티 포크가 난이도 등급과 학습 트래커를 추가해 뒀어요.
- **TJ Null 리스트** — 오래된 터줏대감이지만 현재 시험 기준으로는 다소 옛날 것으로 봅니다.
- 리스트는 체크하듯 서두르지 말고 뼈대로 쓰세요 — 이해한 박스 하나가 워크스루 켜고 깬 세 개보다 낫습니다.

## AD 연습 { #ad-practice }

AD 세트는 40점이자 1위 실패 영역이니, 따로 집중 훈련하세요:

- Challenge Labs OSCP A/B/C (assumed-breach AD).
- Kerberos, 수평 이동, 피벗을 위한 HTB / 전용 AD 룸.
- Hacker Blueprint 같은 AD 집중 드릴이 합격 후기에 자주 나옵니다.

AD 기법의 공부 쪽: [Active Directory](active-directory.md).

## 모의 시험 { #mock-exams }

실전처럼 다루세요 — 해킹이 아닌 부분을 연습하는 자리예요:

- standalone 3대 + AD 세트 1개, 직접 고르고, 24시간 창에서.
- **끝나면 전체 리포트 작성**, 실제 요구 사항대로 → [리포트](reporting.md). 최소 세 번 하세요; 시험 날엔 리포트가 거의 기계적인 작업이 됩니다.
- 로지스틱스도 리허설: 시작 시간, 휴식, 증거 스크린샷, 점수 기록.

## 워크스루 — 쓰는 법 { #walkthroughs }

- 박스를 **끝까지** 먼저 시도하고, 내 아이디어를 정말 소진한 뒤에만 워크스루를 엽니다.
- 깼더라도 공식 writeup / IppSec 영상을 보세요 — 답이 아니라 방법론을 얻으려고요.
- `ippsec.rocks` 는 기법/키워드로 IppSec 영상을 검색해 줘, 어떤 취약점 유형에 막혔을 때 유용합니다.

## 진행 기록 { #progress-log }

| 머신 | 플랫폼 | OS | 완료 | 배운 점 |
|---|---|---|---|---|
|  |  |  |  |  |

## 관련 페이지 { #related-pages }

- [나의 공부 계획](study-plan.md) · [Active Directory](active-directory.md) · [학습 자료](../../learning/resources.md)

## 참고 자료 { #references }

- [LainKusanagi — list of OSCP-like machines](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt)
- [OffSec — Proving Grounds](https://www.offsec.com/products/proving-grounds/)
- [ippsec.rocks](https://ippsec.rocks/)
