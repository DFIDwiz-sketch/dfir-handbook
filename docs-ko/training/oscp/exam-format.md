---
title: 시험 구조와 점수
tags:
  - oscp
---

# 시험 구조와 점수 { #exam-format-scoring }

<div class="dfir-meta" markdown>
**섹션:** OSCP+ · **출처:** OffSec OSCP+ Exam Guide · **최종 수정:** 2026-10-22
</div>

!!! abstract "한 문장 요약"
    실습 23시간 45분, 그다음 24시간 안에 리포트 제출. 100점 만점에 70점 합격이고, 2024년 11월 1일부터 보너스 점수는 없습니다.

!!! info "뼈대 페이지"
    지금은 구조만 있습니다 — 아래 제목이 계획이에요. 공부하면서 각 부분을 채워 나가세요.

## 시험 한눈에 보기 { #at-a-glance }

| 구분 | 머신 | 점수 |
|---|---|---|
| Standalone | 3대 | 대당 20점 — 초기 침투 10점(`local.txt`) + 권한 상승 10점(`proof.txt`) |
| Active Directory 세트 | 3대 (assumed breach: 아이디 + 비밀번호 제공) | 10(#1) + 10(#2) + 20(#3, DC) = 40점 |
| **합격 점수** | | **70 / 100** |

## 합격 점수 조합 { #passing-combinations }

공식 가이드 기준:

- AD 40 + `local.txt` 3개
- AD 40 + `local.txt` 2개 + `proof.txt` 1개
- AD 20 + `local.txt` 3개 + `proof.txt` 2개
- AD 10 + standalone 3대 완전 장악

## 2024년 11월 변경 사항 { #nov-2024-changes }

- assumed breach 방식의 AD 세트, 세트 안에서 부분 점수 인정
- 보너스 점수 폐지
- 버퍼 오버플로우가 더 이상 고정 standalone 문제가 아님
- OSCP(평생) + OSCP+(3년, 갱신 가능)

## 꼭 기억할 시험 규칙 { #exam-rules }

- AI / LLM 사용 금지 — 시험 중과 리포트 작성 단계 모두
- Metasploit은 한 대에만
- 제한된 도구와 기법 — 예약 전에 공식 가이드 다시 읽기
- 감독: 시험 시간 내내 웹캠과 화면 공유

## 점수 전략 { #scoring-strategy }

- 어떤 조합을 목표로 할지, AD 세트가 막혔을 때의 대안

## 관련 페이지 { #related-pages }

- [시험 당일 전략](exam-day.md) · [리포트](reporting.md) · [Active Directory](active-directory.md)

## 참고 자료 { #references }

- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)
- [OffSec — OSCP Exam with AD Preparation](https://help.offsec.com/hc/en-us/articles/4547917816468-Offensive-Security-OSCP-Exam-with-AD-Preparation)
