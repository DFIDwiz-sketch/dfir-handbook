---
title: A Practical Introduction with Silver
---

# A Practical Introduction with Silver { #a-practical-introduction-with-silver }

**Sliver**를 사용한 C2의 원리를 처음부터 쉽게 설명하는 입문 강좌입니다. 페이지 제목은 요청한 메뉴 이름을 따르며, 실제 도구 이름은 **Sliver**입니다.

지금까지 학습한 범위인 **Beacon 대기 시간 45초 계산 예제**까지 다룹니다. 개념과 명령어, 확인 문제를 단계별로 쉽게 설명합니다. 실습 설명은 허가된 격리 환경을 전제로 합니다.

## 학습할 수 있는 강의 { #lessons-available }

| 강의 | 학습 내용 |
|---|---|
| [1강 — C2 기본 원리](lesson-1-c2-fundamentals.md) | C2의 필요성, Assumed Breach, 리버스 셸, 연결과 권한의 차이 |
| [2강 — 구성 요소와 명령어](lesson-2-components-and-commands.md) | Client·Server·Listener·Implant, 명령 입력 위치, Listener 시작과 상태 확인 |
| [3강 — Session과 Beacon](lesson-3-sessions-and-beacons.md) | 대화형·주기적 작업 전달, 대상 선택, 체크인 대기와 작업 실행 시간의 구분 |

한 번에 한 강의씩 읽습니다. 각 강의는 개념을 예제에 연결하고, 확인 문제와 펼쳐 볼 수 있는 해설로 마무리합니다.

## 노트의 표기 방식 { #how-to-read-the-notes }

| 표기 | 의미 |
|---|---|
| **강좌** | 강좌에서 다루는 핵심 주제와 명령 이름 |
| **보충** | 추가 설명, 정정, 공식 프로젝트 자료로 확인한 문법 |
| **설명용 예시** | 학습을 위한 주소·시간표·단순화한 출력 |

!!! note "명령어 예시 사용 안내"
    예시에는 설명용 실습 주소와 단순화한 출력을 사용합니다. 허가된 자신의 실습 환경에 맞게 조정하고, 사용 전에는 설치된 버전의 도움말과 대조하세요.

## 이후 학습 계획 { #planned-continuation }

이후에는 Payload·Stager·Loader 용어, 실습 통신, 탐지 원리, 권한과 내부 환경 파악, 네트워크 분리와 Pivoting, 방어 관점의 복습을 다룹니다. 학습 계획에 있는 주제이며, 아직 해당 강의 내용은 추가하지 않았습니다.

## 참고 자료 { #sources }

- [Sliver 공식 저장소](https://github.com/BishopFox/sliver)
- [Sliver 공식 문서](https://sliver.sh/)
- [Architecture — 공식 위키의 과거 리비전](https://github.com/BishopFox/sliver/wiki/Architecture/a1016f154840c2d9508e38a8201d887744ba5afb)
- [Getting Started — 공식 위키의 과거 리비전](https://github.com/BishopFox/sliver/wiki/Getting-Started/d3948bf50c19e85513258e8b69bb834639fb99f6)

과거 리비전은 문서 사이트로 옮겨진 설명을 확인하기 위한 자료입니다. 현재 명령 정의는 해당 강의에서 따로 연결합니다. 오래된 출력 예시를 현재 버전의 기본값으로 간주하지 마세요.
