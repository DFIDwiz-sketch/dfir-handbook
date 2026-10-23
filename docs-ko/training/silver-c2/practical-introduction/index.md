---
title: A Practical Introduction with Silver
---

# A Practical Introduction with Silver { #a-practical-introduction-with-silver }

제공된 **RTVcron — C2 for Red Team: A Practical Introduction with Sliver** 자동 생성 자막을 바탕으로 작성한 학습 노트입니다. 페이지 제목은 요청한 메뉴 이름을 따르며, 실제 도구 이름은 **Sliver**입니다.

지금까지 학습한 범위인 **Beacon 대기 시간 45초 계산 예제**까지 다룹니다. 자막을 그대로 옮긴 문서나 공식 강의 자료가 아니라, 내용을 쉽게 설명하고 보충한 독립적인 학습 노트입니다. 실습 설명은 허가된 격리 환경을 전제로 합니다.

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
| **강좌** | 제공된 자막에서 확인되는 주제 또는 명령 이름 |
| **보충** | 추가 설명, 정정, 공식 프로젝트 자료로 확인한 문법 |
| **설명용 예시** | 학습을 위한 주소·시간표·단순화한 출력이며, 영상 화면을 복원한 것이 아님 |

!!! note "자동 생성 자막의 한계"
    강사가 화면에 보이는 명령을 소리 내어 읽지 않고 가리키는 경우가 있습니다. 자막에는 모든 옵션·주소·출력이 남아 있지 않습니다. 보충한 명령은 예시로 표시하며, 강사가 입력한 내용을 그대로 재현했다고 주장하지 않습니다. 실제 사용 전에는 설치된 버전의 도움말과 대조하세요.

## 이후 학습 계획 { #planned-continuation }

이후에는 Payload·Stager·Loader 용어, 실습 통신, 탐지 원리, 권한과 내부 환경 파악, 네트워크 분리와 Pivoting, 방어 관점의 복습을 다룹니다. 학습 계획에 있는 주제이며, 아직 해당 강의 내용은 추가하지 않았습니다.

## 참고 자료 { #sources }

- 제공된 자막 파일: *[English (auto-generated)] RTVcron C2 for Red Team A Practical Introduction with Sliver [DownSub.com].txt*. 자막 원문과 로컬 파일 경로는 게시하지 않습니다.
- [Sliver 공식 저장소](https://github.com/BishopFox/sliver)
- [Sliver 공식 문서](https://sliver.sh/)
- [Architecture — 공식 위키의 과거 리비전](https://github.com/BishopFox/sliver/wiki/Architecture/a1016f154840c2d9508e38a8201d887744ba5afb)
- [Getting Started — 공식 위키의 과거 리비전](https://github.com/BishopFox/sliver/wiki/Getting-Started/d3948bf50c19e85513258e8b69bb834639fb99f6)

과거 리비전은 문서 사이트로 옮겨진 설명을 확인하기 위한 자료입니다. 현재 명령 정의는 해당 강의에서 따로 연결합니다. 오래된 출력 예시를 현재 버전의 기본값으로 간주하지 마세요.
