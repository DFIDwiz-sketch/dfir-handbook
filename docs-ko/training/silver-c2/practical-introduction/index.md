---
title: A Practical Introduction with Silver
---

# A Practical Introduction with Silver { #a-practical-introduction-with-silver }

**Sliver**를 사용한 C2의 원리를 처음부터 쉽게 설명하는 입문 강좌입니다. 페이지 제목은 요청한 메뉴 이름을 따르며, 실제 도구 이름은 **Sliver**입니다.

**1~10강**에서 C2 기본 원리, 전달·실행 증거, 백신·EDR, 실효 권한, 네트워크 피벗팅을 다룹니다. 가상환경의 웹 서버 VM을 경유하여 내부 SSH 서버에 접근하는 포트포워딩·SOCKS5 명령을 구체적으로 설명합니다. 개념과 확인 문제 해설을 단계별로 쉽게 풀며, 실습은 허가된 격리 환경을 전제로 합니다.

## 학습할 수 있는 강의 { #lessons-available }

| 강의 | 학습 내용 |
|---|---|
| [1강 — C2 기본 원리](lesson-1-c2-fundamentals.md) | C2의 필요성, Assumed Breach, 리버스 셸, 연결과 권한의 차이 |
| [2강 — 구성 요소와 명령어](lesson-2-components-and-commands.md) | Client·Server·Listener·Implant, 명령 입력 위치, Listener 시작과 상태 확인 |
| [3강 — Session과 Beacon](lesson-3-sessions-and-beacons.md) | 대화형·주기적 작업 전달, 대상 선택, 체크인 대기와 작업 실행 시간의 구분 |
| [4강 — Payload, Stager, Loader](lesson-4-payloads-stagers-and-loaders.md) | Staged·Stageless 전달, Loader의 역할, 통신 방식과의 구분 |
| [5강 — 생성 명령 읽기](lesson-5-reading-generation-commands.md) | 대상 OS·CPU, 연락 주소, 시간 설정, 저장 위치 |
| [6강 — 전달·실행·연결 증거](lesson-6-delivery-execution-and-evidence.md) | 파일 전달, HTTP 200의 한계, SHA-256 비교, 체크인과 작업 결과 |
| [7강 — 백신·EDR과 탐지 증거](lesson-7-antivirus-edr-and-detection-evidence.md) | 정적·실행 중 관찰, Defender 1116·1117, 탐지와 조치의 구분 |
| [8강 — 계정·토큰·접근 권한](lesson-8-identity-tokens-and-permissions.md) | 계정 소속과 프로세스 승격의 차이, 자원별 권한, 권한 문제의 자세한 해설 |
| [9강 — 포트포워딩과 SOCKS5](lesson-9-port-forwarding-and-socks.md) | 도달 가능성·인증·인가, 고정 포워딩과 프록시 클라이언트의 차이, HTTP 예제와 다이어그램 |
| [10강 — 웹 서버를 경유한 내부 SSH 가상환경 실습](lesson-10-web-server-to-internal-ssh-lab.md) | VM 3대와 네트워크 2개, 두 방식의 구체적인 SSH 명령, 호스트 키, 문제 진단, 방어 관찰, 정리 |

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

8~10강에 계정·권한, 네트워크 분리, 포트포워딩·SOCKS5와 SSH 실습을 추가했습니다. 이후 강의는 이 기초를 바탕으로 내부 환경 조사와 방어 관점의 복습을 이어갑니다.

## 참고 자료 { #sources }

- [Sliver 공식 저장소](https://github.com/BishopFox/sliver)
- [Sliver 공식 문서](https://sliver.sh/)
- [Architecture — 공식 위키의 과거 리비전](https://github.com/BishopFox/sliver/wiki/Architecture/a1016f154840c2d9508e38a8201d887744ba5afb)
- [Getting Started — 공식 위키의 과거 리비전](https://github.com/BishopFox/sliver/wiki/Getting-Started/d3948bf50c19e85513258e8b69bb834639fb99f6)

과거 리비전은 문서 사이트로 옮겨진 설명을 확인하기 위한 자료입니다. 현재 명령 정의는 해당 강의에서 따로 연결합니다. 오래된 출력 예시를 현재 버전의 기본값으로 간주하지 마세요.
