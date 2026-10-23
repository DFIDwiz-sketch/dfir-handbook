---
title: "3강 — Session과 Beacon"
---

# 3강 — Session과 Beacon { #lesson-3-sessions-and-beacons }

**학습 목표:** Implant가 언제 작업을 받는지 설명하고, 올바른 대상을 선택하며, 체크인 대기와 실행 시간·네트워크 지연을 구분합니다.

## 작업을 주고받는 두 가지 방식 { #two-ways-to-exchange-work }

**강좌:** Session은 대화형 작업을 지원하고, Beacon은 주기적으로 체크인하여 작업을 받습니다.

**Session**은 전화 통화에 비유할 수 있습니다. 통신이 정상이라면 Beacon의 정해진 체크인 시각을 기다리지 않고 요청을 전달할 수 있습니다. ‘대화형’이 지연 시간 0을 뜻하는 것은 아닙니다. 작업 실행과 통신에는 여전히 시간이 필요합니다.

**Beacon**은 주기적으로 업무함을 확인하는 작업자에 비유할 수 있습니다. Implant가 대기하는 동안 운영자가 서버에 작업을 등록할 수 있습니다. Implant는 다음 체크인에서 그 작업을 알게 되고, 작업을 수행한 뒤 결과를 돌려줍니다.

| 비교 항목 | Session | Beacon |
|---|---|---|
| 상호작용 방식 | 대화형 작업 교환 | 주기적인 작업 수신 |
| 작업 전달 | Beacon의 주기를 기다리지 않음 | 다음 체크인까지 기다릴 수 있음 |
| 운영자가 느끼는 반응 | 비교적 즉각적인 상호작용 | 요청과 결과 사이에 대기 가능 |
| 확인할 주요 상태 | 연결 상태 | 체크인 시각과 작업 상태 |

## 30초 주기의 예시 { #a-30-second-example }

**설명용 예시:** 지터와 네트워크 지연이 없고 정확히 30초마다 체크인한다고 가정합니다. 설명을 위한 조건이며 기본 설정을 뜻하지 않습니다.

```text
t=00s  Beacon checks in. No task is waiting.
t=10s  Operator registers task A on the server.
       Task A waits on the server.
t=30s  Beacon checks in and receives task A.
       Task execution and result return follow.
```

작업을 전달받기 전까지 **20초를 기다렸습니다.** 작업 실행에 20초가 걸렸다는 뜻도, 결과가 반드시 30초 시점에 도착한다는 뜻도 아닙니다.

실제 시간에는 지터, 재연결 시도, 네트워크 지연, 작업 완료에 걸리는 시간 등이 영향을 줄 수 있습니다. 공식 가이드에서 Beacon 작업 처리와 체크인 항목을 설명하지만, 구체적인 동작과 기본값은 버전에 따라 달라집니다. [공식 가이드](https://github.com/BishopFox/sliver/wiki/Getting-Started/d3948bf50c19e85513258e8b69bb834639fb99f6)

## 목록 확인 후 대상 선택 { #list-first-then-select }

**Sliver 콘솔**에서 Session 또는 Beacon 목록을 확인합니다.

```text
sessions
```

```text
beacons
```

Beacon은 ID, 호스트 이름, 사용자 이름, 마지막 체크인과 다음 체크인 정보를 살펴봅니다. 목록에 기록이 남아 있다는 사실만으로 현재 프로세스가 살아 있다고 보장할 수는 없습니다.

기존 Session을 선택하는 형식입니다.

```text
sessions --interact <Session_ID>
```

기존 Beacon을 선택하는 형식입니다.

```text
beacons --interact <Beacon_ID>
```

꺾쇠괄호를 포함한 자리표시자 전체를 목록의 실제 ID로 바꿉니다. **Beacon 선택은 콘솔에서 이후 작업을 보낼 대상을 지정하는 것이며, Beacon을 Session으로 전환하는 동작이 아닙니다.** 이 옵션은 [공식 Session 명령](https://github.com/BishopFox/sliver/blob/master/client/command/sessions/commands.go)과 [공식 Beacon 명령](https://github.com/BishopFox/sliver/blob/master/client/command/beacons/commands.go)에 정의되어 있습니다.

작업을 보내기 전에는 대상 호스트 이름과 실행 사용자를 확인합니다. 올바른 명령이라도 잘못된 컴퓨터에 보내면 실수입니다.

## 기다림을 만드는 세 가지 요인 { #three-different-sources-of-waiting }

| 구간 | 기다리는 이유 |
|---|---|
| 작업 수신 전 | 다음 체크인까지 대기 |
| 작업 전달 후 | 요청받은 작업 수행 |
| 통신 중 | 네트워크 전송과 처리 |

결과가 늦는다고 곧바로 네트워크 오류라고 판단하지 않습니다. 먼저 예정된 작업 수신 시각이 왔는지 확인해야 합니다.

## 단순화된 설명 보완 { #corrections-to-common-shortcuts }

**보충:** 강좌에서는 지속적인 Session 통신과 상대적으로 조용한 Beacon 통신을 대비합니다. 이를 항상 성립하는 보장으로 받아들이지는 마세요.

- Session이라고 항상 많은 데이터를 전송하는 것은 아닙니다.
- 체크인이 잦거나 결과가 크면 Beacon도 상당한 통신량을 만들 수 있습니다.
- Beacon이라고 탐지되지 않는 것은 아닙니다. 반복적인 연결과 대상 PC의 행동이 증거가 될 수 있습니다.

먼저 **작업 전달 방식과 시간 모델**을 이해하세요. 통신량과 탐지 가능성에는 다른 요소들도 영향을 줍니다.

## 확인 문제 { #review-questions }

1. 60초마다 체크인하는 Beacon에 체크인 직후 작업을 등록했습니다. 10초 동안 응답이 없다는 사실만으로 오류를 진단할 수 있을까요?
2. `beacons --interact <Beacon_ID>`를 실행하면 선택한 Beacon이 Session으로 바뀔까요?

??? success "정답과 해설"
    **1. 아니요. 이 예시의 핵심 이유는 정해진 체크인까지의 대기입니다.** Beacon은 다음 체크인에서야 작업을 받을 수 있습니다. 네트워크 지연은 별도의 가능한 요인이며, 이 시간표에서 먼저 짚어야 할 원인은 아닙니다.

    **2. 아니요.** 상호작용할 Beacon을 선택합니다. 대상 선택과 통신 모드 변경은 별개의 동작입니다.

## 계산 예제: 왜 45초일까? { #worked-example-45-seconds }

체크인이 0초, 60초, 120초에 발생한다고 가정합니다. 운영자는 15초에 작업을 등록합니다. 지터와 네트워크 지연은 무시합니다.

```text
t=00s   Check-in
t=15s   Task registered
t=60s   Next check-in; task can be collected

Waiting time = 60 - 15 = 45 seconds
```

**45초는 작업을 받기까지 기다리는 시간입니다.** 실행 시간과 결과 전송 시간은 별도로 더해집니다. 결과가 반드시 정확히 45초 후에 도착한다는 뜻은 아닙니다.

[4강 — Payload, Stager, Loader로 이동](lesson-4-payloads-stagers-and-loaders.md)
