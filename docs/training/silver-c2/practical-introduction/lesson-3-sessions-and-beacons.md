---
title: "Lesson 3 — Sessions and Beacons"
---

# Lesson 3 — Sessions and Beacons { #lesson-3-sessions-and-beacons }

**Goal:** Explain when a task reaches an implant, select the intended target, and distinguish scheduled waiting from execution and network delay.

## Two ways to exchange work { #two-ways-to-exchange-work }

**Lecture:** A session supports interactive operation; a beacon checks in on a schedule to receive tasks.

Think of a **session** as a phone conversation: while the channel is working, requests can be delivered without waiting for a scheduled beacon check-in. “Interactive” does not mean zero latency; task execution and communication still take time.

Think of a **beacon** as a worker periodically checking an inbox. The operator can register a task on the server while the implant is waiting. The implant learns about that task when it next checks in, then performs it and returns results.

| Aspect | Session | Beacon |
|---|---|---|
| Interaction model | Interactive task exchange | Periodic task collection |
| Task delivery | Does not wait for the beacon schedule | May wait until the next check-in |
| Operator experience | Relatively immediate interaction | Request and result can be separated by waiting |
| Key state to inspect | Connection status | Check-in times and task status |

## A 30-second example { #a-30-second-example }

**Illustrative example:** Check-ins occur exactly every 30 seconds, with no jitter or network delay. These are teaching assumptions, not a claim about default settings.

```text
t=00s  Beacon checks in. No task is waiting.
t=10s  Operator registers task A on the server.
       Task A waits on the server.
t=30s  Beacon checks in and receives task A.
       Task execution and result return follow.
```

The task waited **20 seconds before delivery**. That does not mean execution took 20 seconds, and it does not promise that the result arrives at t=30s.

Real timing may include jitter, reconnect attempts, network delay, and the time needed to finish tasks. The official guide explains beacon tasking and check-in fields; the exact behavior and defaults depend on the version. [Official guide](https://github.com/BishopFox/sliver/wiki/Getting-Started/d3948bf50c19e85513258e8b69bb834639fb99f6)

## List first, then select { #list-first-then-select }

In the **Sliver console**, list sessions or beacons:

```text
sessions
```

```text
beacons
```

For beacons, inspect the ID, hostname, username, last check-in, and next check-in information. A record remaining in the list does not guarantee that the process is still alive.

Select an existing session:

```text
sessions --interact <Session_ID>
```

Or select an existing beacon:

```text
beacons --interact <Beacon_ID>
```

Replace the placeholder, including its angle brackets, with the real identifier from your list. **Selecting a beacon changes which target your console addresses; it does not convert the beacon into a session.** These selection options are defined in the [official session commands](https://github.com/BishopFox/sliver/blob/master/client/command/sessions/commands.go) and [official beacon commands](https://github.com/BishopFox/sliver/blob/master/client/command/beacons/commands.go).

Before assigning a task, verify the target hostname and execution user. The right command sent to the wrong machine is still a mistake.

## Three different sources of waiting { #three-different-sources-of-waiting }

| Period | Reason |
|---|---|
| Before task collection | Waiting for the next check-in |
| After task delivery | Performing the requested work |
| During communication | Network transfer and processing |

A delayed result does not automatically mean a network fault. First ask whether the task has reached its scheduled collection time.

## Corrections to common shortcuts { #corrections-to-common-shortcuts }

**Supplement:** The lecture contrasts continuous session traffic with quieter beacon traffic. Treat that as a simplification, not a guarantee.

- An interactive session need not transmit large amounts of data all the time.
- A beacon with frequent check-ins or large results can generate substantial traffic.
- A beacon is not automatically undetectable. Repeated connections and associated endpoint behavior can provide evidence.

Learn the **tasking and timing model** first. Traffic volume and detectability depend on additional factors.

## Review questions { #review-questions }

1. A beacon checks in every 60 seconds. A task is registered just after a check-in, and no response arrives within 10 seconds. Is that enough to diagnose a fault?
2. Does `beacons --interact <Beacon_ID>` turn the selected beacon into a session?

??? success "Answers and reasoning"
    **1. No. The main reason in this example is scheduled waiting.** The beacon may not collect the task until its next check-in. Network delay is a separate possible contributor, not the primary explanation required by this timeline.

    **2. No.** It selects a beacon for interaction. Selection and changing the communication mode are separate actions.

## Worked example: why the answer is 45 seconds { #worked-example-45-seconds }

Assume check-ins occur at t=0s, t=60s, and t=120s. The operator registers a task at t=15s. Ignore jitter and network delay.

```text
t=00s   Check-in
t=15s   Task registered
t=60s   Next check-in; task can be collected

Waiting time = 60 - 15 = 45 seconds
```

**45 seconds is the waiting time until task collection.** Execution and result-transfer time are additional. The result is not guaranteed to arrive after exactly 45 seconds.

[Continue to Lesson 4 — Payloads, stagers, and loaders](lesson-4-payloads-stagers-and-loaders.md)
