---
title: A Practical Introduction with Silver
---

# A Practical Introduction with Silver { #a-practical-introduction-with-silver }

A beginner-friendly introduction to command and control using **Sliver**. The page title follows the requested navigation wording; the actual tool is **Sliver**.

Lessons **1–7** cover C2 fundamentals through file delivery, execution checks, and antivirus/EDR evidence. Concepts, commands, and review questions are explained step by step. Exercises assume an authorized, isolated lab.

## Lessons available { #lessons-available }

| Lesson | What you will learn |
|---|---|
| [1 — C2 fundamentals](lesson-1-c2-fundamentals.md) | Why C2 is useful, assumed breach, reverse shells, and the difference between connectivity and privilege |
| [2 — Components and commands](lesson-2-components-and-commands.md) | Client, Server, Listener, Implant; where commands run; starting and inspecting a listener |
| [3 — Sessions and beacons](lesson-3-sessions-and-beacons.md) | Interactive versus scheduled tasking, selecting a target, and separating check-in delay from execution time |
| [4 — Payloads, stagers, and loaders](lesson-4-payloads-stagers-and-loaders.md) | Staged versus stageless delivery, loader roles, and independent communication choices |
| [5 — Reading a generation command](lesson-5-reading-generation-commands.md) | Target OS, CPU architecture, callback address, timing, and output location |
| [6 — Delivery, execution, and connection evidence](lesson-6-delivery-execution-and-evidence.md) | File transfer, HTTP 200 limits, SHA-256 comparison, check-ins, and task results |
| [7 — Antivirus, EDR, and detection evidence](lesson-7-antivirus-edr-and-detection-evidence.md) | Static and runtime observations, Defender 1116/1117, and detection versus action |

Read one lesson at a time. Each lesson connects a concept to an example and ends with questions and expandable answers.

## How to read the notes { #how-to-read-the-notes }

| Label | Meaning |
|---|---|
| **Lecture** | Core topics and command names covered in the course |
| **Supplement** | Added explanation, a correction, or syntax checked against official project sources |
| **Illustrative example** | A teaching address, timeline, or simplified output |

!!! note "Using command examples"
    Examples use illustrative lab addresses and simplified output. Adapt them to your own authorized lab and check your installed version's help before using them.

## Planned continuation { #planned-continuation }

Later lessons will cover permissions and internal discovery, network segmentation and pivoting, and defensive review. These are roadmap topics; their lessons have not been added yet.

## Sources { #sources }

- [Sliver official repository](https://github.com/BishopFox/sliver)
- [Sliver documentation](https://sliver.sh/)
- [Architecture — official historical wiki revision](https://github.com/BishopFox/sliver/wiki/Architecture/a1016f154840c2d9508e38a8201d887744ba5afb)
- [Getting Started — official historical wiki revision](https://github.com/BishopFox/sliver/wiki/Getting-Started/d3948bf50c19e85513258e8b69bb834639fb99f6)

The historical revisions preserve explanations that moved to the documentation site. Current command definitions are linked in the relevant lessons; do not infer current defaults from old example output.
