---
title: A Practical Introduction with Silver
---

# A Practical Introduction with Silver { #a-practical-introduction-with-silver }

A beginner-friendly introduction to command and control using **Sliver**. The page title follows the requested navigation wording; the actual tool is **Sliver**.

Lessons **1–16** cover C2 fundamentals, delivery and execution evidence, antivirus/EDR, permissions, pivoting, SSH evidence, network inspection, Armory, BOFs, execution mechanisms, Windows tokens, and service permissions and diagnostic findings. Worked virtual-lab commands and diagrams connect the concepts. Detailed follow-up answers include connection failures, BOF/COFF/OBJ explanations, and memory loading versus process placement. Exercises assume an authorized, isolated lab.

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
| [8 — Identity, tokens, and permissions](lesson-8-identity-tokens-and-permissions.md) | Account membership versus process elevation, resource-specific rights, and detailed permission answers |
| [9 — Port forwarding and SOCKS5](lesson-9-port-forwarding-and-socks.md) | Reachability, authentication, and authorization; fixed forwards versus proxy-aware clients; HTTP examples and diagrams |
| [10 — Web server to internal SSH: a virtual lab](lesson-10-web-server-to-internal-ssh-lab.md) | Three VMs and two networks, exact SSH commands for both methods, host keys, troubleshooting, defensive observations, and cleanup |
| [11 — Pivot connections and SSH evidence](lesson-11-pivot-connections-and-ssh-evidence.md) | Observed source versus human operator, temporary ports, authentication records, TCP states, and detailed review answers |
| [12 — Network interfaces, sockets, and reachability](lesson-12-network-interfaces-and-sockets.md) | Selected-target context, ifconfig/netstat, LISTEN limits, and firewall, route, VM, container, and HTTP failure analysis |
| [13 — Built-in commands, Armory, and BOFs](lesson-13-armory-and-bof-basics.md) | Package search/install, aliases/extensions, registration versus execution, compatibility, and memory-execution effects |
| [14 — EXE, .NET Assembly, and BOF execution](lesson-14-exe-dotnet-and-bof-execution.md) | Artifact type, Client/target paths, CLR, hosting processes, and the learner's answers with detailed reasoning |
| [15 — Windows tokens, Deny only, and privileges](lesson-15-windows-tokens-and-privileges.md) | Two programs under one account, permission cards, group attributes, privilege state, integrity, and detailed review answers |
| [16 — Windows services, permissions, and diagnostic findings](lesson-16-windows-services-and-diagnostic-findings.md) | Service identity, management/file rights, diagnostic warnings, the instruction-sheet analogy, disk versus process, and detailed answers |

Read one lesson at a time. The lessons connect concepts to examples, with review questions, detailed answers, and follow-up explanations.

## Follow-up questions and detailed answers { #follow-up-questions-and-detailed-answers }

- [BOF, COFF, loaders, and OBJ files](bof-coff-and-object-files-questions.md): the detailed explanation, simpler report/DOCX analogy, object-file compilation/linking, and the target-compatible preparation sequence.
- [Course coverage and next steps](course-coverage-and-next-steps.md): what the original course covers, which topics have been taught, which explanations were added, and what remains.
- [SSH source-attribution and login-state answers](lesson-11-pivot-connections-and-ssh-evidence.md#answer-source-address-versus-person).
- [Why LISTEN does not establish remote access](lesson-12-network-interfaces-and-sockets.md#answer-listen-versus-access), including the requested non-firewall causes.
- [Why registered help is not a target result](lesson-13-armory-and-bof-basics.md#answer-help-versus-result).
- [EXE-format and hosting-process answers](lesson-14-exe-dotnet-and-bof-execution.md#answer-exe-extension).

- [Deny only and the two-file example](lesson-15-windows-tokens-and-privileges.md#deny-only-file-example): distinguish group attributes, privilege state, and evidence of an actual action.

- [A simpler explanation of service warnings](lesson-16-windows-services-and-diagnostic-findings.md#warning-analogy): the manager/instruction-sheet analogy and stored files versus running processes.
- [Lesson 16 detailed review answers](lesson-16-windows-services-and-diagnostic-findings.md#review-answers): finding a SYSTEM service and interpreting RX.
- [Learning review and the Lessons 17–25 plan](course-coverage-and-next-steps.md#lesson-plan).

## How to read the notes { #how-to-read-the-notes }

| Label | Meaning |
|---|---|
| **Lecture** | Core topics and command names covered in the course |
| **Supplement** | Added explanation, a correction, or syntax checked against official project sources |
| **Illustrative example** | A teaching address, timeline, or simplified output |

!!! note "Using command examples"
    Examples use illustrative lab addresses and simplified output. Adapt them to your own authorized lab and check your installed version's help before using them.

## Planned continuation { #planned-continuation }

Lesson 16 covers service identity, service/file rights, and diagnostic evidence. Next come service-permission and configuration analysis, diagnostic tools, authentication/authorization, internal SMB, executable analysis, and a combined lab. See the [learning review and Lessons 17–25 plan](course-coverage-and-next-steps.md#lesson-plan). These are proposed units, not completed lessons.

## Sources { #sources }

- [Sliver official repository](https://github.com/BishopFox/sliver)
- [Sliver documentation](https://sliver.sh/)
- [Architecture — official historical wiki revision](https://github.com/BishopFox/sliver/wiki/Architecture/a1016f154840c2d9508e38a8201d887744ba5afb)
- [Getting Started — official historical wiki revision](https://github.com/BishopFox/sliver/wiki/Getting-Started/d3948bf50c19e85513258e8b69bb834639fb99f6)

The historical revisions preserve explanations that moved to the documentation site. Current command definitions are linked in the relevant lessons; do not infer current defaults from old example output.
