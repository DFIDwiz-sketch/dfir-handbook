---
title: "Questions — Course Coverage and Next Steps"
---

# Questions — Course Coverage and Next Steps { #course-coverage-and-next-steps }

## Have we covered the whole original course? { #have-we-covered-the-whole-course }

**No. Further topics remain.** The learner asked this after the network-inspection discussion. The original course was compared with the teaching completed so far, and that comparison is updated here through Lesson 15.

The numbered lessons are teaching units created to keep explanations manageable. Their numbers do not map one-to-one to sections in the original presentation or represent a percentage completed. Follow-up questions have deliberately expanded individual topics.

## Current coverage { #current-coverage }

| Original topic | Current teaching status |
|---|---|
| C2 components, listener, implant generation and delivery | Explained with commands and evidence distinctions |
| Sessions, Beacons, check-ins and task timing | Explained with selection and interactive-session examples |
| Payload, stager, and loader | Concepts explained; the course-specific loader implementation has not been reproduced |
| Antivirus detection and executable analysis | Detection/action/outcome explained; hands-on PE-bear and DefenderCheck analysis remains |
| Account identity and permissions | Lessons 8 and 15 explain tokens, Deny only, privilege states, and integrity; domain/share investigation remains |
| Armory and BOF | Lesson 13 and the BOF/COFF/OBJ questions explain package preparation and code structure |
| Program, .NET Assembly, and BOF execution | Lesson 14 explains mechanisms and example syntax; its illustrative assembly is not a completed build-and-run exercise |
| Process, network, and situational-awareness tools | Basic interfaces/connections explained; additional diagnostic-tool work remains |
| Windows service misconfiguration and privilege escalation | Detailed case analysis remains |
| Execution using another identity and lateral movement | Further explanation remains |
| Port forwarding and SOCKS5 | Explained with command examples and the virtual SSH scenario |
| ProxyChains and NetExec against internal SMB | Further explanation remains |
| Authentication-attack examples in the original course | Not yet taught in detail |
| SMB share authorization and scoped file collection | Further explanation remains |

“Explained” describes the published teaching, not a claim that every reader has successfully run it. Command examples, actual execution, and evidence of success are separate things.

## Which material was added as a supplement? { #added-supplements }

The following explanations were added to strengthen understanding:

- A web-server pivot to an internal SSH VM, including fixed forwarding and SOCKS5.
- SSH authentication records, source attribution, temporary ports, and TCP versus authentication.
- LISTEN and ESTABLISHED limits, routing, firewalls, virtual-network separation, and container port mappings.
- The report/DOCX analogy for BOF and COFF, object-file compilation/linking, and target-compatible loader preparation.
- Detailed review answers, including the learner's reasoning and the distinction between memory execution and process placement.

These supplements connect the operator workflow to evidence and troubleshooting. They do not imply that every original-course topic has already been covered.

- Revisit the [permission-card, Deny-only, and file-access examples in Lesson 15](lesson-15-windows-tokens-and-privileges.md).

## Suggested continuation { #suggested-continuation }

Build on Lesson 15's token interpretation by examining additional diagnostic-tool findings. Distinguish a reported misconfiguration from proof of a usable permission or a successful action. Later lessons can connect those findings to service configuration, authentication/authorization, and internal SMB workflows.

Revisit [Lesson 8](lesson-8-identity-tokens-and-permissions.md) for permission principles, [Lesson 13](lesson-13-armory-and-bof-basics.md) for package preparation, and [Lesson 14](lesson-14-exe-dotnet-and-bof-execution.md) for execution mechanisms.

[Lesson 15: Windows tokens and privileges](lesson-15-windows-tokens-and-privileges.md) · [Course overview](index.md)
