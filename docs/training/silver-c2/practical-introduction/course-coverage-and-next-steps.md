---
title: "Questions — Course Coverage and Next Steps"
---

# Questions — Course Coverage and Next Steps { #course-coverage-and-next-steps }

## Have we covered the whole original course? { #have-we-covered-the-whole-course }

**No. Further topics remain.** This review compares the original course with the teaching completed through **Lesson 16 and its detailed follow-up answers**.

Lesson numbers are manageable teaching units. They do not map one-to-one to the original presentation or represent a completion percentage. The proposed Lessons 17–25 below are a plan, not already published lessons.

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
| Windows service misconfiguration and privilege escalation | Lesson 16 introduces service identity, management/file rights, diagnostic warnings, and evidence; detailed configuration cases remain |
| Execution using another identity and lateral movement | Further explanation remains |
| Port forwarding and SOCKS5 | Explained with command examples and the virtual SSH scenario |
| ProxyChains and NetExec against internal SMB | Further explanation remains |
| Authentication-attack examples in the original course | Not yet taught in detail |
| SMB share authorization and scoped file collection | Further explanation remains |

“Explained” describes the published teaching. It does not mean that every example has been run successfully in the learner's VM. Example syntax, actual execution, and evidence of success remain separate.

## Review of the lessons so far { #learning-review }

| Lessons | Material taught | What still needs practice |
|---|---|---|
| 1–3 | C2 structure, listeners/implants, Sessions/Beacons, check-ins | Connect task delivery and result timing to observations |
| 4–7 | Payloads, stagers/loaders, generation/delivery, antivirus/EDR | Perform a focused executable-analysis exercise |
| 8 and 15 | Accounts/tokens, Deny only, privileges, integrity | Read actual permission entries alongside the current token |
| 9–12 | Port forwarding/SOCKS, internal SSH, connection records, sockets | Apply the examples in the learner's lab and correlate evidence |
| 13–14 | Armory, BOF/COFF/OBJ, EXE/.NET execution | Build a small benign example and compare execution results |
| 16 | Windows services, service accounts, management/file permissions | Analyze specific service configuration findings |

The learner's earlier answers correctly separated:

- HTTP 200 from proof of a complete local save or implant execution.
- A detection event from proof of a successful response action.
- Administrator-group membership from elevation of the current process.
- Delayed or missing results from a confirmed task failure.

These answers demonstrate reasoning about evidence. They are not a substitute for observing actual lab outcomes.

## Connections to keep practicing { #reasoning-practice }

| Concept to revisit | Next application |
|---|---|
| Current token plus resource permissions | Can this context perform a particular service or file operation? |
| Reachability, authentication, and authorization | Can a connection reach a server, log in, and access a particular share? |
| Diagnostic finding plus execution evidence | What does a warning establish, and what still needs verification? |

## Explanations developed through the course { #added-supplements }

The course connects concepts to examples and detailed learner questions:

- A web-server pivot to an internal SSH VM using fixed forwarding and SOCKS5.
- SSH authentication records, source attribution, temporary ports, and TCP versus authentication.
- LISTEN/ESTABLISHED limits, routing, firewalls, virtual networks, and container port mappings.
- The report/DOCX analogy for BOF/COFF, object-file compilation/linking, and compatible loader preparation.
- Memory execution versus process placement.
- Permission cards, Deny only, privilege state, and the two-file access example.
- A manager/instruction-sheet analogy for service findings, and stored files versus running processes.

These explanations support understanding; they do not imply that the entire original course has been completed.

Revisit [Lesson 15](lesson-15-windows-tokens-and-privileges.md) and [Lesson 16's simpler diagnostic-warning explanation](lesson-16-windows-services-and-diagnostic-findings.md#warning-analogy).

## Suggested continuation { #suggested-continuation }

Continue from service permissions to configuration analysis, diagnostic-tool findings, identities, SMB authorization, and a combined lab. Each lesson will introduce a small number of new ideas, read short outputs, and include review answers.

### Proposed Lessons 17–25 { #lesson-plan }

| Planned lesson | Topic | What the lesson will develop |
|---|---|---|
| 17 | Read service-management permissions | Separate query, configuration change, start, and stop rights; compare service-object and executable permissions |
| 18 | Unquoted service executable paths | Explain spaces and path interpretation with a diagram; check the conditions behind a warning |
| 19 | Interpret diagnostic tools | Compare roles of tools such as Seatbelt and SharpUp; check findings against actual configuration and permissions |
| 20 | Execution under another identity | Separate local/domain accounts, local/remote computers, another user, and administrative execution |
| 21 | SMB and share permissions | Explain SMB, share permissions, NTFS permissions, and successful authentication with restricted file access |
| 22 | Reach internal SMB through a pivot | Add a Windows file-server VM to the web-pivot lab; separate SOCKS, ProxyChains, and NetExec; use a provisioned test account against one lab server |
| 23 | Authentication attempts and records | Compare password guessing and password spraying; interpret failure, lockout, and success records |
| 24 | Executable analysis and detection evidence | Connect PE structure, strings, and hashes to small examples; distinguish clues from a demonstrated detection cause |
| 25 | Combined lab and evidence review | Connect C2, current identity, internal-service access, and logs; record results and clean up lab changes |

Numbers can change if a learner question needs another smaller lesson. These rows describe future teaching, not completed exercises.

A short practical exercise will also connect BOF/.NET explanations to observable results by comparing a simple, benign identity-reporting program across suitable execution methods.

### How Lesson 17 will begin { #next-lesson-seventeen }

Use one fictional service and answer four questions in order:

1. Under which account is the service configured to run?
2. Can the current context query or change its configuration?
3. Can the current context modify the executable or relevant directory?
4. Can the current context start or stop the service?

Read one short output at a time, then compare two users with different permissions. This develops the three permission categories introduced in Lesson 16.

Revisit [Lesson 8](lesson-8-identity-tokens-and-permissions.md) for permission principles, [Lesson 13](lesson-13-armory-and-bof-basics.md) for package preparation, and [Lesson 14](lesson-14-exe-dotnet-and-bof-execution.md) for execution mechanisms.

[Lesson 16: Windows services and diagnostic findings](lesson-16-windows-services-and-diagnostic-findings.md) · [Course overview](index.md)
