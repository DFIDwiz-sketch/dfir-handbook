---
title: Processes & Code Injection
tags:
  - concept
  - memory
  - injection
---

# Processes & Code Injection

<div class="dfir-meta" markdown>
**Category:** Memory forensics · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    Memory is the only place to reliably catch **fileless** and **injected** code — a payload running inside a legitimate process, a hollowed-out `svchost`, a reflectively-loaded beacon — because none of it has a file on disk to find; this page is how to read the process list for anomalies and interpret `malfind`/injection plugins.

## Reading the process tree for anomalies

Start with `windows.pstree` and look for what shouldn't be:

| Anomaly | Why it's suspicious |
|---|---|
| **Wrong parent** | `lsass.exe` not spawned by `wininit.exe`; `svchost.exe` not by `services.exe`; a shell parented to Office or a web server ([phishing](../adversary/phishing-delivery.md)) |
| **Wrong path** | `svchost.exe` running from `C:\Users\` instead of `System32`; a `System32` name from the wrong directory |
| **Wrong count / singleton** | Two `lsass.exe`, an extra `csrss.exe`; there should be exactly one `lsass`, `wininit`, `services` |
| **Misspelled / lookalike** | `scvhost.exe`, `lsass1.exe`, `svch0st.exe` |
| **No parent (orphan)** | Parent PID points to a process that's gone — normal for some, suspicious for others |
| **Odd session/user** | A SYSTEM process spawned by a user process, or vice versa (`getsids`) |
| **Started far after boot** | A core service that "started" during the incident window, not at boot (`pslist` create time) |

```bash
vol -f mem.raw windows.pstree
vol -f mem.raw windows.pslist                    # note CreateTime column
vol -f mem.raw windows.psscan                     # hidden/exited (compare to pslist)
```

The **known-good parent/child map** for Windows core processes (from SANS "Hunt Evil"): `System`(4)→`smss`→`csrss`/`wininit`/`winlogon`; `wininit`→`services`/`lsass`/`lsm`; `services`→`svchost`/`spoolsv`/etc.; `winlogon`→`userinit`→`explorer`. Deviations from this are the first thing to chase.

## `malfind` — injected executable memory

`malfind` lists memory regions that are **private, committed, and executable** with **no memory-mapped file backing them** — the signature of injected code (nothing legitimate allocates RWX private memory and runs it, mostly).

```bash
vol -f mem.raw windows.malfind                    # summary per region
vol -f mem.raw windows.malfind --dump --output-dir ./inj    # dump each region to a file
```

Reading the output:

- **Protection `PAGE_EXECUTE_READWRITE` (RWX)** on private memory — the classic injection marker.
- The **hex/disasm preview**: `MZ` (a full PE injected), or shellcode patterns (`e8`/`e9` calls/jumps, `push`/`pop` prologues, egg-hunter stubs). Cobalt Strike beacons often show a recognisable stub.
- Which **process** hosts it — a beacon injected into `explorer.exe`, `svchost.exe`, `rundll32.exe`, or a browser is common.
- **False positives**: JIT compilers (.NET, Java, browsers) legitimately allocate RWX — correlate with the process (a beacon in `notepad.exe` is bad; RWX in `chrome.exe` may be JIT). Dump and YARA/sandbox to confirm.

```bash
# Confirm a dumped region
strings -a inj/*.dmp | grep -iE "http|\.dll|cmd|powershell|beacon"
yara cobaltstrike.yar inj/*.dmp
```

## Process hollowing & doppelgänging

**Hollowing**: an attacker starts a legit process suspended, unmaps its image, writes a malicious PE in its place, and resumes it — so `pslist` shows `svchost.exe` but the memory image isn't the real svchost.

```bash
vol -f mem.raw windows.hollowprocesses            # compares on-disk image to in-memory image
vol -f mem.raw windows.ldrmodules                  # DLLs/image not in all 3 PEB lists = unlinked
```

`hollowprocesses` flags a mismatch between the process's on-disk executable and what's actually mapped in memory. `ldrmodules` cross-checks the three PEB module lists — a main image or DLL missing from one (usually the InLoad list) indicates unlinking, a hollowing/injection tell.

## Injection techniques and their memory tells

| Technique | Memory signal |
|---|---|
| Classic DLL injection (`CreateRemoteThread` + `LoadLibrary`) | `dlllist` shows a DLL from an odd path; `ldrmodules` may show it, `malfind` may not (it's file-backed) |
| Reflective DLL / manual mapping | `malfind` RWX region containing a PE (`MZ`), **not** in `dlllist` (no LoadLibrary) |
| Shellcode injection | `malfind` RWX region with shellcode, no PE header |
| Process hollowing | `hollowprocesses` image mismatch; `ldrmodules` unlinked main image |
| Thread hijacking / APC | Harder — look at threads (`windows.threads`), unusual start addresses in private memory |
| .NET / CLR injection | CLR loaded in a process that shouldn't have it; RWX from the JIT (correlate) |

## Threads & start addresses

```bash
vol -f mem.raw windows.threads --pid 1234
# A thread whose start address is in private (non-image) memory = injected thread of execution
```

A legitimate thread starts inside a module's code; a thread starting in a `malfind`-flagged private RWX region is the injected code actually running.

## From memory back to the case

Once you've found the injected process/region:

1. **Dump it** (`malfind --dump`, `memmap --dump`, `dumpfiles`) and hash/YARA/sandbox the payload.
2. **Network**: `netscan` for that PID → the C2 IPs → [beaconing/C2](../network/beaconing-c2.md), [Zeek](../network/index.md).
3. **On disk**: the *host* process's real image → was it launched by a [cradle](../adversary/powershell-cradles.md) or [phishing chain](../adversary/phishing-delivery.md)? Check [Prefetch](../windows/prefetch.md), the loader in `cmdline`.
4. **Persistence**: how does the injector re-run? `svcscan`, Run keys in memory, [ASEP](../adversary/persistence.md).

## References

- [Volatility 3 — malfind, ldrmodules, hollowprocesses](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.html)
- [SANS "Hunt Evil" poster — known-good Windows process tree](https://www.sans.org/posters/hunt-evil/)
- [The Art of Memory Forensics (Ligh et al.)](https://www.memoryanalysis.net/amf)
- Pages: [Volatility workflow](volatility-workflow.md) · [Phishing](../adversary/phishing-delivery.md) · [PowerShell cradles](../adversary/powershell-cradles.md) · [Beaconing & C2](../network/beaconing-c2.md)
