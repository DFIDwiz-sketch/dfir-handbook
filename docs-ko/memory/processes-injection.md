---
title: 프로세스와 코드 인젝션
tags:
  - concept
  - memory
  - injection
---

# 프로세스와 코드 인젝션 { #processes-code-injection }

<div class="dfir-meta" markdown>
**분류:** 메모리 포렌식 · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    **파일리스**와 **주입된** 코드 — 정상 프로세스 안에서 도는 페이로드, 속이 비워진 `svchost`, 리플렉티브 로딩된 비콘 — 를 확실하게 잡을 수 있는 곳은 메모리뿐입니다. 디스크에 찾을 파일이 없기 때문입니다. 이 페이지는 프로세스 목록에서 이상을 읽는 법과 `malfind`/인젝션 플러그인 결과를 해석하는 법을 다룹니다.

## 프로세스 트리에서 이상 읽기 { #reading-the-process-tree-for-anomalies }

`windows.pstree`부터 시작해서 있어서는 안 되는 것을 찾으세요:

| 이상 | 수상한 이유 |
|---|---|
| **잘못된 부모** | `lsass.exe`의 부모가 `wininit.exe`가 아님; `svchost.exe`의 부모가 `services.exe`가 아님; Office나 웹 서버가 부모인 셸 ([피싱](../adversary/phishing-delivery.md)) |
| **잘못된 경로** | `System32`가 아니라 `C:\Users\`에서 실행 중인 `svchost.exe`; 엉뚱한 폴더에 있는 `System32` 이름 |
| **잘못된 개수 / 하나여야 하는 것** | `lsass.exe` 두 개, 남는 `csrss.exe`; `lsass`, `wininit`, `services`는 정확히 하나여야 함 |
| **철자 오류 / 비슷한 이름** | `scvhost.exe`, `lsass1.exe`, `svch0st.exe` |
| **부모 없음 (고아)** | 부모 PID가 이미 없는 프로세스를 가리킴 — 어떤 것은 정상, 어떤 것은 수상 |
| **이상한 세션/사용자** | 사용자 프로세스가 만든 SYSTEM 프로세스, 또는 그 반대 (`getsids`) |
| **부팅 후 한참 뒤 시작** | 부팅 때가 아니라 사고 시간대에 "시작된" 핵심 서비스 (`pslist` 생성 시각) |

```bash
vol -f mem.raw windows.pstree
vol -f mem.raw windows.pslist                    # note CreateTime column
vol -f mem.raw windows.psscan                     # hidden/exited (compare to pslist)
```

Windows 핵심 프로세스의 **정상 부모/자식 지도** (SANS "Hunt Evil" 기준): `System`(4)→`smss`→`csrss`/`wininit`/`winlogon`; `wininit`→`services`/`lsass`/`lsm`; `services`→`svchost`/`spoolsv` 등; `winlogon`→`userinit`→`explorer`. 여기서 벗어나는 것을 가장 먼저 쫓으세요.

## `malfind` — 주입된 실행 가능 메모리 { #malfind-injected-executable-memory }

`malfind`는 **프라이빗이고, 커밋됐고, 실행 가능하며** **메모리 매핑된 파일이 뒤에 없는** 메모리 영역을 나열합니다 — 주입된 코드의 특징입니다(정상적인 것은 대부분 RWX 프라이빗 메모리를 할당해서 실행하지 않습니다).

```bash
vol -f mem.raw windows.malfind                    # summary per region
vol -f mem.raw windows.malfind --dump --output-dir ./inj    # dump each region to a file
```

출력 읽기:

- 프라이빗 메모리에 **`PAGE_EXECUTE_READWRITE`(RWX) 보호** — 전형적인 인젝션 표시.
- **16진수/디스어셈블 미리보기**: `MZ`(PE 전체가 주입됨), 또는 셸코드 패턴(`e8`/`e9` 호출/점프, `push`/`pop` 프롤로그, egg-hunter 스텁). Cobalt Strike 비콘은 알아볼 수 있는 스텁을 보이는 경우가 많습니다.
- 어느 **프로세스**가 품고 있는지 — `explorer.exe`, `svchost.exe`, `rundll32.exe`, 브라우저에 주입된 비콘이 흔합니다.
- **오탐**: JIT 컴파일러(.NET, Java, 브라우저)는 정상적으로 RWX를 할당합니다 — 프로세스와 함께 판단하세요(`notepad.exe` 안의 비콘은 나쁘고, `chrome.exe`의 RWX는 JIT일 수 있음). 덤프해서 YARA/샌드박스로 확인하세요.

```bash
# Confirm a dumped region
strings -a inj/*.dmp | grep -iE "http|\.dll|cmd|powershell|beacon"
yara cobaltstrike.yar inj/*.dmp
```

## 프로세스 할로잉과 도플갱잉 { #process-hollowing-doppelganging }

**할로잉**: 공격자가 정상 프로세스를 일시 정지 상태로 시작하고, 이미지 매핑을 해제한 뒤, 그 자리에 악성 PE를 쓰고 다시 실행시킵니다 — 그래서 `pslist`에는 `svchost.exe`로 보이지만 메모리 이미지는 진짜 svchost가 아닙니다.

```bash
vol -f mem.raw windows.hollowprocesses            # compares on-disk image to in-memory image
vol -f mem.raw windows.ldrmodules                  # DLLs/image not in all 3 PEB lists = unlinked
```

`hollowprocesses`는 프로세스의 디스크상 실행 파일과 실제로 메모리에 매핑된 것이 다르면 표시합니다. `ldrmodules`는 PEB 모듈 목록 세 개를 교차 확인합니다 — 메인 이미지나 DLL이 하나에서 빠져 있으면(보통 InLoad 목록) 연결 해제를 뜻하며, 할로잉/인젝션의 단서입니다.

## 인젝션 기법과 메모리 단서 { #injection-techniques-and-their-memory-tells }

| 기법 | 메모리 신호 |
|---|---|
| 고전적 DLL 인젝션 (`CreateRemoteThread` + `LoadLibrary`) | `dlllist`에 이상한 경로의 DLL; `ldrmodules`에는 보일 수 있지만 `malfind`에는 안 보일 수 있음 (파일 기반이므로) |
| 리플렉티브 DLL / 수동 매핑 | PE(`MZ`)가 들어 있는 `malfind` RWX 영역, `dlllist`에는 **없음** (LoadLibrary 안 거침) |
| 셸코드 인젝션 | PE 헤더 없이 셸코드가 든 `malfind` RWX 영역 |
| 프로세스 할로잉 | `hollowprocesses` 이미지 불일치; `ldrmodules` 메인 이미지 연결 해제 |
| 스레드 하이재킹 / APC | 더 어려움 — 스레드(`windows.threads`)를 보고 프라이빗 메모리의 이상한 시작 주소를 찾음 |
| .NET / CLR 인젝션 | 있어서는 안 되는 프로세스에 CLR이 로드됨; JIT의 RWX (상관분석 필요) |

## 스레드와 시작 주소 { #threads-start-addresses }

```bash
vol -f mem.raw windows.threads --pid 1234
# A thread whose start address is in private (non-image) memory = injected thread of execution
```

정상 스레드는 모듈 코드 안에서 시작합니다. `malfind`가 표시한 프라이빗 RWX 영역에서 시작하는 스레드는 주입된 코드가 실제로 실행되고 있다는 뜻입니다.

## 메모리에서 다시 사건으로 { #from-memory-back-to-the-case }

주입된 프로세스/영역을 찾았다면:

1. **덤프하세요** (`malfind --dump`, `memmap --dump`, `dumpfiles`). 그리고 페이로드를 해시/YARA/샌드박스로 확인.
2. **네트워크**: 그 PID의 `netscan` → C2 IP → [비코닝/C2](../network/beaconing-c2.md), [Zeek](../network/index.md).
3. **디스크**: *호스트* 프로세스의 실제 이미지 → [크래들](../adversary/powershell-cradles.md)이나 [피싱 체인](../adversary/phishing-delivery.md)으로 실행됐나? [Prefetch](../windows/prefetch.md), `cmdline`의 로더 확인.
4. **지속성**: 인젝터는 어떻게 다시 실행되나? `svcscan`, 메모리의 Run 키, [ASEP](../adversary/persistence.md).

## 참고 자료 { #references }

- [Volatility 3 — malfind, ldrmodules, hollowprocesses](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.html)
- [SANS "Hunt Evil" poster — known-good Windows process tree](https://www.sans.org/posters/hunt-evil/)
- [The Art of Memory Forensics (Ligh et al.)](https://www.memoryanalysis.net/amf)
- 관련 페이지: [Volatility 워크플로](volatility-workflow.md) · [피싱](../adversary/phishing-delivery.md) · [PowerShell 크래들](../adversary/powershell-cradles.md) · [비코닝과 C2](../network/beaconing-c2.md)
