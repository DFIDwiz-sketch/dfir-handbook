---
title: Shimcache (AppCompatCache)
tags:
  - artifact
  - windows
  - execution
---

# Shimcache (AppCompatCache) { #shimcache-appcompatcache }

<div class="dfir-meta" markdown>
**분류:** 파일 존재 / 실행 가능성 · **OS:** XP → 11, **서버 포함** · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    애플리케이션 호환성 캐시는 shim 엔진이 *살펴본* 실행 파일을 기록합니다 — 전체 경로, 파일의 **$STANDARD_INFORMATION 마지막 수정 시각**, 그리고 (Win7/8에서만) "실행됨" 플래그. 파일이 **그 경로에 존재했다는 것**을 증명하고, 실행은 가능성이 높지만 보장되지는 않습니다. **Prefetch가 꺼진 서버에서도** 동작합니다.

## 알려 주는 것 { #what-it-tells-you }

- 실행됐**거나** 탐색기에서 둘러본 실행 파일(일부 스크립트/DLL 포함)의 전체 경로 (탐색기는 shim을 적용하려고 파일을 검사합니다).
- **캐시된 시점의 파일 마지막 수정 시각(`$SI`)** — 실행 시각이 *아닙니다*.
- 순서: 항목은 **최근 것부터** 저장되므로 실행 타임스탬프가 없어도 위치가 상대적인 타임라인이 됩니다.
- Win7 / Win8: 실제 실행을 뜻하는 **Insert 플래그 / 실행 플래그** (`CSRSS` 플래그).
- Windows 10/11: **실행 플래그 없음**, 삽입 타임스탬프 없음. 존재와 순서만.

!!! warning "흔히 틀리는 세 가지"
    1. 타임스탬프는 실행 시각이 아니라 **파일의 수정 시각**입니다.
    2. **Windows 10/11에는 실행 플래그가 없습니다** — 탐색기가 EXE가 들어 있는 폴더의 아이콘을 그리기만 해도 항목이 생길 수 있습니다.
    3. 캐시는 **메모리**에 있다가 **종료/재부팅 시에만 레지스트리에 기록**됩니다(또는 가득 찼을 때). 라이브 시스템의 `SYSTEM` 하이브는 오래된 내용이고, 공격 후 한 번도 재부팅하지 않은 시스템에는 아직 항목이 없을 수 있습니다. 메모리 포렌식(`volatility3 windows.shimcachemem`)으로 라이브 버전을 얻으세요.

## 위치 { #location }

| 항목 | 경로 / 키 |
|---|---|
| 레지스트리 (Win7+) | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` (바이너리 값) |
| 레지스트리 (XP) | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache` |
| 오프라인 하이브 | `C:\Windows\System32\config\SYSTEM` (+`.LOG1/.LOG2`). `CurrentControlSet` → `Select\Current`를 보고 `ControlSet001`인지 `002`인지 고름 |
| 최대 항목 수 | XP: 96 · Win7/8: 1024 · Win10/11: 1024 (구 빌드) — 오래된 것은 끝에서 밀려남 |

`ControlSet00N` 키가 여러 개면 각각 캐시를 가질 수 있습니다 — 모두 파싱하세요. 현재 사용하지 않는 쪽은 더 오래된 스냅샷입니다.

## OS별 포맷 { #format-by-os }

| OS | 헤더 / 시그니처 | 타임스탬프 | 실행 플래그 |
|---|---|---|---|
| XP 32비트 | `0xDEADBEEF` | 마지막 수정 + 마지막 업데이트 시각 | — |
| Vista / 2008 | `0xBADC0FFE` | 마지막 수정 | Insert 플래그 |
| Win7 / 2008 R2 | `0xBADC0FFE` | 마지막 수정 | **예** (`CSRSS` insert 플래그) |
| Win8 / 2012 | 항목마다 `00ts` 태그 | 마지막 수정 | **예** |
| Win8.1 / 2012 R2 | `10ts` | 마지막 수정 | **예** |
| Win10 / 11 / 2016+ | `10ts`, 헤더 오프셋 0x30 (Creators Update+는 0x34) | 마지막 수정 | **아니오** |

## 수집 방법 { #how-to-collect }

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target RegistryHivesSystem --mdest C:\Case\mod --module AppCompatCacheParser
    ```

=== "Velociraptor"

    `Windows.Registry.AppCompatCache`

=== "라이브 (먼저 디스크에 기록됨!)"

    ```powershell
    # Forces the in-memory cache to flush? No — only reboot does. Export what is on disk:
    reg save HKLM\SYSTEM C:\Case\SYSTEM
    ```

    메모리에 있는 라이브 버전은 메모리 이미지를 떠서 Volatility(`windows.shimcachemem`)로 보세요.

## 파싱 방법 { #how-to-parse }

=== "AppCompatCacheParser (Eric Zimmerman)"

    ```powershell
    # Offline hive → CSV; -t sorts by timestamp, -c picks a ControlSet (default: all)
    AppCompatCacheParser.exe -f C:\Case\SYSTEM --csv C:\Case\out --csvf shimcache.csv

    # Live system
    AppCompatCacheParser.exe --csv C:\Case\out
    ```

    열: `ControlSet`, `CacheEntryPosition` (0 = 가장 최근), `Path`, `LastModifiedTimeUTC`, `Executed` (Win7/8만), `Duplicate`.

=== "RegRipper"

    ```bash
    rip.pl -r SYSTEM -p appcompatcache
    rip.pl -r SYSTEM -p shimcache      # TLN output for timelines
    ```

=== "Volatility 3 (메모리)"

    ```bash
    vol -f mem.raw windows.shimcachemem
    ```

## 분석 팁 { #analysis-tips }

!!! tip "순서를 정할 때는 타임스탬프가 아니라 *위치*를 쓰세요"
    0번 항목이 가장 최근에 shim된 것입니다. `mimikatz.exe`가 3번, `psexesvc.exe`가 4번이라면 수정 시각이 무엇이든 공격자는 PsExec을 먼저, 그다음 Mimikatz를 실행한 것입니다. 삽입 순서가 타임라인이고, 타임스탬프는 *파일*이 얼마나 오래됐는지만 알려 줍니다.

- **서버 트리아지**: Server SKU는 Prefetch가 꺼져 있으므로 Shimcache + Amcache + 4688 + BAM이 실행 증거의 전부입니다.
- **경로 이상**: `\??\C:\Users\Public\`, `\Device\HarddiskVolumeShadowCopy`, UNC 경로(`\\server\share\tool.exe`), 이동식 드라이브 — 모두 뽑아 볼 가치가 있습니다.
- **타임스톰핑 탐지**: Shimcache의 마지막 수정 시각이 파일의 현재 `$SI` 수정 시각보다 *최신*이라면, 누군가 실행 후에 타임스탬프를 되돌린 것입니다.
- **삭제된 도구**도 새 항목 1024개에 밀려날 때까지 캐시에 남습니다.
- **Win10의 탐색기 잡음**: 탐색기로 `C:\Tools\`를 둘러보기만 해도 안의 EXE가 전부 shim될 수 있습니다. 실행이라고 주장하기 전에 Prefetch / Amcache / 4688로 뒷받침하세요.
- ControlSet 간 **중복**은 정상입니다. `ControlSet001`에는 있고 `002`에는 없는 경로는 두 스냅샷 사이에 나타났다는 뜻입니다.
- **안티포렌식**: 지우려면 바이너리 레지스트리 값을 고쳐야 하거나(드묾), 정상 재부팅을 하지 않아 기록을 막아야 합니다 — 재부팅이 아니라 *크래시*가 난 시스템은 메모리상의 항목을 잃었을 수 있습니다.

## 타임라인 / 상관분석 { #timeline-correlation }

| 질문 | 교차 확인 |
|---|---|
| 정말 실행됐나? | [Prefetch](prefetch.md) (워크스테이션), Security `4688`, Sysmon `1`, [Amcache](amcache.md), BAM/DAM |
| 그 파일은 무엇이었나? | [Amcache](amcache.md) SHA-1 |
| 언제 떨어뜨렸나? | [$MFT / USN](mft-usn.md) — `$FN` 생성 시각 vs Shimcache 마지막 수정 |
| 라이브 캐시와 디스크 캐시가 다른가? | 메모리 이미지 `shimcachemem` vs `SYSTEM` 하이브 |

## 참고 자료 { #references }

- [Mandiant — Leveraging the Application Compatibility Cache in Forensic Investigations](https://www.mandiant.com/resources/blog/caching-out-the-val)
- [Eric Zimmerman — AppCompatCacheParser](https://ericzimmerman.github.io/#!index.md)
- [libyal — Windows AppCompatCache format](https://github.com/libyal/winreg-kb/blob/main/documentation/Application%20Compatibility%20Cache%20key.asciidoc)
