---
title: 디스크와 메모리 이미징
tags:
  - tool
  - collection
  - imaging
---

# 디스크와 메모리 이미징 { #disk-memory-imaging }

<div class="dfir-meta" markdown>
**분류:** 증거 확보 · **플랫폼:** Windows / Linux · **최종 수정:** 2026-09-17
</div>

!!! abstract "한 줄 요약"
    트리아지 아티팩트가 아니라 방어 가능한 완전한 사본이 필요할 때, **메모리**(휘발성, 가장 먼저)와 **디스크**(비트 단위 포렌식 이미지)를 이미징하고, 바뀌지 않았음을 증명할 수 있도록 각각 해시를 남깁니다. 이 페이지는 휘발성 순서, 표준 도구, 증거를 온전하게 지키는 해시와 쓰기 방지를 다룹니다.

## 휘발성 순서 — 이 순서로 수집 { #order-of-volatility-capture-in-this-order }

가장 휘발성이 큰 것부터. 나중 항목을 수집하면 앞 항목이 흐트러지기 때문입니다:

1. **RAM** (메모리 이미지) + 현재 네트워크 연결, 실행 중인 프로세스, 로그온한 사용자.
2. 나중에 이미지로는 얻을 수 없는 **실행 중인 시스템 상태**: 라우팅/ARP, 열린 포트, 마운트된 공유 — 하지만 전체 RAM 이미지가 대부분을 담습니다.
3. **디스크** (포렌식 이미지, 또는 트리아지 수집).
4. **원격/보관 로그** (SIEM, 방화벽) — 가장 덜 휘발적.

머신의 전원을 끌 예정이라면 **무엇보다 먼저, 종료 전에 RAM을 이미징하세요** — 전원이 꺼지면 메모리는 사라집니다.

## 메모리 수집 { #memory-acquisition }

| 도구 | 플랫폼 | 명령 / 메모 |
|---|---|---|
| **WinPmem** | Windows | `winpmem.exe -o mem.raw` (또는 `.aff4`) — 오픈 소스, 드라이버 기반, 믿을 만함 |
| **Magnet RAM Capture** | Windows | GUI, 무료, 흔적이 작음 |
| **DumpIt** (Comae) | Windows | 더블클릭 → raw/`.dmp`; 간단함 |
| **FTK Imager** | Windows | *File → Capture Memory* (페이지 파일도 포함) |
| **AVML** | Linux | `avml mem.lime` — Microsoft의 이식 가능한 Linux 수집기 (LiME 포맷) |
| **LiME** | Linux | 로드 가능한 커널 모듈 → `.lime` |
| **avml / procdump** | 대상 지정 | RAM 전체가 아니라 프로세스 하나만 |

메모: 대상 디스크가 아니라 **외부** 드라이브나 네트워크로 수집하세요(대상 디스크에 쓰면 증거와 슬랙이 파괴됩니다). **페이지 파일/스왑**(`C:\pagefile.sys`, `hiberfil.sys`)도 가져오고, Linux에서 `/proc/kcore`는 대체재가 아닙니다 — AVML/LiME를 쓰세요. 분석은 **Volatility 3**로 ([메모리 포렌식](../memory/index.md)).

```powershell
# WinPmem to an external drive, then hash it
E:\winpmem.exe -o E:\case\mem.raw
certutil -hashfile E:\case\mem.raw SHA256 > E:\case\mem.raw.sha256
```

## 디스크 이미징 { #disk-imaging }

| 도구 | 플랫폼 | 메모 |
|---|---|---|
| **FTK Imager** | Windows | GUI; **E01**(압축, 해시, 메타데이터) 또는 raw `dd`로 이미징; 물리 드라이브, 논리 볼륨 이미징, 이미지를 읽기 전용으로 마운트 가능 |
| **dc3dd / dcfldd** | Linux | 해시, 진행률, 오류 처리가 내장된 `dd` |
| **dd** | Linux | 기본형: `dd if=/dev/sdb of=/evidence/disk.img bs=4M conv=noerror,sync status=progress` |
| **Guymager** | Linux | 빠른 GUI 이미저, E01/raw, 진행하면서 검증 |
| **ewfacquire** (libewf) | Linux | CLI로 E01 생성 |
| **X-Ways / EnCase** | Windows | 상용, 법정 표준 |

**포맷**: 증거에는 **E01(EWF)**이 좋습니다 — 압축하고, 해시와 사건 메타데이터를 파일 안에 저장하며, 세그먼트로 나눕니다. **raw/dd**는 평범한 비트 사본입니다(가장 크고, 어디서나 읽힘). E01은 FTK Imager, Arsenal Image Mounter, `ewfmount`로 읽기 전용 마운트해서 어떤 도구로든 파싱할 수 있습니다([KAPE](kape.md) `--tsource` 포함).

```bash
# Linux, physical disk /dev/sdb → E01 with hashing
ewfacquire -t /evidence/case01 -f encase6 -c fast -S 2GiB /dev/sdb
# or raw with dc3dd + hash
dc3dd if=/dev/sdb of=/evidence/disk.dd hash=sha256 log=/evidence/dc3dd.log
```

## 쓰기 방지와 해시 — 타협 불가 { #write-blocking-and-hashing-non-negotiable }

- **원본에 쓰기 방지.** 물리 디스크는 **하드웨어 쓰기 방지 장치**를, 파일을 이미징할 때는 소프트웨어/OS 읽기 전용 마운트를 쓰세요. 수집하는 동안 원본이 바뀌면 안 됩니다.
- **전후로 해시.** 원본과 이미지의 SHA-256(구식 도구를 위해 MD5도)을 계산하고 일치해야 합니다. E01은 내부에 저장하고 읽을 때 검증하며, raw는 `.sha256` 파일을 옆에 두세요.
- **기록**: 누가, 언제, 도구 + 버전, 원본 장치 시리얼, 해시, 증거 관리 연속성(chain of custody). FTK Imager와 Guymager는 자동으로 기록하고, `dd`는 로그를 남기세요.
- 이미지에 의존하기 전에 수집 후 **이미지를 검증하세요** (FTK Imager *Verify*, `ewfverify`, 또는 다시 해시).

## 라이브 vs. 데드 수집 { #live-vs-dead-acquisition }

| | 라이브 (시스템 실행 중) | 데드 (전원 꺼짐 / 포렌식 OS로 부팅) |
|---|---|---|
| RAM | **예** — 유일한 기회 | 아니오 (전원이 꺼지면 사라짐) |
| 디스크 | 가능하지만 시스템이 계속 바뀜; 트리아지([KAPE](kape.md)/[Velociraptor](velociraptor.md))나 마운트된 볼륨 이미징 | 가장 깨끗함 — 디스크를 빼거나 포렌식 USB(CAINE, Tsurugi, Paladin)로 부팅, 쓰기 방지 |
| 언제 | 시스템을 내릴 수 없음; 휘발성 데이터 필요; 암호화 디스크는 실행 중에만 잠금 해제 | 전원을 내릴 수 있음; 가장 방어 가능한 이미지가 필요 |

**BitLocker/LUKS로 암호화된** 디스크는 **라이브로** 이미징하세요(또는 키/RAM을 확보하세요) — 복구 키가 없으면 암호화된 볼륨의 데드 이미지는 그냥 암호문입니다.

## 클라우드와 가상 환경 { #cloud-virtual }

- **VM**: 스냅숏 + 가상 디스크(`.vmdk`/`.vhdx`)와 메모리 스냅숏(`.vmsn`/`.vmem`) 복사 — 게스트 안에서 이미징하는 것보다 쉽고 깨끗한 경우가 많습니다.
- **클라우드 인스턴스**: 볼륨 스냅숏을 떠서 포렌식 인스턴스에 내보내거나 붙이세요. 가능하면 게스트 안에서 메모리를 수집하세요. 스냅숏과 그 메타데이터를 보존하세요.

## 주의할 점 { #gotchas }

- 이미지를 절대 **원본** 드라이브나 대상의 볼륨에 쓰지 마세요.
- 이미징은 느립니다(큰 디스크는 몇 시간) — 용량을 계획하세요(이미지 ≥ 원본 크기; E01은 압축하지만 넉넉하게 잡으세요).
- **트리아지 수집은 포렌식 이미지가 아닙니다** — [KAPE](kape.md)/[Velociraptor](velociraptor.md)는 고른 아티팩트를 복사합니다. 할당되지 않은 공간, 카빙, 완전한 방어 가능성에는 이미지가 필요합니다.
- 증거 드라이브의 파일시스템을 파일 크기에 맞추세요(4 GB가 넘는 이미지는 FAT32에 안 들어감 — exFAT/NTFS 사용).
- **원본은 건드리지 말고** 사본으로 작업하세요.

## 참고 자료 { #references }

- [SANS — Memory forensics / acquisition guidance](https://www.sans.org/posters/)
- [Volatility 3 (analysis)](https://volatilityfoundation.org/) → [메모리 포렌식](../memory/index.md)
- [libewf / ewftools](https://github.com/libyal/libewf) · [Velocidex WinPmem](https://github.com/Velocidex/WinPmem) · [Microsoft AVML](https://github.com/microsoft/avml)
- 관련 페이지: [KAPE](kape.md) · [Velociraptor](velociraptor.md) · [메모리 포렌식](../memory/index.md)
