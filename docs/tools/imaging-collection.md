---
title: Disk & Memory Imaging
tags:
  - tool
  - collection
  - imaging
---

# Disk & Memory Imaging

<div class="dfir-meta" markdown>
**Category:** Evidence acquisition · **Platform:** Windows / Linux · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    When you need a defensible, complete copy — not just triage artifacts — you image the **memory** (volatile, capture first) and the **disk** (a bit-for-bit forensic image), each with a hash so you can prove it hasn't changed. This page covers the order of volatility, the standard tools, and the hashing/write-blocking that keeps evidence sound.

## Order of volatility — capture in this order

Most volatile first, because collecting later items disturbs earlier ones:

1. **RAM** (memory image) + current network connections, running processes, logged-on users.
2. **Running-system state** you can't get from an image later: routing/ARP, open ports, mounted shares — but a full RAM image captures most of this.
3. **Disk** (forensic image, or triage collection).
4. **Remote/archival logs** (SIEM, firewall) — least volatile.

If the machine will be powered off, **image RAM before anything else** and before shutdown — memory is gone at power-off.

## Memory acquisition

| Tool | Platform | Command / note |
|---|---|---|
| **WinPmem** | Windows | `winpmem.exe -o mem.raw` (or `.aff4`) — open-source, driver-based, reliable |
| **Magnet RAM Capture** | Windows | GUI, free, small footprint |
| **DumpIt** (Comae) | Windows | Double-click → raw/`.dmp`; simple |
| **FTK Imager** | Windows | *File → Capture Memory* (also includes pagefile) |
| **AVML** | Linux | `avml mem.lime` — Microsoft's portable Linux acquirer (LiME format) |
| **LiME** | Linux | Loadable kernel module → `.lime` |
| **avml / procdump** | targeted | For a single process rather than whole RAM |

Notes: capture to an **external** drive or over the network, not the subject's disk (writing to it destroys evidence and slack). Also grab the **pagefile/swap** (`C:\pagefile.sys`, `hiberfil.sys`) and, on Linux, `/proc/kcore` isn't a substitute — use AVML/LiME. Analyse with **Volatility 3** ([Memory forensics](../memory/index.md)).

```powershell
# WinPmem to an external drive, then hash it
E:\winpmem.exe -o E:\case\mem.raw
certutil -hashfile E:\case\mem.raw SHA256 > E:\case\mem.raw.sha256
```

## Disk imaging

| Tool | Platform | Note |
|---|---|---|
| **FTK Imager** | Windows | GUI; images to **E01** (compressed, hashed, metadata) or raw `dd`; can image physical drive, logical volume, or mount images read-only |
| **dc3dd / dcfldd** | Linux | `dd` with hashing, progress, error handling built in |
| **dd** | Linux | Baseline: `dd if=/dev/sdb of=/evidence/disk.img bs=4M conv=noerror,sync status=progress` |
| **Guymager** | Linux | Fast GUI imager, E01/raw, verifies as it goes |
| **ewfacquire** (libewf) | Linux | Create E01 from CLI |
| **X-Ways / EnCase** | Windows | Commercial, court-standard |

**Formats**: **E01 (EWF)** is preferred for evidence — it compresses, stores the hash and case metadata inside the file, and splits into segments; **raw/dd** is a plain bit copy (largest, universally readable). E01 mounts read-only in FTK Imager, Arsenal Image Mounter, or `ewfmount` for parsing with any tool (including [KAPE](kape.md) `--tsource`).

```bash
# Linux, physical disk /dev/sdb → E01 with hashing
ewfacquire -t /evidence/case01 -f encase6 -c fast -S 2GiB /dev/sdb
# or raw with dc3dd + hash
dc3dd if=/dev/sdb of=/evidence/disk.dd hash=sha256 log=/evidence/dc3dd.log
```

## Write-blocking and hashing — non-negotiable

- **Write-block the source.** Use a **hardware write blocker** for physical disks, or a software/OS read-only mount when imaging a file. The source must not change during acquisition.
- **Hash before and after.** Compute SHA-256 (MD5 additionally for legacy tooling) of the source and of the image; they must match. E01 stores this internally and verifies on read; for raw, keep a `.sha256` sidecar.
- **Document**: who, when, tool + version, source device serial, hashes, chain of custody. FTK Imager and Guymager write this automatically; for `dd` keep a log.
- **Verify the image** after acquisition (FTK Imager *Verify*, `ewfverify`, or re-hash) before you rely on it.

## Live vs. dead acquisition

| | Live (system running) | Dead (powered off / boot to forensic OS) |
|---|---|---|
| RAM | **Yes** — only chance | No (gone at power-off) |
| Disk | Possible but system is changing; use triage ([KAPE](kape.md)/[Velociraptor](velociraptor.md)) or image mounted volumes | Cleanest — pull the disk or boot a forensic USB (CAINE, Tsurugi, Paladin), write-blocked |
| When | Can't take the box down; need volatile data; encrypted disk unlocked only while running | Can power down; want the most defensible image |

For a **BitLocker/LUKS-encrypted** disk, image it **live** (or capture the key/RAM) — a dead image of an encrypted volume is just ciphertext unless you have the recovery key.

## Cloud & virtual

- **VM**: snapshot + copy the virtual disk (`.vmdk`/`.vhdx`) and the memory snapshot (`.vmsn`/`.vmem`) — often easier and cleaner than in-guest imaging.
- **Cloud instance**: snapshot the volume, export/attach it to a forensic instance; capture memory in-guest if you can. Preserve the snapshot and its metadata.

## Gotchas

- Never write the image to the **source** drive or the subject's own volume.
- Imaging is slow (hours for large disks) — plan capacity (image ≥ source size; E01 compresses but budget generously).
- A **triage collection is not a forensic image** — [KAPE](kape.md)/[Velociraptor](velociraptor.md) copy chosen artifacts; for unallocated space, carving, and full defensibility you need the image.
- Match your evidence drive's filesystem to file sizes (a >4 GB image won't fit on FAT32 — use exFAT/NTFS).
- Keep the **original untouched**; work on copies.

## References

- [SANS — Memory forensics / acquisition guidance](https://www.sans.org/posters/)
- [Volatility 3 (analysis)](https://volatilityfoundation.org/) → [Memory forensics](../memory/index.md)
- [libewf / ewftools](https://github.com/libyal/libewf) · [Velocidex WinPmem](https://github.com/Velocidex/WinPmem) · [Microsoft AVML](https://github.com/microsoft/avml)
- Pages: [KAPE](kape.md) · [Velociraptor](velociraptor.md) · [Memory forensics](../memory/index.md)
