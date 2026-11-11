---
title: "5 — DC SMB 공격과 Snort 규칙 작성"
tags:
  - training
  - incident-response
  - smb
  - lateral-movement
  - snort
---

# 5 — DC SMB 공격과 Snort 규칙 작성 { #dc-smb-and-snort-rules }

!!! abstract "이 페이지의 범위"
    - 악성코드가 클라이언트에서 도메인 컨트롤러로 SMB를 통해 퍼졌다는 것과 그 시각 증명하기
    - TCP 445 실패 시도 세 가지 구분: MS17-010(EternalBlue), 로그인 시도, ADMIN$ 접근
    - Snort 2 규칙 문법 한 줄씩
    - 경우별 예시 규칙, `local.rules`에 넣고 PCAP으로 시험하기

## SMB를 통한 DC 전파 { #smb-lateral }

DC 감염은 감염된 클라이언트가 SMB(TCP 445, 윈도우 파일 공유)로 DC에 실행파일을 복사하고 원격으로 실행한 시점입니다. 그 쓰기 시각이 "DC가 언제 감염됐나"의 답이고, SMB로 오간 파일이 "SMB 트래픽의 파일"입니다.

```bash
zeek-cut -u ts id.orig_h id.resp_h action path name size < zeek_out/smb_files.log
tshark -r case.pcap -Y "smb2.filename || smb.file" -T fields -e frame.time_utc -e ip.src -e ip.dst -e smb2.cmd -e smb2.filename -e smb.file | sort -u | grep -i -E "\.exe|\.dll"
tshark -r case.pcap -Y "svcctl" -T fields -e frame.time_utc -e ip.src -e ip.dst -e _ws.col.Info
```

- `action`이 `SMB::FILE_WRITE`면 파일을 쓴 것입니다. `path`가 `\\<DC>\ADMIN$`나 `C$`면 관리자 공유 폴더입니다.
- `smb2.filename` / `smb.file`: SMB2와 예전 SMB1의 파일 이름 칸. `smb2.cmd` 5 = Create(열기·만들기), 9 = Write(쓰기).
- `svcctl`: 원격 서비스 제어 프로토콜. `CreateServiceW`, `StartServiceW`가 보이면 복사한 파일을 서비스로 실행한 것입니다(PsExec 방식).

```text
2019-xx-xxTxx:xx:xx  <client IP>  <DC_IP>  SMB::FILE_WRITE  \\<DC>\ADMIN$  <random>.exe  xxxxxx
```

강한 확인: 그 시각 이후 DC가 직접 인터넷과 통신하기 시작합니다.

```bash
zeek-cut -u ts id.orig_h id.resp_h id.resp_p service < zeek_out/conn.log | awk -F'\t' '$2=="<DC_IP>" && $3 !~ /^172\.|^10\.|^192\.168\./'
```

SMB 파일은 `--export-objects smb,objs_smb`로 꺼내 해시를 구하고, HTTP 다운로드의 SHA256과 비교합니다(`uniq -w64 -D`, [해시 구하기](files-and-hashes.md#hashing) 참고). DC까지 간 파일의 패밀리가 DC를 감염시킨 패밀리입니다.

Wireshark: 필터 `smb2.filename contains ".exe" || smb.file contains ".exe"` → `Create Request File: <이름>.exe`와 그 뒤 `Write Request`, 필터 `svcctl`, **File → Export Objects → SMB**, DC의 외부 통신은 `ip.src==<DC_IP> && !(ip.dst==172.16.0.0/12 || ip.dst==10.0.0.0/8 || ip.dst==192.168.0.0/16)`.

!!! note "Export Objects → SMB"
    캡처에 끝까지 담긴 파일만 제대로 저장됩니다. 크기가 예상보다 훨씬 작으면 일부만 잡힌 것이니 답안에 적어 둡니다.

## TCP 445 실패 시도 { #failed-445 }

SMB 명령과 DC의 응답 상태 코드로 흔한 세 경우를 구분합니다. 목록이 아니라 PCAP을 보고 정합니다.

| 후보 | 트래픽에서 보이는 모습 | 실패의 흔적 |
| --- | --- | --- |
| MS17-010 공격(EternalBlue) | 예전 SMB1, 크고 많은 `NT Trans`·`Trans2 Secondary` 요청, `Trans2 SESSION_SETUP`(DoublePulsar 백도어 확인) | DC가 SMB1을 거부하거나, 패치돼 에러 응답 |
| 로그인 시도(비밀번호 대입) | Session Setup 요청 반복 | `STATUS_LOGON_FAILURE`(0xc000006d) |
| 복사와 원격 실행(PsExec 방식) | `\\DC\ADMIN$`·`C$` Tree Connect, `.exe` 쓰기, `svcctl` | `STATUS_ACCESS_DENIED`(0xc0000022) |

```bash
grep "<DC_IP>:445" snort_out/alert | grep -oE "\] ET [^\[]*" | sort | uniq -c
tshark -r case.pcap -Y "ip.addr==<DC_IP> && tcp.port==445 && (smb || smb2)" -T fields -e frame.number -e frame.time_utc -e ip.src -e _ws.col.Info -e smb.nt_status -e smb2.nt_status
tshark -r case.pcap -Y "ip.dst==<DC_IP> && (smb.cmd == 0xa0 || smb.cmd == 0x33 || smb.trans2.cmd == 0x000e)" -T fields -e frame.number -e frame.time_utc -e ip.src -e _ws.col.Info
tshark -r case.pcap -Y "ip.src==<DC_IP> && (smb.nt_status != 0 || smb2.nt_status != 0)" -T fields -e frame.time_utc -e ip.dst -e _ws.col.Info | sort | uniq -c
zeek-cut -u ts id.orig_h id.resp_h path service share_type < zeek_out/smb_mapping.log
```

- 1줄: 알림 이름에 `ETERNALBLUE`, `MS17-010`, `DOUBLEPULSAR`가 있으면 첫째 후보입니다.
- 2줄: DC와 오간 SMB 패킷 전부. `smb` = SMB1(EternalBlue는 SMB1 사용), `smb2` = SMB2/3. `_ws.col.Info`는 Wireshark Info 열을 출력합니다. `nt_status`가 `0x00000000`이면 성공, 그 외는 실패 코드입니다.
- 3줄: `smb.cmd == 0xa0` NT Trans(EternalBlue가 큰 데이터를 보낼 때), `0x33` Trans2 Secondary(이어 보내기), `smb.trans2.cmd == 0x000e` Trans2 SESSION_SETUP(DoublePulsar 확인).
- 4줄: DC가 돌려준 에러를 종류별로 셉니다.
- 5줄: 클라이언트가 연결하려 한 공유 폴더. `zeek_out/notice.log`도 확인합니다.

Wireshark: 필터 `ip.addr==<DC_IP> && tcp.port==445` 후 Info 열 읽기, **Statistics → Service Response Time → SMB / SMB2**로 명령별 횟수, **Analyze → Expert Information**으로 에러 응답, 의심 패킷은 **Follow → TCP Stream**. 답안 틀: [실패한 시도](report-templates.md#failed-attempt-template).

## Snort 규칙 문법 { #snort-rules }

```text
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"..."; flow:to_server,established; content:"|FF|SMB"; offset:4; depth:4; classtype:attempted-admin; sid:1000001; rev:1;)
```

규칙은 괄호 앞의 **헤더**와 괄호 안의 **옵션**으로 나뉩니다.

- `alert`: 모두 맞으면 알림을 냅니다.
- `tcp`: TCP 패킷만.
- `$HOME_NET any`: 출발지 IP와 포트. `$HOME_NET`은 `snort.conf`의 내부망 변수, `any`는 모든 포트.
- `->`: 방향(왼쪽에서 오른쪽).
- `$HOME_NET 445`: 목적지 IP와 포트. DC만 보려면 `<DC_IP> 445`처럼 씁니다.
- `msg:"..."`: 알림 이름.
- `flow:to_server,established`: 연결이 맺어진 뒤 서버로 가는 패킷만(오탐 줄임).
- `content:"|FF|SMB"`: 있어야 하는 바이트. `| |` 안은 16진수, 밖은 글자. `FF 53 4D 42`는 SMB1, `FE 53 4D 42`(`|FE|SMB`)는 SMB2 헤더의 시작입니다.
- `offset:4; depth:4`: TCP 데이터의 4번째 바이트(0부터 셈)부터 4바이트 안에서만 찾습니다. 445번 포트는 앞 4바이트가 NetBIOS 세션(길이) 헤더이고 그 뒤에 SMB 헤더가 옵니다.
- `classtype`: 알림 분류. `sid`: 규칙 번호(직접 쓰는 규칙은 1000000 이상). `rev`: 수정 횟수.
- 옵션은 `;`로 끝내고, 규칙 전체는 한 줄로 씁니다.

## 예시 규칙 { #example-rules }

[TCP 445 실패 시도](#failed-445)에서 확인한 것에 맞는 규칙을 씁니다.

**A. MS17-010(EternalBlue) 시도**: SMB1 NT Trans 요청, 또는 DoublePulsar가 쓰는 Trans2 SESSION_SETUP.

```text
alert tcp any any -> $HOME_NET 445 (msg:"LOCAL SMBv1 NT Trans request - possible MS17-010 EternalBlue"; flow:to_server,established; content:"|FF|SMB|A0|"; offset:4; depth:5; classtype:attempted-admin; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET 445 (msg:"LOCAL SMBv1 Trans2 SESSION_SETUP - possible DoublePulsar check"; flow:to_server,established; content:"|FF|SMB|32|"; offset:4; depth:5; content:"|0E 00|"; offset:65; depth:2; classtype:attempted-admin; sid:1000002; rev:1;)
```

- `|FF|SMB|A0|`: SMB1 표시 + 명령 `A0`(NT Trans). `|FF|SMB|32|`: 명령 `32`(Trans2).
- `offset:65`의 `|0E 00|`: Trans2 하위 명령 `0x000e`(SESSION_SETUP)를 리틀 엔디안으로. 65 = NetBIOS 4 + SMB1 헤더 32 + 파라미터 개수 1 + setup 앞 파라미터 28바이트. Wireshark에서 `Subcommand` 필드를 클릭하면 바이트 창에서 위치를 직접 확인할 수 있습니다.

**B. 로그인 실패 반복**: DC가 짧은 시간에 `STATUS_LOGON_FAILURE`를 여러 번 돌려주면 알림.

```text
alert tcp $HOME_NET 445 -> any any (msg:"LOCAL SMB2 repeated logon failures from server"; flow:from_server,established; content:"|FE|SMB"; offset:4; depth:4; content:"|6D 00 00 C0|"; offset:12; depth:4; detection_filter:track by_dst, count 5, seconds 60; classtype:unsuccessful-user; sid:1000003; rev:1;)
```

- `flow:from_server`: 이번에는 DC의 응답을 봅니다.
- `offset:12`의 `|6D 00 00 C0|`: SMB2 헤더의 상태 코드 칸. `0xC000006D`를 리틀 엔디안(거꾸로)으로 쓴 것입니다.
- `detection_filter:track by_dst, count 5, seconds 60`: 같은 목적지(대입을 시도한 클라이언트)가 60초 안에 5번을 넘으면 알림.

**C. ADMIN$ 공유 접근**: SMB2 Tree Connect로 `ADMIN$`에 연결하려는 요청.

```text
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"LOCAL SMB2 Tree Connect to ADMIN$ share"; flow:to_server,established; content:"|FE|SMB"; offset:4; depth:4; content:"|03 00|"; offset:16; depth:2; content:"A|00|D|00|M|00|I|00|N|00|$|00|"; classtype:policy-violation; sid:1000004; rev:1;)
```

- `offset:16`의 `|03 00|`: SMB2 명령 3번(Tree Connect).
- `A|00|D|00|…`: 윈도우는 경로를 UTF-16(글자마다 2바이트)으로 보내서 글자 사이에 `00`이 끼어 있습니다.

!!! warning "제출 전에 꼭 시험하세요"
    위 offset 값은 SMB 헤더 구조를 보고 계산한 것입니다. 반드시 Wireshark에서 실제 패킷과 맞춰 보고, PCAP에 규칙을 돌려 알림이 뜨는지 확인한 뒤 제출합니다.

## 규칙 넣고 시험하기 { #testing-rules }

```bash
sudo nano /etc/snort/rules/local.rules
grep -n "local.rules" /etc/snort/snort.conf
sudo snort -T -c /etc/snort/snort.conf
sudo snort -q -k none -A console -r case.pcap -c /etc/snort/snort.conf | grep LOCAL
```

- 1줄: `local.rules`에 규칙을 붙여 넣고 저장(nano: Ctrl+O 저장, Ctrl+X 종료).
- 2줄: `snort.conf`가 `local.rules`를 불러오는지 확인. 줄 앞에 `#`이 있으면 지워서 켭니다.
- 3줄: `-T`는 시험 모드. 문법이 틀리면 몇 번째 줄인지 알려 줍니다. `Snort successfully validated the configuration!`이 나오면 성공.
- 4줄: `-A console`은 알림을 화면에 바로 출력합니다. `grep LOCAL`로 직접 만든 규칙의 알림만 봅니다.

```text
xx/xx-xx:xx:xx.xxxxxx  [**] [1:1000001:1] LOCAL SMBv1 NT Trans request - possible MS17-010 EternalBlue [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 172.xx.xx.xx:49xxx -> <DC_IP>:445
```

알림이 안 뜨면: 규칙의 바이트와 offset을 실제 패킷과 비교하고, `$HOME_NET`에 실습 대역이 들어 있는지 확인합니다(`grep "ipvar HOME_NET" /etc/snort/snort.conf`). 규칙을 고칠 때마다 `rev`를 1씩 올립니다.

## Wireshark에서 규칙용 바이트 찾기 { #bytes-in-wireshark }

1. 찾은 공격 패킷을 클릭합니다.
2. 상세 창에서 `SMB Header → SMB Command`(또는 SMB2 `Command`, `NT Status`)를 클릭하면 아래 바이트 창에 그 바이트가 강조됩니다.
3. 우클릭 → **Copy → …as Hex**로 복사해 `content:"|…|"`에 넣습니다.
4. **NetBIOS Session Service** 줄이 TCP 데이터의 시작(offset 0)입니다. 거기서부터 몇 바이트 뒤인지 세면 `offset`입니다.

!!! note "이 섹션의 성격"
    개인 학습 노트입니다. 어떤 기관의 공식 지침도 아닙니다.
