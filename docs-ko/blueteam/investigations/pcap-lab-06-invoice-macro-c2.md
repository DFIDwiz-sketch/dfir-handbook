---
title: PCAP 실습 06 — 청구서 Word 매크로에서 Hancitor 유형 C2까지
tags:
  - blue-team
  - pcap
  - zeek
  - tshark
  - word-macro
  - hancitor
  - c2
---

# PCAP 실습 06 — 청구서 Word 매크로에서 Hancitor 유형 C2까지 { #lab-06 }

!!! abstract "사례 요약"
    `maricheika.net` 도메인의 윈도우 7 PC가 Internet Explorer로 `invoice_284615.doc`를 받았습니다. 이 문서에는 자동 실행 VBA 매크로가 들어 있었습니다. 약 2분 뒤 PC는 `api.ipify.org`로 공인 IP를 확인했습니다. 이어서 `perranrowsin.com`으로 2분마다 POST를 보냈고, 해킹된 워드프레스 사이트에서 파일 3개를 더 받았습니다. 이 통신 패턴은 **Hancitor**와 일치합니다(추정, 오프라인이라 해시 조회는 못 함).

| | |
|---|---|
| **증거** | `Phase1_PCAP_6.pcap`, 2018-10-01 18:37:28 – 18:58:35 UTC (21분) |
| **환경** | 인터넷이 막힌 리눅스 분석 VM, Zeek 4.x, tshark |
| **주 도구** | Zeek 로그 + `zeek-cut`, `awk`, `grep`. 더 쉬운 곳은 tshark |
| **실습 안내** | [트레이닝 → PCAP 침해사고 분석 실습 → 실습 6](../../training/pcap-ir-labs/lab-guide.md#lab-6) |

## 질문 { #questions }

1. 감염 날짜와 시각(UTC)
2. 감염 PC의 IP 주소
3. 감염 PC의 호스트 이름
4. 감염 PC의 MAC 주소
5. 윈도우 사용자 계정 이름
6. Word 문서의 해시, 그리고 안전하게 다룬 방법
7. 초기 감염에 쓰인 악성코드 종류
8. 감염 PC의 공인 IP 주소
9. 핵심 네트워크 정보(LAN 대역, 게이트웨이, 도메인, DC)
10. 침해 설명

## 답 한눈에 보기 { #answers }

| # | 답 | 상태 |
|---|---|---|
| 1 | **2018-10-01 18:38:00 UTC** (문서 HTTP 요청 시각. 파일 데이터는 18:38:01에 처음 보임) | 확인됨 |
| 2 | **172.16.1.125** | 확인됨 |
| 3 | **Anatoliy-PC** | 확인됨 |
| 4 | **b8:97:fa:74:de:c0** | 확인됨 |
| 5 | **anatoliy.demchuk** | 확인됨 |
| 6 | SHA256 `e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51` (MD5·SHA1은 [4단계](#safe-hash)) | 확인됨 |
| 7 | 자동 실행 VBA 매크로가 든 악성 Word 문서(다운로더). 통신은 **Hancitor**와 일치 | 매크로는 확인됨, 계열은 추정 |
| 8 | **31.44.188.95** | 확인됨 |
| 9 | 172.16.1.0/24, 게이트웨이 172.16.1.1, 도메인 maricheika.net, DC 172.16.1.3 Maricheika-DC | 확인됨 |
| 10 | [보고서](#report) 참고 | — |

---

## 0단계 — 준비와 Zeek 로그 만들기 { #step-0 }

```bash
cd ~/Investigation_6
ls                                             # PCAP 파일 이름 확인
sha256sum Phase1_PCAP_6.pcap | tee pcap.sha256 # 증거 해시부터 기록
mkdir zeek_full && cd zeek_full
zeek -C -r ../Phase1_PCAP_6.pcap local \
     frameworks/files/extract-all-files \
     policy/protocols/conn/mac-logging 2>/dev/null
ls
```

| 부분 | 이유 |
|---|---|
| `sha256sum ... \| tee pcap.sha256` | 분석하는 동안 증거가 바뀌지 않았다는 것을 나중에 증명합니다. `tee`는 화면에 보여 주면서 파일로도 저장합니다. |
| `mkdir zeek_full && cd zeek_full` | Zeek은 **지금 있는 폴더**에 로그를 씁니다. 전용 폴더를 쓰면 로그가 한곳에 모이고, 나중에 Zeek을 다시 돌려도 덮어써지지 않습니다. |
| `-C` | 체크섬 오류를 무시합니다. 보내는 PC에서 캡처하면 체크섬을 네트워크 카드가 계산하기 때문에 "틀린" 값으로 보일 때가 많습니다. `-C`가 없으면 Zeek이 그 패킷을 버릴 수 있습니다. |
| `-r ../Phase1_PCAP_6.pcap` | 실시간 인터페이스 대신 파일을 읽습니다. |
| `local` | 기본 정책 스크립트를 불러옵니다. 센서가 실제로 돌리는 것과 같습니다. |
| `frameworks/files/extract-all-files` | 전송된 모든 파일을 `extract_files/`에 저장합니다. 나중에 해시를 구하고 살펴볼 수 있습니다. |
| `policy/protocols/conn/mac-logging` | `conn.log`에 MAC 주소 칸(`orig_l2_addr`, `resp_l2_addr`)을 추가합니다. |
| `2>/dev/null` | 경고 메시지를 숨깁니다. |

`ls`를 하면 `conn.log`, `dns.log`, `http.log`, `files.log`, `dhcp.log`, `kerberos.log`, `ssl.log`와 `extract_files/` 폴더가 보여야 합니다.

---

## 1단계 — 전체 그림 { #step-1 }

### 캡처 시간 { #capture-window }

```bash
zeek-cut -u ts < conn.log | sort | sed -n '1p;$p'
```

```text
2018-10-01T18:37:28+0000
2018-10-01T18:58:35+0000
```

- `zeek-cut -u ts`는 시각 칸만 UTC로 바꿔서(`-u`) 출력합니다.
- `sort`로 시간 순서로 정렬하고, `sed -n '1p;$p'`로 첫 줄과 마지막 줄만 봅니다.
- 캡처는 **21분**입니다. 이후에 찾는 모든 이벤트는 이 안에 있어야 합니다.

=== "tshark 대안"

    ```bash
    TZ=UTC capinfos -a -e ../Phase1_PCAP_6.pcap
    ```

    `capinfos`(Wireshark와 같이 설치됨)는 첫 패킷과 마지막 패킷 시각을 바로 보여 줍니다. `TZ=UTC`는 분석 PC의 현지 시간이 아니라 UTC로 보이게 합니다.

### 내부 호스트 { #internal-hosts }

```bash
zeek-cut id.orig_h < conn.log | grep -E "^10\.|^172\.|^192\.168\." | sort | uniq -c | sort -rn
```

```text
    160 172.16.1.125
```

- `id.orig_h`는 연결을 **시작한** 호스트입니다.
- `grep`은 사설(RFC 1918) 주소만 남깁니다. 정확히는 172.16.0.0/12가 `172.16.`~`172.31.`이지만, 여기서는 `^172\.`로 간단히 걸러도 충분합니다.
- `uniq -c`로 주소마다 개수를 세고, `sort -rn`으로 많은 순서로 정렬합니다.
- **연결을 시작한 내부 호스트는 하나뿐입니다.** 감염 후보는 이 PC 하나입니다.

### DHCP로 호스트 이름과 MAC 찾기 { #dhcp-identity }

```bash
zeek-cut -u ts client_addr mac host_name < dhcp.log
```

```text
2018-10-01T18:37:28+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:37:32+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:40:20+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:42:31+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:45:48+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:47:40+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:52:29+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
```

윈도우 PC는 IP를 요청할 때 자기 호스트 이름(DHCP 옵션 12)을 같이 보냅니다. 그래서 `dhcp.log` 한 줄에 **IP, MAC, 호스트 이름**이 함께 나옵니다. 모든 줄이 같습니다: **172.16.1.125 · b8:97:fa:74:de:c0 · Anatoliy-PC** (2~4번 답).

=== "tshark 대안"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y "dhcp.option.hostname" \
           -T fields -e ip.src -e eth.src -e dhcp.option.hostname | sort -u
    ```

    `-Y`로 호스트 이름이 들어 있는 DHCP 패킷만 고르고, `-T fields -e`로 원하는 칸만 출력합니다. Wireshark 2.x에서는 `bootp.option.hostname`을 씁니다.

### Kerberos로 사용자 계정과 DC 찾기 { #kerberos }

```bash
zeek-cut client id.resp_h < kerberos.log | sort | uniq -c
```

```text
      5 -                               172.16.1.3
      2 anatoliy.demchuk/MARICHEIKA     172.16.1.3
      5 anatoliy.demchuk/MARICHEIKA.NET 172.16.1.3
      2 anatoliy-pc$/maricheika.net     172.16.1.3
      2 anatoliy-pc$/MARICHEIKA.NET     172.16.1.3
     12 ANATOLIY-PC$/MARICHEIKA.NET     172.16.1.3
```

| 값 | 의미 |
|---|---|
| `anatoliy.demchuk/...` | **사람** 계정입니다. 끝에 `$`가 없습니다 → 5번 답 |
| `anatoliy-pc$/...` | **컴퓨터** 계정입니다. 컴퓨터 계정은 항상 `$`로 끝나고 호스트 이름과 같습니다 |
| `/` 뒤의 글자 | Kerberos realm, 즉 AD 도메인 **MARICHEIKA.NET**입니다. 짧게 쓰든 길게 쓰든, 대소문자가 달라도 같은 도메인입니다 |
| `id.resp_h` = 172.16.1.3 | Kerberos(TCP/UDP 88)에 응답하는 서버 = **도메인 컨트롤러(DC)** |

=== "tshark 대안"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y "kerberos.CNameString" \
           -T fields -e ip.src -e ip.dst -e kerberos.CNameString -e kerberos.realm | sort | uniq -c
    ```

    `CNameString`은 Kerberos 요청과 응답에 들어 있는 클라이언트 이름입니다. 출발지·목적지 칸에서 클라이언트와 DC(172.16.1.3)가 주고받는 것을 볼 수 있습니다.

---

## 2단계 — 수상한 파일 찾기 { #step-2 }

```bash
zeek-cut -u ts tx_hosts rx_hosts source mime_type filename seen_bytes < files.log \
  | grep -i -E "msword|officedocument|ms-office|dosexec|zip"
```

```text
2018-10-01T18:38:01+0000   47.88.158.115   172.16.1.125   HTTP   application/msword   invoice_284615.doc   225280
```

| 칸 | 값 | 의미 |
|---|---|---|
| `ts` | 18:38:01 | Zeek이 파일 데이터를 처음 본 시각(응답 본문이 시작된 시각) |
| `tx_hosts` | 47.88.158.115 | 파일을 **보낸** 쪽(외부 서버) |
| `rx_hosts` | 172.16.1.125 | 파일을 **받은** 쪽, 감염 PC |
| `mime_type` | `application/msword` | Zeek은 이름이 아니라 파일 **내용**(매직 바이트)으로 종류를 정합니다 |
| `filename` | `invoice_284615.doc` | "청구서" 미끼. 악성 메일의 전형적인 주제입니다 |

`grep`은 Zeek이 Word 문서에 붙이는 종류 이름(`msword`, `officedocument`, `ms-office`), 실행 파일(`dosexec`), 압축 파일(`zip`)을 찾습니다. Word 문서 하나만 나왔고, **그 뒤에 EXE는 없었습니다.** 이 점이 뒤에서 중요합니다.

!!! tip "함정: 필드 이름을 틀리면 오류가 아니라 빈 칸이 나옵니다"
    처음에는 `seen_bytes` 대신 `seen_types`라고 입력했습니다. `zeek-cut`은 오류 없이 마지막 칸을 비워서 출력했습니다. 칸이 이상하게 비어 있으면 `head -8 files.log`로 로그 헤더의 필드 이름을 확인하세요.

### 문서를 준 URL { #doc-url }

```bash
zeek-cut -u ts id.resp_h host uri status_code resp_mime_types user_agent < http.log | grep -i msword
```

```text
2018-10-01T18:38:00+0000   47.88.158.115   pitchbocaraton.com   /?82a1=APYBKsCs3LUw   200   application/msword
    Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
```

- 전체 URL = `host` + `uri` → `http://pitchbocaraton.com/?82a1=APYBKsCs3LUw`
- `status_code 200` + `application/msword`: 서버가 실제로 문서를 돌려줬습니다.
- `Trident/7.0; rv:11.0`은 **Internet Explorer 11**입니다. `WOW64`는 64비트 윈도우 7(`NT 6.1`)에서 도는 32비트 IE라는 뜻입니다. 사용자가 **브라우저로** 파일을 받았고, 아마 메일 속 링크를 눌렀을 것입니다(추정).
- `http.log`는 **요청**이 시작된 시각(18:38:00)을, `files.log`는 파일 데이터를 처음 본 시각(18:38:01)을 적습니다. 1번 답은 **18:38:00 UTC**로 쓰고 1초 차이를 함께 적습니다.

=== "tshark 대안"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y "http.request" -T fields \
           -e frame.time_utc -e ip.dst -e http.host -e http.request.uri -e http.user_agent
    ```

    모든 HTTP 요청을 UTC 시각과 함께 보여 줍니다. 웹 접속 순서를 한 화면에서 읽을 때 편합니다.

---

## 3단계 — 문서보다 먼저 악성 활동이 있었나? { #step-3 }

18:38:00을 감염 시작으로 정하기 전에, 그 전에 수상한 것이 없었는지 확인합니다. 캡처는 18:37:28에 시작하므로 문서 요청까지 **32초**밖에 없습니다. 먼저 일어난 일이 거의 없겠지만, 그래도 확인합니다.

```bash
zeek-cut -u ts query answers < dns.log | awk -F'\t' '$1 <= "2018-10-01T18:38:01+0000"'
zeek-cut -u ts host uri < http.log     | awk -F'\t' '$1 <  "2018-10-01T18:38:00+0000"'
```

- `awk -F'\t'`는 탭(Zeek의 구분자)으로 칸을 나눕니다. `$1`은 첫 번째 칸, 즉 시각입니다.
- ISO 형식 시각은 **글자 그대로 비교**해도 됩니다. 큰 단위(연→월→일→시…)부터 적기 때문에 글자 순서가 곧 시간 순서입니다.
- 예상되는 결과: 윈도우 부팅·로그인 때의 질의(DC를 찾는 `_ldap._tcp…` SRV, `wpad`, `isatap`, `msftncsi`)와, 다운로드 직전의 `pitchbocaraton.com` 질의입니다. 다른 모르는 도메인이 있으면 사고 시작 시점이 더 앞으로 갑니다. 다른 수상한 것이 없으면 **문서 다운로드가 첫 악성 이벤트**입니다.

!!! tip "어떤 이벤트 직전을 보는 두 가지 방법"
    - `grep -B 15 "msword"`: 찾은 줄과 **그 앞 15줄**을 보여 줍니다(`-A`는 뒤, `-C`는 앞뒤). "바로 전에 무슨 일이?"를 빨리 볼 때 씁니다.
    - `awk -F'\t' '$1 <= "…"'`: 시간 범위를 정확히 자릅니다. 보고서용으로 씁니다.

---

## 4단계 — 문서를 안전하게 다루고 해시 구하기 (6번) { #safe-hash }

### 파일 ID와 Zeek이 미리 계산한 해시 { #fuid }

```bash
zeek-cut fuid mime_type seen_bytes md5 sha1 < files.log | grep -i msword
```

```text
F5VYtO3n6Uvp1v0TU1   application/msword   225280   41a3101af94fca79bbdb0db2a52994c0   103dc7e3100963f31c2280b129d8280b22194c72
```

- `fuid`는 Zeek이 파일에 붙인 ID입니다. 추출된 파일 이름이 `extract_files/extract-<시각>-HTTP-<fuid>`라서 fuid로 찾을 수 있습니다.
- Zeek은 기본으로 **MD5와 SHA1**만 계산하고 SHA256은 계산하지 않습니다.

### 안전한 복사, 파일 종류, SHA256 { #safe-copy }

```bash
cp extract_files/*F5VYtO3n6Uvp1v0TU1 evidence.doc.bin   # .bin: 더블클릭해도 Word로 안 열림
chmod a-x evidence.doc.bin                               # 모든 사용자의 실행 권한 제거
file evidence.doc.bin                                    # 확장자가 아니라 내용으로 종류 확인
md5sum evidence.doc.bin; sha1sum evidence.doc.bin; sha256sum evidence.doc.bin
```

```text
extract-1538419081.436962-HTTP-F5VYtO3n6Uvp1v0TU1: Composite Document File V2 Document, Little Endian,
Os: Windows, Version 6.1, Code page: 1252, Title: , Author: 444555, Template: Normal.dotm,
Last Saved By: win7home, Revision Number: 2, Name of Creating Application: Microsoft Office Word,
Create Time/Date: Mon Oct  1 12:17:00 2018, Last Saved Time/Date: Mon Oct  1 12:17:00 2018,
Number of Pages: 1, Number of Words: 3, Number of Characters: 20, Security: 0

e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51
```

| 항목 | 값 |
|---|---|
| 크기 | 225,280 바이트 (`seen_bytes` = 디스크의 크기 → 파일 전체를 받음) |
| MD5 | `41a3101af94fca79bbdb0db2a52994c0` |
| SHA1 | `103dc7e3100963f31c2280b129d8280b22194c72` |
| SHA256 | `e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51` |

**`file` 메타데이터에서 보이는 수상한 점**

| 항목 | 왜 수상한가 |
|---|---|
| `Composite Document File V2` | 예전 OLE `.doc` 형식입니다. VBA 매크로를 담을 수 있습니다 |
| 작성·저장일 **2018년 10월 1일** | 감염과 같은 날짜입니다. 갓 만든 문서입니다 |
| `Number of Words: 3`, `Characters: 20` | 진짜 청구서라면 내용이 있어야 합니다. 악성 문서는 보통 "콘텐츠 사용" 그림 한 장만 넣습니다 |
| `Author: 444555`, `Last Saved By: win7home` | 의미 없는 이름입니다 |

**왜 안전한가**: 네트워크도 Microsoft Office도 없는 격리된 리눅스 VM에서 작업하므로 매크로가 실행될 수 없습니다. 문서는 한 번도 열지 않고 `file`, `strings`, 해시 도구로 읽기만 합니다. `.bin` 이름과 `chmod a-x`로 실수로 더블클릭하는 것을 막습니다. VirusTotal에는 **해시만** 조회합니다(파일은 절대 올리지 않음). 샘플은 비밀번호 zip으로 보관합니다(`zip -P infected evidence.zip evidence.doc.bin`).

=== "tshark 대안"

    ```bash
    mkdir objs && tshark -r ../Phase1_PCAP_6.pcap -q --export-objects http,objs
    file objs/* | grep -i composite        # 어떤 파일이 Word 문서인지 찾기
    sha256sum "objs/<file이 보여 준 이름>"
    ```

    `--export-objects http,objs`는 모든 HTTP 파일을 `objs/`로 꺼냅니다(Wireshark의 *File → Export Objects → HTTP*와 같음). 파일 이름은 URI에서 오므로, `file`로 종류를 보고 문서를 찾습니다. 해시는 Zeek 결과와 같아야 합니다.

---

## 5단계 — Office 없이 매크로 찾기 (7번) { #macro }

보통은 oletools의 `olevba`를 쓰지만, 설치돼 있지 않았고 VM에 인터넷도 없었습니다(`which olevba oleid` 결과 없음). 그래도 `strings`는 쓸 수 있습니다.

```bash
strings -n 6 evidence.doc.bin | grep -i -E "vba|autoopen|document_open|shell|powershell|cmd|http|createobject"
```

```text
http://ns.adobe.com/xap/1.0/  ... xmp:CreatorTool="Adobe Photoshop CC 2017 (Windows)" ...
<b:Sources ... xmlns:b="http://schemas.openxmlformats.org/officeDocument/2006/bibliography"> ...
1VBA.@Create
Document_Open
CreateObject
ShellV
```

- `strings -n 6`은 읽을 수 있는 글자가 6개 이상 이어진 부분만 출력합니다. `grep -i -E`는 키워드 중 하나라도 있는 줄을 대소문자 구분 없이 남깁니다.
- `ns.adobe.com`, `schemas.openxmlformats.org` 줄은 **정상 메타데이터**입니다. Photoshop XMP 블록은 그림이 들어 있다는 뜻이고, 아마 "콘텐츠 사용" 미끼 그림입니다(추정).

| 문자열 | 의미 |
|---|---|
| `VBA` | VBA 프로젝트가 있음 |
| `Document_Open` | 문서를 **열자마자** 매크로가 실행됨("콘텐츠 사용"을 누른 뒤) |
| `CreateObject` | 윈도우 COM 객체(파일 시스템, 셸, HTTP)를 불러 씀 |
| `Shell` | 프로그램이나 명령을 실행함 |

이 조합은 **악성 자동 실행 매크로**입니다. VBA 코드는 파일 안에 압축돼 있어서 `strings`로는 키워드만 보이고 전체 코드는 안 보입니다. 다운로드 URL도 보이지 않고, 문서 뒤에 EXE를 받은 기록도 없습니다. 이 시기 Hancitor 매크로는 악성코드를 **문서 안에** 넣어 두었다가 PC에 꺼내 실행하는 경우가 많았습니다(추정).

??? note "oletools가 있다면"
    ```bash
    oleid evidence.doc.bin      # 요약: VBA 매크로가 있나? 암호화됐나?
    olevba -a evidence.doc.bin  # 분석 표만: AutoExec / Suspicious / IOC
    olevba --decode evidence.doc.bin  # 난독화된 문자열도 풀어서 보기
    ```
    `AutoExec`과 `Suspicious`(Shell, CreateObject) 줄이 나오면 같은 결론이 확인되고, `IOC` 줄에는 URL이 나옵니다.

---

## 6단계 — 문서 이후에 무슨 일이? { #post-infection }

```bash
zeek-cut -u ts id.resp_h host method uri status_code resp_mime_types user_agent < http.log \
  | awk -F'\t' '$1 >= "2018-10-01T18:38:01+0000"'
```

```text
18:40:20  54.243.179.137   api.ipify.org          GET   /                                          200  text/plain  Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
18:40:20  62.109.30.243    perranrowsin.com       POST  /4/forum.php                               200  text/plain  Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
18:40:21  205.186.179.236  stopfuckinaround.com   GET   /wp-content/plugins/google-sitemap-generator/1  200  -       Mozilla/5.0 (Windows NT 6.1; Win64; x64; ...)
18:40:27  62.109.30.243    perranrowsin.com       POST  /mlu/forum.php                             200  -           Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR ...)
18:40:29  205.186.179.236  stopfuckinaround.com   GET   /wp-content/plugins/google-sitemap-generator/2  200  -       Mozilla/5.0 (Windows NT 6.1; Win64; x64; ...)
18:40:29  205.186.179.236  stopfuckinaround.com   GET   /wp-content/plugins/google-sitemap-generator/3  200  -       Mozilla/5.0 (Windows NT 6.1; Win64; x64; ...)
18:40:30  62.109.30.243    perranrowsin.com       POST  /d2/about.php                              200  -           Mozilla/4.0 (compatible; MSIE 7.0; ...)
18:42:30  62.109.30.243    perranrowsin.com       POST  /4/forum.php                               200  text/plain  Mozilla/5.0 (Windows NT 6.1; Win64; x64; ...)
18:44:31  ... POST /4/forum.php
18:46:31  ... POST /4/forum.php
18:48:32  ... POST /4/forum.php
18:50:33  ... POST /4/forum.php
18:52:34  ... POST /4/forum.php
18:54:34  ... POST /4/forum.php
18:56:35  ... POST /4/forum.php
```

*(폭을 줄이려고 날짜는 뺐습니다. 모두 2018-10-01, UTC입니다.)*

### 읽는 법 { #reading-post-infection }

| 시각 | 이벤트 | 의미 |
|---|---|---|
| 18:38:00 | 문서 다운로드 | 전달(delivery) |
| 18:38~18:40 | **약 2분 20초 동안 HTTP 없음** | 사용자가 문서를 열고 "콘텐츠 사용"을 누른 시간(추정) |
| 18:40:20 | `GET api.ipify.org/` | 악성코드가 "내 공인 IP가 뭐지?"라고 물음 |
| 18:40:20 | `POST /4/forum.php` | 첫 C2 체크인. 피해 PC 정보를 보냄 |
| 18:40:21~29 | `GET .../google-sitemap-generator/1, /2, /3` | **해킹된 워드프레스 사이트**에서 추가 악성코드 3개를 받음. 종류가 `-`라는 것은 Zeek이 종류를 몰랐다는 뜻이고, 암호화된 파일에서 흔합니다(추정) |
| 18:40:27, 18:40:30 | `POST /mlu/forum.php`, `/d2/about.php` | **다른** 악성코드, 즉 방금 받은 추가 악성코드의 체크인(추정) |
| 18:42:30 → 18:56:35 | `POST /4/forum.php` **약 120초마다** | **비콘**: 주 악성코드가 정해진 시간마다 C2에 연락함 |

### User-Agent로 요청을 보낸 프로그램 구분하기 { #user-agent }

| 요청 | User-Agent | 판단 |
|---|---|---|
| 문서 다운로드 | `Windows NT 6.1; WOW64; Trident/7.0; rv:11.0` | 사용자의 진짜 32비트 IE 11 |
| ipify, `/4/forum.php`, 워드프레스 `/1 /2 /3` | `Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0` | IE처럼 보이지만 진짜 브라우저와 **다름** → 다른 프로그램(1단계 악성코드) |
| `/mlu/forum.php`, `/d2/about.php` | `Mozilla/4.0 (compatible; MSIE 7.0; …)` | 2018년 윈도우 7에서 IE 7은 말이 안 됨 → **또 다른** 프로그램에 박혀 있는 문자열 |

PC 한 대에 진짜 브라우저 하나와 악성코드 User-Agent 두 개가 있습니다. 목적지별로 User-Agent를 비교하는 것은 사용자 웹 서핑과 악성코드를 구분하는 가장 빠른 방법 중 하나입니다.

### 비콘 간격 재기 { #beacon-interval }

```bash
zeek-cut ts uri < http.log | grep "/4/forum.php" | awk '{ if (prev) print $1 - prev; prev = $1 }'
```

- `-u`를 빼면 `ts`가 초 단위 숫자(epoch)로 나오므로 `awk`로 뺄셈을 할 수 있습니다.
- `prev`는 바로 앞 줄의 시각입니다. 지금 시각에서 앞 시각을 빼면 간격이 나옵니다.
- 연속된 POST 사이 간격은 매번 약 **120초**입니다(위 시각 18:42:30 → 18:44:31 → 18:46:31 …에서 계산). 이렇게 일정한 간격은 비콘입니다. 사람은 이렇게 규칙적으로 움직이지 않습니다.

### 왜 "Hancitor"인가 (그리고 왜 추정인가) { #family }

아래 순서는 2018년 Hancitor의 잘 알려진 패턴입니다.

1. 매크로가 든 Word 문서
2. `api.ipify.org`로 IP 확인
3. `/4/forum.php`로 POST
4. 해킹된 워드프레스 경로에서 번호 붙은 파일들을 GET
5. `/mlu/forum.php`, `/d2/about.php`로 추가 체크인(추가 정보 탈취 악성코드)

**확인된 것:** 매크로 문서 → IP 확인 → C2 POST → 추가 다운로드 → 2분 간격 비콘.
**추정인 것:** 계열 이름. 인터넷이 막혀서 해시를 조회하지 못했습니다. 보고서에는 *"Hancitor"*가 아니라 *"consistent with Hancitor"*로 씁니다.

---

## 7단계 — 감염 PC의 공인 IP (8번) { #public-ip }

PC는 사설 주소를 쓰고, 밖으로 나갈 때 게이트웨이의 NAT가 공인 주소로 바꿔 줍니다. LAN 안에서 캡처한 pcap에는 그 공인 주소가 패킷 헤더에 보이지 않습니다. 대신 **IP 확인 서비스의 응답**에 들어 있습니다. `api.ipify.org`는 물어본 쪽의 공인 IP를 글자 하나로 돌려줍니다.

```bash
zeek-cut host uri resp_fuids < http.log | grep ipify   # 응답의 파일 ID 찾기
cat extract_files/*FGnsSi1OKpfguaYN9d; echo              # 응답 본문 보기
```

```text
31.44.188.95
```

- `resp_fuids`는 응답 본문의 ID입니다. Zeek은 이 본문도 다른 다운로드처럼 파일로 저장합니다.
- `echo`는 빠진 줄바꿈만 넣어 줍니다. 없으면 IP 뒤에 프롬프트가 붙습니다.

=== "tshark 대안 (더 쉬움)"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y 'http.response and http.response_for.uri contains "ipify"' \
           -T fields -e http.file_data
    ```

    명령 하나로 끝나고 파일 ID도 필요 없습니다. ipify 요청에 대한 응답 본문을 바로 출력합니다. tshark 버전에 따라 16진수로 나오면 뒤에 `| xxd -r -p`를 붙입니다. Wireshark에서는 요청을 우클릭 → *Follow → HTTP Stream*을 열면 파란 글자(서버 응답)에 IP가 있습니다.

**8번 답: 31.44.188.95** (확인됨)

---

## 8단계 — 핵심 네트워크 정보 (9번) { #network-info }

### 도메인과 DC 호스트 이름 { #dc-name }

```bash
zeek-cut service < kerberos.log | sort | uniq -c
```

```text
      4 -
      1 anatoliy-pc$
      1 ANATOLIY-PC$
      2 anatoliy-pc$@MARICHEIKA.NET
      3 cifs/maricheika-dc.maricheika.net
      1 host/anatoliy-pc.maricheika.net
      1 krbtgt/MARICHEIKA
      1 krbtgt/maricheika.net
      9 krbtgt/MARICHEIKA.NET
      2 ldap/Maricheika-DC.maricheika.net
      1 ldap/Maricheika-DC.maricheika.net/maricheika.net
      2 LDAP/Maricheika-DC.maricheika.net/maricheika.net
```

`service`는 티켓을 요청한 대상 서비스입니다. `krbtgt/<REALM>`은 도메인의 티켓 발급 서비스이고, `ldap/…`와 `cifs/…`(파일 공유)는 **DC에 있는** 서비스입니다. 그래서 `/` 뒤의 이름이 DC입니다: **Maricheika-DC.maricheika.net**.

```bash
zeek-cut query answers < dns.log | grep -i -E "_ldap|_kerberos" | sort -u
```

```text
_ldap._tcp.dc._msdcs.maricheika.net                                   maricheika-dc.maricheika.net
_ldap._tcp.default-first-site-name._sites.domaindnszones.maricheika.net  maricheika-dc.maricheika.net
_ldap._tcp.default-first-site-name._sites.forestdnszones.maricheika.net  maricheika-dc.maricheika.net
_ldap._tcp.default-first-site-name._sites.maricheika.net              maricheika-dc.maricheika.net
...
```

`_ldap._tcp.dc._msdcs.<도메인>`은 윈도우가 "이 도메인의 DC가 누구야?"라고 묻는 DNS SRV 질의입니다. 응답이 DC 이름을 다시 확인해 줍니다.

=== "tshark 대안"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y "dns.flags.response == 1 && dns.qry.type == 33" \
           -T fields -e dns.qry.name -e dns.srv.target | sort -u
    ```

    `dns.qry.type == 33`은 SRV 레코드이고, `dns.srv.target`은 SRV가 가리키는 호스트입니다.

!!! note "`dhcp.log`에는 `localdomain`인데 왜 도메인이 `maricheika.net`인가?"
    `zeek-cut domain < dhcp.log`의 결과는 `localdomain`이었습니다. 이것은 **DHCP 서버**의 기본 접미사입니다(VMware NAT나 가정용 공유기에서 흔함). Active Directory 도메인이 아닙니다. AD 도메인은 Kerberos와 DNS에서 확인한 **maricheika.net**입니다. 이 결과는 DHCP 서버가 DC와 다른 장비라는 것도 보여 줍니다.

### 서브넷 마스크와 게이트웨이 { #mask-gateway }

`dhcp.log`에는 마스크와 게이트웨이 칸이 없습니다. Zeek 스크립트로도 출력할 수 있지만 tshark는 한 줄이면 됩니다. 여기서는 tshark가 더 알맞은 도구입니다.

```bash
tshark -r ../Phase1_PCAP_6.pcap -Y dhcp -T fields \
       -e ip.src -e dhcp.option.subnet_mask -e dhcp.option.router | sort -u
```

```text
0.0.0.0
172.16.1.125
172.16.1.254    255.255.255.0    172.16.1.1
```

| 줄 | 보낸 쪽 | 이유 |
|---|---|---|
| `0.0.0.0` | 아직 IP가 없는 PC(Discover / Request) | PC는 알려 줄 마스크·게이트웨이가 없음 → 빈 칸 |
| `172.16.1.125` | IP를 받은 뒤 갱신·정보 요청을 보내는 PC | 여전히 클라이언트 메시지 → 빈 칸 |
| `172.16.1.254 255.255.255.0 172.16.1.1` | **DHCP 서버**(Offer / ACK) | 옵션 1(마스크)과 옵션 3(게이트웨이)은 서버만 알려 줌 |

`sort -u`는 완전히 같은 줄을 하나로 합칩니다. 그래서 많은 DHCP 패킷이 세 줄이 됐습니다. 마스크 `255.255.255.0` = `/24`이고 PC IP가 172.16.1.125이므로, LAN은 **172.16.1.0/24**, 게이트웨이는 **172.16.1.1**, DHCP 서버는 **172.16.1.254**입니다.

??? note "Zeek만으로 게이트웨이 찾기"
    **MAC 주소로** (0단계의 `mac-logging` 스크립트가 필요): 인터넷으로 가는 패킷의 목적지 MAC은 게이트웨이입니다.

    ```bash
    zeek-cut id.resp_h resp_l2_addr < conn.log | grep -v "^172\.16\." | awk '{print $2}' | sort | uniq -c
    zeek-cut id.resp_h resp_l2_addr < conn.log | grep "^172\.16\." | grep <게이트웨이MAC> | sort -u
    ```

    **이벤트 스크립트로** (서버 응답의 마스크와 게이트웨이를 출력. 기존 로그를 덮어쓰지 않도록 빈 폴더에서 실행):

    ```bash
    zeek -C -r ../Phase1_PCAP_6.pcap -e 'event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) { if (!is_orig) print c$id$resp_h, options?$subnet_mask ? fmt("%s", options$subnet_mask) : "-", options?$routers ? fmt("%s", options$routers) : "-"; }'
    ```

### 9번 답 { #answer-9 }

```text
LAN segment range:  172.16.1.0/24 (172.16.1.0 - 172.16.1.255)
Default gateway:    172.16.1.1
DHCP server:        172.16.1.254
Domain:             maricheika.net
Domain Controller:  172.16.1.3 - Maricheika-DC
Infected client:    172.16.1.125 - Anatoliy-PC - b8:97:fa:74:de:c0 - anatoliy.demchuk
Public IP (NAT):    31.44.188.95
```

---

## 타임라인 { #timeline }

| UTC (2018-10-01) | 이벤트 | 출처 |
|---|---|---|
| 18:37:28 | 캡처 시작. Anatoliy-PC가 DHCP로 172.16.1.125를 받음 | dhcp.log |
| 18:38:00 | IE 11이 `pitchbocaraton.com/?82a1=APYBKsCs3LUw` 요청 | http.log |
| 18:38:01 | 응답에서 `invoice_284615.doc`(225,280 바이트)가 보임 | files.log |
| 18:40:20 | 공인 IP 확인, `api.ipify.org` → 31.44.188.95 | http.log, 추출된 응답 본문 |
| 18:40:20 | 첫 C2 POST `perranrowsin.com/4/forum.php` | http.log |
| 18:40:21~29 | `stopfuckinaround.com/wp-content/plugins/google-sitemap-generator/1~3`에서 추가 파일 3개 | http.log |
| 18:40:27, 18:40:30 | POST `/mlu/forum.php`, `/d2/about.php` (MSIE 7 UA) | http.log |
| 18:42:30 ~ 18:56:35 | 약 2분마다 POST `/4/forum.php` | http.log |
| 18:58:35 | 캡처 끝 | conn.log |

## 침해 지표 (IOC) { #iocs }

| 종류 | 지표 | 역할 |
|---|---|---|
| URL | `hxxp://pitchbocaraton[.]com/?82a1=APYBKsCs3LUw` | Word 문서 다운로드 |
| IP | `47.88.158[.]115` | pitchbocaraton.com |
| 파일 | `invoice_284615.doc`, SHA256 `e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51` | 매크로 문서 |
| URL | `hxxp://perranrowsin[.]com/4/forum.php`, `/mlu/forum.php`, `/d2/about.php` | C2 체크인 |
| IP | `62.109.30[.]243` | perranrowsin.com |
| URL | `hxxp://stopfuckinaround[.]com/wp-content/plugins/google-sitemap-generator/1` (`/2`, `/3`) | 추가 악성코드 |
| IP | `205.186.179[.]236` | 해킹된 워드프레스 서버 |
| 도메인 | `api.ipify[.]org` | IP 확인에 악용된 정상 서비스(참고용, 이것만으로 차단할 대상은 아님) |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; …)` | 추가 악성코드 |

## ATT&CK 매핑 { #attack }

| 기법 | 근거 |
|---|---|
| T1566.002 Phishing: Spearphishing Link | 브라우저가 링크로 문서를 받음(전달 경로는 추정) |
| T1204.002 User Execution: Malicious File | 사용자가 문서를 열고 콘텐츠를 허용함(2분 간격에서 추정) |
| T1059.005 Command and Scripting Interpreter: Visual Basic | 문서 안의 `Document_Open`, `CreateObject`, `Shell` |
| T1016.001 System Network Configuration Discovery: Internet Connection Discovery | `api.ipify.org` 조회 |
| T1071.001 Application Layer Protocol: Web Protocols | `/forum.php`로 HTTP POST C2 |
| T1105 Ingress Tool Transfer | `/1`, `/2`, `/3` 다운로드 |

## 보고서 (10번) { #report }

> At 18:38 UTC on 2018-10-01, user anatoliy.demchuk on Anatoliy-PC (172.16.1.125) used Internet Explorer to download a Word file, invoice_284615.doc, from pitchbocaraton.com. The file had an auto-run macro. About 2 minutes later, the PC checked its public IP (31.44.188.95) with api.ipify.org. It then sent C2 POSTs to perranrowsin.com every 2 minutes and downloaded 3 more files from another site. This matches Hancitor (not confirmed by hash). The PC should be isolated and rebuilt, and the user's password reset.

## 탐지 아이디어 { #detection }

=== "Zeek"

    ```bash
    # forum.php / about.php 게이트로 가는 POST
    zeek-cut -u ts id.orig_h host uri method < http.log | awk -F'\t' '$5=="POST" && $4 ~ /(forum|about)\.php$/'
    # IP 확인 서비스에 물어본 호스트 (살펴볼 대상이지 증거는 아님)
    zeek-cut -u ts id.orig_h host < http.log | grep -i -E "ipify|checkip|icanhazip|ip-api|myexternalip"
    # 최신 윈도우에서 나온 옛날 IE User-Agent
    zeek-cut id.orig_h host user_agent < http.log | grep "MSIE 7.0" | sort | uniq -c
    ```

=== "Snort 2"

    ```text
    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Hancitor-style gate POST forum.php"; flow:established,to_server; content:"POST"; http_method; content:"/forum.php"; http_uri; pcre:"/\/(4|mlu)\/forum\.php$/U"; classtype:trojan-activity; sid:1000601; rev:1;)
    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL External IP lookup api.ipify.org"; flow:established,to_server; content:"Host: api.ipify.org"; http_header; nocase; classtype:policy-violation; sid:1000602; rev:1;)
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:http method=POST uri IN ("*/forum.php", "*/about.php")
    | stats count min(_time) as first max(_time) as last values(uri) as uris by id.orig_h host
    | eval span_min=round((last-first)/60,1)
    ```

    인덱스와 소스타입 이름은 Zeek 로그를 어떻게 넣었는지에 따라 다르므로 맞게 바꿉니다. `streamstats`로 간격을 분석하는 방법은 [비콘과 C2](../../network/beaconing-c2.md)를 보세요.

## 교훈 { #lessons }

- **내부 호스트가 하나**면 트리아지가 빠릅니다. 그래도 IP, MAC, 호스트 이름은 두 곳(DHCP + Kerberos/conn)에서 확인합니다.
- **"문서 뒤에 EXE가 없다"**가 "감염이 없다"는 뜻은 아닙니다. 악성코드가 문서 안에 있을 수 있으니, 이어지는 통신을 봅니다.
- **User-Agent를 비교합니다.** 사용자의 진짜 브라우저와 다른 문자열, 또는 말이 안 되는 문자열(2018년의 IE 7)은 악성코드를 가리킵니다.
- **질문마다 맞는 도구를 씁니다.** 전체 그림, 파일, HTTP는 Zeek이 좋고, DHCP 옵션이나 응답 본문 하나를 읽을 때는 tshark가 더 쉽습니다.
- **오타 확인.** `zeek-cut` 칸이 비어 있으면 대부분 필드 이름을 잘못 쓴 것입니다.
- **확인된 것과 추정을 구분합니다.** 해시를 조회할 수 없을 때의 악성코드 계열 이름은 특히 그렇습니다.
