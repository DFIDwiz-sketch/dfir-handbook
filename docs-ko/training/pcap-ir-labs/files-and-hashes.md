---
title: "3 — 다운로드·파일·해시"
tags:
  - training
  - incident-response
  - zeek
  - file-extraction
  - hashing
---

# 3 — 다운로드·파일·해시 { #files-and-hashes }

!!! abstract "이 페이지의 범위"
    - 모든 다운로드를 전체 URL과 크기까지 목록으로 만들기
    - HTTP, SMB, TFTP, FTP, 이메일에서 파일을 열지 않고 꺼내기
    - 안전한 취급, 진짜 파일 종류, MD5·SHA1·SHA256 구하는 순서
    - Zeek `uid`와 `fuid`로 다운로드 하나를 여러 로그에서 따라가기("Bro UID" 문제)
    - 다운로드마다 기록할 핵심 정보, Word 문서의 매크로 읽기

## 다운로드 목록 만들기 { #listing-downloads }

Zeek는 파일 종류를 이름이 아니라 **내용**으로 정합니다. 윈도우 실행파일의 이름을 `radiance.png`로 바꿔도 `application/x-dosexec`로 잡힙니다.

```bash
zeek-cut -u ts id.orig_h id.resp_h host uri resp_fuids resp_mime_types < zeek_out/http.log | grep -i -E "dosexec|msword|officedocument|zip|octet"
zeek-cut -u ts source mime_type filename seen_bytes md5 < zeek_out/files.log
zeek-cut -u ts id.orig_h id.resp_h command arg file_size < zeek_out/ftp.log
```

- `resp_mime_types`: 서버가 돌려준 것의 실제 종류. `dosexec` = 윈도우 실행파일, `msword`/`officedocument` = Word 문서.
- `resp_fuids`: 그 응답의 파일 ID([Zeek UID와 fuid](#zeek-uid) 참고).
- `files.log`의 `source`: 파일이 어느 프로토콜로 왔는지(HTTP, FTP_DATA, SMB 등). `seen_bytes`: Zeek가 실제로 본 바이트 수.
- `ftp.log`: `RETR <파일>`이 FTP 다운로드입니다.

개수 세기: 문제가 되는 파일(실행파일, 스크립트, 압축파일, 문서)만 셉니다. 같은 파일을 두 번 받았다면 해시가 같으니 하나로 세고 그렇게 적습니다.

Wireshark: **File → Export Objects → HTTP / SMB / TFTP**에서 Hostname, Content Type, Size, Filename을 읽습니다. **Statistics → HTTP → Request Sequences**는 어느 페이지가 어느 요청으로 이어졌는지 보여 줍니다.

## 전체 URL과 파일 크기 { #url-and-size }

```bash
zeek-cut host uri resp_mime_types < zeek_out/http.log | grep dosexec | awk -F'\t' '{print "http://"$1$2}' | sort -u
zeek-cut -u ts host uri status_code response_body_len resp_mime_types < zeek_out/http.log | grep dosexec
tshark -r case.pcap -Y 'http.response && http.content_type contains "application"' -T fields -e frame.number -e http.response_for.uri -e http.content_type -e http.content_length
stat -c "%s bytes  %n" "http_objs/<file>"
```

- 1줄: `http://` + host + uri로 답안에 바로 쓸 URL을 만듭니다. `sort -u`는 중복을 지웁니다.
- `response_body_len`: 서버가 보낸 본문 크기(바이트).
- `http.response_for.uri`: 그 응답이 어느 URL에 대한 것인지 전체 URL로. `http.content_length`: 서버가 헤더에 적은 크기.
- `stat -c "%s bytes %n"`: 꺼낸 파일의 실제 크기. 서버가 적은 크기와 다르면 캡처에서 일부가 빠진 것이니 두 값을 모두 적습니다.
- Wireshark에서는 요청 패킷의 상세 창에 **[Full request URI]**가 있습니다. 우클릭 → **Copy → Value**.

## 파일 꺼내기 { #extracting }

```bash
for p in http smb tftp imf; do mkdir -p objs_$p; tshark -r case.pcap -q --export-objects $p,objs_$p; done
ls -l objs_*
```

- `--export-objects <프로토콜>,<폴더>`: 오간 파일을 열지 않고 폴더에 저장합니다.
- `imf`: 이메일 메시지를 `.eml`로 저장합니다(텍스트로 열면 보낸 사람, 제목, 첨부파일 이름이 보입니다).

Zeek도 파일을 꺼낼 수 있고, 파일 ID를 이름에 넣어 줍니다.

```bash
mkdir zeek_x && cd zeek_x
zeek -C -r ../case.pcap local frameworks/files/extract-all-files
ls extract_files/          # extract-<time>-HTTP-<fuid>
cd ..
```

FTP는 명령은 21번 포트로, 파일 내용은 별도의 데이터 연결로 보냅니다. 파일 이름은 tshark로 찾고, 내용은 Wireshark로 저장합니다.

```bash
tshark -r case.pcap -Y 'ftp.request.command == "RETR"' -T fields -e frame.time_utc -e ip.src -e ip.dst -e ftp.request.arg
```

Wireshark: **File → Export Objects → HTTP / SMB / TFTP / IMF** → **Save** 또는 **Save All**. FTP 데이터나 평문 TCP(예: netcat)는 필터 `ftp-data`(또는 **Statistics → Conversations → TCP**에서 큰 연결) → **Follow → TCP Stream** → **Show data as: Raw** → **Save as…**.

## 샘플 안전하게 다루기 { #safe-handling }

"안전하게 해시 구하기"는 파일을 한 번도 열거나 실행하지 않고, 실수해도 피해가 없는 곳에서 작업한다는 뜻입니다.

1. **격리된 분석 VM**: 인터넷·내부망이 끊긴 리눅스 VM, 시작 전에 스냅샷. 리눅스에는 Microsoft Office가 없어 실수로 더블클릭해도 매크로가 실행되지 않습니다.
2. **열지 않고 꺼내기**: tshark, Zeek, Export Objects로 PCAP에서 파일만 꺼냅니다.
3. **이름 바꾸고 실행 권한 빼기**: 무엇도 실수로 열거나 실행하지 못하게 합니다.
4. **내용으로 진짜 종류 확인.**
5. **해시 계산**(MD5, SHA1, SHA256).
6. **해시만 조회**: VirusTotal에 파일을 올리지 않고 해시만 검색합니다. 파일을 올리면 공격자가 탐지 사실을 알 수 있고, 문서 안의 내부 정보가 공개될 수 있습니다.
7. **보관과 정리**: 비밀번호 zip으로 보관하고, 끝나면 **스냅샷으로 되돌립니다**.

```bash
mkdir -p ~/case/doc && cd ~/case/doc
tshark -r ~/case/case.pcap -q --export-objects http,objs
file objs/* | grep -i -E "word|composite|zip|pe32"
cp "objs/<name>" evidence.bin
chmod a-x evidence.bin
md5sum evidence.bin; sha1sum evidence.bin; sha256sum evidence.bin
zip -P infected evidence.zip evidence.bin
```

- `cp … evidence.bin`: 확장자를 `.bin`으로 바꿔 더블클릭해도 Word로 열리지 않게 합니다. 이름만 바뀌고 내용은 같아서 해시도 같습니다.
- `chmod a-x`: 모든 사용자(`a`)에게서 실행 권한(`x`)을 뺍니다(`-`).
- `zip -P infected`: 악성코드 샘플을 주고받을 때 쓰는 업계 관례입니다. 백신이 지우거나 누가 실수로 여는 것을 막습니다.

[안전한 해시 답안 틀](report-templates.md#safe-handling-template)로 이 단계를 답안 문장으로 바꿀 수 있습니다.

## 진짜 파일 종류 확인 { #file-type }

```bash
file objs_http/*
```

```text
objs_http/<doc>        : Composite Document File V2 Document ...      ← 예전 .doc
objs_http/<docx>       : Microsoft Word 2007+                          ← .docx/.docm
objs_http/<file>       : PE32 executable (GUI) Intel 80386, for MS Windows
objs_http/radiance.png : PE32 executable ...                           ← 이미지로 위장한 exe
objs_http/<payload>    : data                                          ← 암호화됐을 수 있음
```

- 이름은 `.png`인데 내용이 `PE32 executable`이면 이미지로 위장한 실행파일입니다.
- 익스플로잇 킷 서버에서 온 수백 KB짜리 `data`는 **암호화된 페이로드**인 경우가 많습니다. 피해 PC가 받은 뒤 복호화하므로 PCAP만으로는 실제 EXE 해시가 나오지 않습니다. 답안에 "전송된 페이로드의 해시"라고 구분해 쓰고, 호스트에서 회수한 EXE가 따로 있는지 확인합니다.
- **Follow → HTTP Stream**에서 윈도우 실행파일 본문은 `MZ`로 시작하고 "This program cannot be run in DOS mode"가 들어 있습니다. 진짜 PNG는 `.PNG`로 시작합니다.

## 해시 구하기 { #hashing }

```bash
for f in objs_http/*; do if file "$f" | grep -q PE32; then echo "== $f"; md5sum "$f"; sha1sum "$f"; sha256sum "$f"; fi; done > exe_hashes.txt
zeek-cut fuid mime_type md5 sha1 < zeek_out/files.log | grep -i -E "dosexec|msword|officedocument"
sha256sum objs_http/* objs_smb/* | sort | uniq -w64 -D
```

- 반복문: 파일마다 `file` 결과에 `PE32`가 있으면(`grep -q`는 있다/없다만 알려 줌) 구분선과 해시 세 개를 출력하고, 전부 `exe_hashes.txt`에 저장합니다.
- `local`로 돌린 Zeek는 MD5·SHA1을 이미 계산해 두었습니다. 직접 구한 값과 같아야 합니다(SHA256은 기본으로 없음).
- 마지막 줄: `uniq -w64 -D`는 앞 64글자(SHA256)가 겹치는 줄을 모두 보여 줍니다. 즉 HTTP **와** SMB에 같은 파일이 있는지 찾습니다. 어떤 다운로드가 나중에 다른 호스트로 복사됐는지 이렇게 증명합니다.
- 윈도우: `Get-FileHash -Algorithm MD5 <파일>`(SHA1, SHA256도 같은 방식).

Wireshark에는 해시 기능이 없습니다. Export Objects로 저장한 뒤 터미널에서 해시를 구합니다. 특수문자(`%`, `&`, `?`)가 있는 파일 이름은 따옴표로 감쌉니다.

## Zeek UID와 fuid { #zeek-uid }

Bro는 Zeek의 옛 이름(2018년 개명)이라 "Bro UID"는 Zeek의 `uid` 칸입니다. Zeek는 **연결**마다 `C`로 시작하는 `uid`를, **파일**마다 `F`로 시작하는 `fuid`를 붙입니다. 이 ID로 로그를 서로 연결합니다.

```bash
zeek-cut -u ts uid id.orig_h id.resp_h host uri resp_fuids resp_mime_types < zeek_out/http.log | grep -i dosexec
zeek-cut fuid conn_uids mime_type < zeek_out/files.log | grep dosexec    # Bro / Zeek 5 이하
zeek-cut fuid uid mime_type < zeek_out/files.log | grep dosexec          # Zeek 6 이상
cd zeek_out && grep -l <UID> *.log && grep <UID> *.log
grep -l <fuid> *.log; ls ../zeek_x/extract_files/ | grep <fuid>
```

- 실행파일 줄의 `uid` = 그 파일을 실어 나른 연결("Bro UID").
- `grep -l <UID> *.log`: 그 연결이 나오는 로그 파일 **이름**만 보여 줍니다. 보통 `conn.log`, `http.log`, `files.log`.
- `fuid`로 한 단계 더 따라가면 `files.log`, `pe.log`(Zeek가 분석한 윈도우 실행파일 정보: 컴파일 시각, 32/64비트), 꺼낸 파일 `extract-…-<fuid>`가 연결됩니다.

```text
conn.log
files.log
http.log
```

Wireshark에는 Zeek UID가 없지만, TCP 연결마다 `tcp.stream` 번호를 붙입니다.

1. 그 UID의 클라이언트 포트 확인: `zeek-cut uid id.orig_p < zeek_out/conn.log | grep <UID>`.
2. 필터 `ip.addr==<infected IP> && tcp.port==<id.orig_p>`.
3. **Transmission Control Protocol → [Stream index: N]** 확인.
4. 필터 `tcp.stream eq N`: Zeek UID 하나와 같은 연결입니다.

## 다운로드 핵심 정보 { #download-key-info }

시각, 출발지 IP/포트, 목적지 IP/포트, 프로토콜, 바이트는 모두 다운로드 UID의 `conn.log` 한 줄에 있고, 프로토콜 세부 정보는 같은 UID의 `http.log`에 있습니다.

```bash
zeek-cut -u ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes < zeek_out/conn.log | grep <UID>
zeek-cut -u ts uid method host uri status_code user_agent response_body_len resp_mime_types < zeek_out/http.log | grep <UID>
tshark -r case.pcap -q -z "conv,tcp,tcp.stream eq N"
tshark -r case.pcap -Y "http.response && ip.dst==<infected IP>" -T fields -e http.server -e http.last_modified -e http.content_type | sort -u
```

- `id.orig_h/p` = 출발지 IP/포트(감염 호스트), `id.resp_h/p` = 목적지 IP/포트(서버).
- `proto` = 전송 프로토콜(tcp), `service` = 응용 프로토콜(http).
- `orig_bytes` / `resp_bytes` = 보낸 / 받은 바이트. `resp_bytes`는 파일 크기와 비슷해야 합니다.
- `-z "conv,tcp,<필터>"`: 그 연결만의 tshark 대화 표(시작 시각, 지속 시간, 방향별 바이트).
- `Server`, `Last-Modified` 헤더는 공격자 인프라의 특징입니다.

추가 조사용으로 다운로드마다 기록할 것: UTC 시각, 전체 URL, 도메인, 서버 IP·포트, 파일 이름, 크기, 진짜 종류, MD5·SHA1·SHA256, User-Agent, 서버 헤더, (VM 밖에서 조회한) 서버 IP 소유자. 이것이 프록시·방화벽 로그와 EDR에서 다른 피해자를 찾을 때 쓰는 IOC(침해 지표)입니다. 틀: [다운로드 핵심 정보](report-templates.md#download-template).

Wireshark: 필터 `tcp.stream eq N` → **Statistics → Conversations → TCP**에서 **Limit to display filter**를 체크하면 Address A/B, Port A/B, Bytes A→B / B→A, Rel Start, Duration이 한 줄에 보입니다.

## 악성 Word 문서와 매크로 { #macros }

악성 문서에는 보통 문서를 열면 자동 실행돼 다음 단계를 내려받는 VBA 매크로가 들어 있습니다. **oletools**는 아무것도 실행하지 않고 매크로를 읽어 줍니다. 격리 VM 안에서 씁니다.

```bash
pip install oletools
oleid evidence.bin
olevba -a evidence.bin
olevba --decode evidence.bin
```

- `oleid`: VBA 매크로, 암호화, 외부 링크가 있는지.
- `olevba -a`: 전체 코드 없이 분석 표만. `--decode`: 일부러 꼬아 둔 문자열(Base64, 16진수 등)도 풀어서 보여 줌.

```text
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|Suspicious|Shell               |May run an executable file or a system command|
|Suspicious|CreateObject        |May create an OLE object                     |
|IOC       |http://<domain>/<p> |URL                                          |
```

- `AutoExec`(`AutoOpen`, `Document_Open`): 문서를 열면 자동 실행.
- `Shell`, `WScript.Shell`, `powershell`: 윈도우 명령 실행.
- `URLDownloadToFile`, `XMLHTTP`, `IOC` URL: 인터넷에서 파일 다운로드.
- 이 조합이면 **매크로 다운로더**입니다. IOC URL을 PCAP의 다음 다운로드와 맞춰 봅니다.

```bash
zeek-cut -u ts id.orig_h host uri resp_mime_types < zeek_out/http.log | awk -F'\t' '$2=="<infected IP>"' | grep -A5 -i -E "msword|officedocument"
```

`grep -A5`는 문서 줄과 그 뒤 5줄을 함께 보여 줍니다. Wireshark에서는 문서 다음 요청들의 User-Agent를 비교합니다. 매크로나 PowerShell이 보낸 요청은 User-Agent가 브라우저와 다르거나 없는 경우가 많습니다.

!!! note "이 섹션의 성격"
    개인 학습 노트입니다. 어떤 기관의 공식 지침도 아닙니다.
