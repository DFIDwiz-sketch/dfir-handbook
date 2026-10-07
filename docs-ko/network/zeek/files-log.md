---
title: files.log와 pe.log
tags:
  - artifact
  - network
  - zeek
  - files
---

# Zeek `files.log`와 `pe.log` { #zeek-fileslog-pelog }

<div class="dfir-meta" markdown>
**분류:** 네트워크 · **출처:** Zeek · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    Zeek이 이해하는 모든 프로토콜(HTTP, SMTP, FTP, SMB, IRC, TLS 인증서…)로 오가는 파일마다 추정 타입, 크기, 해시, 실어 나른 연결이 이곳에 한 줄씩 기록됩니다. `pe.log`는 Windows 실행 파일의 헤더 정보를 더합니다 — 그래서 "네트워크로 무엇이 다운로드/업로드/복사됐고, 그게 악성인가"를 pcap을 열지 않고 답하는 곳입니다.

## `files.log` 필드 { #fileslog-fields }

| 필드 | 의미 | 분석 메모 |
|---|---|---|
| `ts` | 파일을 처음 본 시각 | |
| `fuid` | 파일 고유 ID | 결합 키: `http.log resp_fuids/orig_fuids`, `smtp.log fuids`, `ssl.log cert_chain_fuids`, `smb_files.log fuid`, `pe.log id` |
| `uid` (Zeek 6+) / `conn_uids` (구버전) | 실어 나른 연결 | → [`conn.log`](conn-log.md) |
| `id.orig_h`, `id.resp_h` (6+) / `tx_hosts`, `rx_hosts` (구버전) | 보낸 쪽 / 받은 쪽 | HTTP 다운로드라면: `tx` = 서버, `rx` = 클라이언트 |
| `source` | 프로토콜: `HTTP`, `SMTP`, `FTP_DATA`, `SMB`, `SSL` (인증서), `IRC_DATA`, `KRB` | |
| `depth` | 중첩 깊이 (예: MIME 안) | |
| `analyzers` | 붙은 분석기: `MD5`, `SHA1`, `SHA256`, `PE`, `EXTRACT`, `X509` | 해시가 비어 있으면 분석기가 로드되지 않은 것 |
| `mime_type` | 매직 바이트로 **추정한** 타입 | HTTP 헤더 / 파일명보다 이걸 믿을 것 |
| `filename` | `Content-Disposition`, URI, SMB 경로, MIME에서 | HTTP에서는 비어 있는 경우가 많음 |
| `duration` | 전송 시간 | |
| `local_orig` | 보낸 쪽이 내부인지 | |
| `is_orig` | 연결 시작 측이 보낸 파일인가? | `T` = 클라이언트의 **업로드**, `F` = 다운로드 |
| `seen_bytes` / `total_bytes` | Zeek이 본 바이트 / 선언된 크기 | 다르면 → 잘림 (`missing_bytes`, `overflow_bytes`) |
| `missing_bytes`, `overflow_bytes`, `timedout` | 공백 / 크기 초과 / 시간 초과 | 하나라도 0이 아니면 해시를 믿기 어려움 |
| `parent_fuid` | 컨테이너 파일 | 예: 이메일 안의 첨부 파일 |
| `md5`, `sha1`, `sha256` | 해시 (분석기가 켜져 있다면) | **이것으로 위협 인텔리전스를 검색** |
| `extracted` | 추출된 사본 경로 (`EXTRACT`가 켜져 있다면) | `extract_files/HTTP-FdvK1A3z4tPEujBU9c.exe` |
| `extracted_cutoff`, `extracted_size` | 추출 잘림 정보 | |

## `pe.log` 필드 (Windows PE 파일만) { #pelog-fields-windows-pe-files-only }

| 필드 | 의미 | 분석 메모 |
|---|---|---|
| `id` | = `fuid` | |
| `machine` | `I386`, `AMD64`, `ARM64` | |
| `compile_ts` | PE 헤더 타임스탬프 | 미래 / 아주 오래됨 / 다른 샘플과 일치 → 위조 또는 패밀리 표식 |
| `os`, `subsystem` | `Windows XP`+, `WINDOWS_GUI` / `WINDOWS_CUI` (콘솔) | 실제로는 콘솔 로더인 "GUI" 앱; `NATIVE` = 드라이버 |
| `is_exe`, `is_64bit` | | `is_exe=F` = DLL/드라이버 |
| `uses_aslr`, `uses_dep`, `uses_code_integrity`, `uses_seh` | 보안 완화 기능 | 악성코드와 오래된 도구는 ASLR/DEP가 없는 경우가 많음 |
| `has_import_table`, `has_export_table`, `has_cert_table`, `has_debug_data` | 테이블 존재 여부 | 임포트 테이블 없음 → 패킹; `has_cert_table=T` → 서명됨 (서명은 호스트에서 확인) |
| `section_names` | 섹션 이름 | `.text .rdata .data .rsrc .reloc`가 정상; `UPX0`, `.vmp0`, `.themida`, 무작위 이름 → 패킹 |

## 해시와 추출 켜기 { #enabling-hashes-and-extraction }

기본으로는 MD5만 돕니다(배포판에 따라 아무것도 안 돌기도 함). `local.zeek`이나 명령줄에서:

```zeek
@load policy/frameworks/files/hash-all-files      # md5 + sha1 + sha256 for every file
@load policy/frameworks/files/extract-all-files   # write every file to extract_files/ (disk!)
# Or extract only executables:
event file_sniff(f: fa_file, meta: fa_metadata) {
    if ( meta?$mime_type && meta$mime_type == "application/x-dosexec" )
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
}
redef FileExtract::prefix = "/data/zeek/extract/";
redef FileExtract::default_limit = 50000000;      # 50 MB cap per file
```

```bash
zeek -C -r capture.pcap local policy/frameworks/files/hash-all-files policy/frameworks/files/extract-all-files
ls extract_files/            # HTTP-F..., SMTP-F..., SMB-F...  (named by source + fuid)
```

## 빠른 쿼리 { #quick-queries }

=== "zeek-cut / 셸"

    ```bash
    # All executables, scripts, archives and Office docs that crossed the wire
    zeek-cut -d ts fuid source id.orig_h id.resp_h mime_type filename total_bytes sha256 < files.log \
      | grep -E 'x-dosexec|x-msdownload|x-executable|zip|x-rar|x-7z|msword|officedocument|vnd.ms-|x-shellscript|hta|javascript|x-powershell'

    # Uploads (is_orig = T) leaving the network — exfil / web-shell uploads
    zeek-cut -d ts source id.orig_h id.resp_h mime_type total_bytes filename < files.log | awk -F'\t' '$0 ~ /\tT\t/'   # (add is_orig to the cut)

    # SMB file copies between internal hosts (lateral movement, staging)
    zeek-cut -d ts id.orig_h id.resp_h filename mime_type total_bytes < files.log | awk -F'\t' '$1 ~ /SMB/ || 1' | grep -F 'SMB'
    # better: smb_files.log
    zeek-cut -d ts id.orig_h id.resp_h action path name size < smb_files.log | grep -E 'WRITE|OPEN' | grep -iE '\.(exe|dll|ps1|bat|vbs|sys)\b'

    # Hash list for VT / intel lookup
    zeek-cut sha256 mime_type < files.log | awk '$2 ~ /dosexec|zip|msword|officedocument/ && $1!="-" {print $1}' | sort -u > hashes.txt

    # PE: unusual sections / no ASLR / console apps downloaded via HTTP
    zeek-cut id machine compile_ts subsystem uses_aslr has_import_table section_names < pe.log \
      | awk -F'\t' '$5=="F" || $6=="F" || $7 !~ /\.text/'

    # From a file back to the URL that served it
    grep -F 'FdvK1A3z4tPEujBU9c' http.log | zeek-cut -d ts id.orig_h host uri user_agent
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:files mime_type IN ("application/x-dosexec","application/x-msdownload","application/zip","application/x-rar","application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    | stats values(filename) as names values(source) as proto dc(id.resp_h) as receivers count by sha256, mime_type, total_bytes
    | sort - count
    ```

    위험한 파일 타입을 모두 해시별로 묶고, 어떤 파일명으로 이동했는지(`values(filename)`)와 몇 대가 받았는지(`dc(id.resp_h)`)를 나열합니다. 해시 하나가 여러 호스트에 다른 이름으로 도착한다면 웜이거나 횡적 이동 중에 뿌려지는 도구입니다.

    ```spl
    index=zeek sourcetype=zeek:files is_orig=true local_orig=true
    | eval MB=round(total_bytes/1024/1024,2)
    | stats sum(MB) as total_MB count by id.orig_h, id.resp_h, source
    | where total_MB > 50
    ```

    `is_orig=true`는 *클라이언트*가 파일을 보냈다(업로드)는 뜻이고, `local_orig=true`는 그 클라이언트가 내부에 있다는 뜻입니다. 내부→외부 쌍마다 업로드한 메가바이트를 더하고 50 MB를 넘는 것만 남기면 간단한 유출 헌팅이 됩니다.

## 분석 팁 { #analysis-tips }

!!! tip "해시 → 인텔리전스 → 호스트, 이 순서로"
    해당 시간대의 모든 실행 파일/압축 파일/Office 파일의 `sha256`을 뽑아 VirusTotal/MISP/EDR과 대조하고, 나쁜 해시마다 받은 호스트의 **Amcache**(같은 SHA-1 — `files.log`의 `sha1` 사용)와 **Prefetch**로 가서 도착하고 실행됐음을 증명하세요. pcap을 열지 않고 다운로드→실행 체인이 완성됩니다.

- **추정 MIME이 진실입니다.** `filename`과 HTTP `Content-Type`은 공격자가 정합니다. `filename=invoice.pdf`인데 `mime_type=application/x-dosexec`라면 그게 발견입니다.
- **일부만 받은 파일**: `missing_bytes > 0`이거나 `timedout = T`라면 해시가 VT와 맞지 않습니다 — 센서가 패킷을 놓친 것입니다. "알 수 없는 파일"이라고 하지 말고 그렇게 적으세요.
- **SMB 복사는 두 번 나타납니다**: `files.log`(`source=SMB`, 파일 분석기가 동작했다면)와 `smb_files.log`(`action=SMB::FILE_WRITE/OPEN/CLOSE`, `path=\\host\C$`, `name`). `ADMIN$`에 `*.exe`를 `WRITE`한 뒤 `dce_rpc.log`에 `CreateServiceW` / `StartServiceW` = **PsExec 방식 횡적 이동** (공격 기법 섹션 참고).
- **이메일 첨부 파일**: `source=SMTP`, `parent_fuid` 있음, `filename`은 MIME에서; `smtp.log`(`mailfrom`, `rcptto`, `subject`, `fuids`)와 결합하면 보낸 사람 → 받는 사람 → 첨부 → 해시가 한 줄에 나옵니다.
- **인증서도 파일입니다** (`source=SSL`, `mime_type=application/x-x509-user-cert`) — 그래서 `x509.log`가 `fuid`로 결합됩니다. "진짜" 파일을 셀 때는 걸러 내세요.
- **`pe.log` 빠른 위험 신호**: `compile_ts`가 `ts`와 몇 시간 차이 (막 빌드됨), 표준이 아닌 섹션 이름, `has_import_table=F`, 64비트 바이너리인데 `uses_aslr=F`, 설치 프로그램이라고 주장하는데 `subsystem=WINDOWS_CUI`.
- **추출 위생**: 추출한 악성코드는 살아 있는 악성코드입니다 — 격리된 분석 장비로 추출하고, 바쁜 센서에서는 `extract_files/`가 디스크를 금방 채울 수 있다는 점을 기억하세요. 운영 환경에서는 위의 MIME 필터 추출 스크립트를 쓰세요.
- **다 비어 있나요?** `analyzers`를 확인하세요 — `X509`만 있거나 비어 있다면 로그를 만들 때 해시 정책이 로드되지 않은 것입니다. pcap에 정책을 넣어 Zeek을 다시 돌리세요.

## 상관분석 { #correlation }

| 질문 | 다음에 볼 곳 |
|---|---|
| 어디서 와서 어디로 갔나? | `uid` → [`conn.log`](conn-log.md); `fuid` → [`http.log`](http-log.md) (`host`, `uri`), `smtp.log`, `smb_files.log`, `ftp.log` |
| 받은 호스트에서 실행됐나? | [Prefetch](../../windows/prefetch.md), [Amcache](../../windows/amcache.md) (SHA-1), `4688`/Sysmon `1`; [$MFT](../../windows/mft-usn.md)의 `Zone.Identifier`에 다운로드 URL이 있음 |
| 알려진 악성인가? | VirusTotal, MalwareBazaar, MISP; Suricata 파일 규칙 (`eve.json`의 `fileinfo` 이벤트가 md5/sha256을 공유) |
| 퍼졌나? | `id.resp_h` 전반에 `stats … by sha256`; `smb_files.log`에서 `ADMIN$`/`C$`로의 SMB 쓰기 |
| 무엇을 하나? | `extract_files/<fuid>`의 정적/동적 분석; 첫 확인은 `pe.log` |

## 참고 자료 { #references }

- [Zeek docs — files.log](https://docs.zeek.org/en/master/scripts/base/frameworks/files/main.zeek.html) · [pe.log](https://docs.zeek.org/en/master/scripts/base/files/pe/main.zeek.html)
- [Zeek File Analysis Framework](https://docs.zeek.org/en/master/frameworks/file-analysis.html)
- [MalwareBazaar (abuse.ch) — hash lookup](https://bazaar.abuse.ch/)
