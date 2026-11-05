---
title: "2.8강 — Zeek: 네트워크 보안 모니터링, 로그 구조, jq, Community ID"
tags:
  - training
  - network-forensics
  - zeek
  - logs
---

# 2.8강 — Zeek: 네트워크 보안 모니터링, 로그 구조, jq, Community ID { #zeek }

!!! abstract "이번 회차의 범위"
    - 네트워크 보안 모니터링(NSM)이란 무엇이고, IDS와 무엇이 다른가
    - Zeek로 pcap 처리하기: `-r`, 정책, 그리고 [주의] 체크섬 오프로딩 때문에 로그가 통째로 사라지는 함정
    - 로그 파일의 종류, 공통 필드, `http.log`의 필드. [정정] 비밀번호 칸은 기본으로 비어 있다
    - TSV와 JSON, `zeek-cut`과 `jq`: 고르기, 뽑기, 시각 바꾸기, 배열 다루기, `uid`로 로그 사이를 오가기
    - `jq`의 속도: 먼저 `grep`으로 좁히기
    - 시그니처와 스크립트, [변경됨] JA3에서 JA4로
    - Community ID: 도구 사이를 오가는 흐름 식별자, 직접 계산해 보기
    - 조사용 Zeek 정책을 직접 꾸리기

!!! note "실습 환경과 표기"
    **(직접 실행 결과)**는 이 작업 환경의 **Zeek 9.0.1**(공식 Docker 이미지 `zeek/zeek`)과 jq 1.7, TShark 4.2.2로 얻었습니다. 분석한 pcap은 루프백에서 직접 만든 연습용 트래픽입니다. 2.5강의 Apache 연습 서버(`www.lab.example`, 8080번)에 보낸 HTTP 요청, 2.6강의 연습용 DNS 계층에 보낸 질의, 2.7강의 연습용 DoH 서버(`127.0.0.20`)와의 TLS 연결이 들어 있어요. 그래서 HTTP의 출발지와 목적지가 모두 `127.0.0.1`로 찍힙니다. Basic 인증의 계정과 비밀번호는 **연습용으로 만든 값**입니다. `jq` 속도 비교에는 무작위로 만든 **가짜 dns.log 150만 줄**을 썼습니다.

## 1. 네트워크 보안 모니터링과 Zeek { #nsm }

예전에는 **막는 것**이 최우선이었습니다. 침입 탐지 시스템(IDS), 침입 방지 시스템(IPS)이 나쁜 행동을 잡아 막아 주리라 기대했죠. 하지만 결국 예방은 언젠가 실패하고, 그때는 **튼튼한 증거**에 기반한 조사가 필요하다는 깨달음이 생겼습니다.

**네트워크 보안 모니터링(NSM)**은 그 깨달음에서 나왔습니다. 사고가 발견되기 **전부터** 증거를 모아 두어, 조사를 받쳐 줄 준비가 된 환경("포렌식 준비가 된(forensically ready)" 환경)을 만드는 거예요. "방어할 수 있는 네트워크"라는 전통적인 생각을 "언젠가 반드시 올 조사에 대비한 네트워크"로 바꾼 것이고, IDS·IPS가 NSM 기능을 받아들이며 진화한 것과도 나란합니다. 오늘날의 NSM 개념은 Richard Bejtlich의 책 *The Tao of Network Security Monitoring*과 *The Practice of Network Security Monitoring*이 크게 이끌었습니다.

비유하면 IDS는 **경보기**, NSM은 **블랙박스**입니다. 경보기는 정해진 일이 생기면 울리고, 울리지 않은 일은 남기지 않아요. 블랙박스는 무슨 일이 있었든 계속 기록해 두고, 나중에 "그때 무슨 일이 있었지?"에 답합니다. 비유가 깨지는 곳: 블랙박스는 영상을 통째로 남기지만, Zeek는 패킷을 통째로 남기지 않고 **프로토콜을 이해해서 요약한 기록**(로그)을 남깁니다. 그래서 훨씬 작고 검색하기 쉽지만, 기록하지 않은 세부는 없습니다(1.10강에서 본 "전체 패킷 대 요약" 문제).

**Zeek**(예전 이름 Bro)는 NSM의 대표 도구입니다.

- **목표가 다르다.** 전통적인 IDS가 내용 감시와 경보 생성·관리에 집중한다면, Zeek 개발진은 **트래픽의 가시성과 여러 프로토콜의 응용 계층 이해**를 우선합니다. 시그니처를 더할 수는 있지만(8절), 조사자가 매일 쓰는 주된 용도는 아닙니다.
- **무료이고 공개 소스**이며, 상용 지원은 Corelight라는 회사가 합니다. 사용자 공동체도 활발해요.
- **실시간과 pcap을 같은 방식으로** 처리합니다. 네트워크를 실시간으로 지켜보며 SIEM에 결과를 보내는 운영과, 이미 있는 pcap을 처리하는 포렌식을 **하나의 작업 흐름**으로 묶을 수 있어요. 조사팀이 침해된 시스템이나 구간 앞에 Zeek를 임시로 놓아 가시성을 높이는 전술적인 쓰임도 있습니다.
- **확장성**: 기본 분석기가 조사에서 만나는 프로토콜의 상당 부분을 다루고, 스크립트로 기능을 더할 수 있으며, 클러스터로 100Gb/s 트래픽을 처리한 사례도 있습니다.
- **응용 계층의 세션을 이해**합니다. 그래서 한 로그 줄에 **요청과 그 응답의 정보가 함께** 들어갑니다(2.7강의 `dns.log`에서 질의와 답이 한 줄이었던 것). 다른 용도의 도구를 끌어다 쓸 때보다 분석이 훨씬 쉬워져요.

여러 NSM 플랫폼이 Zeek를 단독으로 쓰거나 더 큰 도구 모음에 넣어 씁니다. Security Onion 배포판이 대표적인 예입니다.

## 2. pcap을 Zeek로 처리하기 { #running-zeek }

실시간 운영 설정은 이 강의의 범위 밖이고, 이미 있는 pcap을 처리하는 것은 간단합니다. `-r`로 입력 파일을 주면, **실행한 디렉터리**에 로그 파일들이 생깁니다.

```text
zeek -r lab.pcap                 # 기본 스크립트만
zeek -r lab.pcap local           # 사이트 정책(site/local.zeek)까지
zeek -r lab.pcap forensic.zeek   # 직접 만든 정책 파일(10절)
```

명령 끝의 이름은 **함께 불러올 스크립트(정책)**입니다. 아무것도 주지 않으면 기본 스크립트만 돌아요. 이 실습의 공식 이미지에서 `local`은 `/usr/local/zeek/share/zeek/site/local.zeek`이었습니다.

### 2.1 [주의] 체크섬 오프로딩: 로그가 통째로 사라진다 { #checksum }

연습용 pcap을 아무 옵션 없이 돌렸습니다.

**(직접 실행 결과)**

```text
$ zeek -r lab.pcap
warning in .../base/misc/find-checksum-offloading.zeek, line 54: Your trace file likely has
invalid TCP and UDP checksums, most likely from NIC checksum offloading.  By default, packets
with invalid checksums are discarded by Zeek unless using the -C command-line option or
toggling the 'ignore_checksums' variable. ...
$ ls
conn.log  packet_filter.log  reporter.log  weird.log
```

`http.log`도 `dns.log`도 **없습니다**. `weird.log`에는 `bad_TCP_checksum`, `bad_UDP_checksum`이 남았어요. 같은 pcap을 `-C`로 다시 돌리면:

```text
$ zeek -C -r lab.pcap
$ ls
conn.log  dns.log  files.log  http.log  packet_filter.log  ssl.log
```

무슨 일일까요? 요즘 운영체제는 체크섬 계산을 **네트워크 카드에 맡깁니다(체크섬 오프로딩)**. 그래서 보내는 컴퓨터 자신에서 캡처하면, 체크섬을 채우기 **전**의 패킷이 저장돼 체크섬이 틀린 것처럼 보여요. 이 pcap은 루프백에서 캡처해서 94개 패킷 중 28개가 그랬습니다(TShark로 확인). Zeek는 기본으로 **체크섬이 틀린 패킷을 버리므로**, 응용 계층 분석에 필요한 패킷이 사라져 HTTP와 DNS 로그가 아예 안 생긴 거예요.

**조사에서의 의미:** 포렌식 pcap이 모두 오프로딩 없는 장비에서 캡처됐으리라 기대할 수 없습니다. 증거 pcap을 처리할 때는 **`-C`(또는 `ignore_checksums = T`)를 기본으로** 쓰고, "이 pcap에는 HTTP가 없다"는 결론을 내리기 전에 `weird.log`와 `reporter.log`를 꼭 확인하세요. 반대로 실시간 센서(SPAN·TAP으로 받은 트래픽)에서 체크섬 오류가 많다면, 그건 실제로 깨진 패킷이거나 조작된 패킷일 수 있어 그 자체가 단서입니다.

## 3. 로그 파일의 종류와 형식 { #log-files }

Zeek는 하나의 통합 로그가 아니라, **관찰한 트래픽에 따라 수십 가지 로그 파일**을 만듭니다. SSL·TLS가 없던 시간대라면 그 시간의 `ssl.log`, `x509.log`는 아예 생기지 않아요. 관리자가 기능을 더하면 새로운 로그가 생기고, 기존 로그에 필드가 늘기도 합니다.

| 분류 | 로그 | 내용 |
| --- | --- | --- |
| 네트워크 프로토콜 | `conn.log` | TCP·UDP·ICMP 연결(NetFlow와 비슷, 1.10강) |
| | `dns.log` | DNS 활동(패시브 DNS와 같은 내용, 2.7강) |
| | `http.log` | HTTP 활동 |
| | `ssl.log` | TLS 협상(서버 이름, 버전, 암호 방식) |
| | `rdp.log`, `smtp.log`, `ssh.log` | 각 프로토콜의 활동 |
| 파일 메타데이터 | `files.log` | 파일 분석(해시, MIME 형식 등). 일부 프로토콜은 파일 내용 전체를 꺼낼 수도 있다 |
| | `smb_files.log` | SMB로 오간 파일 |
| | `x509.log` | 인증서 정보 |
| | `pe.log` | Windows 실행 파일(PE) |
| 관찰로 만드는 목록 | `known_hosts.log`, `known_services.log`, `software.log` | 관찰된 시스템, 서비스, 소프트웨어 목록 |
| 특수한 경우 | `signatures.log` | 시그니처 적중(8절) |
| | `weird.log` | 예상하지 못한 프로토콜 관찰(2.1절의 체크섬 오류 등) |
| | `intel.log` | 위협 정보 프레임워크 적중 |
| | `notice.log` | 걱정스러운 관찰(인증서 검증 오류, 무차별 대입 등) |

!!! info "[보충] \"매시 정각에 로그를 압축 보관한다\"는 운영 환경의 이야기"
    교재는 Zeek가 기본으로 **매시 정각에** 로그를 보관·압축한다고 합니다. 이건 ZeekControl이나 클러스터로 운영하는 실시간 센서의 기본 동작이에요. 이 실습처럼 `zeek -r`로 pcap을 처리할 때는 회전하지 않고 파일 하나씩만 만듭니다(Zeek 9.0.1에서 `Log::default_rotation_interval`을 출력하니 `0 secs`였습니다). 운영 센서의 로그를 받아 조사한다면 `conn.20:00:00-21:00:00.log.gz`처럼 **시간별로 나뉜 여러 파일**을 함께 봐야 전체 그림이 나옵니다.

### 3.1 TSV와 JSON { #tsv-json }

예전에는 **탭으로 구분한(TSV)** 형식이 기본이었고, **지금도 기본값은 TSV**입니다(Zeek 9.0.1에서 `LogAscii::use_json`이 `F`). 하지만 JSON 로그가 널리 쓰이는 흐름이 Zeek에도 와서, 실제 현장에서는 JSON을 아주 많이 만납니다.

TSV 로그는 머리말에 형식 정보가 있습니다.

**(직접 실행 결과, `http.log`의 머리말 일부)**

```text
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	...
#types	time	string	addr	port	addr	port	count	string	string	string	string	...
```

TSV에서 원하는 칸만 뽑을 때는 **`zeek-cut`**을 씁니다. 칸 번호가 아니라 **이름**으로 고르니, 버전마다 칸 순서가 달라도 안전해요. `-d`는 시각을 사람이 읽는 형식으로 바꿉니다.

**(직접 실행 결과)**

```text
$ zeek-cut -d ts uid method host uri status_code < http.log
2026-11-05T07:36:46+0000	CpYAlK2BmtOQIQBL0c	GET	www.lab.example	/	200
2026-11-05T07:36:46+0000	CpYAlK2BmtOQIQBL0c	GET	www.lab.example	/notes.txt	200
2026-11-05T07:36:46+0000	CpYAlK2BmtOQIQBL0c	GET	www.lab.example	/report.zip	200
2026-11-05T07:36:46+0000	CqNOtq2Enp8yKk3sE8	GET	www.lab.example	/admin/	401
```

JSON으로 쓰려면 `LogAscii::use_json=T`를 줍니다. 이 강의의 나머지는 JSON 기준이에요.

```text
zeek -C -r lab.pcap local policy/protocols/conn/community-id-logging LogAscii::use_json=T
```

## 4. 필드 읽기 { #fields }

JSON 로그는 어느 정도 **스스로 설명**합니다. 필드 이름 체계에 익숙해지는 데는 시간이 걸리지만 핵심은 단순해요. 여러 로그에 공통으로 나오는 필드가 있고, 나머지는 로그마다 다릅니다(관리자 설정으로 바뀌기도 함).

**공통 필드**

| 필드 | 뜻 |
| --- | --- |
| `ts` | 그 교환의 **첫 패킷**을 본 시각. 유닉스 시각, 마이크로초 단위 |
| `uid` | 연결의 고유 ID. 한 연결 안의 여러 HTTP 요청(Keep-Alive)을 묶거나, **여러 로그 파일을 넘나들 때** 쓰는 좋은 기준점 |
| `id` | 연결의 네 값(양쪽 주소와 포트)을 묶은 상위 필드. JSON에서는 `id.orig_h`(출발 주소), `id.orig_p`(출발 포트), `id.resp_h`(응답 주소), `id.resp_p`(응답 포트)로 펼쳐진다 |

`orig`(originator)는 연결을 **시작한** 쪽, `resp`(responder)는 **응답한** 쪽입니다. "출발지·목적지"가 아니라 "누가 먼저 연결했나"라는 점이 중요해요. UDP처럼 연결이 없는 경우에는 Zeek가 첫 패킷과 포트로 짐작합니다.

**`http.log`의 필드** (연습용 pcap의 한 줄, 직접 실행 결과)

```text
$ jq 'select(.uri=="/report.zip")' http.log
{
  "ts": 1793864206.74854,
  "uid": "CAU56U3BuXGG04UEil",
  "id.orig_h": "127.0.0.1",
  "id.orig_p": 33246,
  "id.resp_h": "127.0.0.1",
  "id.resp_p": 8080,
  "trans_depth": 3,
  "method": "GET",
  "host": "www.lab.example",
  "uri": "/report.zip",
  "version": "1.1",
  "user_agent": "curl/8.5.0",
  "request_body_len": 0,
  "response_body_len": 46,
  "status_code": 200,
  "status_msg": "OK",
  "tags": [],
  "resp_fuids": [ "FMxNrn1TAZX9SSFI3f" ],
  "resp_mime_types": [ "application/zip" ]
}
```

| 필드 | 뜻 |
| --- | --- |
| `trans_depth` | 이 연결 안에서 몇 번째 요청·응답인가. 이 줄은 **3**: 한 연결로 `/`, `/notes.txt`, `/report.zip`을 차례로 받은 세 번째 |
| `method`, `host`, `uri` | 요청 메서드, `Host` 헤더, 요청 경로 |
| `referrer` | `Referer` 헤더. Zeek 개발진은 표준 문서의 오타(`Referer`)가 아니라 **올바른 철자**를 골랐다 |
| `user_agent` | `User-Agent` 헤더 |
| `request_body_len`, `response_body_len` | 클라이언트·서버가 보낸 **압축을 푼** 본문 크기 |
| `status_code`, `status_msg` | 응답 코드와 문구 |
| `info_code`, `info_msg` | 마지막으로 본 1xx 응답 |
| `filename` | 응답의 `Content-Disposition` 헤더에 있는 파일 이름 |
| `tags` | 요청·응답의 여러 특징을 나타내는 표시 |
| `username`, `password` | Basic 인증의 사용자 이름과 비밀번호(아래 [정정] 참고) |
| `proxied` | 프록시를 거쳤음을 나타낼 수 있는 헤더들 |
| `orig_fuids`, `resp_fuids` | 요청·응답에 실린 파일의 고유 ID. `files.log`와 이어 준다 |
| `orig_mime_types`, `resp_mime_types` | 그 파일들의 MIME 형식(Zeek가 내용을 보고 판단) |

같은 연결(`uid`가 같은) 세 요청의 `user_agent`가 **요청마다** 남는다는 점도 확인했습니다. 첫 요청은 `LabBrowser/1.0`, 나머지 둘은 `curl/8.5.0`이었어요(연습용으로 일부러 첫 요청만 바꿈). 연결 단위가 아니라 요청 단위 기록이라는 뜻입니다.

!!! warning "[정정] `password` 칸은 기본으로 비어 있다"
    교재는 `password`를 "Basic 인증이 있으면 그 비밀번호"라고 소개하지만, Zeek는 **기본으로 비밀번호를 남기지 않습니다**(`HTTP::default_capture_password`의 기본값이 `F`, Zeek 9.0.1에서 확인). 같은 pcap에서:

    **(직접 실행 결과)**

    ```text
    기본값:                        {"uri":"/admin/","status_code":401,"username":"jdoe","password":null}
                                   {"uri":"/admin/","status_code":200,"username":"jdoe","password":null}
    HTTP::default_capture_password=T:
                                   {"uri":"/admin/","status_code":401,"username":"jdoe","password":"wrong"}
                                   {"uri":"/admin/","status_code":200,"username":"jdoe","password":"Lab-Practice-1"}
    ```

    `username`은 기본으로도 남고, 2.5강의 Apache처럼 **401(실패)에도 남습니다**. 비밀번호를 켜면 조사에는 도움이 되지만(어떤 비밀번호로 무차별 대입했나), 2.5강의 `mod_log_forensic`처럼 **로그 자체가 계정 유출 위험**이 됩니다. 켜야 한다면 기간과 접근 권한을 엄격히 하세요. 운영 센서의 로그에 `password`가 비어 있다고 "인증이 없었다"고 판단하면 안 되는 이유이기도 합니다.

!!! warning "[주의] 서버 로그의 200과 Zeek의 \"응답 없음\""
    연습용 CGI에 POST를 보낸 요청은 Apache의 접근 로그에 `"POST /cgi-bin/search.cgi HTTP/1.1" 200 0`으로 남았는데, Zeek의 `http.log`에는 `status_code`가 **비어 있었고** `conn.log`의 `resp_bytes`는 **0**, `history`는 `ShADafF`였습니다(응답 쪽의 데이터 `d`가 없음). curl도 "Empty reply from server"라고 했어요. 원인은 이 연습용 CGI의 동작으로 보이지만 끝까지 확인하지는 않았습니다(가설). 요점은 **서버 로그의 200이 "응답이 실제로 나갔다"는 증거는 아니라는 것**, 그리고 네트워크 쪽 기록(Zeek)과 서버 쪽 기록(접근 로그)을 맞대어 보면 이런 차이가 드러난다는 것입니다.

## 5. jq로 JSON 로그 다루기 { #jq }

**jq**는 Zeek만이 아니라 JSON 데이터 전반을 다루는 도구입니다. 기능이 아주 많지만, 조사에서 자주 쓰는 몇 가지만 익혀도 충분히 강력해요. 이 절의 명령은 모두 jq 1.7로 연습용 로그에 돌린 **직접 실행 결과**입니다.

### 5.1 보기 좋게 출력: `.` { #jq-pretty }

가장 단순한 쓰임은 JSON을 표준 입력으로 주고 **보기 좋게 다시 출력**하는 것입니다. `.`은 "입력 전체"라는 뜻이에요. 4절의 출력이 `select`를 더한 그 모양입니다. 운영 센서의 압축된 로그라면 `zcat http.20:00:00-21:00:00.log.gz | jq '.'`처럼 씁니다. 한 줄에 한 기록씩 보고 싶으면 `-c`(compact)를 붙입니다.

### 5.2 고르고 뽑기: `select()`와 `{ }` { #jq-select }

```text
$ jq -c 'select(.host=="portal.lab.example") | {ts, uid, "id.orig_h", "id.resp_h", host, status_code}' http.log
{"ts":1793864206.769968,"uid":"CiMdK3w2miyU2zLCc","id.orig_h":"127.0.0.1","id.resp_h":"127.0.0.1","host":"portal.lab.example","status_code":null}
```

한 조각씩:

- `select(.host=="portal.lab.example")`: `host`가 그 값인 기록만 통과시킵니다.
- `|`: 앞의 결과를 뒤로 넘깁니다(셸의 파이프와 같은 생각).
- `{ts, uid, "id.orig_h", …}`: 그 필드들만 담은 새 객체를 만듭니다. **`id.orig_h`처럼 점이 든 이름은 큰따옴표로** 감싸야 해요. 따옴표가 없으면 jq는 "`id` 안의 `orig_h`"로 읽습니다.

### 5.3 시각 바꾸기: `|= todate` { #jq-todate }

```text
$ jq -c 'select(.uid=="CqGnde2epFh6bIDYyf") | .ts |= todate | {ts, uid, username, status_code}' http.log
{"ts":"2026-11-05T07:36:46Z","uid":"CqGnde2epFh6bIDYyf","username":"jdoe","status_code":401}
```

`.ts |= todate`는 "`ts` 필드를 그 값에 `todate`를 적용한 결과로 **바꿔 넣어라**"입니다. 유닉스 시각이 ISO 8601 형식(UTC)으로 바뀌어요. 다른 로그에서 찾은 흥미로운 `uid`로 이렇게 바로 찾아 들어가는 것이 흔한 흐름입니다. 소수점 아래(마이크로초)는 `todate`에서 버려진다는 점은 기억하세요. 정밀한 순서가 필요하면 원래 값도 함께 남깁니다.

### 5.4 배열 다루기: `.answers`와 `.answers[0]` { #jq-arrays }

```text
$ jq -c 'select(.query=="cdn.example.com" and .answers!=null) | {uid, query, answers, TTLs}' dns.log
{"uid":"CYHFhr4EQi9PFrUR84","query":"cdn.example.com","answers":["edge.example.net"],"TTLs":[300.0]}
{"uid":"CCRnDa3WxlmQ8naShe","query":"cdn.example.com","answers":["edge.example.net","198.51.100.80"],"TTLs":[300.0,30.0]}
$ jq -c 'select(.query=="cdn.example.com" and .answers!=null) | .answers[0]' dns.log | head -1
"edge.example.net"
```

`answers`와 `TTLs`는 **배열**이고, 같은 위치끼리 짝입니다(`edge.example.net`은 300초, `198.51.100.80`은 30초. 2.6강의 CNAME과 A의 TTL이 따로 노는 모습). `[0]`을 붙이면 첫 원소 하나만 나와요.

두 줄인 이유도 2.6강에서 배운 그대로입니다. 첫 줄은 리졸버가 **권한 서버에게서** 받은 답(CNAME만), 둘째 줄은 리졸버가 **클라이언트에게** 준 답(CNAME과 A를 합친 것)이에요. 이 pcap이 루프백의 모든 53번 트래픽을 담았기 때문입니다. `id.orig_h`로 어느 쪽 기록인지 꼭 확인하세요.

### 5.5 로그 사이를 오가기: `uid`와 `fuid` { #jq-pivot }

`http.log`에서 `/report.zip`의 파일 ID를 얻고, `files.log`에서 그 파일의 해시를 찾았습니다.

```text
$ F=$(jq -r 'select(.uri=="/report.zip") | .resp_fuids[0]' http.log); echo $F
FMxNrn1TAZX9SSFI3f
$ jq -c --arg f "$F" 'select(.fuid==$f) | {fuid, mime_type, total_bytes, md5, sha1, source, uid}' files.log
{"fuid":"FMxNrn1TAZX9SSFI3f","mime_type":"application/zip","total_bytes":46,"md5":"f4d3fed54615b950dcd351770272d341","sha1":"3d9a0375eb63d96912bf6c316f9caa6e487c40d4","source":"HTTP","uid":"CAU56U3BuXGG04UEil"}
```

- `-r`: 문자열을 따옴표 없이(raw) 출력. 셸 변수에 담을 때 필요합니다.
- `--arg f "$F"`: 셸 변수를 jq 안의 `$f`로 넘깁니다. 값을 필터 문자열에 직접 붙이는 것보다 안전해요(따옴표·특수 문자 문제 없음).

서버의 실제 파일로 확인하니 `md5sum`이 `f4d3fed54615b950dcd351770272d341`로 **같았습니다**. `files.log`의 `uid`는 이 파일이 오간 연결이고, 같은 `uid`로 `conn.log`를 찾으면 그 연결 전체의 크기와 상태가 나옵니다.

```text
$ jq -c 'select(.uid=="CAU56U3BuXGG04UEil") | {uid, service, duration, orig_bytes, resp_bytes, conn_state, history}' conn.log
{"uid":"CAU56U3BuXGG04UEil","service":"http","duration":0.0016560554504394531,"orig_bytes":289,"resp_bytes":4842,"conn_state":"SF","history":"ShADadFf"}
```

`http.log` → `files.log` → `conn.log`로, "어떤 요청이 → 어떤 파일을 받았고(해시) → 그 연결은 어땠나"를 이었습니다. 1.10강에서 배운 `conn_state`(`SF` = 정상 종료)와 `history`도 그대로 읽을 수 있어요.

!!! warning "[주의] `uid`는 처리할 때마다 바뀐다"
    같은 pcap을 두 번 처리했더니, 같은 연결(출발 포트 33246)의 `uid`가 첫 번째는 `CAU56U3BuXGG04UEil`, 두 번째는 `CjrN3e3AePQwe77tTl`이었습니다(직접 실행 결과). `uid`는 **그 처리 결과 안에서만** 로그들을 잇는 열쇠입니다. 보고서에 `uid`를 적을 때는 어느 처리 결과(날짜, Zeek 버전, 정책)의 것인지 함께 적고, 다른 도구나 다른 처리 결과와 잇고 싶다면 8절의 **Community ID**를 씁니다.

## 6. jq의 속도: 먼저 grep으로 좁힌다 { #jq-performance }

jq만으로 모든 일을 하면 다른 도구와 함께 쓸 때보다 **훨씬 느릴** 수 있습니다. 이건 jq만의 문제가 아니에요. 조사자는 자기 도구의 한계를 알고, 처리 시간까지 생각해 여러 도구를 조합해야 합니다.

무작위로 만든 가짜 `dns.log` **150만 줄**(gzip으로 약 31MB)에서 `beacon.example.org`를 두 가지 방법으로 찾았습니다.

**(직접 실행 결과, 가짜 데이터)**

```text
$ time (zcat big_dns.log.gz | jq -c 'select(.query=="beacon.example.org") | {ts,"id.orig_h"}' | wc -l)
6
real	0m7.916s

$ time (zgrep -F '"beacon.example.org"' big_dns.log.gz | jq -c '{ts,"id.orig_h"}' | wc -l)
6
real	0m1.780s
```

결과는 같고(6줄), `zgrep`으로 먼저 좁힌 쪽이 **약 4.4배** 빨랐습니다. jq는 모든 줄을 JSON으로 해석해야 하지만, `grep`은 글자만 비교하니까요. `-F`는 정규 표현식이 아닌 **고정 문자열**로 찾으라는 옵션이라 점(`.`)을 이스케이프할 필요가 없고, 큰따옴표까지 넣어 `xbeacon.example.org` 같은 더 긴 이름에 걸리지 않게 했습니다.

그렇다고 `select()`를 쓰지 말라는 뜻은 아닙니다. `grep`은 **필드를 모릅니다**. 같은 글자가 `answers` 칸(다른 이름의 CNAME 대상)에 있어도 걸려요. 그래서 "**`grep`으로 넓게 좁히고, `jq`의 `select()`로 정확히 거른다**"가 좋은 조합입니다. 복잡한 조건을 원시 JSON에 대한 정규 표현식으로 정확히 쓰기는 어렵고, jq는 JSON에 맞는 훨씬 풍부한 검색 문법을 줍니다. 상황에 맞게 고르는 것이 조사자의 몫이에요.

!!! warning "[주의] 온라인 jq 연습장과 운영 보안"
    jq를 익히기 좋은 도구로 브라우저에서 바로 시험해 보는 온라인 "playground"(jqplay.org)가 있고, 웹에서 한 일을 명령줄로 옮긴 모양까지 보여 줍니다. 하지만 **사건 데이터를 통제할 수 없는 인터넷 사이트에 보내는 것**이라 운영 보안(OPSEC) 위험이 큽니다. 실제 로그는 절대 붙여 넣지 말고, 연습용 데이터만 쓰거나, 공개된 소스로 직접 띄운 오프라인판을 쓰세요. jq 자체의 튜토리얼과 설명서도 좋은 출발점입니다.

## 7. Zeek 시그니처와 스크립트 { #signatures-scripts }

### 7.1 시그니처 { #signatures }

Zeek의 주 목적은 시그니처 탐지가 아니지만, **시그니처 엔진**이 있어 사고 대응에 아주 쓸모 있습니다.

- IP 주소, 프로토콜, 포트, 패킷 크기 같은 **패킷 필드**로 맞출 수 있습니다.
- 원시 트래픽의 **내용**, 그리고 HTTP 요청 URI와 요청·응답 헤더 같은 **프로토콜별 필드**로도 맞출 수 있어요.
- `files.log`에 나오는 파일은 **매직 값**(파일 첫 바이트의 형식 표시)이나 알려 온 MIME 형식으로 평가할 수 있습니다.

Snort 같은 순수 IDS만큼 풍부한 내용 기반 탐지는 아니지만, NSM의 다른 기능과 함께라면 조사 중 중요한 트래픽에 표시를 다는 데 충분할 때가 많습니다. 연습용 시그니처를 하나 써 봤습니다.

```text
signature lab-python-tool-post {
  ip-proto == tcp
  http-request /.*cgi-bin\/search\.cgi/
  http-request-header /User-Agent: python-requests/
  event "Practice: scripted POST to search.cgi"
}
```

`http-request`는 요청 URI에, `http-request-header`는 요청 헤더에 정규 표현식을 맞춥니다. 조건은 **모두** 만족해야 해요. `-s` 옵션으로 불러와 돌렸습니다.

**(직접 실행 결과)**

```text
$ zeek -C -r lab.pcap -s lab.sig LogAscii::use_json=T
$ jq -c . signatures.log
{"ts":1793864206.769968,"uid":"C4K6n638HpgJwWWbpf","src_addr":"127.0.0.1","src_port":33276,"dst_addr":"127.0.0.1","dst_port":8080,"note":"Signatures::Sensitive_Signature","sig_id":"lab-python-tool-post","event_msg":"127.0.0.1: Practice: scripted POST to search.cgi","sub_msg":"python-requests/2.31.0"}
```

`signatures.log`와 `notice.log`가 함께 생겼고, `sub_msg`에 맞은 헤더 값이 들어 있습니다. 사고 중 공격자의 알려진(또는 의심되는) 행동으로 시그니처를 만들면, **과거 pcap을 다시 돌려** 언제부터 그 행동이 있었는지 찾을 수 있어요.

### 7.2 스크립트 { #scripts }

Zeek의 진짜 힘은 **스크립트 프레임워크**입니다. 특정 이벤트(연결 성립, HTTP 요청, 파일 발견 등)에 처리를 붙여 **덧붙인 정보와 조회 결과를 로그에** 남길 수 있어요. 예를 들어 관찰한 파일의 해시를 평판 서비스에 조회하기, MAC 주소가 정해진 기준보다 자주 바뀌는 IP 찾기, DNS 활동 빈도 보고, TLS 클라이언트 지문 만들기 같은 일입니다. 이 실습의 `software.log`(관찰한 소프트웨어 목록)도 기본 제공 스크립트가 만든 거예요.

**(직접 실행 결과, `software.log` 일부)**

```text
{"host":"127.0.0.1","software_type":"HTTP::BROWSER","name":"<unknown browser>","unparsed_version":"Mozilla/5.0 (X11; Linux x86_64) LabBrowser/1.0"}
{"host":"127.0.0.1","host_p":8080,"software_type":"HTTP::SERVER","name":"Apache","version.major":2,"version.minor":4,"version.minor2":58,"version.addl":"Ubuntu","unparsed_version":"Apache/2.4.58 (Ubuntu)"}
{"host":"127.0.0.1","software_type":"HTTP::BROWSER","name":"python-requests","version.major":2,"version.minor":31,"version.minor2":0,"unparsed_version":"python-requests/2.31.0"}
```

`User-Agent`와 `Server` 헤더로 클라이언트와 서버의 소프트웨어와 버전을 정리했습니다. 낯선 도구(`python-requests`)가 사내에 나타난 시점을 찾는 데 좋아요. Zeek 스크립트로 공격 행동을 찾아내는 공개 프로젝트(예: ATT&CK 기법에 맞춰 Zeek 로그를 되짚는 BZAR)도 있습니다.

!!! warning "[변경됨] TLS 지문: JA3에서 JA4로"
    교재는 TLS 클라이언트 지문 **JA3**와 서버 지문 **JA3S**, SSH 클라이언트 지문 **HASSH**를 추가 모듈로 소개합니다. 두 가지가 바뀌었어요.

    - **기본으로 들어 있지 않다.** Zeek 9.0.1의 `ssl.log`에는 `ja3`, `ja4` 칸이 없었습니다(직접 실행 결과: 둘 다 `null`). 패키지 관리자(`zkg`)로 따로 설치해야 합니다.
    - **JA3의 쓸모가 줄었다.** 2023년 초 Chrome이 ClientHello의 **확장(extension) 순서를 무작위로 섞기** 시작하면서, 같은 브라우저라도 연결마다 JA3 값이 달라지게 됐습니다. 그래서 확장 목록을 정렬해서 계산하는 등의 방식을 쓰는 **JA4**(FoxIO, 2023년)와 그 계열(JA4S, JA4H 등)이 널리 쓰이기 시작했어요. 다만 JA4 계열은 구성 요소마다 라이선스 조건이 달라, 상업적으로 쓸 때는 확인이 필요합니다.

    **조사에서의 의미:** 예전 보고서나 위협 정보의 JA3 값으로 요즘 트래픽을 찾으면 브라우저 계열은 잘 안 맞을 수 있습니다. 어떤 지문 방식인지, 어떤 버전의 계산인지를 꼭 함께 확인하세요.

## 8. Community ID: 도구 사이를 오가는 흐름 식별자 { #community-id }

### 8.1 왜 필요한가 { #why-community-id }

네트워크 조사의 오랜 문제는 **하나의 흐름(flow)을 가리키는 공통의 이름**이 없다는 것이었습니다. 도구마다 자기 방식의 ID가 있고(Zeek의 `uid`처럼), 한 도구에서 다른 도구로 넘어가려면 주소·포트·시각으로 손수 맞춰야 했어요. 그리고 5.5절에서 봤듯이 Zeek의 `uid`는 처리할 때마다 바뀝니다.

**Community ID**는 Corelight의 Christian Kreibich가 만든 표준으로, 여러 도구에서 **같은 흐름에 같은 값**을 붙이게 합니다. 계산은 이렇습니다.

```text
버전 + ":" + base64( sha1( 씨앗 + 출발 주소 + 목적 주소 + 프로토콜 + 0x00 + 출발 포트 + 목적 포트 ) )
```

- **버전**: 지금은 `1`만 정의되어 있고, 나중을 위해 남겨 둔 자리입니다.
- **씨앗(seed)**: 기본 0(2바이트). 수집 영역을 구분하고 싶을 때 바꿉니다.
- **주소와 포트**: 그대로 바이트로 이어 붙입니다.
- **프로토콜**: 4계층 프로토콜 번호(TCP=6, UDP=17) 1바이트, 그 뒤에 0x00 1바이트.
- 그 밖에 **양방향이 같은 값이 되도록** 주소·포트의 순서를 정하는 규칙이 있고, ICMP는 타입과 코드를 포트 자리에 넣습니다.

### 8.2 직접 계산해서 세 도구와 맞춰 보기 { #cid-lab }

명세대로 짧은 Python 함수를 직접 썼습니다. 순서 규칙은 "(주소, 포트)가 더 작은 쪽을 앞에"로 구현했어요.

```python
def community_id(saddr, daddr, proto, sport, dport, seed=0):
    s = ipaddress.ip_address(saddr).packed; d = ipaddress.ip_address(daddr).packed
    if (s, sport) > (d, dport):            # 양방향이 같은 값이 되도록 순서를 정한다
        s, d, sport, dport = d, s, dport, sport
    data = struct.pack("!H", seed) + s + d + struct.pack("!BB", proto, 0) + struct.pack("!HH", sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()
```

연습용 pcap의 POST 연결(`127.0.0.1:33276 → 127.0.0.1:8080`, TCP)에 대해 세 곳의 값을 비교했습니다.

**(직접 실행 결과)**

```text
직접 구현 (정방향)           1:agacjPK3vGloIKDtKkjCFusqawU=
직접 구현 (역방향)           1:agacjPK3vGloIKDtKkjCFusqawU=
직접 구현 (씨앗 1)           1:nucogqK6PevUrbNex7HDUz00Iv8=
Zeek conn.log community_id   1:agacjPK3vGloIKDtKkjCFusqawU=
TShark communityid 필드      1:agacjPK3vGloIKDtKkjCFusqawU=
```

세 도구가 **같은 값**을 냈고, 방향을 뒤집어도 같았으며, 씨앗을 바꾸면 완전히 달라졌습니다. 그러니 Zeek에서 찾은 흥미로운 연결의 `community_id`를 그대로 Wireshark나 다른 도구의 검색창에 넣으면 같은 흐름이 나와요. 교재에 나오는 Arkime(예전 이름 Moloch)도 수집할 때 이 값을 메타데이터(`communityid`)로 붙입니다.

TShark에서는 이렇게 켰습니다.

```text
$ tshark -r lab.pcap --enable-protocol communityid -Y 'tcp.srcport==33276 && tcp.flags.syn==1' \
    -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e communityid
127.0.0.1	33276	127.0.0.1	8080	1:agacjPK3vGloIKDtKkjCFusqawU=
```

Wireshark 화면에서는 "Analyze > Enabled Protocols"에서 `CommunityID`를 켜면 패킷 상세에 값이 나오고, `communityid == "1:…"`로 걸러 낼 수 있습니다.

!!! info "[변경됨] Zeek에는 이제 기본으로 들어 있다"
    교재는 Zeek에서 Community ID를 쓰려면 **외부 모듈**이 필요하다고 합니다. 지금은 Zeek에 기본 스크립트로 들어 있어요(Zeek 6.0부터). 이 실습의 Zeek 9.0.1에서도 `policy/protocols/conn/community-id-logging`을 불러오기만 하면 `conn.log`에 `community_id`가 생겼습니다. 다만 **기본으로 켜져 있지는 않으니** 정책에서 불러와야 합니다(10절).

!!! warning "[주의] Community ID는 \"연결\"이 아니라 \"5-튜플\"의 이름이다"
    시각이 계산에 들어가지 않습니다. 그래서 같은 주소·포트 조합이 **나중에 다시 쓰이면**(출발 포트 재사용, 오래 걸친 캡처) 서로 다른 연결이 같은 값을 갖습니다. Community ID로 다른 도구에서 찾은 결과는 **시각도 함께 맞춰** 같은 연결인지 확인하세요. 또 NAT 장비 앞뒤처럼 주소가 바뀌는 지점에서는 같은 통신이라도 값이 달라집니다.

## 9. IDS와 NSM의 역할 { #ids-nsm }

한때 IDS는 보안 위협을 끝내 줄 해결책처럼 홍보됐지만, 지금은 관리자를 경보로 질리게 하지 않도록 **조직에 맞게 조율한 감시 장치**라는 적절한 자리를 찾았습니다. 공격이 진행 중이거나 성공했다는 **첫 신호**를 주는 경우가 많아요. NSM은 규칙 기반 IDS에서 **더 적극적인 지속 감시**로 자연스럽게 나아간 것이고, pcap과 실시간 관찰을 같은 방식으로 처리하는 플랫폼이라면 사고 대응에 특히 큰 도움이 됩니다.

둘 다 로그라는 형태의 증거를 줍니다. 공격이나 위협 행위자에 대한 정보가 **나중에 알려진 뒤에**, 과거의 활동 중 의심스러운 것을 다시 찾아내는 데 아주 쓸모 있어요. 그리고 사고 중에는 공격자의 알려진(또는 의심되는) 행동에 대한 시그니처를 직접 만들어, 공격자가 전술을 바꿀 때 빠르게 알아챌 수 있습니다(7.1절).

## 10. 조사용 Zeek 정책 꾸리기 { #forensic-policy }

교재는 강의용으로 꾸민 정책 두 가지를 소개하는데, 그 내용은 어느 조사에서나 쓸 만한 원칙입니다. 이 실습용으로 직접 정책 파일을 만들어 돌려 봤어요.

```text
# Practice policy for offline (pcap) forensic processing.
# Loads selected pieces instead of "local", so the hash lookup over DNS (detect-MHR) is not loaded.
@load frameworks/files/hash-all-files                # MD5/SHA1/SHA256 in files.log
@load protocols/conn/known-hosts                     # known_hosts.log
@load protocols/conn/known-services                  # known_services.log
@load protocols/http/software                        # software.log from HTTP headers
@load policy/protocols/conn/community-id-logging     # community_id in conn.log
redef LogAscii::use_json = T;                        # JSON logs for jq
redef ignore_checksums = T;                          # same effect as -C (offloaded checksums)
redef Site::local_nets += { 127.0.0.0/8 };           # what counts as "local" in this lab
```

`zeek -r lab.pcap forensic.zeek`로 돌리니 `-C` 없이도 `http.log`, `dns.log`, `files.log`(SHA-256 포함), `known_hosts.log` 등이 JSON으로 생겼고, `conn.log`에 `community_id`가 들어 있었습니다(직접 실행 결과). 원칙별로 정리하면:

| 원칙 | 방법 | 이유 |
| --- | --- | --- |
| JSON 로그 | `LogAscii::use_json = T` | `jq`로 다루기 쉽다(5절) |
| 체크섬 무시 | `ignore_checksums = T` 또는 `-C` | 오프로딩된 캡처에서 로그가 사라지는 것을 막는다(2.1절) |
| Community ID | `community-id-logging` 불러오기 | 다른 도구와 잇는다(8절) |
| 파일 해시 | `hash-all-files` | `files.log`에 해시. 평판 조회, 다른 증거와 대조 |
| "우리 쪽" 주소 정의 | `Site::local_nets` | 일부 스크립트(known-hosts 등)가 안·밖을 이 값으로 판단한다. **조사 대상 환경에 맞게** 바꿔야 한다 |
| 외부 조회 끄기 | `local`을 통째로 불러오지 않거나 해당 스크립트를 빼기 | 아래 [주의] |
| 파일 꺼내기는 따로 | `policy/frameworks/files/extract-all-files`는 필요할 때만 | 저장 공간과 처리 시간이 크게 는다 |

!!! warning "[주의] 기본 사이트 정책은 파일 해시를 바깥에 묻는다"
    이 이미지의 `local.zeek`는 `frameworks/files/detect-MHR`을 불러옵니다(직접 확인). 이 스크립트는 관찰한 파일의 해시를 Team Cymru의 악성코드 해시 등록부에 **DNS 질의로** 물어봅니다. 파일 자체를 보내지는 않으니 일반적인 운영 보안 기준은 지키지만, "어떤 해시를 조사하고 있는지"가 바깥에 드러나는 것이 문제가 될 수 있고, 인터넷이 없는 분석 환경에서는 조회가 실패하며 처리를 느리게 할 수 있어요. 그래서 위 정책은 `local`을 통째로 부르지 않고 필요한 것만 골랐습니다.

!!! info "[변경됨] SMB 분석기는 이제 기본으로 켜져 있다"
    교재는 SMB 분석기를 정책에서 따로 켜야 한다고 합니다. Zeek 9.0.1의 기본 스크립트 목록(`base/init-default.zeek`)에는 `@load base/protocols/smb`가 들어 있어(직접 확인), 기본 상태로도 SMB를 만나면 `smb_files.log`, `smb_mapping.log` 등이 생깁니다. Windows가 많은 환경의 조사에 아주 귀한 메타데이터예요.

## 11. 실제 조사에서는 이렇게 씁니다 { #in-practice }

1. **증거 pcap은 `-C`(또는 `ignore_checksums`)로 돌린다.** 그리고 `weird.log`, `reporter.log`를 먼저 본다.
2. **처리 조건을 기록한다.** Zeek 버전, 정책 파일, 옵션. `uid`는 그 처리 결과 안에서만 유효합니다.
3. **로그는 JSON으로, 검색은 `grep`으로 좁히고 `jq`로 정확히.**
4. **`uid`와 `fuid`로 로그를 잇는다.** `http.log` → `files.log`(해시) → `conn.log`(크기, 상태).
5. **다른 도구와는 Community ID와 시각으로 잇는다.**
6. **빈 칸의 뜻을 안다.** `password`가 비었다고 인증이 없던 게 아니고, `status_code`가 비었다면 응답이 안 왔을 수 있습니다.
7. **외부 조회를 하는 스크립트를 확인한다.** 분석 환경과 운영 보안에 맞게 정책을 꾸립니다.
8. **사고 중 알게 된 행동은 시그니처나 스크립트로 만들어 과거 pcap에 다시 돌린다.**

## 12. 정리 { #summary }

- NSM은 사고 전에 증거를 모아 두는 "포렌식 준비"의 접근이고, Zeek는 경보보다 **가시성과 응용 계층 이해**를 우선하는 대표 도구입니다. 실시간과 pcap을 같은 방식으로 처리합니다.
- **[주의]** 직접 확인: 체크섬 오프로딩이 있는 pcap을 옵션 없이 돌리면 `http.log`와 `dns.log`가 **아예 생기지 않았고**, `-C`로 돌리자 생겼습니다.
- 로그는 관찰한 트래픽에 따라 수십 종류이고, 기본 형식은 아직 TSV(`zeek-cut`으로 이름으로 뽑기), 현장에서는 JSON이 흔합니다. 매시 회전은 운영 센서의 이야기입니다.
- 공통 필드 `ts`, `uid`, `id.*`. `http.log`의 `trans_depth`는 한 연결 안의 순번이고, `user_agent`는 요청마다 남습니다. **[정정]** `password`는 기본으로 비어 있고(`username`은 401에도 남음), 켜면 로그가 계정 유출 위험이 됩니다.
- jq: `.`, `-c`, `select()`, `{ }`(점이 든 이름은 따옴표), `|= todate`, `[0]`, `-r`, `--arg`. `http.log` → `files.log`(해시가 실제 파일과 일치) → `conn.log`로 이었습니다.
- 150만 줄에서 `zgrep`으로 먼저 좁히니 jq만 쓸 때보다 약 4.4배 빨랐습니다. 정확한 거르기는 `select()`로.
- 시그니처로 `python-requests`의 POST를 잡았고, `software.log`가 관찰한 소프트웨어를 정리했습니다. **[변경됨]** JA3·JA4는 기본이 아니고, JA3는 Chrome의 확장 순서 무작위화 뒤 쓸모가 줄었습니다.
- Community ID: 직접 구현, Zeek, TShark가 같은 값을 냈고 양방향이 같았습니다. **[변경됨]** Zeek에는 기본 스크립트로 들어 있습니다. 시각은 계산에 안 들어가니 함께 확인합니다.

## 복습 문제 { #review }

**문제 1. (기본)** 동료가 침해된 서버 앞에서 캡처한 pcap을 Zeek로 돌렸더니 `conn.log`만 나오고 `http.log`가 없어서 "이 기간에는 HTTP 통신이 없었다"고 보고했습니다. 무엇부터 확인하겠습니까?

??? success "정답과 해설"
    먼저 `weird.log`와 `reporter.log`, 그리고 Zeek의 경고 메시지를 봅니다. `bad_TCP_checksum`이나 "checksum offloading" 경고가 있다면, Zeek가 체크섬이 틀린 패킷을 버려 응용 계층 분석을 못 한 것입니다(2.1절의 실험에서 똑같이 `http.log`가 사라졌음). `-C`(또는 `ignore_checksums = T`)로 다시 돌려 확인합니다. 그 밖에 `conn.log`의 `service`, `resp_p`(80, 8080, 443…)를 보고, HTTPS(443)라면 `http.log`가 아니라 `ssl.log`에 남는다는 점, 그리고 캡처가 실제로 그 서버의 트래픽을 담았는지(1.11강의 수집 위치)도 확인합니다.

**문제 2. (필드 읽기)** 다음 `http.log` 세 줄(필드 일부)에서 알 수 있는 것을 말해 보세요.

```text
{"uid":"CX1","trans_depth":1,"method":"GET","host":"files.example.com","uri":"/","status_code":200,"user_agent":"Mozilla/5.0 ..."}
{"uid":"CX1","trans_depth":2,"method":"GET","host":"files.example.com","uri":"/dl/setup.msi","status_code":200,"resp_mime_types":["application/x-dosexec"]}
{"uid":"CX1","trans_depth":3,"method":"POST","host":"files.example.com","uri":"/api/report","status_code":204,"request_body_len":48211}
```

??? success "정답과 해설"
    세 요청이 **한 연결**(`uid` 같음) 안에서 차례로(`trans_depth` 1, 2, 3) 일어났습니다. 첫 페이지를 본 뒤 `setup.msi`를 받았는데, Zeek가 내용을 보고 판단한 MIME 형식은 **Windows 실행 파일**(`application/x-dosexec`)입니다. 확장자(`.msi`)와 실제 내용이 다를 수 있다는 신호라 눈여겨볼 만해요. 그리고 같은 연결로 약 47KB를 POST했고, 서버는 본문 없는 204로 답했습니다. 다음 단계: ② 줄의 `resp_fuids`로 `files.log`에서 해시를 얻어 평판을 조회하고, 같은 해시를 받은 다른 PC를 찾습니다. ③ 줄의 POST 내용은 로그에 없으니 pcap이나 `files.log`의 `orig_fuids`(꺼내기가 켜져 있었다면)를 찾습니다. 마지막으로 `uid`로 `conn.log`를 보아 연결 전체의 양과 시간을 확인합니다.

**문제 3. (흔한 오해)** "Zeek `http.log`의 `password` 칸이 모두 비어 있으니, 이 서버에 Basic 인증 시도는 없었다." 무엇이 틀렸나요?

??? success "정답과 해설"
    Zeek는 기본으로 **비밀번호를 기록하지 않습니다**(`HTTP::default_capture_password = F`, 4절의 [정정]). 인증 시도 여부는 `username` 칸으로 봐야 하고, `username`은 실패한 시도(401)에도 남습니다. 4절의 실험에서 기본값으로는 두 시도 모두 `password: null`이었지만 `username: jdoe`는 있었어요. 또 HTTPS였다면 `http.log` 자체가 없고, Basic 인증이 아닌 폼 로그인(POST 본문)이라면 `username` 칸에도 나오지 않습니다.

**문제 4. (jq 적용)** `conn.log`(JSON)에서 바깥으로 1MB 넘게 보낸 연결만 골라, 사람이 읽는 시각과 출발·목적 주소, 보낸 바이트를 보고 싶습니다. jq 명령을 써 보세요. 연결을 시작한 쪽이 사내라고 가정합니다.

??? success "정답과 해설"
    예: `jq -c 'select(.orig_bytes != null and .orig_bytes > 1000000) | .ts |= todate | {ts, "id.orig_h", "id.resp_h", "id.resp_p", orig_bytes, resp_bytes, duration}' conn.log`. 점검할 것: ① `orig_bytes`가 없는(null) 기록이 있으니 먼저 걸러야 비교에서 오류가 안 납니다. ② `id.orig_h`처럼 점이 든 이름은 따옴표로. ③ "바깥으로"를 정확히 하려면 `local_orig`/`local_resp` 칸(정책의 `Site::local_nets`가 맞게 설정됐을 때)을 조건에 넣거나, 목적 주소가 사내 대역이 아닌 것을 고릅니다. ④ 큰 파일이면 먼저 `zcat … | jq`로 하되, 1MB 같은 숫자 비교는 `grep`으로 좁히기 어려우니 `select()`가 맞는 경우입니다(6절).

**문제 5. (변경된 조건)** 같은 pcap을 어제와 오늘 두 번 Zeek로 처리했습니다. 어제 보고서에 적은 `uid`로 오늘 결과를 찾으니 아무것도 안 나옵니다. 왜 그렇고, 어떻게 했어야 할까요?

??? success "정답과 해설"
    `uid`는 처리할 때마다 새로 만들어집니다(5.5절의 실험: 같은 연결이 `CAU56U3…`에서 `CjrN3e3…`로 바뀜). 보고서에는 `uid`와 함께 **어떤 처리 결과인지**(날짜, Zeek 버전, 정책)를 적고, 그 처리 결과의 로그를 증거로 보존해야 합니다. 처리와 무관하게 같은 흐름을 가리키려면 **Community ID**(같은 5-튜플이면 언제 어느 도구로 계산해도 같음, 8.2절)와 **시각, 주소, 포트**를 함께 적습니다.

**문제 6. (Community ID)** Zeek에서 찾은 의심 연결의 Community ID로 Arkime를 검색했더니 연결이 **세 개** 나왔습니다. 무엇을 의심하고 어떻게 가리겠습니까?

??? success "정답과 해설"
    Community ID는 시각을 빼고 5-튜플(주소, 포트, 프로토콜)만으로 계산하므로, **같은 5-튜플이 여러 번 쓰인** 경우 서로 다른 연결이 같은 값을 갖습니다(8.2절의 [주의]). 예를 들어 같은 출발 포트가 시간이 지나 재사용됐거나, UDP처럼 같은 포트 쌍으로 오래 반복된 통신일 수 있어요. Zeek 기록의 `ts`와 `duration`을 세 결과의 시작·끝 시각과 비교해 하나를 고르고, 크기(`orig_bytes`, `resp_bytes`)도 맞춰 봅니다. 나머지 둘이 같은 PC와 서버 사이의 반복 통신이라면 그것 자체가 비커닝(2.4강) 같은 단서일 수 있어요.

**문제 7. (흔한 오해)** "jq는 느리니까 큰 로그에서는 `grep`만 쓰면 된다." 6절의 실험과 설명으로 반박하세요.

??? success "정답과 해설"
    `grep`은 빠르지만(실험에서 약 4.4배) **필드를 모릅니다**. `"beacon.example.org"`라는 글자가 `query`가 아니라 `answers`(다른 이름의 CNAME 대상)에 있어도 걸리고, 숫자 비교(바이트 > 1MB)나 "이 필드가 없는 기록" 같은 조건은 표현하기 어렵습니다. 그래서 `grep`으로 **후보를 넓게 좁힌 뒤** jq의 `select()`로 **정확히 거르는** 조합이 좋아요. 반대로 조건이 복잡하고 데이터가 작다면 jq만으로도 충분합니다. 결과의 정확성과 처리 시간을 함께 따지는 것이 조사자의 판단입니다.

**문제 8. (적용)** 사고 중, 공격자의 도구가 HTTP 요청에 `X-Session-Token: ` 다음에 32자리 16진수를 붙인다는 사실을 알게 됐습니다. 지난 석 달치 pcap에서 이 도구의 흔적을 찾는 방법을 Zeek로 설계해 보세요.

??? success "정답과 해설"
    예: ① 시그니처를 만듭니다. `http-request-header /X-Session-Token: [0-9a-f]{32}/`(7.1절과 같은 형식), 필요하면 `ip-proto == tcp` 등. ② 석 달치 pcap을 `-C`와 이 시그니처(`-s`), 조사용 정책(JSON, Community ID)으로 다시 돌립니다. ③ `signatures.log`의 `uid`로 `http.log`(어느 `host`, `uri`, `user_agent`), `conn.log`(양, 시간), `files.log`(오간 파일)를 잇고, ④ 적중한 내부 주소 목록으로 범위를 정하며, ⑤ 첫 적중 시각을 사고 타임라인의 시작 후보로 봅니다. HTTPS라면 헤더가 보이지 않으니, 그 도구의 TLS 지문(JA4 등)이나 서버 이름, 비커닝 패턴처럼 암호화 밖에서 보이는 특징을 따로 찾아야 합니다.

**문제 9. (해석)** 접근 로그에는 `"POST /upload HTTP/1.1" 200 0`이 있는데, 같은 시각의 Zeek `http.log`에는 그 요청의 `status_code`가 비어 있고 `conn.log`의 `resp_bytes`가 0입니다. 어느 쪽을 믿어야 할까요?

??? success "정답과 해설"
    어느 한쪽이 "틀렸다"기보다 **보는 위치가 다릅니다**. 서버 로그는 서버 프로그램이 "처리 결과를 200으로 기록했다"는 것이고, Zeek는 "네트워크에서 응답 바이트가 **나가지 않았다**"는 것을 봤습니다(4절의 [주의]에서 직접 본 모양: 클라이언트는 "Empty reply"). 클라이언트 입장에서는 응답을 받지 못했을 가능성이 크고, 서버 쪽에서는 요청 본문을 받아 무언가를 처리했을 수 있어요. 업로드 조사라면 중요한 건 "**파일이 서버에 남았나**"이므로 서버의 파일 시스템, 애플리케이션 로그, 오류 로그를 확인하고, Zeek의 `request_body_len`과 `files.log`(`orig_fuids`)로 실제로 보낸 양과 해시를 봅니다. 두 기록의 차이 자체를 보고서에 적어 둡니다.

## 참고 자료 { #references }

- 작업 환경에서 쓴 도구: Zeek 9.0.1(공식 Docker 이미지 `zeek/zeek`, `zeek-cut` 포함), jq 1.7, TShark 4.2.2(CommunityID 분석기), tcpdump, curl 8.5.0, Apache 2.4.58, Unbound 1.19.2, Python 3.13. 실행 결과는 2026-11-05에 얻었습니다.
- Zeek, [설명서](https://docs.zeek.org/en/master/) (로그 파일 목록, `conn.log`·`http.log`·`dns.log`·`files.log` 필드, 시그니처 프레임워크, 스크립트 참고서). 기본값(`LogAscii::use_json`, `HTTP::default_capture_password`, `Log::default_rotation_interval`)과 `local.zeek`·`init-default.zeek`의 내용은 이미지 안에서 직접 확인했습니다.
- Corelight, [Community ID 명세](https://github.com/corelight/community-id-spec).
- Wireshark, [CommunityID 분석기](https://www.wireshark.org/docs/dfref/c/communityid.html).
- jq, [설명서](https://jqlang.github.io/jq/manual/)와 튜토리얼.
- FoxIO, [JA4+ 저장소](https://github.com/FoxIO-LLC/ja4) (JA4 계열과 라이선스). Chrome의 ClientHello 확장 순서 무작위화(2023년 초, Chrome 110 무렵)는 공개된 발표와 분석을 요약했습니다.
- Team Cymru, Malware Hash Registry (Zeek의 `detect-MHR` 스크립트가 쓰는 서비스).
- Richard Bejtlich, *The Tao of Network Security Monitoring*, *The Practice of Network Security Monitoring*.

!!! note "이 페이지에 대하여"
    여러 학습 자료를 바탕으로 직접 다시 쓴 개인 학습 노트입니다. 연습용 트래픽, 시그니처, 정책 파일, Community ID 계산 코드는 직접 만들었고, 사례는 가상입니다.
