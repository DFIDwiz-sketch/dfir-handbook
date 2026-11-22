---
title: Blank Clipboard — 웹메일 속 WhatsApp 피싱 링크에서 Dropbox 1단계 파일, 17 MB ZIP 다운로드, 카운터 요청까지 (Arkime + Splunk)
tags:
  - blue-team
  - pcap
  - arkime
  - splunk
  - zeek
  - phishing
  - email
  - snort
  - ticket
---

# Blank Clipboard — WhatsApp 피싱 링크에서 Dropbox 1단계 파일과 17 MB ZIP까지 (Arkime + Splunk) { #blank-clipboard }

!!! abstract "사례 요약"
    malware-traffic-analysis.net 연습문제 <strong>2018-09-27 "Blank Clipboard"</strong>를 홈 랩의 **pcapbox** VM에서 <strong>Arkime와 Splunk(Zeek 로그)</strong>로, **처음 보는 PCAP이라고 생각하고 처음부터** 분석한 기록입니다. 문제는 PCAP 하나와 **이메일 두 개**를 주고 질문을 하나 던집니다. **어느 이메일이 감염을 시작했나?** LAN 정보를 주지 않아서 도메인, DC, 사용자부터 직접 찾아야 해요.

    Windows 7 PC 한 대(**Escritorio-PC, 사용자 thiago.almeida**)가 회사 **웹메일**을 열고, 포르투갈어 **WhatsApp 미끼 피싱 메일**의 링크를 누릅니다. IE11은 가짜 "연방 검찰청 / 계약서" 페이지와 리다이렉트 관문을 거쳐 **Dropbox의 파일**로 갑니다. 81초 뒤 **브라우저가 아닌 프로그램**이 **17 MB ZIP**을 받고, 이어서 **User-Agent가 없는** 프로그램이 **감염 카운터**로 보이는 주소를 부릅니다. PC는 01:48~01:49에 **재부팅**된 것으로 보여요. ZIP은 **캡처에서 일부가 빠져**(센서가 1.97 MB를 놓침) 해시를 구할 수 없었어요. 마지막에 캠페인 링크 모양을 잡는 **Snort 룰 하나**와 팀 양식의 티켓으로 마무리합니다.

| | |
|---|---|
| **증거** | `2018-09-27-traffic-analysis-exercise.pcap` — 2018-09-27 01:37:01 – 01:51:35 UTC (14분 34초), Zeek 연결 188개, `.eml` 파일 2개 |
| **출처** | [malware-traffic-analysis.net 2018-09-27 "Blank Clipboard"](https://malware-traffic-analysis.net/2018/09/27/index.html) |
| **환경** | 폐쇄망. pcapbox VM: Arkime v5.6.4(태그 = 케이스 이름), Splunk(`index=zeek`, 필드 `pcap_case`), Snort 2.9, tshark |
| **케이스 이름** | `20180927_BLANKCLIPBOARD` |
| **결과물** | 분석, 감염을 시작한 이메일, Snort 룰 하나, 침해사고 티켓(txt) |
| **관련 페이지** | [Night Dew 두 번째 분석(같은 방법)](night-dew-arkime-splunk-netlogon-bruteforce.md) · [피싱 미끼 사례(이메일 분석)](phishing-red-herring-ek-driveby-ursnif-c2.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Zeek 로그](../../network/zeek/index.md) |

!!! tip "이 페이지 읽는 법"
    단계마다 같은 순서예요. **목적 → 쿼리(Arkime 그리고/또는 Splunk) → 설명 → 실제 결과 → 결과 읽기 → 티켓 기록**. SPL 쿼리는 모두 한 줄씩 설명합니다. **질문** 상자는 분석하면서 실제로 나온 질문과 그 답 전체예요. **정정** 상자는 처음에 잘못 읽었다가 고친 곳이고, 일부러 남겨 두었어요.

    전체 원칙은 **모르는 PCAP을 분석한다**는 거예요. 연습문제의 정답 파일에서 아무것도 가져오지 않고, 화면에 나온 것만으로 판단합니다. 그래서 악성코드 계열 이름은 **확인되지 않음**으로 둡니다.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인, IP, URL은 2018년 실제 피싱과 악성 트래픽에서 나온 값입니다. 본문과 표에서는 무력화(`hxxp`, `[.]`)했고, 코드 블록 안은 입력한 그대로 두었어요. **절대 접속하지 마세요.** 이메일은 분석 VM에서 텍스트로만 여세요.

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| 감염을 시작한 이메일 | **"Conversa do WhatsApp no (221206)"**, 2018-09-24 12:52:42 UTC 도착 — 메일 속 링크 URL이 트래픽에 **글자 하나 다르지 않고** 나옴 | 확인 |
| 감염 PC | **172.16.5.203, Escritorio-PC**, MAC `30:85:a9:f4:92:17` (ASUSTek), Windows 7, IE11 | 확인 |
| 사용자 | **thiago.almeida** (도메인 A1-ASSOCIADOS), 01:38:12 로그인 | 확인 |
| 도메인과 DC | `a1-associados[.]com` (NetBIOS `A1-ASSOCIADOS`), DC **A1Associados-DC 172.16.5.5** (DHCP 서버도 겸함) | 확인 |
| 링크가 열린 시각 | **01:40:54 UTC**, 회사 웹메일(HTTPS)에서, Referer 없음 | 확인 (웹메일에서 클릭: 근거 강함) |
| 리다이렉트 체인 | `lealcontabil[.]com` 미끼 페이지 → `cadastro.php` → 관문 `54.38.137.127/index.php` → `/a/` → Dropbox `DOC1_CONTRATO_YBFTOP2078686788.zip` | 확인 |
| 2단계 | 브라우저가 아닌 프로그램(UA `MSIE 7.0`)이 01:42:22에 `dnpland[.]com[.]my/images/z2448800.zip` 17,066,397바이트 다운로드 | 확인 |
| 카운터 | 01:44:06 User-Agent 없는 GET `serveengenharia[.]com[.]br/tmp/soares/cont1/` | 확인 (용도는 추정) |
| 재부팅 | 01:48~01:49 무렵 PC 재부팅 | 추정 (네트워크 근거 4가지) |
| C2 | 캡처가 끝날 때까지 안 보임 | 이 캡처 안에서 확인 |
| 두 번째 이메일 | 가짜 Serasa Experian 채무 통지, 같은 발송자 — 이 캡처에서는 링크로 간 트래픽 없음 | 이 캡처 안에서 확인 |
| ZIP 해시 | 구할 수 없음 — 캡처에서 1,967,951바이트 빠짐 | 확인 |
| 악성코드 계열 | 확인 안 됨 | 확인 안 됨 |

---

## 0단계 — 어떤 연습문제인지 찾고 pcapbox에 넣기 { #prep }

### 0-1. 스크린샷으로 연습문제 찾기 { #find-exercise }

!!! question "질문: 이 Arkime 스크린샷을 보고 어떤 말웨어 PCAP인지 인터넷에서 찾아 주세요."
    스크린샷에서 보인 것은 캡처 시간 **2018/09/27 01:37:02 – 01:51:35 UTC**, 바쁜 내부 호스트 **172.16.5.203**, Kerberos·LDAP·DCE/RPC·SMB를 받는 서버 **172.16.5.5**(DC), 그리고 짧은 외부 IP 목록이었어요.

    날짜로 malware-traffic-analysis.net을 찾아보면 그날 글이 두 개 있어요.

    - **2018-09-27 — 트래픽 분석 연습문제 "Blank Clipboard"**: Windows 호스트 한 대가 감염되는 PCAP과 **이메일 두 개**가 주어지고, 어느 이메일이 감염을 시작했는지 찾는 문제예요. LAN 정보는 일부러 **주지 않아서** 직접 알아내야 해요.
    - 2018-09-27 — "4 days of Hancitor" (연습문제가 아닌 자료 모음)

    AD 환경이고 LAN 정보가 주어지지 않는 구조가 **Blank Clipboard** 연습문제(`2018-09-27-traffic-analysis-exercise.pcap.zip`, 17.1 MB, 그리고 `2018-09-27-traffic-analysis-exercise-both-emails.zip`)와 맞아요. 정답은 따로 있는 정답 PDF에만 있어요. 그래서 악성코드 이름은 **어디서도 가져오지 않고** 트래픽으로만 분석했어요.

### 0-2. 인제스트 { #ingest }

방법은 [Night Dew 두 번째 분석](night-dew-arkime-splunk-netlogon-bruteforce.md#prep)과 같아요.

1. PCAP 이름을 케이스 이름으로 바꿔요. 여기서는 <strong>`20180927_BLANKCLIPBOARD.pcap`</strong>이에요. 그리고 `\\10.50.10.60\incoming`에 넣어요.
2. `/data/logs/ingest.log`에 `DONE case=20180927_BLANKCLIPBOARD`가 나올 때까지 기다려요. `START` 줄의 `sha256=` 값이 티켓의 증거 해시예요.
3. 2018년 데이터라서 Arkime 시간 범위는 **All**, Splunk는 **All time**으로 둬요.

케이스 이름이 헷갈리면:

```spl
index=zeek sourcetype=zeek:conn
| stats count by pcap_case
```

- `stats count by pcap_case`: 케이스마다 연결 수를 세요. 목록에서 이번 케이스 이름을 찾으면 돼요.

!!! question "질문: pcap이 어디에 들어가 있죠? 셋팅을 한번 보실래요?"
    인제스트가 끝나면 pcapbox는 케이스마다 이렇게 나눠 저장해요.

    | 무엇 | 어디 |
    |---|---|
    | 원본 PCAP 사본 | `/data/pcap/<케이스>.pcap` → `/data/pcap/20180927_BLANKCLIPBOARD.pcap` |
    | Zeek 로그 | `/data/zeek/<케이스>/` (Splunk의 `source` 칸에 이 경로가 나와요) |
    | Snort 알림 | `/data/snort/<케이스>/alert` |
    | 처리 기록 | `/data/logs/ingest.log` |
    | Arkime | `<케이스>` 태그가 붙은 세션 |

    확인하는 방법:

    ```bash
    ls -l /data/pcap/
    grep 20180927_BLANKCLIPBOARD /data/logs/ingest.log
    ```

    - `ls -l /data/pcap/`: 보관된 PCAP 목록과 크기예요. 같은 이름을 두 번 넣었으면 `..._2611...pcap`처럼 뒤에 시각이 붙어요.
    - `grep ... ingest.log`: 이번 케이스 줄만 찾아요. `START`(경로와 `sha256=`)와 `DONE`이에요.

    `/data/pcap/`을 읽을 권한이 없다는 오류(`Permission denied`)가 나면 `tshark` 앞에 `sudo `를 붙이고, 그다음 꺼낸 파일을 내 계정 소유로 바꿔요. `sudo chown -R $USER: ~/cases/20180927_BLANKCLIPBOARD/export` (`-R` = 폴더 안 전부, `$USER:` = 내 계정과 내 그룹)

### 0-3. 시간대 { #utc }

Arkime 히스토그램 아래 시각이 이미 **UTC**로 끝나요(`2018/09/27 01:38:00 UTC`). 그래서 이번에는 Arkime 시간대를 고칠 필요가 없었어요. (Night Dew 때는 브라우저 시간으로 나와서 9시간 30분 차이가 났어요.)

---

## 1단계 — 전체 그림 { #overview }

**목적:** 세부 내용을 보기 전에, 캡처가 언제 시작해서 언제 끝나는지, 내부 PC가 몇 대인지, 누가 가장 많이 통신했는지 봐요.

### 1-1. Arkime { #overview-arkime }

**Sessions** → 시간 범위 **All** → 검색:

```text
tags == 20180927_BLANKCLIPBOARD
```

**결과** (SPIView → General):

```text
Start  2018/09/27 01:37:01   End  2018/09/27 01:51:35   (00:14:34, Bounding: Last Packet)
Protocols  tcp (114) udp (70) krb5 (48) dns (38) ldap (26) dcerpc (13) tls (11) dhcp (10) http (8) smb (7) llmnr (6) ntp (2) igmp (1)
Src IP     172.16.5.203 (178)  172.16.5.5 (7)
Dst IP     172.16.5.5 (142)  172.16.5.203 (7)  216.194.135.127 (7)  224.0.0.252 (6)  54.38.137.127 (4)
           172.16.5.255 (4)  255.255.255.255 (4)  103.6.198.141 (3)  162.125.5.1 (2)  162.125.5.6 (2)
           23.65.180.72 (1)  177.12.174.95 (1)  200.157.208.243 (1)  224.0.0.22 (1)
```

### 1-2. Splunk { #overview-splunk }

**쿼리 ① 캡처 시간과 규모**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180927_BLANKCLIPBOARD
| stats min(ts) as first max(ts) as last count as sessions
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- 1줄: 이번 케이스의 Zeek 연결 기록(`conn.log`, 연결 하나당 한 줄)만 가져와요.
- 2줄 `stats`: 결과 전체를 한 줄로 요약해요. 가장 이른 `ts`(`first`), 가장 늦은 `ts`(`last`), 연결 수(`sessions`)예요.
- 3줄 `eval` + `strftime`: `ts`는 1970년부터 센 초(epoch)라서, `strftime`으로 `2018-09-27 01:37:01` 같은 날짜 모양으로 바꿔요. 쉼표로 `eval` 하나에서 두 필드를 바꿀 수 있어요.

```text
first                 last                  sessions
2018-09-27 01:37:01   2018-09-27 01:50:57   188
```

**쿼리 ② 내부 PC별 통신량**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180927_BLANKCLIPBOARD id_orig_h="172.16.5.*"
| stats count as sessions dc(id_resp_h) as dests sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h
| sort - sessions
```

- 1줄 `id_orig_h="172.16.5.*"`: 연결을 **시작한** 쪽이 내부 LAN인 것만 남겨요. 이번 LAN은 문제에서 알려 주지 않아서 Arkime 화면에서 본 대역을 썼어요. `*`는 "아무거나"예요.
- 2줄: 내부 IP마다 `count`(연결 수), `dc(id_resp_h)`(서로 **다른** 목적지 수, dc = distinct count), `sum(orig_bytes)`(보낸 바이트 합), `sum(resp_bytes)`(받은 바이트 합)를 구해요.
- 3줄 `sort - sessions`: 연결이 많은 순서로 정렬해요. `-`는 내림차순이에요.

```text
id_orig_h      sessions  dests  sent     received
172.16.5.203   188       12     172599   18482111
```

**쿼리 ③ 외부 목적지를 받은 양 순서로** (이번 케이스용으로 추가)

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180927_BLANKCLIPBOARD NOT id_resp_h IN ("172.16.5.*", "224.*", "255.255.255.255")
| stats count as sessions min(ts) as first values(id_resp_p) as ports values(service) as service sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h id_resp_h
| eval first=strftime(first,"%H:%M:%S")
| sort - received
```

- 1줄 `NOT id_resp_h IN (...)`: 목적지가 내부 LAN, 멀티캐스트(`224.*`), 브로드캐스트인 것을 **빼요.** 외부로 나간 연결만 남아요.
- 2줄 `stats ... by id_orig_h id_resp_h`: "누가(출발지) 어디로(목적지)" 짝마다 한 줄로 요약해요. `min(ts)`(처음 연결 시각), `values(id_resp_p)`(쓴 목적지 포트 목록), `values(service)`(Zeek이 알아낸 프로토콜: `http`, `ssl`, `dns` 등), `sent` / `received`(보낸 양 / 받은 양)예요.
- 3줄: 처음 연결 시각을 `01:39:12` 같은 모양으로 바꿔요.
- 4줄 `sort - received`: **받은 양이 큰 순서**로 정렬해요. 맨 위가 가장 많이 내려받은 상대예요.

```text
id_orig_h     id_resp_h        sessions  first     ports  service  sent  received
172.16.5.203  103.6.198.141    1         01:42:21  80     http     320   17066676
172.16.5.203  216.194.135.127  7         01:38:49  443    ssl      5936  1261710
172.16.5.203  162.125.5.1      2         01:40:58  443    ssl      1568  10332
172.16.5.203  162.125.5.6      2         01:41:00  443    ssl      1289  7959
172.16.5.203  54.38.137.127    4         01:40:54  80     http     1679  3753
172.16.5.203  177.12.174.95    1         01:44:06  80     http     90    208
172.16.5.203  200.157.208.243  1         01:49:13  80     http     97    179
172.16.5.203  23.65.180.72     1         01:37:07  80     http     97    179
```

### 1-3. 결과 읽기 { #overview-reading }

**① 캡처 범위는 두 도구가 맞아요.** Arkime 01:37:01 – 01:51:35, Zeek 01:37:01 – 01:50:57이에요. 시작은 같아요. 끝이 다른 이유는 Arkime는 **마지막 패킷** 시각이고, Zeek의 `ts`는 **마지막 연결이 시작된** 시각이기 때문이에요.

**② PC 한 대의 트래픽이에요.** Zeek에서 연결을 시작한 내부 IP는 **172.16.5.203 하나뿐**이에요. 연결 188개, 목적지 12곳, 보낸 양 약 170 KB, **받은 양 약 18.5 MB**예요. 그래서 **감염 의심 PC = 172.16.5.203**으로 놓고 가요.

**③ 작은 차이: 172.16.5.5가 출발지?** Arkime에서는 172.16.5.5가 출발지인 세션이 7개인데 Zeek에서는 0개예요. Arkime Dst IP 목록에 `172.16.5.203 (7)`이 있으니 이 7개는 **DC → PC 방향**으로 보여요. 두 도구는 방향을 정하는 방법이 달라요.

- **Arkime:** **처음 본 패킷**을 보낸 쪽을 출발지로 정해요.
- **Zeek:** SYN이나 포트 번호를 보고 누가 시작했을지 추측해요.

캡처가 대화 중간부터 잡혔거나 UDP 응답만 있으면 결과가 달라져요. [2단계](#dc-to-pc)에서 확인해요.

**④ 목적지를 내부와 외부로 나누기.**

- **내부:** `172.16.5.5` 142개. krb5, ldap, dcerpc, smb가 함께 보여서 **DC일 가능성이 높아요.** 도메인 PC가 DC와 많이 통신하는 건 정상이에요.
- **브로드캐스트와 멀티캐스트(보통 정상):** `172.16.5.255`, `255.255.255.255`는 브로드캐스트예요. `224.0.0.252`는 LLMNR(Windows가 이름을 찾을 때 쓰는 멀티캐스트, 프로토콜 목록의 `llmnr 6`과 맞아요), `224.0.0.22`는 IGMP예요.
- **외부:** `216.194.135.127` 7개, `54.38.137.127` 4개, `103.6.198.141` 3개, `162.125.5.1`과 `.6` 각 2개, 나머지는 1개씩이에요.

**⑤ Night Dew와 다른 점: 세션 수로는 용의자가 안 보여요.** 그때는 외부 IP 두 개에 54개, 23개가 몰려 있었어요. 이번에는 가장 많은 것도 7개예요. 캡처가 14분으로 짧아서 **개수만으로는 부족해요.** 다른 기준을 써요.

- **바이트 수:** 세션 1개라도 큰 파일을 받았을 수 있어요.
- **시간 순서:** 무엇이 먼저 일어났나.
- **프로토콜:** `http 8`은 암호화가 안 돼 있어서 바로 볼 수 있어요. 첫 번째로 볼 곳이에요.

받은 양으로 정렬하니 용의자가 바로 보여요.

- **103.6.198.141 — 세션 1개인데 약 17 MB.** 이번 캡처에서 받은 양의 <strong>92%</strong>가 이 연결 하나예요. 포트 80, **암호화 안 된 HTTP**예요.
- **216.194.135.127 — TLS 7개, 1.26 MB.** 두 번째로 커요. 암호화라 내용은 안 보이지만, 시작 시각(01:38:49)이 다른 의심 트래픽보다 **먼저**예요.

### 1-4. HTTP 세션 8개를 시간 순서로 { #http-sessions }

**Arkime:**

```text
tags == 20180927_BLANKCLIPBOARD && protocols == http
```

```text
Start     Src port  Dst IP / port         Packets  Databytes / Bytes   URI
01:37:07  49183     23.65.180.72:80       9        276 / 778           www.msftncsi.com/ncsi.txt
01:40:54  49218     54.38.137.127:80      24       4,182 / 5,494       lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
                                                                       lealcontabil.com/favicon.ico  lealcontabil.com/comercio/cadastro.php ...
01:40:57  49220     54.38.137.127:80      15       1,250 / 2,076       54.38.137.127/index.php  54.38.137.127/a/
01:42:21  49225     103.6.198.141:80      10,000   6,535,736 / 8,061,835   dnpland.com.my/images/z2448800.zip
01:42:21  49225     103.6.198.141:80      10,000   0 / 7,888,936       (태그: incomplete-tcp out-of-order-dst acked-unseen-segment-src)
01:42:21  49225     103.6.198.141:80      283      0 / 243,608
01:44:06  49226     177.12.174.95:80      11       298 / 908           serveengenharia.com.br/tmp/soares/cont1/
01:49:13  49183     200.157.208.243:80    10       276 / 832           www.msftncsi.com/ncsi.txt
```

| 시각 (UTC) | 목적지 | 무엇 | 첫 판단 |
|---|---|---|---|
| 01:37:07 | 23.65.180.72 | `www.msftncsi.com/ncsi.txt` | 정상 (Windows 인터넷 연결 확인) |
| 01:38:49 | 216.194.135.127:443 | TLS 7개, 1.26 MB | **미확인** — SNI 확인 필요 |
| 01:40:54 | 54.38.137.127 | `lealcontabil.com/comercio/?...onlinepor-email?e=whatsapp_Beckup_REG`, `/cadastro.php` | **의심** |
| 01:40:57 | 54.38.137.127 | `54.38.137.127/index.php`, `/a/` | **의심** (도메인 없이 IP로 직접 접속) |
| 01:40:58 | 162.125.5.1 / .6:443 | TLS 각 2개 | **미확인** — SNI 확인 필요 |
| 01:42:21 | 103.6.198.141 | `dnpland.com.my/images/z2448800.zip` 약 17 MB | **강한 의심** |
| 01:44:06 | 177.12.174.95 | `serveengenharia.com.br/tmp/soares/cont1/` | **의심** |
| 01:49:13 | 200.157.208.243 | `www.msftncsi.com/ncsi.txt` | 정상처럼 보이지만 ⑦ 참고 |

**각 줄을 이렇게 읽어요.**

- **01:37:07 NCSI.** Windows는 네트워크에 붙으면 `ncsi.txt`를 받아서 "인터넷이 되나?"를 확인해요. 캡처 시작 6초 뒤에 나왔으니 **PC가 막 네트워크에 연결됐다**는 뜻이에요.
- **01:40:54 lealcontabil.com.** 수상한 점이 여러 개예요. URL에 `onlinepor-email`과 `e=whatsapp_Beckup_REG`가 있어요. **이메일로 받은 링크를 눌렀을 때 생기는 URL** 모양이에요("Beckup"은 "Backup"의 철자 오류예요). `comercio`, `cadastro`(등록), `imagens`, `contabil`(회계)은 **포르투갈어**예요. `/comercio/?imagens/img/tmp/a?...`처럼 `?`가 여러 번 나오는 경로는 정상 사이트가 만들지 않아요. **해킹된 사이트**에 심은 페이지에서 자주 보는 모양이에요.
- **01:40:57 54.38.137.127/index.php, /a/.** 3초 뒤 **같은 서버에 도메인 없이 IP로** 접속했어요. 사람이 IP를 직접 칠 일은 거의 없어요. 앞 페이지가 이 IP로 **넘겨 보냈을(redirect)** 가능성이 커요.
- **01:42:21 dnpland.com.my/.../z2448800.zip.** **ZIP 파일**이고 이름은 숫자뿐이에요. `.com.my`는 **말레이시아** 도메인이에요. 앞의 포르투갈어 사이트와 관계없는 곳이라, 해킹된 사이트를 파일 보관소로 쓰는 경우에 흔해요. 크기가 **약 17 MB**로, 프로그램 하나가 든 ZIP치고 아주 커요. 악성 파일을 일부러 부풀려서 백신이나 샌드박스의 크기 제한을 피하는 수법이 있어요. 여기서는 아직 **가설**이에요. 54.38.137.127 다음 **약 1분 반 뒤**라서 "링크 클릭 → 랜딩 페이지 → 파일 다운로드" 흐름과 맞아요.
- **01:44:06 serveengenharia.com.br/tmp/soares/cont1/.** 또 브라질(`.com.br`) 사이트예요. ZIP을 받은 **약 2분 뒤**이고, 보낸 양 90 B / 받은 양 208 B로 아주 작아요. 사람이 웹 페이지를 본 게 아니라 **프로그램이 짧게 신호를 보낸 것** 같은 크기예요. `cont`는 포르투갈어 *contador*(카운터)의 줄임말일 수 있어요. 그렇다면 **감염 수를 세는 카운터**일 가능성이 있어요(가설. 3단계에서 User-Agent로 브라우저인지 프로그램인지 확인해요).

### 1-5. ZIP 다운로드가 Arkime에서 세 줄로 나온 이유 { #arkime-split }

세 줄 모두 출발지 포트가 **49225**로 같아요. **연결 하나가 세 줄로 잘린 거예요.** Arkime는 세션 하나가 **10,000 패킷**을 넘으면 새 세션으로 나눠 저장해요(`maxPackets` 기본값). 그래서 Zeek에서는 1개, Arkime에서는 3개예요.

태그 세 개의 뜻이에요.

- `incomplete-tcp`: TCP 대화가 완전하지 않아요 (시작이나 끝이 빠짐).
- `out-of-order-dst`: 서버가 보낸 패킷의 순서가 뒤섞여 있어요.
- `acked-unseen-segment-src`: 상대가 "받았다"고 한 데이터가 캡처에는 없어요 → **캡처에서 패킷이 일부 빠졌다**는 뜻이에요.

나중에 이 ZIP을 꺼낼 때 **파일이 깨져 있을 수도** 있어요([5단계](#zip)).

### 1-6. 단서: 01:49에 PC가 재부팅됐을까? { #restart-clue }

두 NCSI 세션의 **출발지 포트가 둘 다 49183**이에요.

- 01:37:07 → 포트 49183
- 01:44:06까지 → 포트가 49226까지 올라감
- 01:49:13 → 다시 **49183**

Windows는 새 연결마다 출발지 포트 번호를 하나씩 올려서 써요(49152부터 시작). 번호가 **처음으로 되돌아간** 건 **PC가 재부팅됐을 때** 자주 보이는 모양이에요. Arkime 히스토그램에도 01:37 시작 부분과 **01:49 부근에 비슷한 세션 덩어리**가 있어요. 부팅과 로그인 때 생기는 덩어리처럼 보여요. 악성코드 중에는 설치를 끝내고 **PC를 재부팅시키는** 종류가 있어서 중요한 단서일 수 있어요. 아직은 가설이고 [2단계](#restart)에서 확인해요.

### 1단계 뒤의 분석 메모 (티켓 아님) { #notes-1 }

- 감염 의심 PC **172.16.5.203**, MAC `30:85:a9:f4:92:17` (Arkime DHCP의 Client MAC), DC 후보 172.16.5.5
- 첫 의심 이벤트 **01:40:54** lealcontabil.com (이메일 링크 같은 URL)
- 핵심 후보 **01:42:21** `z2448800.zip` (약 17 MB), 감염 후 후보 01:44:06 `cont1`
- 미확인: 216.194.135.127:443 (01:38:49, 1.26 MB), 162.125.5.1/.6:443 (01:40:58)
- 가설: 01:49 무렵 재부팅

베이스라이닝 내용은 티켓에 쓰지 않아요.

---

## 2단계 — PC, 사용자, 도메인 찾기 { #identity }

**목적:** IP, MAC, 호스트 이름, 사용자를 찾고, 이번 문제는 LAN 정보를 주지 않았으니 **도메인 이름과 DC 이름**도 찾아요. 재부팅 가설도 확인해요.

### 2-1. Arkime { #identity-arkime }

#### ① DHCP { #dhcp }

```text
tags == 20180927_BLANKCLIPBOARD && protocols == dhcp
```

SPIView → **dhcp**:

```text
Client MAC      30:85:a9:f4:92:17 (10)
Client OUI      ASUSTek COMPUTER INC. (10)
Host            escritorio-pc (4)
Transaction id  15851cd (2) 23eb50a8 (2) 40f8871 (2) 477a1e39 (2) 4b9db1a3 (2) 8c9a47ee (2) ...
Type            ACK (6) INFORM (4)
```

세션 (Start Time 순서):

```text
01:37:05  172.16.5.203:68 -> 255.255.255.255:67   udp dhcp
01:37:05  172.16.5.5:67   -> 172.16.5.203:68      udp dhcp
01:38:49  172.16.5.203:68 -> 255.255.255.255:67   udp dhcp
01:38:49  172.16.5.5:67   -> 172.16.5.203:68      udp dhcp
...
```

#### ② Kerberos { #kerberos }

```text
tags == 20180927_BLANKCLIPBOARD && protocols == krb5
```

SPIView → **krb5**:

```text
cname   escritorio-pc$ (8)  ESCRITORIO-PC$ (4)  thiago.almeida (4)
Realm   A1-ASSOCIADOS.COM (40)  A1-ASSOCIADOS (4)  a1-associados.com (4)
sname   krbtgt/A1-ASSOCIADOS.COM (14)  cifs/a1associados-dc.a1-associados.com (5)
        LDAP/A1Associados-DC.a1-associados.com (4)  escritorio-pc$@A1-ASSOCIADOS.COM (4)
        krbtgt/A1-ASSOCIADOS (4)  krbtgt/a1-associados.com (4)  ldap/A1Associados-DC.a1-associados.com (4)
        ESCRITORIO-PC$ (2)  escritorio-pc$ (2)  host/escritorio-pc.a1-associados.com (2)
        ldap/a1associados-dc.a1-associados.com (2)  cifs/A1Associados-DC.a1-associados.com (1)
```

#### ③ DC → PC 방향 세션 7개 { #dc-to-pc }

```text
tags == 20180927_BLANKCLIPBOARD && ip.src == 172.16.5.5
```

```text
01:37:05  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:37:39  172.16.5.5:445 -> 172.16.5.203:49209  tcp  (패킷 11개, 0 / 604)
01:38:49  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:42:18  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:43:40  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:45:25  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:49:08  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
```

### 2-2. Splunk { #identity-splunk }

**쿼리 ① DHCP (시간 순서)**

```spl
index=zeek sourcetype=zeek:dhcp pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t client_addr server_addr assigned_addr mac host_name domain msg_types
| sort t
```

- 1줄: 이번 케이스의 DHCP 로그만 가져와요.
- 2줄 `eval t=strftime(ts,"%H:%M:%S")`: `ts`를 시:분:초 모양으로 바꿔 새 필드 `t`에 넣어요(날짜는 모두 같아서 시각만 봐요).
- 3줄 `table`: 보고 싶은 칸만 이 순서로 보여 줘요.
    - `server_addr`: DHCP 서버 IP. 작은 네트워크에서는 DC가 DHCP 서버를 같이 하는 경우가 많아요.
    - `host_name`: PC 이름
    - `domain`: 서버가 알려 준 도메인 이름 → **LAN 정보를 여기서 찾아요.**
    - `msg_types`: DHCP 메시지 종류 (`REQUEST`, `ACK`, `INFORM` 등)
- 4줄 `sort t`: 시간 순서로 정렬해요.

```text
t         client_addr   server_addr  assigned_addr  mac                host_name     domain             msg_types
01:37:05  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:38:49  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:42:18  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:43:40  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:45:25  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:49:08  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
```

**쿼리 ② Kerberos (시간 순서)**

```spl
index=zeek sourcetype=zeek:kerberos pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_h id_resp_h request_type client service success error_msg
| sort t
```

- `request_type`: `AS`는 로그인할 때 처음 받는 입장권(TGT), `TGS`는 서비스용 티켓, `AP`는 받은 티켓을 서비스에 내미는 것이에요.
- `client`: 요청한 계정 = **cname**. `service`: 쓰려는 서비스 = **sname**. `krbtgt/<도메인>`이 보이면 그게 **AD 도메인 이름**이고, `cifs/<이름>`이나 `ldap/<이름>`에서는 **DC의 이름**을 알 수 있어요.
- `error_msg`: `success`가 `false`일 때 이유예요. `KDC_ERR_PREAUTH_REQUIRED`는 정상이에요.

중요한 줄 (모두 172.16.5.203 → 172.16.5.5):

```text
t         request_type  client                              service                                           success  error_msg
01:37:02  AS            escritorio-pc$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          false    KDC_ERR_PREAUTH_REQUIRED
01:37:02  AS            escritorio-pc$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          true
01:37:02  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    cifs/a1associados-dc.a1-associados.com            true
01:37:02  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    ldap/A1Associados-DC.a1-associados.com/a1-...     true
01:37:03  TGS                                               escritorio-pc$@A1-ASSOCIADOS.COM                  false    KDC_ERR_BADOPTION
01:37:03  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    escritorio-pc$@A1-ASSOCIADOS.COM                  true
01:37:03  AP            /A1-ASSOCIADOS.COM                  cifs/a1associados-dc.a1-associados.com            true
01:37:12  AS            ESCRITORIO-PC$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          true
01:38:12  AS            thiago.almeida/A1-ASSOCIADOS        krbtgt/A1-ASSOCIADOS                              false    KDC_ERR_PREAUTH_REQUIRED
01:38:12  AS            thiago.almeida/A1-ASSOCIADOS        krbtgt/A1-ASSOCIADOS.COM                          true
01:38:12  TGS           thiago.almeida/A1-ASSOCIADOS.COM    host/escritorio-pc.a1-associados.com              true
01:38:13  TGS           thiago.almeida/A1-ASSOCIADOS.COM    cifs/A1Associados-DC.a1-associados.com            true
01:38:13  TGS           thiago.almeida/A1-ASSOCIADOS.COM    ldap/A1Associados-DC.a1-associados.com            true
01:48:37  AP            /A1-ASSOCIADOS.COM                  cifs/A1Associados-DC.a1-associados.com            true
01:49:05  AS            escritorio-pc$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          false    KDC_ERR_PREAUTH_REQUIRED
01:49:05  AS            escritorio-pc$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          true
01:49:10  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    LDAP/A1Associados-DC.a1-associados.com/a1-...     true
01:49:11  TGS                                               escritorio-pc$@A1-ASSOCIADOS.COM                  false    KDC_ERR_BADOPTION
01:49:11  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    escritorio-pc$@A1-ASSOCIADOS.COM                  true
01:49:11  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    cifs/a1associados-dc.a1-associados.com            true
01:49:16  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    escritorio-pc$                                    true
```

### 2-3. 질문: 왜 DHCP가 01:37과 01:49에 두 번 나오는지 봐야 하나 { #restart }

!!! question "질문: DHCP 세션이 01:37 부근과 01:49 부근 두 번 나오는지도 봐 달라고 했는데, 이걸 보라는 이유는 무엇이죠?"
    **"01:49쯤 PC가 재부팅됐다"는 가설을 확인하려고요.**

    1단계에서 이상한 점 두 개를 봤어요. 01:49:13 NCSI의 출발지 포트가 처음과 같은 **49183으로 되돌아갔고**, 히스토그램에서 01:49 부근에 캡처 시작 때와 **비슷한 세션 덩어리**가 있었어요. Windows는 켜질 때마다 정해진 순서로 같은 일을 해요.

    1. **컴퓨터 계정**으로 DC에 인증해요 (Kerberos)
    2. **DHCP**로 네트워크 설정을 받아요
    3. **NCSI**로 "인터넷 되나?"를 확인해요
    4. **사용자가 로그인**해요 (Kerberos, 사람 계정)

    그래서 캡처 시작 부분의 순서가 **01:49에 똑같이 다시 나오면** 재부팅을 의심할 수 있어요. DHCP는 그중 하나의 확인 지점이었어요.

    **왜 중요한가:** 악성코드 중에는 설치를 끝낸 뒤 **PC를 재부팅시키는** 종류가 있어요. 재부팅하면 자동 실행(Run 키, 서비스 등)에 넣은 악성코드가 다시 시작돼요. 재부팅이 맞다면 타임라인에 "**설치 → 재부팅 → 지속성 확인**"이라는 사건이 생기고, 호스트 담당자에게 줄 단서도 생겨요.

    **그런데 DHCP만으로는 판단이 안 돼요.** Splunk에서 DHCP는 두 번이 아니라 **6번**(01:37:05, 01:38:49, 01:42:18, 01:43:40, 01:45:25, 01:49:08) 나왔고, 모두 **INFORM + ACK**였어요.

    - **INFORM:** "나는 IP가 이미 있어요. **다른 설정**(DNS 서버, 도메인 이름, 프록시 등)만 알려 주세요."
    - **ACK:** 서버의 대답이에요.

    부팅할 때 IP를 새로 받으면 보통 `DISCOVER → OFFER → REQUEST → ACK`가 나와요. 여기서는 그게 없어요. 이 PC는 **IP를 고정으로 쓰거나 이미 받아 둔 상태**예요. 그리고 Windows는 INFORM을 부팅 때만이 아니라 프록시 자동 설정(WPAD)을 찾을 때나 네트워크 상태가 바뀔 때 등 **평소에도 자주** 보내요. INFORM 6번만으로는 재부팅이라고 말할 수 없어요.

    **배울 점:** 가설 하나를 증거 하나로만 확인하지 마세요. DHCP가 약한 증거였으니 Kerberos를 봐요.

    **Kerberos가 더 강한 증거를 보여 줘요.**

    | 순서 | 캡처 시작 부분 | 01:49 부근 |
    |---|---|---|
    | 컴퓨터 계정 AS (`escritorio-pc$` → `krbtgt`, 첫 번째는 PREAUTH_REQUIRED, 다음은 성공) | 01:37:02 | 01:49:05 |
    | DHCP INFORM | 01:37:05 | 01:49:08 |
    | 컴퓨터가 자기 자신에게 티켓 요청 → `KDC_ERR_BADOPTION` → 다시 성공 | 01:37:03 | 01:49:11 |
    | NCSI (출발지 포트 49183) | 01:37:07 | 01:49:13 |
    | 사람 계정 로그인 (`thiago.almeida` AS) | 01:38:12 | 캡처 끝(01:51)까지 **없음** |

    **컴퓨터 계정의 AS 요청**이 핵심이에요. 컴퓨터 계정의 TGT는 보통 **부팅할 때** 새로 받고 10시간 동안 써요. 그런데 12분 만에 다시 받았고, 그 뒤의 순서도 처음과 똑같아요. 그래서 **01:48~01:49 사이에 PC가 재부팅됐을 가능성이 높아요.** 사용자는 캡처가 끝날 때까지 아직 다시 로그인하지 않았어요.

    네트워크만으로는 **확정할 수 없어요.** 호스트의 Windows System 로그로 확인해야 해요. 호스트 담당자 단서는 이래요.

    - **Event 1074:** 어떤 프로그램이나 사용자가 종료/재시작을 **요청했는지** 기록해요. 재시작을 시킨 **프로그램 경로**가 나와서 가장 중요해요.
    - **Event 6006:** 이벤트 로그 서비스가 정상적으로 멈췄다는 기록이에요(정상 종료).
    - **Event 6008:** 예기치 않은 종료예요(강제 종료, 전원 차단 등).
    - **Event 6005:** 이벤트 로그 서비스가 시작됐다는 기록이에요(= 부팅).

    다섯 번째 근거는 나중에 `files.log`에서 나왔어요([5단계](#files-log)). 그룹 정책 파일 `GPT.INI`를 01:37:03, 01:38:13, 그리고 **01:49:11**에 다시 읽었어요.

### 2-4. 질문: krb5 카테고리의 각 항목은 무슨 뜻인가 { #krb5-fields }

!!! question "질문: krb5 카테고리의 각 항목을 설명해 주세요. cname, sname, realm 등등"
    **먼저 Kerberos 흐름 (Splunk `request_type`에 나온 세 가지)**

    1. **AS (Authentication Service):** "저는 누구입니다"라고 DC에 증명하고 <strong>TGT(입장권)</strong>를 받아요. 로그인할 때 맨 처음 해요.
    2. **TGS (Ticket Granting Service):** TGT를 보여 주고 "**이 서비스**에 들어갈 티켓 주세요"라고 해요.
    3. **AP (Application):** 받은 서비스 티켓을 **실제 서비스**(파일 공유, LDAP 등)에 내밀어요. 이때 계정 이름은 암호화된 티켓 안에 있어서 Zeek에는 `client`가 `/A1-ASSOCIADOS.COM`처럼 **이름 없이** 나와요. 정상이에요.

    **cname (client name)** — 티켓을 **요청한 계정**, 즉 "누가"예요.

    - `escritorio-pc$` (8), `ESCRITORIO-PC$` (4): **컴퓨터 계정**이에요. 이름 끝의 `$`가 컴퓨터 계정 표시예요. 대소문자만 다른 **같은 계정**이에요. Windows는 요청에 따라 소문자(호스트 이름에서 온 것)와 대문자(AD에 저장된 이름)를 섞어 써요. AD에서 Kerberos 이름은 대소문자를 구분하지 않아요.
    - `thiago.almeida` (4): `$`가 없으니 **사람 계정**이에요. **이 PC의 사용자**예요.

    **sname (service name)** — 티켓을 받아서 **쓰려는 서비스**, 즉 "어디에 들어가려고"예요. 모양은 `서비스종류/서버이름`이에요.

    - `krbtgt/A1-ASSOCIADOS.COM` (14), `krbtgt/A1-ASSOCIADOS` (4), `krbtgt/a1-associados.com` (4): DC의 **티켓 발급 서비스**예요. 이걸 요청한다 = TGT를 받는다 = **로그인한다**는 뜻이에요. 뒤의 이름 세 개는 같은 도메인을 다르게 쓴 거예요.
    - `cifs/a1associados-dc.a1-associados.com`: DC의 <strong>파일 공유(SMB)</strong>예요. 부팅과 로그인 때 그룹 정책(SYSVOL)과 로그인 스크립트(NETLOGON)를 가져갈 때 써요.
    - `ldap/A1Associados-DC.a1-associados.com`: DC의 <strong>디렉터리 조회(LDAP)</strong>예요. 사용자 정보와 그룹 정책 목록을 물어볼 때 써요.
    - `LDAP/A1Associados-DC.a1-associados.com/a1-associados.com`: 끝에 도메인이 하나 더 붙은 LDAP예요. "이 **도메인의** DC" 용도로, 그룹 정책 처리에서 자주 보여요.
    - `host/escritorio-pc.a1-associados.com`: **사용자 thiago.almeida가 PC 자신**에 대한 티켓을 받은 거예요. 사람이 PC에 **직접 앉아서 로그인**할 때 생겨요.
    - `escritorio-pc$@A1-ASSOCIADOS.COM`, `ESCRITORIO-PC$`, `escritorio-pc$`: **컴퓨터가 자기 자신**에게 티켓을 요청한 거예요(S4U2self). 그룹 정책을 적용할 때 사용자가 어느 그룹에 속하는지 알아내려고 써요. 처음에 `KDC_ERR_BADOPTION`으로 거절되고 다음 요청이 성공하는 건 **흔한 정상 패턴**이에요.

    **Realm** — Kerberos의 **도메인 이름**이에요.

    - `A1-ASSOCIADOS.COM` (40): 대문자로 쓴 정식 realm이에요(AD DNS 도메인을 대문자로 쓴 것).
    - `a1-associados.com` (4): 같은 도메인을 소문자로 쓴 거예요.
    - `A1-ASSOCIADOS` (4): 점이 없는 짧은 이름, **NetBIOS 도메인 이름**이에요. 로그인 화면에서 `A1-ASSOCIADOS\thiago.almeida`처럼 쓸 때 이 이름이 쓰여요. 01:38:12 사용자 AS 요청의 `client`가 `thiago.almeida/A1-ASSOCIADOS`인 것도 이 때문이에요.

    **cname Cnt, Realm Cnt, sname Cnt** — "Cnt"는 **세션 하나 안에 그 필드의 값이 몇 개 있었나**예요. 모두 `1`이면 세션마다 계정, realm, 서비스가 하나씩이었다는 뜻이에요. 괄호 안 숫자 `(16)`, `(48)`은 그런 세션의 수예요. 평소에는 잘 안 보지만, 한 세션에 계정 이름이 여러 개 나오는 이상한 경우(예: 여러 계정을 대입하는 공격)를 찾을 때 쓸 수 있어요.

    **SPIView 값 옆 괄호 숫자** `(8)`, `(14)`는 항상 그 값이 들어 있는 **세션 수**예요. 요청 수가 아니에요.

### 2-5. 결과 읽기 { #identity-reading }

- **PC:** `Escritorio-PC`, 172.16.5.203, MAC `30:85:a9:f4:92:17` (ASUSTek)
- **사용자:** `thiago.almeida` — **01:38:12**에 로그인 (사람 계정 AS 요청 성공)
- **도메인:** `a1-associados.com` (NetBIOS 이름 `A1-ASSOCIADOS`)
- **DC:** `A1Associados-DC` (`a1associados-dc.a1-associados.com`) = **172.16.5.5**. 이 DC가 **DHCP 서버**도 해요. Arkime에서 DHCP 응답이 172.16.5.5:67에서 왔어요. Zeek의 `server_addr` 칸은 비어 있어서 이 정보는 Arkime에서만 얻을 수 있었어요.

**"DC → PC 7개 세션" 의문 해결:** DHCP ACK 6개(서버가 PC에게 보내는 대답이라 출발지가 DC인 게 맞아요) + TCP 445 1개(01:37:39, DC의 SMB 포트. Arkime가 이 연결에서 **DC가 보낸 패킷을 먼저** 봐서 방향이 뒤집혔고, Zeek은 포트 445 = 서버로 보고 PC를 시작한 쪽으로 정했어요). **둘 다 정상이에요.**

**맥락:** `escritorio`는 스페인어/포르투갈어로 "사무실", `associados`는 포르투갈어로 "동업자들", `thiago.almeida`는 포르투갈어권 이름이에요. **피해 조직이 브라질(포르투갈어권) 회사**로 보여요. 1단계에서 본 **포르투갈어 URL과 `.com.br` 사이트**와 맞아요. 공격자가 **피해자의 언어로 미끼를 만들었다**는 뜻이에요. 이메일을 볼 때 기억해 두세요.

로그인(01:38:12) **37초 뒤**에 미확인 TLS 216.194.135.127(01:38:49)이 시작됐어요. 로그인하면 자동으로 켜지는 프로그램이거나, 사용자가 처음 연 프로그램(메일?)일 수 있어요. 3단계에서 SNI로 확인해요.

**티켓 기록 (핵심만):**

```text
Infected host (suspected)
  IP address : 172.16.5.203
  MAC address: 30:85:a9:f4:92:17 (ASUSTek)
  Host name  : Escritorio-PC (escritorio-pc.a1-associados.com)
  User       : thiago.almeida
  Domain     : a1-associados.com (A1-ASSOCIADOS), DC A1Associados-DC 172.16.5.5
```

---

## 3단계 — 감염 흐름 연결하기 { #chain }

**목적:** 아직 모르는 세 가지에 답해요.

1. 암호화된 연결 두 곳(216.194.135.127, 162.125.5.x)은 **어디인가?**
2. **lealcontabil.com → 54.38.137.127 → ZIP 다운로드**가 하나로 이어진 흐름인가?
3. ZIP을 받은 것과 serveengenharia에 접속한 것은 **사람(브라우저)이 한 일인가, 프로그램이 한 일인가?**

화면 네 개를 썼어요. Splunk `zeek:http`, Splunk `zeek:ssl`, Arkime TLS 세션(인증서), Arkime HTTP 세션 **펼친 화면**(헤더 원문)이에요.

### 3-1. Splunk — HTTP 로그 { #http-log }

```spl
index=zeek sourcetype=zeek:http pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h method host uri referrer status_code resp_mime_types response_body_len user_agent
| sort t
```

- 1줄: 이번 케이스의 HTTP 로그만 가져와요. **HTTP 요청 하나가 한 줄**이에요.
- 2줄: `ts`를 시:분:초로 바꿔요.
- 3줄 `table`:
    - `method`: `GET`(가져오기) / `POST`(보내기)
    - `host`: 요청한 웹사이트 이름, `uri`: 사이트 안의 경로
    - `referrer`: **바로 전에 있던 페이지**예요. A 페이지에서 B로 넘어왔으면 B 요청의 referrer가 A예요. **흐름을 잇는 핵심 칸**이에요.
    - `status_code`: 서버의 대답 번호. `200` = 성공, `301`/`302` = "다른 곳으로 가세요"(리다이렉트), `404` = 없음
    - `resp_mime_types`: 받은 내용의 실제 종류 (예: `application/zip`)
    - `response_body_len`: 받은 내용의 크기
    - `user_agent`: 요청한 **프로그램의 이름표**예요
- 4줄: 시간 순서로 정렬해요.

!!! note "주의할 Splunk 함정"
    `host` 칸에 모든 줄이 `pcapbox` 같은 같은 값으로 나오면, 예전 사례처럼 Zeek의 `host`와 Splunk 기본 `host` 필드가 부딪힌 거예요. 그때는 Arkime에서 사이트 이름을 보면 돼요. 이번 케이스에서는 `host`가 제대로 나왔어요.

**결과 (10줄):**

```text
t         id_resp_h        host                    uri                                       status  mime        body_len  user_agent
01:37:08  23.65.180.72     www.msftncsi.com        /ncsi.txt                                 200     text/plain  14        Microsoft NCSI
01:40:54  54.38.137.127    lealcontabil.com        /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG    301  text/html  297   Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
01:40:55  54.38.137.127    lealcontabil.com        /favicon.ico                              404     text/html   209       (위와 같음)
01:40:55  54.38.137.127    lealcontabil.com        /comercio/?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG   200  text/html  1382  (위와 같음)
01:40:56  54.38.137.127    lealcontabil.com        /comercio/cadastro.php                    302                 0         (위와 같음)
01:40:57  54.38.137.127    54.38.137.127           /a/                                       302                 0         (위와 같음)
01:40:57  54.38.137.127    54.38.137.127           /index.php                                302                 0         (위와 같음)
01:42:22  103.6.198.141    dnpland.com.my          /images/z2448800.zip                      200     (빈칸)      17066397  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)
01:44:06  177.12.174.95    serveengenharia.com.br  /tmp/soares/cont1/                        200     (빈칸)      72        (빈칸)
01:49:13  200.157.208.243  www.msftncsi.com        /ncsi.txt                                 200     text/plain  14        Microsoft NCSI
```

`referrer` 칸은 **10줄 모두 비어 있었어요.** `host` 칸에 같은 이름이 두 번 나온 건 표시 방식 때문이라 신경 쓰지 않아도 돼요.

**이 결과에서 본 칸과 알게 된 것**

**① `status_code` — 301, 302가 이어져 있어요.** 01:40:54부터 01:40:57까지 4초 동안 `301 → 200 → 302 → 302 → 302`가 줄줄이 나와요. 사용자가 4초 안에 링크를 다섯 번 누를 수는 없어요. **서버가 브라우저를 다른 곳으로 계속 넘겨 보낸 것**이라 하나의 흐름일 거예요. **어디로** 넘겼는지는 이 표에 없고, 응답의 `Location` 헤더에 있어요. Arkime에서 봐야 해요([3-4](#arkime-http)). 302 줄들의 `response_body_len`이 **0**인 것도 같은 뜻이에요. 내용 없이 "저쪽으로 가세요"라는 말만 한 거예요.

**② `user_agent` — 요청한 프로그램이 세 종류예요.**

- **01:40:54 ~ 01:40:57:** `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko` → `Windows NT 6.1` = Windows 7, `Trident/7.0; rv:11.0` = **Internet Explorer 11**. 사람이 쓰는 **브라우저**예요.
- **01:42:22 ZIP 다운로드:** `Mozilla/4.0 (compatible; MSIE 7.0; ...)` → 자기를 **IE 7**이라고 소개해요. 같은 PC의 브라우저는 방금 IE 11이라고 했어요. 한 PC에 IE 7과 IE 11이 같이 있을 수는 없어요. 그래서 **IE 11 브라우저가 연 게 아니에요.** 이런 모양은 보통 Windows의 인터넷 기능을 빌려 쓰는 **다른 프로그램이나 스크립트**에서 나와요.
- **01:44:06 serveengenharia:** **빈칸** → 브라우저는 항상 User-Agent를 보내요. 이름표가 아예 없다는 건 **프로그램이 직접 만든 요청**이라는 뜻이에요.

질문 3의 답이 여기서 나왔어요. **ZIP 다운로드와 serveengenharia 접속은 사람이 아니라 프로그램이 했어요.**

**③ `referrer` — 전부 비어 있어요.** Referer는 "바로 전에 어느 페이지에 있었나"예요. 링크를 클릭하면 보통 클릭한 페이지 주소가 들어가요.

- **lealcontabil.com(01:40:54)에 Referer가 없는 이유:** 브라우저는 **HTTPS 페이지에서 HTTP 페이지로** 넘어갈 때 보안을 위해 Referer를 빼요. 그래서 "**HTTPS 페이지 어딘가**에서 링크를 눌렀다"와 맞아요. 어디인지는 3-2에서 찾았어요.
- **ZIP과 serveengenharia에 Referer가 없는 이유:** 프로그램이 주소를 **직접** 요청했기 때문이에요. ②의 결론과 맞아요.

**④ `response_body_len` — 크기.** ZIP은 **17,066,397바이트**예요. 1단계 쿼리 ③에서 103.6.198.141로부터 받은 양 17,066,676바이트와 거의 같아요. 그 연결의 거의 전부가 이 파일이었어요. serveengenharia는 **72바이트**로 웹 페이지라고 하기엔 너무 작아요.

**⑤ `resp_mime_types` — ZIP인데 빈칸이에요.** Zeek은 파일의 <strong>첫 몇 바이트(magic bytes)</strong>를 보고 종류를 정해요. ZIP이면 `PK`로 시작해서 `application/zip`이 나와야 해요. 그런데 빈칸이에요. 이 세션에 `acked-unseen-segment-src`(캡처에서 패킷이 빠짐) 태그가 있었으니 **파일 앞부분이 빠졌거나 깨졌을 가능성**이 있어요. 5단계에서 확인해요.

**⑥ 시간 순서 주의 — `/a/`와 `/index.php`.** 표에서는 `/a/`가 `/index.php`보다 위에 있어요. 둘 다 `01:40:57`로 **초까지 같아서** `sort t`가 순서를 정확히 못 정한 거예요. 실제 순서(index.php 01:40:57 → /a/ 01:40:58)는 Arkime에서 응답의 `Date` 헤더로 확인했어요. **같은 초에 여러 줄이 있으면 정렬 순서를 그대로 믿지 마세요.**

### 3-2. Splunk — TLS 로그 (SNI) { #ssl-log }

```spl
index=zeek sourcetype=zeek:ssl pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h id_resp_p server_name version established
| sort t
```

- `server_name`: **SNI**예요. HTTPS는 내용이 암호화되지만, 연결을 시작할 때 "**어느 사이트에 접속하려는지**"는 암호화하지 않고 보내요. 그래서 HTTPS라도 사이트 이름은 알 수 있어요.
- `version`: TLS 버전. `established`: 연결이 끝까지 잘 맺어졌는지(`true`/`false`)예요.

```text
t         id_resp_h        id_resp_p  server_name                                             version  established
01:38:49  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:38:52  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:38:55  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:38:57  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:39:31  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:40:31  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:40:46  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:40:58  162.125.5.1      443        www.dropbox.com                                         TLSv12   true
01:40:58  162.125.5.1      443        www.dropbox.com                                         TLSv12   true
01:41:01  162.125.5.6      443        uc219cb805d84c449d20210774fc.dl.dropboxusercontent.com  TLSv12   true
01:41:01  162.125.5.6      443        uc219cb805d84c449d20210774fc.dl.dropboxusercontent.com  TLSv12   true
```

**216.194.135.127 = `webmail.a1-associados.com` (회사 웹메일)**

- `a1-associados.com`은 2단계에서 찾은 **피해 회사의 도메인**이에요.
- 첫 연결 **01:38:49**는 사용자 로그인(01:38:12) **37초 뒤**예요. 로그인하자마자 메일을 열었어요.
- 마지막 새 연결 **01:40:46**은 lealcontabil.com 요청(01:40:54) **8초 전**이에요.

쿼리 ①의 Referer 이야기와 연결돼요. "HTTPS 페이지에서 클릭했다"고 했죠. **그 시각에 열려 있던 HTTPS 페이지가 바로 웹메일이에요.** 그래서 "**웹메일에서 메일 속 링크를 눌렀다**"고 판단했어요. 질문 1의 첫 번째 답이에요.

**162.125.5.1 / 162.125.5.6 = Dropbox.** `www.dropbox.com`은 01:40:58에 접속했어요. 마지막 302(01:40:57~58) **바로 다음**이에요. `....dl.dropboxusercontent.com`은 01:41:01에 접속했어요. Dropbox는 공유 링크를 열면 이 `dl.` 주소로 넘겨서 **실제 파일**을 내려 줘요. 왜 Dropbox에 갔는지는 [3-4](#arkime-http)에서 봐요.

### 3-3. Arkime — TLS 세션과 인증서 { #tls-certs }

```text
tags == 20180927_BLANKCLIPBOARD && ip.dst == [216.194.135.127, 162.125.5.1, 162.125.5.6]
```

인증서는 "이 서버가 누구인지" 보여 주는 **신분증**이에요. `Subject CN` / `Alt Name`은 신분증에 적힌 **이름**, `Issuer CN`은 신분증을 **발급한 기관**이에요.

```text
162.125.5.1     Alt Name: www.dropbox.com, dropbox.com, support.dropbox.com ...
                Subject CN: www.dropbox.com   Issuer CN: digicert sha2 extended validation server ca
162.125.5.6     Alt Name: *.dl.dropboxusercontent.com, dl.dropboxusercontent.com, dl.dropbox.com ...
                Subject CN: *.dl.dropboxusercontent.com   Issuer CN: digicert sha2 high assurance server ca
216.194.135.127 (첫 세션, 01:38:49)
                Tags: cert:self-signed   Subject CN: a1-associados.com   Issuer CN: a1-associados.com
```

- **Dropbox:** 이름이 dropbox.com이고 발급 기관이 DigiCert(유명한 공인 인증 기관)예요. **진짜 Dropbox 서버**예요. 가짜가 아니에요.
- **웹메일:** 이름과 발급 기관이 **똑같이** `a1-associados.com`이에요. 회사가 <strong>자기 인증서를 직접 만든 것(self-signed)</strong>이에요. Arkime도 `cert:self-signed` 태그를 붙였어요. 보안상 좋은 습관은 아니지만 작은 회사에선 흔해요. **악성의 증거는 아니에요.**

크기 (Databytes / Bytes, **양방향 합계**):

```text
webmail  01:38:49-01:38:52    1,927 /   2,807
webmail  01:38:56-01:39:31  109,382 / 117,930
webmail  01:39:31-01:40:30  694,760 / 745,266   <- 가장 큼
webmail  01:40:30-01:40:39  455,789 / 487,557
webmail  01:40:46-01:41:27    4,812 /   6,070
dropbox  162.125.5.1  세션 2개  7,720 / 9,086  과  4,180 / 4,952
dropbox  162.125.5.6  세션 2개  3,635 / 4,515  와  5,613 / 6,709
```

큰 웹메일 세션은 웹메일 화면, 메일 목록, 메일 본문 등을 불러온 것으로 보여요. 안은 암호화돼서 **어떤 메일을 열었는지는 알 수 없어요.** 그래서 이메일 파일 자체를 봐야 해요(4단계).

!!! note "정정 — Dropbox 파일 크기"
    처음에는 `dl.dropboxusercontent.com` 다운로드가 "약 11 KB"라고 했는데, 그건 **양방향 합**(4,515 + 6,709)이었어요. **받은 양만** 보면 1단계 쿼리 ③의 `received` 칸에 162.125.5.6이 **7,959바이트**로 나와 있어요. 여기에 TLS 연결 과정(인증서 교환 등, 몇 KB)이 포함돼 있어요. 그래서 실제 파일은 **몇 KB 수준**이에요. 큰 프로그램이 아니라 **작은 스크립트나 바로가기 파일** 정도의 크기예요. 크기만 보고 한 **추정**이고, 암호화돼서 내용은 확인할 수 없어요.

### 3-4. Arkime — HTTP 세션을 펼쳐서 헤더 원문 읽기 { #arkime-http }

```text
tags == 20180927_BLANKCLIPBOARD && ip.dst == [54.38.137.127, 103.6.198.141, 177.12.174.95]
```

세션 왼쪽의 `+`를 누르면 **Source**(PC가 보낸 것, 분홍 글씨)와 **Destination**(서버가 보낸 것, 보라 글씨)이 나와요. Splunk에는 없는 **헤더 원문**을 여기서 봐요. 특히 **`Location:`**(어디로 넘겼나)과 **HTML 본문**을 봤어요.

**세션 ① — 포트 49218, 01:40:54 (lealcontabil.com, 요청 4개)**

요청 1 → 응답 1:

```text
GET /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG HTTP/1.1
Accept: text/html, application/xhtml+xml, */*
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
Host: lealcontabil.com
DNT: 1
Connection: Keep-Alive

HTTP/1.1 301 Moved Permanently
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
Location: http://lealcontabil.com/comercio/?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
```

→ `comercio` 뒤에 `/` 하나만 붙여서 다시 오라는 뜻이에요. 의미 없는 단순 이동이에요.

요청 2 → 응답 2 (**미끼 페이지**):

```text
GET /comercio/?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG HTTP/1.1

HTTP/1.1 200 OK
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
Last-Modified: Wed, 16 Dec 2015 23:30:08 GMT
Content-Length: 1382

<meta name="description" content="Ministério Público Federal">
<title> LOCALIZANDO CONTRATO </title>
<meta http-equiv="refresh" content="1; url=cadastro.php">
... Baixando Arquivo... ...
```

- `Ministério Público Federal` = **브라질 연방 검찰청**이에요. 정부 기관을 사칭했어요.
- `LOCALIZANDO CONTRATO` = "**계약서를 찾는 중**", `Baixando Arquivo...` = "**파일 다운로드 중...**"이에요.
- `<meta http-equiv="refresh" content="1; url=cadastro.php">` = **1초 뒤 자동으로 cadastro.php로 이동**해요. 302와 비슷한 일을 HTML로 하는 거예요.
- `Last-Modified`는 2015년인데 서버는 오래된 `PHP/5.4.16`이고 경로도 이상해요. **해킹된 사이트**에 미끼 페이지를 심어 둔 모양이에요(추정).

요청 3: `GET /favicon.ico` → `404 Not Found`. 브라우저가 탭 아이콘을 자동으로 찾은 거예요. 정상이에요.

요청 4 → 응답 4:

```text
GET /comercio/cadastro.php HTTP/1.1

HTTP/1.1 302 Found
Location: http://54.38.137.127/index.php
```

→ 이제 **도메인 없이 IP 주소**로 보내요.

**세션 ② — 포트 49220, 01:40:57 (54.38.137.127, 요청 2개)**

```text
GET /index.php HTTP/1.1
Host: 54.38.137.127

HTTP/1.1 302 Found
Date: Thu, 27 Sep 2018 01:40:57 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
Set-Cookie: last1=0; expires=Fri, 28-Sep-2018 01:40:57 GMT
Location: a/
```

```text
GET /a/ HTTP/1.1
Cookie: last1=0
Host: 54.38.137.127

HTTP/1.1 302 Found
Date: Thu, 27 Sep 2018 01:40:58 GMT
Set-Cookie: last2=2; expires=Fri, 28-Sep-2018 01:40:58 GMT
Location: https://www.dropbox.com/s/0yggmgtymt2r0av/DOC1_CONTRATO_YBFTOP2078686788.zip?dl=1
```

- **`Set-Cookie`:** 서버가 브라우저에 "이 표시를 기억해"라고 남기는 거예요. 다음 요청에서 브라우저가 `Cookie: last1=0`으로 **그대로 돌려줬어요.** 서버는 이걸로 같은 방문자를 알아봐요. 몇 번 왔는지 세거나, 두 번째 방문부터는 다른 곳으로 보내거나, 분석가나 봇을 걸러 내는 데 써요(추정). 이렇게 IP로만 쓰는 중간 단계를 <strong>관문(gate)</strong>이라고 해요.
- **마지막 `Location`:** 드디어 목적지가 나와요. <strong>Dropbox 공유 링크의 `DOC1_CONTRATO_YBFTOP2078686788.zip`</strong>이에요. 끝의 `?dl=1`은 "미리보기 말고 **바로 다운로드**"라는 뜻이에요. `contrato`는 "계약서"예요. 미끼 제목 "계약서를 찾는 중"과 맞아요. 공격자가 <strong>믿을 만한 서비스(Dropbox)</strong>에 파일을 올려 둔 거예요. 보안 장비가 dropbox.com을 막기 어렵다는 점을 노렸어요.
- `Date` 헤더로 실제 순서(index.php 01:40:57 → /a/ 01:40:58)도 확인했어요. [Splunk 정렬 문제](#http-log)가 여기서 풀렸어요.

이 `Location` 덕분에 01:40:58과 01:41:01의 Dropbox TLS가 **왜 생겼는지** 설명돼요. **질문 2의 답이에요.**

**세션 ③, ④ — 포트 49217, 49219 (데이터 0)**

```text
Databytes 0
TCP Flags: SYN 1  SYN-ACK 1  ACK 1  RST 1
```

연결만 맺고 아무것도 안 보낸 채 끊었어요(RST). IE는 페이지를 빨리 불러오려고 **연결을 미리 몇 개 열어 두고**, 안 쓰면 닫아요. **정상이에요.**

**세션 ⑤ — 포트 49225 (ZIP)** — [1-5](#arkime-split)의 세 줄이에요. 헤더는 Splunk에서 이미 봤어요(MSIE 7.0 UA, Referer 없음, 17 MB).

**세션 ⑥ — 포트 49226, 01:44:06 (serveengenharia.com.br)**

```text
GET /tmp/soares/cont1/ HTTP/1.1
Host: serveengenharia.com.br
Cache-Control: no-cache

HTTP/1.1 200 OK
Date: Thu, 27 Sep 2018 01:43:25 GMT
Server: Apache
Transfer-Encoding: chunked
Content-Type: text/html

<meta HTTP-EQUIV='Refresh' CONTENT='0;URL=http://www.google.com'>
```

- **요청 헤더가 두 줄뿐**이에요. IE 11 요청과 비교해 보세요. IE는 Accept, Accept-Language, User-Agent, Accept-Encoding, DNT, Connection까지 항상 보내요. 여기에는 아무것도 없어요. **사람의 브라우저가 아니에요.** Splunk에서 User-Agent가 빈칸이었던 이유가 이거예요.
- **응답 본문**은 "0초 뒤 google.com으로 가라" 한 줄이에요. 누가 이 주소를 브라우저로 열어 봐도 그냥 구글로 넘어가요. **무해해 보이게 숨기는 응답**이에요.
- `cont1`(*contador*?)이라는 이름과 ZIP을 받은 직후 **딱 한 번** 짧게 보냈다는 점을 보면 **감염 1건을 세는 카운터**일 가능성이 있어요(추정).
- 응답 `Date`(01:43:25)가 캡처 시각(01:44:06)보다 41초 이른 건 **서버 시계가 늦은 것**이에요. 시각은 항상 **캡처 시각**을 기준으로 써요.

### 3-5. 질문: Referer가 비어 있다는 건 어떻게 아나 { #referer-empty }

!!! question "질문: referer가 비어 있다고 했는데 그건 어떻게 알 수 있나요?"
    두 곳에서 확인할 수 있어요. **Splunk의 `referrer` 칸**과 **Arkime의 요청 헤더 원문**이에요.

    **1. Splunk — `referrer` 칸이 빈칸.** HTTP 쿼리의 `table`에 `referrer`를 넣었어요. 결과에서 `uri` 바로 오른쪽이 `referrer` 칸인데, **10줄 모두 값이 없었어요.** 옆의 `user_agent` 칸은 값이 차 있는 것과 비교해 보면 잘 보여요. Zeek은 HTTP 요청에 `Referer:` 헤더가 **있으면 그 값을** `referrer` 필드에 적고, <strong>없으면 `-`</strong>를 적어요. `-`는 Zeek 로그에서 "값이 없음" 표시이고, Splunk는 보통 빈칸으로 보여 줘요. (Zeek의 필드 이름은 `referrer`(r 두 개), HTTP 헤더 이름은 `Referer`(r 하나, 옛날 철자 실수가 표준이 된 것)예요. 같은 거예요.)

    빈칸은 눈으로 보면 놓치기 쉬워서 **개수를 세면** 확실해요.

    ```spl
    index=zeek sourcetype=zeek:http pcap_case=20180927_BLANKCLIPBOARD
    | eval has_ref=if(isnull(referrer) OR referrer="" OR referrer="-", "no", "yes")
    | stats count by has_ref
    ```

    - 2줄 `eval has_ref=if(조건, "no", "yes")`: 새 칸 `has_ref`를 만들어요. `if(조건, A, B)`는 조건이 맞으면 A, 아니면 B예요. 조건은 `isnull(referrer)`(필드 자체가 없음), `referrer=""`(빈 글자), `referrer="-"`(Zeek의 "없음" 표시가 그대로 들어옴)이고, 하나라도 맞으면(`OR`) `"no"`예요.
    - 3줄: `no`와 `yes`가 각각 몇 줄인지 세요.

    ```text
    has_ref   count
    no        10
    ```

    `yes` 줄이 없으면 **10개 요청 모두 Referer가 없었다**는 뜻이에요. 원본을 직접 보려면:

    ```spl
    index=zeek sourcetype=zeek:http pcap_case=20180927_BLANKCLIPBOARD
    | table _raw
    ```

    - `_raw`: Splunk가 받은 **원래 로그 한 줄**이에요. 탭으로 나뉜 값 가운데 `referrer` 자리에 `-`가 보여요.

    **2. Arkime — 요청 헤더 원문에 `Referer:` 줄이 없음.** **가장 직접적인 증거**예요. Splunk는 Zeek이 정리한 결과지만, Arkime는 **PC가 실제로 보낸 글자 그대로**를 보여 줘요. lealcontabil.com 첫 요청은 이 7줄이 **전부**였어요.

    ```text
    GET /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG HTTP/1.1
    Accept: text/html, application/xhtml+xml, */*
    Accept-Language: en-US
    User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
    Accept-Encoding: gzip, deflate
    Host: lealcontabil.com
    DNT: 1
    Connection: Keep-Alive
    ```

    Referer가 있었다면 `Referer: https://webmail.a1-associados.com/...` 같은 줄이 끼어 있었을 거예요.

    펼친 화면 오른쪽 **HTTP** 상자의 **`Request Headers`** 칸은 그 세션에서 PC가 보낸 **헤더 이름 목록**이에요(세션 안 모든 요청을 합친 것).

    ```text
    lealcontabil.com (포트 49218)  : accept  accept-encoding  accept-language  connection  dnt  host  user-agent
    54.38.137.127    (포트 49220)  : accept  accept-encoding  accept-language  connection  cookie  dnt  host  user-agent
    serveengenharia  (포트 49226)  : cache-control  host
    ```

    세 목록 어디에도 `referer`가 없어요. 세션을 하나씩 펼치지 않고 바로 찾을 수도 있어요. "없다"를 증명할 때는 **있는 것을 찾았는데 0건**으로 확인하는 게 좋아요.

    ```text
    tags == 20180927_BLANKCLIPBOARD && http.request-header == referer
    ```

    - `http.request-header`: `Request Headers` 칸을 검색하는 필드예요. `== referer`: 헤더 이름 목록에 `referer`가 있는 세션만 찾아요. (필드 이름 오류가 나면 검색창에 `http.request`까지만 치고 자동 완성 목록에서 고르세요.)

    **3. Referer가 비어 있을 때 생각할 수 있는 이유**

    | 이유 | 이번 캡처에 맞는가 |
    |---|---|
    | **HTTPS 페이지에서 HTTP 페이지로 이동** (브라우저가 보안상 Referer를 뺌) | lealcontabil.com 첫 요청에 맞아요. 8초 전까지 HTTPS 웹메일이 열려 있었어요 |
    | 주소창에 직접 입력하거나 즐겨찾기로 열기 | 이런 긴 이상한 URL을 사람이 직접 칠 리 없어요 |
    | Outlook 같은 **메일 프로그램이나 다른 앱**에서 링크를 열기 | 가능은 해요. 하지만 이 PC는 웹메일을 쓰고 있었어요 |
    | **브라우저가 아닌 프로그램**이 직접 요청 | ZIP(01:42:22)과 serveengenharia(01:44:06)에 맞아요. User-Agent도 브라우저가 아니었어요 |

    **리다이렉트 뒤 요청들이 다 비어 있는 이유:** 301, 302로 넘어갈 때 브라우저는 **새 Referer를 만들지 않아요.** 처음 요청의 Referer를 이어 가거나 빼요. 처음부터 없었으니 체인 전체(`/comercio/` → `cadastro.php` → `index.php` → `/a/`)에 계속 없었어요. `<meta http-equiv="refresh">`로 넘어가는 경우에도 IE는 보통 Referer를 보내지 않아요.

    **분석에서 어떻게 썼나:** Referer가 없다는 사실 **하나만으로는** "웹메일에서 클릭했다"고 말할 수 없어요. Referer 없음(Splunk + Arkime), 바로 그 시각에 HTTPS 웹메일 사용 중(SNI, 마지막 연결 01:40:46), 8초 뒤 링크 요청 — 세 가지를 **합쳐서** "가능성 높음"으로 판단했고, 4단계 이메일에서 **확정**했어요.

### 3-6. 네 화면을 합친 결론 { #chain-summary }

```text
[2단계 Kerberos]   01:38:12  thiago.almeida 로그인
        | 37초
[SNI]              01:38:49  웹메일(webmail.a1-associados.com) 열기
        | 마지막 웹메일 연결 01:40:46, 8초 뒤
[HTTP + Arkime ①]  01:40:54  IE11이 lealcontabil.com 링크 열기 (Referer 없음 = HTTPS 페이지에서 클릭)
                   01:40:55  미끼 페이지 "검찰청 / 계약서 찾는 중 / 파일 다운로드 중"
                   01:40:56  302 -> 54.38.137.127/index.php
[Arkime ②]         01:40:57  302 + 쿠키 -> /a/
                   01:40:58  302 -> Dropbox DOC1_CONTRATO_YBFTOP2078686788.zip
[SNI + Arkime TLS] 01:41:01  Dropbox에서 작은 파일(몇 KB) 다운로드
        | 1분 21초 (사용자가 파일을 열고 실행한 시간으로 추정)
[HTTP]             01:42:22  프로그램(MSIE 7.0 UA)이 dnpland.com.my에서 17 MB ZIP 다운로드
[HTTP + Arkime ⑥]  01:44:06  프로그램(UA 없음)이 serveengenharia.com.br/.../cont1/ 요청 (카운터 추정)
[2단계]            01:48~49  재부팅 추정
```

**확인 (화면에 값이 있음):** 웹메일 사용(SNI), 링크 → 미끼 페이지 → 54.38.137.127 → Dropbox ZIP으로 이어지는 리다이렉트 체인(`Location` 헤더), 미끼 내용(HTML), 17 MB ZIP과 serveengenharia 요청은 브라우저가 아닌 프로그램이 보냄(User-Agent, 헤더 모양).

**추정 (근거는 있지만 확정 아님):** 링크를 **웹메일 속 메일에서** 클릭했다(Referer 없음 + 8초 차이) → 4단계에서 확인, Dropbox 파일은 작은 스크립트나 바로가기였다(크기만 봄), 그 파일을 실행해서 17 MB ZIP을 받았다(시간 순서 + UA), serveengenharia는 감염 카운터다(이름 + 모양).

**이번 캡처에서 안 보이는 것:** 지속적인 C2(비콘)예요. 재부팅 뒤 2분 남짓 만에 캡처가 끝났어요. 사용자가 다시 로그인해야 시작되거나, 다른 통로를 쓸 수도 있어요. 티켓에는 "이번 캡처에서는 C2가 관찰되지 않음"이라고만 써요.

**티켓 타임라인 초안:**

```text
#TIMELINE (UTC, 2018-09-27)#
01:38:12  User thiago.almeida logged on to Escritorio-PC (172.16.5.203).
01:38:49  User opened company webmail (webmail.a1-associados.com, 216.194.135.127).
01:40:54  IE11 opened a link with no Referer (likely clicked in webmail):
          hxxp://lealcontabil[.]com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
          Lure page: "LOCALIZANDO CONTRATO", fake "Ministerio Publico Federal".
01:40:56  Redirect chain: /comercio/cadastro.php -> hxxp://54.38.137.127/index.php -> /a/
01:40:58  Redirect to Dropbox: hxxps://www.dropbox[.]com/s/0yggmgtymt2r0av/DOC1_CONTRATO_YBFTOP2078686788.zip?dl=1
          (small file, downloaded from dl.dropboxusercontent.com at 01:41:01)
01:42:22  Non-browser program (UA "MSIE 7.0") downloaded 17 MB ZIP:
          hxxp://dnpland[.]com.my/images/z2448800.zip (103.6.198.141)
01:44:06  Non-browser program (no User-Agent) requested:
          hxxp://serveengenharia[.]com.br/tmp/soares/cont1/ (177.12.174.95) - possible infection counter
01:48-01:49  Host likely restarted (machine logon, DHCP and NCSI repeated). Not confirmed.
No C2 traffic seen in this capture after 01:44:06.
```

URL은 `hxxp`와 `[.]`로 <strong>무력화(defang)</strong>해 두었어요. 티켓을 읽는 사람이 실수로 클릭하지 않게 하려는 거예요. 검색 쿼리나 Snort 룰에서는 원래 모양 그대로 써요.

---

## 4단계 — 이메일 두 개: 어느 메일이 감염을 시작했나 { #emails }

**목적:** 문제의 질문에 답해요. 트래픽에서 이미 **찾아야 할 메일의 조건**이 나와 있어요.

- **받는 사람:** thiago.almeida (또는 `@a1-associados.com` 주소)
- **도착 시각:** **01:40:54 UTC 전**
- **본문:** **`lealcontabil.com/comercio...`** 링크, 또는 "contrato", "Ministério Público Federal", "whatsapp" 같은 단어

!!! tip "왜 트래픽 먼저, 이메일은 나중에"
    [피싱 미끼 사례](phishing-red-herring-ek-driveby-ursnif-c2.md)에서는 이메일을 먼저 봤어요. 그래서 "이메일이 원인이겠지"라는 선입견이 생겼는데, 실제 감염은 웹 drive-by였어요. 트래픽에서 **사실을 먼저** 확보하면 이런 함정을 피할 수 있어요.

!!! danger "이메일을 안전하게 다루기"
    이메일 안의 링크와 첨부파일은 진짜 악성이에요. `.eml`을 노트북에서 더블클릭해서 Outlook이나 메일 앱으로 열지 마세요. 압축은 pcapbox 같은 분석 VM 안에서만 풀고, `cat`, `less`로 **텍스트로만** 보세요.

### 4-1. 명령어 { #email-commands }

**① 압축 풀기**

```bash
mkdir -p ~/cases/20180927_BLANKCLIPBOARD/emails
cd ~/cases/20180927_BLANKCLIPBOARD/emails
unzip /path/to/2018-09-27-traffic-analysis-exercise-both-emails.zip
ls -l
```

- `mkdir -p`: 폴더를 만들어요(중간 폴더까지, 이미 있으면 그냥 넘어가요). `cd`: 그 폴더로 들어가요.
- `unzip`: 압축을 풀어요. `/path/to/`는 ZIP이 실제로 있는 위치로 바꾸세요. 비밀번호는 사이트 "about" 페이지에 있어요.
- `ls -l`: 풀린 파일 이름과 크기예요.

**② 헤더만 보기 (누가, 누구에게, 언제, 제목)**

```bash
grep -iE '^(Date|From|To|Subject|Return-Path|Message-ID|Content-Type|Content-Transfer-Encoding):' *.eml
```

- `grep`: 조건에 맞는 줄만 찾아요. `-i`: 대소문자 무시. `-E`: 확장 정규식이라 `(A|B|C)` = "A 또는 B 또는 C"를 쓸 수 있어요.
- `'^(Date|From|...):'`: 이 헤더 이름으로 **시작하는**(`^`) 줄만이에요.
- `*.eml`: 폴더 안 모든 `.eml` 파일이에요. 결과 앞에 파일 이름이 붙어서 두 메일을 구분할 수 있어요.

볼 것: `To:`가 thiago.almeida인가? `Date:`가 01:40:54 UTC 전인가? `Content-Transfer-Encoding:`이 무엇인가?(`base64`나 `quoted-printable`이면 ③에서 링크가 안 보이거나 잘려 보일 수 있어요.)

**③ 본문 속 링크 찾기**

```bash
grep -oiE 'https?://[^"<> ]+' *.eml | sort -u
```

- `-o`: 줄 전체가 아니라 **맞는 부분만** 보여 줘요.
- `https?://`: `http://` 또는 `https://` (`?`는 앞 글자 `s`가 있어도 되고 없어도 된다는 뜻이에요).
- `[^"<> ]+`: 따옴표, `<`, `>`, 공백이 아닌 글자가 이어지는 동안 = **URL 끝까지**예요.
- `sort -u`: 정렬하고 중복을 없애요.

이번 두 메일은 모두 `Content-Transfer-Encoding: 8bit` HTML이라 링크를 텍스트로 바로 읽을 수 있었어요.

### 4-2. 두 메일을 나란히 보기 { #email-compare }

| 항목 | 메일 A | 메일 B |
|---|---|---|
| 제목 | `Conversa do WhatsApp no (221206)` | `Anotacao de Extrato De Debitos para seu CPF/CNPJ. No (778071)` |
| 제목 뜻 | "WhatsApp 대화 번호 (221206)" | "당신의 CPF/CNPJ에 대한 채무 내역 등록" |
| From (보이는 보낸 사람) | `WhatsApp-WEB <nwindows@communication.microsoft.com>` | `Comunicado \| Serasa Experian <atendimento@serasaexperian.com.br>` |
| 실제 보낸 서버 | `tghs18.portaldecontabil.com.br [145.239.135.211]` | `tghs8.portaldecontabil.com.br [145.239.31.79]` |
| 받는 사람 | thiago.almeida@a1-associados.com | thiago.almeida@a1-associados.com |
| 도착 시각 (UTC) | **2018-09-24 12:52:42** | **2018-09-26 16:19:47** |
| 본문 링크 | `bit.ly/2k5P2Kt?...`, **`lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG`** | `consultafacilserasaexperian.com/clientes?...` |
| 첨부파일 | 없음 (HTML 본문만) | 없음 (HTML 본문만) |

CPF는 브라질의 개인 납세자 번호, CNPJ는 회사 번호예요. Serasa Experian은 브라질의 **신용평가 회사**예요.

### 4-3. 헤더 읽는 법 — 어디를 믿고 어디를 의심하나 { #email-headers }

**`From:`은 믿으면 안 돼요.** 보내는 사람이 아무 글자나 적을 수 있는 칸이에요. 메일 A는 "WhatsApp"이라면서 주소는 `microsoft.com`이에요. 서로 맞지도 않아요.

**`Received:`가 더 믿을 만해요.** 메일 서버를 하나 지날 때마다 그 서버가 **맨 위에 한 줄씩** 덧붙여요. 그래서 <strong>맨 위의 `Received:`</strong>가 가장 중요해요. 우리 회사 서버(`smtp.a1-associados.com`)가 직접 적은 줄이라 위조하기 어렵거든요.

```text
Received: from tghs18.portaldecontabil.com.br ([145.239.135.211]) by
	smtp.a1-associados.com for thiago.almeida@a1-associados.com;
	Mon, 24 Sep 2018 12:52:42 +0000 (UTC)
```

- `from tghs18.portaldecontabil.com.br ([145.239.135.211])`: 실제로 메일을 건네준 서버예요. WhatsApp도 Microsoft도 아니고 **브라질의 `portaldecontabil.com.br`** 서버예요.
- `by smtp.a1-associados.com`: 받은 쪽은 피해 회사의 메일 서버예요. `for thiago.almeida@...`: 받는 사람이에요.
- `+0000`: UTC라는 뜻이에요.

**`Date:`의 시간대 계산.** `Date: Mon, 24 Sep 2018 09:52:39 -0300`에서 `-0300`은 "UTC보다 3시간 늦은 시간대"(브라질)예요. UTC로 바꾸려면 **3시간을 더해요.** 09:52:39 + 3시간 = **12:52:39 UTC**. 3초 뒤 회사 서버에 도착했으니 맞아요.

**`X-PHP-Originating-Script: 1000:javali.php`** — 가장 재미있는 헤더예요. 웹 서버의 **PHP 프로그램**이 메일을 보내면 PHP가 자동으로 이 줄을 붙여요. `javali.php`라는 **스크립트가 보낸 메일**이라는 뜻이에요. 그런데 `X-Mailer: Microsoft Office Outlook`라고 적혀 있어요. Outlook으로 보낸 척했지만 실제로는 **웹 서버의 스크립트로 대량 발송**한 거예요. 이런 모순은 스팸과 피싱에서 흔해요.

### 4-4. 두 메일은 같은 공격자가 보냈어요 { #same-sender }

- 실제 발송 서버가 같은 도메인 `portaldecontabil.com.br`이에요(tghs18, tghs8). IP도 둘 다 `145.239.x.x`예요.
- `X-PHP-Originating-Script: 1000:javali.php`가 똑같아요.
- `X-Mailer: Microsoft Office Outlook, Build 17.551210`이 똑같아요.
- 둘 다 포르투갈어이고, 받는 사람도 같아요.

미끼만 다르고 **같은 발송 도구로 보낸 같은 캠페인**이에요. 메일 B는 이번 감염의 원인은 아니지만, **같은 공격자의 다른 시도**로 티켓에 남길 가치가 있어요. 메일 B 본문은 **빈 줄 수천 개로 부풀려져** 있어요(필터와 검사기를 피하려는 수법).

### 4-5. 메일 A 본문 — 무슨 내용으로 속였나 { #email-body }

포르투갈어 본문의 대략적인 뜻이에요.

> "에휴, 바보! 내가 이 짓을 절대 모를 줄 알았지? 착각이야! 다 알아!! 너가 다른 사람들이랑 나에 대해 나눈 대화 사진을 보냈더라! 여기 네 대화 기록이야. … 이대로 그냥 넘어가지 않을 거야, 알았어? 잘 가."

**감정을 자극하는 미끼**예요. 화난 지인이 "네 뒷담화 증거를 잡았다"고 하면, 사람은 무슨 대화인지 확인하고 싶어서 **생각하기 전에 클릭**하게 돼요.

링크 부분이에요.

```html
<a href="http://bit.ly/2k5P2Kt?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG" ...>
  <img src="https://goo.gl/NFk0qQ" ...></a>

<a href="http://lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG" ...>
  Whatsapp_Beckup_REG(656386387).zip</a>
```

- `href="..."`는 **실제로 가는 주소**, `<a>`와 `</a>` 사이 글자는 **화면에 보이는 글자**예요.
- 두 번째 링크는 화면에 <strong>`Whatsapp_Beckup_REG(656386387).zip`</strong>이라는 **파일 이름처럼** 보여요. 사용자는 "대화 백업 파일을 받는구나" 하고 눌러요. 실제로는 `lealcontabil.com`으로 가는 웹 링크예요.
- 첫 번째 링크는 이미지(`goo.gl` 단축 주소의 그림)를 누르면 `bit.ly` 단축 주소로 가요. 단축 주소를 쓰면 진짜 목적지가 안 보여요.

### 4-6. 결정적 증거 — 트래픽 URL과 완전히 같아요 { #url-match }

```text
메일 A 링크 : http://lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
트래픽 요청 : GET /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG   Host: lealcontabil.com   (01:40:54)
```

경로, 이상한 `?` 위치, 철자 오류 `Beckup`까지 **완전히 같아요.** 이런 긴 URL이 우연히 같을 수는 없어요.

3단계의 추정들도 여기서 **확인**돼요.

- **Referer가 없었던 이유:** HTTPS 웹메일에서 HTTP 링크를 눌렀기 때문이고, 메일 HTML에 `rel="noopener noreferrer"`도 붙어 있어요. 이 표시가 있으면 브라우저가 **Referer를 아예 보내지 않아요.** 두 가지 이유가 겹쳐서 비어 있던 거예요.
- **어느 링크를 눌렀나:** 트래픽에 `bit.ly` 요청이 없고 `lealcontabil.com`으로 **바로** 갔어요. 그러니 이미지(bit.ly)가 아니라 **`Whatsapp_Beckup_REG(...).zip` 글자 링크**를 눌렀어요.
- **`e=whatsapp_Beckup_REG`의 뜻:** 미끼 페이지는 "검찰청 계약서"였는데 메일은 "WhatsApp 대화"였어요. 같은 랜딩 페이지를 **여러 캠페인이 같이 쓰고**, 이 파라미터로 **어느 메일에서 왔는지 구분**하는 것으로 보여요(추정).

### 4-7. 시간 맞춰 보기 { #email-times }

- 메일 A 도착: **09-24 12:52 UTC**
- 메일 B 도착: 09-26 16:19 UTC
- 링크 클릭: **09-27 01:40:54 UTC**

메일 A는 **약 2.5일 전**에 왔고, 사용자는 27일 웹메일을 열었을 때 눌렀어요. 01:40 UTC는 브라질 시간(-03:00)으로 **9월 26일 밤 22:40**이에요. 사용자가 밤늦게 메일을 정리하다 눌렀을 수 있어요. (도착 시각은 클릭 시각과 가까울 필요가 없어요. 메일은 받은 뒤 며칠 있다 열어도 되니까요.)

!!! question "질문: 링크 클릭 09-27 01:40:54 UTC — 이 시각은 어떻게 알 수 있는 건가요?"
    짧게 답하면, <strong>01:40:54는 "마우스를 누른 순간"이 아니라 "그 클릭 때문에 PC가 lealcontabil.com에 첫 요청을 보낸 시각"</strong>이에요. 네트워크 캡처는 PC 안에서 일어난 일(마우스 클릭)은 못 보고 **네트워크로 나간 패킷**만 봐요. 그래서 "클릭 시각"은 **첫 요청 시각**으로 대신해요.

    **이미 본 화면 세 곳에 같은 시각이 있어요.**

    - **3단계 Splunk HTTP의 `t` 칸:** `01:40:54  54.38.137.127  lealcontabil.com  /comercio?imagens/...` — `t`는 Zeek `ts`이고, http.log의 `ts`는 **그 HTTP 요청이 시작된 시각**이에요. 메일 속 URL과 똑같은 요청이 **01:40:54**에 처음 나와요.
    - **3단계 Arkime 세션 목록(포트 49218):** `Start Time 2018/09/27 01:40:54` — 그 세션의 **첫 패킷** 시각이에요.
    - **1단계 Splunk 쿼리 ③의 `first` 칸:** `54.38.137.127  4  01:40:54  80  http` — `min(ts)`, 이 PC가 54.38.137.127에 **처음 연결한 시각**이에요. 01:40:54 **전에는** 이 서버로 간 연결이 하나도 없어요. "이때가 처음"이라는 걸 이 칸이 보여 줘요.

    **클릭 → 요청까지 실제로 일어나는 일** (보통 1초도 안 걸려요):

    1. **DNS 질의:** "lealcontabil.com의 IP가 뭐야?" → DNS 서버(이 회사는 DC 172.16.5.5)에 물어요
    2. **DNS 응답:** "54.38.137.127이야"
    3. **TCP 연결:** 54.38.137.127:80에 SYN → conn.log의 `ts`
    4. **HTTP 요청:** `GET /comercio?...` → http.log의 `ts`

    **진짜 클릭 순간에 가장 가까운 건 DNS 질의**예요. 초 단위로는 다 01:40:54로 보여요. **밀리초**까지 보면 순서가 보여요.

    ```spl
    index=zeek sourcetype=zeek:dns pcap_case=20180927_BLANKCLIPBOARD query="*lealcontabil*"
    | eval t=strftime(ts,"%H:%M:%S.%3N")
    | table t id_orig_h id_resp_h query answers
    | sort t
    ```

    - 1줄: DNS 로그 중 질의 이름에 `lealcontabil`이 들어간 것만 가져와요.
    - 2줄: `%3N`은 **밀리초(1/1000초) 3자리**예요. `01:40:54.123`처럼 나와요.
    - 3줄: `query`는 물어본 이름, `answers`는 받은 IP, `id_resp_h`는 DNS 서버 IP예요(172.16.5.5가 나올 거예요).

    ```spl
    index=zeek pcap_case=20180927_BLANKCLIPBOARD (sourcetype=zeek:conn OR sourcetype=zeek:http) id_resp_h="54.38.137.127"
    | eval t=strftime(ts,"%H:%M:%S.%3N")
    | table t sourcetype id_orig_p uri
    | sort t
    ```

    - 1줄: conn 로그와 http 로그를 **함께** 가져와요. 목적지가 54.38.137.127인 것만이에요.
    - 3줄: `sourcetype`으로 어느 로그인지 구분해요. `id_orig_p`는 PC 쪽 포트(49218 등)예요. conn 줄에는 `uri`가 비어 있어요.

    결과 모양 (밀리초 값은 예시예요):

    ```text
    t              sourcetype   id_orig_p  uri
    01:40:54.0xx   zeek:conn    49217
    01:40:54.0xx   zeek:conn    49218
    01:40:54.0xx   zeek:http    49218      /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
    ```

    DNS 질의 → conn(49218) → http(49218)이 몇십~몇백 밀리초 안에 이어지면, **클릭은 DNS 질의 바로 직전**이에요.

    **티켓에는** 우리가 아는 것, 즉 "**링크가 열린(첫 요청이 나간) 시각**"으로 써요.

    ```text
    Link opened : 2018-09-27 01:40:54 UTC (first DNS/HTTP request to lealcontabil[.]com, from webmail)
    ```

    사용자가 메일을 **처음 읽은 시각**은 네트워크로 알 수 없어요. 웹메일이 HTTPS라 암호화돼 있거든요. 메일 서버 로그(열람 기록)나 호스트의 브라우저 기록에서 확인할 일이라 **호스트 담당자 단서**로 넘겨요.

### 4-8. 메일 B가 원인이 *아니라는* 것도 확인하기 { #negative-check }

"A의 링크가 트래픽에 있다"만 보는 게 아니라 <strong>"B의 링크는 트래픽에 없다"</strong>도 확인해야 결론이 단단해져요. 메일 A의 다른 주소(bit.ly, goo.gl)도 같이 찾아요.

**Splunk**

```spl
index=zeek pcap_case=20180927_BLANKCLIPBOARD ("consultafacilserasaexperian" OR "encontraaruja" OR "bit.ly" OR "goo.gl")
| table sourcetype _raw
```

- 1줄: `sourcetype`을 지정하지 않아서 이번 케이스의 **모든 Zeek 로그**(conn, dns, http, ssl 등)에서 찾아요. `index=zeek`는 명시했으니 회사 지침에도 맞아요.
- `("A" OR "B" ...)`: 원본 글자 안에 넷 중 하나라도 있는 줄이에요. `consultafacilserasaexperian`(메일 B 링크), `encontraaruja`(메일 B 그림), `bit.ly`와 `goo.gl`(메일 A의 단축 링크와 그림)이에요.
- 2줄: 어느 로그(`sourcetype`)에서 나왔는지와 원본(`_raw`)을 보여 줘요.

**Arkime**

```text
tags == 20180927_BLANKCLIPBOARD && (host == *serasa* || host == *encontraaruja* || host == *bit.ly* || host == *goo.gl*)
```

- `host`: DNS 질의 이름, HTTP Host, TLS SNI 등 **모든 호스트 이름 필드**를 한 번에 검색해요.
- `*serasa*`: 앞뒤에 무엇이 붙든 `serasa`가 들어 있으면 맞아요. `||`는 "또는"이에요.

**결과: 둘 다 0건.** 그래서 이번 캡처에서:

- 메일 B의 링크는 **열리지 않았어요.** 그림도 불러오지 않았어요(메일 B를 화면에 띄웠는지조차 네트워크로는 알 수 없어요).
- 메일 A의 **그림 링크(bit.ly)는 누르지 않았고**, 그림(goo.gl)도 **불러오지 않았어요**(웹메일이 외부 그림을 막았을 수 있어요).
- 사용자는 메일 A의 **글자 링크** `Whatsapp_Beckup_REG(656386387).zip` **하나만** 눌렀어요.

**한계:** "없다"는 건 **이 14분 캡처 안에서만** 맞는 말이에요. 메일 B는 26일에 도착했으니 캡처 전에 열었을 수도 있어요. 티켓에는 이렇게 써요.

```text
Second email (Serasa Experian lure): no traffic to its link or images in this capture
(2018-09-27 01:37-01:51 UTC). Earlier clicks cannot be ruled out - check mailbox / proxy logs.
```

### 4-9. 문제의 답 { #exercise-answer }

> **감염을 시작한 메일은 "Conversa do WhatsApp no (221206)" (2018-09-24 12:52 UTC 도착)이에요.** 사용자 thiago.almeida가 2018-09-27 01:40:54 UTC에 웹메일에서 이 메일의 `Whatsapp_Beckup_REG(656386387).zip` 링크를 눌렀어요. 메일 B(Serasa Experian 사칭)는 같은 공격자가 보냈지만 이 캡처에서는 열린 흔적이 없어요.

!!! note "알아차리면 좋은 작은 불일치"
    메일 B의 `Received` 줄에는 `smtp.a1-associaods.com`이라는 **철자 오류**가 있어요(associ**ao**ds). 문제를 만든 사람이 실수한 것으로 보이고 분석에는 영향이 없어요. 하지만 이런 작은 불일치를 알아차리는 습관은 좋아요. 실제 사건에서는 위조된 헤더의 단서가 되기도 해요.

---

## 5단계 — 17 MB ZIP { #zip }

**목적:** ZIP이 **온전한지**(1단계에서 패킷 손실 태그가 있었어요), **해시**(IOC로 쓰고 다른 PC에서 같은 파일을 찾는 데 써요), **안에 무엇이 들었는지**(이름만, 절대 실행하지 않음)를 확인해요.

### 5-1. Splunk — Zeek files.log { #files-log }

```spl
index=zeek sourcetype=zeek:files pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t tx_hosts rx_hosts source mime_type seen_bytes total_bytes missing_bytes md5 sha1
| sort t
```

- 1줄: Zeek이 트래픽에서 찾은 **파일 기록**이에요. 파일 하나가 한 줄이에요.
- 3줄 `table`:
    - `tx_hosts` / `rx_hosts`: 파일을 **보낸** / **받은** IP (다운로드면 서버 / PC)
    - `source`: 어느 프로토콜로 옮겨졌나 (`HTTP`, `SSL`, `SMB`)
    - `mime_type`: 첫 바이트로 알아낸 파일 종류
    - `seen_bytes`: Zeek이 **실제로 본** 바이트 수
    - `total_bytes`: 서버가 "이만큼 보낸다"고 한 크기 (HTTP `Content-Length`)
    - `missing_bytes`: **빠진 바이트 수** — 이번 단계의 핵심이에요
    - `md5`, `sha1`: 파일 해시 (Zeek 설정에 따라 비어 있을 수 있어요)

**결과 (파일 11개):**

```text
t         tx_hosts         rx_hosts      source  mime_type   seen_bytes  total_bytes  missing_bytes  md5
01:37:03  172.16.5.5       172.16.5.203  SMB     text/ini    22          22           0              b20996efc49d181769db184aeea375a2
01:37:08  23.65.180.72     172.16.5.203  HTTP    text/plain  14          14           0              cd5a4d3fdd5bffc16bf959ef75cf37bc
01:38:13  172.16.5.5       172.16.5.203  SMB     text/ini    22          22           0              b20996efc49d181769db184aeea375a2
01:40:55  54.38.137.127    172.16.5.203  HTTP    text/html   209         209          0              18ffb59b61525f781cf9251045be575d
01:40:55  54.38.137.127    172.16.5.203  HTTP    text/html   1382        1382         0              6f23120907a7c8e6a884ea9cb6b0807e
01:40:55  54.38.137.127    172.16.5.203  HTTP    text/html   297         297          0              05f7e2ed44d9d45022ce1a15c44800e3
01:42:23  103.6.198.141    172.16.5.203  HTTP                15098446    17066397     1967951
01:44:07  177.12.174.95    172.16.5.203  HTTP                72                       0              a31fcd450e6b680316a04687c0ee3602
01:49:11  172.16.5.5       172.16.5.203  SMB     text/ini    22          22           0              b20996efc49d181769db184aeea375a2
01:49:13  200.157.208.243  172.16.5.203  HTTP    text/plain  14          14           0              cd5a4d3fdd5bffc16bf959ef75cf37bc
01:49:55  172.16.5.5       172.16.5.203  SMB     text/ini    22          22           0              b20996efc49d181769db184aeea375a2
```

!!! note "`source` 칸에 값이 두 개씩 나온 이유"
    모든 줄의 `source` 칸에 `/data/zeek/20180927_BLANKCLIPBOARD/files.log`와 `HTTP`(또는 `SMB`)가 같이 나왔어요. `host` 칸과 같은 종류의 **필드 이름 충돌**이에요. Splunk의 `source`는 **이 로그를 어느 파일에서 읽었나**, Zeek의 `source`는 **파일이 어느 프로토콜로 옮겨졌나**예요. 이름이 같아서 한 칸에 둘 다 들어갔어요. 아래쪽 값(`HTTP`, `SMB`)이 Zeek 값이에요.

**그룹 1 — 정상 (Windows 기본 동작)**

- **SMB `text/ini` 22바이트, DC에서 옴:** 그룹 정책 설정 파일 <strong>`GPT.INI`</strong>로 보여요. Windows는 **부팅할 때와 로그인할 때** DC의 SYSVOL 공유에서 이 파일을 읽어서 "정책이 바뀌었나?"를 확인해요. 해시가 4번 다 같아요.
- **HTTP `text/plain` 14바이트:** NCSI의 `ncsi.txt`예요. 내용은 "Microsoft NCSI"(14글자)예요. 두 번 다 해시가 같아요.

**재부팅 가설의 또 다른 증거예요.** GPT.INI를 읽은 시각을 보세요.

- **01:37:03** — 컴퓨터 계정 인증(01:37:02) 바로 뒤 = **부팅** 때 컴퓨터 정책
- **01:38:13** — thiago.almeida 로그인(01:38:12) 바로 뒤 = 사용자 정책
- **01:49:11** — 컴퓨터 계정 인증(01:49:05) 뒤 = **또 부팅** 때 컴퓨터 정책

01:37의 패턴이 01:49에 그대로 반복돼요. Kerberos, DHCP, NCSI 패턴에 **증거가 하나 더** 생겼어요.

**그룹 2 — 미끼 페이지 (3단계에서 본 것)**

- 297바이트(301 응답 페이지), 1,382바이트(**미끼 페이지**, MD5 `6f23120907a7c8e6a884ea9cb6b0807e`), 209바이트(404 페이지), 72바이트(serveengenharia 응답, MD5 `a31fcd450e6b680316a04687c0ee3602`)
- 크기가 3단계의 `response_body_len`과 정확히 같아요. 72바이트의 MD5는 3단계 Arkime 화면의 **Body MD5s**와 같아요. **두 도구가 같은 데이터를 봤다**는 뜻이에요.
- serveengenharia의 `total_bytes`가 빈칸인 이유: 응답 헤더에 `Transfer-Encoding: chunked`가 있었어요. 서버가 전체 크기(`Content-Length`)를 미리 알려 주지 않고 **조각으로 나눠 보내는 방식**이라 Zeek이 전체 크기를 몰라요. 정상이에요.

**그룹 3 — 문제의 ZIP**

- `total_bytes` **17,066,397**: 서버가 "이만큼 보낸다"고 한 크기(`Content-Length`)
- `seen_bytes` **15,098,446**: Zeek이 캡처에서 **실제로 본** 크기
- `missing_bytes` **1,967,951**: **캡처에서 빠진** 크기 (약 1.9 MB, 전체의 약 11.5%)

15,098,446 + 1,967,951 = **17,066,397**로 정확히 맞아요. `md5`와 `sha1`이 **빈칸**이에요. 빠진 부분이 있는 파일은 해시가 의미 없어서 Zeek이 남기지 않은 것으로 보여요. `mime_type`도 빈칸이에요. 파일 맨 앞부분(`PK`)이 빠진 구간에 들어갔을 수 있어요.

### 5-2. Arkime — ZIP 세션 { #zip-arkime }

```text
tags == 20180927_BLANKCLIPBOARD && ip.dst == 103.6.198.141
```

세 줄로 나뉜 세션 중 **첫 번째 줄**(URI가 보이는 줄)을 펼쳐요.

```text
Time      2018/09/27 01:42:21 – 01:42:29 UTC
Src       Packets 4,248  Bytes 229,724  Databytes 320
Dst       Packets 5,752  Bytes 7,832,111  Databytes 6,535,416
Tags      20180927_BLANKCLIPBOARD  acked-unseen-segment-src  incomplete-tcp  out-of-order-dst
HTTP      GET (1)  200  dnpland.com.my  Mozilla/4.0 (compatible; MSIE 7.0; ...)
          Request Headers   accept accept-encoding connection host user-agent
          Response Headers  accept-ranges connection content-length content-type date keep-alive last-modified server upgrade
          content-type      application/zip
          server            Apache
```

- 서버는 `Content-Type: application/zip`이라고 말했어요. 이건 **서버의 주장**이에요. Zeek의 `mime_type`처럼 내용을 직접 보고 정한 값이 아니에요.
- HTTP 상자에 **`Body MD5s` 칸이 아예 없어요.** 3단계의 다른 세션들에는 있었어요. Arkime도 본문을 온전히 못 모아서 MD5를 만들지 못한 거예요. Zeek과 같은 결론이에요.

**PC는 파일을 다 받았을까?** **다 받았을 가능성이 높아요.** 빠진 건 **센서의 캡처**예요. 근거는 태그 `acked-unseen-segment-src`예요.

- `acked`: 받았다고 <strong>확인(ACK)</strong>했다
- `unseen-segment`: 캡처에서 **못 본** 데이터 조각을
- `src`: 출발지(PC)가

즉 <strong>"PC는 '받았어'라고 대답했는데, 캡처에는 그 데이터가 없다"</strong>는 뜻이에요. 서버는 보냈고 PC도 받았지만 중간에서 기록하는 센서가 일부를 놓쳤어요(트래픽이 몰릴 때 흔해요). 뒤의 사건도 이걸 뒷받침해요. ZIP을 받은 직후 01:44:06에 **프로그램이** serveengenharia에 요청을 보냈어요. 파일이 PC에서 쓰였다는 간접 증거예요.

**배울 점:** "캡처에 빠져 있다"를 "공격이 실패했다"로 읽으면 안 돼요. **TCP ACK를 보면 받는 쪽이 실제로 받았는지** 알 수 있어요.

### 5-3. tshark — HTTP 파일 꺼내기 { #export }

```bash
mkdir -p ~/cases/20180927_BLANKCLIPBOARD/export
tshark -r /data/pcap/20180927_BLANKCLIPBOARD.pcap --export-objects http,$HOME/cases/20180927_BLANKCLIPBOARD/export
cd ~/cases/20180927_BLANKCLIPBOARD/export
ls -l
```

- `tshark -r 파일`: PCAP을 읽어요.
- `--export-objects http,폴더`: HTTP로 옮겨진 파일을 **모두 꺼내서** 그 폴더에 저장해요.

**결과:**

```text
-rw-r--r--. 1 analyst analyst  297 'a%3fonlinepor-email%3fe=whatsapp_Beckup_REG'
-rw-r--r--. 1 analyst analyst 1382 'a%3fonlinepor-email%3fe=whatsapp_Beckup_REG(1)'
-rw-r--r--. 1 analyst analyst   72  cont1
-rw-r--r--. 1 analyst analyst  209  favicon.ico
-rw-r--r--. 1 analyst analyst   14 'ncsi(1).txt'
-rw-r--r--. 1 analyst analyst   14  ncsi.txt
```

**`z2448800.zip`이 없어요.** `--export-objects`는 HTTP 응답 본문을 **처음부터 끝까지 다 모은 것만** 꺼내요. ZIP은 1,967,951바이트가 빠져서 본문을 완성하지 못해 아예 꺼내지 않았어요. Zeek(`missing_bytes`)과 Arkime(`Body MD5s` 없음)에 이어 **세 번째 도구도 같은 결론**이에요.

| 꺼낸 파일 이름 | 크기 | 실제로는 |
|---|---|---|
| `a%3fonlinepor-email%3fe=whatsapp_Beckup_REG` | 297 | lealcontabil.com의 **301 응답** 페이지 |
| `a%3fonlinepor-email%3fe=whatsapp_Beckup_REG(1)` | 1382 | **미끼 페이지** "LOCALIZANDO CONTRATO" |
| `cont1` | 72 | serveengenharia **카운터 응답** (google.com으로 넘기는 한 줄) |
| `favicon.ico` | 209 | 아이콘이 아니라 **404 오류 페이지** |
| `ncsi.txt`, `ncsi(1).txt` | 14 | NCSI 응답 2개 (01:37, 01:49) |

- tshark는 URL의 **마지막 부분**을 파일 이름으로 써요. `%3f`는 `?`를 URL 인코딩한 거예요(`?`는 파일 이름에 쓰기 곤란해서). 이름이 겹치면 `(1)`을 붙여요.
- `favicon.ico`처럼 **이름이 내용과 다를 수 있어요.** 이름은 요청한 URL에서, 내용은 서버가 보낸 것에서 와요. 서버가 아이콘 대신 404 페이지를 보냈어요.
- 302 응답들(cadastro.php, index.php, /a/)은 본문이 0바이트라 꺼낼 게 없었어요.

두 도구가 같은 데이터를 봤는지 맞춰 보기:

```bash
md5sum *
```

- 폴더 안 모든 파일의 MD5를 구해요. `files.log`의 MD5와 비교해 보세요. 미끼 페이지(1382)는 `6f23120907a7c8e6a884ea9cb6b0807e`, `cont1`(72)은 `a31fcd450e6b680316a04687c0ee3602`가 나와야 해요. 같으면 Zeek, Arkime, tshark가 **같은 데이터를 봤다**는 확인이 돼요.

### 5-4. 선택 — 패킷에서 ZIP 안의 파일 이름 읽기 { #zip-names }

이번 분석에서는 ZIP을 넘어가기로 해서 끝까지 하지 않았어요. 방법으로 남겨 둬요. ZIP 파일은 안에 든 파일의 **이름을 평문으로** 두 군데에 적고, 각 위치에 정해진 **표식**이 있어요.

| 표식 (16진수) | 글자 | 위치 | 들어 있는 것 |
|---|---|---|---|
| `50 4b 03 04` | `PK..` | 각 파일 **바로 앞** (ZIP 맨 앞부터) | 그 파일의 이름 |
| `50 4b 01 02` | `PK..` | ZIP **끝부분** (중앙 디렉터리) | 모든 파일의 이름, 크기 |
| `50 4b 05 06` | `PK..` | ZIP **맨 끝** | 파일 개수, 중앙 디렉터리 위치 |

ZIP은 파일 목록을 **맨 끝에** 저장해요. 그래서 파일이 깨졌어도, 이 표식이 든 패킷이 캡처에 남아 있으면 이름을 읽을 수 있어요.

```bash
P=/data/pcap/20180927_BLANKCLIPBOARD.pcap
tshark -r $P -Y 'ip.src==103.6.198.141 && tcp.payload contains 50:4b:03:04' -T fields -e frame.number -e tcp.seq
tshark -r $P -Y 'ip.src==103.6.198.141 && tcp.payload contains 50:4b:01:02' -T fields -e frame.number -e tcp.seq
tshark -r $P -Y 'ip.src==103.6.198.141 && tcp.payload contains 50:4b:05:06' -T fields -e frame.number -e tcp.seq
tshark -r $P -Y 'frame.number==N' -x
```

- `P=...`: 긴 경로를 `P`라는 짧은 이름에 넣어요. 다음 줄부터 `$P`로 써요.
- `-Y '...'`: Wireshark와 같은 표시 필터예요. ZIP 서버가 **보낸** 패킷 중 TCP 데이터에 이 4바이트가 **들어 있는** 것만이에요.
- `-T fields -e frame.number -e tcp.seq`: 패킷 번호와 `tcp.seq`(그 데이터가 스트림의 몇 번째 바이트부터인지, tshark는 0부터 센 상대값을 보여 줘요)만 출력해요.
- `03 04`는 `tcp.seq` 약 300(HTTP 헤더 뒤) 근처, `01 02` / `05 06`은 약 17,066,000 근처에서 나오길 기대해요. 아무것도 안 나오면 그 부분이 빠진 1.97 MB 안에 있어요.
- `-x`: 패킷 `N`을 16진수 + 글자로 보여 줘요. 오른쪽 글자 칸에서 `PK..` 뒤쪽에 파일 이름(`xxxx.exe`, `xxxx.vbs` 등)이 보여요.

압축을 풀거나 실행하지 마세요.

**ZIP에 대한 티켓 문장:**

```text
Second-stage download (incomplete in capture):
  URL      : hxxp://dnpland[.]com.my/images/z2448800.zip (103.6.198.141)
  Time     : 2018-09-27 01:42:22 UTC
  Size     : 17,066,397 bytes (Content-Type: application/zip)
  Capture  : 1,967,951 bytes missing (sensor packet loss; host ACKed the data).
             No reliable hash from this PCAP.
```

---

## 6단계 — Snort 룰 하나 { #snort }

### 6-1. 무엇을 잡을까 { #rule-choice }

Night Dew 때처럼 **핵심 하나**만 골라요. 이번에는 **피싱 링크를 클릭한 순간**을 잡는 룰이 가장 좋아요. 메일 A의 링크 두 개를 다시 보세요.

```text
http://bit.ly/2k5P2Kt?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
http://lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
```

도메인은 달라도 **뒷부분 `/img/tmp/a?onlinepor-email?e=`가 똑같아요.** 공격자가 캠페인 전체에 쓰는 **경로 모양**이에요. 이걸 잡으면:

- **도메인이나 IP가 바뀌어도 잡혀요.** 해킹된 사이트를 바꿔 가며 써도 이 경로 모양은 그대로일 가능성이 커요.
- **감염 체인의 맨 처음**을 잡아요. 알림이 뜨면 "누군가 피싱 링크를 눌렀다"는 뜻이라, ZIP이 내려오기 **전에** 대응할 수 있어요.
- **오탐이 거의 없어요.** 정상 사이트가 `?onlinepor-email?e=`처럼 `?`를 여러 번 쓰는 이상한 주소를 만들 일은 드물어요.

### 6-2. 룰을 한 부분씩 읽기 { #rule-anatomy }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Phishing lure link clicked - onlinepor-email URI - Sung"; flow:to_server,established; content:"GET "; depth:4; content:"/img/tmp/a?onlinepor-email?e="; distance:0; sid:1000002; rev:1;)
```

**헤더** (괄호 앞부분)

- `alert`: 조건에 맞으면 알림을 내요. `tcp`: TCP 트래픽만 봐요.
- `$HOME_NET any`: 출발지는 **우리 네트워크**, 포트는 아무거나요. `->`: 왼쪽에서 오른쪽으로 가는 패킷만 봐요.
- `$EXTERNAL_NET 80`: 도착지는 **외부**, 포트 80(HTTP)이에요.

**옵션** (괄호 안, 각각 `;`로 끝남)

- `msg:"..."`: 알림에 나올 설명이에요.
- `flow:to_server,established`: **연결이 맺어진 뒤**, **서버 쪽으로 가는** 패킷만 봐요. 클릭 = PC가 서버에 요청하는 것이라 이 방향이에요.
- `content:"GET "; depth:4;`: 패킷 데이터 **맨 앞 4바이트**가 `GET `인지 봐요. HTTP 요청의 첫 단어예요. `depth:4`는 "처음 4바이트 안에서만 찾아라"라서 빠르고 정확해요.
- `content:"/img/tmp/a?onlinepor-email?e=";`: 캠페인 경로 모양이에요.
- `distance:0;`: 바로 앞 `content`(`GET `) **뒤 어딘가에서** 찾으라는 뜻이에요. 순서를 지키게 해요.
- `sid:1000002;`: 룰 번호예요. Night Dew 룰이 1000001이라 다음 번호예요. 내가 만드는 룰은 1,000,000 이상을 써요.
- `rev:1;`: 룰 버전이에요. 고칠 때마다 올려요.

**이 PCAP에서 기대하는 결과:** 세션 ①(포트 49218)에 이 경로가 들어간 **요청이 2개**(01:40:54 → 301, 01:40:55 → 미끼 페이지) 있었어요. 그래서 **알림 2개**, 둘 다 `172.16.5.203:49218 -> 54.38.137.127:80`이 나와야 해요. 다른 곳에서 울리면 오탐이에요.

### 6-3. 시험하기 { #snort-test }

초보자용 전체 가이드는 [Night Dew 두 번째 분석 — Snort 룰 테스트](night-dew-arkime-splunk-netlogon-bruteforce.md#snort-test)에 있어요. 이번 케이스의 순서예요.

**0. HOME_NET 먼저 확인 (이번에 새로 필요한 단계).** Night Dew는 `10.0.14.x`였고 이번은 `172.16.5.x`예요. `HOME_NET`이 172.16 대역을 포함하지 않으면 **룰이 맞아도 안 울려요.**

```bash
grep -E '^ipvar (HOME_NET|EXTERNAL_NET)' /etc/snort/snort.conf
```

- `'^ipvar (HOME_NET|EXTERNAL_NET)'`: `ipvar HOME_NET`이나 `ipvar EXTERNAL_NET`으로 **시작하는** 줄이에요.
- `ipvar HOME_NET any` → 괜찮아요. `[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]`처럼 사설 대역이 다 있으면 괜찮아요. 172.16이 없으면 추가하세요(시험할 때만 `any`로 둬도 돼요).

**1. 룰 넣기**

```bash
nano /data/rules/local.rules
tail -3 /data/rules/local.rules
```

- 맨 아래 빈 줄에 룰을 **한 줄로** 붙여 넣고 **Ctrl+O** → Enter로 저장, **Ctrl+X**로 나와요. sid 1000001 룰은 그대로 두세요. 이번 PCAP에서 그 룰이 **0개**로 나오면 그것도 "오탐 없음" 확인이 돼요.
- `tail -3`: 마지막 3줄이에요. 새 룰이 **한 줄로 통째로** 보여야 해요. 복사하다 따옴표가 둥근 따옴표(`“ ”`)로 바뀌지 않았는지 보세요.

**2. 문법 검사와 PCAP 시험을 한 번에**

```bash
snort-test 20180927_BLANKCLIPBOARD
```

기대하는 결과:

```text
[1/2] 문법 OK
[2/2] /data/pcap/20180927_BLANKCLIPBOARD.pcap
  개수 [gid:sid:rev] 메시지
      2 [1:1000002:1] Phishing lure link clicked - onlinepor-email URI - Sung
```

**3. 알림 한 줄씩 보기 (시각, 출발지, 도착지)**

```bash
mkdir -p /tmp/snortlog
sudo snort -c /etc/snort/snort.conf -r /data/pcap/20180927_BLANKCLIPBOARD.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

- `-r`: 이 PCAP을 읽어요. `-A console`: 알림을 화면에 한 줄씩. `-q`: 긴 안내문을 숨겨요.
- `-k none`: 체크섬 검사를 꺼요. 안 끄면 패킷을 버려서 알림이 안 뜰 수 있어요.
- `-U -y`: 시각을 UTC로, 연도까지. `-l /tmp/snortlog`: 로그 폴더를 정해요(`/var/log/snort` 없음 오류를 피해요).

기대하는 줄:

```text
09/27/18-01:40:54.xxxxxx  [**] [1:1000002:1] Phishing lure link clicked - onlinepor-email URI - Sung [**] [Priority: 0] {TCP} 172.16.5.203:49218 -> 54.38.137.127:80
09/27/18-01:40:55.xxxxxx  [**] [1:1000002:1] Phishing lure link clicked - onlinepor-email URI - Sung [**] [Priority: 0] {TCP} 172.16.5.203:49218 -> 54.38.137.127:80
```

확인할 것: 개수가 **2개**인가? 시각이 **01:40:54와 01:40:55**인가? 도착지가 모두 **54.38.137.127:80**인가?

!!! note "이 테스트의 상태"
    이번 분석에서는 룰 테스트를 **실제로 돌리지 않았어요**(결과가 잘 나온다고 보고 티켓을 마무리했어요). 위 출력은 **기대하는 결과**예요. `snort-test`를 한 번 돌려서 실제 개수를 티켓에 넣으세요.

**안 울리면**

1. **0개:** 0번의 `HOME_NET`부터 확인하세요. 그다음 룰이 한 줄인지, 따옴표가 바뀌지 않았는지 보세요.
2. **그래도 0개:** `content:"onlinepor-email";` 하나만 남겨서 시험해 보세요. 울리면 옵션을 하나씩 다시 넣으면서 원인을 찾아요. 고칠 때마다 `rev`를 올려요.
3. **1개만:** 두 요청이 한 패킷에 같이 들어 있었을 수 있어요. 그래도 클릭은 잡은 거라 괜찮아요. Arkime 세션과 비교해 보세요.

---

## 타임라인 (2018-09-27, UTC) { #timeline }

| 시각 | 사건 |
|---|---|
| 01:37:01 | 캡처 시작 |
| 01:37:02 | PC 시작: 컴퓨터 계정 로그인(Kerberos), 그룹 정책, DHCP INFORM, NCSI(01:37:07) |
| 01:38:12 | thiago.almeida 로그인 (Kerberos) |
| 01:38:49 | 회사 웹메일 `webmail.a1-associados[.]com` (216.194.135.127, TLS) — 01:41:27까지 |
| 01:40:54 | IE11이 메일 A의 링크를 엶 (Referer 없음): `lealcontabil[.]com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG` |
| 01:40:55 | 미끼 페이지 "LOCALIZANDO CONTRATO" (가짜 Ministério Público Federal), `cadastro.php`로 refresh |
| 01:40:56–01:40:58 | `cadastro.php` → 302 → `54.38.137.127/index.php` → 302(쿠키) → `/a/` → 302 → Dropbox |
| 01:40:58–01:41:01 | Dropbox `DOC1_CONTRATO_YBFTOP2078686788.zip` (몇 KB, TLS) |
| 01:42:22 | 브라우저가 아닌 프로그램(MSIE 7.0 UA)이 `dnpland[.]com[.]my/images/z2448800.zip` 17,066,397바이트 다운로드 |
| 01:44:06 | UA 없는 요청 `serveengenharia[.]com[.]br/tmp/soares/cont1/` (카운터 추정) |
| 01:48–01:49 | 재부팅 추정: 컴퓨터 로그인 01:49:05, DHCP 01:49:08, GPT.INI 01:49:11, NCSI 01:49:13 (포트 49183 재사용) |
| 01:51:35 | 캡처 끝 — C2 없음, 사용자 재로그인 없음 |

메일 A 도착은 2018-09-24 12:52:42 UTC, 메일 B 도착은 2018-09-26 16:19:47 UTC예요.

---

## 침해사고 티켓 { #ticket }

팀 티켓 양식(Index Entry, Metadata, 내부/외부 장비, Search Queries, Evidence, Operator Log, Tool Output)으로 썼어요. **핵심 결과만** 넣고 베이스라이닝 작업은 뺐어요. Operator 이름, Operator Log 시각, 티켓 링크, 증거 경로, Snort 결과 개수는 바꿔 넣을 자리예요.

[:material-download: 티켓을 txt 파일로 내려받기](files/180927_ESCRITORIO-PC_ticket.txt){ .md-button }

```text
--8<-- "docs-ko/blueteam/investigations/files/180927_ESCRITORIO-PC_ticket.txt"
```

보내기 전에: `snort-test`를 돌려서 개수를 넣고, `ingest.log`의 SHA256을 넣고, EVIDENCE LOCATIONS에 적은 증거 PCAP을 만들어 두세요(Arkime 각 검색 결과에서 **Actions → Export PCAP**).

티켓의 호스트 단서에 나오는 Windows 이벤트는 이런 뜻이에요. **4688** 새 프로세스 실행(명령줄 포함), **Sysmon 1** 프로세스 생성, **Sysmon 3** 네트워크 연결, **1074** 누가/어떤 프로그램이 재시작을 요청했는지, **6006** 정상 종료, **6008** 예기치 않은 종료, **6005** 이벤트 로그 시작(부팅)이에요.

---

## 복사해서 쓰는 쿼리 모음 { #query-sheet }

`<case>`를 케이스 이름으로 바꾸세요. 실제 네트워크에서는 `tags`/`pcap_case` 조건을 빼요.

**Arkime**

```text
tags == <case>
tags == <case> && protocols == http
tags == <case> && protocols == dhcp
tags == <case> && protocols == krb5
tags == <case> && ip.src == 172.16.5.5
tags == <case> && ip.dst == [216.194.135.127, 162.125.5.1, 162.125.5.6]
tags == <case> && ip.dst == [54.38.137.127, 103.6.198.141, 177.12.174.95]
tags == <case> && ip.dst == 103.6.198.141
tags == <case> && http.request-header == referer
tags == <case> && (host == *serasa* || host == *encontraaruja* || host == *bit.ly* || host == *goo.gl*)
http.uri == *onlinepor-email*
```

**Splunk (Zeek)**

```spl
index=zeek sourcetype=zeek:conn | stats count by pcap_case
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h="172.16.5.*" | stats count as sessions dc(id_resp_h) as dests sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h | sort - sessions
index=zeek sourcetype=zeek:conn pcap_case=<case> NOT id_resp_h IN ("172.16.5.*", "224.*", "255.255.255.255") | stats count as sessions min(ts) as first values(id_resp_p) as ports values(service) as service sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h id_resp_h | eval first=strftime(first,"%H:%M:%S") | sort - received
index=zeek sourcetype=zeek:dhcp pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t client_addr server_addr assigned_addr mac host_name domain msg_types | sort t
index=zeek sourcetype=zeek:kerberos pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h id_resp_h request_type client service success error_msg | sort t
index=zeek sourcetype=zeek:http pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h method host uri referrer status_code resp_mime_types response_body_len user_agent | sort t
index=zeek sourcetype=zeek:http pcap_case=<case> | eval has_ref=if(isnull(referrer) OR referrer="" OR referrer="-", "no", "yes") | stats count by has_ref
index=zeek sourcetype=zeek:ssl pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h id_resp_p server_name version established | sort t
index=zeek sourcetype=zeek:dns pcap_case=<case> query="*lealcontabil*" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t id_orig_h id_resp_h query answers | sort t
index=zeek pcap_case=<case> (sourcetype=zeek:conn OR sourcetype=zeek:http) id_resp_h="54.38.137.127" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t sourcetype id_orig_p uri | sort t
index=zeek pcap_case=<case> ("consultafacilserasaexperian" OR "encontraaruja" OR "bit.ly" OR "goo.gl") | table sourcetype _raw
index=zeek sourcetype=zeek:files pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts source mime_type seen_bytes total_bytes missing_bytes md5 sha1 | sort t
```

**이메일 (분석 VM에서 텍스트로만)**

```bash
grep -iE '^(Date|From|To|Subject|Return-Path|Message-ID|Content-Type|Content-Transfer-Encoding):' *.eml
grep -oiE 'https?://[^"<> ]+' *.eml | sort -u
```

**파일**

```bash
tshark -r /data/pcap/<case>.pcap --export-objects http,$HOME/cases/<case>/export
md5sum *
tshark -r /data/pcap/<case>.pcap -Y 'ip.src==<server> && tcp.payload contains 50:4b:01:02' -T fields -e frame.number -e tcp.seq
```

**Snort**

```bash
grep -E '^ipvar (HOME_NET|EXTERNAL_NET)' /etc/snort/snort.conf
snort-test <case>
sudo snort -c /etc/snort/snort.conf -r /data/pcap/<case>.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

---

## 배운 점 { #lessons }

1. **개수로 안 보이면 바이트로 정렬하세요.** 세션 수로는 튀는 외부 IP가 없었지만, 세션 하나가 받은 양의 92%였어요.
2. **HTTP부터 읽으세요.** 평문 URL, 상태 코드, User-Agent가 TLS나 이메일보다 먼저 이야기 대부분을 알려 줬어요.
3. **`Location`을 따라가세요.** 301/302/refresh 헤더가 따로 떨어진 요청 다섯 개를 Dropbox로 끝나는 체인 하나로 이어 줬어요.
4. **같은 PC의 User-Agent를 비교하세요.** IE11(`rv:11.0`) vs `MSIE 7.0` vs 없음 = 브라우저 vs 프로그램이에요.
5. **비어 있는 칸도 증거예요.** Referer 없음, User-Agent 없음, Body MD5 없음, 해시 없음 — 하나하나 의미가 있었어요.
6. **SNI가 암호화된 목적지의 이름을 알려 줘요.** "미확인 1.26 MB TLS"는 회사 웹메일이었고, 덕분에 클릭 위치가 잡혔어요.
7. **가설은 여러 근거로 확인하세요.** DHCP INFORM만으로는 재부팅을 말할 수 없었고, Kerberos, NCSI 포트, GPT.INI를 합치니 말할 수 있었어요.
8. **"없다"도 증명하세요.** 메일 B 링크, bit.ly, goo.gl을 찾아서 0건 → "글자 링크 하나만 눌렀다".
9. **캡처에 빠짐 ≠ 못 받음.** `acked-unseen-segment-src`는 센서가 놓친 ZIP을 PC는 받았다는 뜻이었어요.
10. **도메인이 아니라 캠페인의 모양으로 룰을 쓰세요.** 링크 경로 모양은 서로 다른 두 도메인에 똑같이 있었어요.

## 참고 { #references }

- [Night Dew 두 번째 분석 — 같은 pcapbox 방법](night-dew-arkime-splunk-netlogon-bruteforce.md) · [피싱 미끼 사례 — 이메일 분석](phishing-red-herring-ek-driveby-ursnif-c2.md)
- [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Arkime로 PCAP 분석하기](../../network/arkime/offline-pcap-guide.md)
- [Zeek 로그](../../network/zeek/index.md) · [files.log](../../network/zeek/files-log.md) · [ssl & x509](../../network/zeek/ssl-x509.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [공격 기법: 피싱 전달](../../adversary/phishing-delivery.md) · [플레이북: 감염된 워크스테이션](../playbooks/compromised-workstation.md)
- 원본 연습문제: [malware-traffic-analysis.net — 2018-09-27 Blank Clipboard](https://malware-traffic-analysis.net/2018/09/27/index.html)
