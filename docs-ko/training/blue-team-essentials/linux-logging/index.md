---
title: Linux 로그
tags:
  - training
  - blue-team
  - linux
  - logging
---

# Linux 로그 { #linux-logging }

!!! abstract "한 줄 요약"
    Linux 서버, 그리고 거의 모든 방화벽·스위치·장비는 syslog로 로그를 남깁니다. 짧은 표준 헤더와 자유 문장이고, 이벤트 ID가 없고, facility와 severity라는 라벨만 붙고, 데몬(rsyslog, syslog-ng, journald)이 파일이나 네트워크로 나눠 보냅니다. 층마다 "syslog"가 진짜 무엇을 뜻하는지 — 형식, 데몬, 프로토콜 — 와 로그가 디스크 어디에 남는지를 알아야 "아무 일도 없었다"와 "기록·보관·전달이 안 됐다"를 구분할 수 있습니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [Syslog — Linux 로그가 다른 점, “syslog”의 세 가지 뜻, 메시지 형식, 네트워크 전송, 데몬, facility와 severity](syslog.md) | Linux vs Windows 로그(이벤트 ID 없음, 자유 문장, facility/severity, journald), "syslog" = 형식 / 데몬 / 프로토콜, RFC 3164 헤더 칸별 해석(연도·시간대 없음, T1110), 정규식으로 칸 뽑기와 깨지는 이유, key=value와 JSON 메시지, `logger` 위조, T1070.002/T1562.006, 구조화 데이터가 있는 RFC 5424 헤더, 전송 방식(UDP 514, TCP, RFC 9662의 TLS 6514, DTLS, RFC 3195/6587/5848 정정), 크기 제한과 잘림, `<PRI>`가 보이는 `tcpdump` 캡처 한 줄씩, 평문 UDP가 위험한 이유, RELP, syslogd·syslog-ng(One Identity, AxoSyslog)·rsyslog, rsyslog 없는 Debian 12, rsyslog 선택자와 큐를 쓴 TLS `omfwd` 한 줄씩, `rsyslogd -N1`, syslog-ng 블록, facility·severity 표, `auth` vs `authpriv`, PRI = facility × 8 + severity 풀이 예, facility·severity를 믿으면 안 되는 이유, SOC 점검 목록, 확인 문제 |

!!! info "이어서 추가될 내용"
    `/var/log`로 가는 전통적인 로그 경로와 흔한 로그 파일(`auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron`, `wtmp`/`btmp`/`lastlog`), systemd 저널과 `journalctl`, 명령줄 로깅 — 그리고 섹션 정리.

## 꼭 기억할 것 { #must-know }

1. "Syslog"는 세 가지다. 메시지 형식, 호스트의 데몬, 네트워크 프로토콜. 문제와 해결은 각각 다른 층에 있다.
2. 옛 헤더에는 연도와 시간대가 없고 메시지는 자유 문장이다. 파서는 조용히 깨지는 정규식이고, 깨진 파서는 "공격 없음"처럼 보인다.
3. 평문 UDP 514는 메시지를 잃고, 흘리고, 위조를 받아들인다. 보안 로그는 인증서 확인을 켠 TLS(6514)와 디스크 큐로 보낸다.
4. PRI = facility × 8 + severity. 8로 나눈 몫과 나머지로 푼다. facility와 severity는 보낸 쪽의 주장이고, 인증 이벤트는 고작 `info`다.
5. `/var/log/auth.log`가 있다고 가정하지 않는다 — Debian 12 이후는 기본이 journald뿐이다 — 그리고 소스가 조용해지면 경보를 건다.

## 관련 레퍼런스 { #related }

- [Windows 로그](../windows-logging/index.md) — 비교 대상인 구조화된, 이벤트 ID 기반 방식
- [Linux 로그, 프로세스, 라이브 트리아지](../../../linux/logs-and-triage.md)
- [Linux 인증과 셸 히스토리](../../../linux/auth-and-history.md)
