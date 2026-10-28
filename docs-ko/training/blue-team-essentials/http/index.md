---
title: HTTP
tags:
  - training
  - blue-team
  - http
---

# HTTP { #http }

!!! abstract "한 줄 요약"
    웹 페이지, 메일, 메신저, 그리고 악성코드까지 거의 모든 것이 HTTP 위에서 움직입니다. 요청 한 줄과 헤더 몇 개만 제대로 읽어도 웹셸, 피싱, C2 비콘을 꽤 많이 잡을 수 있습니다. 다만 2026년에는 거의 모든 웹이 https라서, 경로·파라미터·헤더는 **프록시(TLS 검사)·웹 서버·WAF·EDR 기록**에서 얻는 것이 중심입니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [웹 서버, URL, GET 요청](web-servers-urls-get.md) | 주문과 배달, 문서 루트, 웹셸과 이벤트 4688·Sysmon 1, 모듈 백도어, URL 해부(`@`·`#`·`%`·`file://`), Zeek http.log, GET 로그·SQL 인젝션·경로 조작·C2 비콘, 확인 문제 |
| 2 | [POST, 그 밖의 메서드, 요청 헤더](post-methods-headers.md) | POST와 로그, 악성코드·웹셸의 POST, CONNECT·HEAD·OPTIONS·PUT·DELETE·TRACE, Host·User-Agent·Referer·Cookie·Accept·X-Forwarded-For, 헤더 순서 지문, 확인 문제 |

## 꼭 기억할 10가지 { #must-know }

1. 웹 서버는 파일 공유다. URL 경로가 디스크 경로에 붙고, 실행 폴더에 파일 하나 넣으면 웹셸이 된다.
2. 웹셸 신호: 웹 서버 프로세스가 `cmd.exe`·`powershell.exe`를 띄운다(4688, Sysmon 1).
3. 도메인은 오른쪽부터 읽는다. URL의 `@` 뒤가 실제 목적지이고, `#` 뒤는 로그에 없다.
4. `%` 인코딩과 Base64는 풀어서 본다. 포장은 암호가 아니다.
5. GET은 주소에, POST는 본문에 정보를 담는다. 주소는 로그에 남고 본문은 보통 안 남는다.
6. 로그에 없다 ≠ 일어나지 않았다. 호스트 로그·WAF·풀 패킷 캡처를 찾는다.
7. 외부에서 온 PUT + 2xx + 실행 파일 = 웹셸 업로드 최우선 확인.
8. User-Agent, X-Forwarded-For는 누구나 거짓으로 쓸 수 있다. 우리 장비가 붙인 값만 믿는다.
9. 쿠키는 로그인 손목밴드다. 훔치면 MFA도 소용없다.
10. 요청 한 줄보다 패턴(주기, 순서, 앞뒤 요청)을 본다. CDN IP는 막지 말고 도메인을 막는다.

## 관련 레퍼런스 { #related }

- [Zeek http.log](../../../network/zeek/http-log.md) — 필드별 설명
- [Beaconing & C2 탐지](../../../network/beaconing-c2.md) — 규칙적인 간격의 연결
- [HTTP 상태 코드](../../../basics/http-status-codes.md) — 응답 코드 정리
- [Windows 이벤트 로그](../../../windows/event-logs.md) — 4688·Sysmon 이벤트
- [Web shell / server 플레이북](../../../playbooks/webshell-server.md) — 웹셸 대응 흐름
