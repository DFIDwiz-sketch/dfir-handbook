---
title: Blue Team Essentials
tags:
  - training
  - blue-team
---

# Blue Team Essentials { #blue-team-essentials }

!!! abstract "이 섹션의 성격"
    SOC 분석가가 매일 보는 데이터(DNS, HTTP, 이메일, 엔드포인트 로그 등)를 **"왜 필요한가 → 무엇인가 → 실제로 어떻게 생겼나 → SOC에서 언제 쓰나"** 순서로 정리합니다. 최근 바뀐 도구·기법·위협 환경은 **[변경됨]**, 흔히 틀리게 알려졌거나 옛 방식대로 하면 위험한 부분은 **[주의]**/**[정정]**, 실무에 꼭 필요한 내용은 <strong>[보충]</strong>으로 표시합니다.

## 주제 { #topics }

<div class="grid cards" markdown>

-   :material-dns:{ .lg .middle } **DNS**

    ---

    DNS 구조와 레코드, 기록 수집과 안전한 조사, 도메인 신호, 비인가 DNS·터널링·블록체인 DNS·IDN, 암호화 DNS, 그리고 수상한 DNS 기록 판별표.

    [:octicons-arrow-right-24: DNS](dns/index.md)

-   :material-web:{ .lg .middle } **HTTP**

    ---

    웹 서버와 웹셸, URL 해부와 피싱 속임수, GET·POST와 로그, 그 밖의 메서드(CONNECT·HEAD·OPTIONS·PUT·DELETE·TRACE), 요청 헤더 읽기, 실제 악성 요청 판정 연습(익스플로잇 킷, URL 속 URL), 응답 헤더와 응답 코드, 새 HTTP 표준(HTTP/2·HTTP/3·QUIC·웹소켓), 확인 문제와 해설.

    [:octicons-arrow-right-24: HTTP](http/index.md)

-   :material-shield-search:{ .lg .middle } **HTTP(S) 분석과 공격**

    ---

    HTTP가 쓰이는 공격 단계, 자동·수동 분석 고르기, URL 평판 조회와 OPSEC, 그리고 이어서 피싱·샌드박스·헤더와 내용 분석·파일 추출·HTTPS 분석.

    [:octicons-arrow-right-24: HTTP(S) 분석과 공격](http-analysis/index.md)

-   :material-email-search:{ .lg .middle } **SMTP·이메일**

    ---

    메일이 거쳐 가는 서버들(MUA·MTA·MDA)과 포트, SMTP 대화와 봉투·헤더 주소, 헤더 읽기, SPF 결과, DKIM 서명, DMARC 일치·정책·보고서, 분석 체크리스트.

    [:octicons-arrow-right-24: SMTP·이메일](email/index.md)

-   :material-lan:{ .lg .middle } **기타 네트워크 프로토콜**

    ---

    IP를 장비로 바꾸고 몰래 꽂은 장비를 찾는 DHCP, 그리고 옆으로 이동·유출에 쓰이는 SMB, SSH, RDP/VNC, PowerShell 원격, FTP, ICMP, 원격 접속 도구, 그리고 "안전한" 프로토콜이 없는 이유와 네트워크 파트 정리.

    [:octicons-arrow-right-24: 기타 네트워크 프로토콜](other-protocols/index.md)

-   :material-laptop-account:{ .lg .middle } **엔드포인트 공격**

    ---

    전달 이후 호스트 위에서 벌어지는 일: 엔드포인트가 네트워크보다 많이 보는 이유, 최초 침투(서비스 측 vs 클라이언트 측)와 각각이 남기는 증거, 그리고 실행·지속성·정보 탐색·권한 상승·자격 증명 덤프·옆으로 이동·수집·유출.

    [:octicons-arrow-right-24: 엔드포인트 공격](endpoint-attacks/index.md)

-   :material-shield-lock:{ .lg .middle } **엔드포인트 방어**

    ---

    호스트의 심층 방어를 단계별로: 소프트웨어 인벤토리와 네트워크 스캔, 지속적인 취약점 스캔과 패치, 익스플로잇 보호와 ASR 규칙, Credential Guard, 호스트 방화벽과 백신, 애플리케이션 제어, FIM과 지속성 찾기, PAW, 권한과 특권, EDR, DLP, UEBA, 감사 정책.

    [:octicons-arrow-right-24: 엔드포인트 방어](endpoint-defense/index.md)

-   :material-microsoft-windows:{ .lg .middle } **Windows 로그**

    ---

    Windows가 이벤트를 만드는 방식: 공급자, Event Log 서비스, 채널과 `.evtx` 파일, 감사 정책, Sysmon과 사용자 채널, 이벤트 메타데이터(수준, 공급자, 이벤트 ID, 작업 범주, 키워드), 한 이벤트의 일반·쉬운 보기·XML 보기, System과 EventData/UserData 칸별 해석, 템플릿과 설명 문구, SOC가 모아야 할 채널.

    [:octicons-arrow-right-24: Windows 로그](windows-logging/index.md)

-   :material-linux:{ .lg .middle } **Linux 로그**

    ---

    Linux와 장비가 로그를 남기는 방식: "syslog"의 세 가지 뜻(형식, 데몬, 네트워크 프로토콜), RFC 3164와 RFC 5424 헤더, 자유 문장 파싱, UDP/TCP/TLS 전송, rsyslog·syslog-ng 설정, facility·severity와 PRI 값, 그리고 `/var/log` 아래 로그 파일, systemd 저널, 명령줄 로깅.

    [:octicons-arrow-right-24: Linux 로그](linux-logging/index.md)

-   :material-text-box-search:{ .lg .middle } **꼭 알아야 할 이벤트**

    ---

    분석가가 칸 단위로 읽을 줄 알아야 하는 이벤트: 4624/4625 로그온과 로그온 유형, Status/SubStatus 실패 코드, 4648 명시적 자격 증명, Linux SSH·데스크톱 로그인과 여러 모양의 실패, 이어서 프로세스 생성, 방화벽과 개체 접근, 서비스, 예약 작업, USB, 계정 변경, Defender, PowerShell, Kerberos.

    [:octicons-arrow-right-24: 꼭 알아야 할 이벤트](important-events/index.md)

-   :material-pipe:{ .lg .middle } **로그 파이프라인·SIEM**

    ---

    이벤트가 호스트에서 검색창까지 어떻게 오고 오는 길에 무엇이 바뀌는지: 파이프라인 블록과 지연, 에이전트 vs 에이전트리스 수집, Windows 이벤트 전달, 업체·서드파티 에이전트, rsyslog 전달, 로그 형식과 구조, 보강과 상관 분석, 정규화와 공통 정보 모델, 분류, 저장 계층과 로그 수명 주기.

    [:octicons-arrow-right-24: 로그 파이프라인·SIEM](log-pipeline/index.md)

</div>

!!! info "다음 주제"
    네트워크 파트 완료(DNS, HTTP, HTTP(S) 분석, 이메일, 기타 프로토콜). 호스트 파트는 엔드포인트 공격, 엔드포인트 방어, Windows 로그, Linux 로그, 꼭 알아야 할 이벤트, 로그 파이프라인·SIEM이 완료됐습니다. 다음은 파일 분석입니다.

!!! note "이 섹션에 대하여"
    개인 학습 노트이며 어떤 기관의 공식 지침도 아닙니다.
