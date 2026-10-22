---
title: 홈
hide:
  - navigation
  - toc
---

# DFIR 핸드북 { #dfir-handbook }

디지털 포렌식과 침해사고 대응(DFIR)을 위한 개인 레퍼런스입니다. 공부한 내용을 한곳에 모아 검색할 수 있게 정리했습니다. 기초(포트, 상태 코드, 이벤트 ID)부터 호스트·네트워크 아티팩트, 그리고 공격 기법과 탐지 방법까지 다룹니다.

**검색창**을 쓰세요 (++slash++ 또는 ++s++ 키). 메뉴를 하나씩 찾는 것보다 대개 더 빠릅니다.

<div class="grid cards" markdown>

-   :material-book-open-variant:{ .lg .middle } **기초**

    ---

    잘 알려진 포트, HTTP 상태 코드, Windows 이벤트 ID, 인코딩 — 계속 다시 찾아보게 되는 표들.

    [:octicons-arrow-right-24: 기초](basics/index.md)

-   :material-microsoft-windows:{ .lg .middle } **Windows**

    ---

    레지스트리, Prefetch, Amcache, Shimcache, 이벤트 로그, $MFT, USN 저널, LNK, Jump Lists, SRUM …

    [:octicons-arrow-right-24: Windows](windows/index.md)

-   :material-linux:{ .lg .middle } **Linux**

    ---

    인증 로그, 셸 히스토리, cron, systemd, ext4 타임스탬프, journald.

    [:octicons-arrow-right-24: Linux](linux/index.md)

-   :material-lan:{ .lg .middle } **네트워크**

    ---

    Zeek 로그, pcap 분석, NetFlow, DNS/HTTP/TLS 포렌식, 프록시·방화벽 로그.

    [:octicons-arrow-right-24: 네트워크](network/index.md)

-   :material-memory:{ .lg .middle } **메모리**

    ---

    메모리 수집, Volatility 3 플러그인, 프로세스·인젝션·자격증명 분석.

    [:octicons-arrow-right-24: 메모리](memory/index.md)

-   :material-magnify-scan:{ .lg .middle } **Splunk**

    ---

    SPL 치트시트, 유용한 검색, BOTS 풀이, 데이터 모델 노트.

    [:octicons-arrow-right-24: Splunk](splunk/index.md)

-   :material-sword-cross:{ .lg .middle } **공격 기법**

    ---

    ATT&CK에 매핑한 공격 기법 — 어떻게 동작하는지, 어떤 흔적을 남기는지, 어떻게 탐지하는지.

    [:octicons-arrow-right-24: 공격 기법](adversary/index.md)

-   :material-account-search:{ .lg .middle } **위협 인텔리전스**

    ---

    공격 기법 뒤에 누가 있는가 — 북한 그룹(Lazarus, APT38, TraderTraitor, Kimsuky), 주요 사건, TTP와 헌팅 쿼리.

    [:octicons-arrow-right-24: 위협 인텔리전스](threat-intel/index.md)

-   :material-radar:{ .lg .middle } **펜테스팅**

    ---

    HTB CPTS 공부에서 나온 공격자 측 노트. 우선 정찰(Nmap)부터, 앞으로 계속 추가합니다. 각 페이지는 로그에 남는 흔적과도 연결됩니다.

    [:octicons-arrow-right-24: 펜테스팅](pentesting/index.md)

-   :material-certificate:{ .lg .middle } **OSCP+**

    ---

    OSCP+ 시험 준비 허브 — 시험 구조, Active Directory, 피벗팅, 권한 상승, 웹, 리포트, 실습 랩, 시험 당일 전략.

    [:octicons-arrow-right-24: OSCP+](oscp/index.md)

-   :material-toolbox:{ .lg .middle } **도구**

    ---

    KAPE, Velociraptor, Eric Zimmerman 도구, Plaso, Wireshark, tshark 등의 치트시트.

    [:octicons-arrow-right-24: 도구](tools/index.md)

-   :material-clipboard-list:{ .lg .middle } **플레이북**

    ---

    자주 만나는 상황별 단계적 대응 절차.

    [:octicons-arrow-right-24: 플레이북](playbooks/index.md)

-   :material-school:{ .lg .middle } **학습**

    ---

    학습 로드맵, 매주 기법 하나씩 공부하는 퍼플팀 루프, 24개월 커리큘럼, 학습 자료.

    [:octicons-arrow-right-24: 학습](learning/index.md)

-   :material-presentation:{ .lg .middle } **트레이닝**

    ---

    수강한 강의 노트 — Antisyphon의 Information Security Core Skills(John Strand) 등. 강의 내용을 한국어로 풀고 다른 섹션의 레퍼런스로 연결.

    [:octicons-arrow-right-24: 트레이닝](training/index.md)

</div>

---

!!! quote ""
    *"증거가 없다는 것이 없다는 증거는 아니다."* — 다만 그 로그 소스가 실제로 켜져 있었는지는 꼭 확인하세요.
