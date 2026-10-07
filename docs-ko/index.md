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

-   :material-toolbox:{ .lg .middle } **도구**

    ---

    KAPE, Velociraptor, Eric Zimmerman 도구, Plaso, Wireshark, tshark 등의 치트시트.

    [:octicons-arrow-right-24: 도구](tools/index.md)

-   :material-clipboard-list:{ .lg .middle } **플레이북**

    ---

    자주 만나는 상황별 단계적 대응 절차.

    [:octicons-arrow-right-24: 플레이북](playbooks/index.md)

</div>

---

!!! quote ""
    *"증거가 없다는 것이 없다는 증거는 아니다."* — 다만 그 로그 소스가 실제로 켜져 있었는지는 꼭 확인하세요.
