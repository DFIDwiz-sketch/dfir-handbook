---
title: "1부 — 네트워크 증거의 기초"
tags:
  - training
  - network-forensics
---

# 1부 — 네트워크 증거의 기초 { #part-1 }

!!! abstract "1부에서 다루는 것"
    디스크를 볼 수 없을 때 네트워크에 무엇이 남는지부터 시작합니다. 그다음 웹 프록시의 로그와 캐시, pcap 파일과 tcpdump·BPF, Wireshark와 tshark를 차례로 익히고, 증거를 어디서 어떤 장비로 수집하는지, 무엇이 조사를 어렵게 만드는지까지 다룹니다.

## 회차 { #lessons }

1부의 13개 회차가 모두 게시됐습니다. 차례대로 읽는 것을 권하지만, 실습 가이드(1.10강, 1.13강)는 앞 회차를 훑은 뒤 바로 해 봐도 좋습니다.

| 회차 | 주제 | 상태 |
| --- | --- | --- |
| [1.1강](why-network-forensics.md) | 디스크 밖에 남는 증거: 네트워크 포렌식이 필요한 이유와 조사자의 자세 | 게시 |
| [1.2강](web-proxies.md) | 웹 프록시: 동작 원리, 종류, 설정 파일이 증거인 이유 | 게시 |
| [1.3강](proxy-logs.md) | 프록시 로그 읽기: 기본·맞춤 형식, 유닉스 시간 | 게시 |
| [1.4강](proxy-log-walkthrough.md) | 프록시 로그만으로 사건 재구성하기(조사 실습) | 게시 |
| [1.5강](proxy-cache.md) | 상용 프록시 로그와 프록시 캐시에서 응답 꺼내기 | 게시 |
| [1.6강](pcap-and-tcpdump.md) | libpcap, tcpdump, pcap·pcapng 파일 구조 | 게시 |
| [1.7강](bpf.md) | BPF로 필요한 패킷만 고르기 | 게시 |
| [1.8강](tcpdump-options-wireshark-ui.md) | tcpdump 실전 옵션과 Wireshark 화면 읽기 | 게시 |
| [1.9강](wireshark-display-filters.md) | Wireshark 디스플레이 필터와 스트림 따라가기 | 게시 |
| [1.10강](lab-tcpdump-wireshark-tshark.md) | 실습 가이드: tcpdump와 Wireshark 손에 익히기 | 게시 |
| [1.11강](network-evidence-acquisition.md) | 증거 수집: 어디서, 어떤 장비로 패킷을 모으나 | 게시 |
| [1.12강](challenges-and-opportunities.md) | 네트워크 조사의 어려움과 기회 | 게시 |
| [1.13강](lab-carving-exfiltrated-data.md) | 실습 가이드: 유출된 데이터 카빙하기 | 게시 |

## 1부를 마치며 { #wrap-up }

1부를 마치면 다음을 할 수 있어야 합니다.

- 디스크를 볼 수 없을 때도 **통신이 지나간 길**의 증거(전체 패킷, 플로우, 로그)로 가설을 세우고 검증한다(1.1강, 1.11강).
- 프록시 로그의 칸을 읽고, 로그만으로 사건의 흐름을 재구성하며, 캐시에서 응답을 꺼낸다(1.2~1.5강).
- pcap의 구조를 이해하고, tcpdump와 BPF로 수집하고 줄이며, Wireshark와 tshark로 해석하고 표로 만든다(1.6~1.10강).
- 증거를 어디서 어떤 장비로 얻을지 계획하고, NAT, 암호화, 터널 같은 어려움 속에서 남는 단서를 찾는다(1.11~1.12강).
- 평문 스트림에서 올라간 파일을 여러 단계로 꺼내고, 해시로 재현성을 보이며, 사실과 해석을 나눠 보고한다(1.13강).

각 회차의 실행 결과는 그 회차에 적은 도구 버전으로 얻었고, 바뀐 점은 **[변경됨]**, 바로잡은 점은 **[정정]**으로 표시했습니다.

## 시리즈 처음으로 { #back }

[Network Forensics 첫 페이지](../index.md)
