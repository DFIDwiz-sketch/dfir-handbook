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

강의는 한 회차씩 차례대로 추가합니다. 아래 목록의 아직 링크가 없는 회차는 준비 중입니다. 내용 분량에 따라 한 회차가 둘로 나뉘는 등 번호가 조금 바뀔 수 있어요.

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
| 1.10강 | 실습 가이드: tcpdump와 Wireshark 손에 익히기 | 준비 중 |
| 1.11강 | 증거 수집: 어디서, 어떤 장비로 패킷을 모으나 | 준비 중 |
| 1.12강 | 네트워크 조사의 어려움과 기회 | 준비 중 |
| 1.13강 | 실습 가이드: 유출된 데이터 카빙하기 | 준비 중 |

## 시리즈 처음으로 { #back }

[Network Forensics 첫 페이지](../index.md)
