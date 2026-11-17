---
title: 분석 사례
tags:
  - blue-team
  - pcap
  - zeek
  - tshark
---

# 패킷·로그 분석 사례 { #investigations }

실제 캡처와 로그를 분석한 풀이 모음입니다. 열어 보지 않은 PCAP(또는 로그)에서 시작해 답과 짧은 보고서로 끝납니다. **모든 명령, 실제 출력, 그 출력이 왜 답인지**를 함께 적습니다.

주 도구는 Zeek입니다. tshark로 같은 답을 더 쉽게 얻을 수 있는 곳에는 Zeek 명령 옆에 **tshark** 탭을 붙였습니다.

## 사례 목록 { #cases }

| 사례 | 증거 | 배우는 것 |
|---|---|---|
| [PCAP 실습 06 — 청구서 Word 매크로에서 Hancitor 유형 C2까지](pcap-lab-06-invoice-macro-c2.md) | PCAP 21분, AD 도메인의 윈도우 PC 한 대 | 단일 호스트 트리아지, Word 문서를 안전하게 다루고 해시 구하기, Office 없이 매크로 찾기, IP 확인 서비스로 공인 IP 찾기, 비콘 패턴과 User-Agent 비교, DHCP·Kerberos로 네트워크 정보 찾기 |
| [PCAP 실습 07 — 웹메일 이후 AutoIt 다운로더와 여러 C2](pcap-lab-07-autoit-downloader-multi-c2.md) | PCAP 18.5분, 도메인에 속하지 않은 윈도우 7 PC 한 대 | 도메인 없이 OS 찾기(User-Agent, TTL, DHCP 벤더 클래스), 브라우저가 아닌 다운로드, 캡처 손실과 해시가 없는 이유, 목적지와 함께 읽는 User-Agent, 알 수 없는 연결, SMTP 유출 징후 |
| [Arkime만으로 — 스크립트 다운로더에서 비밀번호 탈취, TLS C2, 침해사고 티켓까지](arkime-only-credential-theft-tls-c2.md) | PCAP 44분, AD 도메인의 윈도우 10 PC 세 대. **Arkime 웹 화면 + CyberChef만**, 폐쇄망 | 세션과 SPI View, 시작·끝 시간, Kerberos로 호스트이름 찾기, POST 본문 읽기(Hide Images & Files), 인증서 발급자/주인과 자체 서명 확인, 447/449 TLS C2, SMB 스캔으로 범위 판단, 침해사고 티켓 작성, 복사용 쿼리 |
| [RedLine Stealer — PowerShell 스크립트에서 net.tcp C2 정보 탈취까지](redline-stealer-powershell-nettcp-c2.md) | PCAP 36초, AD 도메인의 윈도우 10 PC 한 대(Unit 42 퀴즈, 2023년 7월). Arkime 기준 | DHCP로 IP·MAC·호스트이름, DNS SRV와 Kerberos, PowerShell User-Agent 체크인, `.jpg`로 위장한 HTTPS 페이로드, JA3가 변하지 않은 이유, 포트로 TCP C2 찾기, .NET net.tcp 읽기, 서버의 탈취 목록과 실제 업로드, 화면 캡처 꺼내기와 캡처 손실, Trickbot과 비교 |

표에 따로 적지 않은 사례는 Zeek로 풀었습니다.

같은 실습 시리즈의 다른 사례도 끝나는 대로 여기에 추가합니다.

## 사례 페이지 구성 { #case-structure }

1. **상황과 질문**: 무엇이 주어졌고 무엇을 답해야 하는지
2. **준비**: 폴더, 증거 해시, Zeek 로그 만들기
3. **전체 그림**: 캡처 시간, 내부 호스트, DHCP, Kerberos, DC
4. **수상한 것 찾기**: 파일, URL, 첫 악성 이벤트
5. **샘플을 안전하게 다루고 분석하기**: 추출, 해시, 파일 종류, 매크로
6. **감염 이후 통신**: C2, 추가 다운로드, IP 확인, 비콘 간격
7. **네트워크 정보**: 대역, 게이트웨이, 도메인, DC 이름
8. **타임라인, IOC, 답, 보고서**
9. **탐지 아이디어와 교훈**

결과마다 **확인됨**(증거에서 직접 보임)과 **추정**(합리적인 결론이지만 증거만으로는 증명되지 않음)을 구분합니다. 악성코드 계열 이름은 해시 조회나 시그니처로 확인하지 않았다면 추정으로 적습니다.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인, IP, 해시는 실제 악성 트래픽에서 나온 값입니다. IOC 표에서는 `hxxp`, `[.]`처럼 무력화(defang)해서 적었습니다. 접속하지 마세요.

## 방법 페이지 { #method-pages }

- [PCAP 침해사고 분석 실습 — 준비와 분석 순서](../../training/pcap-ir-labs/setup-and-workflow.md): 이 사례들이 따르는 반복 절차
- [Zeek 로그](../../network/zeek/index.md) · [Wireshark & tshark](../../network/wireshark-tshark.md) · [비콘과 C2](../../network/beaconing-c2.md)
- [Arkime로 PCAP 분석하기](../../network/arkime/offline-pcap-guide.md): 같은 실습 질문을 Arkime로 푸는 방법
