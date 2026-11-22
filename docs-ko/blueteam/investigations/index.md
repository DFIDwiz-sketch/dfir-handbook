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
| [IcedID (Cold as Ice) — 리다이렉트·Firebase·가짜 gzip에서 HTTPS 비콘과 BackConnect까지](icedid-tds-gzip-loader-backconnect.md) | PCAP 약 6시간, AD 도메인의 윈도우 클라이언트 3대(Unit 42 퀴즈, 2023년 4월). Arkime 기준 | DHCP 없이 PC 정체 찾기(Kerberos·NetBIOS·MAC), DNS로 감염 PC 좁히기, TDS 302와 Firebase 악용, IcedID 쿠키 해독(호스트·사용자·SID), 자체 서명 `Internet Widgits` 인증서, 5분 비콘 재기, Edge 때문에 늘어나는 JA3, 443인데 TLS가 아닌 BackConnect와 공격자 명령, 두 번째 PC의 zip/.wsf, 앞의 두 사례와 비교 |
| [피싱 메일이라는 함정, 실제 원인은 익스플로잇 킷 — Angler 유형 EK, Ursnif 유형 C2, CAB 유출](phishing-red-herring-ek-driveby-ursnif-c2.md) | 피싱 `.eml` 7개 + 직원 목록 + PCAP(12.5분, 윈도우 7 / IE11 PC 한 대). **Splunk(Zeek) + Arkime + Snort**, 폐쇄망 | 메일 헤더 아래에서 위로 읽기, MIME 인코딩, base64를 풀어 zip 내부 읽기(zip 안의 zip, NTFS 시각), STARTTLS의 한계, Splunk 함정(`_time` = 넣은 시각, `host` 충돌, TSV 다중값 필드), 뻔한 가설 시험하기, Flash 게이트를 거쳐 익스플로잇 킷까지 referrer 사슬, Arkime Body MD5와 natural 보기, POST 속 CAB 유출, 라운드 로빈 C2 DNS, PCAP으로 테스트한 Snort 룰 11개(DNS, flowbits, pcre, Accept 없음), 완성 티켓 |
| [Back to the Present — 네트워크 베이스라이닝부터 .bit C2, 기술지원 사기 팝업, Snort 룰, 티켓까지](back-to-the-present-chthonic-c2-tech-support-scam.md) | PCAP(12분, 가정용 공유기 뒤의 윈도우 10 PC 한 대, malware-traffic-analysis.net 2017-10-21). **Splunk(Zeek) + Arkime + Snort**, 폐쇄망 | 처음부터 하는 네트워크 베이스라이닝(내부 대역, MAC으로 장치 세기, 라우터, DNS·DHCP 서버, DC·파일·메일 서버 없음 확인, 프로토콜, User-Agent·DHCP·NetBIOS·TTL로 OS 찾기, 외부 통신 개요), User-Agent 없는 요청 찾기, Office 실행 직후의 EXE 다운로드, 외부 DNS에 TCP 53으로 묻는 `.bit`(Namecoin) C2, 암호화된 HTTP/1.0 POST C2와 모듈 다운로드, `streamstats`로 간격 재기, 팝언더 스크립트에서 기술지원 사기까지, 범위 확인, PCAP으로 테스트한 Snort 룰 14개(DNS 이름 형식, threshold, flowbits, file_data, pcre), 호스트 오퍼레이터 단서가 든 티켓 |
| [Night Dew — Hancitor 체크인에서 후속 다운로드, 정보 유출, 자체 서명 TLS C2까지](night-dew-hancitor-pony-zeus-panda-tls-c2.md) | PCAP(43분, AD 도메인의 윈도우 7 PC 한 대, malware-traffic-analysis.net 2018-05-11). **Arkime + CyberChef + Snort**, 폐쇄망 | 도메인 환경에서 DHCP·Kerberos·DNS로 베이스라인, 수상한 외부 IP 고르기, C2 본문과 이어지는 api.ipify 공인 IP 조회, Hancitor `GUID=/BUILD=/INFO=` 체크인 읽기, CyberChef(Base64 → XOR 0x7A)로 C2 응답을 다운로드 명령으로 풀기, `text/plain`으로 위장한 암호화 페이로드, Pony 유형 `Content-Encoding: binary` 유출 POST, 자체 서명 `Default Company Ltd` TLS C2와 5분 묶음, 최초 감염 경로 미확인 타임라인, PCAP으로 테스트한 Snort 룰 8개, 하나로 합친 티켓(txt 내려받기) |
| [Night Dew 두 번째 분석 — Arkime + Splunk(Zeek), netlogon 비밀번호 대입, Snort 룰 하나](night-dew-arkime-splunk-netlogon-bruteforce.md) | 같은 PCAP을 **pcapbox** 랩에서 처음부터 다시. **Arkime + Splunk(Zeek 로그) + CyberChef + Snort** | 도구별 케이스 이름과 태그, Arkime를 UTC로, DHCP·Kerberos로 신원 확인(cname과 sname, preauth), HTTP 먼저 읽기, Base64 → XOR crib 방법과 비콘 응답 `{n:}`, `files.log`로 본 암호화 페이로드, TLS 인증서 필드(CN과 Org), `delta`로 비콘 간격, 보낸 948 KB를 `dce_rpc.log`로 추적해 찾은 **netlogon `NetrLogonSamLogonWithFlags` 1,522번(비밀번호 대입)**, PSH와 Payload8, Snort 룰 하나와 초보자용 테스트 가이드, 핵심만 담은 짧은 티켓 |
| [Blank Clipboard — 웹메일 속 WhatsApp 피싱 링크에서 Dropbox 1단계 파일과 17 MB ZIP까지](blank-clipboard-whatsapp-phish-dropbox-zip-downloader.md) | PCAP(14.5분, AD 도메인의 Windows 7 PC 한 대, LAN 정보 없음) + 피싱 `.eml` 2개, malware-traffic-analysis.net 2018-09-27. pcapbox에서 **Arkime + Splunk(Zeek) + Snort** | LAN 정보 없이 도메인·DC·사용자 찾기(DHCP `domain`, Kerberos cname/sname/realm), 개수로 안 보일 때 바이트로 정렬, SNI로 암호화된 목적지 이름 알기(회사 웹메일), `Location` 헤더로 Dropbox 파일까지 리다이렉트 체인 읽기, User-Agent 비교(IE11 vs `MSIE 7.0` vs 없음), 빈 Referer 증명하기, Kerberos·NCSI 출발지 포트·GPT.INI로 재부팅 가설 확인, 이메일 헤더(`Received`, `-0300`, `X-PHP-Originating-Script`), URL 완전 일치로 감염 메일 고르기, 다른 메일이 쓰이지 않았다는 증명, `missing_bytes`와 `acked-unseen-segment-src`(캡처 손실 vs 못 받음), 캠페인 링크 모양을 잡는 Snort 룰 하나, 팀 양식 티켓 |

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
