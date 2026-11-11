---
title: "7 — 실습별 안내"
tags:
  - training
  - incident-response
  - pcap
---

# 7 — 실습별 안내 { #lab-guide }

!!! abstract "이 페이지는"
    8개 실습은 질문 대부분이 겹칩니다. 이 페이지는 실습마다 **새로 나오는 것**을 정리하고, 질문마다 답이 있는 절로 링크합니다. 질문은 요약해서 적었습니다.

## 실습마다 새로 나오는 것 { #overview }

| 실습 | 새로 연습하는 것 |
| --- | --- |
| 1 | 네트워크 현황 파악: DC, 활동 호스트, Ubuntu·안드로이드·아마존 Fire 등 기기 판별 |
| 2 | SMB로 DC까지 퍼진 감염, `.png`로 위장한 실행파일, SMB 파일 해시 |
| 3 | 다운로드 하나를 Zeek UID("Bro UID")로 여러 로그에서 따라가기 |
| 4 | 전달 방식(이메일, 링크, 익스플로잇 킷)과 감염 후 C2 |
| 5 | 전체 URL, 파일 크기, 악성 트래픽 시작 시각 |
| 6 | 악성 문서 안전하게 다루기, 매크로 분석, 공인 IP |
| 7 | 윈도우 전제 없음(OS 판별), 다운로드 방향(내부/외부), 다운로드를 시작한 도구 |
| 8 | 실행파일 6개, DC에 대한 SMB 실패 시도, Snort 규칙 작성 |

## 실습 1 — 네트워크 현황과 기기 판별 { #lab-1 }

여러 종류의 기기가 같은 네트워크에 있고, 윈도우 호스트 한 대가 두 패밀리에 감염됐습니다.

- **Q1** — DC의 IP는? → [도메인 컨트롤러 찾기](host-identification.md#domain-controller)
- **Q2–3** — DC 말고 활동 중인 호스트 수와 IP는? → [LAN의 활동 호스트](host-identification.md#active-hosts)
- **Q4** — Ubuntu 호스트의 IP는? → [기기 판별](host-identification.md#device-fingerprinting)
- **Q5** — 특정 IP는 어떤 기기인가? → [기기 판별](host-identification.md#device-fingerprinting)(MAC 제조사 + DHCP + DNS/User-Agent)
- **Q6** — 아마존 Fire 태블릿의 IP는? → [기기 판별](host-identification.md#device-fingerprinting)
- **Q7** — DC에 접속하는 윈도우 호스트 3대는? → [윈도우 사용자 계정](host-identification.md#user-account)(`$`로 끝나는 컴퓨터 계정), [도메인 컨트롤러 찾기](host-identification.md#domain-controller)
- **Q8** — 패밀리 두 개에 감염된 윈도우 호스트는? → [Snort 알림 읽기](malware-delivery-and-c2.md#snort-alerts), [자주 보고된 패턴](malware-delivery-and-c2.md#patterns)
- **Q9–10** — 안드로이드 8.0.0 기기의 IP와 브랜드·모델은? → [기기 판별](host-identification.md#device-fingerprinting)(User-Agent 모델코드, DHCP `android-dhcp-8.0.0`)
- **Q11** — 다른 기기의 브랜드와 종류는? → [기기 판별](host-identification.md#device-fingerprinting)(mDNS·SSDP 추가)
- **Q12** — 침해 설명 → [패밀리 두 개](report-templates.md#two-families-template)

!!! tip "실습 1 팁"
    원래 문제지의 한 질문에는 숫자 하나가 빠진 IP(`172.16.3.x` 대역인데 `172.6.3.x`로 적힘)가 있습니다. 답하기 전에 실제 주소 목록과 맞춰 오타인지 확인하세요.

## 실습 2 — SMB를 통한 DC 전파 { #lab-2 }

Word 문서 → 첫 실행파일 → `.png`로 위장한 추가 실행파일 → DC로 복사 순서로 진행됩니다.

- **Q1** — 감염 날짜·시각 → [타임라인 만들기](setup-and-workflow.md#timeline), [다운로드 목록](files-and-hashes.md#listing-downloads)(문서 다운로드 시각)
- **Q2–5** — IP, 호스트 이름, MAC, 사용자 계정 → [IP, MAC, 호스트 이름](host-identification.md#ip-mac-hostname), [윈도우 사용자 계정](host-identification.md#user-account)
- **Q6** — Word 문서의 해시 → [해시 구하기](files-and-hashes.md#hashing)
- **Q7** — 첫 악성 바이너리의 해시 → [진짜 파일 종류 확인](files-and-hashes.md#file-type), [해시 구하기](files-and-hashes.md#hashing)
- **Q8** — DC는 언제 감염됐나? → [SMB를 통한 DC 전파](dc-smb-and-snort-rules.md#smb-lateral)
- **Q9** — 이미지로 위장한 바이너리의 해시 → [진짜 파일 종류 확인](files-and-hashes.md#file-type)(두 해시를 비교: 같은 파일인가 다른 파일인가?)
- **Q10** — SMB 트래픽 파일 2개의 해시 → [파일 꺼내기](files-and-hashes.md#extracting), [SMB를 통한 DC 전파](dc-smb-and-snort-rules.md#smb-lateral)
- **Q11** — 악성코드 패밀리 2개 → [악성코드 패밀리와 종류](malware-delivery-and-c2.md#malware-type)
- **Q12** — DC를 감염시킨 패밀리는? → SMB 해시와 HTTP 해시 비교([해시 구하기](files-and-hashes.md#hashing), `uniq -w64 -D`)
- **Q14–15** — 핵심 네트워크 정보 → [핵심 네트워크 정보](host-identification.md#network-info), [틀](report-templates.md#network-info-template)
- **Q16** — 침해 설명 → [도메인 컨트롤러로 전파](report-templates.md#dc-template)

## 실습 3 — Zeek UID로 다운로드 따라가기 { #lab-3 }

- **Q1–4** — IP, MAC, 호스트 이름, 사용자 계정 → [감염 호스트 찾기](host-identification.md#infected-host), [IP, MAC, 호스트 이름](host-identification.md#ip-mac-hostname), [윈도우 사용자 계정](host-identification.md#user-account)
- **Q5** — 실행파일의 해시 → [파일 꺼내기](files-and-hashes.md#extracting)(Zeek `extract-all-files`), [해시 구하기](files-and-hashes.md#hashing)
- **Q6** — 실행파일 트래픽의 Bro UID → [Zeek UID와 fuid](files-and-hashes.md#zeek-uid)
- **Q7** — UID로 연결되는 파일 → [Zeek UID와 fuid](files-and-hashes.md#zeek-uid)(`grep -l`)
- **Q8** — 다운로드 핵심 정보 → [다운로드 핵심 정보](files-and-hashes.md#download-key-info), [틀](report-templates.md#download-template)
- **Q9** — 침해 설명 → [일반 감염](report-templates.md#generic-template)

## 실습 4 — 전달 방식과 감염 후 통신 { #lab-4 }

- **Q1–2** — IP, MAC, 호스트 이름, 사용자 계정 → [감염 호스트 찾기](host-identification.md#infected-host), [IP, MAC, 호스트 이름](host-identification.md#ip-mac-hostname)
- **Q3** — 전달 방식 → [전달 방식](malware-delivery-and-c2.md#delivery)
- **Q4** — 전달에 쓰인 IP → [전달 방식](malware-delivery-and-c2.md#delivery)
- **Q5** — EXE의 해시 → [진짜 파일 종류 확인](files-and-hashes.md#file-type)(익스플로잇 킷 페이로드는 전송 중 암호화돼 있을 수 있음)
- **Q6** — 알림으로 본 악성코드 종류 → [Snort 알림 읽기](malware-delivery-and-c2.md#snort-alerts), [악성코드 패밀리와 종류](malware-delivery-and-c2.md#malware-type)
- **Q7–8** — 감염 후 통신의 IP와 도메인 → [감염 후 통신](malware-delivery-and-c2.md#post-infection)
- **Q9** — 침해 설명 → [익스플로잇 킷·링크·이메일로 전달](report-templates.md#delivery-template)

## 실습 5 — 악성 URL, 크기, 시작 시각 { #lab-5 }

- **Q1** — 악성 트래픽은 언제 시작됐나? → [Snort 알림 만들기](setup-and-workflow.md#snort)(`-y -U`), [타임라인 만들기](setup-and-workflow.md#timeline). 첫 알림 시각과 감염 흐름의 첫 요청 중 더 이른 것을 씁니다.
- **Q2–4** — MAC, 호스트 이름, 사용자 계정 → [IP, MAC, 호스트 이름](host-identification.md#ip-mac-hostname), [윈도우 사용자 계정](host-identification.md#user-account)
- **Q5** — 실행파일을 돌려준 URL → [전체 URL과 파일 크기](files-and-hashes.md#url-and-size)
- **Q6** — 그 파일의 크기 → [전체 URL과 파일 크기](files-and-hashes.md#url-and-size)(서버가 적은 크기와 꺼낸 크기)
- **Q7** — 해시 → [해시 구하기](files-and-hashes.md#hashing)
- **Q8** — 악성코드 종류 → [악성코드 패밀리와 종류](malware-delivery-and-c2.md#malware-type)
- **Q9** — 침해 설명 → [일반 감염](report-templates.md#generic-template)

## 실습 6 — 문서 안전하게 다루기와 공인 IP { #lab-6 }

- **Q1** — 감염 날짜·시각 → 문서 다운로드 시각([다운로드 목록](files-and-hashes.md#listing-downloads))
- **Q2–5** — IP, 호스트 이름, MAC, 사용자 계정 → [IP, MAC, 호스트 이름](host-identification.md#ip-mac-hostname), [윈도우 사용자 계정](host-identification.md#user-account)
- **Q6** — Word 문서 해시를 안전하게 구하고 단계 설명 → [샘플 안전하게 다루기](files-and-hashes.md#safe-handling), [틀](report-templates.md#safe-handling-template)
- **Q7** — 초기 감염 악성코드 종류 → [악성 Word 문서와 매크로](files-and-hashes.md#macros), [악성코드 패밀리와 종류](malware-delivery-and-c2.md#malware-type)
- **Q8** — 클라이언트의 공인 IP → [공인 IP](host-identification.md#public-ip)
- **Q9** — 핵심 네트워크 정보 → [핵심 네트워크 정보](host-identification.md#network-info)
- **Q10** — 침해 설명 → [악성 Word 문서](report-templates.md#macro-template)

## 실습 7 — 방향과 다운로드 도구 { #lab-7 }

침해 호스트가 윈도우라는 전제가 없습니다.

- **Q1–3** — IP, MAC, 호스트 이름 → [감염 호스트 찾기](host-identification.md#infected-host), [IP, MAC, 호스트 이름](host-identification.md#ip-mac-hostname)(mDNS·LLMNR 포함)
- **Q4** — 운영체제 → [운영체제](host-identification.md#operating-system)
- **Q5–6** — 무엇을 몇 개, 어디서 받았나 → [다운로드 목록](files-and-hashes.md#listing-downloads), [파일 꺼내기](files-and-hashes.md#extracting)(HTTP, SMB, TFTP, FTP, 평문 TCP)
- **Q7** — 출처가 내부인가 외부인가 → [내부 출처인가 외부 출처인가](malware-delivery-and-c2.md#direction), [틀](report-templates.md#source-template)
- **Q8** — 추가 조사에 쓸 다운로드 정보 → [다운로드 핵심 정보](files-and-hashes.md#download-key-info)
- **Q9** — 다운로드 이후 눈여겨볼 것 → [감염 후 통신](malware-delivery-and-c2.md#post-infection)
- **Q10** — 무엇으로 다운로드를 시작했나 → [다운로드를 시작한 도구](malware-delivery-and-c2.md#download-tool)
- **Q11** — 침해 설명 → [다운로드·방향·도구](report-templates.md#direction-template)

## 실습 8 — 실행파일 6개, SMB 실패 시도, Snort 규칙 { #lab-8 }

- **Q1–4** — IP, MAC, 호스트 이름, 사용자 계정 → [감염 호스트 찾기](host-identification.md#infected-host), [IP, MAC, 호스트 이름](host-identification.md#ip-mac-hostname), [윈도우 사용자 계정](host-identification.md#user-account)
- **Q5** — 실행파일을 돌려준 URL 6개 → [전체 URL과 파일 크기](files-and-hashes.md#url-and-size)
- **Q6** — 실행파일 6개의 해시 → [해시 구하기](files-and-hashes.md#hashing)(PE 파일 반복문), [틀](report-templates.md#hashes-template)
- **Q7** — 파일 조사로 본 감염 종류 → [악성코드 패밀리와 종류](malware-delivery-and-c2.md#malware-type), [틀](report-templates.md#infection-type-template)
- **Q8** — 침해 설명 → [실행파일 여러 개와 DC 실패 시도](report-templates.md#multi-exe-template)
- **Q9** — DC 445에서 무엇을 시도했나 → [TCP 445 실패 시도](dc-smb-and-snort-rules.md#failed-445)
- **Q10** — 이런 445 트래픽을 잡는 Snort 규칙 → [Snort 규칙 문법](dc-smb-and-snort-rules.md#snort-rules), [예시 규칙](dc-smb-and-snort-rules.md#example-rules), [규칙 넣고 시험하기](dc-smb-and-snort-rules.md#testing-rules)

!!! note "이 섹션의 성격"
    개인 학습 노트입니다. 어떤 기관의 공식 지침도 아닙니다.
