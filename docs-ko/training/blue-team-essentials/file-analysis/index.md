---
title: 파일 분석
tags:
  - training
  - blue-team
  - files
  - file-analysis
---

# 파일 분석 { #file-analysis }

!!! abstract "한 줄 요약"
    경보는 결국 파일 하나를 건네줍니다. 캡처에서 뽑은 다운로드, 이메일 첨부, EDR이 격리한 무언가. 그리고 첫 질문은 언제나 "이거 진짜 뭐지?"와 "위험한가?"입니다. 이 섹션은 이름, 확장자, `Content-Type`을 믿지 않고 그 질문에 답합니다. 바이트로 파일 알아보기(`file`, 헥스 덤프, 매직 바이트, 중첩 파일, 폴리글랏, 인코딩), `strings`로 단서 뽑기, 의심 파일 안전하게 다루기, 공격자가 가장 많이 쓰는 파일 종류(실행 파일, 스크립트, Office, RTF, PDF), 해시와 코드 서명, 좋은 것과 나쁜 것 빠르게 가르기.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [파일 알아보기 — 바이트, file 명령, 매직 바이트, 중첩 파일, 폴리글랏, 유니코드와 인코딩](file-identification.md) | 파일은 그냥 바이트, 이름·확장자·`Content-Type`은 주장일 뿐, `hexdump -C`·`xxd`·PowerShell `Format-Hex` 칸별로 읽기, 샘플 여섯 개(PE32+, ELF, PNG, SVG, PDF, DLL)에 돌린 `file *` 한 줄씩, 텍스트와 스크립트, `-i`/`-k`/`-z`/`--extension`, `file`이 판단하는 방식과 속는 방식, 매직 바이트 표(MZ, PK, gzip, %PDF-, {\rtf1, PNG, ELF, OLE, LNK, 0x8001의 ISO), MZ·DOS 스텁·PE 헤더와 컴파일 시각 바이트 단위 해석, `unzip -l`로 보는 DOCX = ZIP, `.doc` 속 ZIP 찾기, `grep -obUaP`, `dd` 카빙, binwalk/foremost/scalpel과 오탐(T1027.009, T1036.008), 폴리글랏, MalDoc in PDF와 2025년 폴리글랏 공격, 유니코드 코드 포인트, UTF-8/16/32 바이트, 学가 `E5 AD A6`이 되는 과정, BOM과 UTF-16LE, 깨진 글자, 닮은꼴 글자와 RLO(T1036.002), 분류 순서, 확인 문제 |

!!! info "이어서 추가될 내용"
    `strings`(문자열이란, 인코딩과 바이트 순서, 어떻게 도움이 되나), 의심 파일 안전하게 다루기와 위험한 파일 종류, RTF·PDF·기타 파일과 빠른 분류, 해시와 코드 서명, 눈으로 살펴보기와 악성 스크립트.

## 꼭 기억할 것 { #must-know }

1. 증거는 바이트다. 이름, 확장자, `Content-Type`은 공격자가 정하는 주장이다.
2. 먼저 `file`, 그다음 헥스 보기. 매직 바이트를 내 눈으로 확인한다.
3. `MZ`, `PK\x03\x04`, `%PDF-`, `\x7fELF`, `\x89PNG`, `{\rtf1`, `1F 8B`, `D0 CF 11 E0`은 보자마자 알아본다.
4. DOCX/XLSX/PPTX는 ZIP이고, 옛 `.doc`/`.xls`는 OLE다.
5. `file`은 앞부분만 본다. 중첩 파일은 아무 위치에서나 시그니처를 찾아서 찾고, 찾은 것마다 검증한다.
6. 파일 하나가 정상 형식 둘일 수 있다. 무엇인지는 여는 프로그램이 정한다.
7. Windows 문자열은 대개 UTF-16LE다. 맞는 인코딩으로 풀고 찾는다.
8. 파일은 격리된 분석 장비에서 알아보고, 절대 열어서 확인하지 않는다.

## 관련 레퍼런스 { #related }

- [HTTP(S) 분석과 공격](../http-analysis/index.md) — 파일 추출, 샌드박스, Base64
- [꼭 알아야 할 이벤트](../important-events/index.md) — 파일이 실행될 때의 프로세스 생성
- [Zeek files.log와 pe.log](../../../network/zeek/files-log.md)
- [피싱 전달과 최초 실행](../../../adversary/phishing-delivery.md)
