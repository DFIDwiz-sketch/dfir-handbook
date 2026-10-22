---
title: 웹과 초기 침투
tags:
  - oscp
---

# 웹과 초기 침투 { #web-initial-access }

<div class="dfir-meta" markdown>
**배점:** standalone 대당 10점 (`local.txt`) · **최종 수정:** 2026-10-22
</div>

!!! abstract "한 문장 요약"
    standalone에서 첫 셸 얻기. 보통 웹 애플리케이션이나 노출된 서비스이고, 고쳐야 돌아가는 공개 익스플로잇인 경우가 많습니다.

!!! info "뼈대 페이지"
    지금은 구조만 있습니다 — 아래 제목이 계획이에요. 공부하면서 각 부분을 채워 나가세요.

## 웹 정보 수집 { #web-enumeration }

- 디렉터리, vhost, 서브도메인 퍼징; 기술 스택 확인; 소스 읽기

## SQL injection (수동) { #sqli }

## 파일 업로드 우회 { #file-upload }

## LFI / 경로 탐색 → RCE { #lfi }

- SSH 키 읽기; 업로드와 묶어서 코드 실행

## SSRF { #ssrf }

## CMS와 알려진 애플리케이션 { #cms }

- WordPress 플러그인과 사용자, 기본 크리덴셜

## 공개 익스플로잇 { #public-exploits }

- searchsploit, 오래된 익스플로잇 코드 수정하기

## 클라이언트 사이드 공격 { #client-side }

- 누군가 열어볼 파일 → 리버스 셸 또는 NTLMv2 해시 유출

## 웹이 아닌 서비스 { #other-services }

- FTP, SMB, NFS, SNMP (UDP)

## 관련 페이지 { #related-pages }

- [Nmap](../pentesting/recon/nmap/index.md) · [잘 알려진 포트](../basics/well-known-ports.md) · [HTTP 상태 코드](../basics/http-status-codes.md)
- [레드팀: 초기 침투](../redteam/initial-access.md) · [피싱 전달](../adversary/phishing-delivery.md)

## 참고 자료 { #references }

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
