---
title: 피벗팅과 터널링
tags:
  - oscp
---

# 피벗팅과 터널링 { #pivoting-tunnelling }

<div class="dfir-meta" markdown>
**중요한 곳:** AD 세트 — 내부 서브넷 접근 · **우선순위:** 높음 · **최종 수정:** 2026-10-22
</div>

!!! abstract "한 문장 요약"
    2025–2026년 후기에서 가장 많이 나오는 실패 원인입니다. 첫 머신은 땄는데, 그 뒤의 내부망으로 트래픽을 넘기지 못하는 경우예요.

!!! info "뼈대 페이지"
    지금은 구조만 있습니다 — 아래 제목이 계획이에요. 공부하면서 각 부분을 채워 나가세요.

## 피벗이 필요한 때 { #when-to-pivot }

- 신호: 두 번째 네트워크 인터페이스, 내부 라우트, `127.0.0.1` 에서만 듣는 서비스

## 내부 서브넷 찾기 { #subnet-discovery }

- 발판에서 살아 있는 호스트와 포트 찾기

## Ligolo-ng { #ligolo-ng }

- proxy, agent, `tun` 인터페이스, 라우트
- 리버스 셸이 피벗을 거쳐 돌아오게 하는 listener

## Chisel { #chisel }

- 대안으로 쓰는 reverse SOCKS

## SSH 포워딩 { #ssh-forwarding }

- 로컬 `-L`, 리모트 `-R`, 다이나믹 `-D`

## proxychains { #proxychains }

- SOCKS로 되는 도구와 안 되는 도구

## 이중 피벗 { #double-pivot }

- 두 번째 홉 연결하기

## 피벗을 통한 파일 전송 { #file-transfer }

- 내부 호스트로 도구 옮기기

## 관련 페이지 { #related-pages }

- [Nmap](../../pentesting/recon/nmap/index.md) — 터널을 통한 스캔
- [네트워크](../../network/index.md) — 방어자 눈에 터널 트래픽이 어떻게 보이는지
- [Active Directory](active-directory.md)

## 참고 자료 { #references }

- [netguardia — OSCP in 2026 (실패 패턴)](https://netguardia.com/learning-development/certifications/oscp-in-2026-is-it-still-the-gold-standard-and-is-the-new-format-harder/)
