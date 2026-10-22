---
title: 리포트
tags:
  - oscp
---

# 리포트 { #reporting }

<div class="dfir-meta" markdown>
**마감:** 실습 시간 종료 후 24시간 · **최종 수정:** 2026-10-23
</div>

!!! abstract "한 문장 요약"
    리포트가 증명해야 점수가 인정됩니다. VPN이 닫히면 머신으로 돌아갈 수 없으니 실수는 되돌릴 수 없어요.

!!! note "이 페이지 구성"
    리포트에 꼭 들어갈 것, 리포트가 시작 전에 80% 쓰여 있게 만드는 노트 방법, 제출 체크리스트입니다. 리포트 연습은 시험 연습의 일부예요 — [실습 랩 › 모의 시험](practice-labs.md#mock-exams) 참고.

## 리포트의 목적 { #purpose }

채점자가 읽고 **모든 단계를 재현** 할 수 있어야 합니다. 못 따라가거나 플래그가 증명되지 않으면, 실제로 뚫었든 아니든 그 대상은 감점 또는 0점이에요. 시험 네트워크를 클라이언트 업무처럼 다루고, 고객에게 낼 리포트를 쓴다고 생각하세요.

## 증거 요구 사항 (점수를 좌우하는 것) { #proof }

- 플래그마다 **플래그 내용과 대상 IP가 같은 화면에** 보이는 스크린샷이 필요합니다(`ip addr` / `ifconfig` / `ipconfig`). 따로 찍은 두 장은 인정 안 돼요.
- 플래그는 원래 위치에서 `cat` / `type` 로 **인터랙티브 셸** 에서 읽어야 합니다 — **웹 셸은 무효**.
- `proof.txt` 는 올바른 권한으로: Linux는 root, Windows는 SYSTEM / Administrator / 로컬 관리자.
- 모든 플래그를 시험 종료 전에 컨트롤 패널에 제출하고 **그리고** 스크린샷을 리포트에 넣습니다.

자세히: [시험 구조 › 플래그가 인정되는 조건](exam-format.md#flag-rules).

## 시험 중 노트 구조 { #exam-notes }

머신당 한 페이지, 매번 같은 섹션 — 이게 바로 리포트 초안입니다:

```text
## Target: 192.168.x.x  (Standalone 1)
### Nmap / enumeration
### Initial access        → local.txt (스크린샷: 플래그 + IP)
### Local enumeration
### Privilege escalation   → proof.txt (스크린샷: 플래그 + IP)
### Exploit code / changes (URL, 고친 코드, 설명)
```

그때 통한 것만이 아니라 **관련 있을 만한 것은 전부** 기록하세요 — 머신 1의 어떤 정보가 한 시간 뒤 머신 2를 열 수 있고, 적어 두지 않으면 기억나지 않습니다.

## 리포트에 넣는 익스플로잇 코드 { #exploit-code }

- **고치지 않은 공개 익스플로잇:** URL만.
- **고친 익스플로잇:** 고친 코드, 원본 URL, 셸코드 / `msfvenom` 명령(있다면), 그리고 **바꾼 부분마다** 표시하고 설명.

## 템플릿과 도구 { #template }

- **공식 템플릿:** [OSCP Exam Report (.docx)](https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx) — 사용이 강력히 권장됩니다.
- **시험 중:** 손에 익은 노트 도구 — Obsidian, CherryTree, Sublime. 스크린샷을 머신별로 정리.
- **리포트 자동화(선택):** SysReptor로 노트를 최종 문서로 만드는 걸 빠르게 할 수 있어요.

## 제출 { #submission }

| 항목 | 요구 사항 |
|---|---|
| 형식 | PDF 한 개를 `.7z` 로 압축; 스크립트 / PoC는 **PDF 안에 텍스트** (압축 안에 다른 파일 금지) |
| PDF 이름 | `OSCP-OS-XXXXX-Exam-Report.pdf` (내 OSID) |
| 압축 이름 | `OSCP-OS-XXXXX-Exam-Report.7z` (같은 OSID) — **대소문자 구분, 정확히 일치** |
| 비밀번호 | PDF와 압축 모두 없음 |
| 크기 | 최대 200 MB |
| 어디에 / 언제 | <https://upload.offsec.com>, 실습 종료 후 **24시간** 안에 |
| 확인 | 업로드 후 MD5를 내 파일과 비교; 다르면 재업로드, 그다음 **Submit File** 클릭 |

!!! warning "업로드 함정"
    Windows 11에서 업로드할 때 "file is not a proper format" 오류를 겪은 사람들이 있어요 — OffSec은 Kali VM에서 업로드하라고 권합니다. 성공하면 확인 이메일이 옵니다(스팸 확인).

## 제출 체크리스트 { #submission-checklist }

- [ ] 주장하는 모든 플래그에 증거 스크린샷 (플래그 + IP, 한 화면)
- [ ] 모든 단계가 리포트만으로 재현됨
- [ ] 고친 익스플로잇: 코드 + 원본 URL + 변경 설명
- [ ] 머신별로 분명하게 나뉜 섹션 (채점은 리포트 순서대로)
- [ ] 파일 이름 정확히 `OSCP-OS-XXXXX-Exam-Report.pdf` / `.7z`
- [ ] PDF·압축에 비밀번호 없음; 압축 ≤ 200 MB
- [ ] upload.offsec.com에 업로드, MD5 확인, **Submit File** 클릭
- [ ] 확인 이메일 수신

## 관련 페이지 { #related-pages }

- [시험 구조와 점수](exam-format.md) · [방법론과 습관](methodology.md) · [시험 당일 전략](exam-day.md)

## 참고 자료 { #references }

- [OffSec — PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements)
- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)
