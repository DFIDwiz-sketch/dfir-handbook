---
title: 계정 탈취와 BEC
tags:
  - playbook
  - identity
  - cloud
---

# 계정 탈취와 비즈니스 이메일 침해(BEC) { #account-compromise-business-email-compromise }

<div class="dfir-meta" markdown>
**시나리오:** 정상 계정의 수상한 로그인, 사서함 규칙, 또는 사기 이메일 · **최종 수정:** 2026-09-17
</div>

!!! abstract "언제 쓰나"
    사용자의 자격증명이 피싱당했거나 도난당해 누군가 그 사용자로 로그인하고 있을 때 — 불가능한 이동(impossible travel) 로그인, MFA 피로 공격으로 승인된 요청, 답장을 숨기는 새 받은 편지함 규칙, 사용자가 쓰지 않은 메일 발송, 사용자가 모르는 OAuth 앱 동의. BEC의 목적은 보통 **송장/결제 사기**나 신뢰받는 사서함을 이용한 추가 피싱입니다. 증거 대부분은 엔드포인트가 아니라 **클라우드 로그**(Entra/M365, Google Workspace)에 있습니다.

## 1. 트리아지 (첫 15분) { #1-triage-first-15-minutes }

- 수상한 로그인을 확인하세요: 출발지 IP/국가/ASN, 장치, MFA를 통과했는지와 어떻게 통과했는지 (푸시 승인? 토큰? MFA를 우회하는 레거시 인증?).
- **받은 편지함 규칙**과 **전달 설정**을 확인하세요 — 공격자는 "invoice/payment/bank"가 들어간 답장을 RSS/보관/삭제 폴더로 옮기는 규칙을 만들어 사용자가 사기 스레드를 못 보게 합니다.
- 최근 허용된 **OAuth 앱 동의**를 확인하세요 — 악성 앱은 비밀번호를 재설정해도 접근을 유지합니다.
- 돈이 움직이고 있다면(사기성 결제 요청) **즉시** 재무/경영진에 알리세요 — 회수는 시간이 생명입니다.

## 2. 수집 { #2-collect }

| 출처 | 무엇 | 주요 필드 |
|---|---|---|
| Entra ID / Azure AD 로그인 로그 | 모든 인증 시도 | `UserId`, `IPAddress`, `AppDisplayName`, `Status`, `MfaDetail`, `DeviceDetail`, `ConditionalAccessStatus` |
| M365 통합 감사 로그 | 사서함과 관리 작업 | `Operation` (`New-InboxRule`, `Set-Mailbox`, `Add-MailboxPermission`, `UpdateInboxRules`, `Consent to application`), `ClientIP`, `UserId` |
| 메시지 추적 | 보내고 받은 메일 | 보낸 사람, 받는 사람, 제목, 상태 |
| Google Workspace (쓴다면) | 로그인 + 관리 + Gmail 로그 | `login`, `token`, Gmail 설정 감사 |
| 엔드포인트 (페이지/악성코드로 자격증명을 피싱당했다면) | 피싱 아티팩트 | [피싱 전달](../adversary/phishing-delivery.md) |

## 3. 분석 { #3-analyse }

- **악성 세션**: 로그인 로그에서 공격자의 IP/ASN/User-Agent를 확정한 뒤, 감사 로그에서 그 `ClientIP`와 세션의 **모든 행동**을 찾으세요 — 만든 규칙, 읽거나 보낸 메일, 접근한 파일(SharePoint/OneDrive), 추가한 권한.
- **받은 편지함 규칙과 전달**: 사서함의 모든 규칙과 전달 주소를 나열하세요; 공격자는 사기 스레드를 숨기고 외부 주소로 자동 전달합니다. 생성 시각과 규칙의 조건/동작을 기록하세요.
- **OAuth 권한 부여**: 앱 동의를 나열하세요; 악성 "앱"(불법 동의 부여)은 비밀번호 재설정 후에도 살아남아 토큰으로 메일을 다시 읽습니다 — 폐기하세요.
- **피해 범위**: 이 사서함에서 내부/외부 연락처로 피싱을 보냈나? 해당 시간대의 발신 메시지 추적. 공유 파일에 접근했나? SharePoint/OneDrive 감사를 확인하세요.
- **MFA**: MFA가 우회됐나(레거시 인증, 토큰 탈취/AiTM), 아니면 승인됐나(MFA 피로)? AiTM(adversary-in-the-middle) 피싱은 **세션 토큰**을 훔치므로 이상한 IP에서 MFA를 통과한 로그인으로 보입니다 — 비밀번호 재설정만으로는 소용없고, **세션/토큰을 폐기**해야 합니다.

## 4. 봉쇄 / 제거 { #4-contain-eradicate }

- **비밀번호 재설정과 함께 모든 세션/리프레시 토큰을 폐기하세요** (Entra: "Revoke sessions"; Google: 모든 세션 로그아웃) — 토큰을 훔친 공격자는 비밀번호 변경을 무시합니다.
- MFA를 다시 등록/필수화하고, 공격자가 등록한 MFA 방법과 장치를 제거하세요.
- **악성 받은 편지함 규칙과 전달을 삭제**하고, 공격자가 추가한 사서함 권한을 제거하세요.
- **수상한 OAuth 앱 동의를 폐기**하세요.
- 공격자 인프라를 차단하세요; 피싱 페이지가 자격증명을 수집했다면 내리게 하거나 신고하세요.
- 같은 비밀번호를 쓰거나 같은 캠페인에 피싱당한 **다른 계정**도 재설정하세요.

## 5. 복구와 교훈 { #5-recover-lessons }

- 사서함에서 보낸 피싱/사기 메일의 수신자에게 알리고, 재무 부서와 거래 상대방과 함께 사기성 결제 지시를 바로잡으세요 (다른 경로로 연락).
- 의무에 따라 보고하세요 (개인정보 규제 기관, 은행, 보험사).
- 강화: 특히 재무/임원에게 **피싱 저항 MFA**(FIDO2/패스키)를 강제하고, **레거시 인증**을 차단하고, **조건부 액세스**를 강화하고(위험한 로그인 차단, 국가 제한), **OAuth 앱 동의**를 제한하고(관리자 승인), **새 받은 편지함 규칙 / 전달**에 경보를 걸고, BEC를 다루는 사용자 교육 + 결제 확인 절차를 운영하세요.

## 유용한 쿼리 { #useful-queries }

```spl
index=<your_o365_index> sourcetype="o365:management:activity" Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox")
| table _time, UserId, ClientIP, Operation, Parameters
| sort 0 _time
```

`Operation`이 사서함 작업 이름입니다; 공격자 세션의 `ClientIP`로 만든 `New-InboxRule`/`UpdateInboxRules`, 특히 "payment/invoice/bank" 메일을 숨은 폴더로 옮기는 규칙이 BEC의 특징입니다. `Parameters`에 규칙의 조건과 동작이 들어 있습니다.

```spl
index=<your_aad_index> sourcetype="azure:aad:signin"
| stats values(IPAddress) as ips, values(AppDisplayName) as apps, dc(IPAddress) as ip_count, values(Status.errorCode) as codes by UserPrincipalName
| where ip_count > 5
```

사용자별로 로그인을 묶고 고유 출발지 IP 수를 셉니다; 갑자기 여러 IP/국가에서(또는 새 `AppDisplayName`으로) 인증하는 계정은 탈취 지표입니다. 필드 이름은 사용하는 M365/Entra 애드온에 맞게 바꾸세요 — [데이터 탐색](../splunk/data-discovery.md)으로 확인.

```spl
index=<your_o365_index> sourcetype="o365:management:activity" Operation="Consent to application"
| table _time, UserId, ClientIP, ObjectId, ApplicationId
```

불법 OAuth 동의 부여 — 사용자(또는 사용자 행세를 하는 공격자)가 앱을 승인하면 그 앱이 토큰으로 메일을 읽습니다. 비밀번호를 재설정해도 남아 있으므로 반드시 찾아서 폐기해야 합니다.

## 참고 자료 { #references }

- [Microsoft — Responding to a compromised email account](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account)
- [CISA — Business Email Compromise](https://www.cisa.gov/) · [FBI IC3 BEC](https://www.ic3.gov/)
- [Microsoft — Unified Audit Log / AiTM investigation](https://learn.microsoft.com/en-us/defender-xdr/)
- 관련 페이지: [피싱 전달](../adversary/phishing-delivery.md) · [데이터 탐색](../splunk/data-discovery.md)
