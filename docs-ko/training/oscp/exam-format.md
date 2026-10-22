---
title: 시험 구조와 점수
tags:
  - oscp
---

# 시험 구조와 점수 { #exam-format-scoring }

<div class="dfir-meta" markdown>
**섹션:** OSCP+ · **출처:** OffSec OSCP+ Exam Guide (2026-10-23 확인) · **최종 수정:** 2026-10-23
</div>

!!! abstract "한 문장 요약"
    전용 VPN 안에서 23시간 45분 동안 실습하고, 그다음 24시간 안에 리포트를 올립니다. 100점 만점에 70점 합격, 2024년 11월 1일부터 보너스 점수는 없습니다. 그리고 플래그는 **인터랙티브 셸에서 얻었다는 것을 리포트가 증명해야** 점수로 인정됩니다.

!!! warning "규칙은 바뀝니다 — 예약 전에 다시 읽기"
    이 페이지의 내용은 공식 [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)를 정리한 것입니다. OffSec은 예고 없이 가이드를 고칩니다. 시험 1주일 전에 공식 가이드를 꼭 다시 읽으세요.

## 시험 한눈에 보기 { #at-a-glance }

| 항목 | 내용 |
|---|---|
| 실습 시간 | 23시간 45분 (예: 09:00 시작 → 다음 날 08:45에 VPN 종료) |
| 리포트 시간 | 실습 시간이 끝난 뒤 24시간 |
| 머신 | standalone 3대 + Active Directory 세트 1개(3대) |
| 만점 | 100점 |
| **합격 점수** | **70점** |
| 보너스 점수 | 없음 (2024년 11월 1일 폐지) |
| 접속 | Kali Linux + OpenVPN (OffSec이 지원하는 유일한 환경) |
| 감독 | 실습 시간 내내 웹캠 + 화면 공유 |
| 결과 | 리포트 제출 후 영업일 10일 안에 이메일로 |

### 점수는 어디서 나오나 { #points }

| 대상 | 점수 | 방법 |
|---|---|---|
| Standalone 1 / 2 / 3 | 대당 20점 | `local.txt`(저권한 사용자) 10점 + `proof.txt`(root / Administrator) 10점 |
| AD 머신 #1 | 10점 | 첫 번째 호스트 완전 장악 |
| AD 머신 #2 | 10점 | 두 번째 호스트 완전 장악 |
| AD 머신 #3 (도메인 컨트롤러) | 20점 | 도메인 장악 |

AD 세트는 시작할 때 **아이디와 비밀번호**를 줍니다. 이미 피싱으로 계정이 털린 사용자 상황을 흉내 낸 것이에요("assumed breach"). 머신마다 정확한 목표는 **시험 컨트롤 패널**에 나오니, 시작하자마자 읽어 두세요.

### 플래그가 인정되는 조건 { #flag-rules }

플래그를 손에 넣는 것만으로는 부족합니다. 아래 조건을 모두 지키지 않으면 그 대상은 **0점**이 될 수 있어요.

1. **인터랙티브 셸.** 대상 머신의 인터랙티브 셸에서 `cat`(Linux) 또는 `type`(Windows)으로 읽어야 합니다. **웹 셸은 인정되지 않습니다.** 웹 셸로 읽은 플래그는 그 대상 전체가 0점이에요.
2. **원래 위치.** 플래그를 복사하거나 옮기지 말고, 원래 있던 자리에서 읽습니다.
3. **IP가 보이는 스크린샷.** 플래그 내용과 대상의 IP 주소(`ip addr`, `ifconfig`, `ipconfig`)가 **같은 스크린샷 한 장**에 보여야 합니다.
4. **`proof.txt` 는 올바른 권한으로.** Linux는 root 셸, Windows는 SYSTEM / Administrator / 로컬 Administrators 그룹 사용자의 셸.
5. 시험이 끝나기 전에 **컨트롤 패널에 제출.** 패널은 맞았는지 틀렸는지 알려 주지 **않습니다.**
6. 기술을 아는 사람이 모든 단계를 그대로 따라 할 수 있을 만큼 **리포트에 기록.**

1~4번 조건을 한 화면에 담는 증거 스크린샷 예시입니다.

=== "Linux"

    ```bash
    hostname; whoami; ip addr show | grep 'inet '; cat /root/proof.txt
    ```

    ```text title="출력 예시 (설명용)"
    web01
    root
        inet 127.0.0.1/8 scope host lo
        inet 192.168.120.45/24 brd 192.168.120.255 scope global ens160
    3f1c0e9b6a2d47c58e1f0a9d2b7c4e61
    ```

    한 줄씩 보면: `hostname` 은 머신 이름, `whoami` 는 현재 사용자(root여야 함), `ip addr show | grep 'inet '` 은 IP 주소만 골라 보여 주고, `cat` 은 플래그 내용을 출력합니다.

=== "Windows"

    ```powershell
    hostname & whoami & ipconfig | findstr IPv4 & type C:\Users\Administrator\Desktop\proof.txt
    ```

    ```text title="출력 예시 (설명용)"
    MS01
    nt authority\system
       IPv4 Address. . . . . . . . . . . : 10.10.120.141
    9a4e2c71d0b84f6e93c5a1f7e2d6b083
    ```

    `&` 는 cmd에서 명령을 이어서 실행합니다. `ipconfig | findstr IPv4` 는 IPv4 줄만 골라 보여 줍니다.

!!! tip "채점 순서"
    OffSec은 리포트에 적힌 순서대로 머신을 채점합니다. 대상마다 제목이 분명한 섹션을 따로 만드세요.

## 합격 점수 조합 { #passing-combinations }

공식 가이드 기준 — 모두 딱 70점입니다.

- AD 40 + `local.txt` 3개
- AD 40 + `local.txt` 2개 + `proof.txt` 1개
- AD 20 + `local.txt` 3개 + `proof.txt` 2개
- AD 10 + standalone 3대 완전 장악

거꾸로 읽어 보면 왜 다들 *"AD 세트를 잡아라"* 라고 하는지 보입니다.

| AD 점수 | 필요한 standalone 점수 | 의미 |
|---|---|---|
| 40 | 30 | 초기 침투 3개, **또는** 1대 완전 장악 + 초기 침투 1개 |
| 20 | 50 | standalone 플래그 6개 중 5개 |
| 10 | 60 | standalone 플래그 전부 — 실수 하나도 안 됨 |
| 0 | — | 합격 불가 (standalone 최대가 60점) |

## 2024년 11월 변경 사항 { #nov-2024-changes }

| | 2024년 11월 1일 이전 | 지금의 OSCP+ 시험 |
|---|---|---|
| AD 세트 시작 | 초기 발판을 직접 찾아야 함 — 못 찾으면 AD 0점 | **Assumed breach**: 시작할 때 도메인 크리덴셜 제공 |
| AD 점수 | 40점 전부 아니면 0점 | 머신별 점수: 10 / 10 / 20 |
| 보너스 점수 | 랩 리포트·연습문제로 최대 10점 | **없음** |
| 버퍼 오버플로우 | 25점짜리 BOF 전용 머신은 이미 2022년에 없어짐 | 여전히 보장되지 않음 — 나와도 머신의 한 단계 정도 |
| 자격증 | OSCP (평생) | OSCP (평생) **와** OSCP+ (3년) |

OSCP+는 만료 전 6개월 안에 OSCP+ 재인증 시험에 합격하거나, 다른 해당 OffSec 자격증에 합격하거나, OffSec CPE 프로그램으로 유지합니다. 그냥 OSCP는 만료되지 않아요.

## 꼭 기억할 시험 규칙 { #exam-rules }

### 금지된 도구와 기법 { #restricted }

가이드에 나온 **금지 항목** (원문 인용):

> Spoofing (IP, ARP, DNS, NBNS, etc)
>
> Commercial tools or services (Metasploit Pro, Burp Pro, etc.)
>
> Automatic exploitation tools (e.g. db_autopwn, browser_autopwn, SQLmap, SQLninja etc.)
>
> Mass vulnerability scanners (e.g. Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT, etc.)
>
> AI Chatbots (OffSec KAI, ChatGPT, YouChat, etc.)
>
> Features in other tools that utilize either forbidden or restricted exam limitations

위 목록과 같은 일을 하는 도구도 금지입니다. 실제로는 이런 뜻이에요.

| 하고 싶은 것 | 금지 | 대신 쓸 것 |
|---|---|---|
| NetNTLMv2 해시 얻기 | Responder로 LLMNR / NBNS **포이즈닝**(스푸핑) | 대상이 나에게 접속하게 만들기 — `impacket-smbserver`, 파일이나 입력 칸에 UNC 경로 넣기 |
| SQL injection 공격 | sqlmap | 수동 인젝션 → [웹과 초기 침투](web-initial-access.md#sqli) |
| 웹 트래픽 가로채기 | Burp Pro | Burp Suite Community, 브라우저 개발자 도구 |
| 도움 받기 | ChatGPT, Claude, Gemini, OffSec KAI, 다른 사람 | 내 노트, HackTricks, GTFOBins, LOLBAS, man 페이지, 검색 엔진 |

가이드가 허용한다고 적은 예시: Nmap(NSE 포함), Nikto, Burp Free, DirBuster. 인터넷과 Discord에서 검색하는 것은 괜찮지만, 누군가에게 도움을 받는 것은 안 됩니다.

### Metasploit — 한 대에만 { #metasploit }

- Metasploit 모듈(auxiliary, exploit, post) **또는** Meterpreter 페이로드는 내가 고른 **한 대**에만 쓸 수 있습니다.
- 한 번 쓰면 그 선택은 고정됩니다. 실패해도 다른 머신으로 옮길 수 없어요.
- 여러 머신에 `check` 같은 것을 돌려 보고 고르는 것도 금지입니다.
- Metasploit으로 피벗팅 금지 (두 대 이상을 건드리게 되니까요).
- **모든 대상에서 항상 허용:** `msfvenom` 과 `exploit/multi/handler` (Meterpreter가 아닌 페이로드).
- Metasploit 기반 도구(Armitage, Cobalt Strike, Metasploit Community)에도 같은 제한이 적용됩니다.

### 리포트에 넣는 익스플로잇 코드 { #exploit-code }

- **고치지 않은 공개 익스플로잇:** URL만 적고, 코드는 붙이지 않습니다.
- **고친 익스플로잇:** 고친 코드, 원본 URL, 셸코드 / msfvenom 명령(있다면)을 넣고, **바꾼 부분을 모두 표시하고 설명**합니다.

### 그 밖의 규칙 { #other-rules }

- 대상을 공격하는 데 꼭 필요한 경우가 아니면 시험 네트워크에서 파일을 내려받지 말고, 받았다면 끝난 뒤 지웁니다.
- 머신 되돌리기(revert)는 횟수 제한이 있습니다 (컨트롤 패널에 표시). revert하면 그 머신의 모든 것, 내 셸까지 사라져요.
- 23시간 45분에 휴식·식사·수면이 모두 포함됩니다. 일시정지는 없어요. 자리를 비우기 전에 감독관 채팅으로 알립니다.
- 내 쪽 장애에 대비하세요: 두 번째 인터넷(휴대폰 핫스팟), 예비 Kali VM 스냅샷.

### 대상 점수를 잃는 경우 { #lose-points }

가이드에 따르면 아래 경우 **그 대상은 0점**입니다.

- 금지된 도구나 기법을 썼을 때
- Metasploit 모듈이나 Meterpreter를 두 대 이상에 썼을 때
- `local.txt` / `proof.txt` 를 컨트롤 패널 **과** 인터랙티브 셸 스크린샷 양쪽에 내지 않았을 때
- 따라 할 수 있을 만큼 기록하지 않았을 때

## 리포트 제출 (요약) { #submission }

자세한 내용과 체크리스트는 [리포트](reporting.md) 페이지에 있습니다.

| 항목 | 요구 사항 |
|---|---|
| 형식 | PDF 한 개를 `.7z` 압축 파일 안에; 스크립트 / PoC는 PDF 안에 텍스트로 |
| 이름 (대소문자 구분) | `OSCP-OS-XXXXX-Exam-Report.pdf` 와 `OSCP-OS-XXXXX-Exam-Report.7z` (내 OSID) |
| 비밀번호 | PDF와 압축 파일 모두 걸지 않음 |
| 크기 | 최대 200 MB |
| 어디에 / 언제 | <https://upload.offsec.com>, 실습 시간 종료 후 24시간 안에 |
| 확인 | 업로드 후 보이는 MD5를 내 파일과 비교한 뒤 **Submit File** 클릭 |

## 점수 전략 { #scoring-strategy }

**기본 계획: AD 40 + standalone 30 = 70점, 그다음 여유 점수 만들기.**

1. **standalone 하나로 몸 풀기** (2~3시간 정도로 제한). 작업 리듬을 타는 게 목적이고, 되면 10~20점을 먼저 확보합니다.
2. **머리가 맑을 때 AD 세트로.** 가장 큰 점수 덩어리이고, 사슬처럼 이어져 있어서 찾은 크리덴셜 하나하나가 다음 머신에 중요합니다.
3. AD 점수를 확보한 뒤 **남은 standalone으로 돌아가기.** 초기 침투 하나가 10점씩입니다.
4. **70이 아니라 80을 목표로.** 리포트가 플래그 하나를 증명하지 못해도 버틸 수 있게요.

**대안: AD 세트가 막혔을 때.** AD 20점(두 대)이면 standalone에서 50점, 10점이면 60점 전부가 필요합니다. AD 세트에서 오랫동안(몇 시간 동안 새 정보 없이) 막혀 있다면 standalone으로 바꿔서 딸 수 있는 것을 다 따고, 머리를 식힌 뒤 AD로 돌아갑니다.

| 12시간쯤의 상황 | 지금 점수 | 다음 행동 |
|---|---|---|
| AD 40, standalone 초기 침투 1개 | 50 | 초기 침투 2개 더, 또는 한 대 끝내기 |
| AD 20, standalone 없음 | 20 | 지금은 standalone; AD는 나중에 |
| AD 0, standalone 2대 완전 장악 | 40 | AD — 남은 30점은 세트에서 나와야 함 |

## 관련 페이지 { #related-pages }

- [시험 당일 전략](exam-day.md) · [리포트](reporting.md) · [Active Directory](active-directory.md) · [방법론과 습관](methodology.md)

## 참고 자료 { #references }

- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)
- [OffSec — OSCP Exam with AD Preparation](https://help.offsec.com/hc/en-us/articles/4547917816468-Offensive-Security-OSCP-Exam-with-AD-Preparation)
- [OffSec — OSCP exam change FAQ (2024년 11월)](https://help.offsec.com/hc/en-us/articles/29865898402836)
- [OffSec — PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements)
