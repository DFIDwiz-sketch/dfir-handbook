---
title: "권한 상승 — 일반 사용자에서 관리자까지 올라가기"
tags:
  - training
  - blue-team
  - endpoint
  - privilege-escalation
---

# 권한 상승 — 일반 사용자에서 관리자까지 올라가기 { #privilege-escalation }

!!! abstract "이 페이지에서 다루는 것"
    제대로 된 침투는 거의 다, 처음 들어온 낮은 권한 계정에서 로컬 관리자로, 다시 여러 호스트의 관리자로, 마지막엔 도메인 관리자로 <strong>사다리를 올라가야</strong> 합니다. 왜 그런지, 그리고 그 사다리 한 칸 한 칸을 어렵게 만들수록 왜 방어자가 시간을 버는지부터 봅니다. 운영체제는 원래 이걸 막도록 만들어졌는데 어떻게 권한 상승이 가능한지 — 답은 <strong>이미 권한을 가진 무언가가 대신 일하게 만드는 것</strong>입니다(관리자 사용자, SYSTEM/root로 도는 서비스나 작업, OS 특권, 소프트웨어나 커널의 버그). 그다음 두 큰 갈래를 자세히 봅니다. <strong>허술한 권한 악용</strong>(가로챈 관리자 시작 프로그램, 바꿔치기 가능한 서비스 실행 파일, 따옴표 없는 서비스 경로, DLL 검색 순서 가로채기, 수정 가능한 예약 작업, 그리고 메모리에서 도는 PowerUp 같은 자동 점검 도구)과 <strong>커널 익스플로잇</strong>(커널이 무엇인지, 커널 버그가 왜 곧바로 root인지, 공격자에게 필요한 것, Dirty Pipe 사례, 운영 서버에 컴파일러가 있으면 안 되는 이유). 모든 샘플(`icacls`, `whoami /groups`, 토큰 필드가 있는 4688, 4732, 4672, 7045, PowerShell 4104, auditd `SYSCALL`/`EXECVE`, `uname -r`)을 칸 단위로 풀어 봅니다. 끝에 확인 문제가 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 해시, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 대부분의 익스플로잇은 공격자를 <strong>낮은 권한</strong>(일반 사용자, 웹 서비스 계정)에 떨어뜨립니다. 진짜 목표 — 자격 증명 덤프, 보안 도구 끄기, 다른 호스트로 가기 — 에는 그 <strong>이상</strong>이 필요합니다. 그래서 올라갑니다. <strong>사용자 → 로컬 관리자 → 여러 호스트의 관리자 → 도메인 관리자</strong>. ATT&CK 전술 <strong>Privilege Escalation(권한 상승, TA0004)</strong>입니다.
2. 운영체제는 이걸 막도록 설계돼 있어서, 권한 상승은 거의 언제나 <strong>이미 권한을 가진 무언가가 나 대신 움직이게 만드는 것</strong>입니다. 관리자 사용자, SYSTEM이나 root로 도는 서비스·작업, OS 특권(`SeImpersonatePrivilege` 같은 것), 또는 권한 높은 코드의 버그.
3. 근본 원인은 대개 시시합니다. 필요 이상으로 넓게 열린 <strong>파일·폴더 권한</strong>과 <strong>OS 특권</strong>입니다. 일반 사용자가 <strong>관리자나 SYSTEM이 나중에 실행하는 것에 쓸 수 있다면</strong>, 익스플로잇조차 필요 없습니다.
4. Windows의 대표적인 권한 악용: <strong>관리자 시작 프로그램</strong> 바꿔치기, <strong>서비스 실행 파일</strong> 바꿔치기, 공백이 있는데 <strong>따옴표 없는 서비스 경로</strong>, <strong>DLL 검색 순서 가로채기</strong>, <strong>수정 가능한 예약 작업</strong>. ATT&CK은 대부분을 <strong>T1574 Hijack Execution Flow(실행 흐름 가로채기)</strong>로 묶습니다.
5. 공격자는 이걸 손으로 찾지 않습니다. <strong>PowerUp</strong> 같은 스크립트가 몇 초 만에 전부 점검하고, 흔히 디스크에 파일 없이 <strong>메모리에서만</strong> 돕니다. 그래서 <strong>PowerShell 스크립트 블록 로깅(4104)</strong>과 AMSI가 중요합니다.
6. 권한 높은 코드를 돌리게 되면 공격자는 보통 <strong>영구적인</strong> 발판을 만듭니다. 자기 계정을 Administrators에 넣거나(<strong>4732</strong>), 서비스를 만들거나(<strong>7045</strong>), 자격 증명 덤프 도구를 띄웁니다. 권한 상승과 지속성이 한 동작인 경우가 많습니다.
7. <strong>커널 익스플로잇</strong>(<strong>T1068</strong>)은 가장 높은 권한의 코드를 공격합니다. 커널에 알려진 버그가 있으면, 공격자는 <strong>익스플로잇 코드를 그 기계에 올려서 실행</strong>하기만 하면 곧바로 SYSTEM/root가 됩니다. 커널 패치와 운영 서버에서 <strong>컴파일러·개발 도구 제거</strong>가 세 재료 중 두 개를 없앱니다.
8. 전부에 통하는 탐지 생각: <strong>정당한 경로 없이 신원이 바뀌는 순간</strong>을 찾습니다. 조상을 따라가면 일반 사용자 프로세스가 나오는 SYSTEM/root 프로세스, 권한 높은 것이 실행하는 파일을 일반 사용자가 씀, 갑자기 관리자 그룹에 나타난 사용자.

## 공격자는 왜 올라가야 하나 { #why-climb }

### 권한 사다리 { #ladder }

출입 카드로 움직이는 사무실 건물을 떠올려 보세요. 방문자 카드는 로비와 회의실 하나만 열립니다. 직원 카드는 자기 층이 열립니다. 시설 관리 카드는 모든 층이 열립니다. 보안 책임자 카드는 카드를 찍어 내는 방까지 전부 열립니다. 방문자 카드를 훔친 도둑은 할 수 있는 게 별로 없습니다. 그래서 도둑의 계획은 통째로 "<strong>내 카드를 어떻게 업그레이드하지?</strong>"가 됩니다.

Windows 네트워크에서 그 단계는 이렇습니다.

| 단계 | 흔한 신원 | 공격자가 할 수 있게 되는 것 |
| --- | --- | --- |
| 1. 사용자 | `CORP\p.nguyen`, `IIS APPPOOL\Portal`, `www-data` | 그 사용자의 파일 읽기, 그 사용자로 프로그램 실행, 정보 탐색 |
| 2. 로컬 관리자 / SYSTEM / root | `BUILTIN\Administrators`, `NT AUTHORITY\SYSTEM`, `root` | 메모리에서 자격 증명 덤프, 백신/EDR 끄기, 드라이버·서비스 설치, 호스트의 모든 파일 읽기 |
| 3. 여러 호스트의 관리자 | 헬프데스크 그룹, 서버 관리자, 여러 PC가 같이 쓰는 로컬 관리자 비밀번호 | 수십, 수백 대로 옆으로 이동 |
| 4. 도메인 관리자 | `Domain Admins`, `Enterprise Admins` | 도메인에 가입된 모든 기계와 계정 장악, 계정 생성, 정책으로 랜섬웨어 배포 |

표가 가리는 두 가지가 있습니다.

- <strong>방어자 입장에서는 공격자가 최대한 아래 칸에서 시작해야 합니다.</strong> 모든 익스플로잇이 낮은 권한 계정에 떨어지길 바라는 겁니다. 웹 서버가 SYSTEM으로 돌거나, 사용자가 평소에 로컬 관리자로 일한다면 공격자는 <strong>2단계에서 출발</strong>하고 가장 어려운 오르막을 건너뜁니다. 그래서 서비스와 사용자의 최소 권한이 그렇게 값집니다([공격자는 뚫린 프로세스가 된다](initial-exploitation.md#becomes-the-process) 참고).
- <strong>한 칸 오를 때마다 잡을 기회가 생깁니다.</strong> 권한 상승은 평범한 사용자 활동에 비하면 시끄럽습니다. 새 그룹 가입, 이상한 프로세스 족보, 사용자 폴더에서 시작된 권한 높은 프로세스. 방어가 권한 상승을 불가능하게 만들 필요는 없습니다. <strong>느리고 눈에 띄게</strong> 만들기만 해도 이깁니다.

2 → 3 → 4단계는 보통 익스플로잇보다 <strong>훔친 자격 증명</strong>으로 올라갑니다(다음 페이지: 자격 증명 덤프). 이 페이지는 주로 <strong>한 호스트 안의 첫 오르막</strong>, 즉 사용자 → 관리자/SYSTEM/root를 다룹니다.

!!! tip "[보충] 관리자라고 다 같은 관리자가 아닙니다: UAC와 무결성 수준"
    Windows에서는 `Administrators` 그룹 구성원이라도 평소에는 <strong>걸러진 토큰(filtered token)</strong>으로, <strong>Medium(중간)</strong> 무결성 수준에서 일합니다. 관리자 권한은 <strong>UAC</strong> 창에서 허락해서 <strong>High(높음)</strong>로 올린 뒤에야 쓰입니다. 그래서 관리자 사용자의 세션에 떨어진 공격자도 흔히 한 단계가 더 필요합니다. 바로 <strong>UAC 우회</strong>(ATT&CK <strong>T1548.002</strong>, [UAC 우회](../../../adversary/uac-bypass.md) 참고)입니다. SYSTEM 프로세스는 <strong>System</strong> 무결성에서 돕니다. `whoami /groups`로 확인할 수 있습니다.

    ```
    C:\> whoami /groups | findstr Label
    Mandatory Label\Medium Mandatory Level   Label   S-1-16-8192
    ```

    - `Mandatory Label\Medium Mandatory Level` — 이 셸은 <strong>Medium</strong> 무결성으로 돕니다. 관리자 권한이 있어도 <strong>지금은 꺼져</strong> 있습니다.
    - `S-1-16-8192` — Medium을 뜻하는 SID입니다. High는 `S-1-16-12288`, System은 `S-1-16-16384`입니다.

    프로세스 생성 이벤트에서는 같은 개념이 `TokenElevationType`과 `MandatoryLabel`로 나옵니다(아래 예시). Microsoft는 지금 이 UAC 토큰 분리 방식을 <strong>관리자 보호(Administrator protection)</strong>로 바꾸는 중입니다 — 2026년 관점을 보세요.

## 권한 상승은 애초에 어떻게 가능한가 { #how }

운영체제가 하는 일이 바로 일반 사용자가 보호된 것을 못 건드리게 하는 것입니다. 그런데 어떻게 넘어갈까요? 거의 언제나 <strong>권한 있는 쪽이 대신 일하게 만드는 것</strong>입니다. 방법은 네 가지입니다.

1. <strong>권한 있는 사용자가 된다</strong> — 관리자의 비밀번호·해시·티켓을 훔치거나 맞힙니다. OS는 제대로 동작하고 있습니다. 단지 당신을 관리자라고 믿을 뿐입니다.
2. <strong>권한 있는 무언가가 내 코드를 실행하게 속인다</strong> — 관리자, 서비스, 예약 작업, 시작 프로그램이 <strong>내가 바꿀 수 있는 파일</strong>을 실행하게 만듭니다. 아래의 권한 악용 갈래입니다.
3. <strong>이미 가진 OS 특권을 악용한다</strong> — 예를 들어 서비스 계정은 보통 `SeImpersonatePrivilege`(다른 사용자를 흉내 낼 수 있는 특권)를 가지고 있고, "포테이토(potato)"류 도구가 이걸 악용해 SYSTEM 토큰을 얻습니다([토큰 가장과 포테이토 공격](../../../adversary/token-impersonation-potato.md)). Windows가 직접 준 특권을, 공격자가 의도하지 않은 방식으로 쓰는 겁니다.
4. <strong>권한 높은 코드의 버그를 익스플로잇한다</strong> — 취약한 서비스, 드라이버, 또는 커널 자체. 무언가를 확인했어야 할 코드가 확인하지 않은 겁니다.

건물에 빗대면 (1)은 책임자 카드를 훔치기, (2)는 책임자가 읽지도 않고 도장 찍는 결재함에 내 서류를 슬쩍 끼워 넣기, (3)은 청소부 마스터키를 원래 용도가 아닌 곳에 쓰기, (4)는 카드 찍는 방의 고장 난 자물쇠입니다.

권한 높은 실행을 얻으면 공격자는 무엇을 돌릴까요? 보통 셋 중 하나입니다. <strong>SYSTEM/root로 도는 백도어</strong>, <strong>비밀번호 덤프 도구</strong>, 또는 <strong>자기 계정을 관리자로 만드는 명령</strong>. 세 번째가 인기 있는 이유는 <strong>영구적</strong>이기 때문입니다. 나중에 악성코드가 발견돼 지워져도 계정은 Administrators에 남아 있고, 그냥 다시 로그인하면 됩니다.

엄밀히 보면 권한 상승도 <strong>익스플로잇</strong>이지만, 첫 단계와는 종류가 다릅니다. 최초 익스플로잇(앞 페이지)은 공격자를 <em>바깥</em>에서 <em>무언가 코드가 도는 상태</em>로 데려왔습니다. 권한 상승 익스플로잇은 공격자가 <strong>이미 그 호스트에서 코드를 돌리고 있어야</strong> 하고, <em>사용자</em>를 <em>관리자</em>로 옮겨 줍니다. 그래서 <strong>익스플로잇 이후 활동</strong>이고, 첫 경보 <em>뒤에</em> 호스트에서 무슨 일이 있었는지 볼 때 자주 발견됩니다.

## 허술한 OS 권한 악용 { #permissions }

### 핵심 아이디어: 관리자가 실행하는 것에 쓴다 { #core-idea }

가장 단순한 형태부터 봅니다. 이 갈래의 다른 기법은 모두 이것의 변형입니다.

`LT-ENG-0042`의 관리자가 작은 도구 `C:\mytools\admintool.exe`를 만들어, 예약 작업으로 부팅 때마다 <strong>SYSTEM</strong>으로 돌게 해 두었습니다. 폴더를 만들 때 권한은 신경 쓰지 않았습니다. 확인해 봅시다.

```
C:\> icacls C:\mytools
C:\mytools BUILTIN\Administrators:(OI)(CI)(F)
           NT AUTHORITY\SYSTEM:(OI)(CI)(F)
           BUILTIN\Users:(OI)(CI)(M)
           CREATOR OWNER:(OI)(CI)(IO)(F)
Successfully processed 1 files; Failed processing 0 files
```

- `icacls <경로>` — 파일이나 폴더의 접근 제어 목록(ACL, Access Control List)을 보여 줍니다. 한 줄이 <strong>누구</strong> : <strong>(상속 표시)(권한)</strong>입니다.
- `BUILTIN\Administrators:(OI)(CI)(F)` — 관리자는 <strong>F = 모든 권한(Full control)</strong>. `OI`(개체 상속)와 `CI`(컨테이너 상속)는 이 규칙이 안쪽 파일과 하위 폴더로 물려 내려간다는 뜻입니다.
- `NT AUTHORITY\SYSTEM:(OI)(CI)(F)` — SYSTEM도 모든 권한. 정상입니다.
- `BUILTIN\Users:(OI)(CI)(M)` — <strong>여기가 버그입니다.</strong> 모든 일반 사용자가 <strong>M = 수정(Modify)</strong> 권한을 가집니다. 이 폴더의 파일을 쓰고, 바꾸고, 지울 수 있고, 그 권한이 `admintool.exe`에도 물려 내려갑니다. 안전한 ACL이라면 Users에게 `(RX)` = 읽기와 실행만 줍니다.
- `CREATOR OWNER:(OI)(CI)(IO)(F)` — 파일을 만든 사람이 그 파일에 모든 권한을 가집니다. `IO`(상속 전용)는 폴더 자체가 아니라 안에 들어가는 것에만 적용된다는 뜻입니다.

이제 일반 사용자 `p.nguyen`(또는 그 사용자로 도는 악성코드)이 `admintool.exe`를 `net localgroup administrators p.nguyen /add`를 실행하는 자기 프로그램으로 바꿔 놓습니다. 당장은 아무 일도 없습니다. 덫이 놓였을 뿐입니다. 다음 부팅 때 예약 작업이 바뀐 파일을 <strong>SYSTEM으로</strong> 실행하고, `p.nguyen`은 로컬 관리자가 됩니다. 권한 체계는 한 번도 "부서지지" 않았습니다. SYSTEM이 자기 권한으로, 일반 사용자가 바꿀 수 있었던 파일을 실행했을 뿐입니다.

비유하면, 책임자가 매일 아침 결재함의 서류에 읽지도 않고 도장을 찍습니다. 누구나 결재함에 서류를 넣을 수 있다면, 누구나 무엇이든 결재받을 수 있습니다.

!!! tip "[보충] 왜 Run 키가 아니라 SYSTEM 작업과 서비스인가"
    관리자 도구가 `HKLM\…\Run` 키로 시작된다면, 로그온할 때 <strong>로그온한 그 사람으로</strong> 돌고, UAC 아래의 관리자라면 <strong>걸러진(Medium) 토큰</strong>으로 돕니다. 그래서 `net localgroup … /add`가 "Access is denied(액세스 거부)"로 실패합니다. 공격자가 <strong>SYSTEM</strong>으로 도는 것(서비스, SYSTEM이나 "가장 높은 권한으로 실행"으로 설정된 작업)을 노리는 이유이고, 방어자가 그것부터 점검해야 하는 이유입니다.

### 로그에는 이렇게 남습니다 { #permissions-evidence }

덫을 놓는 단계와 덫이 터지는 단계는 다른 시간에, 흔히 며칠 간격으로 일어납니다. 방어자는 둘 다 봐야 합니다.

<strong>1. 덫 놓기</strong> — 권한 높은 작업이 실행하는 폴더에 일반 사용자가 실행 파일을 씀. 그런 폴더에 Sysmon 파일 생성 로깅(이벤트 11)이나 개체 접근 감사(4663)가 걸려 있으면 이렇게 보입니다.

```
Event ID: 11   File created
UtcTime:         2026-11-17 14:02:51.733
Image:           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename:  C:\mytools\admintool.exe
User:            CORP\p.nguyen
```

- `Event ID 11` — Sysmon "파일 생성". 지우고 다시 만드는 방식으로 덮어쓸 때도 남습니다.
- `TargetFilename C:\mytools\admintool.exe` — SYSTEM 작업이 실행하는 바로 그 파일입니다.
- `User CORP\p.nguyen` — <strong>관리자가 아닌</strong> 사람이 썼습니다. 이 파일에 든 것은 곧 SYSTEM으로 돌게 됩니다.
- `Image … powershell.exe` — 쓴 주체가 설치 프로그램이 아니라 PowerShell입니다.

<strong>2. 덫이 터짐</strong> — 재부팅 뒤 작업이 그 파일을 SYSTEM으로 돌리고, 파일이 사용자를 Administrators에 넣습니다. 이벤트 <strong>4732 — "A member was added to a security-enabled local group(보안이 설정된 로컬 그룹에 구성원 추가)"</strong>입니다(Security 로그, *Audit Security Group Management* 필요).

```
EventID:           4732
Computer:          LT-ENG-0042.corp.example
SubjectUserName:   LT-ENG-0042$
SubjectDomainName: CORP
SubjectLogonId:    0x3E7
MemberSid:         S-1-5-21-1111111111-2222222222-3333333333-1604
TargetUserName:    Administrators
TargetDomainName:  Builtin
```

- `EventID 4732` — 누군가 <strong>로컬</strong> 그룹에 추가됐습니다(도메인 글로벌 그룹은 4728, 유니버설 그룹은 4756). Administrators 구성원 자격은 재부팅에도, 악성코드 정리에도 살아남기 때문에 공격자에게 중요합니다.
- `SubjectUserName LT-ENG-0042$`와 `SubjectLogonId 0x3E7` — <strong>누가 추가했나</strong>: 컴퓨터 계정, 로그온 ID `0x3E7` = <strong>SYSTEM</strong>입니다. 사람 관리자가 추가했다면 대화형이나 원격 세션에서 이름으로 나왔을 겁니다. 부팅 직후 <strong>SYSTEM이 사용자를 Administrators에 넣는 것</strong>은 서비스나 작업이 가로채였다는 강한 신호입니다.
- `MemberSid …-1604` — 추가된 계정입니다(이름으로 바꾸면 `p.nguyen`). 이 이벤트는 이름이 아니라 SID를 보여 줍니다.
- `TargetUserName Administrators` — 대상 그룹.

<strong>3. 프로세스</strong> — 그 명령에 대한 4688과 토큰 필드:

```
EventID:            4688
Computer:           LT-ENG-0042.corp.example
SubjectUserName:    LT-ENG-0042$
SubjectLogonId:     0x3E7
NewProcessName:     C:\Windows\System32\net.exe
CommandLine:        net localgroup administrators p.nguyen /add
ParentProcessName:  C:\mytools\admintool.exe
TokenElevationType: %%1936
MandatoryLabel:     S-1-16-16384
```

- `ParentProcessName C:\mytools\admintool.exe` — (이제는 바뀐) 관리자 도구가 `net.exe`를 띄웠습니다. 진짜 도구는 이런 일을 한 적이 없을 겁니다. 이전 부팅 기록과 비교해 보세요.
- `TokenElevationType %%1936` — <strong>유형 1, 완전한 토큰</strong>(UAC 분리 없음, SYSTEM과 서비스에서 흔함). `%%1937` = 유형 2 상승됨, `%%1938` = 유형 3 제한됨(걸러짐).
- `MandatoryLabel S-1-16-16384` — <strong>System</strong> 무결성.

모아 보면 *일반 사용자가 파일을 씀 → 며칠 뒤 SYSTEM이 그 파일을 실행 → SYSTEM이 그 일반 사용자를 Administrators에 넣음*입니다. 이벤트 하나씩은 그럴듯하게 설명될 수 있어도, 이 사슬은 설명되지 않습니다.

### 흔한 변형들 { #variations }

전부 "권한 높은 무언가가 내가 쥔 코드를 돌리게 만들기"이고, 다른 건 <strong>무엇이</strong> 쓰기 가능하냐뿐입니다. ATT&CK ID는 현재 Enterprise 기준입니다.

| 기법 | 무엇이 허술한가 | 공격자가 하는 일 | ATT&CK |
| --- | --- | --- | --- |
| 관리자 시작 프로그램 가로채기 | 관리자나 SYSTEM이 부팅·로그온 때 돌리는 파일/폴더가 쓰기 가능 | 파일 바꿔치기 | T1574(갈래), T1547 |
| 수정 가능한 서비스 실행 파일 | 사용자가 서비스의 `.exe`에 쓸 수 있음 | 바꿔치기 후 재시작이나 재부팅 대기 | T1574.010 Services File Permissions Weakness |
| 수정 가능한 서비스 설정 | 사용자가 서비스의 레지스트리 키·설정을 바꿀 수 있음 | `ImagePath`를 자기 프로그램으로 바꿈 | T1574.011 Services Registry Permissions Weakness |
| 따옴표 없는 서비스 경로 | 공백이 있고 따옴표가 없으며, 중간 폴더가 쓰기 가능 | Windows가 먼저 찾는 위치에 EXE를 놓음 | T1574.009 Path Interception by Unquoted Path |
| DLL 검색 순서 가로채기 | 권한 높은 프로그램이 사용자가 쓸 수 있는 폴더에서 DLL을 이름만으로 불러옴 | 그 이름의 악성 DLL을 놓음 | T1574.001 DLL |
| 수정 가능한 예약 작업 | SYSTEM 작업이 사용자가 쓸 수 있는 스크립트/EXE를 돌림(또는 작업 정의 자체가 쓰기 가능) | 스크립트 수정 | T1053.005, T1574 |
| 리눅스: SUID 바이너리, `sudo` 규칙, 쓰기 가능한 root cron 스크립트 | 너무 후한 SUID 비트나 `sudo` 항목, 사용자가 쓸 수 있는 파일을 돌리는 root 작업 | SUID/`sudo` 프로그램을 의도 밖으로 쓰기, 스크립트 수정 | T1548.001 Setuid and Setgid, T1548.003 Sudo and Sudo Caching, T1053.003 |

이 중 둘은 원리가 덜 뻔해서 더 자세히 봅니다.

#### 따옴표 없는 서비스 경로 { #unquoted }

어떤 서비스가 이런 실행 경로로 등록돼 있다고 합시다. <strong>따옴표가 없습니다.</strong>

```
C:\Apps\Acme Backup\bin\agent.exe -svc
```

공백 때문에 Windows는 프로그램 이름이 어디서 끝나고 인수가 어디서 시작하는지 모릅니다. 그래서 가능한 해석을 <strong>순서대로</strong> 시도합니다.

1. `C:\Apps\Acme.exe` (인수는 `Backup\bin\agent.exe -svc`)
2. `C:\Apps\Acme Backup\bin\agent.exe` (인수는 `-svc`) ← 원래 의도한 것

일반 사용자가 `C:\Apps\`에 쓸 수 있다면 `C:\Apps\Acme.exe`를 놓을 수 있고, 다음에 서비스가 시작될 때 Windows는 <strong>그 사람의</strong> 파일을 서비스 계정(흔히 LocalSystem)으로 실행합니다. 따옴표가 있으면(`"C:\Apps\Acme Backup\bin\agent.exe" -svc`) 헷갈릴 일이 없고, 공격도 없습니다.

조건을 꼭 보세요. 공격자는 <strong>앞쪽 폴더 중 하나에 쓰기 권한</strong>이 있어야 합니다. `C:\Program Files\` 아래는 일반 사용자가 쓸 수 없어서, 거기의 따옴표 없는 경로는 나쁜 습관이지만 대개 악용은 안 됩니다. 진짜 문제는 `C:\` 바로 아래 만든 폴더(`C:\Apps`, `C:\Tools` 같은 곳)입니다. 이런 폴더는 `C:\`에서 <strong>Users: 쓰기/만들기</strong> 권한을 물려받는 경우가 많습니다.

위험한 서비스를 찾는 방어자용 점검:

```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match '^[^"]*\s.*\.exe' } |
  Select-Object Name, StartName, StartMode, PathName
```

1. `Get-CimInstance Win32_Service` — 모든 서비스와 속성을 가져옵니다(`wmic service`의 현대판).
2. `$_.PathName -notmatch '^"'` — 경로가 따옴표로 시작하지 <strong>않고</strong>…
3. `-match '^[^"]*\s.*\.exe'` — …<strong>`.exe` 앞에 공백</strong>이 있는 것, 즉 공백 있는데 따옴표 없는 경우만 남깁니다.
4. `Select-Object …` — 서비스 이름, 실행 계정, 시작 방식, 경로를 보여 줍니다.

출력:

```
Name        StartName    StartMode PathName
----        ---------    --------- --------
AcmeBackup  LocalSystem  Auto      C:\Apps\Acme Backup\bin\agent.exe -svc
```

`LocalSystem` + `Auto` + `C:\Apps` 아래의 따옴표 없는 경로 = 바로 `icacls C:\Apps`를 확인합니다. `BUILTIN\Users`에 `(W)`, `(M)`, `(AD)`(하위 폴더·파일 추가)가 있으면 ACL을 고치고 따옴표를 붙입니다.

#### DLL 검색 순서 가로채기 { #dll-hijack }

프로그램은 도우미 라이브러리(DLL)를 불러옵니다. 프로그램이 DLL을 전체 경로가 아니라 <strong>이름만으로</strong> 요청하면(`LoadLibrary("helper.dll")`) Windows는 정해진 위치 목록을 뒤지는데, <strong>프로그램 자기 폴더가 가장 먼저</strong>입니다. 권한 높은 프로그램이 일반 사용자가 쓸 수 있는 폴더에 있거나 거기서 시작된다면, 공격자가 그 폴더에 `helper.dll`을 놓아 두는 것만으로 그 DLL이 <strong>권한 높은 프로세스 안에서</strong> 불려 옵니다. 새 프로세스는 생기지 않습니다. 악성 코드가 믿을 만한 프로그램의 모습으로 돌기 때문에 은신 기법이기도 합니다.

증거는 <strong>Sysmon 7(이미지 로드)</strong>입니다. 사용자가 쓸 수 있는 낯선 경로에서, 흔히 서명 없이 불려 온 DLL:

```
Event ID: 7   Image loaded
Image:           C:\Apps\Acme Backup\bin\agent.exe
ImageLoaded:     C:\Apps\Acme Backup\bin\version.dll
Signed:          false
SignatureStatus: Unavailable
User:            NT AUTHORITY\SYSTEM
```

- `Image` — DLL을 불러온 프로세스, `SYSTEM`으로 돕니다.
- `ImageLoaded … version.dll` — `version.dll`은 원래 `System32`에 있는 진짜 Windows DLL입니다. 그 복사본이 <strong>프로그램 옆에</strong> 있는 것이 전형적인 가로채기 모양입니다.
- `Signed false` — 진짜는 Microsoft 서명이 있습니다. 앱 폴더에 있는, 서명 없는 "시스템 DLL 이름"은 강한 신호입니다.

(ATT&CK v17에서 옛 *DLL Side-Loading* 하위 기법이 <strong>T1574.001</strong>로 합쳐졌고 이름이 그냥 <strong>DLL</strong>이 됐습니다. 그래서 T1574.002로 태그된 옛 규칙은 다시 매핑해야 합니다.)

### 자동 점검 도구: PowerUp과 친구들 { #powerup }

공격자는 ACL을 손으로 보지 않습니다. 오픈소스 <strong>PowerSploit</strong> 프레임워크에 들어 있는 PowerShell 스크립트 <strong>PowerUp</strong>은 위의 거의 모든 것을 몇 초 만에 점검합니다. 수정 가능한 서비스 실행 파일과 레지스트리 키, 따옴표 없는 경로, `PATH`의 쓰기 가능한 폴더, DLL 가로채기 기회, 수정 가능한 작업, 흔한 파일에 저장된 자격 증명 등. 찾은 것을 <strong>악용</strong>하는 기능도 있습니다. 다른 플랫폼에도 비슷한 도구가 있습니다(WinPEAS/LinPEAS류 스크립트, 컴파일된 C# 점검 도구).

이게 잘 안 보이는 이유: <strong>순수 PowerShell</strong>이고 보통 <strong>메모리에 바로 올라옵니다</strong>(다운로드 크래들, [PowerShell 크래들](../../../adversary/powershell-cradles.md) 참고). 그래서 백신이 검사할 파일이 디스크에 하나도 생기지 않습니다. 대신 이건 <em>보입니다</em>.

- <strong>PowerShell 스크립트 블록 로깅 — 이벤트 4104</strong>(`Microsoft-Windows-PowerShell/Operational`). PowerShell은 메모리에서 왔더라도 자기가 컴파일하는 스크립트 텍스트를 기록하고, 전체 로깅이 꺼져 있어도 수상하다고 판단한 블록은 자동으로 기록합니다.
- <strong>AMSI</strong>(Antimalware Scan Interface, 백신 검사 인터페이스) — Defender나 EDR이 실행 순간에 스크립트 내용을 검사하게 해 줍니다.

방어자가 볼 수 있는 4104 기록:

```
Log Name:       Microsoft-Windows-PowerShell/Operational
Event ID:       4104
Level:          Warning
Computer:       LT-ENG-0042.corp.example
User:           CORP\p.nguyen
Message:        Creating Scriptblock text (1 of 7):
                function Get-ModifiableServiceFile {
                ...
                function Invoke-AllChecks {
                ...
ScriptBlock ID: 6b0e2c4a-91d3-4f6e-9a1b-0c55d2e7a301
Path:
```

- `Event ID 4104` — "스크립트 블록 생성": 실행되는 PowerShell 코드의 본문입니다.
- `Level Warning` — PowerShell 스스로 이 블록을 <strong>수상하다</strong>고 표시했습니다(자동 로깅).
- `(1 of 7)` — 큰 스크립트가 이벤트 일곱 개로 나뉘었습니다. `ScriptBlock ID`로 이어 붙입니다.
- `Get-ModifiableServiceFile` / `Invoke-AllChecks` 같은 함수 이름 — 잘 알려진 권한 상승 점검 함수입니다. 공격자는 이름을 바꾸기도 하니 이름에만 기대지 말고, 한 스크립트 블록 안에 ACL·서비스 조회가 잔뜩 들어 있는지도 보세요.
- `Path:` 비어 있음 — 스크립트가 파일에서 오지 <strong>않았습니다</strong>. 메모리나 명령줄에서 왔습니다.

하지만 이 갈래 전체에 대한 방어자의 최고 대응은 탐지가 아니라 <strong>같은 점검을 먼저 해 두는 것</strong>입니다. 취약점 관리나 정기 감사에서 우리 표준 이미지에 PowerUp류 점검을 돌려 두면, 공격자가 와도 찾을 게 없습니다.

## 커널 익스플로잇 { #kernel }

### 커널이 최종 목표인 이유 { #kernel-why }

<strong>커널(kernel)</strong>은 운영체제의 심장입니다. 프로세스 순서를 정하고, 메모리를 관리하고, 드라이버·하드웨어와 이야기하고, <strong>누가 무엇을 해도 되는지 결정합니다</strong>. 이 페이지의 모든 권한 확인은 결국 커널 코드가 집행합니다. 그래도 커널 코드 역시 사람이 쓴 코드라 버그가 있습니다.

공격자가 <strong>커널 안에서</strong> 자기 코드를 돌리게 해 주는(또는 자기 프로세스의 신원 정보 같은 커널 메모리를 바꾸게 해 주는) 버그를 찾으면, 모든 권한 확인이 의미를 잃습니다. "이 프로세스는 사용자 1001의 것"을 "이 프로세스는 root의 것"으로 그냥 고쳐 쓰면 되니까요. 공격자 입장에서는 마술 같습니다. 프로그램 하나 돌렸더니 root 셸. ATT&CK: <strong>T1068 Exploitation for Privilege Escalation(권한 상승을 위한 익스플로잇)</strong>.

건물로 돌아가면, 출입 카드를 가진 사람을 속이는 대신 지하의 출입 통제 장치를 고장 내서 모든 문이 모든 카드에 열리게 만드는 것입니다.

### 공격자에게 필요한 것 { #kernel-needs }

가장 흔한 경우인 <strong>로컬 권한 상승(local privilege escalation)</strong>에는 재료가 세 개뿐입니다.

1. <strong>취약한 커널</strong> — 알려졌는데 패치 안 된 버그가 있는 버전. 확인도 쉽습니다. 리눅스는 `uname -r`, Windows는 `systeminfo`나 빌드 번호.
2. <strong>그 기계에 익스플로잇 코드</strong> — 완성된 바이너리로 내려받거나, 컴파일러(`gcc`, `make`)가 깔려 있으면 <strong>그 자리에서 컴파일</strong>.
3. <strong>실행할 수 있는 능력</strong> — 아무 사용자의 아무 셸이면 됩니다.

그러니 방어도 뻔합니다. <strong>커널 패치</strong>(1번 제거), <strong>운영 서버에서 컴파일러와 개발 도구 제거</strong>와 실행 파일 다운로드 차단(2번을 어렵게), <strong>애플리케이션 제어 / `/tmp` 같은 쓰기 가능한 마운트에 `noexec`</strong>(3번을 어렵게). 웹 서버에서 `gcc`를 지운다고 미리 컴파일된 바이너리를 가져오는 공격자를 막지는 못하지만, 가장 쉬운 길을 없애고 내려받는 소음을 내게 만듭니다.

### 사례: Dirty Pipe (CVE-2022-0847) { #dirty-pipe }

2022년 3월에 공개된 Dirty Pipe는 리눅스 커널이 <strong>파이프 버퍼(pipe buffer)</strong>와 페이지 캐시(page cache, 커널이 메모리에 들고 있는 파일 사본)를 함께 다루는 방식의 버그였습니다. 제대로 지워지지 않은 플래그 하나 때문에, 일반 사용자가 <strong>읽기만 허락된 파일의 캐시 사본에</strong> 커널이 데이터를 쓰게 만들 수 있었습니다. root 소유 파일, 심지어 읽기 전용 파일까지요. 캐시에서 SUID-root 프로그램이나 root 소유 설정 파일 일부를 덮어쓰면, 다음에 그게 실행되거나 읽힐 때 공격자가 원하는 대로 움직입니다. 즉 root 셸입니다. <strong>5.8</strong>부터의 커널이 영향을 받았고 <strong>5.16.11, 5.15.25, 5.10.102</strong>에서 고쳐졌습니다(그 커널을 쓰는 안드로이드 기기도 영향받았습니다).

리눅스 호스트에서 방어자가 가장 먼저 보는 것:

```
$ uname -r
5.13.0-27-generic
```

- `uname -r` — 지금 돌고 있는 커널 릴리스를 출력합니다.
- `5.13.0-27-generic` — 5.13 커널입니다. 5.8과 수정 버전 사이에 있고, 5.13은 자기 번호로 수정을 받은 장기 지원 갈래가 아니었으므로 겉보기에는 Dirty Pipe에 <strong>취약</strong>합니다. 다만 배포판 커널은 수정을 자기 버전 번호로 백포트(back-port)하므로, 업스트림 번호만 보지 말고 늘 <strong>배포판 보안 권고</strong>와 대조하세요.

커널 권한 상승이 <strong>auditd</strong>에 어떻게 보이는지 봅시다(auditd 자세한 내용은 뒤의 프로세스 생성 페이지에서 다룹니다). 핵심은 <strong>`auid`(감사/로그인 사용자 ID)</strong>입니다. 로그인할 때 정해지고, 프로세스가 root가 돼도 <strong>바뀌지 않습니다</strong>. 그래서 일반 사용자의 `auid`를 가진 root 프로세스가 `sudo`/`su`를 거치지 <strong>않고</strong> 생겼다면 그게 지문입니다.

```
type=SYSCALL msg=audit(1795153445.120:4182): arch=c000003e syscall=59 success=yes exit=0 ppid=24410 pid=24477 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=12 comm="sh" exe="/usr/bin/dash" key="exec"
type=EXECVE msg=audit(1795153445.120:4182): argc=1 a0="/bin/sh"
type=PROCTITLE msg=audit(1795153445.120:4182): proctitle="/bin/sh"
```

- `msg=audit(1795153445.120:4182)` — 에포크 시간(2026-11-20 05:44:05 UTC)과 기록 번호. 세 줄이 같은 값을 가지므로 <strong>한 사건</strong>을 설명합니다.
- `syscall=59` — x86-64(`arch=c000003e`)에서 59는 `execve`, 즉 <strong>프로그램이 시작됐다</strong>는 뜻입니다.
- `ppid=24410 pid=24477` — 부모와 새 프로세스 ID. 다음엔 24410을 찾아봅니다.
- `auid=1001` — <strong>로그인한</strong> 사람은 사용자 1001(예: `d.okafor`)인데…
- `uid=0 euid=0 …` — …이 프로세스는 모든 ID 칸에서 <strong>root</strong>로 돕니다.
- `tty=pts1 ses=12` — 대화형 터미널 세션.
- `exe="/usr/bin/dash"`, `EXECVE a0="/bin/sh"` — root 셸입니다.

이제 부모:

```
type=SYSCALL msg=audit(1795153444.871:4179): arch=c000003e syscall=59 success=yes exit=0 ppid=24301 pid=24410 auid=1001 uid=1001 gid=1001 euid=1001 tty=pts1 ses=12 comm="dp" exe="/tmp/.cache/dp" key="exec"
```

- `uid=1001 euid=1001` — 부모는 일반 사용자로 돌았습니다.
- `exe="/tmp/.cache/dp"` — <strong>`/tmp`의 숨김 폴더</strong>에 있는 프로그램을 사용자가 실행했습니다.
- 0.25초 뒤 그 자식이 root이고, `/var/log/auth.log`나 저널에 <strong>`sudo` 기록이 없습니다</strong>. `/tmp`의 일반 사용자 프로그램, 그 자식이 갑자기 root, 그런데 `sudo`/`su`/아는 SUID 프로그램이 없음 — 이게 커널 익스플로잇의 전형적인 그림입니다. 리눅스용 EDR은 바로 이 "<strong>예상치 못한 UID 전환</strong>"에 경보를 냅니다.

!!! tip "[보충] Windows 쪽 커널 권한 상승"
    Windows에서도 같은 생각이 커널(`ntoskrnl.exe`, `win32k.sys`)이나 커널 드라이버를 노리는 익스플로잇으로 나타납니다. 예를 들어 CLFS(Common Log File System) 드라이버 버그 <strong>CVE-2025-29824</strong>는 2025년에 랜섬웨어 운영자들이 제로데이로 악용했습니다. 흔한 지름길은 <strong>BYOVD(Bring Your Own Vulnerable Driver, 취약 드라이버 직접 가져오기)</strong>입니다. 정상 서명은 있지만 <strong>버그 있는</strong> 드라이버를 설치하고 그걸 익스플로잇해 커널 접근을 얻는 방법으로, 흔히 EDR을 죽이는 데 씁니다. 증거: `Service Type: kernel mode driver`인 <strong>7045</strong>, 낯선 이름이나 경로의 <strong>Sysmon 6(드라이버 로드)</strong>, 그리고 <strong>취약 드라이버 차단 목록</strong>이 막은 기록. 결과로 생긴 SYSTEM 프로세스의 조상에는 보통 사용자 프로세스가 있습니다. 똑같이 "정당한 경로 없이 신원이 바뀜"입니다.

## 권한 상승 탐지: 한 가지 원칙 { #detect }

| 신호 | 어디서 보나 |
| --- | --- |
| SYSTEM/root가 실행하는 폴더에 일반 사용자가 EXE/DLL/스크립트를 씀 | Sysmon 11, 감사 걸린 폴더의 4663, FIM, auditd 파일 감시 |
| SYSTEM/LocalSystem이 계정을 관리자 그룹에 넣음 | Subject = 컴퓨터 계정 / `0x3E7`인 4732 / 4728 / 4756 |
| 새 서비스나 드라이버, 특히 쓰기 가능한 경로에서 | 7045 / 4697, Sysmon 6 |
| 시스템 이름의 DLL이 앱·사용자 폴더에서 로드됨 | Sysmon 7 |
| PowerShell 권한 상승 점검 도구 | 4104(흔히 `Warning` 수준), AMSI/EDR 경보 |
| 조상이 사용자 프로세스인 SYSTEM/root 프로세스(`sudo`, `su`, UAC 동의, 알려진 서비스 경로 없음) | 4688/Sysmon 1 족보, auditd `auid` ≠ `uid`, EDR |
| 가지면 안 되는 로그온에 특수 권한이 할당됨 | 관리자가 아닌 계정에 대한 <strong>4672</strong> "Special privileges assigned to new logon(새 로그온에 특수 권한 할당)" |

공통점은 하나입니다. <strong>신원이 바뀌었는데, 그걸 설명할 정당한 경로가 없다.</strong> 헬프데스크를 통해 관리자가 된 사용자는 티켓과 4732에 관리자 이름을 남깁니다. 가로챈 작업으로 관리자가 된 사용자는 4732에 SYSTEM의 이름을, 며칠 전에는 그 사용자의 파일 쓰기를 남깁니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    사다리(사용자 → 로컬 관리자 → 여러 호스트 → 도메인)는 지금도 거의 모든 사람이 직접 하는 침투와 랜섬웨어 사례를 설명합니다. 허술한 파일·서비스 권한, 따옴표 없는 경로, DLL 가로채기, 수정 가능한 작업은 실제 기업 표준 이미지에서 여전히 발견됩니다. 특히 `Program Files` 밖에 설치된 서드파티·자체 개발 소프트웨어에서요. 커널·드라이버 익스플로잇도 여전히 주요 경로입니다. 리눅스 <strong>CVE-2024-1086</strong>(nf_tables)은 CISA의 실제 악용 취약점 목록(KEV)에 올랐고, 나중에 랜섬웨어 공격에 쓰인 것으로 표시됐습니다. Windows 커널 드라이버 제로데이도 정기 보안 업데이트(Patch Tuesday)마다 계속 나옵니다. "커널 패치, 컴파일러 제거, 최소 권한, 점검 도구를 먼저 돌려 보기"는 지금도 맞는 조언입니다.

!!! info "[변경됨] 바뀐 점"
    - <strong>관리자 보호가 UAC 토큰 분리를 대체합니다.</strong> Windows 11에 <em>관리자 보호(Administrator protection)</em>가 들어왔습니다. 관리자도 평소에는 관리자 권한 없이 일하고, 권한 상승은 Windows Hello 인증을 거친 뒤에만 <strong>따로 분리된, 숨겨진, 일시적인 관리자 토큰</strong>을 만듭니다. 그래서 고전적인 UAC 우회 수법 상당수가 막힙니다. 모든 PC에서 기본으로 켜져 있지는 않고, <strong>Windows 11 26H2 보안 기준(2026년 10월)</strong>이 관리되는 기기에서 이걸 켭니다. 배포된 곳에서는 UAC 우회가 줄어들 것으로 보이고, 호환성 문제도 미리 계획해야 합니다.
    - <strong>취약 드라이버 차단 목록 기본 켜짐</strong>: Windows 11(22H2부터)에서 기본으로 켜져 있고, 새 기기 상당수는 HVCI/메모리 무결성도 기본으로 켜져 있습니다. BYOVD가 어려워졌지만, 이게 꺼져 있거나 그 드라이버가 아직 목록에 없는 곳에서는 여전히 흔합니다.
    - <strong>PowerSploit은 유지 보수가 끝났습니다.</strong> 프로젝트는 몇 년째 보관(archived) 상태입니다. PowerUp은 아직 동작하고 아직 보이지만, 공격자는 점점 유지 보수되는 도구나 컴파일된 점검 도구(메모리에서 도는 C# 어셈블리, WinPEAS/LinPEAS류)를 씁니다. PowerUp 함수 이름에만 기댄 탐지는 약합니다.
    - <strong>ATT&CK 변경.</strong> <strong>T1574.002 DLL Side-Loading</strong>은 <strong>T1574.001(지금 이름 "DLL")</strong>에 합쳐졌습니다. v19(2026년 4월)에서 Defense Evasion 전술이 <strong>Stealth(TA0005)</strong>와 <strong>Defense Impairment(TA0112)</strong>로 나뉘어서, 여러 전술에 걸친 실행 흐름 가로채기 기법은 이제 "Defense Evasion" 대신 Stealth 아래에 나옵니다. T1068과 T1548은 바뀌지 않았습니다.
    - <strong>신원과 클라우드 쪽 권한 상승.</strong> 하이브리드 환경에서는 "권한 상승"의 상당 부분이 이제 신원 공급자(IdP) 안에서 일어납니다. 역할 할당, 앱 권한, 잘못 설정된 인증서 템플릿([AD CS 악용](../../../adversary/adcs-abuse.md))을 악용하는 방식으로, 호스트 익스플로잇이 전혀 없습니다.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - <strong>로컬 권한 상승 버그를 "인터넷에서 못 뚫으니 낮은 우선순위"로 보지 마세요.</strong> 랜섬웨어 조직은 첫 발판에 알려진 LPE를 몇 시간 안에 이어 붙입니다. CISA KEV에 오른 LPE는 원격 버그만큼 급합니다.
    - <strong>업스트림 커널 버전 번호만 믿지 마세요.</strong> 배포판은 수정을 백포트합니다. 호스트가 취약하다/안전하다 말하기 전에 공급사 권고(또는 라이브 패치 상태)를 확인하세요.
    - <strong>운영 환경에서 변경 관리 없이 PowerUp류 도구를 돌리지 마세요.</strong> 악용 기능을 쓰면 일부 점검이 서비스를 <em>바꾸거나</em> 파일을 씁니다. 읽기 전용 감사 모드나 공급사 도구를 쓰세요.
    - <strong>"편하니까" 사용자를 로컬 관리자로 일하게 하지 마세요.</strong> 로컬 관리자 비밀번호 하나를 여러 기계가 같이 쓰게 하지도 마세요. LAPS(지금은 Windows에 기본 내장)를 써서, 훔친 로컬 관리자 하나가 사다리 3단계가 되지 않게 하세요.
    - <strong>`auid` 칸을 잊지 마세요.</strong> 리눅스 탐지 상당수가 `uid=0`만 보는데, 거기엔 정상 root 활동이 가득합니다. `sudo` 없이 `auid` ≠ `uid`인 것이 쓸모 있는 신호입니다.

## 확인 문제 { #quiz }

### 문제 1

`LT-ENG-0042`에서 월요일 08:01에 4732 이벤트가 보입니다. `SubjectUserName = LT-ENG-0042$`, `SubjectLogonId = 0x3E7`, `TargetUserName = Administrators`, `MemberSid`를 이름으로 바꾸면 `CORP\p.nguyen`. 헬프데스크 티켓은 없습니다. 가장 그럴듯한 일은 무엇이고, 어떤 이벤트를 더 찾아보겠으며, 무엇을 고쳐야 할까요?

??? success "정답과 해설"
    `0x3E7`과 컴퓨터 계정은 사람 관리자가 아니라 <strong>SYSTEM</strong>이 바꿨다는 뜻입니다. 월요일 아침 부팅 직후, 티켓도 없이 SYSTEM이 일반 사용자를 Administrators에 넣었다면 <strong>사용자가 바꿀 수 있는 코드를 돌리는 권한 높은 무언가를 통한 권한 상승</strong>을 가리킵니다. 가로챈 서비스 실행 파일, 예약 작업, 따옴표 없는 서비스 경로, DLL(T1574 갈래 / T1053.005).

    찾아볼 것: `net.exe … /add`(또는 `Add-LocalGroupMember`)의 <strong>4688/Sysmon 1</strong>과 그 <strong>부모</strong> — 어느 서비스·작업이 페이로드를 돌렸는지 알려 줍니다. 그 전에 `p.nguyen`이 그 부모 파일을 쓴 <strong>Sysmon 11 / 4663</strong>. 새 서비스나 작업이 만들어졌을 경우를 대비해 <strong>7045/4697/4698</strong>. 덫을 놓기 전에 `p.nguyen`이 돌린 권한 상승 점검 스크립트의 <strong>4104</strong>. 그리고 그 뒤 `p.nguyen`이 새 권한으로 한 로그온과 활동(보통 다음은 자격 증명 덤프입니다).

    고칠 것: 사용자를 Administrators에서 빼고, 원래 실행 파일을 복원하고, <strong>ACL을 고치고</strong>(Users는 읽기·실행만), 서비스 경로에 따옴표를 붙이고, 같은 방식으로 만든 다른 호스트를 훑고, `p.nguyen` 계정과 그 호스트의 자격 증명을 뚫린 것으로 다룹니다.

### 문제 2

한 서비스는 `LocalSystem`으로 `C:\Program Files\Contoso Sync\syncsvc.exe`(따옴표 없음) 경로에서 돕니다. 다른 서비스는 `LocalSystem`으로 `C:\Tools\Fleet Agent\agent.exe`(따옴표 없음)에서 돌고, `icacls C:\Tools`는 `BUILTIN\Users:(OI)(CI)(M)`을 보여 줍니다. 실제로 악용 가능한 건 어느 쪽이고, 어떻게, 그리고 어떻게 고치나요?

??? success "정답과 해설"
    둘 다 <strong>공백이 있는데 따옴표 없는 경로</strong>라서 Windows가 앞쪽 해석을 먼저 시도합니다(`C:\Program.exe`, `C:\Program Files\Contoso.exe` / `C:\Tools\Fleet.exe`). 하지만 공격은 일반 사용자가 그 앞쪽 위치 중 하나에 <strong>쓸 수 있을 때만</strong> 통합니다. 기본적으로 일반 사용자는 `C:\`나 `C:\Program Files\`에 쓸 수 없으니, 첫 번째 서비스는 <strong>나쁜 습관이지만 대개 악용은 안 됩니다</strong>. `C:\Tools`는 <strong>Users: 수정</strong>을 주므로 사용자가 `C:\Tools\Fleet.exe`를 놓을 수 있고, 다음 서비스 시작 때 Windows가 그걸 <strong>LocalSystem으로</strong> 실행합니다(T1574.009). 이쪽이 살아 있는 권한 상승 경로입니다.

    고치기: 두 서비스 경로 모두(서비스의 `ImagePath`에) <strong>따옴표</strong>를 붙이고, `C:\Tools` ACL을 Users 읽기·실행으로 고칩니다(또는 에이전트를 `Program Files` 아래로 옮깁니다). 그다음 `C:\Tools`에 이미 `Fleet.exe`가 있는지, 그게 돌았다는 7036/7045, 4688 이벤트가 있는지 확인합니다.

### 문제 3

리눅스 웹 서버의 auditd에 `exe="/tmp/.cache/dp"`, `auid=1001 uid=1001`인 프로세스가 있고, 0.3초 뒤 그 자식 `/bin/sh`가 `auid=1001 uid=0 euid=0`입니다. 그 시간에 `sudo`나 `su` 기록은 없습니다. `uname -r`은 `5.13.0-27-generic`입니다. 무슨 일이 일어났을 가능성이 크고, 무엇을 하겠습니까?

??? success "정답과 해설"
    `auid`(로그인 사용자)는 두 기록 모두 1001인데, 자식이 갑자기 <strong>root</strong>로 돕니다. 그 변화를 설명할 정당한 경로(`sudo`, `su`, 아는 SUID 프로그램)가 없습니다. 부모는 숨긴 `/tmp` 폴더의 정체불명 바이너리입니다. 여기에 <strong>Dirty Pipe(CVE-2022-0847)</strong>나 다른 알려진 커널 버그의 영향 범위에 드는 커널 버전까지 더하면, <strong>권한 상승을 위한 커널 익스플로잇(T1068)</strong>의 전형적인 그림입니다. 이미 사용자 1001로 돌던 공격자(아마 웹 애플리케이션을 통해)가 익스플로잇을 돌려 root 셸을 얻었습니다.

    조치: 서버를 <strong>root 수준까지 완전히 뚫린 것</strong>으로 다룹니다(root는 파일을 숨기고, 루트킷을 깔고, 로그를 조작할 수 있어서 호스트 안의 증거가 불완전할 수 있습니다). 격리하고, 메모리와 `/tmp/.cache/dp` 바이너리를 수집하고, 사용자 1001이 어떻게 셸을 얻었는지 밝힙니다(웹 로그, 앞쪽 프로세스 나무). <strong>패치된 커널</strong>(배포판 권고로 확인)로 깨끗한 이미지에서 다시 만들고, 컴파일러를 지우고 `/tmp`를 `noexec`로 마운트하고, 그 서버의 비밀 값을 모두 바꾸고, 같은 커널을 쓰는 다른 서버를 사냥합니다.

## 관련 레퍼런스 { #related }

- [실행, 지속성, 정보 탐색](execution-persistence-discovery.md) — 이 단계 바로 앞 · [최초 침투](initial-exploitation.md)
- [UAC 우회](../../../adversary/uac-bypass.md) · [토큰 가장과 포테이토 공격](../../../adversary/token-impersonation-potato.md) · [PrintNightmare](../../../adversary/printnightmare.md)
- [PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md) · [지속성](../../../adversary/persistence.md) · [AD CS 악용](../../../adversary/adcs-abuse.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md) · [리눅스 명령](../../../basics/linux-commands.md)
