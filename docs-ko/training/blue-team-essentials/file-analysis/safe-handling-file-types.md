---
title: "의심 파일 안전하게 다루기 — 분석 환경, 악성 파일 옮기기, 위험한 파일 종류(실행 파일, 스크립트, Office 문서)"
tags:
  - training
  - blue-team
  - files
  - file-analysis
  - malware-triage
  - phishing
---

# 의심 파일 안전하게 다루기 — 분석 환경, 악성 파일 옮기기, 위험한 파일 종류 { #safe-handling-file-types }

!!! abstract "이 페이지에서 다루는 것"
    파일이 **무엇인지** 아는 건(앞 페이지들) 일의 절반입니다. 나머지 절반은 그 파일이 위험한지 판단하는 건데, 그 과정에서 **나도, 다른 사람도 다치면 안 됩니다.** 이 페이지는 안전한 분석 환경의 규칙부터 시작합니다. 잃어도 되는 컴퓨터, 중요한 게 하나도 없는 네트워크, 단단하게 잠근 호스트 OS, 스냅숏을 찍고 되돌리는 가상 머신, 그리고 파일을 **실행할 수 없는** 운영체제에서 분석하는 요령. 그다음 업계 표준 방식(비밀번호 `infected`를 건 암호화 ZIP)으로 파일을 옮기면서 명령과 출력을 한 줄씩 읽고, 그 ZIP이 여전히 무엇을 드러내는지도 봅니다. 이어서 공격자가 어떤 파일 종류를 무기로 쓰는지 훑고, 앞의 세 가족을 깊이 다룹니다. **실행 파일**(PE 가족 전체 — `.scr`, `.cpl`, `.dll`, `.sys`, `.ocx` 등 — 그리고 설치 파일, 자동 압축 풀림 파일, Java `.jar`), **스크립트**(`.ps1`, `.vbs`, `.js`, `.wsf`, `.hta`, `.bat`, 셸, Python), **Microsoft Office 문서**(링크, 삽입 개체, 익스플로잇, 매크로, 옛 바이너리 형식과 ZIP 기반 형식, 그리고 인터넷에서 온 파일의 매크로를 막는 2022년 변화). 가족마다 디스크 위에서 어떻게 생겼는지, 실행될 때 프로세스 생성 로그에 어떻게 찍히는지, 어떤 ATT&CK 기법에 해당하는지, SOC가 어떻게 잡는지를 봅니다. 끝에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름, 해시는 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다. 이 페이지에는 실제로 동작하는 악성 코드가 없습니다. 스크립트와 매크로 샘플은 방어자가 무엇을 봐야 하는지 보여 주려고 일부러 잘라 내고 무력화한 조각입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. **내가 아끼는 컴퓨터나 네트워크에서는 절대 분석하지 않는다.** 잃어도 되는 시스템을, 운영 환경과 떨어진 곳에 두고, 호스트 OS는 단단히 잠그고, 의심 파일은 **가상 머신(VM)** 안에 넣는다. 스냅숏 → 파일 넣기 → 분석 → **되돌리기**.
2. **운영체제를 엇갈리게 고른다.** Windows용 `.exe`, `.vbs`, `.bat`, 매크로 문서는 Linux에서 돌지 않고, ELF나 bash 스크립트는 Windows에게 아무 의미가 없다. 여러 OS에서 도는 형식(PDF, JavaScript)도 Linux가 더 안전한 기본값이다. 사슬 끝의 페이로드는 거의 항상 Windows용이기 때문이다. 예외: 동적 분석에서 **일부러** 실행할 때.
3. **의심 파일은 비밀번호 `infected`를 건 암호화 ZIP에 넣어서만 옮긴다.** 실수로 실행되는 걸 막고, 백신이 증거를 지우는 걸 막고, 나중에 발견한 사람에게 경고가 된다. 일반 ZIP 암호화는 **파일 이름이 그대로 보인다.** 헤더 암호화를 켠 `.7z`는 이름도 숨긴다.
4. **거의 모든 파일 종류가 무기가 될 수 있지만**, 피해 대부분은 네 가족에서 나온다. 실행 파일, 스크립트, 문서, 그리고 "기타"(바로 가기, 이미지, 글꼴, 이메일 파일).
5. **"실행 파일"은 `.exe`만이 아니다.** `.scr`, `.cpl`, `.dll`, `.ocx`, `.sys`, `.drv`, `.efi`, `.ax`, `.acm`, `.mui`, `.tsp`는 모두 같은 `MZ`/PE 형식이다. 설치 파일(`.msi`, `.msp`), 자동 압축 풀림 파일, Java `.jar`도 코드를 실행한다. 확장자가 아니라 **진짜 형식**으로 막고 검사한다.
6. **스크립트는 실행 파일만큼 위험하고** 필터는 더 쉽게 빠져나간다. Windows는 `.js`, `.vbs`, `.wsf`를 `wscript.exe`/`cscript.exe`로, `.hta`를 `mshta.exe`로 기본 실행하고, 난독화가 아주 쉽고, 애플리케이션 제어 규칙이 스크립트는 빼먹는 경우가 많다.
7. **Office 문서는 네 가지 방법으로 공격한다.** 미끼 링크, 삽입한 파일, Office 자체를 노린 익스플로잇, 매크로. 옛 바이너리 형식(`.doc`, `.xls`)은 이름을 바꾸지 않고도 매크로를 숨기고, 새 ZIP 형식은 매크로가 있으면 `m`(`.docm`, `.xlsm`)으로 표시하고 `vbaProject.bin`에 담는다.
8. **이제 Office는 인터넷에서 온 파일의 VBA 매크로를 기본으로 막는다**(Mark of the Web). 공격자는 컨테이너, 바로 가기, HTML 스머글링 같은 다른 형식으로 옮겨 갔다. 파일 종류 싸움은 끝난 게 아니라 자리를 옮긴 것이다.

## SOC에서 왜 중요한가 { #why }

경보가 하나 들어옵니다. 이메일 게이트웨이가 재무팀 세 명에게 `Remittance_Nov.doc`을 통과시켰고, 그중 한 명이 열었습니다. EDR이 그 파일을 갖고 있습니다. 몇 분 안에 "나쁜 거야?", "뭘 하는 거야?", "또 누가 받았어?"라는 질문이 날아옵니다. 답하려면 사본을 내 앞에 가져와야 하는데, 분석가가 스스로 감염되는 게 바로 이 순간입니다. "잠깐 보기만 하려고" 더블클릭하거나, 팀 공유 폴더로 끌어다 놓았다가 백신이 지워 버리거나(증거도 같이), 도메인에 가입된 노트북에서 열어 보거나.

이 페이지의 질문은 두 가지입니다. **이 파일을 어디서, 어떻게 만져야 안전한가?** 그리고 **어떤 종류의 파일이 나를 긴장시켜야 하고, 왜 그런가?** 두 번째 질문은 분석보다 훨씬 넓게 쓰입니다. 이메일 게이트웨이 규칙, 프록시 차단, 애플리케이션 제어 정책, 프로세스 생성 탐지를 만들 때 바로 이 지식을 씁니다.

## 안전한 분석 환경 고르기 { #safe-environment }

의심 파일을 감염병 균이 들어 있을지 모르는 밀봉된 병이라고 생각해 봅시다. 부엌 식탁에서 따지 않죠. 유리벽 뒤 실험실에서, 끝나면 소독할 수 있는 방에서 땁니다. 가장 좋은 건 안에 든 균이 아예 감염시킬 수 없는 도구로 살펴보는 거고요. 아래 네 규칙이 그 실험실입니다.

### 규칙 1 — 잃어도 되는 시스템 { #rule-lose }

매일 쓰는 업무용 컴퓨터에서는 절대 분석하지 않습니다. 악성코드는 파일을 암호화하거나, 브라우저 세션과 저장된 비밀번호를 훔치거나, 백도어를 심을 수 있습니다. 그리고 내 업무용 컴퓨터에는 공격자가 원하는 게 다 있습니다. 메일, VPN, 관리 콘솔, 캐시된 자격 증명. 분석용 컴퓨터에는 도난당하거나 망가져도 상관없는 것만 있어야 합니다. **아무것도** 없어야 합니다. 최악의 경우에도 밀어 버리면 잃을 게 없게요.

### 규칙 2 — 끊긴 네트워크, 아니면 따로 떨어진 네트워크 { #rule-network }

악성코드는 주변을 스캔하고, 퍼지고, 집(공격자 서버)에 연락합니다. 분석 장비가 회사 LAN에 붙어 있으면 웜 같은 샘플이 파일 서버나 도메인 컨트롤러까지 닿을 수 있고, 비컨 하나가 공격자에게 "누가 내 도구를 들여다보고 있다"고 알려 줍니다. 그래서 분석 시스템은 **완전히 끊어** 두거나, 아끼는 게 하나도 없는(운영 환경으로 가는 경로도 없는) 별도 네트워크 구간에 둡니다. [보충] 네트워크 행위를 봐야 할 때는 <strong>호스트 전용(host-only)</strong> 가상 네트워크에 가짜 인터넷 서비스(예: INetSim, FakeNet-NG)를 붙여 씁니다. 이 서비스가 DNS와 HTTP에 그 자리에서 대답해 주니까, 샘플은 "접속에 성공했다"고 믿고 URL을 드러내지만 실제 인터넷에는 절대 닿지 않습니다.

### 규칙 3 — 단단히 잠근 호스트 운영체제 { #rule-host }

호스트(가상 머신을 돌리는 실제 컴퓨터)는 마지막 벽입니다. 패치를 최신으로 하고, 필요한 것만 깔고, 잠가 둡니다. 우리가 보게 될 악성코드 대부분이 Windows를 노리기 때문에 호스트로는 Linux를 많이 씁니다. 분석 전용 배포판도 있습니다. [보충] **REMnux**(정적 분석, 네트워크 흉내, 문서 분석용 Linux 도구 모음)와 **FLARE-VM**(Windows VM에 분석 도구를 한꺼번에 설치해 주는 묶음)이 흔히 짝으로 쓰입니다.

### 규칙 4 — 가상 머신 안에서 분석하고, 스냅숏을 찍고, 되돌린다 { #rule-vm }

<strong>스냅숏(snapshot)</strong>은 VM 상태 전체(디스크, 원하면 메모리까지)를 저장해 둔 사본입니다. 순서는 늘 똑같습니다. 깨끗한 상태에서 스냅숏을 찍고, 샘플을 넣고, 분석하고, 스냅숏으로 **되돌립니다**. 그러면 악성코드가 바꾼 모든 게 사라집니다. 게임에서 보스전 전에 저장해 두고, 지면 불러오는 것과 같습니다.

호스트에서 VirtualBox 명령줄 도구로 하면 이렇게 생겼습니다. VM 이름은 `win10-analysis`입니다.

```
$ VBoxManage snapshot win10-analysis take clean-2026-11 --description "patched, tools installed, no network"
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
Snapshot taken. UUID: 6a1f2c4e-0b7d-4e55-9a10-3c2b8d7e9f01

$ VBoxManage snapshot win10-analysis list
   Name: clean-2026-11 (UUID: 6a1f2c4e-0b7d-4e55-9a10-3c2b8d7e9f01) *

$ VBoxManage controlvm win10-analysis poweroff
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%

$ VBoxManage snapshot win10-analysis restore clean-2026-11
Restoring snapshot 'clean-2026-11' (6a1f2c4e-0b7d-4e55-9a10-3c2b8d7e9f01)
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
```

한 줄씩 봅시다.

- `VBoxManage snapshot win10-analysis take clean-2026-11 --description "..."` — 지금 VM 상태를 `clean-2026-11`이라는 이름으로 저장합니다. 샘플이 VM에 닿기 **전에** 찍어야 합니다. 설명(description)에는 "깨끗하다"는 게 무슨 뜻인지(패치 완료, 도구 설치, 네트워크 꺼짐) 적어 둡니다. 몇 달 뒤 "이 스냅숏 믿어도 되나?" 고민할 때 쓸모가 있습니다.
- 퍼센트 막대와 `Snapshot taken. UUID: ...` — 스냅숏이 끝났고 고유 ID를 받았다는 뜻입니다.
- `snapshot ... list` — 스냅숏 목록입니다. `*`는 지금 VM이 기반으로 삼고 있는 스냅숏 표시입니다.
- `controlvm ... poweroff` — 분석이 끝나면 VM 전원을 강제로 끕니다. 안에서 정상 종료를 하지 않는 이유는, 악성코드에게 조용히 뭔가 써 둘 정상 종료 시간을 주고 싶지 않아서입니다.
- `snapshot ... restore clean-2026-11` — 스냅숏 이후의 변경을 전부 버립니다. VM이 다시 깨끗해집니다.

KVM/libvirt 호스트라면 같은 일을 `virsh snapshot-create-as win10-analysis clean-2026-11`과 `virsh snapshot-revert win10-analysis clean-2026-11`로 합니다.

!!! warning "[주의] VM은 벽이지 금고가 아니다"
    VM 탈출(VM escape)은 드물지만 실제로 있고, 편의 기능이 벽에 구멍을 냅니다. 분석 VM에서는 **공유 폴더**, **공유 클립보드**, **끌어서 놓기**, USB 연결을 끄고, 호스트 드라이브를 붙이지 말고, VM 안에서 진짜 계정으로 아무 데도 로그인하지 마세요. 또 어떤 악성코드는 VM 안인지 확인하고, 그렇다면 얌전한 척합니다. VM에서 깨끗하게 나왔다고 무죄가 증명된 건 아닙니다.

### 파일을 실행할 수 없는 OS에서 분석한다 { #os-mismatch }

감염되지 않는 가장 좋은 방법은, 그 파일의 코드가 **아예 돌 수 없는** 시스템에서 보는 겁니다. Windows PE 파일, VBScript, 배치 파일, Office 매크로는 Linux에서 아무것도 못 합니다. Windows 로더도 없고, `wscript.exe`도 없고, Word도 없으니까요. 그래서 `file`, `strings`, 헥스 뷰어, `olevba` 같은 도구를 완전히 안전하게 돌릴 수 있습니다. 반대도 됩니다. ELF 바이너리나 bash 스크립트는 Windows에게 그냥 바이트일 뿐입니다. 비유하자면 사람에게만 옮는 병을 개에게 보여 주는 셈이죠.

| 의심 파일 | 기본으로 실행되는 곳 | 살펴보기 더 안전한 곳 | 이유 |
| --- | --- | --- | --- |
| `.exe`, `.dll`, `.scr`, `.cpl`, `.sys` | Windows | Linux | Linux에는 PE 로더가 없음 |
| `.vbs`, `.js`(WSH), `.wsf`, `.hta`, `.bat` | Windows | Linux | Windows Script Host, `mshta`, `cmd.exe`가 없음 |
| 매크로 있는 `.doc`/`.docm`/`.xls` | Windows/macOS의 Office | Linux(Office 없음) | VBA 엔진이 없음 |
| `.ps1` | Windows, 그리고 **PowerShell 7이 깔린 Linux/macOS** | `pwsh`가 **안 깔린** Linux | 이제 PowerShell은 여러 OS에서 돈다 |
| ELF, `.sh` | Linux | Windows(또는 다른 Linux VM) | ELF 로더가 없고, 기본으로 bash가 없음 |
| PDF, 브라우저/Node용 JavaScript | 어디서나 | Linux | 받아 오는 페이로드가 거의 항상 Windows 전용 |

마지막 줄은 조금 설명이 필요합니다. PDF 리더와 브라우저는 모든 OS에 있으니까 PDF나 JavaScript는 어디서든 위험할 수 있습니다. 그래도 Linux가 더 낫습니다. 이유는 두 가지입니다. 첫째, 공격자는 거의 항상 피해자가 Windows를 쓴다고 가정합니다. 그래서 익스플로잇의 셸코드(shellcode)나, 그게 받아서 실행하는 파일이 Windows용 코드입니다. Linux에서는 그 사슬이 끊깁니다. 둘째, 여러 OS에서 **그리고** OS마다 다른 PDF 리더에서 모두 통하는 익스플로잇을 만드는 건 어렵습니다. 어렵지, 불가능하지는 않습니다. 그러니 규칙 1~4는 그대로 지킵니다.

[정정] "PowerShell은 Linux에서 못 돈다"는 이제 틀린 말입니다. PowerShell 7(`pwsh`)은 Linux와 macOS에서 돕니다. Windows를 노린 `.ps1`은 Linux에서 대부분 실패하지만(Windows DLL을 부르는 `Add-Type`도, 레지스트리도, WMI도 없으니까), 단순한 "받아서 실행" 로직은 돌 수도 있습니다. 살펴보기용 장비에는 `pwsh`를 깔지 말거나, `.ps1`은 "여기서도 돈다"고 생각하세요.

### 정적 분석과 동적 분석, 한 번 더 { #static-dynamic }

위의 이야기는 모두 <strong>정적 분석(static analysis)</strong>, 즉 파일을 실행하지 않고 보는 것에 관한 겁니다. 가끔은 <strong>동적 분석(dynamic analysis)</strong>이 필요합니다. 일부러 실행해서 무엇을 하는지 지켜보는 거죠. 그때는 OS 엇갈리기가 거꾸로 됩니다. Windows 샘플을 터뜨리려면 Windows VM이 필요하고, 안전은 규칙 1~4가 전부 떠맡습니다. 대부분의 SOC는 이 일을 **샌드박스**에 맡기고([스크린샷, 샌드박스, 그리고 수동 분석으로 넘어갈 때](../http-analysis/screenshots-sandboxes.md) 참고), 손으로 터뜨리는 건 제대로 된 실험실을 가진 분석가에게 남겨 둡니다.

## 의심 파일 안전하게 옮기기 { #moving-files }

언젠가는 샘플을 옮겨야 합니다. EDR 격리 보관소에서 내 분석 장비로, 동료에게서 나에게로, 나에게서 리버스 엔지니어에게로. 그냥 복사·붙여넣기, 끌어서 놓기, 명령줄의 `copy`는 틀린 방법입니다. 이유는 세 가지입니다.

1. **실수로 실행된다.** 탭 자동 완성 한 번 잘못(`./invoice` + Tab + Enter), 복잡한 다운로드 폴더에서 엉뚱한 아이콘을 한 번 더블클릭하면, 새 컴퓨터에서 실행됩니다. 아무리 조심해도 손가락은 실수합니다.
2. **백신이 지운다.** 받는 쪽 컴퓨터의 백신이나 EDR이 알려진 악성 파일이 들어오는 걸 보고 격리하거나 지우고, 새 경보를 띄웁니다. 이제 다른 누군가가 *나를* 조사하게 되고, 내 증거는 사라집니다.
3. **나중에 누가 발견한다.** 공유 폴더나 메일 스레드에 남은 `invoice.pdf.exe`는 다음 사람 눈에 그냥 청구서로 보입니다.

업계 표준 해법은 비밀번호 **`infected`**를 건 암호화 ZIP입니다. 처음 보면 좀 이상하지만, 모든 악성코드 분석가, 샌드박스, 샘플 공유 사이트가 아는 약속입니다. "비밀번호: infected"를 보면 누구나 안에 위험한 게 들었다는 걸 압니다. 암호화돼 있으니 백신이 안을 들여다보고 지울 수 없고, 먼저 풀어야 하니 실수로 실행할 수도 없습니다. 위험한 물건을 "생물학적 위험" 스티커가 붙은 잠긴 상자에 넣는 것과 같습니다. 이 약속은 실행 파일뿐 아니라 악성 내용이 들었을 수 있는 모든 것에 씁니다. 문서, 스크립트, PCAP, 메모리 이미지까지.

분석 장비에서 하는 전체 순서입니다. `7z`는 7-Zip 명령줄 도구입니다.

```
$ sha256sum Remittance_Nov.doc
3b9e1f6c0d2a47e8b5c1f9a0e7d4c3b2a1908f7e6d5c4b3a2918f7e6d5c4b3a2  Remittance_Nov.doc

$ 7z a -tzip -pinfected -mem=AES256 Remittance_Nov.zip Remittance_Nov.doc

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20

Scanning the drive:
1 file, 48128 bytes (47 KiB)

Creating archive: Remittance_Nov.zip

Add new data to archive: 1 file, 48128 bytes (47 KiB)

Files read from disk: 1
Archive size: 22650 bytes (23 KiB)
Everything is Ok

$ 7z l -slt Remittance_Nov.zip | grep -E "^(Path|Encrypted|Method|Size)"
Path = Remittance_Nov.zip
Path = Remittance_Nov.doc
Size = 48128
Encrypted = +
Method = AES-256 Deflate
```

한 줄씩 봅시다.

- `sha256sum Remittance_Nov.doc` — 묶기 **전에** 해시를 구합니다. 해시는 파일의 지문입니다. 티켓에 적어 두면 나중에 누구나 샘플이 바뀌지 않았는지 확인할 수 있고, 파일을 넘기지 않고도 조회할 수 있습니다. (해시는 이 섹션 뒤쪽에서 따로 다룹니다.)
- `7z a` — `a`는 "압축 파일에 추가(add)"라는 뜻입니다.
- `-tzip` — 7-Zip 고유의 `.7z`가 아니라 `.zip`으로 만듭니다. 어떤 도구, 어떤 동료든 열 수 있으니까요.
- `-pinfected` — 비밀번호를 `infected`로 정합니다. `-p`와 비밀번호 사이에 띄어쓰기가 없습니다.
- `-mem=AES256` — AES-256 암호화를 씁니다. 이게 없으면 ZIP은 옛 **ZipCrypto** 방식을 쓰는데 약합니다. 호환성 때문에 아직 ZipCrypto를 쓰는 샌드박스와 공유 사이트도 있지만, 양쪽을 내가 다 관리한다면 AES가 낫습니다.
- `Remittance_Nov.zip Remittance_Nov.doc` — 만들 압축 파일 이름, 그다음 넣을 파일.
- `Scanning the drive: 1 file, 48128 bytes` → `Archive size: 22650 bytes` → `Everything is Ok` — 47KiB 파일 하나를 찾아서 약 23KiB로 압축했고, 오류 없이 끝났다는 뜻입니다.
- `7z l -slt` — 압축 파일 내용을 기술적인 세부 정보와 함께 보여 줍니다(`l`은 list). `grep`으로 볼 만한 칸만 남겼습니다.
- `Path = Remittance_Nov.doc` — **비밀번호 없이도 파일 이름이 보입니다.** ZIP 형식은 파일 *내용*만 암호화하고, 이름·크기·날짜는 암호화 안 된 헤더에 그대로 있습니다. 보통은 괜찮습니다(받는 사람이 뭘 받았는지 알 수 있으니까요). 하지만 이름 자체가 민감하다면, 예를 들어 파일 이름에 피해자 이름이 들어 있다면 문제가 됩니다.
- `Encrypted = +`와 `Method = AES-256 Deflate` — 내용이 AES-256으로 암호화되고 Deflate로 압축됐다는 확인입니다.

이름까지 숨겨야 하면 헤더 암호화를 켠 7z 형식을 씁니다.

```
$ 7z a -t7z -pinfected -mhe=on case-2026-1142.7z Remittance_Nov.doc
$ 7z l case-2026-1142.7z
...
Enter password (will not be echoed):
```

`-mhe=on`("header encryption on", 헤더 암호화 켜기)은 파일 목록까지 암호화합니다. 그래서 목록만 보려 해도 비밀번호를 묻습니다.

[보충] ZIP을 다룰 때 좋은 습관:

- 할 수 있으면 <strong>압축 안의 파일 이름을 무력화(defang)</strong>합니다. `Remittance_Nov.doc_`나 `3b9e1f6c....bin`은 압축을 푼 뒤에도 더블클릭으로 열리지 않습니다.
- **해시는 티켓과 압축 파일 옆의 텍스트 메모에** 적습니다. 자동으로 스캔돼 격리될 수 있는 이메일 본문에는 적지 않습니다.
- **어떤 이메일 게이트웨이는 암호화 압축 파일을 막거나 떼어 냅니다.** 공격자도 검사를 피하려고 비밀번호 걸린 ZIP을 보내기 때문이죠. 메일 대신 사건 관리 시스템, 보안 파일 공유, 샌드박스 자체의 전송 기능을 씁니다.
- **압축은 분석 장비에서만 풀고**, 푼 뒤 해시를 다시 확인합니다. `sha256sum`이 적어 둔 값과 같은 값을 찍어야 합니다.

## 어떤 파일 종류가 위험한가 { #dangerous-types }

솔직한 답은 "조건만 맞으면 거의 전부"입니다. 파일을 <strong>해석(parse)</strong>하는 프로그램은 어떤 것이든 버그가 있을 수 있고, 잘 만든 파일은 그 버그를 노릴 수 있습니다. 하지만 어떤 종류는 **원래부터** 위험하고(그 자체가 코드니까), 어떤 종류는 **기능** 때문에 위험하고(매크로, 삽입 개체, 링크), 어떤 종류는 여는 프로그램에 **취약점**이 있어야 위험합니다. 이 차이가 각 종류를 무기로 만들기가 얼마나 쉬운지를 알려 줍니다.

| 가족 | 예 | 왜 위험한가 | 무기화 난이도 |
| --- | --- | --- | --- |
| 실행 파일 | Windows PE(`.exe`, `.dll`, `.scr`, `.cpl`, `.sys`...), 설치 파일, Linux ELF | 그 자체가 코드. OS가 바로 실행 | 아주 쉬움 |
| 스크립트 | OS 전용: bash, 배치, VBScript, Office 매크로. 여러 OS: JavaScript, Python, PowerShell | 그 자체가 코드. 이미 깔린 해석기가 실행 | 아주 쉬움 |
| 문서 | Office, RTF, PDF | 코드를 실행하거나, 파일을 품거나, 외부 내용을 가리키는 기능 + 리더를 노린 익스플로잇 | 쉬움~보통 |
| 기타 | 바로 가기(`.lnk`), 아이콘, 이미지, 동영상, 글꼴, 이메일 파일 | 해석기 버그나 기능 악용이 필요하고, 대개 사용자 도움도 필요 | 더 어려움 |

이 페이지는 앞의 세 가족을 깊이 다룹니다. RTF, PDF, "기타" 파일은 다음 페이지에서 다룹니다.

## 실행 파일 { #executables }

### "실행 파일"은 확장자가 아니라 형식이다 { #pe-family }

`.exe`는 다들 막습니다. 그런데 Windows 파일 한 가족 전체가 **같은 형식**이라는 걸 아는 사람은 훨씬 적습니다. 바로 [파일 알아보기](file-identification.md)에서 본 `MZ` 매직 바이트로 시작하는 <strong>PE(Portable Executable)</strong> 형식이고, 이 파일들은 모두 똑같이 코드를 실행할 수 있습니다. 확장자는 Windows에게 *어느 프로그램에게 이 파일을 넘길지*만 알려 줍니다. 안의 바이트는 어느 쪽이든 프로그램입니다. 같은 사람이 이름표만 바꿔 단 것과 같습니다.

| 확장자 | 무엇인가 | 어떻게 실행되나 | ATT&CK |
| --- | --- | --- | --- |
| `.exe` | 보통 프로그램 | OS가 바로 실행 | T1204.002 User Execution: Malicious File |
| `.dll` | 다른 프로그램이 쓰는 함수 모음(라이브러리) | `rundll32.exe`, `regsvr32.exe`, 또는 프로그램이 불러옴(사이드로딩) | T1218.011 Rundll32, T1218.010 Regsvr32, T1574.002 DLL Side-Loading |
| `.scr` | 화면 보호기 | **더블클릭하면 `.exe`처럼 실행**, 화면 보호기로 지정도 됨 | T1546.002 Screensaver |
| `.cpl` | 제어판 항목(사실은 DLL) | 더블클릭 → `control.exe` → `rundll32.exe` | T1218.002 Control Panel |
| `.ocx` | ActiveX 컨트롤(DLL) | `regsvr32.exe`로 등록, 앱이 불러옴 | T1218.010 |
| `.sys`, `.drv` | 커널 드라이버, 장치 드라이버 | 서비스로 설치돼 커널에서 실행 | T1543.003 Windows Service, T1068(취약한 드라이버) |
| `.efi` | UEFI 응용 프로그램/부트 로더 | Windows가 뜨기 전에 펌웨어가 실행 | T1542 Pre-OS Boot |
| `.ax` | DirectShow 필터(DLL) | 미디어 앱이 불러옴 | — |
| `.acm` | 오디오 압축 코덱(DLL) | 오디오 계층이 불러옴 | — |
| `.mui` | 언어 리소스 파일(PE) | 화면 글을 위해 불러옴, 사이드로딩 가능 | — |
| `.tsp` | 전화 통신 서비스 공급자(DLL) | 전화 통신 서비스가 불러옴 | — |
| `.com` | 옛 DOS 명령 파일. 요즘 Windows에서는 이름만 바꾼 PE인 경우가 많음 | 바로 실행되고, **`PATHEXT`에서 `.exe`보다 먼저 찾아짐** | T1036 Masquerading |

[보충] `.fon`(옛 비트맵 글꼴) 파일에도 `MZ` 헤더가 있습니다(더 옛날 16비트 "NE" 구조를 씀). 그래서 "위험한 확장자" 목록에 가끔 등장합니다. 요즘 악용되는 일은 드물지만, `MZ`가 생각지도 못한 곳에 나타난다는 걸 잘 보여 줍니다.

`.scr`가 왜 공격 수단이 될까요? Windows에게 화면 보호기는 그냥 확장자만 다른 프로그램이고, 더블클릭하면 실행되기 때문입니다. 이미지 아이콘을 단 `Holiday_Photos.scr`는 파일 확장자를 숨겨 둔 사용자 눈에 무해해 보입니다. `.cpl`은 왜일까요? `.exe`와 `.dll`을 막는 게이트웨이 중 상당수가 이 확장자를 아예 모르기 때문입니다.

분석 장비에서는 어떻게 보일까요? 이름을 바꿔도 바이트는 그대로고, `file`은 바이트를 읽습니다.

```
$ file holiday_photos.scr invoice_view.cpl vidfilter.ax netcard.sys
holiday_photos.scr: PE32 executable (GUI) Intel 80386, for MS Windows, 4 sections
invoice_view.cpl:   PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 6 sections
vidfilter.ax:       PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 5 sections
netcard.sys:        PE32+ executable (native) x86-64, for MS Windows, 7 sections
```

- `holiday_photos.scr: PE32 executable (GUI) Intel 80386` — 32비트 Windows 창(GUI) 프로그램입니다. "화면 보호기"는 평범한 실행 파일입니다.
- `invoice_view.cpl: PE32+ executable (DLL)` — 64비트 DLL입니다. 제어판 항목이 원래 이렇게 생겼습니다.
- `vidfilter.ax: ... (DLL)` — DirectShow 확장자를 단 DLL입니다.
- `netcard.sys: ... (native)` — `native` 하위 시스템은 보통의 Windows 사용자 모드 환경 밖에서 돈다는 뜻입니다. 커널 드라이버입니다.

게이트웨이와 프록시에 주는 교훈: 확장자 목록이 아니라 **진짜 형식**(`MZ` 헤더 / PE 구조)으로 막거나 검사합니다. 요즘 보안 이메일 게이트웨이와 프록시 대부분이 이걸("진짜 파일 형식" 탐지) 할 수 있으니, 그 옵션이 켜져 있는지 확인하세요.

### 실행될 때는 어떻게 보이나 { #pe-in-logs }

사용자가 다운로드 폴더에서 `invoice_view.cpl`을 더블클릭했다고 합시다. Windows에서 프로세스 생성 감사가 켜져 있으면 보안 로그에 **이벤트 ID 4688**("새 프로세스가 만들어졌습니다")이 남습니다. 프로세스가 시작될 때마다 생기고, 공격자가 신경 쓰는 이유는 *무엇이, 어떤 명령줄로, 무엇에 의해 시작됐는지*를 기록하기 때문입니다. 공격자가 가장 피하고 싶은 흔적이죠. (칸별 전체 설명은 [프로세스 생성 이벤트](../important-events/process-creation.md)에 있습니다.)

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-11-20T23:41:07.5521337Z" />
    <Computer>FIN-WS-0117.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">j.kim</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="NewProcessId">0x1f3c</Data>
    <Data Name="NewProcessName">C:\Windows\System32\rundll32.exe</Data>
    <Data Name="TokenElevationType">%%1938</Data>
    <Data Name="ProcessId">0x22a8</Data>
    <Data Name="CommandLine">"C:\Windows\System32\rundll32.exe" Shell32.dll,Control_RunDLL "C:\Users\j.kim\Downloads\invoice_view.cpl",</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\control.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-8192</Data>
  </EventData>
</Event>
```

- `EventID 4688` — 프로세스가 시작됐습니다.
- `Computer FIN-WS-0117.corp.example` — 재무팀 PC입니다.
- `SubjectUserName j.kim` — 더블클릭한 사용자 권한으로 돕니다.
- `NewProcessName C:\Windows\System32\rundll32.exe` — 실제로 시작된 프로세스는 `.cpl`이 아니라 **서명된 Windows** `rundll32.exe`입니다. 이게 이 기법의 핵심입니다. 악성 DLL이 믿을 만한 프로그램 **안에서** 돌기 때문에, "서명 안 된 프로세스에 경보" 같은 단순한 규칙에는 아무것도 안 걸립니다.
- `CommandLine ... Shell32.dll,Control_RunDLL "C:\Users\j.kim\Downloads\invoice_view.cpl",` — 여기가 결정적 단서입니다. `Control_RunDLL`은 제어판이 `.cpl`을 불러오는 방식이고, `.cpl` 경로가 사용자의 **다운로드** 폴더입니다. 진짜 제어판 항목은 `System32`에 있습니다.
- `ParentProcessName C:\Windows\System32\control.exe` — 더블클릭이 먼저 제어판으로 갔고, 제어판이 `rundll32`를 시작했습니다.
- `TokenElevationType %%1938` — 권한 상승 안 된(제한된) 토큰, `MandatoryLabel S-1-16-8192` — **중간(medium)** 무결성, 즉 보통 사용자 권한입니다. UAC 창도 필요 없었습니다.

가져 둘 만한 탐지: 명령줄에 `Control_RunDLL`(또는 `.cpl`)이 있고 경로가 `\Users\`, `\Temp\`, `\Downloads\` 아래인 `rundll32.exe`. 사용자가 쓸 수 있는 폴더에서 DLL이나 `.ocx`를 불러오는 `regsvr32.exe`에도 같은 패턴을 씁니다.

### 설치 파일, 자동 압축 풀림 파일, Java { #installers-sfx-jar }

PE 파일이 아니거나, PE 파일을 감싸고 있으면서도 코드를 실행하는 형식들이 더 있습니다.

- **`.msi`와 `.msp` — Windows Installer 패키지와 패치.** MSI는 OLE 복합 파일(매직 바이트 `D0 CF 11 E0`, 옛 Office 파일과 같은 그릇)이고, 안에 설치 동작 데이터베이스가 들어 있습니다. `msiexec.exe`가 실행하는데, 그 안의 "사용자 지정 동작(custom action)"이 내장한 어떤 프로그램이나 스크립트든 실행할 수 있습니다. 사용자는 설치 파일이 관리자 권한을 달라고 하는 걸 당연하게 여기니까 공격자가 좋아합니다. ATT&CK: **T1218.007 System Binary Proxy Execution: Msiexec**. 로그에서는 `/i`나 `/q`로 URL이나 사용자 폴더를 가리키는 `msiexec.exe`, 그리고 셸인 `msiexec.exe`의 자식 프로세스를 봅니다.
- **자동 압축 풀림(self-extracting) 파일(`.sfx`, `.sea`, 그리고 많은 `.exe`).** 작은 압축 풀기 프로그램 끝에 압축 파일을 붙인 것입니다. [파일 알아보기](file-identification.md#nested-files)의 "중첩 파일" 모양 그대로죠. 실행하면 압축을 풀고, 그 안의 파일을 실행할 수 있습니다. `file`은 보통 "PE32 executable"이라고만 하고, 시그니처 검색(`binwalk`)을 하면 안의 압축 파일이 나옵니다. `.sea`는 옛 Mac의 "self-extracting archive" 이름이고, 둘 다 스팸에 쓰인 적이 있습니다.
- **`.jar` — Java 압축 파일.** 컴파일된 Java 클래스와 시작할 클래스를 적은 `META-INF/MANIFEST.MF`를 담은 ZIP(매직 `PK\x03\x04`)입니다. 엄밀히 말해 OS가 바로 실행하는 파일은 아니고 Java 가상 머신 안에서 돌지만, Java가 깔려 있으면 더블클릭 한 번에 사용자의 모든 권한으로 실행됩니다.

```
$ unzip -l shipping_label.jar
Archive:  shipping_label.jar
  Length      Date    Time    Name
---------  ---------- -----   ----
       84  2026-11-18 09:12   META-INF/MANIFEST.MF
     3120  2026-11-18 09:12   com/label/Main.class
    15872  2026-11-18 09:12   com/label/res/d.bin
---------                     -------
    19076                     3 files

$ unzip -p shipping_label.jar META-INF/MANIFEST.MF
Manifest-Version: 1.0
Main-Class: com.label.Main
```

- `unzip -l`은 압축을 풀지 않고 목록만 봅니다. 항목이 세 개입니다.
- `META-INF/MANIFEST.MF` — 매니페스트입니다. 실행 가능한 JAR라면 다 있습니다.
- `com/label/Main.class` — 컴파일된 Java 코드입니다.
- `com/label/res/d.bin` — 이름에 아무 뜻이 없는 15KB짜리 "리소스". 코드 + 속을 알 수 없는 덩어리는 전형적인 로더(loader) 모양입니다. 클래스가 그 덩어리를 복호화하거나 풀어서 실행하죠. 배송 라벨에 둘 중 어느 것도 들어 있을 이유가 없습니다.
- `unzip -p ... MANIFEST.MF`는 파일 하나를 화면에 찍습니다. `Main-Class: com.label.Main`은 JAR를 더블클릭했을 때 Java가 시작할 클래스입니다.

[보충] Linux와 macOS의 "실행 파일"은 **ELF**(`\x7fELF`)와 **Mach-O** 파일, 그리고 공유 라이브러리(`.so`, `.dylib`)입니다. 서버와 개발자 노트북에서 중요하고, "확장자가 아니라 진짜 형식" 규칙은 똑같이 적용됩니다.

### OS를 노린 익스플로잇으로서의 실행 파일 { #pe-exploits }

실행 파일은 그 자체로 악성코드일 수도 있고, 운영체제를 노린 **익스플로잇**일 수도 있습니다. 예를 들어 커널 버그를 악용하는 권한 상승 도구, 또는 보안 도구를 끄려고 불러오는 악성 드라이버나 **취약한 서명 드라이버**(`.sys`)("bring your own vulnerable driver", [권한 상승](../endpoint-attacks/privilege-escalation.md) 참고). 어느 쪽이든 그 파일은 먼저 시스템에 들어와서 실행돼야 합니다. 이메일, 프록시, 애플리케이션 제어 규칙이 막으려는 게 바로 그 단계입니다.

## 스크립트 { #scripts }

### 공격자가 스크립트를 좋아하는 이유 { #why-scripts }

스크립트는 명령을 적은 텍스트 파일이고, 이미 깔려 있는 프로그램인 <strong>해석기(interpreter)</strong>가 읽어서 실행합니다. 실행 파일이 할 수 있는 일은 대부분 스크립트도 할 수 있습니다. 파일 받기, 레지스트리 쓰기, 프로세스 시작, Windows API 부르기. 요리로 치면 실행 파일은 완성된 도시락이고, 스크립트는 레시피입니다. 주방(해석기)이 이미 집에 있으니 레시피만 보내면 같은 요리가 나옵니다. 그리고 스크립트에는 공격자에게 유리한 점이 더 있습니다.

- **눈에 덜 띈다.** 많은 필터가 바이너리보다 텍스트 파일에 너그럽습니다. `.exe`와 `.bat`를 막는 조직도 `.js`, `.vbs`, `.ps1`, `.py`는 통과시키곤 합니다.
- **난독화가 쉽다.** 스크립트는 텍스트라서 끝없이 다시 쓸 수 있습니다(문자열 쪼개기, 인코딩, 쓰레기 코드). 그래서 시그니처 기반 백신이 붙잡을 고정된 무언가가 없습니다. 기본 동작("받기", "실행")도 평범한 내장 함수만 쓰니, 그 자체로 악해 보이는 부분이 거의 없습니다.
- **애플리케이션 제어가 빼먹는 경우가 많다.** 허용 목록 정책 상당수가 `.exe`와 `.dll`만 다루고 스크립트는 안 다룹니다. 그래서 스크립트가 **애플리케이션 제어 우회** 수단이 됩니다([애플리케이션 제어](../endpoint-defense/appcontrol-fim-persistence.md) 참고).
- **Windows는 더블클릭 한 번에 많은 스크립트를 실행한다.** Windows Script Host(창 모드 `wscript.exe`, 콘솔 모드 `cscript.exe`)가 `.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`를 기본으로 실행합니다. `mshta.exe`는 `.hta`(HTML 응용 프로그램)를, `cmd.exe`는 `.bat`/`.cmd`를 실행합니다. 따로 깔 것도 없습니다.
- **다른 형식 안에 숨는다.** Office 매크로는 스크립트(VBA)입니다. PDF는 JavaScript를 품을 수 있고, HTML 첨부 파일도 JavaScript를 품습니다.
- **그래서 전달이 잘 된다.** 킬 체인으로 말하면, 스크립트는 다른 대부분의 방법보다 전달(delivery) 단계를 쉽게 통과합니다.

| 확장자 | 해석기(Windows) | 메모 | ATT&CK |
| --- | --- | --- | --- |
| `.ps1` | `powershell.exe` / `pwsh.exe` | 기본 설정에서 더블클릭하면 메모장이 열려서, 보통은 다른 무언가가 실행시킴 | T1059.001 PowerShell |
| `.vbs`, `.vbe` | `wscript.exe` / `cscript.exe` | `.vbe` = 인코딩된 VBScript | T1059.005 Visual Basic |
| `.js`, `.jse` | `wscript.exe` / `cscript.exe`(JScript) | 브라우저 JavaScript가 아님. ActiveX 개체를 통해 시스템 전체에 접근 | T1059.007 JavaScript |
| `.wsf` | `wscript.exe` / `cscript.exe` | VBScript와 JScript를 섞을 수 있는 XML 포장 | T1059.005 / T1059.007 |
| `.hta` | `mshta.exe` | 스크립트가 든 HTML 페이지인데 **브라우저 샌드박스가 없음** | T1218.005 Mshta |
| `.bat`, `.cmd` | `cmd.exe` | 배치 파일 | T1059.003 Windows Command Shell |
| `.sh` | `bash`/`sh`(Linux, macOS) | 셸 스크립트 | T1059.004 Unix Shell |
| `.py`, `.rb`, `.pl` | Python, Ruby, Perl(깔려 있다면) | Linux와 개발자 PC에 흔함 | T1059.006 Python |

[정정] 바탕 화면의 `.js` 파일은 웹 페이지 안의 JavaScript와 **다릅니다.** 브라우저 안의 JavaScript는 샌드박스 안에 갇혀 있어 내 파일을 건드릴 수 없습니다. 그런데 같은 파일을 Windows에서 더블클릭하면 `wscript.exe`가 JScript로 실행하고, 사용자의 모든 권한을 갖습니다.

### 악성 스크립트는 디스크에서 어떻게 생겼나 { #script-on-disk }

`file`에게 스크립트는 그냥 텍스트입니다. 그래서 "그냥 텍스트 파일이잖아"라는 생각이 그렇게 위험합니다.

```
$ file invoice_2026.js
invoice_2026.js: ASCII text, with very long lines (4812), with no line terminators

$ head -c 300 invoice_2026.js
var _0x3f1a=['\x57\x53\x63\x72\x69\x70\x74','\x53\x68\x65\x6c\x6c','\x52\x75\x6e'];var q=
_0x3f1a[0]+'.'+_0x3f1a[1];var Zt="hxxps://cdn-assets[.]example/"+"s/"+"u.p"+"s1";/* ... */
```

(이 샘플은 이 페이지를 위해 쓴, 무력화하고 잘라 낸 조각이라 아무 일도 하지 않습니다.)

- `ASCII text, with very long lines (4812), with no line terminators` — 거의 5,000자짜리 한 줄입니다. 사람은 스크립트를 이렇게 쓰지 않고, 난독화 도구가 이렇게 씁니다. 이것만으로도 다시 볼 이유가 됩니다.
- `var _0x3f1a=[...]` — `_0x3f1a` 같은 변수 이름은 흔한 JavaScript 난독화 도구의 지문입니다.
- `'\x57\x53\x63\x72\x69\x70\x74'` — 16진수 이스케이프입니다. 풀면(`\x57`=W, `\x53`=S, ...) `WScript`, `Shell`, `Run`이 나옵니다. 스크립트가 프로그램을 띄울 때 쓰는 개체와 메서드죠.
- `"hxxps://cdn-assets[.]example/"+"s/"+"u.p"+"s1"` — 단순히 `.ps1`을 문자열 검색하면 못 찾도록 URL을 조각내 놓았습니다. 이어 붙이면 내려받을 PowerShell 스크립트 주소입니다. (티켓에 적을 때처럼 `hxxps`와 `[.]`로 무력화해 두었습니다.)

방어자의 습관: 실행하지 말고 풀어서 본다. CyberChef, `box-js`(JavaScript 샌드박스 흉내 도구), 아니면 격리된 해석기에서 풀린 문자열만 찍어 보는 방법으로 이걸 읽을 수 있는 글로 바꿉니다. ATT&CK에서는 난독화를 **T1027 Obfuscated Files or Information**, 실행할 때 푸는 걸 **T1140 Deobfuscate/Decode Files or Information**이라고 부릅니다.

### 실행될 때는 어떻게 보이나 { #script-in-logs }

요즘 가장 흔한 모양은 이렇습니다. 스크립트가 ZIP 안에 담겨 오고, 사용자가 탐색기에서 ZIP을 열고 스크립트를 더블클릭합니다. Windows는 그걸 임시 폴더에 풀고 `wscript.exe`에게 넘깁니다.

```xml
<EventData>
  <Data Name="SubjectUserName">j.kim</Data>
  <Data Name="NewProcessName">C:\Windows\System32\wscript.exe</Data>
  <Data Name="CommandLine">"C:\Windows\System32\WScript.exe" "C:\Users\j.kim\AppData\Local\Temp\Temp1_Invoice_2026.zip\invoice_2026.js"</Data>
  <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
</EventData>
```

- `NewProcessName ... wscript.exe` — Windows Script Host가 시작됐습니다. 대부분의 사무용 PC에서 일반 사용자가 이걸 실행할 일은 없습니다.
- `CommandLine ... \AppData\Local\Temp\Temp1_Invoice_2026.zip\invoice_2026.js` — `Temp1_<이름>.zip` 폴더는 ZIP 안의 파일을 열 때 탐색기가 풀어 두는 곳입니다. "방금 받은 ZIP 안에서 실행된 스크립트"만큼 분명한 신호는 드뭅니다.
- `ParentProcessName ... explorer.exe` — 사용자가 Windows 셸(탐색기)에서 더블클릭했습니다.

보통 몇 초 뒤에 다음 단계가 보입니다. `wscript.exe`가 `powershell.exe`나 `cmd.exe`를 시작하거나, 네트워크 연결을 만듭니다(Sysmon 이벤트 ID 3). 사용자 PC에서 **`wscript.exe` → `powershell.exe`** 부모-자식 짝은 가치가 아주 높은 경보입니다. PowerShell 쪽은 스크립트 블록 로깅(이벤트 ID 4104)이 풀린 코드를 기록해 줍니다. [계정, Defender, PowerShell 이벤트](../important-events/accounts-defender-powershell.md)를 참고하세요.

[보충] 싸고 효과 좋은 방어 두 가지:

- **스크립트 확장자를 메모장에 연결한다.** 그룹 정책으로 `.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`, `.wsh`, `.hta`의 기본 프로그램을 `notepad.exe`로 바꿉니다. 미끼를 더블클릭한 사용자는 실행 대신 알 수 없는 글자만 보게 됩니다. 이 파일이 필요한 관리자는 `cscript.exe`로 직접 실행하면 됩니다.
- Microsoft Defender의 **공격 표면 감소(ASR) 규칙**을 켭니다. 예를 들어 "JavaScript나 VBScript가 다운로드한 실행 콘텐츠를 실행하지 못하게 차단", "난독화됐을 수 있는 스크립트 실행 차단". **AMSI**(Antimalware Scan Interface)는 해석기가 스크립트를 *푼 뒤의* 내용을 백신이 검사하게 해 줘서, 난독화 상당수를 무력화합니다.

## Microsoft Office 문서 { #office }

### 왜 Office가 인기인가 { #why-office }

Office 문서는 어디에나 있고, 사람들은 하루 종일 동료, 고객, 거래처와 주고받습니다. 조직은 `.scr`처럼 `.docx`와 `.xlsx`를 그냥 막을 수 없습니다. 그래서 무기화된 문서는 필터를 통과할 가능성이 높고, "첨부한 청구서 확인 부탁드립니다"가 워낙 평범하니 열릴 가능성도 높습니다. ATT&CK은 전달을 **T1566.001 Phishing: Spearphishing Attachment**, 사용자가 여는 순간을 **T1204.002 User Execution: Malicious File**로 분류합니다.

### 문서가 나쁜 짓을 하는 네 가지 방법 { #office-methods }

**1. 악성 링크.** 문서 안에 그럴듯한 이유와 함께 링크 하나가 들어 있을 뿐입니다("이 문서는 보호되어 있습니다. 온라인에서 보려면 여기를 누르세요"). 순수한 사회 공학입니다. 잡기 어렵습니다. 정상 문서에도 링크가 많고, 시그니처를 만들 매크로나 익스플로잇이 없으니까요. 링크는 보통 자격 증명 피싱 페이지나 다운로드로 이어집니다. 가장 좋은 신호는 URL 평판, 도메인 나이, 그리고 문서를 연 뒤 사용자 브라우저가 한 일입니다.

**2. 삽입 개체(embedded object).** Office의 "개체 삽입" 기능으로 문서 안에 **어떤 종류든 다른 파일**을 넣을 수 있습니다. `.exe`, 스크립트, `.lnk` 등이 아이콘으로 보입니다("청구서를 열려면 더블클릭하세요"). 공격자에게는 더 위험한 방법입니다. 중첩 파일을 꺼내서 재귀적으로 검사하는 메일 필터라면 페이로드를 찾아낼 테니까요. 하지만 그걸 잘하지 못하는 필터도 많습니다. 재미있는 점은, 삽입 개체는 **저절로 실행되지 않는다**는 겁니다. 그래서 모든 걸 눌러 보도록 만들어지지 않은 자동 샌드박스에서는 문서가 깨끗하다고 나올 수 있습니다. 공격자 입장에서 단점은 사람에게도 멈출 기회가 있다는 것입니다. 개체를 열 때 보안 경고가 뜨고, 어떤 사용자는 실수를 깨닫고 문서를 닫습니다. 분석가에게 삽입 개체는 OLE 파일에서는 `\x01Ole10Native`나 `ObjectPool`이라는 스트림으로, ZIP 형식에서는 `word/embeddings/oleObject1.bin` 같은 부분으로 보입니다.

**3. Office 자체를 노린 익스플로잇.** 문서 안에 Word, Excel, 또는 그들이 불러오는 부품의 버그를 건드리는 데이터가 들어 있어서, **열기만 해도**(때로는 미리 보기만 해도) 코드가 실행됩니다. 드물지만, 쓸 만한 게 하나 나오면 빠르게 퍼지고 **꼬리가 깁니다.** 공격자는 Office가 Windows만큼 빨리 패치되지 않는다고 가정하고(대개 맞습니다) 그걸 몇 년씩 계속 씁니다. 대표적인 예가 **CVE-2017-11882**입니다. 옛 수식 편집기(Equation Editor) 부품의 버그인데, 패치가 나오고 여러 해 뒤까지도 피싱에 쓰였습니다. 또 하나는 <strong>CVE-2022-30190 "Follina"</strong>로, 문서가 원격 HTML 파일을 불러와 `ms-msdt:` URL 처리기를 악용했습니다. ATT&CK: **T1203 Exploitation for Client Execution**. 비슷한 수법으로 **원격 템플릿 주입**(**T1221 Template Injection**)이 있는데, `.docx`가 열릴 때 URL에서 템플릿(매크로나 익스플로잇이 들어 있을 수 있음)을 불러옵니다.

**4. 매크로.** 문서 안의 VBA(Visual Basic for Applications) 코드이고, 열 때 자동으로 실행되도록 설정된 경우가 많습니다(`AutoOpen`, `Document_Open`, `Workbook_Open`). 예전에는 이 공격이, 사용자가 경고를 무시하고 <strong>제한된 보기(Protected View)</strong>를 벗어나 노란 막대의 **콘텐츠 사용(Enable Content)** 단추를 누르는 데 달려 있었습니다. 미끼 문서는 "이 문서는 새 버전의 Office로 만들어졌습니다. 보려면 콘텐츠 사용을 누르세요" 같은 말을 했죠. 악성 매크로는 링크나 삽입 파일보다 메일 필터가 찾기 쉽지만, 항상 그런 건 아닙니다. ATT&CK: **T1059.005 Command and Scripting Interpreter: Visual Basic**.

| 방법 | 저절로 실행? | 필터가 잡기 쉬운가? | 주요 신호 |
| --- | --- | --- | --- |
| 링크 | 아니요 — 사용자가 눌러야 함 | 어려움(링크는 흔함) | URL 평판, 도착 페이지, 문서를 연 뒤 브라우저 활동 |
| 삽입 개체 | 아니요 — 사용자가 더블클릭해야 함 | 보통, 필터가 재귀적으로 푼다면 | 문서 안에 든 `.exe`/스크립트/`.lnk` |
| 익스플로잇 | 예, 열거나 미리 볼 때 | 보통(알려진 버그는 시그니처) | Office 프로세스가 이상한 자식을 만들거나 죽음 |
| 매크로 | 대개, 허용되면 | 더 쉬움(매크로 존재와 키워드) | `vbaProject.bin` / VBA 스트림, 자동 실행 이름, Office → 셸 프로세스 |

### 두 가지 형식: 옛 바이너리 형식과 새 ZIP 형식 { #office-formats }

사용자는 거의 눈치채지 못하지만, Office 파일은 기술적으로 아주 다른 두 형식으로 나옵니다.

**2007년 이전 바이너리 형식 — `.doc`, `.xls`, `.ppt`.** OLE <strong>복합 파일(compound file)</strong>입니다. 파일 하나 안에 작은 파일 시스템이 있고, 본문, 서식, 매크로가 각각 "스트림"에 들어 있습니다. 매직 바이트는 `D0 CF 11 E0 A1 B1 1A E1`. 핵심은 이겁니다. **매크로가 있든 없든 확장자가 똑같습니다.** `.doc`에는 매크로가 있을 수도, 없을 수도 있고, 이름으로는 알 수 없습니다. 자동 실행 매크로를 찾으려면 메일 필터가 파일을 뜯어서 해석하거나, 모든 첨부 파일을 샌드박스에서 돌려야 합니다. 꽤 큰일이죠. 그래서 Office 기반 악성코드 상당수가 새 형식이 아니라 `.doc`과 `.xls`로 들어왔습니다.

**Office 2007 이후 XML 형식 — `.docx`, `.xlsx`, `.pptx`**("x"는 XML의 x). XML 파일들을 담은 **ZIP** 압축 파일(매직 `PK\x03\x04`)입니다. 매크로가 있으면 확장자가 반드시 **`m`**으로 끝나야 하고(`.docm`, `.xlsm`, `.pptm`), 매크로 코드는 `vbaProject.bin`이라는 바이너리 부분에 들어 있습니다. 그래서 "`.docm` 첨부 파일 차단" 같은 일괄 규칙을 만들기 쉽습니다. ZIP이니까 `.zip`으로 이름을 바꾸거나 그냥 `unzip -l`을 돌려서 안을 볼 수 있습니다.

```
$ file Remittance_Nov.doc Q4_forecast.xlsm
Remittance_Nov.doc: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Author: admin, Template: Normal.dotm, Last Saved By: user01, Revision Number: 2, Name of Creating Application: Microsoft Office Word, Create Time/Date: Mon Nov 16 08:02:00 2026, Last Saved Time/Date: Mon Nov 16 08:04:00 2026, Number of Pages: 1, Number of Words: 3, Number of Characters: 21

$ unzip -l Q4_forecast.xlsm | grep -E "vba|embed|xl/workbook"
     1567  2026-11-15 22:10   xl/workbook.xml
    23552  2026-11-15 22:10   xl/vbaProject.bin
```

- `Composite Document File V2 Document` — `file`이 OLE 복합 형식을 부르는 이름입니다. 옛 방식 `.doc`입니다.
- `Author: admin`, `Last Saved By: user01` — 문서에 내장된 메타데이터입니다. 이런 흔한 이름은 키트로 찍어 낸 악성 문서에 자주 보입니다.
- `Create Time ... 08:02:00`, `Last Saved ... 08:04:00`, `Revision Number: 2` — 만들고 2분 만에 저장했고, 두 번만 고쳤습니다.
- `Number of Words: 3, Number of Characters: 21` — "송금 내역서"인데 **단어가 세 개**입니다. 진짜 업무 문서에는 내용이 있습니다. 미끼 문서는 "콘텐츠 사용을 누르세요"라는 그림 하나 정도뿐인 경우가 많죠. 메타데이터는 쉽게 꾸밀 수 있으니 증거가 아니라 힌트로만 봅니다.
- `.xlsm`에서는 `unzip -l`이 `xl/vbaProject.bin`을 보여 줍니다. **이 통합 문서에는 매크로가 있습니다.** Word 파일이라면 같은 부분이 `word/vbaProject.bin`입니다.

[정정] "매크로는 `.docm`에만 숨을 수 있다"는 틀렸습니다. `m` 약속은 XML 형식에만 적용됩니다. `.doc`은 아무 표시 없이 매크로를 품을 수 있습니다. 게다가 Word는 확장자만이 아니라 **내용**을 보고 파일을 여는 방법을 정하기 때문에, 매크로가 든 문서를 `.doc` 이름으로 저장해도 열립니다. 공격자는 이걸 이용해 "`.docm` 차단" 규칙을 빠져나갑니다.

### 매크로를 실행하지 않고 들여다보기 { #olevba }

Linux 분석 장비에서는 **oletools**(Python 도구 모음)가 두 형식 모두에서 매크로를 바로 읽어 냅니다. `olevba`는 VBA 소스를 꺼내고 수상한 키워드에 표시를 합니다.

```
$ olevba Remittance_Nov.doc
olevba 0.60.2 on Python 3.12 - http://decalage.info/python/oletools
===============================================================================
FILE: Remittance_Nov.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: Remittance_Nov.doc - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
    Dim a As String
    a = Chr(112) & Chr(111) & Chr(119) & "ershe" & "ll -w hidden -enc " & UserForm1.Tag
    ' ... (fragment shortened for this page)
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|powershell          |May run PowerShell commands                  |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

- `Type: OLE` — `file`이 말한 대로 옛 바이너리 형식입니다.
- `OLE stream: 'Macros/VBA/ThisDocument'` — 복합 파일 안에서 매크로가 사는 위치입니다.
- `Sub AutoOpen()` — 문서가 열릴 때(매크로가 허용되면) Word가 자동으로 실행하는 루틴입니다.
- `Chr(112) & Chr(111) & Chr(119) & "ershe" & "ll ..."` — `Chr(112)`는 `p`, `111`은 `o`, `119`는 `w`입니다. 매크로가 `powershell`이라는 단어를 한 글자씩 조립해서, 단순 키워드 검색에 걸리지 않게 합니다.
- `-w hidden -enc` — PowerShell 옵션으로 "창 숨김", "명령이 Base64로 뒤따름"이라는 뜻입니다. 인코딩된 명령은 문서 안의 폼 속성인 `UserForm1.Tag`에 숨겨 두었습니다. 그래서 매크로 글에도 페이로드가 안 보입니다.
- 키워드 표는 `olevba`의 요약입니다. **AutoExec** 줄은 *언제* 실행되는지, **Suspicious** 줄은 *무엇을* 할 수 있는지 알려 주고, 있다면 **IOC** 줄이 찾아낸 URL, IP, 파일 이름을 보여 줍니다. `--deobf`와 `--decode`는 단순한 난독화를 풀어 달라는 옵션입니다.

같은 도구 모음의 친척들: `oleid`(빠른 위험 개요: 암호화돼 있나? VBA가 있나? 외부 링크가 있나?), `oleobj`(삽입 개체 꺼내기), RTF 파일용 `rtfobj`.

### 문서가 공격할 때는 어떻게 보이나 { #office-in-logs }

방법이 무엇이든 진실의 순간은 대개 같습니다. **Office 프로그램이 시작할 이유가 없는 프로세스를 시작합니다.**

```xml
<EventData>
  <Data Name="SubjectUserName">j.kim</Data>
  <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  <Data Name="CommandLine">powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...</Data>
  <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
</EventData>
```

- `ParentProcessName ... WINWORD.EXE`와 `NewProcessName ... powershell.exe` — Word가 PowerShell을 시작했습니다. Word의 정상 자식 프로세스는 거의 없습니다(인쇄할 때 가끔 `splwow64.exe` 정도). Office → `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`는 SOC가 돌릴 수 있는 가장 가치 높은 탐지 중 하나입니다.
- `-w hidden -enc SQBFAFgA...` — 창 숨김, Base64 인코딩 명령. `SQBFAFgA`를 UTF-16LE Base64로 풀면 `IEX`, 즉 PowerShell의 "이 문자열을 코드로 실행"(`Invoke-Expression`)입니다. (푸는 법은 [Base64](../http-analysis/base64.md)에 있습니다.)

[보충] Microsoft Defender의 ASR 규칙 <strong>"모든 Office 응용 프로그램이 자식 프로세스를 만들지 못하게 차단"</strong>이 정확히 이 사슬을 막고, 많은 EDR이 기본으로 이걸 경보로 띄웁니다.

### 큰 변화: 인터넷에서 온 매크로는 막힌다 { #motw-macros }

Office 문서 감염은 오랫동안 조직에 들어오는 주요 통로 중 하나였습니다. 2022년에 Microsoft가 드디어 기본값을 바꿨습니다. **인터넷에서 온 파일의 VBA 매크로는 차단되고**, 사용자가 단추 하나로 허용할 수도 없게 됐습니다. 노란 "콘텐츠 사용" 막대 대신 빨간 막대가 뜹니다. *"보안 위험 — 이 파일의 원본을 신뢰할 수 없으므로 Microsoft에서 매크로 실행을 차단했습니다."* 이 변화는 버전 2203으로 예고됐다가 잠시 멈췄고, 2022년 중반 현재 채널(Current Channel) 버전 2206부터 배포된 뒤 다른 업데이트 채널로 퍼졌습니다.

Office는 파일이 "인터넷에서 왔다"는 걸 어떻게 알까요? **Mark of the Web**(MotW, 웹의 표시)으로 압니다. 브라우저나 메일 프로그램이 받은 파일을 NTFS 디스크에 저장하면, Windows가 그 파일에 `Zone.Identifier`라는 숨겨진 <strong>대체 데이터 스트림(alternate data stream)</strong>을 붙입니다. 택배 상자에 "해외 발송" 스티커가 붙는 것과 비슷합니다. PowerShell로 읽을 수 있습니다.

```
PS C:\Users\j.kim\Downloads> Get-Content .\Remittance_Nov.doc -Stream Zone.Identifier
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://webmail.corp.example/
HostUrl=https://webmail.corp.example/attachment?id=88213
```

- `Get-Content ... -Stream Zone.Identifier` — 파일의 보통 내용 대신 이름 붙은 대체 데이터 스트림을 읽습니다.
- `[ZoneTransfer]` — 영역(zone) 정보가 시작된다는 머리글입니다.
- `ZoneId=3` — 보안 영역입니다. `0` = 이 컴퓨터, `1` = 로컬 인트라넷, `2` = 신뢰할 수 있는 사이트, **`3` = 인터넷**, `4` = 제한된 사이트. 영역 3이 제한된 보기와 매크로 차단을 일으킵니다.
- `ReferrerUrl`과 `HostUrl` — 어디서 받았는지. 조사할 때 금덩이입니다. 어느 페이지에서, 정확히 어느 다운로드 URL로 받았는지 알려 줍니다. (모든 프로그램이 이 두 줄을 쓰지는 않습니다.)

차단은 MotW가 붙은 파일 **그리고** 신뢰할 수 없는 일부 위치에서 연 파일에 적용됩니다. 관리자는 여전히 신뢰할 수 있는 위치(Trusted Locations), 신뢰할 수 있는 게시자가 서명한 매크로, 정책으로 매크로를 허용할 수 있습니다. [보충] 공격자가 그쪽으로 몰려가자, 2023년에 Microsoft는 인터넷에서 온 **XLL 추가 기능**(사실은 DLL인 Excel 추가 기능)도 막기 시작했고, **OneNote**에 삽입된 위험한 파일 종류도 막기 시작했습니다.

**공격자가 그다음에 한 일**은 변화 자체만큼 중요합니다. 이제 어디를 봐야 하는지 알려 주니까요.

- **MotW를 떨어뜨리는 컨테이너** — 압축을 풀거나 열었을 때 안의 파일이 표시를 물려받지 않는 ISO, IMG, VHD, 7z, ZIP 파일(**T1553.005 Subvert Trust Controls: Mark-of-the-Web Bypass**). Microsoft가 2022년 11월에 ISO/IMG 경우를 패치했지만, MotW를 물려주지 않는 도구와 압축 프로그램 문제는 계속 다시 나옵니다.
- **바로 가기(`.lnk`) 파일**, 흔히 그 컨테이너 안에 들어 있고 `cmd`, `powershell`, `mshta`, `rundll32`를 실행합니다.
- **HTML 스머글링**(**T1027.006**) — HTML 첨부 파일의 JavaScript가 브라우저 안에서 페이로드를 조립합니다.
- **OneNote, XLL, SVG, MSC, 링크 든 PDF 같은 "덜 흔한" 형식** — 다음 페이지에서 다룹니다.

## 정리 — 분류 순서 { #triage-routine }

의심 파일이 나에게 오면:

1. **해시를 구해서 조회한다.** 다른 무엇보다 먼저(평판, 본 사람이 있나?).
2. **`infected` ZIP에 넣어** 새 스냅숏을 찍은 격리 분석 장비로 옮긴다.
3. **바이트로 알아본다.** 이름이 아니라 `file`과 헥스 보기로.
4. **가족을 고른다.** 실행 파일, 스크립트, 문서, 기타. 그리고 맞는 도구를 쓴다. 실행 파일은 `strings`와 PE 도구, 스크립트는 텍스트 뷰어와 난독화 해제, Office는 `oleid`/`olevba`/`unzip -l`.
5. **결정적 단서를 찾는다.** 자동 실행 매크로 이름, 삽입 개체, 난독화된 한 줄짜리 스크립트, URL, 문서인 척하는 `.cpl`이나 `.scr`.
6. **엔드포인트 로그에서 실행 패턴을 확인한다.** 다운로드 폴더에서 `rundll32 ... Control_RunDLL`, `Temp1_*.zip` 폴더에서 `wscript.exe`, 셸을 띄우는 Office. 그리고 같은 해시나 URL이 다른 PC에도 있는지.
7. **VM을 되돌리고** 찾은 것(해시, URL, 파일 이름, ATT&CK 기법)을 티켓에 기록한다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    안전한 분석 환경의 네 규칙(잃어도 되는 장비, 격리된 네트워크, 잠근 호스트, 스냅숏·되돌리기 VM), 정적 분석을 위한 OS 엇갈리기 요령, `infected` ZIP 약속은 모두 지금도 표준 관행입니다. MalwareBazaar 같은 샘플 공유 서비스도 여전히 비밀번호 `infected`를 건 ZIP으로 샘플을 나눠 줍니다. "실행 파일"은 `.exe` 확장자가 아니라 PE 형식이라는 것, 스크립트가 실행 파일만큼 위험하다는 것, Office 문서가 링크·삽입 개체·익스플로잇·매크로로 공격한다는 것도 그대로입니다. 실행 시점의 가장 좋은 탐지도 여전히 부모-자식 프로세스 짝입니다. 셸을 띄우는 Office나 `wscript.exe`, 사용자 폴더의 파일을 불러오는 `rundll32`/`regsvr32`/`msiexec`.

!!! info "[변경됨] 바뀐 점"
    - **인터넷에서 온 매크로는 기본으로 막힙니다.** Microsoft 365 Apps와 최신 Office 버전에서(2022년 중반부터 배포, 파일에 Mark of the Web이 있어야 함). 그 뒤로 매크로를 쓴 `.doc`/`.xls` 피싱은 크게 줄었습니다. 2023년에는 **인터넷에서 온 XLL 추가 기능**도 막혔고, 같은 해 OneNote가 위험한 삽입 파일을 막기 시작했습니다.
    - **전달 수단이 옮겨 갔습니다.** ISO/IMG/VHD/ZIP 컨테이너, `.lnk` 바로 가기, HTML 스머글링, OneNote, 스크립트나 리디렉션을 품은 SVG 파일, `.msc`(관리 콘솔) 파일, 자격 증명 피싱 페이지로 이어지는 PDF와 QR 코드. 2025년까지의 업계 보고서들은 특히 SVG와 압축 파일 기반 전달이 빠르게 늘고 있다고 보여 줍니다.
    - **VBScript가 은퇴하는 중입니다.** Microsoft는 2023년에 VBScript를 지원 중단(deprecated) 예정으로 발표했고, Windows 11 24H2에서는 아직 기본으로 켜져 있는 "주문형 기능(feature on demand)"이 됐습니다. 이후 단계에서 기본으로 끄고 결국 없앨 계획입니다. 탐지를 짤 때 이걸 염두에 두되, 우리 조직 PC에서 이미 없어졌다고 가정하지는 말고 직접 확인하세요.
    - **PowerShell 7은 Linux와 macOS에서 돕니다.** 그래서 OS 엇갈리기 규칙에서 `.ps1`은 더 이상 Windows 전용 파일이 아닙니다.
    - **분석 도구가 성숙했습니다.** REMnux와 FLARE-VM이 흔한 분석 배포판이고, Office 파일에는 여전히 oletools가 표준이며, 많은 샌드박스가 이제 스크립트와 매크로의 AI 요약을 붙여 줍니다. 쓸모 있지만 실제 코드로 확인하세요.
    - **이 페이지에서 쓴 ATT&CK 이름**: T1204.002 Malicious File, T1566.001 Spearphishing Attachment, T1218.002 Control Panel, T1218.005 Mshta, T1218.007 Msiexec, T1218.010 Regsvr32, T1218.011 Rundll32, T1546.002 Screensaver, T1574.002 DLL Side-Loading, T1059.001/.003/.004/.005/.006/.007, T1027, T1027.006 HTML Smuggling, T1140, T1203, T1221 Template Injection, T1553.005 Mark-of-the-Web Bypass.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **확장자 차단 목록에만 기대지 마세요.** 진짜 파일 형식으로 막고 검사하고, PE 가족 전체, 스크립트, `.hta`, `.lnk`, `.iso`/`.img`/`.vhd`, `.one`, `.msc`, `.svg`까지 생각에 넣으세요.
    - **"매크로가 기본으로 막히니 안전하다"고 가정하지 마세요.** 정책이 매크로를 다시 켤 수 있고, 신뢰할 수 있는 위치는 차단을 비켜 가고, MotW가 없는 파일(일부 압축 파일, USB, 내부 공유 폴더에서 온 것)은 적용되지 않고, 공격자가 매크로를 아예 안 쓸 수도 있습니다.
    - **샘플을 이메일로 보내지 마세요. 압축했더라도.** 게이트웨이가 암호화 압축 파일을 막을 수 있고, 잘못 보낸 샘플은 그 자체로 사고입니다. 사건 관리 시스템이나 보안 공유를 쓰고, ZIP의 파일 이름은 보인다는 걸 기억하세요.
    - **삽입 개체나 링크가 든 문서의 "깨끗함" 샌드박스 판정을 믿지 마세요.** 아무것도 누르지 않았으니 아무것도 실행되지 않은 것뿐입니다.
    - **정적 분석 장비에 "편하려고" PowerShell, Office, Java, Wine을 깔지 마세요.** 하나하나가 나를 지켜 주는 OS 엇갈리기를 없앱니다.
    - **`.js`를 "그냥 JavaScript"로 보지 마세요.** Windows에서는 `wscript.exe`가 사용자의 모든 권한으로 실행합니다.

## 확인 문제 { #quiz }

### 문제 1

동료가 수상한 첨부 파일 `Payment_Advice.xls`를 살펴보려고 이렇게 계획합니다. 격리 공유 폴더에서 자기 노트북으로 끌어서 놓아 복사하고, 그 노트북의 Windows VM에서 "매크로를 끈 채로" Excel로 열고, 다 보면 나에게 이메일로 보낸다. 이 계획에서 무엇이 잘못됐는지 짚고, 안전한 방법을 단계별로 말하세요.

??? success "정답과 해설"
    **잘못된 점:** (1) 끌어서 놓기는 파일을 실행 가능한 상태로 옮깁니다. 실수로 한 번 더블클릭하면 실행되고, 노트북의 백신이 지우고 경보를 띄울 수 있습니다. (2) 노트북은 회사 네트워크에 붙은 일상용 장비라서 "잃어도 되는 시스템"과 "떨어진 네트워크" 규칙을 둘 다 어깁니다. (3) `.xls`를 **Excel**로 여는 건 그 파일이 공격하도록 만들어진 바로 그 프로그램을 쓰는 겁니다. 익스플로잇은 매크로가 필요 없고, "매크로 끔"은 클릭 한 번이나 정책으로 풀릴 수 있습니다. (4) 이메일로 보내면 게이트웨이에 막히거나, 엉뚱한 사람에게 가거나, 자동 검사로 격리될 수 있습니다.

    **안전한 방법:** 해시를 구하고(`sha256sum`) 조회합니다. `7z a -tzip -pinfected -mem=AES256 ...`로 묶습니다. ZIP을 격리된 네트워크의 전용 분석 장비로 옮깁니다. VM 스냅숏을 찍습니다. Office가 없는 **Linux** 분석 VM에서 풉니다(OS 엇갈리기). `file`(`Composite Document File V2`가 나올 것)과 `oleid`/`olevba`로 매크로, 자동 실행 이름, IOC를 봅니다. 스냅숏으로 되돌립니다. 결과와 해시는 사건 관리 시스템으로 공유하고, 샘플이 필요하면 `infected` ZIP으로 보안 공유를 통해 넘깁니다.

### 문제 2

이메일 게이트웨이는 `.exe`, `.bat`, `.docm`을 막습니다. 한 주 동안 첨부 파일 세 개가 통과했습니다. `Holiday_Photos.scr`, `invoice_view.cpl`, `Remittance_Nov.doc`. 각각 왜 통과했는지, 어떻게 실행되는지, 실행되면 로그에 어떤 패턴이 보이는지 하나씩 말하세요.

??? success "정답과 해설"
    **`Holiday_Photos.scr`** — 화면 보호기는 평범한 PE 실행 파일(`MZ`)인데 확장자가 차단 목록에 없었습니다. 더블클릭하면 바로 실행됩니다. 로그: `NewProcessName`이 `Holiday_Photos.scr`로 끝나고(흔히 다운로드나 Temp 경로), 부모가 `explorer.exe`나 메일 프로그램인 이벤트 4688. ATT&CK T1204.002, 지속성을 위해 화면 보호기로 지정했다면 T1546.002.

    **`invoice_view.cpl`** — 제어판 항목은 PE DLL이고, 확장자가 막혀 있지 않았습니다. 더블클릭하면 `control.exe`로 가고, 그게 `rundll32.exe Shell32.dll,Control_RunDLL "<경로>.cpl"`을 실행합니다. 로그: `Control_RunDLL`과 `\Users\...\Downloads\` 아래 `.cpl`이 명령줄에 있고 부모가 `control.exe`인 `rundll32.exe`의 4688. ATT&CK T1218.002.

    **`Remittance_Nov.doc`** — 옛 바이너리 형식은 확장자를 바꾸지 않고 매크로를 품기 때문에 "`.docm` 차단"이 건드리지 못합니다. 게이트웨이가 VBA를 찾으려면 OLE 파일을 해석해야 합니다. 사용자가 열고 매크로가 실행되거나(MotW 정책으로 막히지 않았다면), 익스플로잇으로 실행됩니다. 로그: `ParentProcessName`이 `WINWORD.EXE`이고 자식이 `powershell.exe -w hidden -enc ...` 같은 4688. ATT&CK T1566.001, T1204.002, T1059.005.

    셋 모두의 해법: 확장자가 아니라 **진짜 파일 형식**으로 막거나 검사하고, Office 파일은 VBA가 있는지 해석해서 봅니다.

### 문제 3

(a) PDF 리더는 양쪽 OS에 다 있는데도, Windows를 노린 것으로 보이는 악성 PDF를 Linux에서 분석하는 게 왜 여전히 더 안전한가요? (b) 받은 `.zip`을 `7z l`로 보니 비밀번호를 모르는데도 `Path = CEO_J_Smith_passwords.xlsx`가 보입니다. 압축 파일이 고장 난 건가요? 이게 무슨 뜻이고, 어떻게 피하나요? (c) 삽입 개체가 든 Office 문서가 자동 샌드박스에서 "깨끗함"으로 나올 수 있는 이유 두 가지를 말하세요.

??? success "정답과 해설"
    **(a)** 공격자는 거의 항상 피해자가 Windows라고 가정하므로, 익스플로잇의 코드나 그게 받아서 실행하는 페이로드가 Windows용 코드입니다. Linux에서는 사슬이 끊깁니다. 또 익스플로잇은 보통 한 OS의 특정 리더 하나를 노리고 만들어지고, 여러 OS **그리고** 서로 다른 PDF 리더에서 모두 통하게 만들기는 어렵습니다. 어렵지 불가능하지는 않으니, 그래도 격리된 VM과 스냅숏을 씁니다.

    **(b)** 고장 난 게 아닙니다. 일반 ZIP 암호화는 **내용**만 보호하고, 이름·크기·날짜는 암호화 안 된 헤더에 있어서 누구나 목록을 볼 수 있습니다. 그래서 민감한 정보(여기서는 사람 이름)가 샐 수 있습니다. 헤더 암호화를 켠 7z 형식(`7z a -t7z -pinfected -mhe=on ...`)을 쓰거나, 묶기 전에 안의 파일 이름을 중립적인 이름(예: 해시 + `.bin`)으로 바꿉니다.

    **(c)** 다음 중 둘: 삽입 개체는 **저절로 실행되지 않고** 사용자의 더블클릭이 필요한데 샌드박스가 그걸 안 할 수 있다. 개체를 열 때 뜨는 보안 확인 창을 사람이 허용해야 한다. 샌드박스가 중첩 파일을 재귀적으로 꺼내서 검사하지 않을 수 있다. 미끼가 사용자에게 링크를 누르거나 무언가를 허용하라고 해야 비로소 일이 벌어진다.

## 관련 레퍼런스 { #related }

- [파일 알아보기 — 매직 바이트, 중첩 파일, 유니코드와 인코딩](file-identification.md) · [문자열](strings.md)
- [스크린샷, 샌드박스, 그리고 수동 분석으로 넘어갈 때](../http-analysis/screenshots-sandboxes.md) · [Base64](../http-analysis/base64.md)
- [프로세스 생성 이벤트](../important-events/process-creation.md) · [계정, Defender, PowerShell 이벤트](../important-events/accounts-defender-powershell.md)
- [애플리케이션 제어, 파일 무결성 모니터링, 지속성 잡기](../endpoint-defense/appcontrol-fim-persistence.md) · [최초 침투](../endpoint-attacks/initial-exploitation.md)
- [피싱 전달과 최초 실행](../../../adversary/phishing-delivery.md) · [LOLBins](../../../adversary/lolbins.md) · [PowerShell 다운로드 크래들](../../../adversary/powershell-cradles.md)
