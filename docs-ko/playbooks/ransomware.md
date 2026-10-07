---
title: 랜섬웨어
tags:
  - playbook
  - ransomware
---

# 랜섬웨어 대응 { #ransomware-response }

<div class="dfir-meta" markdown>
**시나리오:** 파일 암호화, 랜섬 노트 발견, 또는 대량 파일 이름 변경 진행 중 · **최종 수정:** 2026-09-17
</div>

!!! abstract "언제 쓰나"
    대량 파일 암호화나 랜섬 노트(`*.README.txt`, `HOW_TO_DECRYPT.*`), 새 확장자로 갑작스러운 파일 이름 변경 폭풍, 섀도 복사본 삭제, 백업 변조. 랜섬웨어는 보통 며칠 또는 몇 주 동안 이어진 침입의 **끝**입니다 — 암호화를 사고 전체가 아니라 마지막 단계로 다루세요.

!!! danger "먼저: 아직 진행 중인가?"
    암호화가 진행 중이라면 퍼지고 있는 호스트에 대해서는 **수집보다 봉쇄가 우선**입니다 — 지금 바로 네트워크에서 격리하세요(스위치 포트 비활성화 / 케이블 뽑기 / EDR 격리; 전원은 **끄지 마세요** — RAM과 실행 중인 키를 잃습니다). 하지만 몇 초 안에 할 수 있다면 감염된 호스트 최소 한 대의 RAM부터 확보하세요 — 키 자료와 실행 중인 암호화 도구가 메모리에 있을 수 있습니다.

## 1. 트리아지 (첫 15분) { #1-triage-first-15-minutes }

- 범위 확인: 어떤 호스트, 어떤 공유, 얼마나 빨리 퍼지나? 파일 서버 로그와 EDR에서 이름 변경 폭풍을 확인하세요.
- **변종**을 식별하세요: 랜섬 노트 이름, 덧붙은 확장자, 노트 내용이 보통 이름을 알려 줍니다 — 노트 샘플 + 암호화된 파일로 [ID-Ransomware / No More Ransom]을 검색하세요. **복호화 도구가 있는지**, 그 그룹이 **데이터를 유출하는지**(이중 협박) 알 수 있습니다.
- 조치가 무언가를 건드리기 전에 감염 호스트 한 대의 **RAM**([이미징](../tools/imaging-collection.md))과 암호화된 파일 샘플 + 노트를 보존하세요.
- 자기 권한으로 몸값을 지불하거나 협상하지 **마세요** — 그건 경영진/법무/보험의 결정입니다. 노트나 암호화된 파일을 지우지 마세요.

## 2. 수집 { #2-collect }

| 출처 | 무엇 | 방법 |
|---|---|---|
| 감염 호스트 RAM | 실행 중인 암호화 도구, 키 | [WinPmem / FTK](../tools/imaging-collection.md) — 가능하면 격리로 프로세스가 죽기 전에 |
| 트리아지 아티팩트 (최초 감염 + 전파 호스트) | 실행, 지속성, 횡적 이동 | [KAPE `!SANS_Triage`](../tools/kape.md) 또는 [Velociraptor](../tools/velociraptor.md) 헌트 |
| `$MFT` + `$UsnJrnl` | 암호화 타임라인 — 정확한 시작, 폴더 순서, 파일 수 | [MFT/USN](../windows/mft-usn.md) — `$J`가 이름 변경 폭풍의 시작/끝과 순회 순서를 보여 줌 |
| 이벤트 로그 | 배포 방법, 로그 삭제 | [Event logs](../windows/event-logs.md) — `7045`, `4688`, `1102`, `4104` |
| 백업 | 상태, 공격자가 지우거나 암호화했는지 | 백업 콘솔 + `vssadmin`/`wbadmin` 이력 |
| 네트워크 | C2 (암호화 전), 유출 (이중 협박) | [Zeek](../network/index.md) / [Arkime](../network/arkime/index.md) / [SRUM](../windows/srum.md) |

## 3. 분석 — 침입 전체를 재구성 { #3-analyse-reconstruct-the-whole-intrusion }

암호화는 N단계입니다; 1…N−1단계를 찾으세요:

- **암호화 타임라인과 최초 감염**: `$UsnJrnl`이 처음 암호화된 파일과 호스트를 정확히 알려 줍니다 — [MFT/USN 대량 활동 헌팅](../windows/mft-usn.md). 가장 먼저 시작한 호스트가 보통 배포가 실행된 곳입니다.
- **배포 방법**: 여러 호스트에서 동시에 암호화됐다면 밀어 넣기를 뜻합니다 — GPO, PsExec, PDQ, 또는 도메인 컨트롤러. [PsExec/SMB](../adversary/psexec-smb.md) `7045`, [WMI/WinRM](../adversary/wmi-winrm.md), 또는 전사에 배포된 예약 작업([지속성](../adversary/persistence.md))을 찾으세요.
- **섀도 복사본 / 백업 파괴** (암호화 직전에 실행): `vssadmin delete shadows`, `wbadmin delete`, `bcdedit /set recoveryenabled no`, `wevtutil cl` — [LOLBin 명령줄 검색](../splunk/security-searches.md#what-ran)으로 잡으세요.
- **최초 침투와 체류**: 거꾸로 추적하세요 — [비코닝/C2](../network/beaconing-c2.md), [자격증명 덤프](../adversary/lsass-dumping.md), [횡적 이동](../adversary/psexec-smb.md), [피싱 전달](../adversary/phishing-delivery.md). 그 그룹은 아마 며칠 동안 안에 있었을 겁니다.
- **유출** (이중 협박): 암호화 전의 큰 업로드 — [데이터 유출 플레이북](data-exfiltration.md), [SRUM](../windows/srum.md), Zeek `orig_bytes`.

## 4. 봉쇄 / 제거 { #4-contain-eradicate }

- 감염된 호스트와 인접 호스트를 모두 격리하고, 배포에 쓰인 계정과 수단(GPO, 서비스, 작업)을 비활성화하세요.
- DC나 도메인 관리자가 관련됐다면 **도메인 전체의 자격증명을 재설정**하세요 — 모든 해시가 덤프됐다고 가정하고([LSASS](../adversary/lsass-dumping.md)) `krbtgt`를 **두 번** 교체하세요.
- 손댄 모든 호스트에서 지속성을 제거하세요 ([Autoruns / ASEP](../adversary/persistence.md)).
- 출구에서 C2와 유출 인프라를 차단하세요.
- 최초 침투 경로가 막혔다는 걸 확인하기 전에는 호스트를 되살리지 마세요. 그러지 않으면 다시 암호화됩니다.

## 5. 복구와 교훈 { #5-recover-lessons }

- 체류 기간이 시작되기 전에 만든 **확실히 깨끗한 백업**으로 재구축하세요 (깨끗하고 공격자가 변조하지 않았는지 검증). 일부 변종은 복호화 도구가 있으니 전부 잃었다고 가정하기 전에 확인하되, 공격자의 복호화 도구는 절대 맹신하지 마세요.
- 침해된 환경이 아니라 **정리되고 자격증명이 재설정된** 환경에서 복원하세요.
- 법적/규제 의무에 따라 보고하세요 (호주에서는 OAIC 신고 대상 데이터 유출(NDB) 제도와 업종별 규정을 고려하고, 일찍 경영진/법무로 올리세요).
- 사고 후: 최초 침투 경로를 패치하고, EDR + Sysmon을 배포/확대하고, [스크립트 블록 로깅](../adversary/powershell-cradles.md)을 켜고, 백업을 보호하고(오프라인/불변), 관리자 계정을 계층화하세요.

## 유용한 쿼리 { #useful-queries }

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval cmd=lower(CommandLine)
| where match(cmd,"vssadmin.*delete|wbadmin.*delete|bcdedit.*(recoveryenabled|bootstatuspolicy)|wevtutil\s+cl|wmic.*shadowcopy.*delete|shadowcopy delete")
| table _time, host, User, Image, cmd
| sort 0 _time
```

섀도 복사본과 백업 삭제는 거의 항상 암호화 직전에 일어납니다. `vssadmin delete shadows`는 복원 지점을 지우고, `bcdedit /set recoveryenabled no`는 Windows 복구를 끄며, `wevtutil cl`은 로그를 지웁니다 — 이 명령들의 호스트와 시각을 찾으면 배포 순간과 호스트를 정확히 짚을 수 있습니다.

```spl
index=botsv3 sourcetype="WinEventLog:System" EventCode=7045
| table _time, host, Service_Name, Service_File_Name | sort 0 _time
```

많은 랜섬웨어 계열과 배포 도구(PsExec)는 서비스를 설치합니다 — 짧은 시간 안에 많은 호스트에 걸친 `7045`가 밀어 넣기를 보여 줍니다.

## 참고 자료 { #references }

- [No More Ransom (decryptors + ID)](https://www.nomoreransom.org/) · [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
- [CISA — #StopRansomware guide](https://www.cisa.gov/stopransomware)
- [OAIC — Notifiable Data Breaches (AU)](https://www.oaic.gov.au/privacy/notifiable-data-breaches)
- 관련 페이지: [MFT/USN](../windows/mft-usn.md) · [PsExec/SMB](../adversary/psexec-smb.md) · [LSASS 덤프](../adversary/lsass-dumping.md) · [데이터 유출](data-exfiltration.md)
