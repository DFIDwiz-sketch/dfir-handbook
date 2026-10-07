---
title: 데이터 유출
tags:
  - playbook
  - exfiltration
---

# 데이터 유출 { #data-exfiltration }

<div class="dfir-meta" markdown>
**시나리오:** 데이터 탈취 의심 — 큰 업로드, 압축 파일 준비, DLP 경보 · **최종 수정:** 2026-09-17
</div>

!!! abstract "언제 쓰나"
    DLP 경보, 평소와 다른 큰 아웃바운드 전송, 임시 폴더에 나타난 준비용 압축 파일, 또는 이중 협박 랜섬 위협. 조사 목표는 구체적입니다: **어떤 데이터가, 얼마나, 어떤 경로로, 어디로, 언제 나갔나** — 이 답들이 법적/규제상 통지와 피해 범위를 결정하기 때문입니다.

## 1. 트리아지 (첫 15분) { #1-triage-first-15-minutes }

- **경로**를 확정하세요: 웹 업로드 (클라우드 스토리지로 HTTPS), 클라우드 동기화 클라이언트 (rclone/MEGA/Dropbox), 이메일 첨부, DNS 터널, SSH/SFTP 세션, 또는 물리 매체 (USB).
- 네트워크/호스트 텔레메트리로 **대략적인 양과 시간 창**을 확정하세요 — 아직 진행 중인가?
- **준비 단계**(공격자는 보통 보내기 전에 모아서 압축함)와 **목적지**를 파악하세요.
- 진행 중이라면, 무엇이 나갔는지 증명할 만큼 확보한 뒤 경로를 봉쇄하세요 (목적지 차단, 세션 종료).

## 2. 수집 { #2-collect }

| 출처 | 보여 주는 것 | 어디서 |
|---|---|---|
| [SRUM](../windows/srum.md) | 사용자와 함께 **앱별·시간별 보낸 바이트** | 호스트 쪽 최고의 유출 아티팩트 |
| [$MFT / $UsnJrnl](../windows/mft-usn.md) | 준비용 압축 파일(`.zip/.7z/.rar`) 생성 후 삭제; 무엇을 모았나 | 압축 파일에 대한 `FileCreate` + `DataExtend`, 그다음 `FileDelete` |
| [Zeek `conn.log`](../network/zeek/conn-log.md) | 쌍별 `orig_bytes` — 누가 어디로 얼마나 올렸나 | 네트워크 쪽 양 |
| [Zeek `files.log`](../network/zeek/files-log.md) / [http.log](../network/zeek/http-log.md) | `is_orig=T` 업로드, 해시, 목적지 | 어떤 파일을 어디로 |
| [Zeek `dns.log`](../network/zeek/dns-log.md) | DNS 터널 양 | 경로가 DNS라면 |
| [Arkime](../network/arkime/hunting-workflows.md#workflow-6-exfiltration) | 전송의 전체 세션 + pcap | 증거 + 내용 |
| 클라우드/프록시/DLP 로그 | 허가된/허가되지 않은 SaaS로의 업로드 | 프록시, CASB, M365/Google 감사 |
| USB 아티팩트 | 장치 + 이동식 매체로 복사된 파일 | [레지스트리 USB 키](../windows/registry-keys.md#usb-removable-devices-system), [E:\\를 가리키는 LNK](../windows/lnk-jumplists.md) |

## 3. 분석 { #3-analyse }

- **무엇이 준비됐나**: `$UsnJrnl`이 압축 파일 생성과 크기를 보여 주고([MFT/USN 유출 패턴](../windows/mft-usn.md)), 그 직전에 만들어진 파일들이 수집물입니다. 압축 파일이 아직 있다면 내용이 정확히 무엇을 가져갔는지 알려 주고, 삭제됐다면 `$MFT`에 크기와 이름이 남아 있을 수 있습니다.
- **얼마나, 어디로 나갔나**: [SRUM](../windows/srum.md)이 사용자와 함께 앱별·시간별 바이트를 주고, 목적지별 [Zeek `conn.log` `orig_bytes`](../network/zeek/conn-log.md)와 상관분석하세요. 밤에 수백 MB를 보내는 `rclone.exe`/`megasync.exe`/`winscp.exe`/`curl.exe` 같은 도구가 후보입니다.
- **경로와 목적지**: 클라우드 스토리지로의 [http.log](../network/zeek/http-log.md) POST/PUT, [ssl.log SNI](../network/zeek/ssl-x509.md) (mega.nz, dropbox, drive.google, VPS), 터널링은 [dns.log](../network/zeek/dns-log.md), 또는 긴 SSH/SFTP 세션. 내용을 증명해야 한다면 [Arkime](../network/arkime/index.md)에서 pcap을 꺼내세요.
- **타임라인**: SRUM의 시간 구간 + `$J` 타임스탬프 + Zeek `ts`로 보고서에 쓸 정확한 "데이터가 X와 Y 사이에 나갔다"가 나옵니다.
- **USB 경로**: 이동식 매체라면 [MountPoints2 / USBSTOR](../windows/registry-keys.md#usb-removable-devices-system)가 장치를 사용자와 연결하고, `E:\`를 가리키는 [LNK 파일](../windows/lnk-jumplists.md)이 그곳에서 열거나 복사한 파일을 보여 줍니다.

## 4. 봉쇄 / 제거 { #4-contain-eradicate }

- 출구에서 목적지 도메인/IP를 차단하고; 사용된 계정이나 세션을 비활성화하고; 클라우드 동기화 도구가 설치됐다면 제거하고 그것이 쓴 토큰/앱을 폐기하세요.
- 유출이 더 큰 침입과 함께 일어났다면(보통 그렇습니다) [횡적 이동 / 도메인 플레이북](lateral-domain.md)으로 넘어가 관련 자격증명을 재설정하세요.
- 모든 것을 보존하세요 — 유출 사고는 자주 법적/규제 사안이 됩니다; 압축 파일, 로그, pcap의 증거 관리 연속성을 유지하세요.

## 5. 복구와 교훈 { #5-recover-lessons }

- **어떤 데이터**가 나갔는지(개인정보, 규제 대상 데이터)에 따라 통지 의무를 판단하세요. 호주에서는 **신고 대상 데이터 유출(NDB)** 제도(OAIC)와 업종별 규정에 비추어 평가하고, 일찍 법무/개인정보 담당을 참여시키세요.
- 강화: 출구에 DLP, 허가되지 않은 클라우드 스토리지와 터널링 도구 차단/모니터링, 호스트별 큰 `orig_bytes`와 압축 후 업로드 패턴에 경보, USB 제한/모니터링, 그리고 이상이 눈에 띄도록 평소 업로드 양의 기준선 잡기.

## 유용한 쿼리 { #useful-queries }

```spl
index=botsv3 sourcetype=stream:tcp
| where NOT cidrmatch("10.0.0.0/8",dest_ip) AND NOT cidrmatch("192.168.0.0/16",dest_ip) AND NOT cidrmatch("172.16.0.0/12",dest_ip)
| stats sum(bytes_out) as out, sum(bytes_in) as in by src_ip, dest_ip, dest_port
| eval out_MB=round(out/1048576,1), ratio=round(out/(in+1),1)
| where out_MB > 100 AND ratio > 5
| sort - out_MB
```

내부→외부 쌍별로 나간 바이트와 들어온 바이트를 더합니다. `ratio` = 보낸 양 ÷ 받은 양; 외부 IP로 받은 것보다 5배 넘게, 수백 MB를 보낸 호스트는 업로드 중입니다. `out_MB`가 보고서용 수치를 줍니다.

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=11 TargetFilename IN ("*.zip","*.7z","*.rar","*.tar","*.gz")
| where match(TargetFilename,"(?i)\\\\(temp|users\\\\public|programdata|windows\\\\temp|perflogs|appdata)\\\\")
| table _time, host, User, Image, TargetFilename
| sort 0 _time
```

Sysmon `11` = 파일 생성. 준비 폴더(`Temp`, `Public`, `ProgramData`)에 쓰인 압축 파일은 유출 전 수집 단계입니다 — 그것을 만든 프로세스(`Image`)와 시점이 행위자와 "무엇을 가져갔나"를 가리킵니다.

## 참고 자료 { #references }

- [MITRE ATT&CK — Exfiltration (TA0010)](https://attack.mitre.org/tactics/TA0010/) · [Collection (TA0009)](https://attack.mitre.org/tactics/TA0009/)
- [OAIC — Notifiable Data Breaches (AU)](https://www.oaic.gov.au/privacy/notifiable-data-breaches)
- 관련 페이지: [SRUM](../windows/srum.md) · [MFT/USN](../windows/mft-usn.md) · [Zeek conn/http/dns](../network/index.md) · [Arkime 유출 워크플로](../network/arkime/hunting-workflows.md) · [비코닝과 C2](../network/beaconing-c2.md)
