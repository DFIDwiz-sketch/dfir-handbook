---
title: Linux 권한 상승
tags:
  - oscp
---

# Linux 권한 상승 { #linux-privilege-escalation }

<div class="dfir-meta" markdown>
**배점:** Linux standalone 대당 10점 (`proof.txt`) · **최종 수정:** 2026-10-23
</div>

!!! abstract "한 문장 요약"
    저권한 셸에서 root까지. 먼저 꼼꼼히 정보를 모으고, 흔한 설정 실수를 순서대로 확인하고, 커널 익스플로잇은 마지막에 씁니다.

!!! note "이 페이지 구성"
    공부 체크리스트입니다. 정보 수집 스크립트의 출력을 읽는 법을 익히세요 — 답은 거의 항상 이미 화면에 있고, 실력은 그걸 알아보는 데 있습니다. Proving Grounds Linux 박스로 연습하세요 → [실습 랩](practice-labs.md).

## 0. 먼저 셸 안정화 { #shell-upgrade }

날것의 리버스 셸은 탭 완성도, 방향키도 없고 Ctrl-C에 죽습니다. 다른 걸 하기 전에 업그레이드하세요:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 그다음: Ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

## 1. 정보 수집 { #enumeration }

자동 스크립트를 돌리고 **그리고** 직접 읽으세요 — 스크립트는 뻔한 걸 잡아 주고, 미묘한 건 사람이 잡습니다.

```bash
./linpeas.sh | tee linpeas.txt      # 빨강/노랑 강조 = 가장 눈여겨볼 것
```

아래는 항상 손으로도 확인:

```bash
id; sudo -l                 # 비밀번호 없이 root로 실행 가능한 것?
find / -perm -4000 -type f 2>/dev/null   # SUID 바이너리
getcap -r / 2>/dev/null     # capabilities
crontab -l; cat /etc/crontab; ls -la /etc/cron.*
uname -a; cat /etc/os-release            # 커널 / 배포판 버전
ps aux --forest             # 실행 중 서비스, 소유자
netstat -tulpn              # localhost 전용 서비스 → 포트 포워딩 후보
```

## 2. 흔한 경로를 순서대로 { #vectors }

가장 쉽고 확실한 것부터:

| 경로 | 볼 것 | 단서 |
|---|---|---|
| **sudo 규칙** | `sudo -l` 이 root로 실행 가능한 바이너리를 보여줌 | [GTFOBins](https://gtfobins.github.io/)에서 찾기 — 대부분 탈출법이 문서화돼 있음 |
| **SUID 바이너리** | 표준 집합이 아닌 특이한 SUID 바이너리 | 역시 GTFOBins; 커스텀 바이너리는 상대 경로로 뭔가를 호출할 수도 |
| **Capabilities** | 바이너리의 `cap_setuid`, `cap_dac_read_search` | GTFOBins "Capabilities" 섹션 |
| **Cron 작업** | 내가 쓸 수 있는 스크립트를 돌리는 root cron, 또는 와일드카드 사용 | 스크립트를 고치거나 와일드카드 악용(`tar`/`rsync` 트릭) |
| **쓰기 가능한 `PATH` / 스크립트** | root 프로세스가 명령을 이름으로 호출하는데 그 디렉터리에 내가 쓸 수 있음 | `PATH` 앞쪽에 악성 바이너리 넣기 |
| **디스크의 크리덴셜** | 설정 파일, history, `.ssh`, DB 파일, 웹앱 설정의 비밀번호 | `su`, SSH, 다른 서비스에 재사용 |
| **쓰기 가능한 `/etc/passwd`** | 파일이 모두 쓰기 가능 | 알려진 비밀번호의 root-UID 사용자 추가 |

## 3. 크리덴셜과 내부 서비스 { #credentials }

권한 상승은 흔히 그냥 **크리덴셜 재사용** 입니다:

```bash
cat ~/.bash_history ~/.*_history 2>/dev/null
grep -riE 'password|passwd|secret|api[_-]?key' /var/www /opt /home 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
```

`127.0.0.1` 에만 묶인 서비스(`netstat`에서)는 밖에서 못 닿습니다 — 포트를 포워딩해(→ [피벗팅 › SSH 포워딩](pivoting.md#ssh-forwarding)) 로컬에서 공격하세요.

## 4. 커널 익스플로잇 — 마지막 수단 { #kernel }

`uname -a` 와 배포판 버전을 알려진 익스플로잇(DirtyPipe, DirtyCOW, PwnKit 등)에 맞춥니다. 이건 마지막에: 커널 익스플로잇은 박스를 뻗게 해 revert를 낭비시킬 수 있고, 시험은 거의 항상 더 깔끔한 설정 실수 경로를 의도해 둡니다.

## 체크리스트 { #checklist }

- [ ] 셸을 제대로 된 TTY로 업그레이드
- [ ] `sudo -l` 확인 → GTFOBins
- [ ] SUID + capabilities 수집 → GTFOBins
- [ ] Cron 작업 읽기 (쓰기 가능한 스크립트? 와일드카드?)
- [ ] 설정 파일 / history / SSH 키에서 크리덴셜 찾기
- [ ] localhost 전용 서비스 찾고 포트 포워딩으로 접근
- [ ] 커널 / 배포판 버전 기록 (마지막 옵션으로 보관)

## 관련 페이지 { #related-pages }

- [Linux 인증과 히스토리](../../linux/auth-and-history.md) · [Linux 지속성](../../linux/persistence.md) · [Linux 로그와 트리아지](../../linux/logs-and-triage.md)
- [Linux 명령어](../../basics/linux-commands.md) · [방법론과 습관](methodology.md)

## 참고 자료 { #references }

- [GTFOBins](https://gtfobins.github.io/)
- [PEASS-ng (linpeas)](https://github.com/peass-ng/PEASS-ng)
