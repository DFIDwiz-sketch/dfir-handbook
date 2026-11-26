---
title: "익스플로잇으로 쓰이는 RTF·PDF·기타 파일 — 그리고 좋은 것과 나쁜 것 빠르게 가르기"
tags:
  - training
  - blue-team
  - files
  - file-analysis
  - malware-triage
  - phishing
---

# 익스플로잇으로 쓰이는 RTF·PDF·기타 파일 — 그리고 좋은 것과 나쁜 것 빠르게 가르기 { #rtf-pdf-misc-triage }

!!! abstract "이 페이지에서 다루는 것"
    앞 페이지에서는 실행 파일, 스크립트, Office 문서를 다뤘습니다. 이번에는 사람들이 **필요 이상으로 믿는** 형식들입니다. 먼저 **RTF**(Rich Text Format). 매크로는 없지만 파일을 품을 수 있고, 링크를 걸 수 있고, 익스플로잇에 쓰인 역사가 깁니다. 게다가 Word는 확장자와 상관없이 RTF를 열어 주기 때문에 공격자는 이름을 `.doc`로 바꿔 보내곤 합니다. 무해한 시험용 RTF를 바이트 단위로 뜯어 봅니다. 제어어(control word), 16진수 글자로 적힌 `\objdata` 덩어리, `grep`으로 그 안의 실행 파일을 찾는 법, `rtfobj`가 보여 주는 내용까지. 다음은 **PDF**. 피싱 페이지로 가는 링크, 박혀 있는 파일, JavaScript, 자동 실행 동작, 뷰어(리더) 익스플로잇. 시험용 PDF의 개체(object)를 `strings`로 읽고, `pdfid`의 키워드 개수를 한 줄씩 해석하고, 압축된 스트림이 왜 URL을 숨기는지 직접 풀어 봅니다. 그다음 **기타 파일**(그림, 글꼴, 음악·동영상, 이메일, `.lnk` 바로 가기). 드물지만 실제로 있습니다. 그 파일을 해석하는 프로그램의 버그를 노리는데, 그중에는 Windows 커널 안의 버그도 있습니다. 바로 가기는 버그 없이도 스크립트를 몰래 실행하는 도구가 됩니다. 마지막으로 **좋은 것과 나쁜 것을 빠르게 가르는** 6단계 순서를 두 시험 파일에 적용해 봅니다. 끝에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 호스트 이름, 도메인, 계정, IP, 파일 이름은 모두 설명용 가상 값(`.example`, 문서용·사설 IP)입니다. 이 페이지의 RTF와 PDF 샘플은 이 페이지를 위해 만든 무해한 시험용 파일입니다. RTF 안의 "실행 파일"은 PE 헤더처럼 보이는 몇 바이트와 글자 꼬리표일 뿐이고 실행되지 않습니다. PDF의 JavaScript는 메시지 상자 하나를 띄울 뿐입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. **RTF에는 매크로가 없다. 그렇다고 안전한 건 아니다.** 파일(OLE 개체)을 품고, 원격 내용에 링크를 걸고, 해석기(parser) 버그를 건드릴 수 있다. 역사상 가장 많이 쓰인 문서 익스플로잇 몇 개가 RTF로 배달됐다.
2. **Word는 확장자가 아니라 내용을 보고 연다.** `.doc`로 이름을 바꾼 RTF도, `.rtf`로 바꾼 `.doc`도 잘 열린다. 첫 바이트를 확인한다. RTF는 `{\rtf`(전부 찍히는 글자), OLE `.doc`는 `D0 CF 11 E0`, DOCX는 `PK`로 시작한다.
3. **RTF는 박힌 파일까지 전부 글자다.** 박힌 개체는 `\objdata` 안에 **16진수 숫자 글자**로 적혀 있다. 그래서 안에 든 실행 파일은 `4d5a…`(`MZ`)라는 글자로, DOS 문장은 `546869732070726f6772616d…`로 보인다. 이걸 `grep`하거나 `rtfobj`에게 풀게 한다.
4. **RTF에서 중요한 키워드**는 `\object`, `\objdata`, `\objclass`, `\objupdate`(열자마자 개체를 새로 고치게 함, 익스플로잇의 단골 방아쇠), `\*\template`(원격 템플릿, T1221)이다.
5. **PDF를 무기로 만드는 방법은 넷이다.** 링크(지금은 단연 가장 흔함: 계정 탈취 피싱 페이지), 박힌 파일, JavaScript와 자동 실행 동작(`/OpenAction`, `/AA`, `/Launch`), 뷰어 익스플로잇. Flash는 죽었지만 옛 샘플에서는 키워드가 아직 보인다.
6. **`strings` + `grep http`로 PDF를 열지 않고 링크를 뽑을 수 있다.** 다만 **압축 안 된** 개체에서만. `pdfid`는 위험한 키워드 개수를 세 준다. "아무것도 없다"고 결론 내리기 전에 스트림을 푼다.
7. **그림, 글꼴, 미디어, 이메일, 바로 가기도 악성일 수 있다.** 그 파일을 해석하는 무언가(때로는 커널, 때로는 이메일 미리 보기 창)의 버그를 통해서. `.lnk` 바로 가기는 버그조차 필요 없다. 인코딩된 명령으로 `cmd`나 `powershell`을 띄울 수 있다.
8. **빠른 분류 순서:** 해시 조회 → 디지털 서명 → 안전하게 눈으로 보기(스크린샷/VM) → `strings`로 있으면 안 되는 것 찾기(실행 파일이 아닌데 `MZ`, 그림 속 스크립트, 이상한 URL) → 난독화된 스크립트 → 샌드박스로 행위 보기. 각 단계는 결론이 아니라 단서다.

## SOC에서 왜 중요한가 { #why }

메일 게이트웨이와 사용자는 `.exe` 첨부가 나쁘고 "콘텐츠 사용"이 함정이라는 걸 배웠습니다. 그러자 공격자는 무해해 보이는 형식으로 갈아탔습니다. RTF "거래 내역서", PDF "인보이스", 그림 한 장, ZIP 안의 바로 가기. 이런 건 필터를 더 쉽게 통과하고, 사람도 더 쉽게 엽니다. 택배 기사 옷을 입은 도둑과 비슷합니다. 문이 열리는 건 누가 소포를 확인해서가 아니라 겉모습 때문이죠.

이 형식들은 국경(메일 게이트웨이)에서 통째로 막을 수 없습니다. 모든 회사가 PDF를 주고받고, 아직 RTF를 쓰는 곳도 많으니까요. 그래서 SOC가 할 일은 그 **안을** 빠르고 안전하게 들여다보고, 좋은지 나쁜지 정하고, 안에서 나온 것(URL, 박힌 파일의 해시, 프로세스 행위)을 차단과 헌팅으로 바꾸는 겁니다. 이 페이지는 형식마다 바이트 수준의 모습과, 그 판단을 빨리 내리는 순서를 알려 줍니다.

## Rich Text Format(`.rtf`) { #rtf }

### RTF란 { #rtf-what }

RTF는 1980년대 후반에 나온 문서 형식으로, 서로 다른 워드프로세서끼리 서식 있는 글을 주고받으려고 만들었습니다. `.doc`(바이너리 OLE 컨테이너)나 `.docx`(XML 파일을 담은 ZIP)와 달리 **RTF 파일은 그냥 텍스트**입니다. 찍히는 글자로 된 마크업 언어가 서식을 설명합니다. 기본 재료는 셋입니다.

- <strong>제어어(control word)</strong>: 역슬래시 + 단어, 뒤에 숫자가 붙기도 합니다. `\rtf1`, `\par`, `\fs22`. "새 문단", "글꼴 크기 11pt" 같은 지시입니다.
- <strong>그룹(group)</strong>: 중괄호 `{ … }`. 수학의 괄호처럼 설정이 미치는 범위를 묶습니다.
- <strong>데스티네이션(destination)</strong>: `\*`로 시작하는 그룹은 "이 제어어를 모르면 그룹 전체를 건너뛰어라"라는 뜻입니다. 선택적인 데이터를 넣는 방법인데, 모르는 그룹을 건너뛰는 해석기는 공격자가 쓰레기를 숨기기에도 좋습니다. 그래서 공격자들이 아주 좋아합니다.

"단순한" 형식이 왜 위험할까요? RTF는 Office 문서가 하는 일 대부분을 할 수 있기 때문입니다. **OLE 개체를 박고**(파일, 다른 문서, 수식 개체), 원격 내용에 **링크**를 걸고, 템플릿을 불러옵니다. 그리고 수십 년 동안 느슨하게 정의되고 관대하게 쓰여 온 문법을 읽어야 하는 해석기에는 버그가 있기 마련입니다. RTF가 **못 하는** 단 한 가지는 VBA 매크로를 담는 겁니다. 사람들은 이 말을 듣고 안전하다고 결론 내리는데, 공격자가 RTF를 쓰는 이유가 바로 그겁니다.

### 확장자 장난: 사실은 RTF인 `.doc` { #rtf-extension }

Word는 파일을 어떻게 열지 **내용**을 보고 정합니다. `statement_nov.doc`로 저장된 RTF는 RTF로 열리고, 매크로가 든 OLE `.doc`를 `.rtf`로 바꿔도 `.doc`로 열립니다. 공격자는 두 방향을 다 씁니다. RTF를 `.doc`로 불러 평범한 문서처럼 보이게 하거나, `.doc`를 `.rtf`로 불러 "매크로는 없겠지" 하고 넘기게 만들거나. 그러니 언제나처럼 확장자는 아무것도 말해 주지 않습니다. 바이트가 말해 줍니다.

```
$ file statement_nov.doc
statement_nov.doc: Rich Text Format data, version 1, ANSI, code page 1252
```

- `file`은 `.doc` 확장자를 무시하고 맨 앞의 `{\rtf1`을 보고 RTF라고 알아봤습니다.
- `version 1`은 `\rtf1`에서, `ANSI`는 `\ansi`에서, `code page 1252`는 `\ansicpg1252`(서유럽 Windows 코드 페이지)에서 나왔습니다.

헥스로 보면 RTF가 Office 형식과 왜 쉽게 구별되는지 보입니다. 모든 바이트가 찍히는 글자입니다.

```
$ python3 hexview.py statement_nov.doc | head -8
00000000  7b 5c 72 74 66 31 5c 61  6e 73 69 5c 61 6e 73 69  |{\rtf1\ansi\ansi|
00000010  63 70 67 31 32 35 32 5c  64 65 66 66 30 7b 5c 66  |cpg1252\deff0{\f|
00000020  6f 6e 74 74 62 6c 7b 5c  66 30 20 43 61 6c 69 62  |onttbl{\f0 Calib|
00000030  72 69 3b 7d 7d 0a 7b 5c  2a 5c 67 65 6e 65 72 61  |ri;}}.{\*\genera|
00000040  74 6f 72 20 4d 73 66 74  65 64 69 74 20 35 2e 34  |tor Msftedit 5.4|
00000050  31 2e 32 31 2e 32 35 31  30 3b 7d 5c 76 69 65 77  |1.21.2510;}\view|
00000060  6b 69 6e 64 34 5c 75 63  31 5c 70 61 72 64 5c 66  |kind4\uc1\pard\f|
00000070  30 5c 66 73 32 32 20 50  6c 65 61 73 65 20 72 65  |0\fs22 Please re|
```

- 분석 VM에 `hexdump`도 `xxd`도 없어서, 열 줄짜리 Python 스크립트로 `hexdump -C`와 같은 모양(오프셋, 16바이트 헥스, ASCII 칸)을 찍었습니다.
- `7b 5c 72 74 66 31` = `{\rtf1`, RTF의 매직입니다. [파일 알아보기 페이지](file-identification.md#magic-bytes)의 OLE `.doc` `D0 CF 11 E0`, `.docx` `50 4B 03 04`(`PK..`)와 비교해 보세요.
- ASCII 칸이 처음부터 끝까지 읽힙니다. 유일한 `.`는 `0x35`의 `0a`, 즉 줄바꿈입니다. 바이너리 형식은 절대 이렇게 생기지 않습니다.

<strong>[보충]</strong> Word는 머리말에 아주 관대한 것으로 유명합니다. 맨 앞이 대략 `{\rt`이기만 하면 되기 때문에, 악성 RTF는 "`{\rtf1`로 시작하나?"만 보는 단순한 필터를 피하려고 `{\rtx…`나 `{\rt0…`로 시작하는 경우가 많습니다. `{\rt`를 찾고, 정상에서 벗어난 변형은 그 자체로 수상하게 봅니다.

### 시험용 RTF를 한 줄씩 읽기 { #rtf-read }

시험 파일 전체입니다(헥스 덩어리는 줄였습니다).

```
{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Calibri;}}
{\*\generator Msftedit 5.41.21.2510;}\viewkind4\uc1\pard\f0\fs22 Please review the attached statement.\par
{\object\objemb\objw1440\objh1440{\*\objclass Package}{\*\objdata
0105000002000000080000005061636b61676500010000000001000000001201
000002007570646174652e65786500433a5c55736572735c6465765c4465736b
...
}}\par
}
```

| 조각 | 뜻 |
| --- | --- |
| `{\rtf1` | 문서 그룹 시작, RTF 버전 1 |
| `\ansi\ansicpg1252` | 문자 집합 ANSI, 코드 페이지 1252 |
| `\deff0{\fonttbl{\f0 Calibri;}}` | 기본 글꼴은 0번. 글꼴 표에서 0번을 Calibri로 정의 |
| `{\*\generator Msftedit 5.41.21.2510;}` | 파일을 쓴 프로그램 이름을 적는 선택적 데스티네이션. 위조하기 쉽지만, 주장하는 이야기와 안 맞으면 그것도 단서 |
| `\pard\f0\fs22` | 문단 서식 초기화, 0번 글꼴, 크기 22 하프포인트(11pt) |
| `Please review the attached statement.\par` | 화면에 보이는 글, 그리고 문단 끝 |
| `{\object\objemb` | **여기서 OLE 개체가 시작**, 종류는 **박힌(embedded)** 개체(데이터가 파일 안에 있음) |
| `\objw1440\objh1440` | 개체 너비와 높이, 단위는 트윕(twip, 1440트윕 = 1인치). 페이지 위의 1인치짜리 아이콘 |
| `{\*\objclass Package}` | 개체 클래스는 **Package**, 아무 파일이나 감싸는 OLE "패키저(Packager)". 문서 안에 `.exe`, `.js`, `.hta`를 넣는 고전적인 방법 |
| `{\*\objdata 0105…}` | 개체의 바이트를 **16진수 숫자 글자**로 적은 것 |

알아 둘 다른 개체 키워드:

- `\objlink` / `\objautlink`: 개체가 박혀 있지 않고 다른 곳(파일이나 URL)의 데이터에 **링크**된 것.
- `\objupdate`: "문서가 열리자마자 이 개체를 새로 고쳐라". 이게 없으면 사용자가 개체를 더블클릭해야 합니다. 이게 있으면 Word가 스스로 개체를 가져오거나 활성화합니다. RTF 버그 여러 개를 **더블클릭 한 번**(문서 열기)이면 감염되는 공격으로 만든 게 이것입니다.
- `\*\template`: 이 경로나 URL에서 템플릿을 불러와라. 원격 서버를 가리키게 하면 <strong>템플릿 인젝션(template injection)</strong>(ATT&CK **T1221**)입니다. 문서 자체는 깨끗하고, 불러온 템플릿이 페이로드를 싣고 옵니다.
- `\*\datastore`, 클래스가 `Equation.3`이나 `OLE2Link`인 `\*\objdata`: 유명한 익스플로잇과 연결된 클래스(아래 참고).

### 헥스 속에서 박힌 파일 찾기 { #rtf-objdata }

`\objdata`의 앞부분, 즉 OLE 1.0 개체 머리말을 풀어 보면:

```
01050000 02000000 08000000 5061636b61676500 ...
```

- `01050000`: OLE 버전 `0x00000501`, 리틀 엔디언(바이트가 거꾸로 저장됨. [문자열 페이지](strings.md#byte-order)와 같은 이야기).
- `02000000`: 형식 ID `2` = **박힌** 개체(`1`이면 링크된 개체).
- `08000000`: 뒤따르는 클래스 이름의 길이가 8바이트.
- `5061636b61676500`: `P a c k a g e \0`. `\objclass`와 같은 클래스입니다.

조금 더 가면 `7570646174652e65786500`이 `update.exe\0`, 박힌 파일의 이름으로 풀립니다. 분류할 때 손으로 다 풀 필요는 없습니다. 박힌 바이트가 16진수 글자로 적혀 있으니, **이미 아는 시그니처의 16진수**를 `grep`하면 됩니다.

```
$ grep -o "4d5a9000" statement_nov.doc
4d5a9000
$ grep -c "546869732070726f6772616d" statement_nov.doc
1
```

- `4d5a9000` = `MZ` 다음에 `90 00`. 전형적인 Windows 실행 파일의 시작입니다([매직 바이트](file-identification.md#magic-bytes)).
- `546869732070726f6772616d` = `This program`, DOS 스텁 문장의 앞부분. 한 번 나옵니다.
- 이메일로 온 거래 내역서 안에 실행 파일이 있을 무해한 이유는 없습니다. 아래 분류 목록의 "있으면 안 되는 곳에 매직 바이트" 확인이 바로 이겁니다.
- 주의: `\objdata`의 헥스는 (여기처럼) 줄이 나뉘거나, 공백이 섞이거나, 해석기가 무시하는 쓰레기 제어어로 채워질 수 있습니다. `grep`이 못 찾았다고 **없다는 증거는 아닙니다.** 그래서 해석기도 같이 돌립니다.

<strong>[보충]</strong> `rtfobj`(**oletools**에 들어 있음)는 RTF를 Word처럼 해석해서 모든 개체를 꺼내고 정체를 알려 줍니다.

```
$ rtfobj statement_nov.doc
===============================================================================
File: 'statement_nov.doc' - size: 862 bytes
---+----------+---------------------------------------------------------------
id |index     |OLE Object
---+----------+---------------------------------------------------------------
0  |000000E2h |format_id: 2 (Embedded)
   |          |class name: b'Package'
   |          |data size: 274
   |          |OLE Package object:
   |          |Filename: 'update.exe'
   |          |Source path: 'C:\\Users\\dev\\Desktop\\update.exe'
   |          |Temp path = 'C:\\Users\\dev\\AppData\\Local\\Temp\\update.exe'
   |          |MD5 = '7a22d6d62fd72ea377a4407885c54e40'
   |          |EXECUTABLE FILE
   |          |File Type: Windows PE Executable or DLL
---+----------+---------------------------------------------------------------
```

- `id 0`, `index 000000E2h`: 첫 번째 개체이고, RTF의 오프셋 `0xE2`에서 시작합니다.
- `format_id: 2 (Embedded)`, `class name: b'Package'`: 우리가 손으로 푼 것과 같습니다.
- `data size: 274`: 개체 속 실제 데이터 크기(바이트).
- `Filename: 'update.exe'`: 아이콘 아래 사용자에게 보이는 이름. 공격자가 정하는 값이라, `.exe`인데 `Statement.pdf`라고 써 놓을 수도 있습니다.
- `Source path: 'C:\\Users\\dev\\Desktop\\update.exe'`: 공격자가 개체를 박을 때 **공격자 PC에서 파일이 있던 위치**. 패키저가 자동으로 기록합니다. 원본 경로에 남은 사용자 이름과 폴더 구조는 캠페인을 묶는 데 쓸모가 있습니다.
- `Temp path = …\AppData\Local\Temp\update.exe`: 사용자가 아이콘을 더블클릭하면 패키저가 파일을 떨어뜨리는 곳. 파일 생성·프로세스 생성 로그에서 **이 경로를 헌팅**합니다.
- `MD5 = '…'`: 박힌 파일의 해시. 조회해 보고 IOC에 추가합니다(조회 열쇠로는 MD5도 괜찮습니다. 한계는 다음 페이지에서).
- `EXECUTABLE FILE` / `File Type: Windows PE Executable or DLL`: rtfobj가 박힌 바이트를 확인하고 `MZ`를 찾았습니다. 여기서는 무해한 가짜지만, 실제 메일이라면 빨간불입니다.
- `rtfobj -s 0 -d outdir statement_nov.doc`로 0번 개체를 폴더에 저장하면, 분석 VM에서 해시를 구하고 `file`과 `strings`를 돌릴 수 있습니다.

### 유명한 RTF 익스플로잇과 남기는 흔적 { #rtf-exploits }

| CVE | 노린 것 | RTF가 방아쇠를 당긴 방법 | 엔드포인트에서 보이는 것 |
| --- | --- | --- | --- |
| CVE-2017-0199 | URL을 가리키는 `OLE2Link` 개체를 Office가 처리하는 방식. URL은 **HTA**를 돌려줌 | `\objautlink` + `\objupdate`: Word가 문서를 열 때 원격 문서를 가져와 실행. 매크로도 경고 막대도 없음 | `WINWORD.EXE` → URL과 함께 `mshta.exe`, 이어서 다음 단계를 내려받는 PowerShell/VBScript |
| CVE-2017-11882, CVE-2018-0802 | 옛 **수식 편집기**(`EQNEDT32.EXE`)의 버퍼 오버플로 | RTF 속 `Equation.3` 개체. 열면 취약한 프로세스가 시작됨 | `EQNEDT32.EXE`가 실행되는 것 자체(그리고 `cmd`/`powershell`을 띄움). Microsoft가 2018년 1월에 수식 편집기를 없앴지만, 옛 빌드와 패치 안 된 설치본이 수년간 남았음 |
| CVE-2017-8570 | 0199와 비슷한 다른 OLE 모니커(moniker) 경로로 스크립틀릿을 떨어뜨림 | 조작된 모니커가 든 박힌 개체 | Word의 자식으로 뜬 스크립트 호스트(`wscript`, `cscript`, `mshta`) |
| CVE-2023-21716 | Word **RTF 해석기**의 힙 손상(글꼴 표 처리) | 파일을 해석하기만 하면 됨. Outlook **미리 보기 창**으로도 충분 | Word나 Outlook이 죽거나 자식 프로세스를 띄움. 2023년 2월 패치 |

공통점은 문서를 **열거나 미리 보기만** 하면 된다는 겁니다. ATT&CK로는 **T1203 Exploitation for Client Execution**이고, 보통 **T1566.001 Spearphishing Attachment**로 배달되며, 첫 클릭은 **T1204.002 User Execution: Malicious File**에 기댑니다. 조사할 때는 파일보다 엔드포인트 쪽이 더 선명한 경우가 많습니다. CVE-2017-0199 사슬이 프로세스 생성 이벤트에 어떻게 찍히는지 봅시다(**4688**, "새 프로세스가 생성되었습니다". 프로세스가 시작될 때마다 생깁니다. 무엇이, 어떤 명령줄로, 누구에 의해 시작됐는지 남기기 때문에 공격자가 신경 쓰는 이벤트입니다. [프로세스 생성 이벤트](../important-events/process-creation.md) 참고).

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-11-24T02:13:48.0912254Z" />
    <Computer>HR-WS-0042.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">s.park</Data>
    <Data Name="NewProcessName">C:\Windows\System32\mshta.exe</Data>
    <Data Name="CommandLine">C:\Windows\System32\mshta.exe -Embedding</Data>
    <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
    <Data Name="TokenElevationType">%%1938</Data>
  </EventData>
</Event>
```

- `NewProcessName …mshta.exe`: Windows HTML 응용 프로그램 호스트. HTA 파일(HTML + 스크립트, 사용자 권한 전체로 실행)을 실행합니다. **T1218.005 Mshta**.
- `CommandLine mshta.exe -Embedding`: `-Embedding`은 다른 프로그램을 대신해 COM/OLE가 띄웠다는 뜻입니다. 가져온 HTA는 명령줄에 안 나옵니다. 이 직전에 Word나 mshta가 보낸 HTTP 요청을 네트워크 로그에서 찾으세요.
- `ParentProcessName …WINWORD.EXE`: Word가 띄웠습니다. Word가 `mshta.exe`를 띄울 정상적인 이유는 거의 없습니다. 이 부모-자식 짝이 곧 탐지 규칙입니다.
- `TokenElevationType %%1938`: 제한된 토큰, 즉 평범한 사용자 권한. 익스플로잇에 관리자 권한은 필요 없었습니다.

### RTF 분류하는 법 { #rtf-triage }

1. `file`로 확인. `.doc`라는 이름의 RTF, 또는 정확히 `{\rtf1`이 아닌 머리말이 첫 경고입니다.
2. `grep -c '\\object' file`, `grep -c '\\objupdate'`, `grep -ci 'objclass'`, `grep -c '\\\*\\template'`. 한 문단짜리 "내역서"에 박힌 개체가 필요할 리 없습니다.
3. `rtfobj file`로 모든 개체를 나열하고 정체를 확인. `-s all -d out/`로 꺼내서 해시를 구하고 더 깊이 분석합니다.
4. `grep -i "4d5a"`와 DOS 문장의 헥스. `d0cf11e0`(안에 든 OLE 파일), `504b0304`(안에 든 ZIP)도 눈여겨봅니다.
5. 개체가 `Equation.3`이나 `OLE2Link`라면 익스플로잇으로 가정하고, 엔드포인트에서 `EQNEDT32.EXE`나 `WINWORD.EXE` → `mshta.exe`를 확인합니다.

## PDF 파일 { #pdf }

### PDF가 이렇게 흔한 공격 경로인 이유 { #pdf-why }

PDF는 어디에나 있습니다. 인보이스, 계약서, 급여 명세서, 배송 안내. 메일 게이트웨이에서 막을 수 없고, 사용자는 생각 없이 엽니다. 그래서 구조를 이해하고 안을 들여다볼 수 있는 도구가 필요합니다. PDF는 다른 문서와 같은 방법으로 무기가 되고, 자기만의 방법도 몇 가지 더 있습니다.

- 악성 사이트로 가는 **링크**. 요즘은 단연 이게 가장 흔합니다. PDF는 가짜 "인보이스"나 "공유 문서" 화면이고, 큰 버튼을 누르면 Microsoft 365나 Google 로그인 화면을 베낀 페이지로 갑니다. "터뜨릴" 건 없습니다. 사용자가 비밀번호를 입력하는 순간 피해가 납니다. 점점 더 많이 링크가 **QR 코드** 그림으로 들어 있어서, 사용자가 회사 통제 밖의 휴대폰으로 찍게 만듭니다("큐싱(quishing)").
- **박힌 파일**: PDF는 첨부 파일(`/EmbeddedFile`)을 실을 수 있고, 실행 파일이나 스크립트도 됩니다.
- 문서를 열 때 실행되는 **JavaScript**, 그리고 자동으로 실행되는 **동작(action)**: `/OpenAction`(열 때), `/AA`(페이지 보기, 닫기 등에서 실행되는 추가 동작), `/Launch`(프로그램 실행이나 파일 열기).
- 예전에는 **Flash** 콘텐츠(`/RichMedia`), 그리고 뷰어 자체를 노리는 **익스플로잇**(Adobe Reader, Foxit, 브라우저 PDF 엔진).
- 데이터를 URL로 보내거나 스크립트를 담을 수 있는 **양식(form)**(`/AcroForm`, `/XFA`).

주제는 뻔합니다. 인보이스, 송금 내역, 음성 메시지 알림, 클라우드 서비스의 "문서가 공유되었습니다", 인사 규정 변경, 전자 서명 요청.

### PDF는 어떻게 생겼나 { #pdf-structure }

PDF는 대체로 텍스트인 파일 안에 바이너리 스트림이 들어 있는 모양입니다. 네 부분입니다.

1. **머리말(header)**: `%PDF-1.7`(버전). 보통 그 뒤에 높은 값 바이트로 된 주석 줄(`%âãÏÓ`)이 와서, 전송 도구가 파일을 바이너리로 다루게 합니다.
2. **본문(body)**: 번호 붙은 <strong>개체(object)</strong>들. 하나하나가 `N 0 obj … endobj`입니다. 개체는 보통 **사전(dictionary)** `<< /Key value … >>`이고, 데이터 **스트림(stream)**(페이지 내용, 그림, 글꼴, 박힌 파일)을 달고 있을 수 있는데, 흔히 압축돼 있습니다.
3. **상호 참조 표(cross-reference table, `xref`)**: 모든 개체의 바이트 오프셋. 뷰어가 개체로 곧장 건너뛸 수 있게 해 줍니다.
4. **트레일러(trailer)**: 뿌리 개체(`/Root`)와 xref 위치(`startxref`)를 가리키고, `%%EOF`로 끝납니다.

참조는 `5 0 R`("5번 개체, 세대 0")처럼 생겼습니다. PDF를 번호 붙은 쪽과 맨 뒤 색인이 있는 바인더라고 생각하세요. 뷰어는 색인부터 보고, 뿌리를 찾고, 참조를 따라갑니다. 공격자가 할 일은 뷰어가 알아서 실행할 쪽 하나를 바인더에 몰래 끼워 넣는 겁니다.

### PDF에 `strings`: 빠르게 훑어보기 { #pdf-strings }

시험용 PDF에 `strings`(아주 짧은 잡음을 빼려고 `-n 6`):

```
$ strings -n 6 invoice_8841.pdf
%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R /Names << /EmbeddedFiles 7 0 R >> >>
endobj
...
4 0 obj
<< /Length 122 /Filter /FlateDecode >>
stream
	&&.I;
Qh	-Eoo
m@74{4U
endstream
endobj
5 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert\('Test file - harmless'\);) >>
endobj
6 0 obj
<< /Type /Annot /Subtype /Link /Rect [72 650 400 680] /A << /S /URI /URI (https://docs-view.example/inv/8841) >> >>
endobj
...
9 0 obj
<< /Type /EmbeddedFile /Length 25 >>
stream
harmless test attachment
endstream
...
trailer
<< /Size 10 /Root 1 0 R >>
startxref
```

개체별로 읽어 보면:

- `%PDF-1.7`: 매직과 버전.
- **1번 개체**, `/Type /Catalog`: 문서의 뿌리. `/OpenAction 5 0 R`은 <strong>"문서가 열리면 5번 개체를 실행하라"</strong>라는 뜻입니다. `/Names << /EmbeddedFiles 7 0 R >>`는 PDF에 첨부 파일이 있고 그 목록이 7번 개체에 있다는 뜻입니다. 둘 다 평범한 인보이스에는 필요 없는 것들입니다.
- **4번 개체**, `/Filter /FlateDecode` + `stream`: 페이지 내용 스트림이고, zlib/deflate로 **압축**돼 있습니다. `strings`에는 쓰레기 몇 줄(`&&.I;`, `Qh -Eoo`)만 보입니다. 압축된 무작위 바이트가 우연히 찍히는 값이 된 것으로, [문자열 페이지](strings.md#printable)에서 설명한 잡음 그대로입니다. 안에 무슨 글이 있든 여기서는 안 보입니다.
- **5번 개체**, `/S /JavaScript /JS (…)`: 종류가 JavaScript인 동작이고, 괄호 안에 코드가 있습니다. 여기서는 무해한 `app.alert`. 악성 파일이라면 여기에 난독화된 코드(긴 문자열과 `eval`이 흔함)가 있거나, `/JS 12 0 R`처럼 압축된 스트림을 가리킵니다.
- **6번 개체**, `/Subtype /Link … /URI (https://docs-view.example/inv/8841)`: 누르면 URL을 여는 사각형 영역(`/Rect`, 왼쪽 아래 기준 포인트 단위). 이게 **피싱 링크 IOC**입니다.
- **9번 개체**, `/Type /EmbeddedFile`: 첨부 파일의 내용. 여기서는 압축 안 된 텍스트입니다. 실제로 박힌 페이로드는 대개 압축돼 있습니다.
- `trailer … /Root 1 0 R`: 뷰어는 1번 개체에서 시작합니다.

파일을 열지 않고 IOC를 뽑는 가장 빠른 방법:

```
$ strings invoice_8841.pdf | grep -i http
<< /Type /Annot /Subtype /Link /Rect [72 650 400 680] /A << /S /URI /URI (https://docs-view.example/inv/8841) >> >>
```

- 링크 주석(annotation)에서 URL 하나. 프록시와 DNS 로그에서 `docs-view.example`을, 그리고 어느 호스트든 `/inv/8841` 경로를 찾습니다.
- **그런데 페이지 글에도 URL이 들어 있는데**(일부러 넣었습니다) `grep`은 못 찾았습니다. 4번 개체가 압축돼 있기 때문입니다. 스트림을 풀면(여기서는 Python `zlib` 세 줄로. 전용 도구는 아래에서) 나타납니다.

```
BT /F1 18 Tf 72 700 Td (Your invoice is ready - click View Document) Tj ET
BT 72 660 Td (https://docs-view.example/inv/8841) Tj ET
```

- `BT … ET`: 글 덩어리 시작/끝. `/F1 18 Tf`: 1번 글꼴, 크기 18. `72 700 Td`: x=72, y=700 포인트로 이동. `(…) Tj`: 이 문자열을 그려라.
- 그러니까 페이지에는 "Your invoice is ready - click View Document"가 쓰여 있고 URL이 찍혀 있습니다. 사용자가 보는 미끼죠.
- 교훈: `strings | grep http`는 훌륭한 **첫** 확인이고, 못 찾았다는 건 "깨끗하다"가 아니라 "더 깊이 봐라"입니다.

### `pdfid`: 위험한 키워드 세기 { #pdfid }

`pdfid`(Didier Stevens 작, 여기서는 Python 패키지판)는 아무것도 그리지 않고 PDF에서 중요한 이름들을 찾아 개수를 셉니다.

```
$ python3 -m pdfid invoice_8841.pdf
PDFiD 0.2.7 invoice_8841.pdf
 PDF Header: %PDF-1.7
 obj                    9
 endobj                 9
 stream                 2
 endstream              2
 xref                   1
 trailer                1
 startxref              1
 /Page                  1
 /Encrypt               0
 /ObjStm                0
 /JS                    1
 /JavaScript            1
 /AA                    0
 /OpenAction            1
 /AcroForm              0
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          1
 /XFA                   0
 /Colors > 2^24         0
```

| 줄 | 뜻 | 왜 신경 쓰나 |
| --- | --- | --- |
| `obj`/`endobj` 9 | 개체 9개, 모두 닫힘 | 개수가 안 맞으면 망가졌거나 일부러 깨뜨린 파일(해석기 혼란 노림) |
| `stream` 2 | 데이터 스트림 2개 | 하나하나가 내용을 숨길 수 있음. 풀어 본다 |
| `xref`/`trailer`/`startxref` 1 | 개정판 하나 | 여러 개면 **증분 업데이트**된 파일. 나중에 내용이 덧붙었다는 뜻이고, 무언가를 숨기거나 바꾸려는 경우도 있음 |
| `/Page` 1 | 한 쪽 | 악성 PDF는 아주 흔히 한 쪽짜리다. 미끼와 버튼만 있으면 되니까 |
| `/Encrypt` 0 | 암호화 안 됨 | 암호화는 스캐너에게서 문자열을 숨긴다(빈 비밀번호라 뷰어는 조용히 열기도 함) |
| `/ObjStm` 0 | 개체 스트림 없음 | 개체 스트림은 개체를 압축 스트림 안에 담아서 `strings`와 단순한 스캐너에게서 키워드를 숨긴다 |
| `/JS` 1, `/JavaScript` 1 | JavaScript 있음 | 평범한 업무 PDF에는 거의 필요 없다. **관심 높음** |
| `/AA` 0, `/OpenAction` 1 | 자동 동작 하나 | `/JavaScript`와 합치면 **열자마자 코드 실행**. 가장 수상한 조합 |
| `/AcroForm`, `/XFA` 0 | 양식 없음 | 양식은 스크립트를 담거나 데이터를 보낼 수 있다 |
| `/JBIG2Decode` 0 | JBIG2 그림 없음 | 이 디코더에 실제로 악용된 심각한 버그가 있었다. 정상 문서에는 드묾 |
| `/RichMedia` 0 | Flash/미디어 없음 | 옛날 Flash 익스플로잇 경로 |
| `/Launch` 0 | 실행 동작 없음 | 있으면 프로그램을 시작하거나 파일을 연다. 관심 아주 높음 |
| `/EmbeddedFile` 1 | 첨부 하나 | 꺼내서 별도 파일로 분석한다 |
| `/Colors > 2^24` 0 | 터무니없는 색상 값 없음 | 옛 익스플로잇 지표 |

시험 파일은 `/JS`, `/JavaScript`, `/OpenAction`, `/EmbeddedFile`에 걸렸습니다. 실제 첨부였다면 곧장 더 깊은 분석으로 갔을 겁니다.

<strong>[보충]</strong> 공격자는 이름을 **헥스 이스케이프**로 숨깁니다. `/J#61vaScript`는 뷰어에게는 여전히 `/JavaScript`(`#61` = `a`)지만 단순한 `grep`에게는 아닙니다. `pdfid`는 이걸 정상화해서 세고, 난독화된 개수를 괄호 안에 보여 줍니다. 예: `/JavaScript 1(1)`. 정상 PDF 생성기는 그렇게 할 이유가 없으니, 이름이 난독화돼 있다는 것 자체가 수상합니다.

다음 도구로는 보통 **`pdf-parser`**(같은 개발자)를 씁니다. 개체를 나열하고, 키워드를 찾고(`--search javascript`), 개체 하나를 보여 주고(`-o 5`), 스트림을 풀거나(`-f`) 파일로 덤프합니다(`-d`). `pdfid` → `pdf-parser`가 표준 정적 분석 경로이고, 둘 다 흔히 쓰는 분석용 배포판에 들어 있습니다([2026년 관점](#trends) 참고).

### PDF 공격이 엔드포인트에서 보이는 모습 { #pdf-in-logs }

- **피싱 링크**: PDF를 연 직후 브라우저가 그 URL에 접속한 것 말고는 엔드포인트에 수상한 게 없습니다. 프록시/DNS 로그(PDF에서 뽑은 도메인)와 메일 로그(누가 받았나)를 엮어 누가 눌렀는지 봅니다.
- **JavaScript/익스플로잇**: 뷰어(`AcroRd32.exe`, `Acrobat.exe`, `FoxitPDFReader.exe`)가 `cmd.exe`, `powershell.exe`, `rundll32.exe`를 띄우거나 Temp에 `.exe`/`.dll`을 쓰는 것. PDF 뷰어가 셸을 띄울 이유는 거의 없습니다.
- **박힌 파일 / `/Launch`**: 뷰어가 첨부를 디스크에 쓰고, 그 경로에서 프로세스가 시작됩니다. 뷰어의 임시 폴더 아래 파일 생성, 이어서 같은 경로에서의 프로세스 생성을 헌팅합니다.

## 익스플로잇으로 쓰이는 기타 파일 { #misc }

### 그림이 정말 악성일 수 있나? { #misc-how }

네. 다만 드물고 알아채기 어렵습니다. 그림, 노래, 동영상, 글꼴에는 악용할 "기능"이 없습니다. 매크로도, 링크도, 스크립트 자리도 없죠. 그래서 길은 **파일을 해석하는 코드의 버그** 하나뿐입니다. 이미지 디코더, 글꼴 렌더러, 미디어 코덱은 복잡한 바이너리 구조를 읽고, 파일에서 그대로 가져온 크기와 오프셋으로 계산을 많이 합니다. "너비" 값을 일부러 이상하게 만든 파일이 버퍼를 넘치게 하면, 해석기가 공격자가 정한 바이트를 코드가 있는 곳에 쓰게 되고, 결국 **뷰어**가 공격자의 코드를 실행합니다.

해석기를 서류를 장부에 옮겨 적는 직원이라고 생각해 보세요. 직원은 서류 맨 위 "줄 수" 칸을 믿고 그만큼 적습니다. 그 칸에 거짓말을 하면 직원은 장부의 다음 쪽까지 덮어써 버립니다. 기술적으로는 해석 라이브러리의 메모리 손상 버그(오버플로, use-after-free, 정수 오버플로)입니다.

해석기가 어디서 도느냐가 피해 크기를 정합니다.

- **응용 프로그램**(그림 뷰어, 미디어 플레이어, 브라우저) 안이면, 공격자는 그 앱의 권한을 얻습니다. 샌드박스 안인 경우가 많습니다.
- **Windows 커널** 안이면 치명적입니다. Windows는 오랫동안 일부 글꼴을 커널 안(`win32k.sys`, 그리고 Adobe Type Manager 글꼴 드라이버 `ATMFD.DLL`)에서 해석했습니다. 거기에 글꼴 버그가 있으면 웹 페이지나 문서 미리 보기에서 글자를 그리기만 해도 **커널 권한**으로 코드가 실행됐습니다.
- **미리 보기** 기능(탐색기 미리 보기 창, Outlook 읽기 창, 썸네일 생성) 안이면, 사용자가 파일을 열 필요조차 없습니다.

예:

| CVE | 형식 / 구성 요소 | 방아쇠 |
| --- | --- | --- |
| CVE-2010-2568 | Windows 셸의 `.lnk` 아이콘 처리 | 조작된 바로 가기가 든 폴더를 **보여 주기만** 하면 됨(예: USB). Stuxnet이 사용 |
| CVE-2018-1010 | Windows 글꼴 라이브러리 | 조작된 박힌 글꼴을 불러오는 페이지나 문서 보기 |
| CVE-2018-8475 | Windows 이미지 처리 | 조작된 그림을 **보기** |
| CVE-2020-1349 | Outlook | 조작된 메일을 읽기 창에서 **미리 보기** |
| CVE-2023-4863 [보충] | `libwebp` 이미지 라이브러리(Chrome 등 수많은 앱이 사용) | 조작된 WebP 그림 그리기. 2023년 실제로 악용됐고, 이 라이브러리를 품은 앱 하나하나에 수정이 들어가야 했음 |
| CVE-2023-23397 [보충] | Outlook 미리 알림 | 미리 알림 소리 경로가 공격자의 SMB 서버를 가리키는 일정 항목. Outlook이 **클릭 하나 없이** 사용자의 NTLM 해시를 보냄 |

### 바로 가기(`.lnk`): 익스플로잇이 필요 없다 { #lnk }

`.lnk` 파일은 Windows 바로 가기입니다. **대상(target)** 프로그램과 **인수(arguments)**, 아이콘, 작업 폴더, "최소화로 실행" 설정을 저장합니다. 그것만으로도 실행기가 됩니다. 공격자가 대상을 `cmd.exe`나 `powershell.exe`로 정하고, 인수에 인코딩된 다운로드-후-실행 명령을 넣습니다. 아이콘은 PDF나 폴더처럼 보이게 합니다. 사용자가 "Invoice.pdf"를 더블클릭하면 PowerShell이 실행됩니다. 그래서 2022년 이후 `.lnk` 첨부와 ZIP/ISO 컨테이너 속 `.lnk`가 매크로를 대신하는 단골 수단이 됐습니다.

바로 가기 해석 도구(Eric Zimmerman의 `LECmd`가 흔히 쓰임)로 보면 악성 바로 가기는 대략 이렇게 생겼습니다(설명용 가상 값).

```
Source file: C:\Cases\8841\Invoice_8841.pdf.lnk
  Target path:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Arguments:          -w hidden -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
  Icon location:      C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  Show window:        SwShowMinNoActive
  Working directory:  %TEMP%
  Machine ID:         desktop-q7k2m1
  MAC address:        00:0c:29:5a:1e:77
```

- `Source file … Invoice_8841.pdf.lnk`: 진짜 확장자는 `.lnk`입니다. 탐색기는 "확장자 표시"를 켜도 `.lnk`는 숨기기 때문에, 사용자 눈에는 `Invoice_8841.pdf`로 보입니다.
- `Target path … powershell.exe`: PowerShell을 띄우는 "PDF"(**T1059.001**).
- `Arguments -w hidden -nop -enc SQBFAFgA…`: 숨은 창, 프로필 안 읽음, Base64로 인코딩된 명령. `SQBFAFgA`는 `IEX`(Invoke-Expression)의 UTF-16LE Base64로, 앞 페이지에서 본 것과 같은 결정적 단서입니다.
- `Icon location … msedge.exe`: Edge 아이콘을 빌려 씁니다. 사용자는 Edge 아이콘을 보면 PDF가 열리겠거니 생각합니다.
- `Show window SwShowMinNoActive`: 최소화 상태로, 포커스도 없이 시작합니다. 화면에 아무것도 번쩍이지 않습니다.
- `Machine ID`, `MAC address`: **공격자가 바로 가기를 만든 PC**의 이름과 MAC. 바로 가기의 추적 데이터에 자동으로 저장됩니다. 같은 제작자가 만든 샘플을 잇는 데 금 같은 정보입니다.

관련 ATT&CK: **T1204.002 Malicious File**(클릭), **T1547.009 Shortcut Modification**(바로 가기를 지속성에 쓸 때), **T1027.012 LNK Icon Smuggling**(아이콘 위치 칸에 페이로드나 URL을 숨김).

<strong>[변경됨]</strong> 수년간 공격자는 인수 앞을 공백으로 채워서, 속성 창에는 대상의 무해해 보이는 앞부분만 보이게 했습니다. ZDI-CAN-25373 / CVE-2025-9491로 추적됐고 여러 국가 배후 그룹이 썼습니다. Microsoft는 2025년 말(2025년 11~12월 보도) Windows를 바꿔 속성 창에 명령 전체가 보이게 했는데, 일반적인 보안 공지 없이 조용히 했습니다. 바로 가기는 도구로 해석하고, 속성 창을 믿지 마세요.

## 좋은 것과 나쁜 것 빠르게 가르기 { #triage }

이제 공격자가 주로 쓰는 파일 형식을 다 봤습니다. 그런 파일이 책상에 떨어졌을 때 쓰는, 빠르고 겉핥기 수준의 순서입니다. 뒤 단계로 갈수록 비싸고, 답이 분명해지면 바로 멈춥니다.

1. **온라인 해시 조회.** SHA-256을 구해 조회합니다(VirusTotal이나 위협 인텔리전스 플랫폼). 알려진 악성이면 분류는 끝났고 범위 파악을 시작합니다. 수년 기록이 있는 알려진 정상이면 안심할 만합니다. **처음 보는** 해시는 아무것도 말해 주지 않거나, 약간 수상합니다(흔한 소프트웨어는 대개 한 번쯤 조회됐으니까요). 자세한 내용과 함정은 다음 페이지에서.
2. **디지털 서명**(서명할 수 있는 형식: 실행 파일, DLL, 드라이버, MSI, 스크립트, 일부 Office 매크로). 잘 알려진 게시자의 유효한 서명이면 좋은 신호입니다. 서명이 없거나 모르는 이의 서명이면 더 자세히 볼 이유이지, 판결은 아닙니다. 이것도 다음 페이지에서.
3. **안전하게 눈으로 보기.** 문서라면 샌드박스의 스크린샷이나 버려도 되는 VM에서 열어 보는 것만으로 한눈에 답이 나오는 경우가 많습니다. 흐릿한 "인보이스" 위에 커다란 "콘텐츠 사용"이나 "문서 보기" 버튼이 있다면 미끼입니다. (눈으로 살펴보기는 따로 한 페이지에서 다룹니다.)
4. **문자열: 있으면 안 되는 곳에 있는 것 찾기.**
    - 실행 파일이 아닌 것(문서, 그림, PDF 스트림) 안의 `MZ` / `This program cannot be run in DOS mode`, 또는 RTF 안의 그 **헥스 형태**.
    - 그림 속 스크립트(`<script>`, `powershell`, `eval(`), 그림이 끝난 뒤의 `PK`나 `%PDF`.
    - PDF 속 이상한 URL: 닮은꼴 로그인 도메인, 날 IP 주소, 무료 호스팅, URL 단축 서비스.
5. **스크립트: 이름을 읽을 수 없나?** `_0x3fa1`, `xQzPw`, `lllIIlI` 같은 변수·함수 이름과 길게 이어 붙인 문자열은 자동 스캐너를 속이려고 만든 겁니다. 오히려 사람 분석가의 일은 **쉬워집니다.** 읽을 수 있는 정상 코드는 그렇게 생길 필요가 없으니까요. 자기 코드를 보호하려고 난독화하는 개발자도 있으니, 맥락(어디서 왔나, 무엇을 하나)으로 판단합니다.
6. **최종 시험: 샌드박스에 넣기.** 실행하면 무엇을 하나요? 새 프로세스, 떨어뜨린 파일, 레지스트리 변경, 네트워크 연결. 특히 **열자마자** 일어나는 일(자동 실행 매크로, `/OpenAction` JavaScript, `\objupdate` 개체).

이 페이지의 두 시험 파일에 적용해 보면:

| 단계 | `statement_nov.doc`(RTF) | `invoice_8841.pdf` |
| --- | --- | --- |
| 1 해시 | 처음 봄(새 파일) → 판단 없음 | 처음 봄 → 판단 없음 |
| 2 서명 | 해당 없음(RTF는 Authenticode 서명 불가) | 서명 없음. 업무용 PDF는 원래 서명된 경우가 드묾 |
| 3 보기 | 글 한 줄과 `update.exe`라고 쓰인 패키지 아이콘 | "Your invoice is ready — click View Document" |
| 4 문자열 | `\objclass Package`, 헥스 `4d5a9000`, 헥스로 된 DOS 문장, `rtfobj`는 PE 실행 파일이라고 함 | `/OpenAction` → `/JavaScript`, `docs-view.example` 링크, 박힌 파일 |
| 5 스크립트 | — | `app.alert`(여기서는 무해. 실제 사건이라면 난독화돼 있을 것) |
| 6 샌드박스 | 아이콘이 보일 것. 누르면 `%TEMP%\update.exe`로 떨어뜨리고 실행 | 메시지 상자와 링크가 보일 것 |
| 판정 | **악성 패턴**: "내역서"에 박힌 실행 파일 | **의심**: 열 때 자동 실행되는 JavaScript + 첨부 + 외부 링크. 도메인을 확인하고 첨부를 꺼낸다 |

## 2026년 관점 { #trends }

!!! success "[2026 현재] 지금도 그대로 유효"
    RTF는 여전히 매크로를 못 담지만 OLE 개체와 링크는 여전히 담고, Word는 여전히 확장자가 아니라 내용으로 파일을 엽니다. `\object`/`\objdata`/`\objupdate`/`\*\template` 키워드, 글자 속 헥스 요령, `rtfobj`는 지금도 RTF 분류 방법 그대로입니다. PDF 구조(개체, 스트림, xref, 트레일러), 위험한 키워드(`/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/ObjStm`), 첫 확인으로서의 `strings | grep http`, 다음 단계로서의 `pdfid`/`pdf-parser`도 변함없습니다. 이미지·글꼴·미디어 라이브러리의 해석 버그는 지금도 해마다 나옵니다. 6단계 좋은 것/나쁜 것 가르기 순서도 여전히 건전한 작업 순서입니다.

!!! info "[변경됨] 바뀐 점"
    - **Flash는 사라졌습니다.** Adobe가 2020년 12월 31일 Flash Player를 끝냈고 뷰어도 더는 재생하지 않으니, `/RichMedia` Flash 익스플로잇은 옛 샘플에서만 의미가 있습니다. **Acrobat Reader는 지금도 JavaScript가 기본으로 켜져 있고**, 보호 모드(Protected Mode)와 고급 보안(Enhanced Security)도 기본으로 켜져 있으며, 관리자가 JavaScript를 제한하거나 끌 수 있습니다. 브라우저 내장 PDF 뷰어는 PDF JavaScript의 일부만 지원합니다.
    - **요즘 PDF는 대부분 계정 탈취 피싱의 링크와 QR 코드 운반책**입니다. 세션 쿠키를 훔쳐 일반 MFA를 무력화하는 중간자(AitM) 페이지도 포함됩니다. 익스플로잇은 적고 URL은 많을 거라고 보세요. `strings`로 못 읽는 QR 그림도 있습니다(샌드박스에서 QR 도구로 풀기).
    - **수식 편집기는 없어졌지만**(2018년 1월 제거) CVE-2017-11882는 패치 안 된 Office가 남아 있었던 탓에 수년 동안 흔한 악성코드 캠페인에 계속 나왔습니다. 새로운 RTF 해석기 버그(예: CVE-2023-21716)는 미리 보기 창이 여전히 공격 표면이라는 걸 보여 줍니다.
    - **2022년 매크로 차단 이후 바로 가기가 무대 중앙으로** 나왔습니다. ZIP/ISO/IMG 컨테이너 속 `.lnk`, LNK 아이콘 스머글링, 그리고 Microsoft가 2025년 말 조용히 완화한 공백 채우기 수법(CVE-2025-9491).
    - **이미지 라이브러리 버그가 공급망 문제가 됐습니다.** CVE-2023-4863(libwebp)은 브라우저, 메신저, 그 라이브러리를 품은 모든 앱에 영향을 줬고, 패치는 제품 하나가 아니라 여러 제품을 업데이트하는 일이었습니다.
    - **도구**: oletools(`rtfobj`, `oleid`, `olevba`, `oleobj`)와 Didier Stevens의 `pdfid`/`pdf-parser`가 여전히 표준입니다. REMnux에 미리 깔려 있고, 상당수는 FLARE-VM에도 있습니다. 샌드박스가 AI 요약을 붙여 주지만, 실제 개체와 대조해 확인하세요.
    - 이 페이지에서 쓴 **ATT&CK 이름**: T1566.001 Spearphishing Attachment, T1204.002 Malicious File, T1203 Exploitation for Client Execution, T1221 Template Injection, T1218.005 Mshta, T1059.001 PowerShell, T1547.009 Shortcut Modification, T1027.012 LNK Icon Smuggling.

!!! warning "[주의] 옛 방식대로 하면 틀리거나 위험한 점"
    - **"RTF = 매크로 없음"을 "RTF = 안전"으로 받아들이지 마세요.** 박힌 개체, 원격 템플릿, 해석기 익스플로잇에는 매크로가 필요 없습니다.
    - **확장자나 머리말이 깔끔할 거라고 믿지 마세요.** 악성 RTF는 `{\rt0` 같은 머리말과 쓰레기로 끊어 놓은 헥스를 흔히 씁니다. `grep`만이 아니라 해석기를 쓰세요.
    - **`strings | grep http`만으로 PDF가 깨끗하다고 결론 내리지 마세요.** 스트림과 개체 스트림은 압축돼 있고, 이름은 헥스 이스케이프될 수 있고, 링크가 QR 그림일 수도 있습니다.
    - **의심 파일을 내 업무용 PC에서 미리 보지 마세요.** 미리 보기 창과 썸네일 생성기도 파일을 해석합니다. 분석 장비에서는 끄고, 샘플은 격리된 VM에서만 다룹니다.
    - **`.lnk` 대상을 Windows 속성 창으로 확인하지 마세요.** 도구로 바로 가기를 해석해서 인수 전체를 읽습니다.
    - **엔드포인트 쪽을 건너뛰지 마세요.** 문서 익스플로잇은 부모-자식 프로세스 짝(`WINWORD.EXE` → `mshta.exe`, PDF 뷰어 → `powershell.exe`, `EQNEDT32.EXE` 실행)이 파일 자체보다 더 선명한 경우가 많습니다.

## 확인 문제 { #quiz }

### 문제 1

사용자가 `Remittance_0412.doc`를 받았습니다. 게이트웨이는 "매크로 없음"이라고 합니다. `file`은 `Rich Text Format data, version 1, unknown character set`이라고 하고, `grep -c objupdate`는 `1`을 돌려줍니다. (a) `.doc`가 왜 RTF일 수 있고, "매크로 없음"이 왜 안전을 뜻하지 않나요? (b) `\objupdate`는 무엇을 하고, 왜 중요한가요? (c) 사용자의 엔드포인트에서 무엇을 찾겠습니까?

??? success "정답과 해설"
    **(a)** Word는 확장자가 아니라 **내용**을 보고 파일을 열기 때문에, `.doc`로 이름을 바꾼 RTF도 정상적으로 열립니다. RTF는 VBA 매크로를 담을 수 없지만 **OLE 개체**(패키지로 감싼 실행 파일이나 스크립트 포함)를 박고, 원격 내용에 링크하고, 원격 템플릿(T1221)을 쓰고, Word RTF 해석기의 버그를 노릴 수 있습니다. 매크로 검사는 애초에 상관이 없었습니다.

    **(b)** `\objupdate`는 박힌 개체나 링크된 개체를 **문서가 열리자마자** 새로 고치거나 활성화하라고 Word에게 지시합니다. 그래서 사용자가 개체를 더블클릭할 필요가 없습니다. CVE-2017-0199 같은 익스플로잇이 경고 막대 하나 없이 "문서 열기"를 "공격자 코드 실행"으로 바꾼 방법이 이겁니다. 다음 단계: `rtfobj`로 개체를 나열하고 정체를 확인합니다(`OLE2Link`, `Equation.3`, `Package`를 찾음).

    **(c)** `WINWORD.EXE`가 `mshta.exe`, `powershell.exe`, `cmd.exe`, `wscript.exe`, `rundll32.exe`의 부모인 프로세스 생성(4688이나 Sysmon 1), `EQNEDT32.EXE` 프로세스, 문서를 연 직후 Word나 mshta의 네트워크 연결, `%TEMP%`에 떨어진 파일. 그다음 다른 엔드포인트에서 같은 파일 해시와 URL을 찾습니다.

### 문제 2

`Statement_Q3.pdf`에 `pdfid`를 돌렸더니 `/Page 1`, `/JavaScript 1(1)`, `/OpenAction 1`, `/ObjStm 2`, `/EmbeddedFile 0`이 나왔습니다. `strings Statement_Q3.pdf | grep -i http`는 아무것도 돌려주지 않습니다. (a) 각 줄은 무엇을 말해 주나요? (b) URL이 있는데도 `grep`이 못 찾을 수 있는 이유는? (c) 다음에 무엇을 하겠습니까?

??? success "정답과 해설"
    **(a)** `/Page 1`: 한 쪽짜리, 미끼의 전형. `/JavaScript 1(1)`: JavaScript가 있고, `(1)`은 그 이름이 헥스 이스케이프(예: `/J#61vaScript`)로 **난독화**됐다는 뜻입니다. 정상 생성기는 그러지 않으니 그 자체로 수상합니다. `/OpenAction 1`: 열 때 자동으로 무언가 실행되고, JavaScript와 합치면 **열자마자 코드 실행**일 가능성이 큽니다. `/ObjStm 2`: 개체가 압축된 개체 스트림 안에 담겨 있어서 키워드와 URL이 `strings`에게 안 보입니다.

    **(b)** URL이 **압축된 스트림**이나 개체 스트림(FlateDecode) 안에 있거나, JavaScript가 실행 중에 만들어 내거나, 헥스 이스케이프됐거나, **QR 코드 그림**일 수 있습니다. `strings`는 압축 안 된 글만 봅니다.

    **(c)** `pdf-parser`로 JavaScript 개체를 찾아 보여 주고 스트림을 풀어서(`-f`) URL과 코드를 뽑습니다. 안전한 환경에서 JavaScript 난독화를 풉니다. 샌드박스에서 실행해 동작과 네트워크 요청을 봅니다. 엔드포인트에서는 PDF 뷰어가 프로세스를 띄우거나 실행 파일을 쓰는지 찾습니다. 파일 해시를 구해 다른 곳에도 도착했는지 확인합니다.

### 문제 3

빠른 분류 6단계를 순서대로 놓고, 각 단계가 드러낼 수 있는 것의 예를 하나씩 드세요. 그리고 `Invoice.pdf`라는 이름의 `.lnk` 파일이 왜 익스플로잇 없이도 위험한지 설명하고, 사용자의 더블클릭에 해당하는 ATT&CK 기법을 쓰세요.

??? success "정답과 해설"
    **순서:** (1) **해시 조회**: 알려진 악성코드, 또는 기록 없음. (2) **서명 확인**: 알려진 게시자의 서명, 서명 없음, 모르는 이의 서명. (3) **안전하게 눈으로 보기**: "콘텐츠 사용"이나 "문서 보기" 버튼이 있는 미끼 화면. (4) **문자열**: 실행 파일이 아닌 것 안의 `MZ`/DOS 문장(RTF라면 그 헥스), 그림 속 스크립트, PDF 속 이상한 URL. (5) **스크립트 난독화**: 무작위 변수 이름과 이어 붙인 문자열. (6) **샌드박스**: 프로세스, 파일, 레지스트리, 네트워크 활동, 특히 열자마자 일어나는 것.

    **`.lnk`:** 바로 가기는 대상 프로그램과 그 인수를 저장합니다. 공격자는 대상을 `powershell.exe`나 `cmd.exe`로 하고, 숨은 창으로 인코딩된 다운로드-후-실행 명령을 인수로 넣고, PDF 같은 아이콘을 붙입니다. 탐색기는 `.lnk` 확장자를 숨기니 사용자에게는 `Invoice.pdf`로 보입니다. 더블클릭하면 설정된 명령이 그냥 실행됩니다. 취약점이 필요 없습니다. 기법: **T1204.002 User Execution: Malicious File**(실행되는 PowerShell은 T1059.001).

## 관련 레퍼런스 { #related }

- [의심 파일 안전하게 다루기와 위험한 파일 형식](safe-handling-file-types.md) · [문자열](strings.md) · [파일 알아보기](file-identification.md)
- [스크린샷, 샌드박스, 그리고 수동 분석으로 넘어갈 때](../http-analysis/screenshots-sandboxes.md) · [Base64](../http-analysis/base64.md)
- [피싱 배달과 초기 실행](../../../adversary/phishing-delivery.md) · [LOLBins](../../../adversary/lolbins.md) · [PowerShell 크래들](../../../adversary/powershell-cradles.md)
- [프로세스 생성 이벤트](../important-events/process-creation.md) · [이메일](../email/index.md) · [Zeek files.log와 pe.log](../../../network/zeek/files-log.md)
