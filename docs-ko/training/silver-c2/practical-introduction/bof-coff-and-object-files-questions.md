---
title: "문답 — BOF·COFF·로더·OBJ 파일"
---

# 문답 — BOF·COFF·로더·OBJ 파일 { #bof-coff-and-object-files-questions }

**13강 보충:** 추가 질문, 자세한 설명, 더 쉬운 비유, 빌드부터 실행까지의 정정한 흐름을 모았습니다. 전형적인 Windows BOF를 기준으로 하며 구체적인 로더 지원은 달라질 수 있습니다.

## BOF와 COFF를 더 자세히 설명해 주세요 { #bof-versus-coff }

한 파일을 서로 다른 관점에서 설명합니다.

| 용어 | 전체 이름 | 설명하는 것 |
|---|---|---|
| BOF | Beacon Object File | 지원되는 에이전트 실행 규약에 맞춘 작업 코드 |
| COFF | Common Object File Format | 목적 코드와 관련 정보를 담는 구조 |
| COFF 로더 | 로더 구현 | 파일을 읽어 코드를 실행할 준비를 하는 소프트웨어 |

‘계정 정보를 조회하는 BOF’와 ‘이 BOF는 COFF 목적 파일로 담았다’는 설명이 동시에 맞을 수 있습니다. 파일 형식과 작업 규약은 경쟁하는 실행 방식이 아닙니다.

BOF에는 시작 함수, 인자, 출력, 지원 외부 함수 등에 관한 규약이 필요합니다. 아무 C 프로그램을 목적 파일로 컴파일했다고 호환되는 BOF가 되지는 않습니다. 이름은 Cobalt Strike의 Beacon에서 유래했으며 호환 실행 환경에서도 이 방식을 지원할 수 있습니다. [BOF가 유래한 프로젝트의 설명](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm?Highlight=bof)

## COFF 목적 파일 안에는 무엇이 있나요? { #inside-a-coff-object }

| 구성 요소 | 쉬운 설명 |
|---|---|
| 헤더 | 대상 CPU 종류 등 기본 정보 |
| 섹션 | 코드·데이터가 들어가는 구역 |
| 심볼 정보 | 함수·데이터의 이름과 참조 정보 |
| 재배치 정보 | 코드·데이터를 배치할 때 참조를 조정하는 정보 |

컴파일할 때 문자열이나 함수의 최종 메모리 위치가 정해지지 않았을 수 있습니다. 실행 준비 시 참조를 실제 위치에 연결해야 합니다. COFF는 일반 개발에서도 쓰는 형식이며 본질적으로 공격용 형식은 아닙니다. Windows PE 실행 이미지와 COFF 목적 파일은 관련되지만 구분됩니다. COFF 목적 파일을 곧바로 일반적인 완성형 EXE라고 생각하면 안 됩니다. [Microsoft PE·COFF 명세](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

로더의 흐름을 단순화하면 구조 읽기, 메모리 배치, 지원 참조와 주소 조정 연결, 약속한 시작 함수 호출입니다. COFFLoader는 그 구현 예이며 파일 형식 자체의 이름과 다릅니다. [COFFLoader 프로젝트](https://github.com/sliverarmory/COFFLoader)

## 조금 더 쉽게 설명할 수 있나요? { #simpler-report-and-docx-analogy }

**보고서**와 **DOCX**를 생각해 보세요.

- 보고서는 문서의 용도와 내용을 설명합니다.
- DOCX는 문서를 저장하는 형식입니다.

비슷하게 BOF는 작업 프로그램과 실행 규약을, COFF는 목적 파일의 구조를 설명합니다. 문서와 실행 코드가 기술적으로 같다는 비유가 아니라 이 관계를 쉽게 설명한 것입니다.

| 용어 | 가장 쉬운 이해 |
|---|---|
| BOF | 특정 작업을 하는 작은 추가 프로그램 |
| COFF | 그 코드를 담는 목적 파일 형식 |
| 로더 | 목적 코드를 실행할 준비를 하는 기능 |

사용자 이름 조회 예입니다.

```text
Task: Find the current account name
    -> BOF: Small program implementing that task
    -> COFF: Object-file structure containing its code

Existing implant
    -> Loader prepares the BOF
    -> BOF queries the account
    -> Illustrative result: LAB\student
```

따라서 ‘사용자 조회 BOF’는 프로그램을, ‘COFF 형식’은 그 목적 코드의 배치를 설명합니다.

## 목적 파일이란 OBJ 파일인가요? { #what-is-an-obj-file }

**네. `.obj`는 목적 파일에 흔히 쓰는 확장자입니다.** 목적 파일은 컴파일한 중간 결과물입니다. 기계어 코드, 데이터, 다른 코드와 연결하기 위한 정보를 포함할 수 있지만 일반적인 실행 파일로 준비하는 작업은 남아 있습니다.

```text
hello.c          hello.obj          hello.exe
Source code  ->  Object file    ->  Executable
             Compile           Link
```

| 단계 | 의미 |
|---|---|
| 소스 코드 | 사람이 작성한 명령 |
| 컴파일 | 소스를 대상 환경의 목적 코드로 번역 |
| 목적 파일 | 번역한 코드·데이터와 연결 정보 |
| 링크 | 필요한 코드와 참조를 결합·연결 |
| 실행 파일 | 일반적인 운영체제 로딩을 위해 준비한 이미지 |

예를 들어 소스가 화면 출력 함수를 호출할 수 있습니다. 목적 파일에 그 참조가 들어 있어도 실제로 연결하는 작업이 남아 있을 수 있습니다. 컴파일되지 않은 소스와도 다르고, 보통 완성형 EXE처럼 바로 시작하는 파일도 아닙니다.

BOF는 별도의 실행 규약에 맞춘 목적 코드를 활용합니다. 단순화한 경로를 비교합니다.

```text
Ordinary program:
Source -> Object file -> Link -> Launch EXE

BOF:
Source -> BOF-compatible object -> Loader prepares it -> Run inside implant
```

| 표기 | 알려 주는 것 |
|---|---|
| `.obj` | 흔히 쓰는 파일 이름 확장자 |
| COFF | 파일 내부의 목적 파일 구조 |
| BOF | 지원되는 에이전트 작업 프로그램 규약 |

모든 `.obj`가 BOF는 아닙니다. 목적 파일은 `.o`도 사용하며 확장자만으로 내부 형식·BOF 호환성을 확정할 수 없습니다. 파일 이름을 바꿔도 구조나 실행 규약은 바뀌지 않습니다.

## Implant 환경에 맞춰 만들고 로더가 실행하나요? { #environment-build-loader-sequence }

**학습자 질문:** ‘Implant가 있는 환경에 맞게 BOF 목적 파일을 생성하고, 로더가 준비해서 실행하는 것인가요?’

**네. 한 가지 표현을 더 정확히 하면**, 컴파일러가 BOF 소스에서 목적 파일을 만듭니다. BOF라는 이유만으로 BOF 스스로 목적 파일을 생성하는 것은 아닙니다.

```text
1. Development / build environment
   BOF source code
       -> Compile for compatible target
       -> BOF object file, such as Windows/x64 COFF

2. Target computer
   Running implant receives task code
       -> Loader prepares memory and required references
       -> BOF entry function runs
       -> Result returns
```

맞춰야 할 환경에는 OS, **Implant 프로세스의 아키텍처**, 지원 실행 규약, 의존성이 포함됩니다. 64비트 OS에서도 모든 프로세스가 64비트인 것은 아닙니다. Armory 패키지에 컴파일된 목적 파일이 들어 있을 수 있으므로 운영자가 매번 직접 컴파일할 필요는 없습니다.

BOF와 로더가 자동으로 다른 신원이나 관리자 토큰을 얻지는 않습니다. 자원 접근은 실제 프로세스·스레드 컨텍스트와 권한에 달려 있습니다. 사용자 조회 성공은 그 컨텍스트에서의 해당 조회를 입증하며 다른 자원에 대한 무제한 접근을 뜻하지 않습니다.

## 일반 EXE와 보통의 BOF 실행 비교 { #compare-exe-and-bof }

| 구분 | 일반 EXE 시작 | 일반적인 BOF 실행 |
|---|---|---|
| 준비한 파일 | 완성된 PE 실행 파일 | 호환 목적 코드 |
| 실행 준비 | 운영체제 로딩과 필요한 런타임 지원 | BOF 로더·실행기 |
| 프로세스 위치 | 보통 새 프로그램 프로세스 | 보통 기존 Implant 프로세스 |
| 결과 전달 | 프로그램이 선택한 출력 방식 | 지원되는 BOF 출력 방식 |
| 자동 관리자 승격 | 아니요 | 아니요 |

BOF가 그런 작업을 수행하면 프로세스 생성, 파일 읽기·쓰기, 통신도 가능합니다. 일반적인 프로세스 내부 로딩이 이후 동작을 모두 보이지 않게 만들지는 않습니다. [14강](lesson-14-exe-dotnet-and-bof-execution.md)에서 실행 방식의 차이를 이어갑니다.

[이전: Armory와 BOF 기본](lesson-13-armory-and-bof-basics.md) · [다음: EXE·.NET·BOF 실행](lesson-14-exe-dotnet-and-bof-execution.md)
