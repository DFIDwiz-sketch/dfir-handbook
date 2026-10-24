---
title: "14강 — EXE·.NET Assembly·BOF 실행"
---

# 14강 — EXE·.NET Assembly·BOF 실행 { #lesson-14-exe-dotnet-and-bof-execution }

**학습 목표:** ‘현재 계정 표시’라는 단순한 작업으로 실행 방식을 비교합니다. 코드 형식, 파일 위치, 런타임, 프로세스 위치, 정상 결과를 구분합니다.

실습 명령의 예이며 학습자 대신 실제 실행한 결과 보고가 아닙니다. Windows 예시는 앞의 Linux 웹 Session이 아닌 호환되는 **Windows 대상**을 사용합니다.

## 비슷한 작업을 수행하는 세 방식 { #three-execution-mechanisms }

| 방식 | 준비한 코드 | 실행 구조 |
|---|---|---|
| `execute`로 프로그램 시작 | 대상에 있는 프로그램 | 프로그램 프로세스 시작 |
| .NET Assembly 실행 | 호환 .NET 코드와 메타데이터 | 적합한 .NET 실행 환경 사용 |
| BOF 실행 | 호환 작업 목적 코드 | 보통 기존 Implant 안에서 준비·실행 |

파일 이름을 서로 배타적으로 분류한 표가 아니라 실행 방식의 비교입니다. 특히 .NET 프로그램도 대상에 파일과 필요한 런타임이 있으면 일반 프로그램처럼 시작할 수 있습니다.

## 기존 Windows 프로그램 시작 { #launch-an-existing-program }

Windows의 `whoami.exe`는 계정 정보를 표시합니다. **Windows 실습 Session을 선택한 Sliver 콘솔**에서 입력합니다.

```text
help execute
execute --output whoami.exe
```

`execute`는 대상에서 프로그램 시작 요청, `--output`은 출력 수집, `whoami.exe`는 대상 프로그램입니다. 대상에서 이 Windows 프로그램을 찾을 수 있다는 전제입니다. 운영자 컴퓨터의 실행 파일을 자동 업로드하지는 않습니다. [Sliver execute 구현](https://github.com/BishopFox/sliver/blob/master/client/command/exec/execute.go)

```text
Target Windows host
    Implant process
    Separate whoami.exe program process
```

Sliver 기본 명령과 명시적인 프로그램 시작을 비교합니다.

```text
whoami
execute --output whoami.exe
```

비슷한 정보를 다루지만 내부 동작이 같다고 입증되지는 않습니다. 두 번째는 대상의 별도 프로그램을 명시적으로 시작합니다. 이름이나 결과가 비슷해도 같은 실행 경로로 가정하면 안 됩니다.

## .NET Assembly는 어셈블리어가 아닌 코드 단위 { #what-is-a-dotnet-assembly }

여기서 **Assembly는 어셈블리어가 아닙니다.** 코드와 관련 정보를 묶은 .NET의 단위입니다. 현재 Windows 계정 이름을 표시하는 간단한 C# 콘솔 프로그램을 생각해 보세요. 호환되는 .NET Framework 빌드의 이름을 `LabWhoAmI.exe`로 지을 수 있습니다.

Assembly는 EXE나 DLL 파일일 수 있습니다. EXE 확장자만으로 네이티브 코드인지 관리형 .NET 코드인지 알 수 없습니다. [Microsoft Assembly 설명](https://learn.microsoft.com/en-us/dotnet/standard/assembly/)

여기서 다룰 일반적인 관리형 .NET Framework 예의 흐름입니다.

```text
C# source
    -> Build a .NET Assembly
    -> .NET runtime prepares the code
    -> CPU executes the required instructions
```

**CLR, Common Language Runtime**은 실행 환경을 제공합니다. 관리형 컴파일은 보통 중간 코드를 만들며, 런타임은 필요한 코드를 CPU 명령으로 바꾸고 메모리 관리 등을 지원할 수 있습니다. 입문용 설명이며 현대 C#의 모든 빌드가 같은 배포·런타임 방식을 쓴다는 뜻은 아닙니다. [Microsoft 관리형 실행 과정](https://learn.microsoft.com/en-us/dotnet/standard/managed-execution-process)

## execute-assembly는 Client의 파일을 읽음 { #client-side-assembly-file }

**Sliver 콘솔**에서 확인합니다.

```text
help execute-assembly
```

명령 형태를 보여 주는 예시입니다.

```text
execute-assembly /home/student/lab/LabWhoAmI.exe
```

`LabWhoAmI.exe`는 설명용 이름이며 Sliver에 포함된 도구가 아닙니다. **Sliver Client 컴퓨터**의 해당 경로에 호환되는 단순한 Assembly가 실제로 있어야 합니다. 모든 C#·EXE 파일이 이 조건을 만족하지는 않습니다. Client가 파일 내용을 읽어 대상 실행을 위해 전달합니다. [execute-assembly 구현](https://github.com/BishopFox/sliver/blob/master/client/command/exec/execute-assembly.go)

| 예시 | 지정한 파일의 위치 |
|---|---|
| `execute --output whoami.exe` | 대상 컴퓨터 |
| `execute-assembly /home/student/lab/LabWhoAmI.exe` | Client 컴퓨터 |

운영자 쪽 Linux 경로를 지정했다고 Assembly가 Linux 대상 프로그램이 되는 것은 아닙니다. 파일의 위치와 대상 호환성은 별개입니다.

## 메모리 로딩과 실행 프로세스는 다른 질문 { #memory-loading-and-process-placement }

확인한 Sliver 버전의 기본 `execute-assembly`는 **Windows의 자식 호스팅 프로세스**에 Assembly를 불러 실행합니다. 기존 프로세스 안에서 실행하는 옵션도 있습니다. 따라서 메모리 실행이라고 기존 Implant 안에서 실행된다고 단정할 수 없습니다. [Sliver 명령 정의](https://github.com/BishopFox/sliver/blob/master/client/command/exec/commands.go)

```text
Target Windows host
    Implant process
    Separate hosting process
        .NET runtime
            Supplied assembly code
```

호스팅 프로세스는 코드를 실행할 자리를 제공합니다. 두 관점을 구분합니다.

| 질문 | 설명하는 관점 |
|---|---|
| 코드를 어떻게 준비하고 실행하는가? | 로딩·실행 방식 |
| 어느 프로세스에서 실행하는가? | 프로세스 위치 |

실제 동작은 선택한 구현과 옵션에 따라 다릅니다. ‘메모리’라는 말만으로 추측하지 말고 설치된 도움말과 실제 프로세스 증거를 확인합니다.

## 목적 파일 모델을 사용하는 BOF { #bof-object-file-model }

같은 계정 조회를 BOF로 만들 수 있습니다.

```text
Account-query source
    -> Compile for compatible target
    -> BOF object file
    -> Loader prepares execution
    -> Task runs inside the existing implant
```

```text
Target Windows host
    Implant process
        BOF executor / loader
            Account-query BOF
```

`sa-whoami` 같은 추가 도구가 이 패키지 모델의 예입니다. 설치, 대상 호환성, 실행 지원이 준비되어야 합니다. BOF 작업이 다른 프로그램을 시작한다면 새 프로세스도 생길 수 있습니다. 그림은 BOF 코드 자체의 일반적인 위치이며 이후 모든 동작을 보장하지는 않습니다.

## 반환된 이름보다 실행 증거 비교 { #compare-execution-evidence }

| 구분 | 프로그램 시작 | .NET Assembly 방식 | 일반적인 BOF 방식 |
|---|---|---|---|
| 코드 형태 | 완성된 프로그램 이미지 | .NET 코드와 메타데이터 | 작업 목적 코드 |
| 실행 준비 | OS 로딩과 필요한 런타임 | 호스팅 방식과 .NET 환경 | BOF 실행기·로더 |
| 여기서 설명한 위치 | 새 프로그램 프로세스 | 기본적으로 별도 호스트 | 기존 Implant |
| 자동 관리자 권한 획득 | 아니요 | 아니요 | 아니요 |

계정 이름이 같아도 같은 방식으로 실행했다고 입증되지는 않습니다. 실효 컨텍스트가 다르면 계정도 달라질 수 있습니다. 결과를 의도한 대상·작업·컨텍스트와 맞춰야 하며 요청, 실행, 정상 완료는 여전히 별개입니다.

## 상세 해답 1: 모든 Tool.exe를 execute-assembly로 실행할까요? { #answer-exe-extension }

**질문:** 이름이 `Tool.exe`라는 이유만으로 `execute-assembly`를 선택할 수 있을까요?

**학습자 답:** ‘아니요. 일반 실행 파일일 수도 있습니다.’

**정확합니다.** 네이티브 실행 파일 또는 .NET Assembly일 수 있습니다. 확장자가 구분해 주지 않으며 파일 이름을 바꿔도 호환 .NET 코드가 되지 않습니다. 실제 형식과 런타임 요구를 확인합니다.

추가 설명도 중요합니다. 호환 .NET EXE가 대상에 저장되어 있고 필요한 환경이 있다면 `execute`로 일반 프로그램처럼 시작할 수도 있습니다. 파일 종류와 요청하는 실행 방식은 다른 분류입니다.

## 상세 해답 2: 메모리 실행이면 새 호스트가 없을까요? { #answer-hosting-process }

**질문:** Assembly를 메모리에 불러 실행했습니다. 새 프로세스가 만들어지지 않았다고 확정할 수 있을까요?

**학습자 답:** ‘아니요. 호스팅 프로세스가 실행되었을 수도 있습니다.’

**정확합니다.** 다음 두 방식 모두 메모리 로딩을 설명합니다.

```text
Model A
Existing implant process
    -> Load and run code in that process

Model B
Existing implant process
    -> Create separate hosting process
        -> Load and run code in its memory
```

**어떻게 실행했는지**와 **어디서 실행했는지**를 함께 묻습니다. 프로세스 생성과 계정에는 각각의 증거가 필요하며 메모리 실행이라는 말만으로 답할 수 없습니다.

[이전: BOF·COFF·OBJ 문답](bof-coff-and-object-files-questions.md) · [학습 범위와 다음 단계](course-coverage-and-next-steps.md) · [강좌 개요](index.md)
