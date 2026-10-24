---
title: "Lesson 14 — EXE, .NET Assembly, and BOF Execution"
---

# Lesson 14 — EXE, .NET Assembly, and BOF Execution { #lesson-14-exe-dotnet-and-bof-execution }

**Goal:** Compare execution mechanisms using the harmless task “report the current account.” Separate code format, file location, runtime, process placement, and successful results.

These are lab command examples, not a report of executions performed for the reader. Use a compatible **Windows target** for the Windows examples, not the Linux web Session from the earlier SSH scenario.

## Three ways to perform a similar task { #three-execution-mechanisms }

| Mechanism | Prepared code | Execution model |
|---|---|---|
| Launch a program with `execute` | A program available on the target | Start a program process |
| Execute a .NET Assembly | Compatible .NET code and metadata | Use a suitable .NET execution environment |
| Execute a BOF | Compatible task object code | Usually prepare and run it inside the existing implant |

These are comparisons of mechanisms, not mutually exclusive filename categories. In particular, a .NET program can also be launched normally when the target has the file and required runtime.

## Launch an existing Windows program { #launch-an-existing-program }

Windows provides `whoami.exe` to report identity information. With a **Windows lab Session selected in the Sliver console**:

```text
help execute
execute --output whoami.exe
```

`execute` requests a program launch on the target, `--output` captures its output, and `whoami.exe` is the target program. This assumes the Windows program can be located on that target. The command does not automatically upload an executable from the operator's machine. [Sliver execute implementation](https://github.com/BishopFox/sliver/blob/master/client/command/exec/execute.go)

```text
Target Windows host
    Implant process
    Separate whoami.exe program process
```

Compare the built-in Sliver command with the explicit program launch:

```text
whoami
execute --output whoami.exe
```

They concern similar information but do not establish identical internal behavior. The second explicitly starts a target-side program. Similar names or output do not prove identical execution paths.

## A .NET Assembly is a code unit, not assembly language { #what-is-a-dotnet-assembly }

Here, **Assembly does not mean assembly language**. It is a .NET unit containing code and related information. Imagine a simple C# console program that prints its Windows account identity. A compatible .NET Framework build might be named `LabWhoAmI.exe`.

Assemblies can be EXE or DLL files. An EXE suffix alone does not identify whether its code is native or managed .NET code. [Microsoft assembly explanation](https://learn.microsoft.com/en-us/dotnet/standard/assembly/)

For the ordinary managed .NET Framework example used here:

```text
C# source
    -> Build a .NET Assembly
    -> .NET runtime prepares the code
    -> CPU executes the required instructions
```

The **CLR**, Common Language Runtime, supplies the execution environment. Managed compilation commonly produces intermediate code; the runtime can translate needed code into CPU instructions and supply services such as memory management. This is an introductory model, not a claim that every modern C# build uses the same deployment/runtime model. [Microsoft managed execution process](https://learn.microsoft.com/en-us/dotnet/standard/managed-execution-process)

## execute-assembly reads a Client-side file { #client-side-assembly-file }

In the **Sliver console**:

```text
help execute-assembly
```

An illustrative command shape is:

```text
execute-assembly /home/student/lab/LabWhoAmI.exe
```

`LabWhoAmI.exe` is an illustrative filename, not an included Sliver tool. A compatible harmless assembly must actually exist at that path on the **Sliver Client machine**. Not every C# or EXE file satisfies that requirement. The Client reads its bytes for target execution. [execute-assembly implementation](https://github.com/BishopFox/sliver/blob/master/client/command/exec/execute-assembly.go)

| Example | Where the named file is located |
|---|---|
| `execute --output whoami.exe` | Target machine |
| `execute-assembly /home/student/lab/LabWhoAmI.exe` | Client machine |

The operator-side Linux path does not make the assembly a Linux target program. Source-file location and target compatibility are separate properties.

## Memory loading and process placement are different questions { #memory-loading-and-process-placement }

In the checked Sliver version, default `execute-assembly` loads and executes the assembly in a **child hosting process on Windows**. An in-process option also exists. Therefore memory execution does not automatically mean execution inside the existing implant. [Sliver command definitions](https://github.com/BishopFox/sliver/blob/master/client/command/exec/commands.go)

```text
Target Windows host
    Implant process
    Separate hosting process
        .NET runtime
            Supplied assembly code
```

A hosting process supplies a place for the code to run. Keep two dimensions separate:

| Question | Dimension |
|---|---|
| How is code prepared and run? | Loading/execution mechanism |
| In which process does it run? | Process placement |

The actual behavior depends on the selected implementation and options. Inspect the installed help and observed process evidence rather than inferring it from the words “in memory.”

## BOF execution uses the object-file model { #bof-object-file-model }

The same account-query task could be implemented as a BOF:

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

An additional tool such as `sa-whoami` illustrates this package model. Installation, target compatibility, and required execution support must be in place. A BOF can itself start another program if its task does so; the diagram describes usual placement of the BOF's own code, not a guarantee about every subsequent action.

## Compare evidence, not just returned names { #compare-execution-evidence }

| Point | Program launch | .NET Assembly mechanism | Usual BOF mechanism |
|---|---|---|---|
| Code artifact | Finished program image | .NET code and metadata | Task object code |
| Preparation | OS loading and needed runtime support | Hosting model and .NET environment | BOF executor/loader |
| Placement discussed here | New program process | Separate host by default | Existing implant |
| Automatically gains administrator rights? | No | No | No |

Similar account-name output does not establish the same execution mechanism. Different effective contexts can also produce different identities. A result must be tied to the intended target, task, and context; request, execution, and successful completion remain separate stages.

## Detailed answer 1: can every Tool.exe use execute-assembly? { #answer-exe-extension }

**Question:** The file is named `Tool.exe`. Is that enough to choose `execute-assembly`?

**Learner answer:** “No. It could be an ordinary executable.”

**Correct.** It could be a native executable or a .NET assembly. The suffix does not distinguish them, and renaming a file does not turn it into compatible .NET code. Check the actual format and runtime requirements.

The additional clarification is important: a compatible .NET EXE can also be started as an ordinary program with `execute` when it is present on the target and that target has the necessary environment. Artifact type and requested execution mechanism are different classifications.

## Detailed answer 2: does memory execution exclude a new host? { #answer-hosting-process }

**Question:** An assembly was loaded into memory. Can we conclude no new process was created?

**Learner answer:** “No. A hosting process might have been started.”

**Correct.** Both of these descriptions involve memory loading:

```text
Model A
Existing implant process
    -> Load and run code in that process

Model B
Existing implant process
    -> Create separate hosting process
        -> Load and run code in its memory
```

Ask both **how the code was executed** and **where it executed**. Process creation and identity need their own evidence; memory execution alone does not answer either question.

[Previous: BOF, COFF, and OBJ questions](bof-coff-and-object-files-questions.md) · [Course coverage and next steps](course-coverage-and-next-steps.md) · [Course overview](index.md)
