---
title: "Questions — BOF, COFF, Loaders, and OBJ Files"
---

# Questions — BOF, COFF, Loaders, and OBJ Files { #bof-coff-and-object-files-questions }

**Supplement to Lesson 13:** This page preserves the follow-up questions, detailed explanations, simpler analogy, and corrected build-to-execution sequence. Examples refer to typical Windows BOFs; exact loader support varies.

## Can BOF and COFF be explained in more detail? { #bof-versus-coff }

They describe different aspects of a file:

| Term | Full name | Describes |
|---|---|---|
| BOF | Beacon Object File | Task code written for a supported agent execution convention |
| COFF | Common Object File Format | The structure containing object code and related information |
| COFF loader | Loader implementation | Software that reads such a file and prepares its code to run |

Both statements can be true: “This is a BOF that queries account information” and “This BOF is packaged as a COFF object file.” The format and the task convention are not rival execution methods.

A BOF needs conventions for its entry function, arguments, output, and supported external functions. Arbitrarily compiling a C program to an object file does not guarantee a compatible BOF. The term originated with Cobalt Strike's Beacon; compatible execution environments can support the same model. [BOF description from the originating project](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm?Highlight=bof)

## What is inside a COFF object? { #inside-a-coff-object }

| Component | Plain explanation |
|---|---|
| Header | Basic information such as target machine type |
| Sections | Regions containing code or data |
| Symbol information | Names and references for functions and data |
| Relocation information | Information needed to adjust references when code/data are placed |

At compilation, the final memory location of a string or function may not yet be known. Preparation must connect references to their eventual locations. COFF is a general development format, not an inherently offensive format. Windows PE executable images and COFF object files are related but distinct; a COFF object is not simply an ordinary ready-to-launch EXE. [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

An illustrative loader sequence is to read structure, arrange code/data in memory, resolve supported references and address adjustments, then call the agreed entry function. COFFLoader is one implementation, not the name of the file format itself. [COFFLoader project](https://github.com/sliverarmory/COFFLoader)

## Can this be explained more simply? { #simpler-report-and-docx-analogy }

Think of a **report** and **DOCX**:

- Report describes the document's purpose and content.
- DOCX describes how a document is stored.

Similarly, BOF describes the task program and its execution convention; COFF describes its object-file structure. The analogy explains this relationship, not the technical equivalence of documents and executable code.

| Term | Simplest working explanation |
|---|---|
| BOF | Small additional task program |
| COFF | Object-file format used to contain that code |
| Loader | Functionality that prepares the object code for execution |

For a user-name query:

```text
Task: Find the current account name
    -> BOF: Small program implementing that task
    -> COFF: Object-file structure containing its code

Existing implant
    -> Loader prepares the BOF
    -> BOF queries the account
    -> Illustrative result: LAB\student
```

Thus, “account-query BOF” describes the program, while “COFF format” describes how its object code is organized.

## Is an OBJ file an object file? { #what-is-an-obj-file }

**Yes. `.obj` is a common object-file extension.** An object file is an intermediate compilation result. It can already contain machine code, data, and information needed for connection with other code, while ordinary executable preparation remains to be done.

```text
hello.c          hello.obj          hello.exe
Source code  ->  Object file    ->  Executable
             Compile           Link
```

| Stage | Meaning |
|---|---|
| Source code | Instructions written by a programmer |
| Compile | Translate source into object code for a target |
| Object file | Resulting code/data with linking information |
| Link | Combine and connect needed code and references |
| Executable | Image prepared for normal operating-system loading |

For example, source may call an output function. The object can describe that reference while the work needed to connect it remains. An object is not uncompiled source, and it is not normally launched like a finished EXE.

BOFs use object code following their own runtime conventions. Compare the simplified paths:

```text
Ordinary program:
Source -> Object file -> Link -> Launch EXE

BOF:
Source -> BOF-compatible object -> Loader prepares it -> Run inside implant
```

| Label | What it tells you |
|---|---|
| `.obj` | A commonly used filename extension |
| COFF | Internal object-file structure |
| BOF | Supported agent task-program convention |

Not every `.obj` is a BOF. Objects can also use `.o`; an extension alone does not establish internal format or BOF compatibility. Renaming a file does not change its structure or execution convention.

## Is it built for the implant environment, then prepared by a loader? { #environment-build-loader-sequence }

**Learner question:** “So a BOF object is generated for the environment where the implant runs, and then the loader prepares and executes it?”

**Yes, with one wording correction:** the compiler produces the object from BOF source; a BOF does not itself generate the object merely by being a BOF.

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

“Compatible target” includes the OS, **implant-process architecture**, supported execution convention, and dependencies. A 64-bit OS does not automatically mean every process on it is 64-bit. Packages can supply precompiled objects through Armory, so the operator need not personally compile each use.

The BOF and loader do not automatically acquire a new identity or administrator token. Resource access still depends on the effective process/thread context and permissions. A successful user query establishes that query in its execution context, not unrestricted access elsewhere.

## Compare ordinary EXE and usual BOF execution { #compare-exe-and-bof }

| Point | Ordinary EXE launch | Usual BOF execution |
|---|---|---|
| Prepared artifact | Finished PE executable | Compatible object code |
| Preparation | Operating-system loading and runtime support as needed | BOF loader/executor |
| Process placement | Usually a new program process | Usually the existing implant process |
| Result handling | Program's chosen output mechanism | Supported BOF output mechanism |
| Automatically elevated? | No | No |

A BOF can itself create processes, read/write files, or communicate if its task does so. The usual in-process loading mechanism does not make all later behavior invisible. The same distinction is developed in [Lesson 14](lesson-14-exe-dotnet-and-bof-execution.md).

[Previous: Armory and BOF basics](lesson-13-armory-and-bof-basics.md) · [Next: EXE, .NET, and BOF execution](lesson-14-exe-dotnet-and-bof-execution.md)
