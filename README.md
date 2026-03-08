> [!NOTE]
> This repo is a work-in-progress

# ExeTraducer

A (not-so-)small **python 3.x** project made with the intent to fully "translate" a windows PE file, *either 32-bit or 64-bit, x86/x64 or ARM 32/64* into an ELF binary for Unix and Unix-like systems.  
This is (hopefully) acheived with this small Pipeline:

```
       PE File
         |
   src/disassembler -> Assembly lines
         |
   src/translator   -> x64/x86 Assembly <-> IR <-> ARM64 Assembly lines
         |
      assembler     -> ELF x86/x64/ARM32/ARM64 binary
```

Support for .NET PEs and WinAPI functions will be provided respectively through:

* .NET-specific disassembly logic
* Not-yet-fully-planned static C/C++ libraries or shims

# Status

|Code / Abstract Logic|Completition|
|---|---|
|src/disassembler|100%|
|src/translator|20%|
|general asm-to-asm translation logic:|40%|
|.NET logic:|70%|
|WinAPI support:|0%|
