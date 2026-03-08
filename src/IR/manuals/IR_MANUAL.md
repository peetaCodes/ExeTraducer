# ExeTraducer IR — Reference Manual (v0.1)

> **Purpose:** definitive reference manual for the ExeTraducer Intermediate Representation (IR). This manual documents
> the IR we’ve designed so far — syntax, semantics, canonical JSON form, validation rules, and practical guidance for
> lifter and backend implementers.

> **Audience:** lifter/backend developers, tool integrators, and contributors. The IR is intentionally low-level and
> implementation-oriented so it can be used to write lifters, backends, canonicalizers, and test harnesses.

---

## Table of contents

1. [Introduction & Goals](#introduction--goals)
2. [Big Picture — Where IR Fits](#big-picture--where-ir-fits)
3. [Design Principles](#design-principles)
4. [Program State Primitives](#program-state-primitives)
5. [Widths & Endianness](#widths--endianness)
6. [Operand Model & Addressing Expressions](#operand-model--addressing-expressions)
7. [Language Categories & Instruction Set](#language-categories--instruction-set)
8. [Control Flow Primitives](#control-flow-primitives)
9. [Flags Model & Semantics](#flags-model--semantics)
10. [Function Calls, ABIs & Call Adapters](#function-calls-abis--call-adapters)
11. [Side-Effects, Implicitness & Canonicality](#side-effects-implicitness--canonicality)
12. [Undefined & Implementation-Defined Behavior Policy](#undefined--implementation-defined-behavior-policy)
13. [Textual Syntax (Human-Friendly IR)](#textual-syntax-human-friendly-ir)
14. [Canonical JSON Form (Machine-Friendly)](#canonical-json-form-machine-friendly)
15. [Core JSON Schema (Compact)](#core-json-schema-compact)
16. [Examples: x86 → IR Mappings](#examples-x86--ir-mappings)
17. [Round-Trips & API Contracts](#round-trips--api-contracts)
18. [Validation Rules & Canonicalization](#validation-rules--canonicalization)
19. [Extension Points: SIMD, Atomics, Privileged Ops](#extension-points-simd-atomics-privileged-ops)
20. [Testing Strategy & Recommended Unit Tests](#testing-strategy--recommended-unit-tests)
21. [Implementation Checklist & Next Steps](#implementation-checklist--next-steps)
22. [Glossary & Conventions](#glossary--conventions)
23. [Appendix: Minimal Examples](#appendix-minimal-examples)

---

## Introduction & Goals

ExeTraducer IR is the canonical, low-level, architecture-neutral representation used by ExeTraducer to implement static
**assembly → IR → assembly** translation. It is explicitly designed to be:

- **Semantically explicit**: every side effect (flags, memory, SP, PC) is represented in the IR. No hidden behavior.
- **Low-level but architecture-neutral**: sufficient to express x86/x64/ARM semantics precisely without introducing
  source-level constructs.
- **Easy to implement**: compact textual syntax and a canonical JSON form for tooling.
- **Practical**: target >70% of real-world assembly usage quickly, and be extensible to cover the rest.

This manual documents the IR elements implemented so far (v0.1) and gives lifter/backend implementers the rules they
need for interoperability.

---

## Big Picture — Where IR Fits

Typical pipeline:

```
PE bytes (or other binary)
  ↓ (disassembler)
Assembly (capstone, etc.)
  ↓ (lifter)
IR (textual + canonical JSON)
  ↓ (analysis / transforms / canonicalizer / optimizer)
IR (validated + canonical)
  ↓ (backend)
Target assembly / object / native binary
```

IR is the single canonical semantic representation. Lifters map assembly → IR; backends map IR → target assembly. Tests
validate final machine-visible semantics by comparing execution traces.

---

## Design Principles

1. **Semantic clarity:** every instruction’s semantics must be explicit. No side-effects are implicit.
2. **Low-level:** model registers, flags, memory, control flow; do not introduce types or object-level constructs.
3. **IR as canonical layer:** implement analysis and optimizations on IR, not on source assembly.
4. **Readable & serializable:** textual syntax for humans; canonical JSON for tooling.
5. **Deterministic fallback:** for undefined behavior, pick deterministic semantics and annotate with metadata.
6. **Extensible:** easy to add new instructions (SIMD, atomics) while preserving older semantics.

---

## Program State Primitives

The IR models the following primitives explicitly:

- **Registers**: named physical registers (e.g., `RAX`, `EAX`, `X0`) exposed as register operands.
- **Temps**: `t0`, `t1`, etc. — ephemeral values used by lifters/backends.
- **Flags**: `CF, PF, AF, ZF, SF, OF` (explicit flag pseudo-registers).
- **Memory**: byte-addressable linear memory. Accessed via `load`/`store` with explicit addresses.
- **Stack pointer (`SP`)**: modeled as a normal register but semantically special for ABI passes.
- **Program counter (`PC`)**: pseudo-register representing current instruction address for indirect control flow.
- **Environment metadata**: image base, entry point, imports, exports, section info — kept alongside IR.

All state-changing effects must be visible in IR.

---

## Widths & Endianness

- All values are **width-tagged** in bits (8, 16, 32, 64, 128...). Example: `{type: 'reg', name: 'RAX', width: 64}`.
- Endianness is declared in IR header; for PE-derived IR default is `little`.
- Implicit size casts are **not allowed**. Lifters must insert `sext`, `zext`, or `trunc` explicitly.

Primitive width ops:

- `sext(dst_width, src)` — signed extend
- `zext(dst_width, src)` — zero extend
- `trunc(dst_width, src)` — truncate

---

## Operand Model & Addressing Expressions

Operands are objects of the following types:

- `imm` — immediates: `{type:'imm', value:123, width:32}`
- `reg` — registers: `{type:'reg', name:'RAX', width:64}`
- `temp` — temporaries: `{type:'temp', id:'t0', width:32}`
- `mem` — memory container: `{type:'mem', addr: <addr_expr>, width: 64}`
- `label` — IR label reference: `{type:'label', name:'L1'}`

Address expressions (addr) are structured, e.g. for x86 addressing:

```json
{
  "type": "addr",
  "base": {
    "type": "reg",
    "name": "RAX",
    "width": 64
  },
  "index": {
    "type": "reg",
    "name": "RBX",
    "width": 64
  },
  "scale": 2,
  "disp": 16
}
```

Backends may preserve complex addressing expressions to re-emit `lea`/faster addressing modes.

---

## Language Categories & Instruction Set

IR organizes operations into clear categories. Implementers should focus on the core subset first, then extend.

### 1. Move & LEA

- `mov` — copy value. By default does **not** set flags unless `set_flags: true`.
- `lea` — address computation with no memory access. Prefer to preserve addressing expression.

### 2. Arithmetic & Logical

- `add`, `sub`, `mul`, `div`, `and`, `or`, `xor`, `shl`, `shr`, `sar`, `rol`, `ror`.
- Multi-width results use `umul128`, `smul128`, etc., returning large-width temps to extract high/low parts.

### 3. Bitwise & Scanning

- `bsf`, `bsr`, `popcnt`, `tzcnt` etc.

### 4. Memory Ops

- `load` and `store` with explicit width and address expression.

### 5. Compare & Flags

- `cmp` modeled as `sub` that sets flags (lifters may produce `icmp` ops to represent boolean results).

### 6. Control Flow

- `jmp label`, `cjmp cond, true, false`, `call target`, `ret`, `indirect_jmp addr_expr`, `indirect_call addr_expr`.

### 7. Call/Return & Stack

- `push`/`pop` allowed in lifter output but canonical IR prefers explicit `SP` manipulation and `store`/`load`.

### 8. Syscalls/Traps

- `syscall`, `int`, `svc` — target-specific control-flow/trap ops.

### 9. Atomic & Memory Ordering (advanced)

- `atomic.load`, `atomic.store`, `cmpxchg` with `order` attribute.

### 10. Intrinsics & High-level Ops

- `memcpy`, `memset`, `rep_movsb` may be represented as intrinsics to allow backend optimization.

### 11. Privileged / Hardware Ops

- `cpuid`, `rdtsc`, `xgetbv` — unique ops with structured results.

---

## Control Flow Primitives

IR uses explicit functions and basic blocks:

- **Function**: object with `name`, `entry`, `blocks`.
- **Block**: `id`, `instrs` array, optional `succ` array for successors.
- Each block must end with a single **terminator**: `jmp`, `cjmp`, `ret`, `indirect_jmp`, etc.

**Conditional jumps**: `cjmp` takes a condition operand (flag or boolean expression). Example:

```
cjmp {type:'reg', name:'ZF', width:1}, 'L1', 'L2'
```

**Indirect control flow**: lifter must attach jump-table metadata when possible for analysis. Use
`indirect_jmp addr_expr` / `indirect_call addr_expr`.

---

## Flags Model & Semantics

- Flags are explicit pseudo-registers: `CF, PF, AF, ZF, SF, OF`.
- Arithmetic ops may have attribute `set_flags:true`. Canonicalizer expands these into explicit flag assignments.

**Example:** `add64 RAX, RBX, set_flags=true` canonicalizes to:

1. `t = add64(RAX, RBX)`
2. `CF = carry_add64(RAX, RBX)`
3. `OF = overflow_add64(RAX, RBX)`
4. `ZF = (t == 0)`
5. `SF = sign_bit(t)`
6. `PF = parity(t & 0xff)`
7. `RAX = t`

Backends targeting architectures with different flag models must synthesize equivalent behavior (commonly by computing
flags explicitly into temporaries).

---

## Function Calls, ABIs & Call Adapters

A `call` op in IR is **calling-convention-agnostic** but may include a `conv` attribute (e.g., `win64`, `sysv`).

Example call instruction:

```json
{
  "op": "call",
  "target": {
    "type": "label",
    "name": "@foo"
  },
  "args": [
    ...
  ],
  "conv": "win64"
}
```

**ABI adapter** pass responsibilities:

- Map abstract args to concrete registers or stack slots per *target* ABI.
- Create shadow space where required (Windows x64) and adjust `SP`.
- Save/restore caller-saved registers as needed.
- Map return value from target ABI register(s) back to expected IR register(s).

ABI adapters may expand `call` into lower-level `mov`/`store`/`load` sequences plus actual `call`/`jmp` terminator.

---

## Side-Effects, Implicitness & Canonicality

- **No implicit side effects:** any register, flag, memory modification must be explicit.
- **Canonicalization tasks:** expand `set_flags` shorthands; normalize immediates; convert `push/pop` to explicit `SP`
  ops if desired.
- **Metadata:** lifter must preserve `meta` per instruction: original bytes, RVA, original mnemonic, etc. This metadata
  does not affect semantics but is essential for debugging and testing.

---

## Undefined & Implementation-Defined Behavior Policy

When lifter encounters undefined or implementation-defined behavior (e.g., signed overflow, certain privileged
instructions), follow one of three options:

1. **Annotate `undef` and pick deterministic fallback.** Add metadata such as
   `{"undef":true, "reason":"signed overflow", "chosen":"two's complement truncated"}`.
2. **Emit a runtime check / trap** (if strict semantics are required).
3. **Reject lifting**: report as unsupported construct.

Default for ExeTraducer v0.1: choose deterministic fallback but **annotate** it thoroughly so downstream tools/tests can
opt-in to strictness.

---

## Textual Syntax (Human-Friendly IR)

The textual IR is intended for human inspection and editing. It maps 1:1 with canonical JSON.

Basic rules:

- Comments start with `;`.
- `version`, `arch`, `endianness` appear at top of file.
- `func` defines a function. Blocks are labeled via `label:`.
- Operators are lower-case keywords: `mov`, `add64`, `load64`, `store64`, `cjmp`, `call`, `ret`.

Example:

```
version 0.1
arch x86_64
endianness little

.func @main:
b0:
  SP = SP - 8
  store64 [SP], RBP
  RBP = SP
  RAX = load64 [RDI]
  t0 = add64 RAX, 1
  store64 [RBP - 0x10], t0
  cmp64 RAX, 0
  cjmp ZF, b2, b1

b1:
  RAX = call @helper(RAX)
  jmp b3

b2:
  RAX = 0
  jmp b3

b3:
  SP = SP + 8
  ret
```

Notes:

- `load64 [addr]` and `store64 [addr], value` use bracket address expressions.
- `cmp64` is a shorthand that sets flags; canonicalizer expands it if needed.

---

## Canonical JSON Form (Machine-Friendly)

Top-level structure (summary):

```json
{
  "version": "0.1",
  "arch": "x86_64",
  "endianness": "little",
  "image_base": "0x140000000",
  "entry": "@main",
  "imports": [
    ...
  ],
  "functions": [
    {
      "name": "@main",
      "entry": "b0",
      "blocks": [
        ...
      ],
      "meta": {
        ...
      }
    }
  ],
  "analysis": {
    ...
  }
}
```

Instruction object (canonical):

```json
{
  "op": "add",
  "dst": {
    "type": "reg",
    "name": "RAX",
    "width": 64
  },
  "src": {
    "type": "reg",
    "name": "RBX",
    "width": 64
  },
  "set_flags": true,
  "meta": {
    "asm": "add rax, rbx",
    "rva": "0x401234"
  }
}
```

Memory op example:

```json
{
  "op": "load",
  "dst": {
    "type": "temp",
    "id": "t0",
    "width": 64
  },
  "addr": {
    "type": "addr",
    "base": {
      "type": "reg",
      "name": "RSI",
      "width": 64
    },
    "index": null,
    "scale": 1,
    "disp": 0
  },
  "width": 64
}
```

Control op example:

```json
{
  "op": "cjmp",
  "cond": {
    "type": "reg",
    "name": "ZF",
    "width": 1
  },
  "true": "b2",
  "false": "b1"
}
```

`meta` is optional but strongly recommended for debugging and testing.

---

## Core JSON Schema (Compact)

Below is a compact JSON Schema fragment to validate the core shape. Implementers should extend it for more op-specific
validation.

> **Note:** This fragment is included for convenience. Use a proper `jsonschema` validator in tooling.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ExeTraducer IR (core)",
  "type": "object",
  "required": [
    "version",
    "arch",
    "endianness",
    "functions"
  ],
  "properties": {
    "version": {
      "type": "string"
    },
    "arch": {
      "type": "string"
    },
    "endianness": {
      "type": "string",
      "enum": [
        "little",
        "big"
      ]
    },
    "image_base": {
      "type": "string"
    },
    "entry": {
      "type": "string"
    },
    "imports": {
      "type": "array"
    },
    "functions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "name",
          "entry",
          "blocks"
        ],
        "properties": {
          "name": {
            "type": "string"
          },
          "entry": {
            "type": "string"
          },
          "blocks": {
            "type": "array",
            "items": {
              "type": "object",
              "required": [
                "id",
                "instrs"
              ],
              "properties": {
                "id": {
                  "type": "string"
                },
                "instrs": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "required": [
                      "op"
                    ],
                    "properties": {
                      "op": {
                        "type": "string"
                      },
                      "dst": {
                        "$ref": "#/definitions/operand"
                      },
                      "src": {
                        "$ref": "#/definitions/operand"
                      },
                      "addr": {
                        "$ref": "#/definitions/addr"
                      },
                      "args": {
                        "type": "array",
                        "items": {
                          "$ref": "#/definitions/operand"
                        }
                      },
                      "width": {
                        "type": "integer"
                      },
                      "set_flags": {
                        "type": "boolean"
                      },
                      "cond": {
                        "$ref": "#/definitions/operand"
                      },
                      "true": {
                        "type": "string"
                      },
                      "false": {
                        "type": "string"
                      },
                      "meta": {
                        "type": "object"
                      }
                    }
                  }
                }
              },
              "succ": {
                "type": "array",
                "items": {
                  "type": "string"
                }
              },
              "meta": {
                "type": "object"
              }
            }
          }
        }
      }
    }
  },
  "definitions": {
    "operand": {
      "type": "object",
      "required": [
        "type"
      ],
      "oneOf": [
        {
          "properties": {
            "type": {
              "const": "imm"
            }
          },
          "required": [
            "value",
            "width"
          ]
        },
        {
          "properties": {
            "type": {
              "const": "reg"
            }
          },
          "required": [
            "name",
            "width"
          ]
        },
        {
          "properties": {
            "type": {
              "const": "temp"
            }
          },
          "required": [
            "id",
            "width"
          ]
        },
        {
          "properties": {
            "type": {
              "const": "label"
            }
          },
          "required": [
            "name"
          ]
        },
        {
          "properties": {
            "type": {
              "const": "mem"
            }
          },
          "required": [
            "addr",
            "width"
          ]
        }
      ]
    },
    "addr": {
      "type": "object",
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "enum": [
            "addr",
            "expr"
          ]
        },
        "base": {
          "$ref": "#/definitions/operand"
        },
        "index": {
          "$ref": "#/definitions/operand"
        },
        "scale": {
          "type": "integer"
        },
        "disp": {
          "type": "integer"
        }
      }
    }
  }
}
```

---

## Examples: x86 → IR Mappings

These canonical mappings are the basis of lifter implementations.

### `add rax, rbx`

Textual (shorthand):

```
add64 RAX, RBX    ; set_flags implied or explicit depending on lifter
```

Canonical JSON (shorthand form):

```json
{
  "op": "add",
  "dst": {
    "type": "reg",
    "name": "RAX",
    "width": 64
  },
  "src": {
    "type": "reg",
    "name": "RBX",
    "width": 64
  },
  "set_flags": true
}
```

Canonical expansion (fully explicit flag ops):

1. `t0 = add64(RAX, RBX)`
2. `CF = carry_add64(RAX, RBX)`
3. `OF = overflow_add64(RAX, RBX)`
4. `ZF = (t0 == 0)`
5. `SF = sign_bit(t0)`
6. `PF = parity(t0 & 0xff)`
7. `RAX = t0`

### `cmp rax, rbx` + `je L1`

Canonical expansion:

1. `t0 = sub64(RAX, RBX)`
2. `ZF = (t0 == 0)`
3. `SF = sign_bit(t0)`
4. `CF = carry_sub64(RAX, RBX)`
5. `OF = overflow_sub64(RAX, RBX)`
6. `cjmp ZF, L1, fallthrough`

### `lea rcx, [rax + rbx*2 + 0x10]`

Representation (preserve addressing expression where possible):

```json
{
  "op": "assign",
  "dst": {
    "type": "reg",
    "name": "RCX",
    "width": 64
  },
  "src": {
    "type": "expr",
    "expr": {
      "op": "addr",
      "base": {
        "type": "reg",
        "name": "RAX",
        "width": 64
      },
      "index": {
        "type": "reg",
        "name": "RBX",
        "width": 64
      },
      "scale": 2,
      "disp": 16
    }
  }
}
```

Lifter may expand into arithmetic ops if backend cannot preserve `lea` semantics.

### `mul rbx` (unsigned multiply: `RAX*RBX` → `RDX:RAX`)

Canonical expansion:

1. `t0 = umul128(RAX, RBX)`
2. `RAX = extract_low64(t0)`
3. `RDX = extract_high64(t0)`

---

## Round-Trips & API Contracts

**Lifter contract**:

- Emit `meta` per instruction containing original bytes, RVA, and original mnemonic when available.
- Always specify `width` on operands.
- Attach `rva`/`va` for top-level functions/blocks where possible.
- For unresolved indirect jumps/calls attach analysis metadata (`jump_table` hints, signatures).

**Backend contract**:

- Accept canonicalized IR.
- Preserve semantics for non-`undef` ops.
- Honor `meta` if requested to emit debugging info.

**Round-trip test**:

1. Pick small function `F` and inputs.
2. Execute original binary `orig(F)` under sandbox; snapshot registers/memory.
3. Translate to target binary via lifter→IR→backend; execute under similar sandbox.
4. Compare snapshots.

---

## Validation Rules & Canonicalization

Canonicalizer must perform these transformations:

1. Expand `set_flags` shorthand into explicit flag assignments.
2. Normalize immediates into explicit `{type:'imm', value:..., width:...}` structures.
3. Convert ambiguous `push`/`pop` into `SP` arithmetic + `store`/`load` sequences if required.
4. Ensure each block ends with a single terminator op.
5. Normalize `addr` expressions into the canonical structure.
6. Tag every instruction with `meta.original_bytes` and `meta.rva` where available.

Validation checklist before backend:

- All operands have `type` and `width` when applicable.
- All referenced labels exist.
- No implicit flag mutations remain invisible (i.e., no `set_flags` shorthand lingering).
- No overlapping/wrong block terminators.

---

## Extension Points: SIMD, Atomics, Privileged Ops

**SIMD**: add vector types by width (128/256/512) and vector ops `vadd128`, `vsub256`, etc. Represent lanes implicitly
with vector widths.

**Atomics**: `atomic.load`, `atomic.store`, `cmpxchg` with `order` attribute (default `seq_cst`). Add `fence` op for
memory barriers.

**Privileged/hardware ops**: `cpuid`, `rdtsc`, `xgetbv` — represent as unique ops with structured results; annotate with
`privileged:true` metadata.

**Intrinsics**: `memcpy`, `memset`, `rep_movsb` available as intrinsics allowing backends to substitute optimized
implementations.

---

## Testing Strategy & Recommended Unit Tests

**Essential test families:**

- Instruction-level correctness (for each lifted op) via small asm snippets.
- Flag tests for signed/unsigned arithmetic corner cases.
- Memory aliasing and overlapping operations.
- Calling-convention tests verifying callee/caller-saved registers, argument passing, and return mapping.
- Control-flow tests including indirect jumps and jump tables.
- String-operation tests (e.g., `rep movsb`) with DF=0/1.
- Undef behavior tests to ensure annotations appear.

**Harness suggestions:**

- Use QEMU for cross-arch comparisons.
- Use an instrumented VM or emulator to capture register/memory snapshots.
- Automate round-trip comparisons with a CI pipeline and regression suite.

---

## Implementation Checklist & Next Steps

1. Implement **IR serializer/deserializer** (text ↔ JSON).
2. Implement **canonicalizer** expanding `set_flags` etc.
3. Implement `ir.validate()` using JSON Schema.
4. Implement a **reference interpreter** (slow but authoritative) to execute IR for unit tests.
5. Implement a **minimal lifter** (capstone → IR) for a small instruction subset (mov, add, sub, cmp, jcc, call, ret,
   lea, load/store).
6. Implement a **minimal backend** to emit x86_64 SystemV code for the minimal subset.
7. Expand instruction set coverage and add ARM64 backend.

---

## Glossary & Conventions

- **Canonical IR** - validated IR JSON expected by backends.
- **Lifter** - component converting assembly → IR.
- **Backend** - component converting IR → target assembly/binary.
- **Temp** - ephemeral temporary (`t0`, `t1`).
- **Meta** - auxiliary instruction/block metadata.
- **Undef** - annotation for undefined or implementation-defined behavior.

**Conventions:** registers in UPPERCASE (RAX), temps lowercase (t0), widths in bits, labels as `b0` or `func::b0`. JSON
keys use `snake_case`.

---

## Appendix: Minimal Examples

### Textual IR (sum of 64-bit array)

```
version 0.1
arch x86_64
endianness little

.func @sum_array:
b0:
  RAX = 0                             ; accumulator
  loop:
  t0 = load64 [RDI]                   ; load *RDI
  RAX = add64 RAX, t0
  RDI = add64 RDI, 8
  RCX = sub64 RCX, 1
  cjmp ZF, end, loop
end:
  ret
```

### Canonical JSON (excerpt)

```json
{
  "version": "0.1",
  "arch": "x86_64",
  "endianness": "little",
  "functions": [
    {
      "name": "@sum_array",
      "entry": "b0",
      "blocks": [
        {
          "id": "b0",
          "instrs": [
            {
              "op": "mov",
              "dst": {
                "type": "reg",
                "name": "RAX",
                "width": 64
              },
              "src": {
                "type": "imm",
                "value": 0,
                "width": 64
              }
            },
            {
              "op": "label",
              "name": "loop"
            },
            {
              "op": "load",
              "dst": {
                "type": "temp",
                "id": "t0",
                "width": 64
              },
              "addr": {
                "type": "addr",
                "base": {
                  "type": "reg",
                  "name": "RDI",
                  "width": 64
                },
                "index": null,
                "scale": 1,
                "disp": 0
              },
              "width": 64
            },
            {
              "op": "add",
              "dst": {
                "type": "reg",
                "name": "RAX",
                "width": 64
              },
              "src": {
                "type": "temp",
                "id": "t0",
                "width": 64
              },
              "set_flags": false
            },
            {
              "op": "add",
              "dst": {
                "type": "reg",
                "name": "RDI",
                "width": 64
              },
              "src": {
                "type": "imm",
                "value": 8,
                "width": 64
              }
            },
            {
              "op": "sub",
              "dst": {
                "type": "reg",
                "name": "RCX",
                "width": 64
              },
              "src": {
                "type": "imm",
                "value": 1,
                "width": 64
              },
              "set_flags": true
            },
            {
              "op": "cjmp",
              "cond": {
                "type": "reg",
                "name": "ZF",
                "width": 1
              },
              "true": "end",
              "false": "loop"
            }
          ],
          "succ": [
            "loop",
            "end"
          ]
        },
        {
          "id": "end",
          "instrs": [
            {
              "op": "ret"
            }
          ],
          "succ": []
        }
      ]
    }
  ]
}
```