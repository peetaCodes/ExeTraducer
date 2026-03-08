-- dialect: sqlite
-- init_translation_tables_expanded_x86_64.sql
-- ExeTraducer translation tables initialization (expanded x86_64)
-- Run with: sqlite3 translation_tables.db < init_translation_tables_expanded_x86_64.sql

PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;

-- Meta table to track schema version
CREATE TABLE IF NOT EXISTS schema_version
(
    version    INTEGER NOT NULL,
    applied_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (version)
);

-- ----------------------------
-- x86_64 translations table
-- ----------------------------
CREATE TABLE IF NOT EXISTS translations_x86_64
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    arch          TEXT NOT NULL DEFAULT 'x86_64',
    flavor        TEXT NOT NULL DEFAULT 'intel', -- assembler flavour: 'intel', 'att', etc.
    mnemonic      TEXT NOT NULL,
    pattern       TEXT NOT NULL,
    template_json TEXT NOT NULL,
    description   TEXT,
    created_at    TEXT          DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (mnemonic, pattern, flavor)
);

CREATE INDEX IF NOT EXISTS idx_x86_64_mnemonic ON translations_x86_64 (mnemonic);
CREATE INDEX IF NOT EXISTS idx_x86_64_pattern ON translations_x86_64 (pattern);

-- ----------------------------
-- x86 (i386 / 32-bit) translations table (placeholder)
-- ----------------------------
CREATE TABLE IF NOT EXISTS translations_x86
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    arch          TEXT NOT NULL DEFAULT 'x86',
    flavor        TEXT NOT NULL DEFAULT 'intel',
    mnemonic      TEXT NOT NULL,
    pattern       TEXT NOT NULL,
    template_json TEXT NOT NULL,
    description   TEXT,
    created_at    TEXT          DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (mnemonic, pattern, flavor)
);
CREATE INDEX IF NOT EXISTS idx_x86_mnemonic ON translations_x86 (mnemonic);

-- ----------------------------
-- armv7 translations table (placeholder)
-- ----------------------------
CREATE TABLE IF NOT EXISTS translations_armv7
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    arch          TEXT NOT NULL DEFAULT 'armv7',
    flavor        TEXT NOT NULL DEFAULT 'arm',
    mnemonic      TEXT NOT NULL,
    pattern       TEXT NOT NULL,
    template_json TEXT NOT NULL,
    description   TEXT,
    created_at    TEXT          DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (mnemonic, pattern, flavor)
);
CREATE INDEX IF NOT EXISTS idx_armv7_mnemonic ON translations_armv7 (mnemonic);

-- ----------------------------
-- armv8 / aarch64 translations table (placeholder)
-- ----------------------------
CREATE TABLE IF NOT EXISTS translations_armv8
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    arch          TEXT NOT NULL DEFAULT 'armv8',
    flavor        TEXT NOT NULL DEFAULT 'arm',
    mnemonic      TEXT NOT NULL,
    pattern       TEXT NOT NULL,
    template_json TEXT NOT NULL,
    description   TEXT,
    created_at    TEXT          DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (mnemonic, pattern, flavor)
);
CREATE INDEX IF NOT EXISTS idx_armv8_mnemonic ON translations_armv8 (mnemonic);

-- Mark schema version (bumped to 2 for expanded data)
INSERT OR
REPLACE
INTO schema_version(version, applied_at)
VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- =======================================================
-- Populate translations_x86_64 with expanded templates
-- =======================================================
-- Each INSERT uses JSON template strings that the Translator will render.
-- The JSON templates follow the IR conventions described in the IR manual.

-- 1) MOV family (register/memory/immediate variants)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('mov', 'reg,reg', '{\"op\":\"mov\",\"dst\":\"{0}\",\"src\":\"{1}\"}', 'mov reg, reg (copy)'),
       ('mov', 'reg,mem', '{\"op\":\"load\",\"dst\":\"{0}\",\"addr\":\"{1}\",\"width\":64}',
        'mov reg, [mem]  (load 64-bit)'),
       ('mov', 'mem,reg', '{\"op\":\"store\",\"addr\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'mov [mem], reg (store 64-bit)'),
       ('mov', 'reg,imm', '{\"op\":\"mov\",\"dst\":\"{0}\",\"src\":\"{1}\"}', 'mov reg, imm'),
       ('mov', 'mem,imm', '{\"op\":\"store\",\"addr\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'mov [mem], imm (store immediate to memory)'),
       ('mov', 'reg,mem_disp', '{\"op\":\"load\",\"dst\":\"{0}\",\"addr\":\"{1}\",\"width\":64}',
        'mov reg, moffs64 / mem with displacement (load 64)');

-- 2) MOVE with 8/16/32/64 explicit size helpers
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('mov8', 'reg,mem', '{\"op\":\"load\",\"dst\":\"{0}\",\"addr\":\"{1}\",\"width\":8}', 'explicit load8'),
       ('mov16', 'reg,mem', '{\"op\":\"load\",\"dst\":\"{0}\",\"addr\":\"{1}\",\"width\":16}', 'explicit load16'),
       ('mov32', 'reg,mem', '{\"op\":\"load\",\"dst\":\"{0}\",\"addr\":\"{1}\",\"width\":32}', 'explicit load32'),
       ('mov64', 'reg,mem', '{\"op\":\"load\",\"dst\":\"{0}\",\"addr\":\"{1}\",\"width\":64}', 'explicit load64'),
       ('mov8', 'mem,reg', '{\"op\":\"store\",\"addr\":\"{0}\",\"src\":\"{1}\",\"width\":8}', 'explicit store8'),
       ('mov16', 'mem,reg', '{\"op\":\"store\",\"addr\":\"{0}\",\"src\":\"{1}\",\"width\":16}', 'explicit store16'),
       ('mov32', 'mem,reg', '{\"op\":\"store\",\"addr\":\"{0}\",\"src\":\"{1}\",\"width\":32}', 'explicit store32'),
       ('mov64', 'mem,reg', '{\"op\":\"store\",\"addr\":\"{0}\",\"src\":\"{1}\",\"width\":64}', 'explicit store64');

-- 3) MOVZX / MOVSX (zero/sign-extend)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('movzx', 'reg,reg', '{\"op\":\"zext\",\"dst\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'movzx r64, r/m -> zero-extend into 64-bit'),
       ('movzx', 'reg,mem', '{\"op\":\"zext\",\"dst\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'movzx r64, [mem] -> zero-extend'),
       ('movsx', 'reg,reg', '{\"op\":\"sext\",\"dst\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'movsx r64, r/m -> sign-extend into 64-bit'),
       ('movsx', 'reg,mem', '{\"op\":\"sext\",\"dst\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'movsx r64, [mem] -> sign-extend');

-- 4) Arithmetic (add/sub/mul/div) and increments/decrements
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('add', 'reg,reg', '{\"op\":\"add\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'add reg, reg (sets flags)'),
       ('add', 'reg,imm', '{\"op\":\"add\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'add reg, imm (sets flags)'),
       ('sub', 'reg,reg', '{\"op\":\"sub\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'sub reg, reg (sets flags)'),
       ('sub', 'reg,imm', '{\"op\":\"sub\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'sub reg, imm (sets flags)'),
       ('inc', 'reg',
        '{\"op\":\"add\",\"dst\":\"{0}\",\"src\":{\"type\":\"imm\",\"value\":1,\"width\":64},\"set_flags\":true}',
        'inc reg -> add reg, 1 (sets flags)'),
       ('dec', 'reg',
        '{\"op\":\"sub\",\"dst\":\"{0}\",\"src\":{\"type\":\"imm\",\"value\":1,\"width\":64},\"set_flags\":true}',
        'dec reg -> sub reg, 1 (sets flags)'),
-- multiplication: wide results
       ('mul', 'reg',
        '{\"op\":\"umul128\",\"args\":[{\"type\":\"reg\",\"name\":\"RAX\",\"width\":64},\"{0}\"],\"meta\":{\"notes\":\"unsigned multiply; result is 128-bit in temp; canonicalize to RDX:RAX\"}}',
        'mul r/m (unsigned): RDX:RAX = RAX * r/m'),
       ('imul', 'reg,reg',
        '{\"op\":\"smul128\",\"args\":[\"{0}\",\"{1}\"],\"meta\":{\"notes\":\"signed multiply, consumer must extract low/high\"}}',
        'imul two-operand signed multiply -> smul128'),
       ('imul', 'reg',
        '{\"op\":\"smul128\",\"args\":[{\"type\":\"reg\",\"name\":\"RAX\",\"width\":64},\"{0}\"],\"meta\":{\"notes\":\"single operand IMUL; RDX:RAX result\"}}',
        'imul r/m (single operand)'),
       ('div', 'reg',
        '{\"op\":\"udiv\",\"args\":[\"{0}\",\"{1}\"],\"meta\":{\"notes\":\"unsigned division; semantics depend on canonicalization (RAX/RDX)\"}}',
        'div semantics: use canonicalizer to expand into proper divide ops'),
       ('idiv', 'reg',
        '{\"op\":\"sdiv\",\"args\":[\"{0}\",\"{1}\"],\"meta\":{\"notes\":\"signed division; canonicalize handling of dividend in RDX:RAX\"}}',
        'idiv signed divide');

-- 5) Logical ops and TEST
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('and', 'reg,reg', '{\"op\":\"and\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'and reg, reg (sets flags)'),
       ('and', 'reg,imm', '{\"op\":\"and\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'and reg, imm (sets flags)'),
       ('or', 'reg,reg', '{\"op\":\"or\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'or reg, reg (sets flags)'),
       ('xor', 'reg,reg', '{\"op\":\"xor\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'xor reg, reg (sets flags)'),
       ('test', 'reg,reg',
        '{\"op\":\"and\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true,\"meta\":{\"note\":\"test -> and but destroy dst? treat as flags-only: canonicalizer may remove dst assignment\"}}',
        'test reg, reg -> logical AND, set flags only'),
       ('not', 'reg', '{\"op\":\"not\",\"dst\":\"{0}\",\"meta\":{\"note\":\"bitwise NOT\"}}', 'not reg');

-- 6) Shifts & rotates
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('shl', 'reg,imm', '{\"op\":\"shl\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}', 'shl (logical left)'),
       ('sal', 'reg,imm', '{\"op\":\"shl\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}', 'sal synonym for shl'),
       ('shr', 'reg,imm', '{\"op\":\"shr\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}', 'shr logical right'),
       ('sar', 'reg,imm', '{\"op\":\"sar\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}',
        'sar arithmetic right'),
       ('rol', 'reg,imm', '{\"op\":\"rol\",\"dst\":\"{0}\",\"src\":\"{1}\"}', 'rotate left'),
       ('ror', 'reg,imm', '{\"op\":\"ror\",\"dst\":\"{0}\",\"src\":\"{1}\"}', 'rotate right'),
       ('bswap', 'reg', '{\"op\":\"bswap\",\"dst\":\"{0}\"}', 'byte-swap register');

-- 7) LEA and addressing helpers
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('lea', 'reg,mem', '{\"op\":\"lea\",\"dst\":\"{0}\",\"addr\":\"{1}\"}',
        'lea reg, [mem] -> compute effective address'),
       ('lea', 'reg,mem_disp', '{\"op\":\"lea\",\"dst\":\"{0}\",\"addr\":\"{1}\"}',
        'lea with displacement / moffs addressing');

-- 8) Load/Store explicit widths (aliases)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('movsxb', 'reg,mem', '{\"op\":\"sext\",\"dst\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'movsxb -> sign-extend byte to 64'),
       ('movsxw', 'reg,mem', '{\"op\":\"sext\",\"dst\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'movsxw -> sign-extend word to 64'),
       ('movsxd', 'reg,mem', '{\"op\":\"sext\",\"dst\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'movsxd -> sign-extend dword to 64');

-- 9) Push/Pop (canonicalizer should convert these to SP arithmetic + store/load)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('push', 'reg',
        '{\"op\":\"push\",\"src\":\"{0}\",\"meta\":{\"note\":\"canonicalize to SP=SP-8; store [SP], src\"}}',
        'push reg (stack push)'),
       ('push', 'imm',
        '{\"op\":\"push\",\"src\":\"{0}\",\"meta\":{\"note\":\"push immediate; canonicalize to SP adjustments and store\"}}',
        'push imm'),
       ('pop', 'reg',
        '{\"op\":\"pop\",\"dst\":\"{0}\",\"meta\":{\"note\":\"canonicalize to load [SP], dst; SP=SP+8\"}}', 'pop reg');

-- 10) Calls, returns, indirects
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('call', 'label', '{\"op\":\"call\",\"target\":{\"type\":\"label\",\"name\":\"{0}\"}}', 'direct call to label'),
       ('call', 'reg', '{\"op\":\"call\",\"target\":{\"type\":\"reg\",\"name\":\"{0}\",\"width\":64}}',
        'indirect call via register'),
       ('call', 'mem', '{\"op\":\"call\",\"target\":\"{0}\",\"meta\":{\"note\":\"indirect call via memory operand\"}}',
        'indirect call via memory'),
       ('ret', '', '{\"op\":\"ret\"}', 'return from function'),
       ('jmp', 'label', '{\"op\":\"jmp\",\"target\":\"{0}\"}', 'unconditional jump'),
       ('jmp', 'reg', '{\"op\":\"jmp\",\"target\":\"{0}\"}', 'indirect jmp via register'),
       ('jmp', 'mem', '{\"op\":\"jmp\",\"target\":\"{0}\"}', 'indirect jmp via memory');

-- 11) Conditional jumps (simple flag-based cases)
-- ZF (zero) family
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('je', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'jump if equal / zero (ZF==1)'),
       ('jz', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'alias of je (ZF==1)'),
       ('jne', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1},\"true\":\"fallthrough\",\"false\":\"{0}\"}',
        'jump if not equal (ZF==0)'),
       ('jnz', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1},\"true\":\"fallthrough\",\"false\":\"{0}\"}',
        'alias of jne');

-- Carry flag / unsigned comparisons
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('jc', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"CF\",\"width\":1},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'jump if carry (CF==1)'),
       ('jnc', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"CF\",\"width\":1},\"true\":\"fallthrough\",\"false\":\"{0}\"}',
        'jump if no carry (CF==0)');

-- Signed comparisons (overflow/sign)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('jo', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"OF\",\"width\":1},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'jump if overflow (OF==1)'),
       ('jno', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"OF\",\"width\":1},\"true\":\"fallthrough\",\"false\":\"{0}\"}',
        'jump if not overflow (OF==0)'),
       ('js', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"SF\",\"width\":1},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'jump if sign (SF==1)'),
       ('jns', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"SF\",\"width\":1},\"true\":\"fallthrough\",\"false\":\"{0}\"}',
        'jump if not sign (SF==0)');

-- 12) Common compound conditions (mapped to expressions)
-- ja: (CF==0 && ZF==0)  -> true target is {0}
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('ja', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"op\":\"and\",\"args\":[{\"op\":\"not\",\"args\":[{\"type\":\"reg\",\"name\":\"CF\",\"width\":1}]},{\"op\":\"not\",\"args\":[{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1}]}]},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'jump if above (CF==0 && ZF==0)'),
       ('jb', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"type\":\"reg\",\"name\":\"CF\",\"width\":1},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'jump if below (CF==1)'),
       ('jbe', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"op\":\"or\",\"args\":[{\"type\":\"reg\",\"name\":\"CF\",\"width\":1},{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1}]},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'jump if below or equal (CF==1 || ZF==1)'),
       ('jg', 'label',
        '{\"op\":\"cjmp\",\"cond\":{\"op\":\"and\",\"args\":[{\"op\":\"not\",\"args\":[{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1}]},{\"op\":\"eq\",\"args\":[{\"type\":\"reg\",\"name\":\"SF\",\"width\":1},{\"type\":\"reg\",\"name\":\"OF\",\"width\":1}]}]},\"true\":\"{0}\",\"false\":\"fallthrough\"}',
        'jump if greater (signed)');

-- 13) Conditional move (CMOVcc family) -> cmov op (cond + args)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('cmove', 'reg,reg',
        '{\"op\":\"cmov\",\"cond\":{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1},\"dst\":\"{0}\",\"src\":\"{1}\"}',
        'cmove (move if equal)'),
       ('cmovne', 'reg,reg',
        '{\"op\":\"cmov\",\"cond\":{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1},\"dst\":\"{0}\",\"src\":\"{1}\",\"invert\":true}',
        'cmovne (move if not equal)'),
       ('cmovg', 'reg,reg',
        '{\"op\":\"cmov\",\"cond\":{\"op\":\"and\",\"args\":[{\"op\":\"not\",\"args\":[{\"type\":\"reg\",\"name\":\"ZF\",\"width\":1}]},{\"op\":\"eq\",\"args\":[{\"type\":\"reg\",\"name\":\"SF\",\"width\":1},{\"type\":\"reg\",\"name\":\"OF\",\"width\":1}]}]},\"dst\":\"{0}\",\"src\":\"{1}\"}',
        'cmovg (signed greater)');

-- 14) TEST and CMP (cmp lowered to sub+set_flags; test -> and set_flags no dest)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('cmp', 'reg,reg',
        '{\"op\":\"sub\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true,\"meta\":{\"note\":\"cmp lowered to sub + set_flags; canonicalizer may remove dst assignment\"}}',
        'compare reg, reg'),
       ('cmp', 'reg,imm', '{\"op\":\"sub\",\"dst\":\"{0}\",\"src\":\"{1}\",\"set_flags\":true}', 'compare reg, imm'),
       ('test', 'reg,reg',
        '{\"op\":\"and\",\"dst\":{\"type\":\"temp\",\"id\":\"t0\",\"width\":64},\"src\":\"{1}\",\"set_flags\":true,\"meta\":{\"note\":\"test updates flags only; canonicalizer may erase temp\"}}',
        'test reg, reg -> sets flags');

-- 15) String / repeated / intrinsic ops
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('rep_movsb', 'intrinsic',
        '{\"op\":\"intrinsic\",\"name\":\"rep_movsb\",\"meta\":{\"note\":\"memcopy semantic; backend may use memcpy\"}}',
        'rep movsb intrinsic (memcpy)'),
       ('rep_stosb', 'intrinsic',
        '{\"op\":\"intrinsic\",\"name\":\"rep_stosb\",\"meta\":{\"note\":\"memset semantic\"}}',
        'rep stosb intrinsic (memset)');

-- 16) Bit-scan and population count
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('bsf', 'reg,reg', '{\"op\":\"bsf\",\"dst\":\"{0}\",\"src\":\"{1}\"}', 'bit scan forward'),
       ('bsr', 'reg,reg', '{\"op\":\"bsr\",\"dst\":\"{0}\",\"src\":\"{1}\"}', 'bit scan reverse'),
       ('popcnt', 'reg,reg', '{\"op\":\"popcnt\",\"dst\":\"{0}\",\"src\":\"{1}\"}', 'population count');

-- 17) Atomic / lock-prefixed ops (best-effort intrinsic / annotated)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('lock_xchg', 'mem,reg',
        '{\"op\":\"atomic_xchg\",\"addr\":\"{0}\",\"src\":\"{1}\",\"meta\":{\"note\":\"lock-prefixed xchg\"}}',
        'atomic xchg (lock prefix)'),
       ('xchg', 'reg,reg', '{\"op\":\"xchg\",\"args\":[\"{0}\",\"{1}\"]}', 'xchg reg, reg (exchange)');

-- 18) System / privileged ops
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('syscall', '', '{\"op\":\"syscall\",\"meta\":{\"note\":\"system call; arguments ABI-dependent\"}}', 'syscall'),
       ('int', 'imm', '{\"op\":\"trap\",\"meta\":{\"int\":\"{0}\"}}', 'int imm (software interrupt)'),
       ('int3', '', '{\"op\":\"trap\",\"meta\":{\"int\":3}}', 'int3 breakpoint'),
       ('rdtsc', '',
        '{\"op\":\"rdtsc\",\"dst_lo\":{\"type\":\"reg\",\"name\":\"RAX\",\"width\":64},\"dst_hi\":{\"type\":\"reg\",\"name\":\"RDX\",\"width\":64}}',
        'read time stamp counter'),
       ('cpuid', '', '{\"op\":\"cpuid\",\"meta\":{\"note\":\"cpuid; returns to RAX/RBX/RCX/RDX\"}}',
        'cpuid instruction');

-- 19) NOP and alignment
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('nop', '', '{\"op\":\"nop\"}', 'no operation'),
       ('align', '', '{\"op\":\"align\",\"meta\":{\"note\":\"alignment directive\"}}', 'alignment directive');

-- 20) Floating point and SSE (minimal, as intrinsics/ops)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('movsd', 'reg,mem', '{\"op\":\"fp_load\",\"dst\":\"{0}\",\"addr\":\"{1}\",\"width\":64}',
        'load scalar double (SSE)'),
       ('movsd', 'mem,reg', '{\"op\":\"fp_store\",\"addr\":\"{0}\",\"src\":\"{1}\",\"width\":64}',
        'store scalar double (SSE)'),
       ('adds', 'reg,reg',
        '{\"op\":\"fp_add\",\"dst\":\"{0}\",\"src\":\"{1}\",\"meta\":{\"note\":\"floating point add\"}}',
        'floating add (scalar)');

-- 21) Bit test instructions (bittest variants)
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('bt', 'reg,reg', '{\"op\":\"bit_test\",\"args\":[\"{0}\",\"{1}\"],\"set_flags\":true}', 'bit test (set flags)'),
       ('bts', 'reg,reg', '{\"op\":\"bit_test_and_set\",\"args\":[\"{0}\",\"{1}\"],\"set_flags\":true}',
        'bit test and set');

-- 22) Misc helpers and fallbacks for unknown forms
-- Generic fallback template: if nothing matches, produce an op with args preserved
INSERT OR IGNORE INTO translations_x86_64 (mnemonic, pattern, template_json, description)
VALUES ('unknown', 'any',
        '{\"op\":\"{mn}\",\"args\":[\"{0}\",\"{1}\"],\"meta\":{\"note\":\"fallback: untranslated mnemonic\"}}',
        'fallback unknown translation (should not be used if specific template exists)');

-- =======================================================
-- End of inserts for expanded x86_64 pack
-- =======================================================

COMMIT;