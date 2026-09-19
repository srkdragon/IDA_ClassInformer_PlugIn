# IDB Annotation Pass — Applying the RE Findings to the Corpus Databases

Goal-methodology step 2 ("improve readability in the database") applied to the
two reference databases (`RE/test/rtti_corpus_x64.exe.i64`,
`rtti_corpus_x86.exe.i64`), executed and persisted through `idasql -w`.
Every change is derived from the verified facts in
[MSVC-RTTI-Layout.md](MSVC-RTTI-Layout.md) and
[VBTables-and-Virtual-Inheritance.md](VBTables-and-Virtual-Inheritance.md).

## What was changed

### 1. RTTI structure types applied (180 per architecture)

Binary-accurate IDA til types applied at every verified object address
(address lists generated from `RE/data/rtti_*.json`, script
`RE/data/annotate_<arch>.sql`):

| Type (IDA til) | Size | Applied at | Count |
|---|---|---|---|
| `_RTTICompleteObjectLocator` | 0x18 | every COL (`??_R4`) | 64 |
| `_RTTIClassHierarchyDescriptor` | 0x10 | every CHD (`??_R3`) | 52 |
| `_RTTIBaseClassDescriptor` | 0x1C | every BCD (`??_R1`) | 64 |

Verification: `applied_types WHERE decl LIKE '_RTTI%'` → 183 rows on x64
(180 here + 3 pre-existing IDA-placed named instances), 180 on x86; spot
checks render as e.g. `_RTTICompleteObjectLocator <0>` at `0x1400A7120`.

### 2. vbtables rescued from mis-analysis (6 per architecture)

IDA's auto-analyzer had disassembled the `??_8` vbtable dwords as code
(`clc`, `sar byte ptr [rdx+rcx+40h], 1`, …). Each vbtable region was
re-converted to its true item type — an array of 4-byte signed displacements
(`RE/data/fix_vbtables_<arch>.sql` via `idapython_snippet`):

```text
??_8CVLeft@@7B@            [-8,  8]     ??_8CDiamond@@7BCVLeft@@@  [-8, 24]
??_8CVRight@@7B@           [-8,  8]     ??_8CDiamond@@7BCVRight@@@ [-8,  8]
(x64 shown; x86 uses -4 steps and half the displacements)
```

Each vbtable also received a repeatable comment stating the verified decode
(`entry[0] = -(vbptr offset)`, `entry[i] = displacement of the i-th virtual
base from the vbptr`, `base = obj + pdisp + entry[vdisp/4]`) with a pointer to
the deep-dive doc.

**This rescue is now automated in the plugin**: the same operations (proven
out here first via `idapython_snippet`) were ported to
`RTTI::fixKnownVbtables()` as a new scan stage — see
[Plugin-Findings-and-Fixes.md](Plugin-Findings-and-Fixes.md) FEATURE 8.

### 3. Function naming (verified already sufficient)

IDA 9.4's RTTI pass had already derived `Class::method` names for all
vftable-member functions (286 `::`-named functions; 0 unnamed `sub_*` remain),
so no renames were needed — consistent with the plugin's current
"gather and display" role rather than primary namer.

## idasql operational notes discovered during this pass

* **`comments` table SELECT does not enumerate every commented address** —
  comments placed at addresses whose items were auto-disassembled as code did
  not appear in `SELECT ... FROM comments` even though they existed in the
  IDB. Authoritative readback is `ida_bytes.get_cmt(ea, 0/1)` via
  `idapython_snippet`.
* **`disasm_range()` forces disassembly rendering** — it disassembles bytes
  for display even where the IDB holds data items, so it must not be used to
  judge item types; use `ida_bytes.is_dword/is_code(get_flags(ea))`.
* `INSERT INTO comments (addr, rpt_comment)` upserts the repeatable slot and
  leaves the regular slot alone (and vice versa); clearing requires
  `set_cmt(ea, "", slot)` — `NULL`/absent columns are no-ops.
* Virtual-table writes from `-f` scripts persist fine with `-w`; verify in a
  fresh session.

## Reproduction

```text
idasql -s RE/test/rtti_corpus_x64.exe -w -f RE/data/annotate_x64.sql
idasql -s RE/test/rtti_corpus_x86.exe -w -f RE/data/annotate_x86.sql
idasql -s RE/test/rtti_corpus_x64.exe -w -f RE/data/fix_vbtables_x64.sql
idasql -s RE/test/rtti_corpus_x86.exe -w -f RE/data/fix_vbtables_x86.sql
```
