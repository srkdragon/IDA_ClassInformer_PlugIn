# ClassInformer — Verified Findings and Applied Fixes

Each item states the defect, the empirical evidence that established it, and
the change made. Baseline for "old behavior" is the repo state before this RE
pass (commit `1b497e3`). Validation gates: byte-scan vs linker-map round-trip
(64/64 x86 and x64) and a clean `Release|x64` plugin build.

---

## FIX 1 — `mangleNumber()` emitted hex nibbles in reverse order  *(correctness, user-visible labels)*

**Where**: `RTTI.cpp`, `mangleNumber()` (BCD label generation for `??_R1…` names).

**Defect**: values > 10 were written least-significant nibble first
(`64 → "AE@"`, `16 → "AB@"`). MSVC writes them most-significant first.

**Evidence**: every public-inheritance BCD in both corpus binaries carries
`attributes = 0x40 = 64`, mangled `EA@` in the linker map and decoded as
`(…,…,…,64)` by Microsoft's `undname.exe`; `CMI_Three`'s `CMI_C` BCD has
`mdisp = 16` mangled `BA@` (`??_R1BA@?0A@EA@CMI_C@@8`). The old code cannot
produce either string. Palindromic values like `0x88 → II@` (CMI_BigOffset)
masked the bug during casual testing. Consequence: any BCD label IDA had *not*
already named got an undecodable name, so IDA displayed the raw mangled string
instead of `Class::'RTTI Base Class Descriptor at (a,b,c,d)'`.

**Fix**: digits are accumulated then reversed to MSB-first; overflow check
rewritten (`num > 0` after the loop instead of the old inverted counter).
Regenerated names now round-trip twice over: 64/64 exact matches vs the
linker maps (per architecture), and 128/128 decoded by Microsoft's
`undname.exe` back to the exact `(mdisp,pdisp,vdisp,attributes)` values read
from the binary.

## FIX 2 — BCD attribute flags 0x04 / 0x08 were swapped  *(correctness, comments)*

**Where**: `RTTI.h`, `BCD_PRIVORPROTINCOMPOBJ` / `BCD_PRIVORPROTBASE`.

**Defect**: plugin had `0x04 = PRIVORPROTINCOMPOBJ`, `0x08 = PRIVORPROTBASE`;
the compiler header `rttidata.h` (MSVC 14.51) defines the opposite.

**Evidence**: corpus classes deriving `private`/`protected CAccess_Base`
produce BCD `attributes = 0x4D` (= `NOTVISIBLE|PRIVORPROTBASE|PRIVORPROTINCOMPOBJ|HASPCHD`),
matching the header's bit assignment. With the swapped constants the plugin's
attribute-flag comments on BCDs would mislabel every private/protected
inheritance.

**Fix**: constants corrected and annotated with the provenance + measured
0x4D encoding. The `ATRIBFLAG()` comment generator picks them up automatically.

## FIX 3 — `CHD_AMBIGUOUS` missing from the hierarchy label  *(feature, resolves a TODO)*

**Where**: `RTTI.cpp`, `attributeLabel()` (had `// TODO: Consider CHD_AMBIGUOUS?`).

**Evidence**: `CAmbiguous` (two non-virtual copies of `CAmb_Root`) measures
`CHD attributes = 5 = MULTINH|AMBIGUOUS`, and both its `CAmb_Root` BCDs carry
`BCD_AMBIGUOUS` (0x42). The chooser's Flags column already displayed an `A`;
the anterior comment on the vftable did not.

**Fix**: full 3-bit switch — `[MI]`, `[VI]`, `[MI VI]`, `[AMB]`, `[MI AMB]`,
`[VI AMB]`, `[MI VI AMB]`.

## FIX 4 — TypeDescriptor trailing alignment  *(resolves a `#pragma message` TODO)*

**Where**: `RTTI.cpp`, `type_info::tryStruct()` 64-bit branch
("`>> Should be align 8? Do we really even need this?`").

**Evidence**: in the VS2026 binaries the next object after a 64-bit TD is
8-byte aligned (measured strides: names of 13–18 bytes all allocate to 8-byte
boundings, with zero padding). 32-bit: 4-byte alignment.

**Fix**: alignment now uses `plat.ptrSize` (8 on x64, 4 on x86) in both
branches; the pragma question is answered in-code.

## FIX 5 — `getIdaString()` could write past the caller's buffer  *(latent overflow)*

**Where**: `RTTI.cpp`, cached-string copy path used `strncpy_s(buffer, MAXSTR, …)`
regardless of the `bufferSize` parameter. All current callers pass `MAXSTR`
buffers, so no live bug — fixed for safety.

## FIX 6 — inconsistent sign handling of the BCD `pTypeDescriptor` offset  *(consistency)*

**Where**: `RTTI.cpp`, `_RTTIBaseClassDescriptor::tryStruct()` 64-bit path
used a raw `UINT32` add while every other site uses `TO_INT64()` sign
extension. Harmless for real images (RVAs < 2 GB) but now uniform.

## FIX 7 — answered two more in-code TODOs with measured facts  *(documentation-in-code)*

* `scanSeg4Cols()` 64-bit: "Is this always 1 or can it be zero like 32bit?" —
  signature is `COL_SIG_REV1`, constant 1 in every x64 image; 0 is the 32-bit
  REV0 form only.
* `_RTTICompleteObjectLocator::isValid()` 64-bit: "Can any of these be zero
  and still be valid?" — no: `pSelf` is the COL's own RVA (never 0) and an
  offset of 0 would resolve to the PE header, which is never a valid RTTI
  object. The existing non-zero checks are correct.

## FEATURE 8 — new `RTTI::fixKnownVbtables()` pass  *(readability, new capability)*

**Where**: `RTTI.cpp`/`RTTI.h`/`Main.cpp` — new scan stage after the vftable
scan; collects `??_8` names during `gatherKnownRttiData()`.

**Evidence**: on both corpus databases, IDA 9.4 *names* the six vbtables but
leaves them mis-disassembled as code (`clc`, `sar [rdx+rcx+40h], 1` — visible
in `disasm_range` output). The vbtables' true layout (4-byte signed entries,
`entry[0] = -(vbptr offset)`, terminated by zero padding) was verified in
[VBTables-and-Virtual-Inheritance.md](VBTables-and-Virtual-Inheritance.md),
and the exact del_items/create_dword/set_cmt rescue was proven out live on
both corpus IDBs via `idapython_snippet` (see
[IDB-Annotation-Pass.md](IDB-Annotation-Pass.md)) before being ported to the
plugin.

**Implementation**: for every known `??_8` address that is still a code item,
convert the run of small non-zero signed dwords (≤ 0x10000 magnitude, zero
terminated, capped at 256 bytes) into a dword array and place one repeatable
comment stating the verified decode formula. Data items are never touched
(where IDA typed them correctly, the pass leaves them alone).

## Verified-correct things left untouched (so future RE doesn't re-litigate them)

| Area | Verification |
|---|---|
| `FORMAT_RTTI_*` name formats (`??_7/??_R0/??_R1/??_R2/??_R3/??_R4`) | exact match vs 64 linker-map symbols each (`??_R0?AVX@@@8` needs the double `@@`) |
| REV1 math (`col - objectBase = image base`) | holds for all 64 x64 COLs; field is `pSelf` per `rttidata.h` |
| COL signature checks (x86 `== 0`, x64 `== 1`) | constant across corpus; header names them `COL_SIG_REV0/REV1`; TODO in `scanSeg4Cols()` answered in-code |
| CHD `signature == 0`, attributes low-nibble mask, `numBaseClasses ≥ 1` | holds for all 128 hierarchies |
| BCD validity mask `attributes & 0xFFFFFF00 == 0` | holds (observed max 0x4D) |
| BCD struct size 0x1C incl. 6th field | `+0x18` → valid CHD in 64/64 BCDs; adjacent-BCD stride 0x1C; plugin's existing `BCD_HASPCHD` handling already placed all six fields |
| `GetKnownTypeID()` expected sizes on x64 (COL 0x24, BCD 0x24, CHD 0x14) | match IDA 9.4 til entries (`_s__RTTICompleteObjectLocator2` 36, `_s__RTTIBaseClassDescriptor` 36, `_s__RTTIClassHierarchyDescriptor` 20) — these target the *source-level* til types, while the plugin's own definitions match the *binary* sizes (0x18/0x1C/0x10) |
| TD validity heuristics (vfptr plausible, `spare == 0`, name demangles) | hold across corpus incl. non-class TDs |
| MI/VI vftable & COL naming for secondary bases (`??_7X@@6BY@@@`) | matches map for all 12 secondary vftables (52 primary + 12 secondary = 64, both architectures) |

## Open observations (no code change)

* `CHD_VIRTINH` (0x02) is not set for classes with a *single* virtual base
  (`CVLeft`, `CVRight` measure attributes 0) — only for diamonds/mixed
  hierarchies (3). Labels are computed from the flags, so nothing to fix, but
  label readers should not equate "no [VI]" with "no virtual bases".
* IDA 9.4 names RTTI objects but applies no struct types and leaves BCD
  `+0x14/+0x18` untyped — the plugin's struct-placement path remains the
  value-add for dirty/bin-IDBs where IDA found nothing.
* VS2026 places TypeDescriptors in `.data` (runtime-mutated `type_info`);
  older lore says `.rdata`. The plugin's segment-agnostic scan is unaffected.
* ARM64 COL signature lore ("signature 2") could not be tested — no ARM64
  toolchain installed. Deliberately left **UNVERIFIED**; nothing in the plugin
  depends on it (plugin is metapc-only by `init()`).

## Build validation

`Release|x64` with VS2026 toolset `v145` (project default is v143/VS2022; the
public GitHub Actions workflow stays on windows-2022/v143):

```text
msbuild IDA_ClassInformer.sln -p:Configuration=Release -p:Platform=x64
       -p:PlatformToolset=v145 -p:QtInstall=D:\Sources\_idadeps\Qt\6.8.2\msvc2022_64
       -p:QtMsBuild=D:\Sources\_idadeps\QtMsBuild   # with _IDADIR/IDASUPPORT set
→ Build succeeded. 0 Warning(s) 0 Error(s)
```
