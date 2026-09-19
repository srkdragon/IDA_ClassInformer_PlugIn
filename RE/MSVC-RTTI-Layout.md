# MSVC RTTI Binary Layout — Empirical Reference (VS2026 / MSVC 14.51)

> **Status**: every fact below was measured from binaries compiled on this machine with
> Visual Studio 2026 (MSVC 14.51.36231), cross-checked against the linker `.map` symbol
> tables, Microsoft's own `undname.exe`, the compiler's own header
> (`rttidata.h`), and IDA Professional 9.4 (via `idasql`).
> Nothing here is reproduced from folklore without verification.
> Reproduction: see [Methodology.md](Methodology.md). Corrections to prior art are
> marked **CORRECTION**.

Corpus: `RE/test/rtti_corpus.cpp` — 40+ classes covering SI/MI/VI/MI+VI, ambiguous
bases, private/protected inheritance, structs, namespaces, nested classes, templates,
interfaces, big displacements (mdisp = 8, 16, 136), and non-class `type_info` objects.
Built as `x86` and `x64` Release (`/O2 /EHsc /Zi /GR`).

Validation totals (both architectures, identical results):

| Check | Result |
|---|---|
| COLs found by byte-scan vs linker `??_R4` symbols | **64 / 64, 0 missing, 0 extra** |
| vftable COL-pointers vs `??_7` symbols | **64 / 64, 0 missing, 0 extra** |
| Regenerated `??_R1` BCD names vs linker symbols | **64 / 64 exact, 0 mismatched** |
| Regenerated `??_R1` names decoded by Microsoft `undname.exe` → (mdisp,pdisp,vdisp,attrs) vs raw bytes | **128 / 128 (both architectures), 0 mismatched** |
| BCD `pClassDescriptor` (+0x18) resolving to a valid CHD | **64 / 64** |
| IDA 9.4 name counts (`??_R4`,`??_7`,`??_R1`,`??_8`) | identical sets: 64/64/64/6, both architectures |

---

## 1. The RTTI object graph

```
vftable[-1] ──────────► _RTTICompleteObjectLocator (COL)
                             │ +0x0C  pTypeDescriptor ──► type_info / TypeDescriptor (TD)
                             │ +0x10  pClassDescriptor ─► _RTTIClassHierarchyDescriptor (CHD)
                             │                                   │ +0x0C pBaseClassArray
                             │                                   ▼
                             │                          _RTTIBaseClassArray (BCA)
                             │                                   │ [i] dword per entry
                             │                                   ▼
                             │                          _RTTIBaseClassDescriptor (BCD) ×N
                             │                                   │ +0x00 pTypeDescriptor ─► TD
                             └───────────────────────────────────┘ +0x18 pClassDescriptor ─► CHD
```

Per-class emitted block order in `.rdata` (measured, x64 example `CSI_Base`):

```
rva 0x000a7120  ??_R4  COL   (0x18 bytes: 6 dwords)
rva 0x000a7138  zero padding (align to 8/16)
rva 0x000a7150  ??_R3  CHD   (0x10 bytes: 4 dwords)
rva 0x000a7160  zero padding
rva 0x000a7168  ??_R2  BCA   (N×4 bytes)
rva 0x000a7178  ??_R1  BCD   (0x1C bytes each, see §5)
rva 0x000a7194  zero padding to next object
```

TypeDescriptors live in **`.data`**, not `.rdata`, in VS2026 output (§6) —
`type_info` is mutated at runtime (`_M_data` / hash-cache), so the compiler cannot
mark it `const`-read-only. ClassInformer scans all data segments and does not assume a
section, which remains correct.

BCDs are **shared** between hierarchies (COMDAT folding): e.g. `CDiamond`'s BCA
reuses `CVLeft`'s and `CVRight`'s BCDs; a unique-BCD count (64) is therefore smaller
than total BCA entries.

---

## 2. Complete Object Locator (COL)

```
x86 (REV0), 0x14 bytes                    x64 (REV1), 0x18 bytes
+0x00 UINT32 signature      = 0           +0x00 UINT32 signature      = 1
+0x04 UINT32 offset                        +0x04 UINT32 offset
+0x08 UINT32 cdOffset                      +0x08 UINT32 cdOffset
+0x0C VA32   pTypeDescriptor  (absolute)   +0x0C INT32  pTypeDescriptor  (image-relative)
+0x10 VA32   pClassDescriptor (absolute)   +0x10 INT32  pClassDescriptor (image-relative)
                                          +0x14 INT32  pSelf            (image-relative)
```

* **`signature` is a format revision** (MSVC `rttidata.h`: `COL_SIG_REV0 0`,
  `COL_SIG_REV1 1`), not a runtime-initialized field:
  * `0` = REV0 = 32-bit form, all pointers are absolute VAs.
  * `1` = REV1 = 64-bit form, pointers are 32-bit image-relative offsets.
  * Measured: constant across all 128 corpus COLs (64 x86 = 0, 64 x64 = 1).
    No other value was observed. (ARM64 was not testable — no ARM64 toolchain
    installed; marked **UNVERIFIED**, do not assume.)
* **`offset`** = displacement of this vftable's subobject within the complete
  object. Verified: primary vftable 0; `CMI_Two` secondary 8; `CMI_Three`
  secondaries 8/16; `CMI_BigOffset` secondary 136; `CMixFinal` secondaries
  8/24/40.
* **`cdOffset`** = constructor displacement (`this`-adjustment for the
  constructor that owns this vftable). Zero in the whole corpus (no
  constructor-via-secondary-base cases).
* **`pSelf`** (x64 only) = RVA of the COL itself; therefore
  `COL_VA - pSelf = image base`, and every REV1 offset resolves as
  `image_base + int32(field)`.
  **CORRECTION of nomenclature**: ClassInformer calls this field `objectBase`;
  the compiler calls it `pSelf`. The computation `col - objectBase` used by the
  plugin is exactly `image_base` and is correct.

## 3. Class Hierarchy Descriptor (CHD) — 0x10 bytes, both architectures

```
+0x00 UINT32 signature     = 0 (static; set to 'true' at runtime by the loader)
+0x04 UINT32 attributes    (low nibble used)
+0x08 UINT32 numBaseClasses
+0x0C ptr/offset           → BCA (VA32 on x86, INT32 image-relative on x64)
```

`attributes` (values confirmed identical to `rttidata.h`):

| Bit | Name | Observed on |
|---|---|---|
| 0x01 | `CHD_MULTINH` | CMI_Two (1), CMI_Three (1), CMI_BigOffset (1), CDiamond (3), CMixFinal (3), CAmbiguous (5) |
| 0x02 | `CHD_VIRTINH` | CDiamond (3), CMixFinal (3) |
| 0x04 | `CHD_AMBIGUOUS` | CAmbiguous (5) |

**Empirical nuance**: `CHD_VIRTINH` was **not** set for `CVLeft`/`CVRight`
(attributes = 0) even though each singly inherits `CVBase` virtually. The flag
appeared only when virtual bases coexist with multiple non-virtual bases
(diamond/mixed). Treat 0x02 as "hierarchy needs virtual-base-aware casting", not
"contains any virtual base", when reading labels.

## 4. Base Class Array (BCA)

`numBaseClasses` × 4-byte entries (VA32 on x86; INT32 image-relative on x64),
pointing at BCDs, in hierarchy order: self first, then bases in declaration /
hierarchy order (measured order for `CDiamond`: `CDiamond, CVLeft, CVRight,
CVBase…` with shared BCDs).

## 5. Base Class Descriptor (BCD) — **0x1C bytes**, both architectures

```
+0x00 ptr/offs  pTypeDescriptor   (VA32 x86 / INT32 image-rel x64)
+0x04 UINT32    numContainedBases (number of following BCA entries this base spans)
+0x08 INT32     mdisp             (PMD.mdisp)
+0x0C INT32     pdisp             (PMD.pdisp; -1 = not a virtual base)
+0x10 INT32     vdisp             (PMD.vdisp; byte offset into vbtable)
+0x14 UINT32    attributes
+0x18 ptr/offs  pClassDescriptor  (VA32 x86 / INT32 image-rel x64) ← the 6th field
```

**Every BCD emitted by VS2026 (and, as far as observable, every MSVC era that
sets `BCD_HASPCHD`) carries `attributes & 0x40` and a valid 6th field**: 64/64
corpus BCDs have `+0x18` → valid CHD (0 zero, 0 dangling). Even the classic
`(0,-1,0,64)` encoding seen in decades-old binaries (`??_R1A@?0A@EA@…`) is
`attributes = 64 = 0x40`. Adjacent-BCD stride measured = 0x1C exactly.

### 5.1 BCD attribute flags

**CORRECTION — flag values 0x04 and 0x08 were swapped in ClassInformer's
`RTTI.h`** (and appear swapped in some older articles). Authoritative values
from the compiler's `rttidata.h`, confirmed by measurement (private/protected
base BCD encodes `0x4D = NOTVISIBLE|PRIVORPROTBASE|PRIVORPROTINCOMPOBJ|HASPCHD`):

| Bit | `rttidata.h` name | Meaning |
|---|---|---|
| 0x01 | `BCD_NOTVISIBLE` | base not visible for casting in the complete object |
| 0x02 | `BCD_AMBIGUOUS` | ambiguous base (measured on `CAmbiguous`) |
| 0x04 | `BCD_PRIVORPROTBASE` | base inherited private/protected **by its direct deriver** |
| 0x08 | `BCD_PRIVORPROTINCOMPOBJ` | base private/protected **within the complete object** |
| 0x10 | `BCD_VBOFCONTOBJ` | virtual base of the complete object (measured: +0x10 on all virtual-base BCDs) |
| 0x20 | `BCD_NONPOLYMORPHIC` | (not producible in this corpus; value per header) |
| 0x40 | `BCD_HASPCHD` | `pClassDescriptor` field present — **always set in observed output** |

Measured attribute values across the corpus: `0x40` (public, plain),
`0x50` (virtual base), `0x42` (ambiguous), `0x4D` (private/protected).

### 5.2 PMD (mdisp/pdisp/vdisp) measured values

| Hierarchy | BCD | mdisp | pdisp | vdisp |
|---|---|---|---|---|
| CMI_Two → CMI_B | CMI_B | 8 (x64) / 4 (x86) | -1 | 0 |
| CMI_Three → CMI_C | CMI_C | 16 (x64) / 8 (x86) | -1 | 0 |
| CMI_BigOffset → CPad_B | CPad_B | 136 (x64) / 132 (x86) | -1 | 0 |
| CVLeft → CVBase | CVBase | 0 | 8 (x64) / 4 (x86) | 4 |
| CMixFinal → CVBase | CVBase | 0 | 16 (x64) / 8 (x86) | 4 |

`pdisp` is the byte offset of the vbptr inside the owning subobject; `vdisp` is
a **byte** offset into the vbtable (entries are 4-byte displacements even on
x64 — hence `vdisp = 4`, not 8). See
[VBTables-and-Virtual-Inheritance.md](VBTables-and-Virtual-Inheritance.md) for
the full vbtable decode.

## 6. TypeDescriptor / `type_info` — emitted in `.data`

```
x86: +0x00 VA32 vfptr (→ ??_7type_info@@6B@), +0x04 VA32 spare(_M_data)=0,
      +0x08 char _M_d_name[] ".?AVName@@" / ".?AUname@@" / ".?AW4enum@@"
x64: same with 8-byte fields, name at +0x10
```

* `spare` (`_M_data`) is **0 in the image** on every corpus TD (runtime fills a
  hash cache there) — a good validity check the plugin already uses.
* Name allocation padding (measured): the next object starts pointer-size
  aligned (8 on x64, 4 on x86); MSVC leaves at least 4 trailing bytes of zero
  padding (x86 observed alloc = `roundup4(len)+4`; x64 = `roundup8(len)` with
  frequent +8 slack). Trailing bytes are zeros.

## 7. Decorated-name formats (verified by exact round-trip)

Ground truth = linker map symbols; decoder = Microsoft `undname.exe`;
regenerator = `RE/tools/rtti_scan.py` (`bcd_name()`), 64/64 exact matches:

| Object | Format | Example (measured) |
|---|---|---|
| vftable | `??_7<scope>6B[@<base>@@]@` | `??_7CMI_Two@@6BCMI_B@@@` |
| TypeDescriptor | `??_R0?<rawname-minus-.?>@8` | `??_R0?AVCSI_Base@@@8` |
| BCD | `??_R1<mdisp><pdisp><vdisp><attrs><rawname-minus-.?A>8` | `??_R1A@?0A@EA@CSI_Base@@8` |
| BCA | `??_R2<name>8` | `??_R2CSI_Base@@8` |
| CHD | `??_R3<name>8` | `??_R3CSI_Base@@8` |
| COL | `??_R4<scope>6B[@<base>@@]@` | `??_R4CDiamond@@6BCVRight@@@` |
| vbtable | `??_8<scope>7B[@<base>@]@` | `??_8CDiamond@@7BCVLeft@@@` |

### 7.1 Number mangling inside `??_R1` names (**CORRECTION**)

Empirically exact encoding (all four numbers use it):

| Value | Encoding | Example |
|---|---|---|
| 0 | `A@` | mdisp 0 → `A@` |
| 1 … 10 | digit `'0'`…`'9'` (value − 1) | 8 → `7`; −1 → `?0` |
| > 10 | hex nibbles `'A'`…`'P'`, **most-significant nibble first**, terminated `@` | 16 → `BA@`; 64 → `EA@`; 136 → `II@` |
| negative | `?` prefix on the above | −1 → `?0` |

ClassInformer's `mangleNumber()` previously wrote the hex nibbles
**least-significant first** (`64 → "AE@"`), so any displacement/attribute with
asymmetric nibbles > 10 (e.g. every `attributes = 0x40` → should be `EA@`)
produced invalid names that IDA's demangler cannot decode. Fixed in
`RTTI.cpp`; validated 64/64 against the linker map. Palindromic values
(`0x88 → II@`) masked the bug in casual testing.

## 8. What IDA Pro 9.4 does with these structures (idasql cross-check)

On the final corpus, both architectures: IDA found and named **64/64 COLs,
64/64 vftables, 64/64 BCDs, 6 vbtables** (`??_8`) — identical sets to the
independent byte-scan and the linker maps. Details worth knowing for the plugin:

* IDA **names** every RTTI object with the correct decorated name but applies
  **no struct type** to them (`applied_types` empty at all 60 COL addresses).
* BCD fields get per-field comments ("member displacement", "vftable
  displacement", …) and `dd rva` items for the first five dwords — the 6th
  field (`+0x18`) and often `+0x14` remain untyped bytes (`add [rax], al`
  artifacts), i.e. even IDA treats the BCD as 0x14 for display purposes.
* IDA's local til contains both "source-level" and "binary-accurate" RTTI
  types: `_s__RTTICompleteObjectLocator2` (0x24) / `_RTTICompleteObjectLocator`
  (0x18), `_s__RTTIBaseClassDescriptor` (0x24) / `_RTTIBaseClassDescriptor`
  (0x1C), `_s__RTTIClassHierarchyDescriptor` (0x14) /
  `_RTTIClassHierarchyDescriptor` (0x10). ClassInformer's
  `GetKnownTypeID()` expected sizes are tuned to the first column (they match),
  and its own definitions match the binary-accurate second column.

## 9. Runtime consumption (decompiled evidence)

IDA 9.4 Hex-Rays decompilation of the statically-linked CRT in the corpus
(`__RTDynamicCast`, `CDiamond::CDiamond`) confirms the static layout
semantics:

**`__RTDynamicCast(void *inptr, long VfDelta, TypeDescriptor *src, TypeDescriptor *target, int isReference)`**:

```c
v10 = *(_s_RTTICompleteObjectLocator **)(*(_QWORD *)inptr - 8);  // vftable[-1] → COL
cdOffset = v10->cdOffset;
if (cdOffset) v12 = *(_DWORD *)&inptr[-cdOffset];                // ctor this-adjustment
v13 = &inptr[-v12 - v10->offset];                                // complete object base
if (v10->signature != 0)                                         // REV1 branch
    _ImageBase = (char *)v10 - v10->pSelf;                       // == image base
```

* The runtime itself branches on `signature` (REV0 vs REV1) and computes the
  image base as `COL - pSelf` — **exactly the `col - objectBase` arithmetic
  ClassInformer uses**.
* Complete-object address = `this - *(int*)(this - cdOffset) - offset`.

**`CDiamond::CDiamond`** (virtual-base construction, confirms PMD/vbtable
mechanics):

```c
*(_QWORD *)((char *)this + 8)  = &CDiamond::`vbtable'{for `CVLeft'};   // vbptr at pdisp=8
*(_QWORD *)((char *)this + 24) = &CDiamond::`vbtable'{for `CVRight'};
this->vfptr = CDiamond::`vftable'{for `CVLeft'};
*(_QWORD *)((char *)this + 8 + *(int *)(*(char **)((char *)this + 8) + 4))
                               = CDiamond::`vftable'{for `CVBase'};
```

* vbtable entries are **4-byte ints** even on x64 (read as `*(int*)(vbptr + 4)`)
  — matching `vdisp = 4` measured in the BCDs.
* Virtual-base subobject address = `this + pdisp + *(int*)(vbptr + vdisp)`.

## 10. Quick-reference size table (measured)

| Structure | x86 | x64 | Align (inter-object) |
|---|---|---|---|
| COL | 0x14 | 0x18 | 8 |
| CHD | 0x10 | 0x10 | 8 (x64) / 4 (x86) |
| BCA | 4·N | 4·N | 8 (x64) / 4 (x86) |
| BCD | 0x1C | 0x1C | 4 |
| TD | 8+len+pad | 16+len+pad | pointer-size |

Primary sources: `rttidata.h` (MSVC 14.51), binaries + maps in `RE/test/`,
dumps in `RE/data/`.
