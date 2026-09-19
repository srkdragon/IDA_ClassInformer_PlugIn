# MSVC vbtables (`??_8`) and Virtual Inheritance — Empirical Reference

Everything in this document was derived **empirically** from the two VS2026
(MSVC 14.51.36231, `/O2 /GR`) corpus binaries and cross-checked against three
independent ground truths:

1. **Linker maps** (`RE/test/rtti_corpus_x64.map`, `rtti_corpus_x86.map`) —
   authoritative symbol names + absolute VAs.
2. **RTTI structures** (`RE/data/rtti_x64.json`, `rtti_x86.json` from
   `RE/tools/rtti_scan.py`) — COL `offset` fields, BCD `mdisp/pdisp/vdisp`.
3. **Generated code** — `dumpbin /disasm` of `RE/test/rtti_corpus.obj` (x64,
   with symbols; saved as `RE/test/RE_dumpbin_x64.txt`) and of
   `rtti_corpus_x86.exe` (`RE/test/RE_dumpbin_x86.txt`): constructors store
   vbtable/vftable pointers at literal offsets.

Demangled names are Microsoft's own `undname.exe` output. Corpus classes
(`RE/test/rtti_corpus.cpp` lines 147–191):

```cpp
class CVBase  { virtual ~CVBase() = default; virtual int v() const; virtual int v2() const; };
class CVLeft  : public virtual CVBase { int v() const override; virtual int l() const; };
class CVRight : public virtual CVBase { int v2() const override; virtual int r() const; };
class CDiamond : public CVLeft, public CVRight { int v() const override; int v2() const override; };
class CMixFinal : public CMix_Plain, public CVLeft, public CVRight { /* overrides only */ };
```

Image bases: x64 `0x140000000`, x86 `0x400000`. All "RVA" values below are
`VA - image_base`; map lines carry absolute VAs.

---

## 1. The `??_8` symbol inventory (from the maps)

Six vbtables per architecture. Map line refs: x64 map lines 2983–2998,
x86 map lines 2986–3001.

| Mangled name | undname.exe result | x64 VA (=RVA+0x140000000) | x86 VA (=RVA+0x400000) |
|---|---|---|---|
| `??_8CVLeft@@7B@` | ``const CVLeft::`vbtable'`` | `0x140099280` (RVA `0x99280`) | `0x47D00C` (RVA `0x7D00C`) |
| `??_8CVRight@@7B@` | ``const CVRight::`vbtable'`` | `0x1400992D0` (RVA `0x992D0`) | `0x47D038` (RVA `0x7D038`) |
| `??_8CDiamond@@7BCVLeft@@@` | ``const CDiamond::`vbtable'{for `CVLeft'}`` | `0x140099338` (RVA `0x99338`) | `0x47D070` (RVA `0x7D070`) |
| `??_8CDiamond@@7BCVRight@@@` | ``const CDiamond::`vbtable'{for `CVRight'}`` | `0x140099344` (RVA `0x99344`) | `0x47D07C` (RVA `0x7D07C`) |
| `??_8CMixFinal@@7BCVLeft@@@` | ``const CMixFinal::`vbtable'{for `CVLeft'}`` | `0x1400993E8` (RVA `0x993E8`) | `0x47D0D4` (RVA `0x7D0D4`) |
| `??_8CMixFinal@@7BCVRight@@@` | ``const CMixFinal::`vbtable'{for `CVRight'}`` | `0x1400993F4` (RVA `0x993F4`) | `0x47D0E0` (RVA `0x7D0E0`) |

Naming grammar (observed): `??_8<CompleteClass>@@7B@` when the vbptr belongs
to the complete class's *own* subobject (`CVLeft`, `CVRight`), and
`??_8<CompleteClass>@@7B<SubObject>@@@` for the copy of a base subobject's
vbtable specialized for `<CompleteClass>`. A synthetic
`??_8CDiamond@@7B@` also demangles fine (``const CDiamond::`vbtable'``) but
is not emitted for CDiamond because its only vbptrs live inside the CVLeft /
CVRight subobjects.

---

## 2. Empirically decoded vbtable layout

### 2.1 Structure

* Entries are **4-byte little-endian signed ints on both x86 and x64**
  (not pointer-sized). x64 proof: constructor loads the entry with a dword
  access and sign-extends — `movsxd rcx, dword ptr [rax+4]`
  (`??0CDiamond@@QEAA@XZ`, obj disasm offset `0x36`).
* **Entry count = 1 + number of virtual bases** reachable from the owning
  subobject in this corpus (every class has exactly one virtual base, so all
  six vbtables have exactly 2 entries = 8 bytes).
* `entry[0]` = **displacement of the owning subobject's start, relative to
  the vbptr field address**. In all 12 samples it equals
  −(vbptr offset inside the owning subobject) = `-8` on x64, `-4` on x86
  (verified against the BCD `pdisp` of the subobject's own hierarchy, 12/12
  matches, and against the constructor store offsets).
* `entry[i>0]` = **displacement of the i-th virtual base subobject, also
  relative to the vbptr field address** (see §3).
* Nothing else lives inside the object: after the last entry the linker
  places zero padding (to 4 or 8 bytes) and then the *next* `.rdata` object,
  which in this corpus is always the COL pointer of the following `??_7`
  vftable (x64: 8-byte VA; x86: 4-byte VA). That pointer is a reliable
  content-based terminator when scanning without symbols: it is an absolute
  VA (`0x1400A7CD0`, `0x4871C4`, …), far outside the plausible displacement
  range. A `0` dword alone is **not** a safe terminator — it is padding here,
  but `0` is also a legal displacement value (a virtual base can coincide
  with a position, and `entry[0]` can be `0` when the vbptr is the first
  member). UNVERIFIED whether a `0` entry ever occurs in this compiler's
  output for this corpus (it does not).

### 2.2 Annotated dump — `??_8CVLeft@@7B@`

A standalone `CVLeft` object is `[+0 vfptr][+8 vbptr][+16 CVBase]` (x64) /
`[+0 vfptr][+4 vbptr][+8 CVBase]` (x86). Subobject positions are ground truth
from COL `offset` fields: `??_7CVLeft@@6B0@@`→COL off 0,
`??_7CVLeft@@6BCVBase@@@`→COL off 16 (x64) / 8 (x86).

x64, RVA `0x99280` (VA `0x140099280`):

```
99280  F8 FF FF FF   entry[0] = -8   ; subobject start = vbptr( +8) + (-8) = +0
99284  08 00 00 00   entry[1] = +8   ; CVBase = vbptr(+8) + 8 = +16  (COL off 16 OK)
99288  00 00 00 00   padding (tail align to 8)
9928C  00 00 00 00   padding (high dword of next qword)
99290  D0 7C 0A 40 01 00 00 00  = VA 0x1400A7CD0 -> COL of CVRight off=0
                                   (COL pointer of ??_7CVRight@@6B0@@ @ 0x99298)
```

x86, RVA `0x7D00C` (VA `0x47D00C`):

```
47D00C  FC FF FF FF   entry[0] = -4  ; subobject start = vbptr(+4) + (-4) = +0
47D010  04 00 00 00   entry[1] = +4  ; CVBase = vbptr(+4) + 4 = +8   (COL off 8 OK)
47D014  00 00 00 00   padding
47D018  C4 71 48 00                = VA 0x4871C4 -> COL of CVRight off=0
                                   (COL pointer of ??_7CVRight@@6B0@@ @ 0x47D01C)
```

### 2.3 Annotated dump — the two CDiamond vbtables

`CDiamond` layout (COL offsets `0/16/32` x64, `0/8/16` x86):
`[CVLeft part @0: vfptr@0, vbptr@8/4][CVRight part @16/8: vfptr, vbptr@+8/4
within part][CVBase @32/16]`.

x64, RVA `0x99338` and `0x99344`:

```
??_8CDiamond@@7BCVLeft@@@   (stored into [this+8] by the ctor)
99338  F8 FF FF FF   entry[0] = -8   ; CVLeft part start = 8 + (-8) = 0
9933C  18 00 00 00   entry[1] = +24  ; CVBase = vbptr(8) + 24 = +32   (COL off 32 OK)
99340  00 00 00 00   padding

??_8CDiamond@@7BCVRight@@@  (stored into [this+0x18] by the ctor)
99344  F8 FF FF FF   entry[0] = -8   ; CVRight part start = 24 + (-8) = 16
99348  08 00 00 00   entry[1] = +8   ; CVBase = vbptr(24) + 8 = +32    (same subobject!)
9934C  00 00 00 00   padding
99350  D0 7E 0A 40 01 00 00 00  = VA 0x1400A7ED0 -> COL of CMix_Plain off=0
                                   (COL pointer of ??_7CMix_Plain@@6B@ @ 0x99358)
```

x86, RVA `0x7D070` and `0x7D07C`:

```
??_8CDiamond@@7BCVLeft@@@    (stored into [ecx+4])
47D070  FC FF FF FF   entry[0] = -4  ; CVLeft part = 4 + (-4) = 0
47D074  0C 00 00 00   entry[1] = +12 ; CVBase = vbptr(4) + 12 = +16    (COL off 16 OK)
47D078  00 00 00 00   padding

??_8CDiamond@@7BCVRight@@@   (stored into [ecx+0Ch])
47D07C  FC FF FF FF   entry[0] = -4  ; CVRight part = 12 + (-4) = 8
47D080  04 00 00 00   entry[1] = +4  ; CVBase = vbptr(12) + 4 = +16    (same subobject!)
47D084  00 00 00 00   padding
47D088  F8 72 48 00               = VA 0x4872F8 -> COL of CMix_Plain off=0
```

Note the diamond in action: **both** vbtables locate the *same shared* CVBase
subobject (`+32`/`+16`), each relative to its own vbptr field. The entries
differ (`24` vs `8` on x64) precisely because the two vbptr fields sit at
different offsets (`+8` vs `+24`).

`??_8CMixFinal@@7B*` are shaped identically to CDiamond's
(CMixFinal layout: `[CMix_Plain@0][CVLeft@8/4: vfptr, vbptr@16/8][CVRight@24/12:
vfptr, vbptr@32/16][CVBase@40/20]`):

| vbtable | x64 entries | x86 entries | CVBase check |
|---|---|---|---|
| `??_8CMixFinal@@7BCVLeft@@@` | `-8, 24` | `-4, 12` | 16+24=40 / 8+12=20 = COL off 40/20 OK |
| `??_8CMixFinal@@7BCVRight@@@` | `-8, 8`  | `-4, 4`  | 32+8=40 / 16+4=20 = COL off 40/20 OK |

---

## 3. The verified PMD (pdisp/vdisp) resolution formula

### 3.1 The formula

For a `_RTTIBaseClassDescriptor` with `PMD {mdisp, pdisp, vdisp}` and
`pdisp != -1` (virtual base; flag `BCD_VBOFCONTOBJ 0x10` set on the base):

```c
char* vbptr_field = (char*)obj + pdisp;             // where the vbptr lives
int*  vbtable     = *(int**)vbptr_field;            // what it points at
char* base        = vbptr_field + vbtable[vdisp/4]; // vdisp is a BYTE offset
// all corpus samples additionally have mdisp == 0 for virtual bases,
// so the general "obj + mdisp + ..." form could not be distinguished here
// (see §8).
```

Equivalently: **`base_offset_in_object = pdisp + vbtable[vdisp/4]`**.
Verified numerically for **every** `BCD_VBOFCONTOBJ` descriptor in both
binaries (x64: BCD@`0xA7C70` in CVLeft/CVRight/CDiamond CHDs, BCD@`0xA8040`
in CMixFinal's CHD; x86: BCD@`0x87188` and BCD@`0x873E4`), always matching
the COL `offset` of the `??_7<Class>@@6BCVBase@@@` vftable:

| Object (x64) | BCD used | pdisp | vdisp | vbtable read | result | ground truth |
|---|---|---|---|---|---|---|
| CVLeft    | `0xA7C70` | 8  | 4 | `??_8CVLeft@@7B@`[1] = 8  | 8+8  = 16 | COL off 16 |
| CVRight   | `0xA7C70` | 8  | 4 | `??_8CVRight@@7B@`[1] = 8 | 8+8  = 16 | COL off 16 |
| CDiamond  | `0xA7C70` | 8  | 4 | `??_8CDiamond@@7BCVLeft@@@`[1] = 24 | 8+24 = 32 | COL off 32 |
| CMixFinal | `0xA8040` | 16 | 4 | `??_8CMixFinal@@7BCVLeft@@@`[1] = 24 | 16+24 = 40 | COL off 40 |

(x86 rows: 4+4=8, 4+4=8, 4+12=16, 8+12=20 — all match the x86 COL offsets.)

The entries are relative to the **vbptr field**, not to the object start:
for CDiamond x64, `??_8CDiamond@@7BCVLeft@@@[1] = 24` would place CVBase at
`+24` if added to `obj`; it is correct (`+32`) only when added to
`obj + pdisp` (`+8`).

### 3.2 The compiler implements exactly this

`??0CDiamond@@QEAA@XZ` (x64 obj, `RE/test/RE_dumpbin_x64.txt` around line 96):

```asm
0000000000000007: lea  rax,[??_8CDiamond@@7BCVLeft@@@]
000000000000000E: mov  qword ptr [rcx+8],rax          ; vbptr field @ +8  (= pdisp)
0000000000000012: lea  rax,[??_8CDiamond@@7BCVRight@@@]
0000000000000019: mov  qword ptr [rcx+18h],rax        ; vbptr field @ +24
000000000000001D: lea  rax,[??_7CVBase@@6B@]
0000000000000024: mov  qword ptr [rcx+20h],rax        ; CVBase vfptr @ +32
...
0000000000000032: mov  rax,qword ptr [rcx+8]          ; rax = vbtable
0000000000000036: movsxd rcx,dword ptr [rax+4]        ; rcx = entry @ +4 (= vdisp!)
000000000000003A: lea  rax,[??_7CVLeft@@6BCVBase@@@]
0000000000000041: mov  qword ptr [rcx+r8+8],rax       ; store at this + 8 + 24 = +32
...
0000000000000051: mov  rax,qword ptr [r8+18h]         ; CVRight's vbptr @ +24
0000000000000055: movsxd rcx,dword ptr [rax+4]        ; entry = 8
0000000000000059: lea  rax,[??_7CVRight@@6BCVBase@@@]
0000000000000060: mov  qword ptr [rcx+r8+18h],rax     ; store at 24 + 8 = +32 (same!)
```

x86 `??0CDiamond@@QAE@XZ` @ `0x407BA0` (`RE_dumpbin_x86.txt` lines 6434–6464):

```asm
00407BA8: mov dword ptr [ecx+4],offset  ??_8CDiamond@@7BCVLeft@@@   ; vbptr @ +4
00407BAF: mov dword ptr [ecx+0Ch],offset ??_8CDiamond@@7BCVRight@@@ ; vbptr @ +12
00407BB6: mov dword ptr [ecx+10h],offset ??_7CVBase@@6B@            ; CVBase @ +16
00407BBD: mov eax,dword ptr [ecx+4]
00407BC6: mov eax,dword ptr [eax+4]          ; entry[1] = 12
00407BC9: mov dword ptr [eax+ecx+4],offset ??_7CVLeft@@6BCVBase@@@  ; 4+12 = +16
00407BD1: mov eax,dword ptr [ecx+0Ch]
00407BDB: mov eax,dword ptr [eax+4]          ; entry[1] = 4
00407BDE: mov dword ptr [eax+ecx+0Ch],offset ??_7CVRight@@6BCVBase@@@ ; 12+4 = +16
```

Same pattern in `??0CVLeft`, `??0CVRight`, `??0CMixFinal` on both
architectures (x86 @ `0x407E10`, `0x407E50`, `0x407CC0`; x64 obj at the
corresponding labels). Also note the **most-derived flag protocol**: the
vbptr/virtual-base initialization is guarded by `test edx,edx` (x64) /
`cmp dword ptr [esp+8],0` (x86, hidden stack arg, `ret 4`) — only the
most-derived constructor fills vbptrs.

### 3.3 Two coordinate frames for `pdisp` (both verified)

* **RTTI frame**: in a BCD inside class M's CHD, `pdisp` is the offset of the
  vbptr field **within a complete M object**. Evidence: CMixFinal's CVBase
  BCD (`0xA8040`) has `pdisp = 16` — that is CVLeft's vbptr at
  `CMixFinal+16` (CVLeft part @8 + 8). Measured from the CVLeft *subobject*
  it would be 8; measured from the CVRight part it would be 40 — both wrong.
* **Code frame**: inside a subobject's constructor/member code the compiler
  addresses that subobject's own vbptr with a subobject-relative offset
  (CDiamond ctor loads CVRight's vbptr from `[r8+18h]` = subobject(16)+8).
  The vbtable *entries* are relative to the vbptr field in both frames,
  which is why the same arithmetic works.

A single BCD is COMDAT-shared across hierarchies whenever its content
collides: x64 BCD@`0xA7C70` (`??_R1A@73FA@CVBase@@8`: mdisp 0, pdisp 8,
vdisp 4, attrs 0x50) is referenced by the BCAs of CVLeft, CVRight **and**
CDiamond — in each of those complete objects the vbptr-to-use really is at
`+8`. CMixFinal needs `pdisp 16` so it gets its own BCD@`0xA8040`
(`??_R1A@BA@3FA@CVBase@@8`). x86 equivalents: `??_R1A@33FA@CVBase@@8`
(pdisp 4) shared by CVLeft/CVRight/CDiamond, `??_R1A@73FA@CVBase@@8`
(pdisp 8) for CMixFinal. Consequence: the RTTI runtime always resolves
CVBase through the **CVLeft-path vbptr** in these hierarchies (both BCA
entries `[2]`/`[4]`, `[3]`/`[5]` share one BCD); the `{for 'CVRight'}`
vbtables are consumed by generated code in the CVRight-subobject context,
not by RTTI. The PMD values are additionally visible in the decorated BCD
names themselves (`??_R1<mdisp><pdisp><vdisp><attrs><name>8`).

### 3.4 `entry[0]` (task: what is it?)

`entry[0]` is the displacement of the **owning subobject's start from the
vbptr field** — i.e. `subobject_start = vbptr_field + entry[0]`, numerically
`entry[0] = -(pdisp_within_subobject)`. Verified 12/12 against the BCD
`pdisp` of the owning subobject's own hierarchy (`-8` vs pdisp 8 on x64,
`-4` vs pdisp 4 on x86) and against constructor store offsets. Examples:
`??_8CDiamond@@7BCVRight@@@` x64: vbptr @ `+24`, `entry[0] = -8` →
subobject start `+16` = CVRight part ✓ (COL off 16).
`??_8CMixFinal@@7BCVLeft@@@` x86: vbptr @ `+8`, `entry[0] = -4` →
subobject start `+4` = CVLeft part ✓ (COL off 4).

---

## 4. Correlation table: class → vbtable → entries → referencing BCDs

BCD "pdisp/vdisp" columns are the PMD of the CVBase descriptor inside that
class's CHD; "via vbptr @" is where the constructor stores the vbtable.

| Complete class | vbtable | x64 RVA | x64 entries | x86 RVA | x86 entries | stored at (ctor) | Referenced by BCD |
|---|---|---|---|---|---|---|---|
| CVLeft    | `??_8CVLeft@@7B@`            | `0x99280` | `-8, 8`  | `0x7D00C` | `-4, 4`  | this+8 / +4   | `0xA7C70`/`0x87188` (pdisp 8/4, vdisp 4) |
| CVRight   | `??_8CVRight@@7B@`           | `0x992D0` | `-8, 8`  | `0x7D038` | `-4, 4`  | this+8 / +4   | `0xA7C70`/`0x87188` (pdisp 8/4, vdisp 4) |
| CDiamond  | `??_8CDiamond@@7BCVLeft@@@`  | `0x99338` | `-8, 24` | `0x7D070` | `-4, 12` | this+8 / +4   | `0xA7C70`/`0x87188` (pdisp 8/4, vdisp 4) |
| CDiamond  | `??_8CDiamond@@7BCVRight@@@` | `0x99344` | `-8, 8`  | `0x7D07C` | `-4, 4`  | this+24 / +12 | (RTTI resolves via the CVLeft vbptr; used by CVRight-context code) |
| CMixFinal | `??_8CMixFinal@@7BCVLeft@@@` | `0x993E8` | `-8, 24` | `0x7D0D4` | `-4, 12` | this+16 / +8  | `0xA8040`/`0x873E4` (pdisp 16/8, vdisp 4) |
| CMixFinal | `??_8CMixFinal@@7BCVRight@@@` | `0x993F4` | `-8, 8`  | `0x7D0E0` | `-4, 4`  | this+32 / +16 | (same note as CDiamond/CVRight) |

Object layouts derived from COL offsets + ctor stores (all cross-consistent):

```
x64:  CVLeft/CVRight : 0 vfptr | 8 vbptr | 16 CVBase          (size 24)
      CDiamond        : 0 CVLeft(vfptr,vbptr@8) | 16 CVRight(vfptr,vbptr@24) | 32 CVBase
      CMixFinal       : 0 CMix_Plain vfptr | 8 CVLeft vfptr | 16 CVLeft vbptr
                      | 24 CVRight vfptr | 32 CVRight vbptr | 40 CVBase
x86:  CVLeft/CVRight : 0 vfptr | 4 vbptr | 8 CVBase           (size 12)
      CDiamond        : 0 CVLeft(vbptr@4) | 8 CVRight(vbptr@12) | 16 CVBase
      CMixFinal       : 0 CMix_Plain | 4 CVLeft(vbptr@8) | 12 CVRight(vbptr@16) | 20 CVBase
```

---

## 5. Virtual-base subobject vftables and the `6B0@` name

### 5.1 `{for 'CVBase'}` vftables carry the base's offset as COL offset

| vftable | undname | COL x64 | COL x86 |
|---|---|---|---|
| `??_7CVLeft@@6BCVBase@@@`   | ``const CVLeft::`vftable'{for `CVBase'}``    | off 16 | off 8  |
| `??_7CVRight@@6BCVBase@@@`  | ``const CVRight::`vftable'{for `CVBase'}``   | off 16 | off 8  |
| `??_7CDiamond@@6BCVBase@@@` | ``const CDiamond::`vftable'{for `CVBase'}``  | off 32 | off 16 |
| `??_7CMixFinal@@6BCVBase@@@`| ``const CMixFinal::`vftable'{for `CVBase'}`` | off 40 | off 20 |

For a **non-virtual** base subobject, the COL offset is a constant of the
base class; for a **virtual** base it depends on the most-derived class, so
every most-derived class emits its own copy of the subobject vftables it
overrides through. The inlined base-constructor sequence inside the x64
`??0CDiamond` shows the layering: instruction @`+0x24` writes
`??_7CVBase@@6B@` to `[rcx+20h]`, @`+0x41` overwrites the same slot with
`??_7CVLeft@@6BCVBase@@@`, and @`+0x89` finally writes
`??_7CDiamond@@6BCVBase@@@` — the surviving vfptr names the most-derived
override set. All three stores target the same computed address
`this+8+24 = +32`.

### 5.2 What `??_7CVLeft@@6B0@@` is

```
undname: ??_7CVLeft@@6B0@@   ->  const CVLeft::`vftable'{for `CVLeft'}
```

The `0@` component is a **self-scope reference** in the vftable's `{for …}`
qualifier list: this is the vftable of the class's *own* virtual functions.
It appears here (and for `??_7CVRight@@6B0@@`) because CVLeft/CVRight have
**only a virtual base** — there is no non-virtual polymorphic base at offset
0 whose vftable could be extended, so MSVC allocates a fresh vftable at
offset 0 for the class's newly introduced virtuals (`l()` / `r()`) plus
overrides, scoped `{for 'CVLeft'}`. Classes that extend a *non-virtual*
primary base keep the plain form: `??_7CMixFinal@@6B@` (CMix_Plain at offset
0 hosts it), `??_7CPlain@@6B@`, etc. CDiamond, which introduces no new
virtual functions, emits no self vftable at all. Evidence: COL offsets
(`6B0@` tables all have off 0), constructor stores (`[rcx]=??_7CVLeft@@6B0@@`
immediately followed by the CVBase-slot store at `+0x36`), and the undname
probes below. A synthetic `??_7CDiamond@@6B0@@` also demangles
(``const CDiamond::`vftable'{for `CDiamond'}``), while `??_7CVLeft@@6B1@@`
is **rejected** by undname (echoed unchanged) — `0` is the only valid digit
in that position (the "self" index), not an arbitrary base ordinal.

Whether a virtual-base-only class with *no* new virtuals still receives a
`6B0@` table is UNVERIFIED (no such class in the corpus).

---

## 6. x86 vs x64 differences

| Property | x86 | x64 | Evidence |
|---|---|---|---|
| vbtable entry size | 4 bytes (`int32`) | 4 bytes (`int32`) — **not** pointer-scaled | ctor `movsxd … dword ptr [rax+4]` (x64); identical dword grids |
| `entry[0]` | `-4` (= −vbptr offset) | `-8` (= −vbptr offset) | all six vbtables per arch |
| `vdisp` | byte offset, `4` everywhere (entry index 1) | same | all VBOFCONTOBJ BCDs |
| `pdisp` | 4 / 8 | 8 / 16 | BCDs `0x87188`/`0x873E4` vs `0xA7C70`/`0xA8040` |
| Entry values for the same class pair | CVBase at vbptr+4 (CVLeft), vbptr+12 / +4 (CDiamond L/R) | vbptr+8 (CVLeft), vbptr+24 / +8 (CDiamond L/R) | §2 dumps |
| vbptr slot size | 4 bytes | 8 bytes | ctor qword vs dword stores |
| Alignment after vbtable | pad to 4 | pad to 4/8, next COL ptr 8-aligned | §2 dumps |
| Ctor most-derived flag | hidden stack arg (`[esp+8]`, `ret 4`) | `edx` | `??0CDiamond` both arches |

The **semantics** (formula, entry[0] meaning, vdisp scaling, BCD sharing)
are identical; only the pointer-size-driven object geometry differs, which
changes pdisp and the entry values but nothing structural. Everything that
varies does so exactly as the layout does.

---

## 7. What IDA 9.4 does, and implications for ClassInformer

### 7.1 IDA 9.4 ground truth (idasql, one run per arch)

`idasql.exe -s <exe> -q "SELECT addr,name FROM names WHERE name LIKE '??_8%'
OR name LIKE '??_7%' ORDER BY addr"` (raw output captured in
`RE/data/ida_names_x64.txt` / `ida_names_x86.txt`):

* IDA 9.4 **does** create names for vbtables, using the **raw decorated
  MSVC name**: x64 `5369336448 = 0x140099280 → ??_8CVLeft@@7B@`,
  `5369336632 → ??_8CDiamond@@7BCVLeft@@@`, `5369336644 →
  ??_8CDiamond@@7BCVRight@@@`, `5369336808/5369336820 →
  ??_8CMixFinal@@7BCVLeft@@@/??_8CMixFinal@@7BCVRight@@@` — addresses match
  the linker maps exactly. x86: `4706316 = 0x47D00C → ??_8CVLeft@@7B@`,
  `4706360 → ??_8CVRight@@7B@`, `4706416/4706428 → ??_8CDiamond@@7B…`,
  `4706516/4706528 → ??_8CMixFinal@@7B…`. All six `??_8` names present per
  architecture; `??_7…6B0@@` names present as well.
* The `names` view returns the mangled form only. Whether the IDA UI
  additionally displays a demangled variant for `??_8` is UNVERIFIED (not
  queryable with this single view).

### 7.2 Implications for ClassInformer

ClassInformer currently neither names nor structures `??_8` objects. The
empirical facts above enable:

1. **Naming**: `??_8` symbols can be demangled exactly like `??_7`
   (same `6B`/`7B` qualifier grammar; undname output in §1). A
   ClassInformer pass that already demangles `{for 'X'}` vftables gets
   vbtables for free: ``const CDiamond::`vbtable'{for `CVLeft'}``.
2. **Sizing/typing**: give the vbtable a real array type. Length is
   `4 * (1 + nVirtualBases)`; safe end-detection = "dwords that are small
   signed values (roughly `-object_size … +object_size`), stopping at the
   first dword that is an image VA or at a symbol/RTTI-derived bound". Do
   **not** stop at `0` (see §2.1). `int vbtable[1 + nVB]` with a comment per
   entry: `[0] = back-displacement to subobject start (== -pdisp)`,
   `[i] = displacement of i-th virtual base from the vbptr field`.
3. **Cross-referencing RTTI → vbtables**: every BCD with
   `pdisp != -1` (and `BCD_VBOFCONTOBJ`) resolves to a vbtable slot:
   the class COL → CHD → BCA → BCD chain gives `pdisp/vdisp`; the vbtable
   identity follows from the constructor store at `this+pdisp` (or from the
   `??_8<Class>@@7B<Sub>@` name grammar). The formula
   `base = obj + pdisp + vbtable[vdisp/4]` (§3) lets the plugin annotate
   each vbtable entry with "N-th virtual base of <TD name>, BCD @…" —
   symmetric to what it already does for `??_R1` names, whose mangling
   already encodes `pdisp`/`vdisp` (§3.3).
4. **Structure recovery**: `entry[0]` yields the owning subobject's vbptr
   placement; combined with COL offsets, the full multi-inheritance object
   skeleton (vfptrs, vbptrs, base subobjects — §4 layout diagrams) can be
   emitted as IDA struct types for virtual-inheritance classes.
5. **Don't parse the trailing bytes as entries**: in both binaries the
   dword(s) after the last entry are padding and then the *next vftable's
   COL pointer* — an over-long vbtable would swallow a valid VA
   (e.g. `0x400A7ED0` after `??_8CDiamond@@7BCVRight@@@`) and corrupt both
   objects.

---

## 8. Open questions / UNVERIFIED

* **`mdisp != 0` for a virtual base**: every VBOFCONTOBJ BCD in the corpus
  has `mdisp = 0`, so the placement of `mdisp` in the formula
  (`base = obj + mdisp + entry` vs `base = obj + entry` with the vbptr at
  `obj + mdisp + pdisp`) could not be distinguished empirically. UNVERIFIED.
* Whether `entry[0]` can be `0` (vbptr as first member) or positive in
  other layouts: no sample (all twelve are `-4`/`-8`). The
  subobject-displacement interpretation predicts it can be `0`; UNVERIFIED.
* vbtables with more than one virtual base (entry indices ≥ 2, `vdisp ≥ 8`):
  no corpus class has two virtual bases, so multi-entry vbtables are
  UNVERIFIED; the `vdisp`-as-byte-offset semantics is expected to generalize
  but was only observed at `vdisp = 4`.
* Whether a virtual-base-only class introducing no new virtuals still gets
  a `6B0@` self vftable (§5.2). UNVERIFIED.
* IDA's on-screen (demangled) rendering of `??_8` names (§7.1). UNVERIFIED.

## 9. Evidence artifact index

| Artifact | Contents |
|---|---|
| `RE/test/rtti_corpus_x64.map` / `x86.map` | symbol ground truth (lines 2983–2998 / 2986–3001 for `??_8`) |
| `RE/data/rtti_x64.json` / `rtti_x86.json` | COL/CHD/BCA/BCD/TD dumps incl. PMDs |
| `RE/test/RE_dumpbin_x64.txt` | `dumpbin /disasm rtti_corpus.obj` (x64, symbolized) |
| `RE/test/RE_dumpbin_x86.txt` | `dumpbin /disasm rtti_corpus_x86.exe` (ctors @ `0x407BA0`, `0x407CC0`, `0x407E10`, `0x407E50`) |
| `RE/data/ida_names_x64.txt` / `ida_names_x86.txt` | idasql (IDA 9.4) `??_7`/`??_8` name capture |
