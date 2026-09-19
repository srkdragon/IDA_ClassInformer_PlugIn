# RE — Reverse Engineering Notes (MSVC RTTI)

Evidence-based documentation of the MSVC RTTI binary format as emitted by
**Visual Studio 2026 (MSVC 14.51)**, produced to verify and improve the
ClassInformer plugin. Everything here is derived from freshly compiled x86 and
x64 binaries on this machine and cross-checked against three independent
sources (linker maps, Microsoft's `undname.exe`, IDA Pro 9.4 via `idasql`).

## Reading order

| Document | Contents |
|---|---|
| [MSVC-RTTI-Layout.md](MSVC-RTTI-Layout.md) | The reference: structure layouts, sizes, signatures, flags, name formats, number mangling — with corrections to prior art |
| [Methodology.md](Methodology.md) | How every fact was derived and how to reproduce the whole pipeline |
| [Plugin-Findings-and-Fixes.md](Plugin-Findings-and-Fixes.md) | Defects found in the plugin, the evidence, the applied fixes, and what was verified correct |
| [VBTables-and-Virtual-Inheritance.md](VBTables-and-Virtual-Inheritance.md) | Deep-dive: `??_8` vbtables, PMD resolution formula, virtual-base vftables |
| [IDB-Annotation-Pass.md](IDB-Annotation-Pass.md) | Applying the findings to the corpus IDBs (types, vbtable rescue, comments) + idasql operational notes |

## Directory map

```
RE/
├── test/               RTTI corpus source + VS2026 builds
│   ├── rtti_corpus.cpp   (classes covering every RTTI shape)
│   ├── build.cmd         (x86 + x64, /O2 /Zi /GR /MAP)
│   ├── rtti_corpus_x86.exe/.map/.pdb
│   └── rtti_corpus_x64.exe/.map/.pdb
├── tools/
│   └── rtti_scan.py    Dependency-free PE/RTTI scanner + map differ
│                       (validates COL/CHD/BCA/BCD/TD graphs, regenerates
│                       ??_R1 names, checks them against the linker map)
└── data/
    ├── rtti_x86.json   Full structural dump of the x86 corpus
    ├── rtti_x64.json   Full structural dump of the x64 corpus
    └── bcd_names_x64.txt
```

## Headline results

* All 128 RTTI graphs (64 classes × 2 architectures) parse, validate, and
  **name-regenerate exactly** (0 mismatches vs the linker).
* Two genuine plugin bugs fixed (reversed hex nibbles in `mangleNumber()`;
  swapped BCD flag constants 0x04/0x08), five smaller hardening/TODO fixes,
  and one new capability (`fixKnownVbtables()`: rescues `??_8` vbtables IDA
  leaves mis-disassembled as code) — see
  [Plugin-Findings-and-Fixes.md](Plugin-Findings-and-Fixes.md).
* IDA 9.4's built-in RTTI pass finds the identical object set (60/60 COLs on
  the pre-extension corpus), but names only — no struct types — leaving the
  plugin's struct placement and class list as its remaining value-add.
