# Methodology — How the MSVC RTTI facts in this folder were derived

Goal: replace folklore about MSVC RTTI with measurements taken from binaries
produced by a current compiler on this machine, then feed the verified facts
back into the ClassInformer plugin.

## 0. Environment

| Component | Version / path |
|---|---|
| Compiler | Visual Studio 2026 Community, MSVC 14.51.36231 (`cl.exe`, `/O2 /EHsc /Zi /GR`) |
| Ground-truth decoder | `undname.exe` shipped with that MSVC (`VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/`) |
| Compiler's own RTTI header | `VC/Tools/MSVC/14.51.36231/include/rttidata.h` (primary source for flags/names) |
| Disassembler / cross-check | IDA Professional 9.4 + `idasql.exe` (SQL surface over idalib databases) |
| Plugin build | same repo, `Release|x64`, VS2026 toolset `v145` override, IDA SDK 9.4 + Qt 6.8.2 (`D:\Sources\_idadeps`), `IDA_Support` at `D:\Sources\IDA_Support` |

## 1. Corpus design (`RE/test/rtti_corpus.cpp`)

Every RTTI shape the plugin must understand, each class exercised at runtime
(`typeid` + `dynamic_cast` so nothing is optimized away or left unreferenced):

1. SI chains (depth 1–5), `class` and `struct` variants (`.?AV` vs `.?AU`)
2. MI with 2 and 3 bases → secondary vftables with COL `offset` 4/8/16
3. MI with padded first base → `mdisp` 132/136 (multi-letter hex mangling)
4. Virtual-inheritance diamond → vbtables, `pdisp ≥ 0`, `vdisp = 4`
5. Mixed MI+VI (3 bases + virtual base) → CHD attrs 3
6. Ambiguous non-virtual base → CHD attrs 5, BCD attrs 0x42
7. Private/protected inheritance → BCD attrs 0x4D (flags 0x01|0x04|0x08|0x40)
8. Interface + `final` implementer, abstract classes
9. Namespace, nested class, template instantiation (`Tmpl<int,10>`, `Tmpl<double,32>`)
10. Long class name (~64 chars), >10-method vftables
11. Non-class `type_info` objects (`int`, `double`, `char*`, enums, fn-ptr, array)

Built x86 + x64 with `/Zi` **and `/MAP`** — the linker map is the
ground-truth symbol table (it contains the private RTTI symbols with their
final VAs, which a stripped binary does not).

## 2. Ground truth chain (three independent sources per claim)

1. **Linker map** — decorated names (`??_R0..4`, `??_7`, `??_8`) + absolute VAs.
   Parser: `parse_map()` in `RE/tools/rtti_scan.py` (handles both the
   "Publics by Value" and "Static symbols" map sections; the latter carries
   the VA column and lowercase hex offsets).
2. **Microsoft `undname.exe`** — authoritative decoding of the four numbers
   inside `??_R1` names ("`RTTI Base Class Descriptor at (mdisp,pdisp,vdisp,attributes)`").
   This is how the number-mangling alphabet (§7.1 of the layout doc) was
   established, including the MSB-first nibble order.
3. **Byte-level scan** — `RE/tools/rtti_scan.py` walks the PE independently
   (vftable → COL → TD/CHD → BCA → BCDs), validates every pointer/offset,
   regenerates every `??_R1` name from parsed bytes, and diffs against the
   map. It also verifies REV1 offset resolution (`COL - pSelf = image base`)
   and that BCD `+0x18` resolves to a real CHD.

A fact is accepted only when scan ↔ map ↔ undname agree. Where the compiler
header (`rttidata.h`) is cited, the binary measurement was checked for
consistency as well (e.g. the 0x4D private-base encoding confirms the
0x04/0x08 naming).

## 3. IDA cross-verification (idasql)

```text
idasql -s RE/test/rtti_corpus_x64.exe -q "SELECT COUNT(*) FROM names WHERE name LIKE '??_R4%'"
```

Raw binaries are auto-analyzed by idalib; no pre-built IDB needed. Queries
used (see transcript summary in the layout doc §8):

* per-prefix name counts (`??_R4`, `??_7`, `??_R1`, `??_R3`, `??_R2`, `??_R0`, `??_8`)
* `applied_types` at COL/BCD addresses (→ IDA names but does not type them)
* `types WHERE name LIKE '%RTTI%'` (→ the dual source-level/binary-accurate til entries)
* `disasm_range()` around a BCD (→ which fields IDA leaves untyped)

Result: IDA 9.4's own RTTI pass finds exactly the same object set as the
independent byte-scan, which quantifies the plugin's remaining value-add
(naming/typing objects IDA missed + the browsable class list).

## 4. Fixing and validating the plugin

1. Every suspected defect was first **reproduced as data**: e.g. the old
   `mangleNumber()` output for 64 (`"AE@"`) vs the map's `EA@`.
2. Fixes applied to `RTTI.cpp` / `RTTI.h` / `Main.cpp` (list in
   [Plugin-Findings-and-Fixes.md](Plugin-Findings-and-Fixes.md)).
3. Compile gate: full `Release|x64` plugin build with the VS2026 `v145`
   toolset — must finish 0 warnings / 0 errors.
4. Logic gate: the Python scanner implements the same algorithms (name
   regeneration, REV1 math, validation predicates) and passes 64/64 against
   ground truth on both architectures.

## 5. Reproduction steps

```text
cd RE/test && build.cmd                 # x86 + x64 exe/map/pdb (VS2026)
python ../tools/rtti_scan.py rtti_corpus_x64.exe --map rtti_corpus_x64.map --json ../data/rtti_x64.json
python ../tools/rtti_scan.py rtti_corpus_x86.exe --map rtti_corpus_x86.map --json ../data/rtti_x86.json
undname.exe <map symbols>               # decode any ??_R1 name
"C:\Program Files\IDA Professional 9.4\idasql.exe" -s rtti_corpus_x64.exe -q "…"
```

The scanner is deliberately dependency-free (pure-stdlib Python) so it can run
anywhere and diff any MSVC PE against its map.
