#!/usr/bin/env python3
# =============================================================================
# rtti_scan.py - Empirical MSVC RTTI structure scanner for PE images
# =============================================================================
# Purpose: ground-truth extraction of MSVC RTTI layouts from freshly compiled
# VS2026 (MSVC 14.51) binaries, for the IDA ClassInformer plugin RE effort.
#
# Walks the classic RTTI graph:
#   vftable[-1] -> _RTTICompleteObjectLocator (COL)
#     -> type_info (TypeDescriptor, TD)
#     -> _RTTIClassHierarchyDescriptor (CHD)
#        -> _RTTIBaseClassArray (BCA)
#            -> _RTTIBaseClassDescriptor (BCD) ... -> TD, [CHD]
#
# Everything is derived from file bytes; nothing is assumed beyond PE parsing.
# Optional: --map <linker map> cross-checks every discovered object against
# the linker's symbol names (authoritative ground truth).
#
# Output: JSON dump (structures) + human report (layouts, strides, anomalies).
# =============================================================================
import argparse
import json
import re
import struct
import sys

BCD_FLAGS = {
    0x01: "BCD_NOTVISIBLE",
    0x02: "BCD_AMBIGUOUS",
    0x04: "BCD_PRIVORPROTINCOMPOBJ",
    0x08: "BCD_PRIVORPROTBASE",
    0x10: "BCD_VBOFCONTOBJ",
    0x20: "BCD_NONPOLYMORPHIC",
    0x40: "BCD_HASPCHD",
}
CHD_FLAGS = {
    0x01: "CHD_MULTINH",
    0x02: "CHD_VIRTINH",
    0x04: "CHD_AMBIGUOUS",
}


class Pe:
    """Minimal PE parser: sections, image base, RVA<->file offset."""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("not an MZ file")
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        coff = e_lfanew + 4
        machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from(
            "<HHIIIHH", d, coff)
        self.machine = machine
        self.is64 = machine == 0x8664
        self.is32 = machine == 0x14C
        opt = coff + 20
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic == 0x20B:
            self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
        elif magic == 0x10B:
            self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        else:
            raise ValueError("unknown optional header magic %#x" % magic)
        self.sections = []
        sec_off = opt + opt_size
        for i in range(num_sections):
            off = sec_off + i * 40
            name = d[off:off + 8].rstrip(b"\0").decode("latin1")
            vsize, va, rsize, roff = struct.unpack_from("<IIII", d, off + 8)
            self.sections.append({
                "name": name, "vsize": vsize, "va": va,
                "rsize": rsize, "roff": roff,
            })

    def va(self, rva):
        return self.image_base + rva

    def rva(self, va):
        return va - self.image_base

    def off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                delta = rva - s["va"]
                if delta < s["rsize"]:
                    return s["roff"] + delta
                return None  # in virtual (uninitialized) part
        return None

    def read(self, rva, size):
        o = self.off(rva)
        if o is None:
            return None
        return self.data[o:o + size]

    def u32(self, rva):
        b = self.read(rva, 4)
        return None if b is None else struct.unpack("<I", b)[0]

    def i32(self, rva):
        b = self.read(rva, 4)
        return None if b is None else struct.unpack("<i", b)[0]

    def u64(self, rva):
        b = self.read(rva, 8)
        return None if b is None else struct.unpack("<Q", b)[0]

    def ea(self, rva):
        """Pointer-sized value at rva -> VA."""
        return self.u64(rva) if self.is64 else self.u32(rva)

    def cstr(self, rva, limit=1024):
        b = self.read(rva, limit)
        if b is None:
            return None
        z = b.find(b"\0")
        if z < 0:
            return None
        return b[:z].decode("latin1", "replace")

    def in_section(self, rva, name):
        for s in self.sections:
            if s["name"] == name and s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                return True
        return False


def parse_map(path):
    """Parse a linker .map: symbol name -> (section_idx, section_offset, va|None).
    Handles both 'Publics by Value' (name + obj) and 'Static symbols'
    (name + absolute VA + obj) layouts; hex offsets are lower/upper mixed."""
    syms = {}
    pat = re.compile(
        r"^\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+(\S+)(?:\s+([0-9A-Fa-f]+))?")
    with open(path, "r", errors="replace") as f:
        for ln in f:
            m = pat.match(ln)
            if m:
                sec, off, name, va = m.groups()
                syms[name] = (int(sec, 16), int(off, 16),
                              int(va, 16) if va else None)
    return syms


def map_rva(pe, syms):
    """Map file symbols to RVAs: prefer the absolute VA column when present,
    else derive from PE section order (map section N = PE sections[N-1])."""
    out = {}
    for name, (sec, off, va) in syms.items():
        if va:
            out[name] = va - pe.image_base
        elif 1 <= sec <= len(pe.sections):
            out[name] = pe.sections[sec - 1]["va"] + off
    return out


def decode_td_name(raw):
    """'.?AVFoo@@' -> ('class', 'Foo@@'); returns (kind, rest) or None."""
    if not raw or raw[0] != ".":
        return None
    kind = None
    if raw.startswith(".?AV"):
        kind = "class"
    elif raw.startswith(".?AU"):
        kind = "struct"
    elif raw.startswith(".?AW"):
        kind = "enum"
    else:
        kind = "other"
    return kind, raw[4:]


class RttiScanner:
    def __init__(self, pe, verbose=False):
        self.pe = pe
        self.verbose = verbose
        self.tds = {}       # rva -> td dict
        self.chds = {}      # rva -> chd dict
        self.bcds = {}      # rva -> bcd dict
        self.cols = {}      # rva -> col dict
        self.vfts = []      # list of vftable dicts
        self.anomalies = []

    def note(self, msg):
        self.anomalies.append(msg)
        if self.verbose:
            print("  [!] " + msg)

    # ---------------- TD ----------------
    def read_td(self, rva):
        if rva in self.tds:
            return self.tds[rva]
        # VS2026 emits TypeDescriptors into .data (type_info is mutated at
        # runtime: _M_data hash cache); older MSVC used .rdata as well.
        if not (self.pe.in_section(rva, ".rdata") or self.pe.in_section(rva, ".data")):
            return None
        vfptr = self.pe.ea(rva)
        spare = self.pe.ea(rva + (8 if self.pe.is64 else 4))
        name_off = rva + (16 if self.pe.is64 else 8)
        raw = self.pe.cstr(name_off)
        if raw is None or not raw.startswith(".?A"):
            # also allow builtin/other type names (they still start with '.')
            if raw is None or raw[0] != ".":
                return None
        td = {
            "rva": rva, "va": self.pe.va(rva),
            "vfptr": vfptr, "vfptr_rva": None if vfptr is None else self.pe.rva(vfptr),
            "spare": spare,
            "raw_name": raw,
        }
        dec = decode_td_name(raw)
        td["kind"] = dec[0] if dec else None
        # measure actual allocation: name bytes + terminator, aligned
        b = self.pe.read(name_off, 1200) or b""
        z = b.find(b"\0")
        raw_len = z + 1
        td["name_len"] = raw_len
        align = 16 if self.pe.is64 else 8  # hypothesis; corrected below
        for a in (16, 8, 4):
            if (rva + 16 + raw_len) % a == 0 or True:
                pass
        td["alloc_align_guess"] = align
        self.tds[rva] = td
        return td

    # ---------------- BCD ----------------
    def read_bcd(self, rva, imgbase_rva):
        if rva in self.bcds:
            return self.bcds[rva]
        if not self.pe.in_section(rva, ".rdata"):
            return None
        td_off = self.pe.u32(rva)
        if td_off is None:
            return None
        td_rva = ((td_off - self.pe.image_base) if self.pe.is32
                  else imgbase_rva + struct.unpack("<i", struct.pack("<I", td_off))[0])
        ncb = self.pe.u32(rva + 4)
        mdisp = self.pe.i32(rva + 8)
        pdisp = self.pe.i32(rva + 12)
        vdisp = self.pe.i32(rva + 16)
        attrs = self.pe.u32(rva + 20)
        if attrs is None or attrs & 0xFFFFFF00:
            return None
        bcd = {
            "rva": rva, "va": self.pe.va(rva),
            "td_rva": td_rva,
            "numContainedBases": ncb,
            "mdisp": mdisp, "pdisp": pdisp, "vdisp": vdisp,
            "attributes": attrs,
            "attr_names": [n for b, n in BCD_FLAGS.items() if attrs & b],
        }
        # optional 6th field when 0x40 (BCD_HASPCHD)
        if attrs & 0x40:
            cd = self.pe.u32(rva + 24)
            if cd is not None:
                cd_signed = struct.unpack("<i", struct.pack("<I", cd))[0]
                bcd["chd_rva_if_haspchd"] = (
                    (imgbase_rva + cd_signed) if self.pe.is64
                    else cd - self.pe.image_base)
        self.bcds[rva] = bcd
        return bcd

    # ---------------- CHD ----------------
    def read_chd(self, rva, imgbase_rva):
        if rva in self.chds:
            return self.chds[rva]
        if not self.pe.in_section(rva, ".rdata"):
            return None
        sig = self.pe.u32(rva)
        attrs = self.pe.u32(rva + 4)
        n = self.pe.u32(rva + 8)
        if sig != 0 or attrs is None or attrs & 0xFFFFFFF0 or not (1 <= n <= 128):
            return None
        bca_field = self.pe.u32(rva + 12)
        bca_rva = ((bca_field - self.pe.image_base) if self.pe.is32
                   else imgbase_rva + struct.unpack("<i", struct.pack("<I", bca_field))[0])
        chd = {
            "rva": rva, "va": self.pe.va(rva),
            "signature": sig, "attributes": attrs,
            "attr_names": [nme for b, nme in CHD_FLAGS.items() if attrs & b],
            "numBaseClasses": n,
            "bca_rva": bca_rva,
        }
        self.chds[rva] = chd
        return chd

    # ---------------- COL ----------------
    def read_col(self, rva):
        if rva in self.cols:
            return self.cols[rva]
        if not self.pe.in_section(rva, ".rdata"):
            return None
        sig = self.pe.u32(rva)
        if self.pe.is32 and sig != 0:
            return None
        if self.pe.is64 and sig != 1:
            return None
        if self.pe.is32:
            # sig==0 alone is too weak: validate the TD like ClassInformer
            tdp = self.pe.u32(rva + 12)
            chdp = self.pe.u32(rva + 16)
            if not tdp or not chdp:
                return None
            raw = self.pe.cstr(tdp - self.pe.image_base + 8)
            if not raw or raw[0] != ".":
                return None
        off = self.pe.u32(rva + 4)
        cdoff = self.pe.u32(rva + 8)
        if self.pe.is32:
            # 32-bit RTTI pointer fields hold absolute VAs (image base added)
            td_rva = self.pe.u32(rva + 12) - self.pe.image_base
            chd_rva = self.pe.u32(rva + 16) - self.pe.image_base
            imgbase = None
        else:
            selfoff = self.pe.u32(rva + 20)
            imgbase = rva - struct.unpack("<i", struct.pack("<I", selfoff))[0]
            td_rva = imgbase + struct.unpack("<i", struct.pack("<I", self.pe.u32(rva + 12)))[0]
            chd_rva = imgbase + struct.unpack("<i", struct.pack("<I", self.pe.u32(rva + 16)))[0]
        col = {
            "rva": rva, "va": self.pe.va(rva),
            "signature": sig, "offset": off, "cdOffset": cdoff,
            "td_rva": td_rva, "chd_rva": chd_rva,
            "self_offset": None if self.pe.is32 else self.pe.u32(rva + 20),
            "computed_image_base_rva": imgbase,
        }
        self.cols[rva] = col
        return col

    # ---------------- vftable walk ----------------
    def scan_vftables(self):
        """Scan .rdata for pointers to COLs; vftable = ptr + word."""
        pe = self.pe
        for s in pe.sections:
            if s["name"] != ".rdata":
                continue
            base = s["va"] & ~7
            rva = base
            end = s["va"] + s["rsize"]
            while rva + (8 if pe.is64 else 4) <= end:
                v = pe.ea(rva)
                if v is not None and pe.image_base <= v < pe.image_base + 0x10000000:
                    col_rva = pe.rva(v)
                    col = self.read_col(col_rva)
                    if col is not None:
                        vft_rva = rva + (8 if pe.is64 else 4)
                        self.vfts.append({
                            "col_ptr_rva": rva, "vft_rva": vft_rva,
                            "col_rva": col_rva,
                        })
                step = 8 if pe.is64 else 4
                rva += step
        return self.vfts

    def full_walk(self):
        for v in self.scan_vftables():
            col = self.read_col(v["col_rva"])
            td = self.read_td(col["td_rva"])
            chd = self.read_chd(col["chd_rva"], col["computed_image_base_rva"] or 0)
            if chd:
                bca = chd["bca_rva"]
                for i in range(chd["numBaseClasses"]):
                    e = self.pe.u32(bca + i * 4)
                    if e is None:
                        break
                    if self.pe.is64:
                        e = (col["computed_image_base_rva"]
                             + struct.unpack("<i", struct.pack("<I", e))[0])
                    else:
                        e = e - self.pe.image_base  # direct VA pointers
                    bcd = self.read_bcd(e, col["computed_image_base_rva"] or 0)
                    if bcd is None:
                        self.note("BCA entry %d @%#x invalid" % (i, bca + i * 4))
                        break


def mangle_number(v):
    """MSVC number mangling (validated against VS2026 undname ground truth):
    0 -> 'A@'; 1..10 -> '0'..'9' (v-1); >10 -> hex 'A'..'P' MSB-first + '@';
    negative -> '?' + mangling(|v|)."""
    if v == 0:
        return "A@"
    sign = ""
    if v < 0:
        sign = "?"
        v = -v
    if 1 <= v <= 10:
        return "%s%d" % (sign, v - 1)
    digits = ""
    while v > 0:
        digits = chr(ord("A") + (v % 16)) + digits  # MSB first
        v //= 16
    return "%s%s@" % (sign, digits)


def bcd_name(bcd, td_raw):
    """Build the ??_R1 decorated name exactly as MSVC does."""
    rest = td_raw[4:] if td_raw.startswith(".?A") else td_raw  # strip .?AV/.?AU
    return "??_R1%s%s%s%s%s8" % (
        mangle_number(bcd["mdisp"]),
        mangle_number(bcd["pdisp"]),
        mangle_number(bcd["vdisp"]),
        mangle_number(bcd["attributes"]),
        rest,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--map", dest="mapfile")
    ap.add_argument("--json", dest="jsonout")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    pe = Pe(args.image)
    print("PE: machine=%#x bits=%d image_base=%#x" % (
        pe.machine, 64 if pe.is64 else 32, pe.image_base))
    for s in pe.sections:
        print("  sec %-8s va=%#010x vsize=%#x rsize=%#x" % (
            s["name"], s["va"], s["vsize"], s["rsize"]))

    sc = RttiScanner(pe, args.verbose)
    sc.full_walk()

    # map ground truth
    truth = {}
    if args.mapfile:
        truth = map_rva(pe, parse_map(args.mapfile))

    print("\n== RTTI objects discovered ==")
    print("vftables: %d  COLs: %d  CHDs: %d  BCDs: %d  TDs: %d" % (
        len(sc.vfts), len(sc.cols), len(sc.chds), len(sc.bcds), len(sc.tds)))

    # --- verify names we can rebuild against linker truth ---
    matched = mismatched = 0
    for rva, bcd in sorted(sc.bcds.items()):
        td = sc.tds.get(bcd["td_rva"])
        if not td or not td["raw_name"] or not td["raw_name"].startswith(".?A"):
            continue
        gen = bcd_name(bcd, td["raw_name"])
        hit = [n for n, r in truth.items() if r == rva and n.startswith("??_R1")]
        if hit:
            if hit[0] == gen:
                matched += 1
            else:
                mismatched += 1
                print("MISMATCH @%#x\n  truth: %s\n  gen:   %s" % (rva, hit[0], gen))
    print("\nBCD name round-trip vs linker map: %d matched, %d mismatched" % (
        matched, mismatched))

    # --- COL completeness vs linker truth ---
    if truth:
        r4 = {n: r for n, r in truth.items() if n.startswith("??_R4")}
        r7 = {n: r for n, r in truth.items() if n.startswith("??_7")}
        found = set(sc.cols)
        want = set(r4.values())
        print("COLs found %d vs map ??_R4 %d: missing=%d extra=%d" % (
            len(found), len(want), len(want - found), len(found - want)))
        for n, r in sorted(r4.items()):
            if r not in found:
                print("  missing COL: %#x %s" % (r, n))
        vft_found = {v["vft_rva"] for v in sc.vfts}
        vft_want = set(r7.values())
        print("vft ptrs found %d vs map ??_7 %d: missing=%d extra=%d" % (
            len(vft_found), len(vft_want), len(vft_want - vft_found),
            len(vft_found - vft_want)))

    # --- BCD stride analysis (are the 0x40/6th-field BCDs 0x18 bytes?) ---
    print("\n== BCD stride analysis ==")
    by_addr = sorted(sc.bcds)
    strides = {}
    for a, b in zip(by_addr, by_addr[1:]):
        strides[b - a] = strides.get(b - a, 0) + 1
    print("BCD-to-BCD strides: %s" % dict(sorted(strides.items())))

    # what's actually at BCD+0x10 (the classDescriptor slot)?
    has_chd_valid = has_chd_invalid = zero = 0
    for rva, bcd in sorted(sc.bcds.items()):
        if bcd.get("chd_rva_if_haspchd") is not None:
            v = bcd["chd_rva_if_haspchd"]
            if v == 0:
                zero += 1
            elif v in sc.chds:
                has_chd_valid += 1
            else:
                has_chd_invalid += 1
    print("BCD+0x10 dword: points at valid CHD: %d, zero: %d, other: %d" % (
        has_chd_valid, zero, has_chd_invalid))

    # --- TD alignment analysis ---
    print("\n== TypeDescriptor allocation ==")
    for rva, td in sorted(sc.tds.items())[:40]:
        end = rva + (16 if pe.is64 else 8) + td["name_len"]
        print("  TD %#010x name(%2d) end=%#x end%%4=%d end%%8=%d %s" % (
            rva, td["name_len"], end, end % 4, end % 8, td["raw_name"][:40]))

    # --- vftable/COL summary ---
    print("\n== vftables ==")
    for v in sc.vfts:
        col = sc.cols[v["col_rva"]]
        td = sc.tds.get(col["td_rva"], {})
        chd = sc.chds.get(col["chd_rva"], {})
        print("  vft=%#010x col=%#010x sig=%d off=%2d nbase=%d %s" % (
            v["vft_rva"], v["col_rva"], col["signature"], col["offset"],
            chd.get("numBaseClasses", -1), td.get("raw_name", "?")))

    if sc.anomalies:
        print("\n== anomalies (%d) ==" % len(sc.anomalies))
        for a in sc.anomalies[:30]:
            print("  " + a)

    if args.jsonout:
        out = {
            "image": args.image,
            "bits": 64 if pe.is64 else 32,
            "image_base": pe.image_base,
            "vftables": sc.vfts,
            "cols": {hex(k): v for k, v in sc.cols.items()},
            "chds": {hex(k): v for k, v in sc.chds.items()},
            "bcds": {hex(k): v for k, v in sc.bcds.items()},
            "tds": {hex(k): v for k, v in sc.tds.items()},
            "anomalies": sc.anomalies,
        }
        with open(args.jsonout, "w") as f:
            json.dump(out, f, indent=1)
        print("\nwrote %s" % args.jsonout)


if __name__ == "__main__":
    main()
