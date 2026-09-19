// =============================================================================
// MSVC RTTI test corpus for ClassInformer reverse engineering
// =============================================================================
// Purpose: exercise every MSVC RTTI structural shape and name-mangling edge
// case that the IDA ClassInformer plugin has to parse:
//
//   - Single inheritance chains (SI), depth 1..5
//   - Multiple inheritance (MI) with 2 and 3 bases, primary + secondary
//     vftables (COL offset != 0)
//   - Virtual inheritance (VI) diamond (vbtables, pdisp >= 0, vdisp 0..N)
//   - Mixed MI + VI
//   - Ambiguous non-virtual base (CHD_AMBIGUOUS)
//   - Base displacements (mdisp) spanning 0..10, 11..0xF, 0x10+ (number
//     mangling: "A@", digits, multi-letter hex)
//   - class vs struct (.?AV / .?AU), namespaces, nested classes, templates
//   - Pure-virtual interfaces, abstract classes, big vftables (>10 methods)
//   - Non-class type_info objects (built-ins, enums, pointers)
//
// Build (VS2026, MSVC 14.51):
//   x86: cl /nologo /O2 /EHsc /Zi /W4 rtti_corpus.cpp /Fe:rtti_corpus_x86.exe
//   x64: cl /nologo /O2 /EHsc /Zi /W4 rtti_corpus.cpp /Fe:rtti_corpus_x64.exe
// =============================================================================

#include <cstdio>
#include <typeinfo>

// -----------------------------------------------------------------------------
// 1. Single inheritance chain, depth 3 (SI)
// -----------------------------------------------------------------------------
class CSI_Base {
public:
    virtual ~CSI_Base() = default;
    virtual const char* name() const { return "CSI_Base"; }
};

class CSI_Mid : public CSI_Base {
public:
    const char* name() const override { return "CSI_Mid"; }
    virtual int midOnly() const { return 1; }
};

class CSI_Leaf : public CSI_Mid {
public:
    const char* name() const override { return "CSI_Leaf"; }
    int midOnly() const override { return 2; }
};

// -----------------------------------------------------------------------------
// 2. struct SI (".?AU" type descriptor prefix)
// -----------------------------------------------------------------------------
struct SSPolyBase {
    virtual ~SSPolyBase() = default;
    virtual int sb() const { return 10; }
};

struct SSPolyMid : SSPolyBase {
    int sb() const override { return 11; }
    virtual int sm() const { return 12; }
};

// -----------------------------------------------------------------------------
// 3. Plain polymorphic class, no bases
// -----------------------------------------------------------------------------
class CPlain {
public:
    virtual ~CPlain() = default;
    virtual void m0() {}
    virtual void m1() {}
    virtual void m2() {}
    virtual void m3() {}
    virtual void m4() {}
    virtual void m5() {}
    virtual void m6() {}
    virtual void m7() {}
    virtual void m8() {}
    virtual void m9() {}
    virtual void m10() {}
    virtual void m11() {}   // >10 methods in vftable
};

// -----------------------------------------------------------------------------
// 4. Independent polymorphic bases for MI tests
// -----------------------------------------------------------------------------
class CMI_A {
public:
    virtual ~CMI_A() = default;
    virtual int a() const { return 0xAAAA; }
};

class CMI_B {
public:
    virtual ~CMI_B() = default;
    virtual int b() const { return 0xBBBB; }
};

class CMI_C {
public:
    virtual ~CMI_C() = default;
    virtual int c() const { return 0xCCCC; }
};

// 4a. MI with two bases: secondary vftable at mdisp != 0
class CMI_Two : public CMI_A, public CMI_B {
public:
    int a() const override { return 1; }
    int b() const override { return 2; }
    virtual int both() const { return 3; }
};

// 4b. MI with three bases
class CMI_Three : public CMI_A, public CMI_B, public CMI_C {
public:
    int a() const override { return 1; }
    int b() const override { return 2; }
    int c() const override { return 3; }
};

// -----------------------------------------------------------------------------
// 5. MI with large secondary-base displacement.
//    First base padded so the second base lands well past 0x10 (tests the
//    multi-letter hex branch of the number mangler: mdisp >= 0x11).
// -----------------------------------------------------------------------------
class bigpad_t {   // non-polymorphic padding object
public:
    unsigned char pad[0x40];
};

class CPad_A {
public:
    virtual ~CPad_A() = default;
    virtual int pa() const { return 1; }
    bigpad_t pad1, pad2;   // 0x80 bytes pushes next base past 0x80
};

class CPad_B {
public:
    virtual ~CPad_B() = default;
    virtual int pb() const { return 2; }
};

class CMI_BigOffset : public CPad_A, public CPad_B {
public:
    int pa() const override { return 11; }
    int pb() const override { return 22; }
};

// -----------------------------------------------------------------------------
// 6. Virtual inheritance diamond (VI):
//    CVBase <- (virtual) CVLeft, (virtual) CVRight; CDiamond : CVLeft, CVRight
//    Produces vbtables and BCDs with pdisp != -1 and vdisp 0..1
// -----------------------------------------------------------------------------
class CVBase {
public:
    virtual ~CVBase() = default;
    virtual int v() const { return 0x56; }
    virtual int v2() const { return 0x57; }
};

class CVLeft : public virtual CVBase {
public:
    int v() const override { return 1; }
    virtual int l() const { return 2; }
};

class CVRight : public virtual CVBase {
public:
    int v2() const override { return 3; }
    virtual int r() const { return 4; }
};

class CDiamond : public CVLeft, public CVRight {
public:
    int v() const override { return 5; }
    int v2() const override { return 6; }
};

// -----------------------------------------------------------------------------
// 7. Mixed MI + VI with an extra plain base
// -----------------------------------------------------------------------------
class CMix_Plain {
public:
    virtual ~CMix_Plain() = default;
    virtual int mp() const { return 7; }
};

class CMixFinal : public CMix_Plain, public CVLeft, public CVRight {
public:
    int mp() const override { return 70; }
    int v() const override { return 71; }
    int v2() const override { return 72; }
};

// -----------------------------------------------------------------------------
// 8. Ambiguous non-virtual base -> CHD_AMBIGUOUS (attributes & 0x04)
// -----------------------------------------------------------------------------
class CAmb_Root {
public:
    virtual ~CAmb_Root() = default;
    virtual int root() const { return 0; }
};

class CAmb_L : public CAmb_Root {
public:
    int root() const override { return 1; }
};

class CAmb_R : public CAmb_Root {
public:
    int root() const override { return 2; }
};

class CAmbiguous : public CAmb_L, public CAmb_R {
    // CAmb_Root appears twice, non-virtually => ambiguous base
};

// -----------------------------------------------------------------------------
// 9. Pure virtual interface + implementer (abstract class TD/`vftable')
// -----------------------------------------------------------------------------
class IInterface {
public:
    virtual ~IInterface() = default;
    virtual int  queryInterface() const = 0;
    virtual void addRef() const = 0;
    virtual void release() const = 0;
};

class CImpl final : public IInterface {
public:
    int  queryInterface() const override { return 42; }
    void addRef() const override {}
    void release() const override {}
};

// -----------------------------------------------------------------------------
// 10. Namespace + nested class (name mangling stress)
// -----------------------------------------------------------------------------
namespace deep { namespace inner {
    class CNamespaced {
    public:
        virtual ~CNamespaced() = default;
        virtual int ns() const { return 1; }
    };

    class CNestedOuter {
    public:
        class CNestedInner {
        public:
            virtual ~CNestedInner() = default;
            virtual int in() const { return 2; }
        };
        virtual ~CNestedOuter() = default;
        virtual int out() const { return 3; }
    };
}}

// -----------------------------------------------------------------------------
// 11. Template instantiation (mangled name with embedded numbers)
// -----------------------------------------------------------------------------
template <typename T, int N>
class Tmpl {
public:
    virtual ~Tmpl() = default;
    virtual T value() const { return static_cast<T>(N); }
    virtual int count() const { return N; }
};

template class Tmpl<int, 10>;    // explicit instantiation -> RTTI objects
template class Tmpl<double, 0x20>;

using TmplI10 = Tmpl<int, 10>;
using TmplD32 = Tmpl<double, 0x20>;

// -----------------------------------------------------------------------------
// 12. Deep SI chain, depth 5 (long base class array, BCD ordering)
// -----------------------------------------------------------------------------
class CD1 { public: virtual ~CD1() = default; virtual int d1() { return 1; } };
class CD2 : public CD1 { int d1() override { return 2; } };
class CD3 : public CD2 { public: virtual int d3() { return 3; } };
class CD4 : public CD3 { public: virtual int d4() { return 4; } };
class CD5 : public CD4 { public: virtual int d5() { return 5; } };

// -----------------------------------------------------------------------------
// 13. Long-ish class name (readability limit testing, ~64 chars)
// -----------------------------------------------------------------------------
class CThisIsAVeryLongClassNameToTestTheNameBufferHandlingInClassInformer {
public:
    virtual ~CThisIsAVeryLongClassNameToTestTheNameBufferHandlingInClassInformer() = default;
    virtual int ln() const { return 0; }
};

// -----------------------------------------------------------------------------
// 14. Private / protected inheritance (BCD attribute bits 0x04 / 0x08)
// -----------------------------------------------------------------------------
class CAccess_Base {
public:
    virtual ~CAccess_Base() = default;
    virtual int ab() const { return 1; }
};

class CPriv_Direct : private CAccess_Base {          // base private in direct class
public:
    virtual int pd() const { return 2; }
};

class CProt_Direct : protected CAccess_Base {        // base protected in direct class
public:
    virtual int pt() const { return 3; }
};

// private base two levels down: private in the direct deriver (0x08) AND
// non-visible/private in the complete object chain for further derivations
class CPriv_Leaf : public CPriv_Direct {
public:
    int pd() const override { return 4; }
    virtual int pl() const { return 5; }
};

// -----------------------------------------------------------------------------
// 15. Non-class type_info objects (created via typeid on non-class types)
// -----------------------------------------------------------------------------
enum class ECorpusEnum { kOne, kTwo };
enum EPlainEnum { kPlainA, kPlainB };

typedef int (*fnptr_t)(int);
struct SNonPoly { int x; };   // non-polymorphic: typeid uses static TD only

// -----------------------------------------------------------------------------
// Force emission + linking of everything; print ground truth from runtime
// -----------------------------------------------------------------------------
static void report(const char* tag, const std::type_info& ti, const void* vf)
{
    std::printf("%-12s %-60s vf=%p\n", tag, ti.name(), vf);
}

int main()
{
    CSI_Leaf           siLeaf;
    SSPolyMid          sPoly;
    CPlain             plain;
    CMI_Two            miTwo;
    CMI_Three          miThree;
    CMI_BigOffset      miBig;
    CDiamond           diamond;
    CMixFinal          mix;
    CAmbiguous         amb;
    CImpl              impl;
    CPriv_Direct       privD;
    CProt_Direct       protD;
    CPriv_Leaf         privL;
    deep::inner::CNamespaced ns;
    deep::inner::CNestedOuter::CNestedInner nested;
    TmplI10            t10;
    TmplD32            t32;
    CD5                d5;
    CThisIsAVeryLongClassNameToTestTheNameBufferHandlingInClassInformer longName;

    // dynamic_cast forces RTTI COL usage (and __dynamic_cast import)
    CSI_Base* up = &siLeaf;
    if (CSI_Leaf* down = dynamic_cast<CSI_Leaf*>(up))
        report("SI-dyncast", typeid(*down), *reinterpret_cast<void**>(down));

    report("SI",       typeid(siLeaf),    *reinterpret_cast<void**>(&siLeaf));
    report("SI-mid",   typeid(CSI_Mid),   nullptr);
    report("struct-SI",typeid(sPoly),     *reinterpret_cast<void**>(&sPoly));
    report("plain",    typeid(plain),     *reinterpret_cast<void**>(&plain));
    report("MI-2",     typeid(miTwo),     *reinterpret_cast<void**>(&miTwo));
    report("MI-3",     typeid(miThree),   *reinterpret_cast<void**>(&miThree));
    report("MI-big",   typeid(miBig),     *reinterpret_cast<void**>(&miBig));
    report("VI-diam",  typeid(diamond),   *reinterpret_cast<void**>(&diamond));
    report("MI-VI",    typeid(mix),       *reinterpret_cast<void**>(&mix));
    report("ambig",    typeid(amb),       *reinterpret_cast<void**>(&amb));
    report("iface",    typeid(impl),      *reinterpret_cast<void**>(&impl));
    report("priv-direct", typeid(privD),  *reinterpret_cast<void**>(&privD));
    report("prot-direct", typeid(protD),  *reinterpret_cast<void**>(&protD));
    report("priv-leaf",   typeid(privL),  *reinterpret_cast<void**>(&privL));
    report("ns",       typeid(ns),        *reinterpret_cast<void**>(&ns));
    report("nested",   typeid(nested),    *reinterpret_cast<void**>(&nested));
    report("tmpl",     typeid(t10),       *reinterpret_cast<void**>(&t10));
    report("tmpl2",    typeid(t32),       *reinterpret_cast<void**>(&t32));
    report("deep5",    typeid(d5),        *reinterpret_cast<void**>(&d5));
    report("longname", typeid(longName),  *reinterpret_cast<void**>(&longName));

    // Non-class type_info objects (plain TDs, no COL/vftable)
    report("int",      typeid(int),        nullptr);
    report("double",   typeid(double),     nullptr);
    report("charptr",  typeid(char*),      nullptr);
    report("enumcls",  typeid(ECorpusEnum),nullptr);
    report("enumplain",typeid(EPlainEnum), nullptr);
    report("fnptr",    typeid(fnptr_t),    nullptr);
    report("nonpoly",  typeid(SNonPoly),   nullptr);
    report("ary",      typeid(int[16]),    nullptr);

    // Virtual-base dynamic casts exercise the vbtable path
    CVBase* vb = &diamond;
    if (CDiamond* dd = dynamic_cast<CDiamond*>(vb))
        std::printf("diamond downcast ok: %d\n", dd->v());

    std::printf("corpus done\n");
    return 0;
}
