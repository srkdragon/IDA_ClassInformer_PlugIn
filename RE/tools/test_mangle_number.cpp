// Standalone replica of ClassInformer's fixed mangleNumber() for validation.
// Oracle values come from VS2026 linker-map ground truth (RE/MSVC-RTTI-Layout.md 7.1).
#include <cstdio>
#include <cstring>
#include <climits>

static const char *mangleNumber(unsigned int number, char *buffer)
{
    int num = *(int *)&number;
    if (num == 0)
        return strcpy(buffer, "A@");
    int sign = 0;
    if (num < 0) { sign = 1; num = -num; }
    if (num <= 10) { sprintf_s(buffer, 64, "%s%d", sign ? "?" : "", num - 1); return buffer; }
    char buffer2[64];
    int count = 0;
    while ((num > 0) && (count < (int)sizeof(buffer2)))
    {
        buffer2[count++] = (char)('A' + (num % 16));
        num = (num / 16);
    }
    for (int l = 0, r = (count - 1); l < r; l++, r--)
    { char t = buffer2[l]; buffer2[l] = buffer2[r]; buffer2[r] = t; }
    buffer2[count] = 0;
    sprintf_s(buffer, 64, "%s%s@", sign ? "?" : "", buffer2);
    return buffer;
}

struct { int in; const char *want; } tests[] = {
    { 0,   "A@" },  // mdisp/vdisp 0        (??_R1A@...)
    { 1,   "0" },   // smallest digit form
    { 8,   "7" },   // CMI_B mdisp x64      (??_R17?0A@...)
    { 10,  "9" },   // digit branch edge
    { 11,  "L@" },  // 0xB -> hex branch edge
    { 16,  "BA@" }, // CMI_C mdisp x64      (??_R1BA@...)
    { 64,  "EA@" }, // attributes 0x40, every public BCD (??_R1A@?0A@EA@)
    { 66,  "EC@" }, // attributes 0x42 ambiguous
    { 77,  "EN@" }, // attributes 0x4D private/protected (??_R1A@?0A@EN@)
    { 80,  "FA@" }, // attributes 0x50 virtual base
    { 132, "IE@" }, // 0x84 CPad_B x86 (??_R1IE@?0A@EA@CPad_B@@8)
    { 136, "II@" }, // 0x88 CPad_B x64 (palindrome)
    { -1,  "?0" },  // pdisp -1
};

int main()
{
    int fail = 0; char buf[64];
    for (auto &t : tests)
    {
        mangleNumber((unsigned int)t.in, buf);
        bool ok = (strcmp(buf, t.want) == 0);
        printf("%-6d -> %-5s %s\n", t.in, buf, ok ? "OK" : "** FAIL **");
        if (!ok) fail++;
    }
    // 132 must be IE@ not DC@ per nibble order: fix expectation if typo above
    return fail;
}
