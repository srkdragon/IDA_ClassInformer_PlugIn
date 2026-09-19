PRAGMA idasql.enable_idapython = 1;
SELECT idapython_snippet('import ida_bytes
ea = 0x47D00C
ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, 8)
ok = True
ok = ida_bytes.create_dword(ea + 0, 4) and ok
ok = ida_bytes.create_dword(ea + 4, 4) and ok
ida_bytes.set_cmt(ea, None, 0)
ida_bytes.set_cmt(ea, "??_8CVLeft@@7B@ -- vbtable: 4-byte signed entries. entry[0] = -(vbptr offset in owning subobject); entry[i] = displacement of i-th virtual base FROM THE VBPTR field. Resolve: base = obj + pdisp + entry[vdisp/4]. See RE/VBTables-and-Virtual-Inheritance.md", 1)
print("??_8CVLeft@@7B@ ->", ok)
ea = 0x47D038
ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, 8)
ok = True
ok = ida_bytes.create_dword(ea + 0, 4) and ok
ok = ida_bytes.create_dword(ea + 4, 4) and ok
ida_bytes.set_cmt(ea, None, 0)
ida_bytes.set_cmt(ea, "??_8CVRight@@7B@ -- vbtable: 4-byte signed entries. entry[0] = -(vbptr offset in owning subobject); entry[i] = displacement of i-th virtual base FROM THE VBPTR field. Resolve: base = obj + pdisp + entry[vdisp/4]. See RE/VBTables-and-Virtual-Inheritance.md", 1)
print("??_8CVRight@@7B@ ->", ok)
ea = 0x47D070
ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, 8)
ok = True
ok = ida_bytes.create_dword(ea + 0, 4) and ok
ok = ida_bytes.create_dword(ea + 4, 4) and ok
ida_bytes.set_cmt(ea, None, 0)
ida_bytes.set_cmt(ea, "??_8CDiamond@@7BCVLeft@@@ -- vbtable: 4-byte signed entries. entry[0] = -(vbptr offset in owning subobject); entry[i] = displacement of i-th virtual base FROM THE VBPTR field. Resolve: base = obj + pdisp + entry[vdisp/4]. See RE/VBTables-and-Virtual-Inheritance.md", 1)
print("??_8CDiamond@@7BCVLeft@@@ ->", ok)
ea = 0x47D07C
ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, 8)
ok = True
ok = ida_bytes.create_dword(ea + 0, 4) and ok
ok = ida_bytes.create_dword(ea + 4, 4) and ok
ida_bytes.set_cmt(ea, None, 0)
ida_bytes.set_cmt(ea, "??_8CDiamond@@7BCVRight@@@ -- vbtable: 4-byte signed entries. entry[0] = -(vbptr offset in owning subobject); entry[i] = displacement of i-th virtual base FROM THE VBPTR field. Resolve: base = obj + pdisp + entry[vdisp/4]. See RE/VBTables-and-Virtual-Inheritance.md", 1)
print("??_8CDiamond@@7BCVRight@@@ ->", ok)
ea = 0x47D0D4
ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, 8)
ok = True
ok = ida_bytes.create_dword(ea + 0, 4) and ok
ok = ida_bytes.create_dword(ea + 4, 4) and ok
ida_bytes.set_cmt(ea, None, 0)
ida_bytes.set_cmt(ea, "??_8CMixFinal@@7BCVLeft@@@ -- vbtable: 4-byte signed entries. entry[0] = -(vbptr offset in owning subobject); entry[i] = displacement of i-th virtual base FROM THE VBPTR field. Resolve: base = obj + pdisp + entry[vdisp/4]. See RE/VBTables-and-Virtual-Inheritance.md", 1)
print("??_8CMixFinal@@7BCVLeft@@@ ->", ok)
ea = 0x47D0E0
ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, 8)
ok = True
ok = ida_bytes.create_dword(ea + 0, 4) and ok
ok = ida_bytes.create_dword(ea + 4, 4) and ok
ida_bytes.set_cmt(ea, None, 0)
ida_bytes.set_cmt(ea, "??_8CMixFinal@@7BCVRight@@@ -- vbtable: 4-byte signed entries. entry[0] = -(vbptr offset in owning subobject); entry[i] = displacement of i-th virtual base FROM THE VBPTR field. Resolve: base = obj + pdisp + entry[vdisp/4]. See RE/VBTables-and-Virtual-Inheritance.md", 1)
print("??_8CMixFinal@@7BCVRight@@@ ->", ok)');
