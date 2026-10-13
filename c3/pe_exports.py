import struct

BASE = "C:/Program Files (x86)/Webzen/Mu/"
for dll in ["npcipher.dll", "mumsg.dll", "wzCipher.dll", "npchk.dll", "npupdate0.dll"]:
    path = BASE + dll
    try:
        data = open(path, "rb").read()
    except Exception as e:
        print(dll, "ERR", e)
        continue
    if data[:2] != b"MZ":
        print(dll, "not PE, size", len(data))
        continue
    pe_off = struct.unpack_from("<I", data, 60)[0]
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    dir_off = pe_off + 20 + opt_hdr_size
    dirs = struct.unpack_from("<I", data, dir_off)[0]
    print("=" * 50)
    print("%-14s PE@%08X sections=%d dirs=%d optHdr=%d" % (dll, pe_off, nsec, dirs, opt_hdr_size))
    rva, size = struct.unpack_from("<II", data, dir_off + 2 * 16)
    if not rva:
        print("  no exports")
        continue
    ed = data[pe_off + rva: pe_off + rva + 20]
    addr_tbl_rva, base, n_sym, n_func, name_tbl_rva = struct.unpack_from("<IIHHI", ed, 0)
    print("  numSym=%d addrTable@%X nameTable@%X" % (n_sym, addr_tbl_rva, name_tbl_rva))
    sym = struct.unpack_from("<%dI" % n_sym, data, pe_off + addr_tbl_rva)
    nm = struct.unpack_from("<%dI" % n_sym, data, pe_off + name_tbl_rva)
    for i in range(n_sym):
        fn_rva = sym[i]
        fn_off = base + fn_rva
        out = "?"
        try:
            s = data[pe_off + fn_off: pe_off + fn_off + 64]
            out = s[: s.index(0)].decode("latin1", "ignore")
        except Exception:
            pass
        try:
            n = data[pe_off + name_tbl_rva + nm[i] : pe_off + name_tbl_rva + nm[i] + 64]
            nm_s = n[: n.index(0)].decode("latin1", "ignore")
        except Exception:
            nm_s = "?"
        print("  %-40s  %s" % (nm_s, out))
