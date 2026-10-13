import struct
for path in [r"C:\Program Files (x86)\Webzen\Mu\Data\Enc1.dat", r"C:\Program Files (x86)\Webzen\Mu\Data\Dec2.dat"]:
    data = open(path, "rb").read()
    print("====", path, "len=", len(data))
    print("hex:", data.hex(" "))
    sig, size = struct.unpack_from("<HI", data, 0)
    print("sig=0x%04X size=%d" % (sig, size))
    raw = struct.unpack_from("<12I", data, 6)
    FX = (0x3F08A79B, 0xE25CC287, 0x93D27AB9, 0x20DEA7BF)
    vals = [raw[i] ^ FX[i % 4] for i in range(12)]
    print("raw  = [", ", ".join(hex(v) for v in raw), "]")
    print("xored= [", ", ".join(hex(v) for v in vals), "]")
    print("  mod = [", ", ".join(hex(v) for v in vals[0:4]), "]  bitlen=", [v.bit_length() for v in vals[0:4]])
    print("  key = [", ", ".join(hex(v) for v in vals[4:8]), "]  even=", [v % 2 == 0 for v in vals[4:8]])
    print("  xor = [", ", ".join(hex(v) for v in vals[8:12]), "]")
