import struct

BASE = "C:/Program Files (x86)/Webzen/Mu/"
path = BASE + "npcipher.dll"
data = open(path, "rb").read()
pe_off = struct.unpack_from("<I", data, 60)[0]
opt = struct.unpack_from("<H", data, pe_off + 20)[0]
# The export names we saw are near each other; the export directory name table
# should contain "Encryption" and "Decryption". Find "Decryption" at 0x0000D6B5.
# Let's find the string table by locating the two known strings.
def read_str(data, off):
    end = data.find(b"\x00", off)
    return data[off:end].decode("latin1", "ignore"), end

for off, s in [(0x0000D6B5, "Decryption?"), (0x0000D6C4, "Encryption?")]:
    st, end = read_str(data, off)
    print("  @%08X '%s' (len %d)" % (off, st, end - off))

# Now find the export directory. The name table RVA points to these strings.
# Search the directory tables region. Try to locate a 2-byte count = 2 near the strings.
# Simpler: brute-force find the export directory by scanning for a 20-byte structure
# whose NameTable points near 0xD6B5.

# Look for the string table: it's an array of offsets (WORDs) to strings in a
# contiguous string pool. The two names are adjacent. Let's find the pool.
# The string pool contains: "Decryption\0" and "Encryption\0" possibly adjacent.
# Decryption at 0xD6B5 (10 chars + null = 11 bytes), then Encryption at 0xD6C4 = 0xD6B5 + 0xF? 
# 0xD6C4 - 0xD6B5 = 0xF = 15. "Decryption" is 10 chars. 10 + 1 (null) = 11 = 0xB. Not 0xF.
# So there's something between. Let's dump the region.
print("  region around 0xD6B0-0xD6DC:")
for off in range(0xD6A0, 0xD6E0, 1):
    ch = data[off]
    out = chr(ch) if 32 <= ch < 127 else "."
    print("  %08X %02X %s" % (off, ch, out))
