import struct

BASE = "C:/Program Files (x86)/Webzen/Mu/"
path = BASE + "npcipher.dll"
data = open(path, "rb").read()
pe_off = struct.unpack_from("<I", data, 60)[0]
nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
opt = struct.unpack_from("<H", data, pe_off + 20)[0]
chars = struct.unpack_from("<H", data, pe_off + 22)[0]
print("PE@%08X sections=%d opt=%d chars=%X" % (pe_off, nsec, opt, chars))
# Directory tables at pe_off + 20 + opt (standard) OR pe_off + 40
for cand_off in [pe_off + 40, pe_off + 20 + opt]:
    if cand_off + 16 <= len(data):
        dirs = struct.unpack_from("<I", data, cand_off)[0]
        print("  cand @%08X: dirs=%d" % (cand_off, dirs))
# Look at the end of optional header for NumberOfRvaAndSizes
# Standard 32-bit opt header: NumberOfRvaAndSizes at offset 208 (0xD0) within opt header
nrav = struct.unpack_from("<I", data, pe_off + 24 + 0xD0)[0]
print("  NumberOfRvaAndSizes @opt+0xD0 =", hex(nrav))
dir_off = pe_off + 24 + 0xD0 + 4
print("  directory tables at %08X" % dir_off)
print("  dir bytes: ", data[dir_off:dir_off+32].hex(" "))
