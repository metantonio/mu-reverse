import struct

BASE = "C:/Program Files (x86)/Webzen/Mu/"
for dll in ["npcipher.dll", "mumsg.dll", "wzCipher.dll"]:
    path = BASE + dll
    data = open(path, "rb").read()
    pe_off = struct.unpack_from("<I", data, 60)[0]
    print("=" * 50)
    print("%s  size=%d PE@%08X" % (dll, len(data), pe_off))
    # find strings that look like function names
    names = [b"Get", b"Encrypt", b"Decrypt", b"Cipher", b"CRC", b"Key", b"C3", b"C4"]
    for n in names:
        pos = 0
        while True:
            pos = data.find(n, pos)
            if pos < 0:
                break
            # read the null-terminated string
            end = data.find(b"\x00", pos)
            if end < 0 or end - pos > 128:
                end = min(len(data), pos + 64)
            s = "".join(chr(c) for c in data[pos:end] if 32 <= c < 127)
            if len(s) >= 4:
                print("  @%08X %s" % (pos, s))
            pos = end + 1
