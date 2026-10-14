"""STEP7: Known-plaintext cross-reference.
Extract clear C1/C2 strings (S2C) -> candidate usernames.
For each candidate name + each cipher transform, ENCRYPT [0xF1]+name (13 bytes)
and compare to the ACTUAL first C2S C3 ciphertext. Match = cipher found.
Also test decryption anchors on the same transforms.
"""
import sys, re
sys.path.insert(0, r"C:\Repositorios\mu-reverse")
from mu_proto import simple_modulus as sm

ENC = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Enc1.dat")
DEC = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Dec2.dat")

def read_c3(path):
    data = open(path, "rb").read()
    out, i, n = [], 0, len(data)
    while i < n:
        if data[i] == 0xC3:
            total = data[i+1]
            if i + total <= n:
                out.append(bytes(data[i:i+total])); i += total
            else: break
        else: i += 1
    return out

def all_strings(data):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        out.append(m.group().decode("latin1", "ignore"))
    return out

# Clear (C1/C2) byte strings from S2C stream (the readable part)
s2c = open("s2c.bin", "rb").read()
s2c_strings = all_strings(s2c)
print("S2C clear strings (>=4 chars):")
for s in s2c_strings:
    print("   ", repr(s))

# Build candidate 12-byte usernames from character names found
names = ["Charoen", "Galus the Elder", "Warhouse Elder", "Chaos Goblin",
         "Shadow Phantom Soldier", "Gens Vaneer", "Captain Slough Ward",
         "Sir Lesnar Ugh", "Lorenzian Entrance Mines", "Aida Entrance",
         "Atlant Entrance"]
def to12(s):
    b = s.encode("latin1")
    if len(b) >= 12: return b[:12]
    return b + b"\x00" * (12 - len(b))
usernames = {name: to12(name) for name in names}

def w_le(b):  return [b[0]|b[1]<<8, b[2]|b[3]<<8, b[4]|b[5]<<8, b[6]|b[7]<<8]
def w_be(b):  return [b[0]<<8|b[1], b[2]<<8|b[3], b[4]<<8|b[5], b[6]<<8|b[7]]
def p_le(ws):
    o = bytearray(8)
    for i, w in enumerate(ws): o[i*2], o[i*2+1] = w & 0xFF, (w >> 8) & 0xFF
    return bytes(o)
def p_be(ws):
    o = bytearray(8)
    for i, w in enumerate(ws): o[i*2], o[i*2+1] = (w >> 8) & 0xFF, w & 0xFF
    return bytes(o)
def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)
def inv_mod(a, m):
    g, x, y = egcd(a % m, m)
    return x % m if g == 1 else None

def enc_block(k, plain8, cin, cout, mod_src, key_src, useinv, unchain, xorsrc, prevsrc):
    # encrypt: enc[i] = (xor ^ w[i] ^ prev) * KEY % MOD
    words = w_le(plain8) if cin == "LE" else w_be(plain8)
    mods = k.modulus if mod_src == "mod" else k.key
    keys = k.key if key_src == "key" else k.modulus
    ws = []
    prev = 0
    for i in range(4):
        w = words[i]
        val = (k.xor[i] ^ w ^ prev) * keys[i] % mods[i]
        ws.append(val)
        prev = val & 0xFFFF
    # chain
    if unchain:
        for i in (2, 1, 0):
            ws[i] ^= k.xor[i] ^ (ws[i + 1] & 0xFFFF)
    # pack
    o = p_le(ws) if cout == "LE" else p_be(ws)
    return o

def enc_pkt(k, plain, cin, cout, mod_src, key_src, useinv, unchain, xorsrc, prevsrc):
    # pad to 16 bytes (2 blocks)
    pad = plain + b"\x00" * (16 - len(plain))
    out = b""
    for j in range(len(pad) // 8):
        out += enc_block(k, pad[j*8:(j+1)*8], cin, cout, mod_src, key_src, useinv, unchain, xorsrc, prevsrc)
    return out[:16]  # ciphertext 16 bytes (pad byte separate)

P1 = read_c3("c2s.bin")[0]
actual = P1[2:-1]  # 16-byte ciphertext
print("\nActual first C2S C3 ciphertext:", actual.hex(" "))

hits = []
for kname, k in [("Enc1", ENC), ("Dec2", DEC)]:
    for name, uname in usernames.items():
        plain = bytes([0xF1]) + uname  # 13 bytes
        for cin, cout in [("LE","LE"),("LE","BE"),("BE","LE"),("BE","BE")]:
            for mod_src in ["mod", "key"]:
                for key_src in ["mod", "key"]:
                    for unchain in (True, False):
                        for xorsrc in ["full", "none"]:
                            for prevsrc in ["dec", "w"]:
                                for useinv in (False, True):
                                    enc = enc_pkt(k, plain, cin, cout, mod_src, key_src, useinv, unchain, xorsrc, prevsrc)
                                    if enc == actual:
                                        hits.append((kname, name, cin, cout, mod_src, key_src, useinv, unchain, xorsrc, prevsrc))
print("\nKNOWN-PLAINTEXT MATCHES:", len(hits))
for h in hits:
    print("   ", h)
print("  (if 0, no candidate transform + username reproduces the ciphertext)")
