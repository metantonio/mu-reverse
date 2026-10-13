"""STEP4: Broad brute-force over ALL C3 packets in both directions.
Score = count of ASCII-printable bytes across the decrypted blocks.
Modulus set: {file_mod, 0x10000, file_mod&0xFFFF}. Key set: {key, key&0xFFFF}.
Inverse: {True, False (key*dec % mod, old-style)}.
This is the key step: if the cipher is "SimpleModulus math, 16-bit words",
exactly one (key, modsel, useinv) should give high ASCII on MANY packets.
"""
import sys
sys.path.insert(0, r"C:\Repositorios\mu-reverse")
from mu_proto import simple_modulus as sm

ENC = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Enc1.dat")
DEC = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Dec2.dat")

# Read C3 packets from the saved streams
def read_c3(path):
    data = open(path, "rb").read()
    out = []
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b == 0xC3:
            total = data[i+1]
            if i + total <= n:
                out.append(bytes(data[i:i+total]))
                i += total
            else:
                break
        else:
            i += 1
    return out

c2s_c3 = read_c3("c2s.bin")
s2c_c3 = read_c3("s2c.bin")
print("C2S C3 packets:", len(c2s_c3), "  S2C C3 packets:", len(s2c_c3))

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

def dec_block(k, c8, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, keys_override):
    enc = w_le(c8) if cin == "LE" else w_be(c8)
    if unchain:
        for i in (2, 1, 0):
            enc[i] ^= k.xor[i] ^ (enc[i+1] & 0xFFFF)
    ws = [0]*4
    prev = 0
    for i in range(4):
        dec = enc[i] & 0xFFFF
        if modsel == "file":
            MOD = keys_override[i]
        elif modsel == "f16":
            MOD = 0x10000
        else:  # "mask"
            MOD = keys_override[i] & 0xFFFF
        if useinv:
            inv = inv_mod(k.key[i], MOD)
            if inv is None:
                return None
            base = (inv * dec) % MOD
        else:
            base = (k.key[i] * dec) % MOD if modsel != "f16" else (k.key[i] * dec) & 0xFFFF
        w = (base ^ k.xor[i] ^ prev) if xorsrc == "full" else base
        w &= 0xFFFF
        ws[i] = w
        prev = (dec & 0xFFFF) if prevsrc == "dec" else (w & 0xFFFF)
    return p_le(ws) if cout == "LE" else p_be(ws)

def ascii_count(b):
    return sum(32 <= c <= 126 for c in b)

# Focus: use S2C C3 (Dec2 expected) and C2S C3 (Enc1 expected)
# Score = ASCII bytes across the first 3 packets of each direction.
sc = []
for kname, k, modsel_default in [("Enc1", ENC, None), ("Dec2", DEC, None)]:
    for cin in ("LE", "BE"):
        for cout in ("LE", "BE"):
            for modsel in ("file", "f16", "mask"):
                for useinv in (False, True):
                    for unchain in (True, False):
                        for xorsrc in ("full", "none"):
                            for prevsrc in ("dec", "w"):
                                total_ascii = 0
                                ok = True
                                for pkt in c2s_c3[:3]:
                                    ciph = pkt[2:-1]
                                    blocks = [ciph[j*8:(j+1)*8] for j in range(len(ciph)//8)]
                                    for blk in blocks:
                                        p = dec_block(k, blk, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, k.modulus)
                                        if p is None:
                                            ok = False
                                            break
                                        total_ascii += ascii_count(p)
                                    if not ok: break
                                if not ok:
                                    continue
                                # also add S2C C3 ascii
                                s_total = 0
                                for pkt in s2c_c3[:3]:
                                    ciph = pkt[2:-1]
                                    blocks = [ciph[j*8:(j+1)*8] for j in range(len(ciph)//8)]
                                    for blk in blocks:
                                        p = dec_block(k, blk, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, k.modulus)
                                        if p is None:
                                            s_total = -1
                                            break
                                        s_total += ascii_count(p)
                                    if s_total == -1:
                                        break
                                if s_total < 0: continue
                                sc.append((total_ascii + s_total, (kname, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)))
sc.sort(reverse=True)
print("Top 30 (key, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc) by total ASCII:")
for total, d in sc[:30]:
    print(f"  {total:3d}  {d[0]:4s} cin={d[1]} cout={d[2]} modsel={d[3]:4s} inv={d[4]} chain={d[5]} xor={d[6]:4s} prev={d[7]}")
