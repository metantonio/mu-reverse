"""STEP4b: Per-direction scoring. For each (key, cin, cout, modsel, useinv,
unchain, xorsrc, prevsrc), compute total ASCII bytes over ALL C3 packets of that
direction. The correct cipher yields a sharp peak (high ASCII on nearly all packets).
"""
import sys
sys.path.insert(0, r"C:\Repositorios\mu-reverse")
from mu_proto import simple_modulus as sm

ENC = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Enc1.dat")
DEC = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Dec2.dat")

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
print("C2S C3:", len(c2s_c3), " S2C C3:", len(s2c_c3))

# Precompute ciphertext blocks for each packet (avoid re-splitting)
def blocks_of(pkts):
    res = []
    for pkt in pkts:
        ciph = pkt[2:-1]
        res.append([ciph[j*8:(j+1)*8] for j in range(len(ciph)//8)])
    return res
C2S_BLK = blocks_of(c2s_c3)
S2C_BLK = blocks_of(s2c_c3)

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

def ascii_count(b):
    return sum(32 <= c <= 126 for c in b)

def dec_block(k, c8, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, keys_override):
    enc = w_le(c8) if cin == "LE" else w_be(c8)
    if unchain:
        for i in (2, 1, 0):
            enc[i] ^= k.xor[i] ^ (enc[i+1] & 0xFFFF)
    ws = [0]*4
    prev = 0
    for i in range(4):
        dec = enc[i] & 0xFFFF
        MOD = keys_override[i] if modsel == "file" else (0x10000 if modsel == "f16" else (keys_override[i] & 0xFFFF))
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

params = [("LE","LE"),("LE","BE"),("BE","LE"),("BE","BE")]
modsels = ["file","f16","mask"]

def score(key, blks, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, kmod):
    total, blocks = 0, 0
    for bblk in blks:
        for blk in bblk:
            p = dec_block(key, blk, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, kmod)
            if p is None:
                return -1
            total += ascii_count(p)
            blocks += 1
    return (total, blocks)

def run_direction(key, blks, label):
    results = []
    for cin, cout in params:
        for modsel in modsels:
            for useinv in (False, True):
                for unchain in (True, False):
                    for xorsrc in ("full", "none"):
                        for prevsrc in ("dec", "w"):
                            res = score(key, blks, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, key.modulus)
                            if isinstance(res, int):
                                continue
                            t, nblk = res
                            results.append((t, nblk, (cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)))
    results.sort(reverse=True, key=lambda x: (x[0] / max(1, x[1]), x[0]))
    print(f"\n===== {label} =====")
    for t, nblk, d in results[:15]:
        print(f"  ascii={t:4d}/{nblk*8:5d} ({t/nblk/8:.2f}/byte)  cin={d[0]} cout={d[1]} modsel={d[2]:4s} inv={d[3]} chain={d[4]} xor={d[5]:4s} prev={d[6]}")
    return results[:1]

r2s = run_direction(ENC, C2S_BLK, "C2S with Enc1")
r2s_dec = run_direction(DEC, C2S_BLK, "C2S with Dec2 (swap)")
r2c = run_direction(DEC, S2C_BLK, "S2C with Dec2")
r2c_enc = run_direction(ENC, S2C_BLK, "S2C with Enc1 (swap)")
print("\n\nSUMMARY (top param sets):")
for name, res in [("C2S/Enc1", r2s), ("C2S/Dec2", r2s_dec), ("S2C/Dec2", r2c), ("S2C/Enc1", r2c_enc)]:
    if res:
        t, nblk, d = res[0]
        print(f"  {name}: {t}/{nblk*8} bytes ascii, params={d}")
