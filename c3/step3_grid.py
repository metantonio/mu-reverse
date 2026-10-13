"""STEP3 (clean): Wide-grid brute-force of C2S login C3 with anchors:
  * B2 last word == 0x0000 (zero padding)
  * B1 first byte in {0xF1,0xF4,0xF3}
Modulus set for the multiply: {file mod, 0x10000}. Inverse: {key, inv}.
Also top-ASCII decryptions of B2 and B1 (relaxed) for manual review.
"""
import sys
sys.path.insert(0, r"C:\Repositorios\mu-reverse")
from mu_proto import simple_modulus as sm

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_mod(a, m):
    g, x, y = egcd(a % m, m)
    return x % m if g == 1 else None

ENC = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Enc1.dat")
DEC = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Dec2.dat")

PKT = bytes.fromhex("c3136f10a0806fe7d947afc839d8c422f9b105")
ciph = PKT[2:-1]
B1 = ciph[0:8]
B2 = ciph[8:16]

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

def dec_block(k, c8, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc):
    enc = w_le(c8) if cin == "LE" else w_be(c8)
    if unchain:
        for i in (2, 1, 0):
            enc[i] ^= k.xor[i] ^ (enc[i+1] & 0xFFFF)
    ws = [0] * 4
    prev = 0
    for i in range(4):
        dec = enc[i] & 0xFFFF
        MOD = k.modulus[i] if modsel == "mod" else 0x10000
        if useinv:
            inv = inv_mod(k.key[i], MOD)
            if inv is None:
                return None
            base = (inv * dec) % MOD
        else:
            base = (k.key[i] * dec) % MOD if modsel == "mod" else (k.key[i] * dec) & 0xFFFF
        w = (base ^ k.xor[i] ^ prev) if xorsrc == "full" else base
        w &= 0xFFFF
        ws[i] = w
        prev = (dec & 0xFFFF) if prevsrc == "dec" else (w & 0xFFFF)
    return p_le(ws) if cout == "LE" else p_be(ws)

def txt(b): return "".join(chr(c) if 32 <= c < 127 else "." for c in b)

hits = []
for kname, k in [("Enc1", ENC), ("Dec2", DEC)]:
    for cin in ("LE", "BE"):
        for cout in ("LE", "BE"):
            for modsel in ("mod", "f16"):
                for useinv in (False, True):
                    for unchain in (True, False):
                        for xorsrc in ("full", "none"):
                            for prevsrc in ("dec", "w"):
                                try:
                                    p2 = dec_block(k, B2, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
                                    p1 = dec_block(k, B1, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
                                except Exception:
                                    continue
                                if p1 is None or p2 is None:
                                    continue
                                w2 = w_le(p2) if cout == "LE" else w_be(p2)
                                if w2[3] != 0:
                                    continue
                                b0 = p1[0]
                                if b0 in (0xF1, 0xF4, 0xF3):
                                    hits.append((kname, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, b0, p1, p2))

print("ANCHOR HITS (B2.word3==0 and B1[0] in F1/F4/F3):", len(hits))
for kname, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, b0, p1, p2 in hits:
    print(f"  {kname} cin={cin} cout={cout} modsel={modsel} inv={useinv} chain={unchain} xor={xorsrc} prev={prevsrc} b0=0x{b0:02X}")
    print(f"    B1={p1.hex(' ')} | {txt(p1)}")
    print(f"    B2={p2.hex(' ')} | {txt(p2)}")

print("\n=== Top ASCII B2 (relaxed) ===")
sc = []
for kname, k in [("Enc1", ENC), ("Dec2", DEC)]:
    for cin in ("LE", "BE"):
        for cout in ("LE", "BE"):
            for modsel in ("mod", "f16"):
                for useinv in (False, True):
                    for unchain in (True, False):
                        for xorsrc in ("full", "none"):
                            for prevsrc in ("dec", "w"):
                                try:
                                    p2 = dec_block(k, B2, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
                                except Exception:
                                    continue
                                if p2 is None: continue
                                s = sum(32 <= c <= 126 for c in p2) / 8
                                if s > 0.75:
                                    sc.append((round(s, 3), (kname, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, p2)))
sc.sort(reverse=True)
for s, d in sc[:20]:
    print(f"  {s:.3f} {d[0]} {d[1]} {d[2]} {d[3]} inv={d[4]} ch={d[5]} xor={d[6]} prev={d[7]} | {d[8].hex(' ')} | {txt(d[8])}")

print("\n=== Top ASCII B1 (relaxed) ===")
sc1 = []
for kname, k in [("Enc1", ENC), ("Dec2", DEC)]:
    for cin in ("LE", "BE"):
        for cout in ("LE", "BE"):
            for modsel in ("mod", "f16"):
                for useinv in (False, True):
                    for unchain in (True, False):
                        for xorsrc in ("full", "none"):
                            for prevsrc in ("dec", "w"):
                                try:
                                    p1 = dec_block(k, B1, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
                                except Exception:
                                    continue
                                if p1 is None: continue
                                s = sum(32 <= c <= 126 for c in p1) / 8
                                if s > 0.75:
                                    sc1.append((round(s, 3), (kname, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, p1)))
sc1.sort(reverse=True)
for s, d in sc1[:20]:
    print(f"  {s:.3f} {d[0]} {d[1]} {d[2]} {d[3]} inv={d[4]} ch={d[5]} xor={d[6]} prev={d[7]} | {d[8].hex(' ')} | {txt(d[8])}")
