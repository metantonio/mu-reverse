"""STEP5: Decrypt first packets with top param sets and dump raw output for inspection.
Also try to force plaintext[0]=0xF1 by scanning which param set gives B1[0]=0xF1 (or 0xF4).
"""
import sys
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

def dec_block(k, c8, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, kmod):
    enc = w_le(c8) if cin == "LE" else w_be(c8)
    if unchain:
        for i in (2, 1, 0):
            enc[i] ^= k.xor[i] ^ (enc[i+1] & 0xFFFF)
    ws = [0]*4
    prev = 0
    for i in range(4):
        dec = enc[i] & 0xFFFF
        MOD = kmod[i] if modsel == "file" else (0x10000 if modsel == "f16" else (kmod[i] & 0xFFFF))
        if useinv:
            inv = inv_mod(k.key[i], MOD)
            if inv is None: return None
            base = (inv * dec) % MOD
        else:
            base = (k.key[i] * dec) % MOD if modsel != "f16" else (k.key[i] * dec) & 0xFFFF
        w = (base ^ k.xor[i] ^ prev) if xorsrc == "full" else base
        w &= 0xFFFF
        ws[i] = w
        prev = (dec & 0xFFFF) if prevsrc == "dec" else (w & 0xFFFF)
    return p_le(ws) if cout == "LE" else p_be(ws)

def txt(b): return "".join(chr(c) if 32 <= c < 127 else "." for c in b)

def dec_pkt(pkt, k, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc):
    ciph = pkt[2:-1]
    out = b""
    for j in range(len(ciph)//8):
        p = dec_block(k, ciph[j*8:(j+1)*8], cin, cout, modsel, useinv, unchain, xorsrc, prevsrc, k.modulus)
        if p is None:
            return None
        out += p
    return out

c2s_c3 = read_c3("c2s.bin")
s2c_c3 = read_c3("s2c.bin")
P1 = c2s_c3[0]
P2 = c2s_c3[1]
S1 = s2c_c3[0]

print("=== C2S first C3 (login?) ===")
print("  pkt =", P1.hex(" "))
for kname, k in [("Enc1", ENC), ("Dec2", DEC)]:
    for cin, cout in [("LE","LE"),("LE","BE"),("BE","LE"),("BE","BE")]:
        for modsel in ["file","f16","mask"]:
            for useinv in (False, True):
                for unchain in (True, False):
                    for xorsrc in ["full","none"]:
                        for prevsrc in ["dec","w"]:
                            p = dec_pkt(P1, k, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
                            if p is None: continue
                            if p[0] in (0xF1, 0xF4, 0xF3):
                                print(f"  ** {kname} cin={cin} cout={cout} modsel={modsel} inv={useinv} chain={unchain} xor={xorsrc} prev={prevsrc} -> first byte 0x{p[0:1].hex()}")
                                print(f"     full = {p.hex(' ')} | {txt(p)}")

print("\n=== Top-ASCII param sets applied to first packets ===")
sets = [
    ("C2S/Enc1", ENC, "BE","LE","file",False,False,"none","dec"),
    ("C2S/Dec2", DEC, "LE","LE","mask",False,True,"none","dec"),
    ("S2C/Dec2", DEC, "LE","LE","file",False,True,"full","dec"),
    ("S2C/Enc1", ENC, "LE","LE","file",False,True,"none","dec"),
]
for name, k, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc in sets:
    print(f"\n{name} params={ (cin,cout,modsel,useinv,unchain,xorsrc,prevsrc) }")
    print("  C2S[0] =", (dec_pkt(P1, ENC, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc) if name.startswith("C2S") else None) or "")
    if name.startswith("C2S"):
        p1 = dec_pkt(P1, k, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
        p2 = dec_pkt(P2, k, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
        print(f"  C2S[0] = {p1.hex(' ')} | {txt(p1)}")
        print(f"  C2S[1] = {p2.hex(' ')} | {txt(p2)}")
    else:
        p1 = dec_pkt(S1, k, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
        print(f"  S2C[0] = {p1.hex(' ')} | {txt(p1)}")
        p2 = dec_pkt(s2c_c3[1], k, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
        p3 = dec_pkt(s2c_c3[2], k, cin, cout, modsel, useinv, unchain, xorsrc, prevsrc)
        print(f"  S2C[1] = {p2.hex(' ')} | {txt(p2)}")
        print(f"  S2C[2] = {p3.hex(' ')} | {txt(p3)}")
