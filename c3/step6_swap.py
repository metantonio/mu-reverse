"""STEP6: Test REMAPPED constants hypothesis:
  real_mod = file.key  (values <= 0x10000 -> 16-bit enc)
  real_key = file.mod
  xor      = file.xor
  enc[i] = (xor[i] ^ w[i] ^ prev) * real_key[i] % real_mod[i]
  dec: w[i] = (inv(real_key[i]%real_mod[i], real_mod[i]) * enc[i] % real_mod[i]) ^ xor[i] ^ prev
Also try a few (mod_src, key_src) combos. Anchor: C2S first C3 -> [0xF1, ...] and B2.word3==0.
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

def txt(b): return "".join(chr(c) if 32 <= c < 127 else "." for c in b)

def dec_block(k, c8, cin, cout, mod_src, key_src, xor_src, useinv, unchain, xorsrc, prevsrc):
    enc = w_le(c8) if cin == "LE" else w_be(c8)
    if unchain:
        for i in (2, 1, 0):
            enc[i] ^= k.xor[i] ^ (enc[i+1] & 0xFFFF)
    ws = [0]*4
    prev = 0
    for i in range(4):
        dec = enc[i] & 0xFFFF
        mods = k.modulus if mod_src == "mod" else k.key
        keys = k.key if key_src == "key" else k.modulus
        xorv = k.xor if xor_src == "xor" else k.xor
        MOD = mods[i]
        KEY = keys[i]
        if useinv:
            inv = inv_mod(KEY, MOD)
            if inv is None: return None
            base = (inv * dec) % MOD
        else:
            base = (KEY * dec) % MOD
        w = (base ^ xorv[i] ^ prev) if xorsrc == "full" else base
        w &= 0xFFFF
        ws[i] = w
        prev = (dec & 0xFFFF) if prevsrc == "dec" else (w & 0xFFFF)
    return p_le(ws) if cout == "LE" else p_be(ws)

def dec_pkt(pkt, k, **kw):
    ciph = pkt[2:-1]
    out = b""
    for j in range(len(ciph)//8):
        p = dec_block(k, ciph[j*8:(j+1)*8], **kw)
        if p is None: return None
        out += p
    return out

c2s_c3 = read_c3("c2s.bin")
s2c_c3 = read_c3("s2c.bin")
P1, P2 = c2s_c3[0], c2s_c3[1]
S1 = s2c_c3[0]

print("=== SWAP-CONSTANTS TEST on C2S first C3 (anchors: b0 in F1/F4/F3, B2 word3==0) ===")
for kname, k in [("Enc1", ENC), ("Dec2", DEC)]:
    for mod_src in ["mod", "key"]:
        for key_src in ["mod", "key"]:
            for cin, cout in [("LE","LE"),("LE","BE"),("BE","LE"),("BE","BE")]:
                for unchain in (True, False):
                    for xorsrc in ["full", "none"]:
                        for prevsrc in ["dec", "w"]:
                            for useinv in (False, True):
                                p = dec_pkt(P1, k, cin=cin, cout=cout, mod_src=mod_src,
                                            key_src=key_src, xor_src="xor",
                                            useinv=useinv, unchain=unchain, xorsrc=xorsrc,
                                            prevsrc=prevsrc)
                                if p is None: continue
                                if p[0] not in (0xF1, 0xF4, 0xF3): continue
                                b2 = dec_block(k, P2[2:-1][8:], cin, cout, mod_src, key_src, "xor",
                                               useinv, unchain, xorsrc, prevsrc)
                                if b2 is None: continue
                                w3 = (w_le(b2)[3] if cout == "LE" else w_be(b2)[3])
                                if w3 != 0: continue
                                print(f"** {kname} mod_src={mod_src} key_src={key_src} cin={cin} cout={cout} inv={useinv} chain={unchain} xor={xorsrc} prev={prevsrc}")
                                print(f"   b0=0x{p[0]:02X} full={p.hex(' ')}")
                                print(f"   txt  ={txt(p)}")
                                # also check B2 word3 (already 0)
                                print(f"   B2   ={b2.hex(' ')} | {txt(b2)}")
