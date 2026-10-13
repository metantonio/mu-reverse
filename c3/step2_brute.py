"""STEP2: Brute-force decrypt C3 using the SimpleModulus math with 8-byte packing.

Hypothesis: same math as mu_proto/simple_modulus.py, but each 18-bit enc[i] is
packed as a 16-bit word (4 x 16-bit = 8 bytes) instead of 18 bits (4 x 18 = 11).

We try:
  * both key files (Enc1 for C2S, Dec2 for S2C, and swapped)
  * word endianness LE/BE
  * the repo's direct decryption ((key*dec)%mod ^ xor ^ prev)
  * a modular-inverse decryption ((inv(key,mod)*dec)%mod ^ xor ^ prev)
  * with/without the ^xor term in the word step
  * chain variants

Known-plaintext anchors:
  C2S first C3 is the very first client packet => likely opcode 0xF1 (Login) or 0xF4 (ConnectServer)
  or 0xF3 (CharacterSelect).
  S2C C3 are login/character responses; expect ASCII.
"""
import struct
sys = __import__("sys")
sys.path.insert(0, r"C:\Repositorios\mu-reverse")
from mu_proto import packets as pk
from mu_proto import simple_modulus as sm

PCAP = r"C:\Users\anton\Downloads\WiresharkPortable64\Data\Temp\wireshark_Wi-FiIVW3W3.pcapng"

def load_keys():
    enc1 = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Enc1.dat")
    dec2 = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Dec2.dat")
    return enc1, dec2

def inv_mod(a, m):
    # extended euclid; m is odd (modulus values are odd) so inverse exists
    def egcd(a, b):
        if b == 0:
            return (a, 1, 0)
        g, x1, y1 = egcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)
    g, x, y = egcd(a % m, m)
    if g != 1:
        return None
    return x % m

def hexview(b):
    return " ".join(f"{x:02x}" for x in b)

def printable_score(b):
    return sum(32 <= c <= 126 for c in b) / max(1, len(b))

def try_decrypt_block(keys, cipher8, order, math_var, unchain=True, prev_src="dec"):
    """Decrypt one 8-byte block -> 8-byte plaintext (or None)."""
    k = keys
    if order == "LE":
        words_in = struct.unpack("<4H", cipher8)
    else:
        words_in = struct.unpack(">4H", cipher8)
    # reconstruct ciphertext words (16-bit) in the order used by the cipher
    enc = list(words_in)
    if unchain:
        for i in (2, 1, 0):
            enc[i] ^= k.xor[i] ^ (enc[i + 1] & 0xFFFF)
    out = bytearray(8)
    prev = 0
    for i in range(4):
        dec = enc[i]
        base = None
        if math_var == "direct":
            base = (k.key[i] * dec) % k.modulus[i]
        elif math_var == "inv":
            inv = inv_mod(k.key[i], k.modulus[i])
            if inv is None:
                return None
            base = (inv * dec) % k.modulus[i]
        else:  # "inv_noxor"
            inv = inv_mod(k.key[i], k.modulus[i])
            base = (inv * dec) % k.modulus[i]
        if math_var in ("direct", "inv"):
            w = base ^ k.xor[i] ^ prev
        else:
            w = base
        w &= 0xFFFF
        out[i * 2:i * 2 + 2] = struct.pack("<H", w) if order == "LE" else struct.pack(">H", w)
        if prev_src == "dec":
            prev = dec & 0xFFFF
        else:
            prev = w & 0xFFFF
    return bytes(out)

ENC, DEC = load_keys()
print("Enc1: mod=", ENC.modulus, "key=", ENC.key, "xor=", ENC.xor)
print("Dec2: mod=", DEC.modulus, "key=", DEC.key, "xor=", DEC.xor)
for k in (ENC, DEC):
    for i in range(4):
        inv = inv_mod(k.key[i], k.modulus[i])
        print("  inv key[%d] mod[%d] = %s" % (i, k.key[i], hex(inv) if inv else "None"))

# C2S first C3 (login): c3 13 6f 10 a0 80 6f e7 d9 47 af c8 39 d8 c4 22 f9 b1 05
pkt = bytes.fromhex("c313 6f 10 a0 80 6f e7 d9 47 af c8 39 d8 c4 22 f9 b1 05".replace(" ", ""))
# ciphertext = pkt[2:-1] (2-byte header, exclude pad), pad = pkt[-1]
pad = pkt[-1]
ciph = pkt[2: -1]
print("\nC2S first C3: pad=%d ciph(%d bytes)=%s" % (pad, len(ciph), hexview(ciph)))
print("  blocks:", [hexview(ciph[i * 8:(i + 1) * 8]) for i in range(len(ciph) // 8)])

print("\n=== BRUTE C2S first C3 (Enc1 & Dec2, both orders, math variants) ===")
for kname, kkey in [("Enc1", ENC), ("Dec2", DEC)]:
    for order in ("LE", "BE"):
        for mv in ("direct", "inv"):
            for unchain in (True, False):
                for psrc in ("dec", "w"):
                    blocks = [ciph[i * 8:(i + 1) * 8] for i in range(len(ciph) // 8)]
                    plains = []
                    ok = True
                    for b in blocks:
                        p = try_decrypt_block(kkey, b, order, mv, unchain, psrc)
                        if p is None:
                            ok = False
                            break
                        plains.append(p)
                    if not ok:
                        continue
                    plain = b"".join(plains)
                    s0 = plain[0]
                    anchor = "OPCODE!" if s0 in (0xF1, 0xF4, 0xF3, 0xF2, 0xF8) else ""
                    print("%-5s %s mv=%-6s unchain=%s psrc=%-2s pad=%d -> b0=0x%02x %s"
                          % (kname, order, mv, unchain, psrc, pad, s0, anchor))
                    print("    plain=", hexview(plain), "| printable=", round(printable_score(plain), 2))
                    asx = "".join(chr(c) if 32 <= c <= 126 else "." for c in plain)
                    if printable_score(plain) > 0.5:
                        print("    text  =", asx)
