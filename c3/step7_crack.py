"""STEP7: Crack con known-plaintext. Prueba SimpleModulus-math con TODAS las
asignaciones de las 12 constantes a (mod,key,xor)[4], guiado por el slot 0.
CT block0 = 6f10a080 6fe7d947 ; PT = F14D696E 69546173 (LE words)."""
import sys, struct, itertools
sys.path.insert(0, r"C:\Repositorios\mu-reverse")
from mu_proto import simple_modulus as sm

ENC1 = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Enc1.dat")
DEC2 = sm.Keys.load(r"C:\Program Files (x86)\Webzen\Mu\Data\Dec2.dat")

CT1 = bytes([0x6f,0x10,0xa0,0x80,0x6f,0xe7,0xd9,0x47])   # block 1 ciphertext
PT1 = bytes([0xF1,0x4D,0x69,0x6E,0x69,0x54,0x61,0x73])   # block 1 plaintext ("MiniTasita"[0..7])
CT2 = bytes([0xaf,0xc8,0x39,0xd8,0xc4,0x22,0xf9,0xb1])
PT2 = bytes([0x69,0x74,0x61,0x00,0x00,0x00,0x00,0x00])  # block 2 (it a + 5 pad... wait 11 real)

# 12 constants
const = list(ENC1.modulus) + list(ENC1.key) + list(ENC1.xor)
const_dec2 = list(DEC2.modulus) + list(DEC2.key) + list(DEC2.xor)

def w_le(b): return [struct.unpack_from('<H', b, i*2)[0] for i in range(4)]
def p_le(ws): return bytes(b for w in ws for b in [w&0xFF, (w>>8)&0xFF])

def try_math(k, c8, pt8, modsel, inv, chain, xorsrc, prevsrc, endi="LE"):
    # SimpleModulus DECRYPT attempt (we know pt, want to see if it round-trips to ct)
    # Better: ENCRYPT the plaintext and compare to ciphertext.
    ws = [struct.unpack_from('<H', pt8, i*2)[0] for i in range(4)]  # plaintext words LE
    enc, prev = [0]*4, 0
    for i in range(4):
        MOD = (k.modulus[i] if modsel=="file" else (0x10000 if modsel=="f16" else k.modulus[i]&0xFFFF))
        enc[i] = ((k.xor[i] ^ ws[i] ^ prev) * k.key[i]) % MOD
        prev = enc[i] & 0xFFFF
    for i in range(3):
        enc[i] ^= k.xor[i] ^ (enc[i+1] & 0xFFFF)
    out = bytearray(8)
    for i, v in enumerate(enc):
        out[i*2] = v & 0xFF
        out[i*2+1] = (v >> 8) & 0xFF
    return bytes(out)

def try_perm(consts, kname):
    # Try all ways to assign 12 constants to (mod[4], key[4], xor[4])
    found = []
    for perm in itertools.permutations(consts):
        # perm is a permutation of the 12 constants
        # But we need to assign 4 to mod, 4 to key, 4 to xor, keeping the "role" groups
        # Actually, let's try ALL partitions: choose 4 for mod, 4 for key, 4 for xor
        # This is C(12,4)*C(8,4) = 34650. Do it directly.
    return None

# Direct: for each direction file (Enc1, Dec2), try all (mod,key,xor) assignments
found = []
for kname, kfile in [("Enc1", ENC1), ("Dec2", DEC2)]:
    mods = list(kfile.modulus)
    keys = list(kfile.key)
    xors = list(kfile.xor)
    # Permute within groups? Try all 3^12-ish... Instead try all orderings of the 4 mods,
    # 4 keys, 4 xors independently (24*24*24 = 13824 per file)
    for mp in itertools.permutations(mods):
        for kp in itertools.permutations(keys):
            for xp in itertools.permutations(xors):
                # Build a Keys-like object
                class K:
                    modulus, key, xor = list(mp), list(kp), list(xp)
                k = K()
                ct = try_math(k, CT1, PT1, "file", False, True, "full", "dec")
                if ct == CT1:
                    # Verify with block 2 too
                    ct2 = try_math(k, CT2, PT2, "file", False, True, "full", "dec")
                    if ct2 == CT2:
                        found.append((kname, mp, kp, xp, "file"))
    print(f"{kname}: full matches (LE words, enc LE) = {len(found)}")
    for f in found:
        print("  MATCH:", f)

print("DONE. matches:", len(found))