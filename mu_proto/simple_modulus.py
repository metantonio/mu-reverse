"""SimpleModulus cipher (C3/C4 packets). Public algorithm (MuEmu/OpenMU)."""
import struct

FILE_XOR = (0x3F08A79B, 0xE25CC287, 0x93D27AB9, 0x20DEA7BF)


def _get_bits(buf, pos, n):
    v = 0
    for i in range(n):
        p = pos + i
        v = (v << 1) | ((buf[p >> 3] >> (7 - (p & 7))) & 1)
    return v


def _put_bits(buf, pos, value, n):
    for i in range(n):
        p = pos + i
        if (value >> (n - 1 - i)) & 1:
            buf[p >> 3] |= 0x80 >> (p & 7)


class Keys:
    """modulus, key (encrypt or decrypt), xor: each a list of 4 uint32."""

    def __init__(self, modulus, key, xor):
        self.modulus, self.key, self.xor = list(modulus), list(key), list(xor)

    @classmethod
    def load(cls, path):
        data = open(path, "rb").read()
        sig, size = struct.unpack_from("<HI", data, 0)
        if sig != 0x1112 or size != len(data):
            raise ValueError("invalid key file: %s" % path)
        raw = struct.unpack_from("<12I", data, 6)
        vals = [raw[i] ^ FILE_XOR[i % 4] for i in range(12)]
        return cls(vals[0:4], vals[4:8], vals[8:12])


def encrypt_block(k, src8, size):
    """8 plaintext bytes (size = real bytes used, 1..8) -> 11 bytes."""
    words = struct.unpack("<4H", bytes(src8))
    enc, prev = [0] * 4, 0
    for i in range(4):
        enc[i] = ((k.xor[i] ^ words[i] ^ prev) * k.key[i]) % k.modulus[i]
        prev = enc[i] & 0xFFFF
    for i in range(3):
        enc[i] ^= k.xor[i] ^ (enc[i + 1] & 0xFFFF)
    out, pos = bytearray(11), 0
    for v in enc:
        _put_bits(out, pos, ((v & 0xFF) << 8) | ((v >> 8) & 0xFF), 16)
        _put_bits(out, pos + 16, (v >> 16) & 3, 2)
        pos += 18
    chk = 0xF8
    for b in src8:
        chk ^= b
    _put_bits(out, pos, ((size ^ chk ^ 0x3D) << 8) | chk, 16)
    return bytes(out)


def decrypt_block(k, src11):
    """11 cipher bytes -> (8 plaintext bytes, real size) ; size -1 = bad checksum."""
    dec, pos = [0] * 4, 0
    for i in range(4):
        w = _get_bits(src11, pos, 16)
        dec[i] = ((w >> 8) & 0xFF) | ((w & 0xFF) << 8) | (_get_bits(src11, pos + 16, 2) << 16)
        pos += 18
    for i in (2, 1, 0):
        dec[i] ^= k.xor[i] ^ (dec[i + 1] & 0xFFFF)
    words, prev = [], 0
    for i in range(4):
        words.append(((k.key[i] * dec[i]) % k.modulus[i] ^ k.xor[i] ^ prev) & 0xFFFF)
        prev = dec[i] & 0xFFFF
    plain = struct.pack("<4H", *words)
    tail = _get_bits(src11, pos, 16)
    b0, b1 = (tail >> 8) & 0xFF, tail & 0xFF
    size = b0 ^ b1 ^ 0x3D
    chk = 0xF8
    for b in plain:
        chk ^= b
    return plain, (size if chk == b1 else -1)


def decrypt(k, data):
    """Decrypt a multiple-of-11 buffer. Returns bytes or None on error."""
    if len(data) % 11:
        return None
    out = bytearray()
    for off in range(0, len(data), 11):
        plain, size = decrypt_block(k, data[off:off + 11])
        if size < 0 or size > 8:
            return None
        out += plain[:size]
    return bytes(out)


def encrypt(k, data):
    out = bytearray()
    for off in range(0, len(data), 8):
        chunk = data[off:off + 8]
        out += encrypt_block(k, chunk.ljust(8, b"\0"), len(chunk))
    return bytes(out)

