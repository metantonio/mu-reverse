"""MU packet framing: C1/C2 (plain) and C3/C4 (SimpleModulus) + XOR3 layer.

Based on public protocol documentation (OpenMU). Not verified against the
current Webzen client: confirm with real captures.
"""
from . import simple_modulus as sm

XOR32 = bytes([
    0xAB, 0x11, 0xCD, 0xFE, 0x18, 0x23, 0xC5, 0xA3,
    0xCA, 0x33, 0xC1, 0xCC, 0x66, 0x67, 0x21, 0xF3,
    0x32, 0x12, 0x15, 0x35, 0x29, 0xFF, 0xFE, 0x1D,
    0x44, 0xEF, 0xCD, 0x41, 0x26, 0x3C, 0x4E, 0x4D,
])


def header_size(t):
    return 2 if t in (0xC1, 0xC3) else 3


def packet_length(buf):
    """Declared length of the packet at buf[0], or None if incomplete/invalid."""
    if not buf or buf[0] not in (0xC1, 0xC2, 0xC3, 0xC4):
        return None
    if buf[0] in (0xC1, 0xC3):
        return buf[1] if len(buf) >= 2 else None
    return (buf[1] << 8 | buf[2]) if len(buf) >= 3 else None


def xor32_decrypt(pkt):
    """Undo the client->server XOR chain on a plain C1/C2 packet."""
    p = bytearray(pkt)
    hs = header_size(p[0])
    for i in range(len(p) - 1, hs, -1):
        p[i] ^= p[i - 1] ^ XOR32[i % 32]
    return bytes(p)


def split_stream(buf):
    """Split a TCP byte stream into packets. Returns (packets, remainder)."""
    out = []
    while True:
        n = packet_length(buf)
        if n is None or n < 3:
            break
        if len(buf) < n:
            break
        out.append(bytes(buf[:n]))
        buf = buf[n:]
    return out, buf


def decode_packet(pkt, keys=None, client_to_server=False, use_xor32=True):
    """Return dict: type, encrypted, ok, body (bytes after header).

    For C3/C4 the body is the SimpleModulus plaintext; per public docs its
    first byte is a serial counter, followed by the inner packet contents.
    """
    t, hs = pkt[0], header_size(pkt[0])
    info = {"type": t, "len": len(pkt), "encrypted": t in (0xC3, 0xC4)}
    if not info["encrypted"]:
        if client_to_server and use_xor32:
            pkt = xor32_decrypt(pkt)
        info.update(ok=True, body=pkt[hs:])
        return info
    plain = sm.decrypt(keys, pkt[hs:]) if keys else None
    info.update(ok=plain is not None, body=plain if plain is not None else pkt[hs:])
    return info
