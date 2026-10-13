"""Tests de validación del canal C5 (AES-256-GCM + anti-replay)."""
from __future__ import annotations
import os, struct
from c5 import C5Link, make_pair, make_aad, C5

PASS = 0
FAIL = 0


def check(name, ok, detail=None):
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{status}] {name}" + (f"  {detail}" if detail and not ok else ""))


def craft(pkt_link, pkt_type, seq, plaintext, stream_id=0):
    """Crea un paquete C5 válido con un seq dado (para probar replay/gaps)."""
    nonce = pkt_link._nonce(seq, stream_id)
    aad = make_aad(pkt_type, seq, stream_id)
    ct = pkt_link._c.encrypt(nonce, plaintext, aad)
    return (bytes([C5]) + struct.pack(">H", len(ct)) + nonce
            + seq.to_bytes(8, "little") + bytes([pkt_type]) + ct)


def t_roundtrip():
    a, b = make_pair(key=b"K" * 32)
    pkt = a.send(b"\x11\x02\x03\x04", pkt_type=0x11)
    r = b.recv(pkt)
    check("roundtrip", r == (0x11, b"\x11\x02\x03\x04", "ok"), repr(r))


def t_tamper_ct():
    a, b = make_pair(key=b"K" * 32)
    pkt = bytearray(a.send(b"hello world"))
    m = bytearray(pkt); m[-2] ^= 0xFF          # flipar byte del ciphertext
    r = b.recv(bytes(m))
    check("tamper ciphertext -> integrity", r[-1] == "integrity", r[-1])


def t_tamper_tag():
    a, b = make_pair(key=b"K" * 32)
    pkt = bytearray(a.send(b"hello"))
    m = bytearray(pkt); m[-1] ^= 0x33           # flipar tag
    r = b.recv(bytes(m))
    check("tamper tag -> integrity", r[-1] == "integrity", r[-1])


def t_tamper_seq():
    """Cambiar seq en header -> AAD cambia -> tag falla."""
    a, b = make_pair(key=b"K" * 32)
    pkt = bytearray(a.send(b"hello"))
    m = bytearray(pkt); m[15] ^= 0x55
    r = b.recv(bytes(m))
    check("tamper seq (header) -> integrity", r[-1] == "integrity", r[-1])


def t_tamper_nonce():
    a, b = make_pair(key=b"K" * 32)
    pkt = bytearray(a.send(b"hello"))
    m = bytearray(pkt); m[5] ^= 0x11
    r = b.recv(bytes(m))
    check("tamper nonce -> integrity", r[-1] == "integrity", r[-1])


def t_wrong_key():
    a, b = make_pair(key=b"K" * 32)
    c = C5Link(key=b"X" * 32, session_nonces=dict(b.session_nonces))
    pkt = a.send(b"hello")
    r = c.recv(pkt)
    check("wrong key -> integrity", r[-1] == "integrity", r[-1])


def t_replay():
    a, b = make_pair(key=b"K" * 32)
    pkt = a.send(b"hello")
    check("first accept", b.recv(pkt)[-1] == "ok")
    check("replay (dup seq) -> replay", b.recv(pkt)[-1] == "replay")


def t_old_seq():
    a, b = make_pair(key=b"K" * 32)
    for i in range(200):                      # high llega a 199
        b.recv(a.send(b"x"))
    r = b.recv(craft(a, 1, 0, b"old"))        # seq 0 << high-64
    check("seq fuera de ventana (viejo) -> replay", r[-1] == "replay", r[-1])


def t_gap():
    a, b = make_pair(key=b"K" * 32)
    for i in range(10):                        # high = 9
        b.recv(a.send(b"x"))
    r = b.recv(craft(a, 1, 100, b"jump"))     # seq 100 > high+64
    check("seq jump (gap) -> gap", r[-1] == "gap", r[-1])


def t_out_of_order_in_window():
    a, b = make_pair(key=b"K" * 32)
    p0 = a.send(b"0")
    p1 = a.send(b"1")
    p2 = a.send(b"2")
    r1 = b.recv(p1)
    r2 = b.recv(p2)
    check("out-of-order p1 then p2 ok", r1[-1] == "ok" and r2[-1] == "ok", (r1[-1], r2[-1]))


def t_integrity_of_plain():
    """La misma secuencia de bytes no debe colisionar: distintos plaintexts -> distintos ct."""
    a, _ = make_pair(key=b"K" * 32)
    c1 = a.send(b"\x00"*8, pkt_type=1)
    a._counter[0] = 0                          # reset para mismo seq
    c2 = a.send(b"\x00"*8, pkt_type=2)
    check("different pkt_type -> different packet", c1 != c2)


def main():
    t_roundtrip(); t_tamper_ct(); t_tamper_tag(); t_tamper_seq(); t_tamper_nonce()
    t_wrong_key(); t_replay(); t_old_seq(); t_gap(); t_out_of_order_in_window()
    t_integrity_of_plain()
    print(f"\n=== {PASS} PASS, {FAIL} FAIL ===")
    raise SystemExit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
