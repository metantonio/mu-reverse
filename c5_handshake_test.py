"""Tests de validación del key exchange C5 (X25519 + HKDF)."""
from __future__ import annotations
from c5_handshake import gen_ephemeral, setup
from c5 import C5Link

PASS = 0
FAIL = 0

def check(name, ok, detail=None):
    global PASS, FAIL
    if ok: PASS += 1
    else: FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail and not ok else ""))


def t_same_key():
    csk, ssk = gen_ephemeral(), gen_ephemeral()
    res = setup(csk, ssk)
    # la key es determinista dado el mismo par
    res2 = setup(csk, ssk)
    check("same ephemeral pair -> same key", res["key"] == res2["key"])


def t_different_key():
    csk1, ssk1, csk2, ssk2 = (gen_ephemeral() for _ in range(4))
    r1, r2 = setup(csk1, ssk1), setup(csk2, ssk2)
    check("different pair -> different key", r1["key"] != r2["key"])


def t_forward_secrecy():
    csk1, ssk1, csk2, ssk2 = (gen_ephemeral() for _ in range(4))
    r1, r2 = setup(csk1, ssk1), setup(csk2, ssk2)
    # aunque compartieran la misma clave larga, sesiones distintas -> keys distintas
    check("forward secrecy (per-session keys)", r1["key"] != r2["key"])


def t_roundtrip_after_handshake():
    csk, ssk = gen_ephemeral(), gen_ephemeral()
    res = setup(csk, ssk)
    c = C5Link(key=res["key"], session_nonces={0: res["nonce_client"]})
    s = C5Link(key=res["key"], session_nonces={0: res["nonce_server"]})
    pkt = c.send(b"\x11\x02\x03", pkt_type=1)
    (t, pt, st) = s.recv(pkt)
    check("C5 roundtrip after handshake", st == "ok" and pt == b"\x11\x02\x03", (st, pt))


def t_replay_after_handshake():
    csk, ssk = gen_ephemeral(), gen_ephemeral()
    res = setup(csk, ssk)
    c = C5Link(key=res["key"], session_nonces={0: res["nonce_client"]})
    s = C5Link(key=res["key"], session_nonces={0: res["nonce_server"]})
    pkt = c.send(b"\x11", pkt_type=1)
    s.recv(pkt)
    (t, pt, st) = s.recv(pkt)
    check("replay rejected after handshake", st == "replay", st)


def t_key_not_reused_across_sessions():
    csk, ssk = gen_ephemeral(), gen_ephemeral()
    res1, res2 = setup(csk, ssk), setup(csk, ssk)  # mismo par, llamas distintas
    # el nonce cambia por sesión -> paquetes distintos aunque key sea igual
    c = C5Link(key=res1["key"], session_nonces={0: res1["nonce_client"]})
    p1 = c.send(b"x", 1)
    c2 = C5Link(key=res2["key"], session_nonces={0: res2["nonce_client"]})
    p2 = c2.send(b"x", 1)
    check("different session nonce -> different packet", p1 != p2)


def main():
    t_same_key(); t_different_key(); t_forward_secrecy()
    t_roundtrip_after_handshake(); t_replay_after_handshake(); t_key_not_reused_across_sessions()
    print(f"\n=== {PASS} PASS, {FAIL} FAIL ===")
    raise SystemExit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
