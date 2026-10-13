"""
C5: canal AEAD (AES-256-GCM) para paquetes de juego.
Implementación de referencia del reemplazo C3->AEAD (ver c3-replacement-design.md).

Framing:
    byte  0       : 0xC5
    byte  1..2    : len(ct)   (2B BE)   ct = ciphertext || 16B GCM tag
    byte 3..14    : nonce     (12B)    = session_nonce(8B) || seq[0:32]
    byte 15..22   : seq       (8B LE)
    byte 23       : pkt_type  (1B)
    byte 24..     : ct        (ciphertext || 16B tag)

AAD  = pkt_type(1B) || seq(8B LE) || stream_id(4B LE)
Key  = 32B  (HKDF-SHA256 de session_material; en prod session_material =
         handshake TLS o secreto ECDH; en el lab puede pasarse una key)
Nonce: único por (sesion, direccion) via 8B session_nonce aleatorio + 4B contador.
Ventana: el receptor acepta seq en [max_seen-63 .. max_seen+64]; rechaza replay y gaps.
"""
from __future__ import annotations
import os
import struct
from typing import Dict, Set, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

C5 = 0xC5
NONCE_LEN = 12
SESSION_NONCE_LEN = 8
SEQ_LEN = 8              # 64-bit seq, little-endian
TAG_LEN = 16
HDR_SIZE = 1 + 2 + NONCE_LEN + SEQ_LEN + 1   # = 24
WINDOW = 64


def make_aad(pkt_type: int, seq: int, stream_id: int) -> bytes:
    """AAD = pkt_type(1) || seq(8 LE) || stream_id(4 LE)."""
    return (bytes([pkt_type])
            + seq.to_bytes(SEQ_LEN, "little")
            + stream_id.to_bytes(4, "little"))


def derive_key(session_material: bytes, info: bytes = b"mu-c5-v1") -> bytes:
    """HKDF-SHA256 -> 32B. En prod, session_material viene del key exchange."""
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=b"mu-c5", info=info).derive(session_material)


class C5Link:
    """Una sesion: key + nonces compartidos, emisor + receptor."""

    def __init__(self, key: Optional[bytes] = None,
                 session_material: Optional[bytes] = None,
                 session_nonces: Optional[Dict[int, bytes]] = None):
        if key is None:
            key = derive_key(session_material or b"lab-session-material")
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self.key = key
        if session_nonces is None:
            session_nonces = {0: os.urandom(SESSION_NONCE_LEN)}
        self.session_nonces = dict(session_nonces)
        self._c = AESGCM(key)
        self._counter: Dict[int, int] = {}        # stream_id -> next seq (emisor)
        self._rx_high: Dict[int, int] = {}        # stream_id -> max seq aceptado
        self._rx_seen: Dict[int, Set[int]] = {}   # stream_id -> seqs en ventana

    def _nonce(self, seq: int, stream_id: int) -> bytes:
        sn = self.session_nonces.get(stream_id, self.session_nonces[0])
        return sn + (seq & 0xFFFFFFFF).to_bytes(4, "little")

    def send(self, plaintext: bytes, pkt_type: int = 0, stream_id: int = 0,
             seq: Optional[int] = None) -> bytes:
        if seq is None:
            seq = self._counter.get(stream_id, 0)
            self._counter[stream_id] = seq + 1
        nonce = self._nonce(seq, stream_id)
        aad = make_aad(pkt_type, seq, stream_id)
        ct = self._c.encrypt(nonce, plaintext, aad)     # ct = ciphertext||tag
        return (bytes([C5])
                + struct.pack(">H", len(ct))
                + nonce
                + seq.to_bytes(SEQ_LEN, "little")
                + bytes([pkt_type])
                + ct)

    def recv(self, packet: bytes, stream_id: int = 0) -> Tuple[Optional[int], bytes, str]:
        """Devuelve (pkt_type, plaintext, status). status in {ok, integrity, replay, gap, bad}."""
        if len(packet) < HDR_SIZE + TAG_LEN or packet[0] != C5:
            return None, b"", "bad"
        ct_len = struct.unpack(">H", packet[1:3])[0]
        if ct_len < TAG_LEN:
            return None, b"", "bad"
        nonce = packet[3:3 + NONCE_LEN]
        seq = int.from_bytes(packet[15:23], "little")
        pkt_type = packet[23]
        ct = packet[24:24 + ct_len]
        aad = make_aad(pkt_type, seq, stream_id)
        # --- integridad (AEAD tag) ---
        try:
            pt = self._c.decrypt(nonce, ct, aad)
        except Exception:
            return None, b"", "integrity"
        # --- anti-replay (ventana) ---
        high = self._rx_high.get(stream_id)
        if high is None:
            self._rx_high[stream_id] = seq
            self._rx_seen[stream_id] = {seq}
            return pkt_type, pt, "ok"
        low = high - WINDOW
        if seq < low:
            return None, b"", "replay"          # demasiado viejo
        if seq > high + WINDOW:
            return None, b"", "gap"             # desorden fuera de ventana
        seen = self._rx_seen.get(stream_id, set())
        if seq in seen:
            return None, b"", "replay"          # duplicado
        self._rx_seen.setdefault(stream_id, set()).add(seq)
        if seq > high:
            self._rx_high[stream_id] = seq
        return pkt_type, pt, "ok"


def make_pair(key: Optional[bytes] = None,
              session_material: bytes = b"lab-session-material") -> Tuple[C5Link, C5Link]:
    """Crean emisor+receptor que comparten key y session_nonces (simula setup)."""
    key = key if key is not None else derive_key(session_material)
    sn = {0: os.urandom(SESSION_NONCE_LEN)}
    return C5Link(key=key, session_nonces=dict(sn)), C5Link(key=key, session_nonces=dict(sn))
