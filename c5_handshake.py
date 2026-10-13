"""
Key exchange para el canal C5 (rama ECDH de c3-replacement-design.md).
X25519 efímero -> secreto compartido -> HKDF-SHA256 -> session key (32B).

Notas de seguridad:
  * FWD SECRECY: clave efímera, no reutilizada por sesión.
  * Autenticación de la clave efímera del servidor: en prod con signatura
    (Ed25519) o envuelto en TLS. Aquí NO se firma (focus en DH + HKDF);
    ver c3-replacement-design.md §3b / §7.
"""
from __future__ import annotations
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey, X25519PrivateKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEX_SALT = b"mu-c5-kex-salt"
KEX_INFO = b"mu-c5-kex-v1"
NONCE_LEN = 8


def _hkdf(session_secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=KEX_SALT, info=info).derive(session_secret)


def gen_ephemeral() -> X25519PrivateKey:
    """Par efímero X25519 (nuevo por sesión)."""
    return X25519PrivateKey.generate()


def pub_bytes(sk) -> bytes:
    """Clave pública de 32 bytes (raw, para envío)."""
    return sk.public_key().public_bytes_raw()


def setup(client_sk, server_sk) -> dict:
    """Handshake completo (lab: tenemos ambas claves privadas).
    En prod: el cliente solo recibe `server_sk`'s public key bytes.
    """
    server_pub_obj = server_sk.public_key()
    client_pub_obj = client_sk.public_key()
    ss_c = client_sk.exchange(server_pub_obj)   # lado cliente
    ss_s = server_sk.exchange(client_pub_obj)   # lado servidor
    assert ss_c == ss_s, "mismatch en secreto compartido"
    key = _hkdf(ss_c, info=KEX_INFO)
    return {
        "key": key,
        "nonce_client": os.urandom(NONCE_LEN),
        "nonce_server": os.urandom(NONCE_LEN),
    }


def client_from_pub_bytes(client_sk, server_pub_bytes) -> bytes:
    """Lado cliente real: solo tiene su privada + las public bytes del servidor."""
    server_pub_obj = X25519PublicKey.from_public_bytes(server_pub_bytes)
    ss = client_sk.exchange(server_pub_obj)
    return _hkdf(ss, info=KEX_INFO)
