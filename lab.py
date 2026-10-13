"""
LAB / HARNES — mide la TASA DE DETECCIÓN de las contramedidas contra ataques
simulados (opción C). Se apoya en los vectores del threat model (V1..V7).

Contramedidas probadas:
  * Server-authoritative  (posición: máx velocidad; oro: solo por transacción legítima)
  * Canal C5 = AES-256-GCM (integridad + anti-replay + inyección con key errada)
  * Detección de anomalías (tasa de oro)

Uso:      python lab.py
Salida:    matriz (OK/FAIL por ataque) + resumen de tasa global.
"""
from __future__ import annotations
import math
from c5 import make_pair

# ---------------------------------------------------------------------------
# Modelo de servidor AUTHORITY (la contramedida central)
# ---------------------------------------------------------------------------
class Server:
    """Servidor authoritative: el cliente manda INTENTOS; el servidor valida."""

    def __init__(self, max_speed: float = 10.0, gold_per_tick: int = 50):
        self.pos = [0.0, 0.0]
        self.gold = 0
        self.xp = 0
        self.max_speed = max_speed          # unidades por tick
        self.gold_per_tick = gold_per_tick
        self.ticks = 0
        self.c1_ignored = 0

    # --- movimiento (V1) ---
    def validate_move(self, target) -> bool:
        """Cliente afirma 'estoy aquí' (C1). Servidor valida contra máx velocidad.
        True = ACEPTADO (legítimo); False = RECHAZADO (spoof)."""
        d = math.dist(self.pos, list(target))
        self.ticks += 1
        if d > self.max_speed:
            return False
        self.pos = list(target)
        return True

    # --- economía (V4) ---
    def validate_gold(self, delta: int, source: str) -> bool:
        """Oro SÓLO por transacción legítima. source: {item, trade, quest, forge}."""
        legit = {"item", "trade", "quest"}
        if source not in legit:
            return False
        if source == "item" and delta > 1000:
            return False
        self.gold += delta
        return True

    # --- C1: intents no confiables (V6) ---
    def handle_c1_gold_intent(self, amount: int) -> None:
        """Un 'intent' C1 de oro NO cambia el oro (servidor no confía en C1)."""
        self.c1_ignored += 1
        # gold: sin tocar

    # --- anomalías (V7) ---
    def check_anomaly(self, gold_per_tick: int) -> bool:
        return gold_per_tick > self.gold_per_tick


# ---------------------------------------------------------------------------
# Canal C5 (defensa AEAD) -- reutilizamos c5.py
# ---------------------------------------------------------------------------
class C5Client:
    def __init__(self, key: bytes = b"K" * 32):
        self.a, self.b = make_pair(key=key)
    def send(self, plain, pkt_type):
        return self.a.send(plain, pkt_type)
    def recv(self, pkt):
        return self.b.recv(pkt)


# ---------------------------------------------------------------------------
# Ataques simulados
# ---------------------------------------------------------------------------
RESULTS = []

def run(name: str, fn, expect: str):
    """expect: 'detect' o 'accept'. Returns True si el comportamiento es CORRECTO."""
    got = fn()
    ok = bool(got)
    RESULTS.append((name, got))
    print(f"[{'OK' if ok else 'FAIL'}] {name}")


# --- V1: spoof de posición por C1 (en claro) ---
def atk_pos_spoof():
    s = Server(max_speed=10.0)
    return not s.validate_move([1000.0, 0.0])     # spoof -> rechazado

# --- V1b: movimiento legítimo SE ACEPTA (sin falsos positivos) ---
def atk_pos_ok():
    s = Server(max_speed=10.0)
    return s.validate_move([1.0, 2.0])            # legítimo -> aceptado

# --- V2: tamper de paquete C5 ---
def atk_c5_tamper():
    c = C5Client()
    pkt = bytearray(c.send(b"\x11\x02\x03", pkt_type=0x11))
    m = bytearray(pkt); m[-2] ^= 0xFF
    return c.recv(bytes(m))[2] == "integrity"

# --- V3: replay de paquete C5 ---
def atk_c5_replay():
    c = C5Client()
    pkt = c.send(b"\x11", pkt_type=0x11)
    c.recv(pkt)
    return c.recv(pkt)[2] == "replay"

# --- V3b: inyección de C5 con clave equivocada ---
def atk_c5_inject_wrong_key():
    c1 = C5Client(key=b"K" * 32)
    c2 = C5Client(key=b"X" * 32)          # clave DIFERENTE
    forged = c1.a.send(b"\x01", pkt_type=0x11)
    return c2.b.recv(forged)[2] == "integrity"

# --- V4: duplo de oro por transacción forjada ---
def atk_gold_fraud():
    s = Server()
    return not s.validate_gold(1_000_000, source="forge")

# --- V6: inyección de oro por C1 (el servidor la ignora) ---
def atk_gold_c1():
    s = Server()
    s.handle_c1_gold_intent(5000)
    return s.gold == 0 and s.c1_ignored == 1

# --- V7: anomalía de acumulación de oro ---
def atk_econ_anomaly():
    s = Server()
    return s.check_anomaly(999_999)

# ---------------------------------------------------------------------------
# Ejecutar
# ---------------------------------------------------------------------------
tests = [
    ("V1  spoof posición (C1 claro)      ", atk_pos_spoof),
    ("V1  movimiento legítimo aceptado   ", atk_pos_ok),
    ("V2  tamper paquete C5 (AEAD)       ", atk_c5_tamper),
    ("V3  replay paquete C5 (ventana)    ", atk_c5_replay),
    ("V3  inyección C5 (clave errada)    ", atk_c5_inject_wrong_key),
    ("V4  duplo de oro (forje)           ", atk_gold_fraud),
    ("V6  inyección oro por C1 (ignorado)", atk_gold_c1),
    ("V7  anomalía economía              ", atk_econ_anomaly),
]

print("=== LAB: contramedidas vs ataques simulados ===")
for name, fn in tests:
    run(name, fn, "detect")

det = sum(1 for _, ok in RESULTS if ok)
total = len(RESULTS)
print("\n=== RESUMEN ===")
print(f"Tasa global de comportamiento correcto: {det}/{total} = {100*det/total:.0f}%")
print("\nMatriz de vectores del threat model:")
for n, ok in RESULTS:
    print(f"  {n.strip():36} -> {'CORRECTO' if ok else 'INCORRECTO'}")

raise SystemExit(0 if det == total else 1)
