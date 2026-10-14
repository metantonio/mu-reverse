# Threat Model — Cliente Mu (Webzen 1.15.14) + GameGuard + Servidor oficial

> **v0.2** — Aterrizado en la **captura real** (`wireshark_Wi-FiIVW3W3.pcapng`) y en el
> cliente/binario real (`C:\Program Files (x86)\Webzen\Mu`). Enfoque **defensivo**:
> superficie de ataque + contramedidas. No se construye un evadir *deployable*.

---

## 1 · Evidencia de la captura (lo que medimos)

**Flujo:** `139.5.226.87:55903 ↔ 192.168.1.148:55612` — 678 segmentos TCP, 1 stream MU.
**C2S (193 pkt):** `C1:38`, `C3:155`.  **S2C (487 pkt):** `C1:392`, `C2:47`, `C3:48`.

| Canal | Header | Estado en el wire |
|---|---|---|
| **C1** | 2 byte `[0xC1, len≤255]` | **EN CLARO** (sin cripto observado). S2C muestra opcodes legibles: `0x2A, 0x83, 0x5A (movimiento), 0x0F (tick)`. C2S muestra `0x42`. |
| **C2** | 3 byte `[0xC2, hi, lo]` | **EN CLARO** — broadcast (nombres, tiendas, entorno). |
| **C3** | 2 byte `[0xC3, len]` + `8N` ct + 1 pad byte | **Cifrado custom 8-byte** (ver abajo). |

### 1a · C3 = cifrador CUSTOM, NO el SimpleModulus público
- **Framing confirmado:** `[0xC3, len(1B)] [8N ciphertext] [pad(1B)]`, total `= 3 + 8N`.
  C2S C3 `{11,19,27}` → `{2+8·1+1, 2+8·2+1, 2+8·3+1}` ✓; S2C `{11,19,35,59}` ✓.
- El último byte = *bytes reales del último bloque* (0..7) (ej. 19B ⇒ 2 blocks ⇒ 13 bytes real).
- **Contraste SimpleModulus público (OpenMU):** expande **8→11 bytes**.
  La captura **nunca** muestra cuerpos múltiplos de 11.
- **Clave observada:** los `mod` del `.dat` son de **17–18 bits** (p. ej. 128079=0x1F4B7,
  171058=0x28F9A). `A·key % mod` ⇒ valores de 17–18 bits ⇒ **no encajan en 4×16-bit** (64 bits
  por bloque de 8). Esto explica por qué el SimpleModulus-math 4×16-bit falla: los top-bits del
  ciphertext confirman valores de 17–18 bits (0x80A0, 0xE76F).
- **Consecuencia:** el `mu_proto/simple_modulus.py` del repo **NO descifra el build 1.15.14**
  (verificado: **100% de los C3 fallan** con las claves `.dat`). El tooling está **desactualizado**;
  el README lo admite ("Not verified against the current Webzen client").
- **Reversión en curso** (subagente, `c3/findings.md`): hipótesis activas = (a) 3 valores/bloque
  17–18 bits con overlap, (b) cipher de stream (keystream LCG/Feistel), (c) `.dat` remapeados,
  (d) **decompilar `wsctlcd.dll`** (no packed), (e) **anchor de plaintext conocido** en el login
  (`0xF1` + 12-byte account).

### 1b · Claves ESTÁTICAS, dentro del cliente
- `Enc1.dat` / `Dec2.dat` (54 bytes) en `Mu\Data\`: sig `0x1112`, 12 × uint32, enmascaradas
  con un `FILE_XOR` estático. Proveen `modulus / key / xor`.
- Ejemplo (`Enc1`): `mod=[128079,164742,70235,106898] key=[23489,11911,19816,13647]`.
- Son **claves fijas del cliente**: cualquiera con el instalador tiene las claves.
- **No se observó intercambio de claves por sesión** en la captura (a confirmar en login).

### 1c · La capa "XOR32" NO aparece aplicada
- El código define una cadena XOR de 32 bytes para C1/C2 *saliente*, pero el flujo real
  muestra **C1 legible en crudo** (opcodes limpios sin des-XOR). La ofuscación XOR32 **no
  está activa** en este build (o no está siendo aplicada al C1 del cliente) — **por confirmar**.

### 1d · El servidor manda la posición del jugador EN CLARO
- S2C C1 `0x5A` (Movement/Position Sync) es **legible sin cifrar**. El cliente reporta
  posición e el servidor la retransmite/acepta en C1. → **Brecha de server-authoritative.**

---

## 2 · Activo / Actuario

**Ataquénte:** local (controla la máquina del cliente, proceso corriendo), persistente, acceso a
memoria/proceso y red. Interés: gold / XP / items / posición.
> Consecuencia: la frontera **no puede depender del cliente**.

---

## 3 · Superficie de ataque
| Componente | Qué puede manipular |
|---|---|
| Proceso cliente | memoria, funciones, imagen |
| GameGuard | driver + checks de integridad |
| Canal cliente↔servidor | paquetes C1 (claro), C3 (custom) |
| Servidor | validación, estado, economía |

---

## 4 · Amenazas por vector (evidencia → contramedida)

| # | Vector | Evidencia | Debilidad | Impacto | Contramedida |
|---|---|---|---|---|---|
| **V1** | **Inyección/falsificación de C1** | C1 en claro, sin MAC. S2C 0x5A/0x0F legibles | Canal sin integridad ni confidencialidad; easy MITM/local | **CRÍTICO** | **Server-authoritative**; C1 = *intento*, no afirmación |
| **V2** | **Falsificación de C3** | C3 custom, claves **estáticas** | Claves en el cliente ⇒ attacker las tiene; cripto no verificado | **CRÍTICO** | Reemplazar C3 por **AEAD estándar** con claves por sesión |
| **V3** | **Replay / inyección** | No hay nonces/MAC/seq visibles | Sin protección anti-replay | Alto | AEAD (incluye tag) + nonces + ventana replay |
| **V4** | **Confianza del servidor en el cliente** | Servidor retransmite posición 0x5A del cliente | No re-simula; acepta estado del cliente | **CRÍTICO** | Server-authoritative + re-simulación física/económica |
| **V5** | **Bypass de integridad de GameGuard** | GameGuard es client-side | Un check client-side es desactivable por un local attacker | Medio | GameGuard = **early-warning** (alert/ban), no la pared; la pared es el servidor |
| **V6** | **Tamper/reemplazo de la imagen** | `main.exe` empaquetado (Themida) | Sin attestation fuerte del cliente | Alto | Code-signing + attestation en servidor |
| **V7** | **Falta de detección de anomalías** | C1/C2 en claro; el cheat es "invisible" al integridad | Solo se detecta por integridad (desactivable) | Alto | **Anomalías en servidor** (física, tasas, economía) |

---

## 5 · Hallazgo clave (no cambia)
> La única frontera que no se puede evadir es **el servidor**. El C3 "protegido" en realidad
> tiene **claves estáticas en el cliente** y un **cifrador custom no verificado** ⇒ no es una
> frontera. El C1 **está en claro**. GameGuard, por ser client-side, es **deterrente/avisos**,
> no garantía de justicia.

**Presupuesto:** la mayor parte va a **server-authoritative + reemplazo del cripto**, no a
"vencer" GameGuard en el cliente.

---

## 6 · Contramedidas priorizadas (aterrizar en evidencia)

| Pri | Acción | Neutraliza |
|---|---|---|
| **P0** | **Server-authoritative:** cliente manda *intentos*; servidor re-simula (física, economía) y rechaza estado inconsistente. Desconfiar de 0x5A/0x0F/0x42 del cliente. | V1, V4 |
| **P0** | **Reemplazar C3:** AEAD estándar (**AES-256-GCM** o **ChaCha20-Poly1305**), **claves por sesión** (key exchange / TLS / server-challenge). Eliminar `.dat` estáticos. | V2, V3 |
| **P1** | **Anti-replay + MAC + nonces + ventana:** secuencia por sesión, tag de AEAD. | V3, V4 |
| **P1** | **Deteción de anomalías en servidor:** velocidad/energía, tasas de items/moneda, economía, timing. (Indispensable: C1/C2 están en claro.) | V7 |
| **P2** | **Tratar el cripto C3 actual como comprometido** (custom = asumir roto). No basar seguridad en él. | V2 |
| **P2** | **Attestation + code-signing** del cliente + `GameGuard` como early-warning. | V5, V6 |
| **P2** | **Fix tooling:** `simple_modulus.py` es *stale* (no es 1.15.14). El equipo necesita el algoritmo real del C3 o —mejor— dejar de depender de él. | — |

---

## 7 · Alcance / límites
Este proyecto cubre **análisis pasivo** del protocolo (captura, documentación) y **diseño de
contramedidas / endurecimiento**. **No** se construye: (a) una herramienta de **inyección de
paquetes live** para alterar el estado en el servidor oficial, ni (b) un **bypass activo de
GameGuard**. El objetivo defensivo es que *ningún* vector (V1–V7) quede viable sin ser detectado.

---

## 8 · Próximos pasos
1. **Validar el login:** confirmar si hay intercambio de claves por sesión (pasear los C3 de
   login/`0xF4`/`0xF1` descifrados) o si son solo las `.dat` estáticas.
2. **Characterizar el C3 real** (propiedades: bloques de 8, padding, constantes) *para saber*
   que es custom y justificar el reemplazo — **no** para fabricar un inyectador.
3. **Diseñar el key exchange + AEAD** (P0): el reemplazo de C3.
4. **Lab/harness:** medir *tasa de detección* de las contramedidas (V1–V7) contra ataques
   simulados, en entorno aislado.
5. **Fix el tooling** del repo (`simple_modulus.py` stale).
