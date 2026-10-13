# Diseño del reemplazo C3 → AEAD (contramedida P0)

> Objetivo: sustituir el canal C3 (cifrador custom 8-byte, claves estáticas, sin AEAD) por
> un canal **autenticado, íntegro, confidencial, con forward secrecy**. Neutraliza los vectores
> **V2, V3** del threat model. Documentación de diseño — se validará en el lab (opción C).

## 1 · Amenazas a resolver (de la evidencia)
- Claves **estáticas** en `.dat` del cliente ⇒ cualquier atacante local tiene las claves.
- Cripto **custom**, no verificado ⇒ asumiendo roto.
- Sin **AEAD** (sin tag de autenticación) ⇒ sin protección contra modificación.
- Sin **intercambio por sesión** (por confirmar en A) ⇒ sin forward secrecy.
- C1/C2 **en claro** ⇒ el canal C3 "seguro" no protege lo que va en C1/C2.

## 2 · Principio: la cripto protege el *canal*, NO el *estado*
Aunque el canal sea perfecto, si el servidor **confía en el estado que manda el cliente**
(V1/V4), la cripto no sirve. El reemplazo C3→AEAD es **necesario pero no suficiente**:
debe ir acompañado de **server-authoritative**. (Ver threat model, secciones 5 y V4.)

## 3 · Establecimiento de claves (key exchange)

### 3a · Recomendado: **TLS (TLS 1.3)**
- Envolver el canal de juego en TLS sobre el TCP existente (o un handshake aparte).
- El **certificado del servidor** autentica al servidor ⇒ previene MITM.
- TLS 1.3 da: intercambio ECDHE (forward secrecy), AEAD (AES-GCM/ChaCha20-Poly1305),
  integridad de todos los bytes, y protección contra replay por diseño.
- Menor código a auditar, cripto auditado por el ecosistema TLS.
- **Mejor opción.** Si el cliente puede hablar TLS, úsalo.

### 3b · Alternativa (si no puede haber TLS): **ECDH + autenticación + AEAD**
1. **Ephemeral ECDH** (P-256 o X25519): cliente y servidor intercambian claves públicas
   efímeras.
2. **Autenticar** la clave efímera del servidor (la firma con la clave larga del servidor):
   SIN esto, ECDH por sí solo **NO** previene MITM.
3. **Derivar** la sesión con HKDF (input: clave compartida ECDH + salts + transcript).
4. **AEAD** (sección 4) sobre la sesión.
- ECDH **efímero** ⇒ forward secrecy.
- **No** reutilizar la clave efímera: nueva sesión ⇒ nuevo ECDH.

> **No recomendado:** server-challenge con `client_secret` estático: no da forward secrecy y
> `client_secret` es extraíble del cliente.

## 4 · AEAD

| | AES-256-GCM | ChaCha20-Poly1305 |
|---|---|---|
| Seguridad | 256 bits | ~128 bits (suficiente) |
| Velocidad | muy alta (AES-NI) | alta (software-only) |
| Nonce | 12 bytes | 12 bytes |
| Tag | 16 bytes | 16 bytes |

- **AES-256-GCM** (recomendado, si hay AES-NI): 32-byte key, 12-byte nonce, 16-byte tag.
- **ChaCha20-Poly1305** (alternativa): 32-byte key, 12-byte nonce, 16-byte tag.
- **Nonce**: 96 bits, **monotónico por dirección** (no reutilizar jamás el mismo nonce con
  la misma key ⇒ colisión ⇒ catastrófica en GCM). Inicializar de un valor aleatorio 96 bits
  por sesión + contador, o derivado del ECDH.
- **AAD (Associated Auth Data):** incluir `pkt_type`, `seq` y `stream_id` en el AAD.
  Esto hace que una modificación de `seq` o `pkt_type` falle la autenticación.

## 5 · Anti-replay (protección contra replay)

- **Secuencia monotónica por dirección** (64 bits): el servidor y el cliente envían cada
  paquete con su `seq`. El AAD incluye `seq`.
- **Ventana de aceptación:** el receptor acepta `seq ∈ [last, last+W]` (W ≈ 64).
  - `seq < last-W` ⇒ **rechazar** (replay).
  - `seq > last+W` ⇒ **gap** (retransmisiones); rechazar por seguridad y pedir reenvío.
- Alternativa: usar el **nonce GCM como secuencia** (el nonce es único por sesión/dirección),
  lo que da anti-replay por diseño.

## 6 · Nuevo framing (reemplazo de C3)

```
[0xC5] [len: 2B] [nonce: 12B] [ciphertext] [tag: 16B]
```
- `len` = longitud del `ciphertext` (el tag no cuenta / o sí, definir).
- **Sin padding indicator** (AEAD no necesita padding: la longitud se sabe del framing y se
  autenticada).
- Repropósito de `0xC5` = "AEAD-encrypted" (o reutilizar `0xC3` para AEAD y retiras el
  custom). Definir en el nuevo protocolo.
- **C1/C2:** idealmente también van por el canal AEAD (o al menos reciben integridad).
  Si se dejan en claro, **mantiene la debilidad V1**. (Ver P0 server-authoritative + P1
  integridad en C1/C2.)

## 7 · Autenticación y MITM
- **TLS:** el cert del servidor ⇒ el cliente valida la identidad ⇒ MITM bloqueado.
- **ECDH:** firma de la clave efímera por la clave larga del servidor ⇒ MITM bloqueado.
- En ambos: el cliente **debe** validar el servidor (no confiar en un "cualquiera").

## 8 · Forward secrecy
- Claves efímeras (TLS 1.3 / ECDH) ⇒ aunque el atacante extraiga las claves `.dat` o el
  `client_secret` del cliente, **no puede descifrar sesiones pasadas ni futuras** (solo la
  sesión en curso, y solo si también tiene la clave efímera).

## 9 · Migración (dual-mode)
1. El servidor acepta **C3 (viejo)** y **C5 (nuevo, AEAD)** por un periodo.
2. El cliente nuevo prefiere **C5**; el viejo sigue con C3.
3. Lograr la transición: forzar C5 (depreciar C3) en la siguiente versión.
4. Durante dual-mode: el **server-authoritative** debe aplicar a C5 desde el inicio.

## 10 · Validación (enlaza con opción C — lab/harness)
- **Correctitud:** descifrar/verificar AEAD con claves conocidas; inyectar bit-flips ⇒ tag
  falla.
- **Anti-replay:** reenviar paquetes con `seq` viejos ⇒ rechazados.
- **MITM:** un proxy que reescribe `pkt_type`/`seq`/`nonce` ⇒ autenticación falla.
- **Performance:** AEAD + TLS a la tasa de paquetes del juego (≈ decenas/paquete por segundo,
  bien dentro de las capacidades).
- **Tasa de detección:** el lab mide que cualquier ataque V1–V7 queda detectado/rechazado.

## 11 · Resumen de decisiones
| Decisión | Opción | Justificación |
|---|---|---|
| Key exchange | **TLS 1.3** (primario) / ECDH+autenticación (alt.) | Auth + forward secrecy + cripto auditado |
| AEAD | **AES-256-GCM** / ChaCha20-Poly1305 | Autenticación + integridad + confidencialidad |
| Anti-replay | `seq` 64 bits + ventana, o nonce-secuencia | Anti-replay por diseño |
| AAD | `pkt_type` + `seq` + `stream_id` | Integridad de metadatos |
| Framing | Nuevo `0xC5`, 12B nonce, sin padding | AEAD nativo |
| C1/C2 | **Mover al canal AEAD** (o al menos integridad) | Cerrar la debilidad V1 (claro) |
| Server-authoritative | **Obligatorio** (P0) | La cripto no salva un servidor que confía en el cliente |
