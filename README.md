# MU Online - Ingenieria Inversa del Protocolo de Red

Investigacion y herramientas de analisis pasivo del protocolo de red de **MU Online** (version oficial Webzen `1.15.14`).

Este proyecto documenta la estructura del trafico, el sistema de transporte y los esquemas criptograficos utilizados por el cliente oficial sin interactuar con la memoria del proceso ni disparar alertas de GameGuard.

---

## 1. Arquitectura del Binario y Subsistemas de Red (Hallazgos REA/Ghidra)

El analisis estatico con Ghidra sobre los binarios del juego arrojo la siguiente arquitectura:

| Archivo | Rol / Proteccion | Hallazgos de Ingenieria Inversa |
|---|---|---|
| `main.exe` (~33 MB) | Ejecutable principal | Empaquetado con **Themida** (secciones `.themida` de 41 MB y `.boot` de 23 MB). Solo expone 23 procedimientos estaticos de arranque. La logica de juego y encriptacion de paquetes reside en memoria virtual desempaquetada. |
| [wsctlcd.dll](file:///C:/Program%20Files%20(x86)/Webzen/Mu/wsctlcd.dll) | Socket Client Wrapper (`CWsctlc`) | **No empaquetado**. Implementa el transporte TCP nativo (`WS2_32.DLL::send` y `recv`). Su descompilacion revelo que en `CWsctlc::nRecv` solo reconoce paquetes en claro con encabezados `0xC1` y `0xC2`; los paquetes protegidos son procesados en capas superiores por `main.exe`. |
| [wzCipher.dll](file:///C:/Program%20Files%20(x86)/Webzen/Mu/wzCipher.dll) | Verificador de Integridad | Solo exporta `GetCRC32(key, path)`; valida archivos del cliente contra un GUID estatico (`AA840-5397-40b7-BDDF-6582A52E293`) para el sistema de parches. No cifra trafico de red. |
| [Enc1.dat](file:///C:/Program%20Files%20(x86)/Webzen/Mu/Data/Enc1.dat) / [Dec2.dat](file:///C:/Program%20Files%20(x86)/Webzen/Mu/Data/Dec2.dat) | Archivos de Claves Criptograficas | Archivos de 54 bytes en `Data\`. Almacenan matrices de 12 enteros (`uint32`) enmascarados con una clave estatica `XOR` (`0x3F08A79B`, etc.). Proveen las claves de multiplicacion, modulo y XOR. |

---

## 2. Hallazgos del Trafico de Red (Captura en Vivo)

A traves de la captura pasiva en la tarjeta Wi-Fi (`192.168.1.148`), se identifico la conexion al GameServer oficial:
* **IP del Servidor**: `139.5.226.87` en el puerto TCP **`55903`**.
* **Trafico auxiliar**: `139.5.226.192:443` (HTTPS para autenticacion, launcher y servicios web).

### Estadisticas de la Sesion (678 Segmentos TCP Reensamblados)

* **Total de Paquetes**: 680 paquetes de juego extraidos sin perdida ni desfase de bytes:
  * **Cliente -> Servidor (193 paquetes)**:
    * `38` paquetes `0xC1` (comandos ligeros, sincronizacion como `Opcode 0x42`).
    * `155` paquetes `0xC3` (acciones de juego protegidas).
  * **Servidor -> Cliente (487 paquetes)**:
    * `392` paquetes `0xC1` (sincronizacion de movimiento de entidades `0x5A`, ticks de tiempo `0x0F`, estados de inventario `0xB1`).
    * `47` paquetes `0xC2` (difusion masiva del entorno).
    * `48` paquetes `0xC3` (respuestas cifradas del servidor).

### Extraccion de Entidades del Mundo en Claro (`0xC2`)
Los paquetes `0xC2` viajan sin cifrado por bloques. A partir de la captura se extrajeron de forma transparente:
* **Nombres de personajes en el campo visual**: ----
* **Tiendas personales activas**: Mensajes de broadcast como `"VERY VERY LOW PRICE / FRUITS / SIGN OF LORD"`.

---

## 3. Estructura y Criptografia del Protocolo

### A. Paquetes en Claro (`0xC1` y `0xC2`)
* **`0xC1`**: Encabezado de 2 bytes (`[0xC1, Longitud]`), longitud maxima de 255 bytes.
* **`0xC2`**: Encabezado de 3 bytes (`[0xC2, LongitudHi, LongitudLo]`), longitud maxima de 65535 bytes.
* **Ofuscacion XOR32**: En paquetes salientes del cliente se aplica una rotacion XOR acumulativa de 32 bytes para prevenir manipulacion trivial. Modulo: [packets.py](file:///c:/Repositorios/mu-reverse/mu_proto/packets.py).

### B. Paquetes Cifrados (`0xC3`)
* **Diferencia con Season 6 clasica**: El algoritmo historico *SimpleModulus* expandia bloques de 8 bytes en 11 bytes de texto cifrado.
* **Comportamiento en version moderna (`1.15.14`)**:
  El cliente utiliza un cifrador por bloques de **64 bits (8 bytes)** con sufijo indicador de relleno:
  $$\text{Longitud Total} = 3 + (8 \times N)$$
  * Se observaron paquetes con longitudes exactas de **11, 19, 27, 35 y 59 bytes** ($N = 1, 2, 3, 4, 7$ bloques de 8 bytes).
  * **Ultimo byte (`p[-1]`)**: Contiene el tamano de relleno (*padding size*) o bytes reales del ultimo bloque (valores entre `0` y `7`).

---

## 4. Uso de las Herramientas

### Requisitos
* Python 3.10 o superior (solo libreria estandar, sin dependencias externas).
* Wireshark (para captura pasiva).

### Analizar una Captura
Para procesar un archivo de trafico `.pcapng` o `.pcap`:

```powershell
python analyze_pcap.py trafico.pcapng
```

El script:
1. Reensambla los flujos TCP bidireccionales segun numero de secuencia y puertos.
2. Identifica la frontera de cada paquete (`0xC1`-`0xC4`).
3. Mapea opcodes conocidos (movimiento, chat, NPCs, viewport, ticks de sincronizacion).
4. Extrae automaticamente cadenas de texto, nombres de personajes y anuncios en el viewport.

---

## 5. Estructura del Codigo

```text
c:\Repositorios\mu-reverse\
├── analyze_pcap.py            # CLI principal para diseccionar capturas
├── mu_proto\
│   ├── __init__.py
│   ├── pcap.py                # Lector nativo de formatos PCAP y PCAPNG
│   ├── packets.py             # Framing de paquetes MU y tabla XOR32
│   └── simple_modulus.py      # Implementacion del cifrado modular y lector de claves .dat
├── .gitignore                 # Excluye capturas de trafico, temporales y binarios
└── README.md                  # Documentacion tecnica del protocolo
```
