# C3 Cipher — Running Findings Log

> Passive analysis of `wireshark_Wi-FiIVW3W3.pcapng`, stream
> `139.5.226.87:55903 ↔ 192.168.1.148:55612`. No live injection, no GameGuard bypass.
> One line per hypothesis (what tried / observed / result).

## Extraction (verified)
- **Framing:** C3 = `[0xC3, total_len(1 byte)] [8N ciphertext] [pad byte]`, total = 2 + 8N + 1 = 3 + 8N; last byte = pad ∈ 0..7.
  *Observed:* C2S splits **193 packets, 0 bytes remainder** (155 C3 + 38 C1, matches threat model). C2S C3 lengths {11,19,27}; S2C C3 {11,19,35,59}. Pad bytes all in 0..7. C1/C2 clear (XOR32 NOT active — confirmed by readable opcodes 0x42/0x5A/0x0F and ASCII character names in S2C C1).
- **Streams:** C2S = 2248 B (188 segments), S2C = 13482 B (243 segments). S2C has 5 C3 packets (offsets 0x12C, 0x3AC, 0x3EC, 0x654, 0x913) interleaved with clear C1 (position sync 0x5A, tick 0x0F, char list 0x1E, char names 0xE7) and C2 broadcasts. C2S starts at login (first packet is a C3).

## Key files (confirmed)
- Enc1: mod=[128079,164742,70235,106898] key=[23489,11911,19816,13647] xor=[48413,46165,15171,37433]
- Dec2: mod=[73326,109989,98843,171058] key=[18035,30340,24701,11141] xor=[62004,64409,35374,64599]
- Note: mod values are **17–18 bits** (e.g. 128079 = 0x1F4B7, 171058 = 0x28F9A) → `A*key % mod` yields 17–18-bit results. **Cannot fit 4 of them into 64 bits.** Key parity: Enc1 key[2]=19816 even; Dec2 key[1]=30340 even → no modular inverse mod 0x10000 for all 4 slots.

## Hypotheses
1. **Public SimpleModulus (18-bit packing, 11-byte blocks):** FAIL. Body is 8N, never 11N (verified: 100% of C3 reject).
2. **Framing as `[0xC3, len_hi, len_lo, body]` (3-byte header, 16-bit len):** FAIL to parse (0 packets C2S). Correct framing is 1-byte total len (see extraction).
3. **Same SimpleModulus math + 4×16-bit LE/BE packing, raw modulus, direct/inv decryption, chain on/off, xor-on/off, prev=dec/w (step2/step3):** FAIL — 0 anchor hits (B1[0]∈{F1,F4,F3} ∧ B2.lastword==0) and 0 ASCII>0.75. **Expected failure cause:** 17–18-bit enc values don't fit 16-bit words; ciphertext top-bits confirm 17–18-bit values (e.g. 0x80A0, 0xE76F).
4. **Broad grid (in step4b_score.py):** modulus ∈ {file mod, 0x10000, file mod & 0xFFFF}, key×dec or inv(key)×dec, × LE/BE × chain × xor × prev. **Running / scoring by total ASCII bytes over all C3 packets per direction.**

## Login-phase anchor expectations
- C2S first C3 (`c3 13 ... 05`, 2 blocks, pad=5) = **login request**, expected plaintext `[0xF1] + 12-byte account` (13 B, last block last word = 0x0000 padding).
- C2S 11-byte C3 × many (pad 1–6) = short encrypted client actions; C1 between them = 0x42 ops.
- S2C C3 = server login/character responses (interleaved with clear char-name C1 0xE7).

## Open questions
- Where is the 8-byte block transform? If enc values are 17–18 bits, the block may pack them overlapping, or the math differs from `A*key % mod` (different modulus base, no modulus, XOR-based, or the .dat constants map to different roles than mod/key/xor).
- Which direction uses which file (Enc1=enc, Dec2=dec, or swapped)?
- Is there a per-session key exchange (any non-.dat values in the login C3)?

## Status
**BLOCKED on step 4:** brute grid still searching. Next: read step4b_score results; if still no ASCII peak, next hypothesis = (a) block packs 4×18-bit values with 8-bit overlap/drop of MSB, (b) math uses `& 0xFFFF` truncation after `% mod` (lossy but client-side deterministic), (c) constants remapped (e.g. xor used as modulus), (d) inspect wsctlcd.dll / wzCipher.dll / themida strings for cipher hints.
