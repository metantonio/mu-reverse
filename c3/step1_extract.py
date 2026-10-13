"""STEP1 (v2): Extract the MU stream from the pcap, split into packets with the CORRECT
C3 framing found on the data, and dump ALL packets.

Framing discovered (from C2S stream, verified):
  C1: [0xC1, total_len]          total_len 1 byte, total = total_len (C1 header 2 bytes)
  C2: [0xC2, len_hi, len_lo, ..] total = 3 + len16
  C3: [0xC3, total_len]          total_len 1 byte == TOTAL packet length
                                 followed by 8N ciphertext bytes then 1 padding byte
                                 (total = 2 + 8N + 1 = 3 + 8N)
  last byte of packet = padding, observed 0..7.

The earlier session wrote header = [0xC3, len_hi, len_lo] (3 bytes, 16-bit len).
On the data: byte[1] = total length (1 byte). Both the "3+8N" total and the
last-byte=padding hold under this framing. We try block offsets 2 and 3 in the
crypto step to be safe.
"""
import sys

sys.path.insert(0, r"C:\Repositorios\mu-reverse")
from mu_proto import pcap as pcapm

PCAP = r"C:\Users\anton\Downloads\WiresharkPortable64\Data\Temp\wireshark_Wi-FiIVW3W3.pcapng"
CLIENT = ("192.168.1.148", 55612)
SERVER = ("139.5.226.87", 55903)

c2s: bytearray = bytearray()
s2c: bytearray = bytearray()
for ts, src, sport, dst, dport, seq, payload in pcapm.tcp_segments(PCAP):
    if not payload:
        continue
    if (src, sport) == CLIENT:
        c2s.extend(payload)
    elif (src, sport) == SERVER:
        s2c.extend(payload)

print(f"C2S={len(c2s)} bytes  S2C={len(s2c)} bytes")

PADS = (0, 1, 2, 3, 4, 5, 6, 7)


def split_stream(buf):
    """Yield (offset, total, bytes). C3 total = byte[1] (1 byte)."""
    out = []
    i, n = 0, len(buf)
    while i < n:
        b = buf[i]
        if b == 0xC1:
            total = buf[i + 1]
            if i + total > n:
                break
            out.append((i, total, bytes(buf[i:i + total])))
            i += total
        elif b == 0xC2:
            total = 3 + ((buf[i + 1] << 8) | buf[i + 2])
            if i + total > n:
                break
            out.append((i, total, bytes(buf[i:i + total])))
            i += total
        elif b == 0xC3:
            total = buf[i + 1]  # 1-byte total length
            if total not in (11, 19, 27, 35, 59):
                print(f"  !! C3 at offset {i} has suspicious total {total}")
                break
            if i + total > n:
                print(f"  !! C3 at offset {i} total {total} exceeds stream ({n})")
                break
            p = bytes(buf[i:i + total])
            pad = p[-1]
            if pad not in PADS:
                print(f"  !! C3 at offset {i}: pad byte 0x{pad:02X} out of range 0..7")
            out.append((i, total, p))
            i += total
        else:
            i += 1
    return out


def summarize(name, data, save_bin):
    pkts = split_stream(data)
    rem = len(data) - sum(t for _, t, _ in pkts)
    print(f"\n[{name}] packets={len(pkts)} remainder={rem} bytes")
    c3 = [(o, p) for o, t, p in pkts if p[0] == 0xC3]
    print(f"  C3 count={len(c3)}  offsets={sorted(o for o, _ in c3)}")
    # save
    open(save_bin, "wb").write(bytes(data))
    print(f"  saved stream to {save_bin}")
    print(f"  --- all packets ---")
    for idx, (off, total, p) in enumerate(pkts):
        t = p[0]
        if t == 0xC3:
            body = p[2:]
            pad = p[-1]
            nblocks = (total - 3) // 8
            print(f"  #{idx+1:03d} off=0x{off:04X} 0xC3 total={total:2d} pad={pad:2d} blocks={nblocks} "
                  f"{p.hex(' ')}")
        elif t == 0xC1:
            print(f"  #{idx+1:03d} off=0x{off:04X} 0xC1 total={total:2d} body={p[2:].hex(' ')}")
        else:
            print(f"  #{idx+1:03d} off=0x{off:04X} 0x{t:02X} total={total:2d} body={p[3:].hex(' ')}")

p2s = summarize("C2S", bytes(c2s), "c2s.bin")
p2c = summarize("S2C", bytes(s2c), "s2c.bin")
