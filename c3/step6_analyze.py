"""STEP6: Confirmar username en C1 claro + extraer primer C3 ciphertext + known-plaintext."""
import sys
sys.path.insert(0, r"C:\Repositorios\mu-reverse")
from mu_proto import pcap as pcapm, packets as pk

PCAP = r"C:\Users\anton\Downloads\WiresharkPortable64\Data\Temp\wireshark_Wi-FiIVW3W3.pcapng"
PORTS = (44405,55901,55902,55903,55999)
streams = {}
for ts, src, sport, dst, dport, seq, payload in pcapm.tcp_segments(PCAP):
    if not payload: continue
    if dport in PORTS or sport in PORTS:
        fk = tuple(sorted([(src,sport),(dst,dport)]))
        streams.setdefault(fk, {'c2s':bytearray(),'s2s':bytearray(),'s2c':bytearray()})
        (streams[fk]['c2s'] if dport in PORTS else streams[fk]['s2c']).extend(payload)

def strings(buf, min_len=4):
    out, cur = [], b""
    for b in buf:
        if 32 <= b < 127: cur += bytes([b])
        else:
            if len(cur) >= min_len: out.append(cur)
            cur = b""
    if len(cur) >= min_len: out.append(cur)
    return out

for fk, fl in streams.items():
    for d, data in [('C2S',fl['c2s']),('S2C',fl['s2c'])]:
        pkts, rem = pk.split_stream(bytes(data))
        # clear C1/C2 strings
        cs = []
        for p in pkts:
            if p[0] in (0xC1,0xC2):
                s = strings(p)
                for x in s:
                    if x not in cs:
                        cs.append(x)
        print(f"=== {d} clear strings (first 25) ===")
        print("  " + " | ".join(cs[:25]))
        # first C3 packets
        c3 = [p for p in pkts if p[0]==0xC3]
        print(f"  C3 count={len(c3)}, first 3 packet-hex:")
        for p in c3[:3]:
            print("   ", p.hex(" "))
