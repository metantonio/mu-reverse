"""Probe: decrypt real C3 packets from the capture using the static .dat keys.
Passive analysis of a local pcap file — reads bytes only, no live connection."""
import sys
sys.path.insert(0, r'C:\Repositorios\mu-reverse')
from mu_proto import simple_modulus as sm
from mu_proto import packets as pk
from mu_proto import pcap as pcapm

PCAP = r'C:\Users\anton\Downloads\WiresharkPortable64\Data\Temp\wireshark_Wi-FiIVW3W3.pcapng'
DATS = {
    'Enc1': sm.Keys.load(r'C:\Program Files (x86)\Webzen\Mu\Data\Enc1.dat'),
    'Dec2': sm.Keys.load(r'C:\Program Files (x86)\Webzen\Mu\Data\Dec2.dat'),
}
# show the key values (hex) so we can confirm they are static/client-side
for name, k in DATS.items():
    print(f"{name}: mod={k.modulus!r} key={k.key!r} xor={k.xor!r}")

PORTS = (44405, 55901, 55902, 55903, 55999)
streams = {}
for ts, src, sport, dst, dport, seq, payload in pcapm.tcp_segments(PCAP):
    if not payload:
        continue
    if dport in PORTS or sport in PORTS:
        fk = tuple(sorted([(src, sport), (dst, dport)]))
        if fk not in streams:
            streams[fk] = {'c2s': bytearray(), 's2c': bytearray()}
        (streams[fk]['c2s'] if dport in PORTS else streams[fk]['s2c']).extend(payload)

for fk, fl in streams.items():
    for dirn, data in [('Client->Server', fl['c2s']), ('Server->Client', fl['s2c'])]:
        pkts, rem = pk.split_stream(bytes(data))
        c3 = [p for p in pkts if p[0] == 0xC3]
        print(f"\n=== {dirn}: {len(c3)} C3 packets (header 2/3) ===")
        for i, p in enumerate(c3[:2]):
            for hs in (2, 3):
                body = p[hs:]
                print(f"  [{i}] rawlen={len(p)} hs={hs} bodylen={len(body)} div11={len(body) % 11 == 0}")
                for name, k in DATS.items():
                    out = sm.decrypt(k, body)
                    tag = 'OK' if out else 'FAIL'
                    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in (out or body[:24]))
                    print(f"     {name} -> {tag}  { (out[:32] if out else b'')!r:30}  {printable}")
