"""Dissect MU Online packets from a Wireshark pcap / pcapng file.

Usage:
    python analyze_pcap.py <traffic.pcapng>
"""

import argparse
import os
import sys
from collections import Counter, defaultdict

from mu_proto import packets
from mu_proto import pcap
from mu_proto import simple_modulus as sm

KNOWN_OPCODES = {
    0xF1: {
        0x01: "Login Request (F1:01)",
        0x02: "Login Result (F1:02)",
        0x03: "Logout Request (F1:03)",
    },
    0xF3: {
        0x00: "Character List (F3:00)",
        0x01: "Character Create (F3:01)",
        0x02: "Character Delete (F3:02)",
        0x03: "Character Select (F3:03)",
        0x04: "World Join Result (F3:04)",
        0x06: "Level Up / Stats (F3:06)",
        0x10: "Character Info Update (F3:10)",
    },
    0x00: {None: "Chat Message (00)"},
    0x02: {None: "Whisper Message (02)"},
    0x0E: {None: "Ping / KeepAlive (0E)"},
    0x0F: {None: "Client Tick / Timing (0F)"},
    0x12: {None: "Viewport Character/Monster Spawn (12)"},
    0x13: {None: "Viewport Character Walk Update (13)"},
    0x14: {None: "Viewport Entity Despawn / Out of Scope (14)"},
    0x11: {None: "Attack Request / Result (11)"},
    0x19: {None: "Skill Attack (19)"},
    0x22: {None: "Item Pickup (22)"},
    0x24: {None: "Item Move / Equip (24)"},
    0x26: {None: "Item Drop (26)"},
    0x30: {None: "NPC Talk Request (30)"},
    0x31: {None: "NPC Close / Result (31)"},
    0x5A: {None: "Movement / Position Sync (5A)"},
    0xD0: {None: "Player Walk (D0)"},
    0xDF: {None: "Player Stop / Personal Shop View (DF)"},
    0xF4: {
        0x03: "ConnectServer Server List (F4:03)",
        0x06: "ConnectServer Select Server (F4:06)",
    },
    0xF8: {None: "Pet / Muun Status Update (F8)"},
    0xB1: {None: "Inventory / Action State (B1)"},
}


def describe_packet(body):
    if not body:
        return "Empty"
    op1 = body[0]
    op2 = body[1] if len(body) > 1 else None
    if op1 in KNOWN_OPCODES:
        sub = KNOWN_OPCODES[op1]
        if op2 in sub:
            return sub[op2]
        if None in sub:
            return sub[None]
        return f"Opcode 0x{op1:02X}:0x{op2:02X}"
    return f"Opcode 0x{op1:02X}"


def extract_strings(buf, min_len=4):
    strings = []
    cur = []
    for b in buf:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                strings.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        strings.append("".join(cur))
    return strings


def main():
    parser = argparse.ArgumentParser(description="MU Online PCAP Dissector")
    parser.add_argument("pcap_path", help="Path to pcap or pcapng capture file")
    parser.add_argument(
        "--data-dir",
        default=r"C:\Program Files (x86)\Webzen\Mu\Data",
        help="Path to MU Data directory containing Enc1.dat and Dec2.dat",
    )
    parser.add_argument(
        "--server-ports",
        nargs="+",
        type=int,
        default=[44405, 55901, 55902, 55903, 55999],
        help="Known MU server TCP ports",
    )
    args = parser.parse_args()

    streams = defaultdict(lambda: {"c2s": bytearray(), "s2c": bytearray()})
    total_segments = 0

    print(f"[*] Reading capture file: {args.pcap_path}")
    for ts, src, sport, dst, dport, seq, payload in pcap.tcp_segments(args.pcap_path):
        total_segments += 1
        if not payload:
            continue

        is_c2s = dport in args.server_ports
        is_s2c = sport in args.server_ports

        if not (is_c2s or is_s2c):
            if payload[0] in (0xC1, 0xC2, 0xC3, 0xC4):
                is_c2s = True
            else:
                continue

        flow_key = tuple(sorted([(src, sport), (dst, dport)]))
        direction = "c2s" if is_c2s else "s2c"
        streams[flow_key][direction].extend(payload)

    print(f"[*] Processed {total_segments} TCP segments across {len(streams)} MU streams.\n" + "=" * 70)

    for flow_key, flow in streams.items():
        ep1, ep2 = flow_key
        print(f"\n[STREAM] {ep1[0]}:{ep1[1]} <---> {ep2[0]}:{ep2[1]}")

        for direction, data in [("Client -> Server", flow["c2s"]), ("Server -> Client", flow["s2c"])]:
            if not data:
                continue
            pkts, rem = packets.split_stream(data)
            type_counts = Counter(p[0] for p in pkts)
            print(f"\n  [{direction}] - Total: {len(pkts)} paquetes ({len(rem)} bytes remanentes)")
            type_str = ", ".join(f"C{k-0xC0}: {v}" for k, v in sorted(type_counts.items()))
            print(f"    Desglose: {type_str}")

            # Collect game entities from C2 / C1 text
            entities = set()
            for p in pkts:
                body = p[packets.header_size(p[0]):]
                for s in extract_strings(body):
                    if len(s) >= 4 and not s.startswith("0000"):
                        entities.add(s)

            if entities:
                print(f"    Textos/Entidades detectadas ({len(entities)}): {sorted(list(entities))[:8]}")

            # Print first 15 packets sample
            print("    Muestra de paquetes:")
            for idx, raw_pkt in enumerate(pkts[:15]):
                ptype = f"0xC{raw_pkt[0]-0xC0}"
                hs = packets.header_size(raw_pkt[0])
                body = raw_pkt[hs:]
                desc = describe_packet(body) if raw_pkt[0] < 0xC3 else f"Encrypted Block (len={len(raw_pkt)}, pad={raw_pkt[-1]})"
                print(f"      #{idx+1:03d} [{ptype}] len={len(raw_pkt):02d} | {desc} | {raw_pkt[:16].hex(' ')}")


if __name__ == "__main__":
    main()
