"""Minimal pcap / pcapng reader + IPv4/TCP stream reassembly (stdlib only)."""
import struct


def _iter_pcap(f, data):
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    off = 24
    while off + 16 <= len(data):
        ts, tus, incl, _ = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        yield ts + tus / 1e6, linktype, data[off:off + incl]
        off += incl


def _iter_pcapng(data):
    off, endian, links = 0, "<", []
    while off + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == 0x0A0D0D0A:
            magic = data[off + 8:off + 12]
            endian = "<" if magic == bytes.fromhex("4d3c2b1a") else ">"
            links = []
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        body = data[off + 8:off + blen - 4]
        if btype == 1:
            links.append(struct.unpack_from(endian + "H", body, 0)[0])
        elif btype == 6:
            iface, hi, lo, cap = struct.unpack_from(endian + "IIII", body, 0)
            ts = ((hi << 32) | lo) / 1e6
            yield ts, links[iface] if iface < len(links) else 1, body[20:20 + cap]
        if blen < 12:
            break
        off += blen


def read_packets(path):
    data = open(path, "rb").read()
    if data[:4] == bytes.fromhex("0a0d0d0a"):
        return _iter_pcapng(data)
    return _iter_pcap(None, data)


def tcp_segments(path):
    """Yield (ts, src, sport, dst, dport, seq, payload) for IPv4 TCP."""
    for ts, link, frame in read_packets(path):
        if link == 1:  # Ethernet
            if len(frame) < 14 or frame[12:14] != b"\x08\x00":
                continue
            ip = frame[14:]
        elif link in (101, 228):  # raw IPv4
            ip = frame
        else:
            continue
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        total = struct.unpack_from(">H", ip, 2)[0] or len(ip)
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack_from(">HHI", tcp, 0)
        payload = tcp[(tcp[12] >> 4) * 4:]
        src = ".".join(map(str, ip[12:16]))
        dst = ".".join(map(str, ip[16:20]))
        yield ts, src, sport, dst, dport, seq, bytes(payload)

