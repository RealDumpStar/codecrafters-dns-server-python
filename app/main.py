from __future__ import annotations
import sys
import socket
import struct

class DNSPacket:
    def __init__(self, identifier, qr_opcode_aa_tc_rd, ra_z_rcode, qd, an, ns, ar):
        self.identifier = identifier
        self.qr = qr_opcode_aa_tc_rd >> 7
        self.opcode = (qr_opcode_aa_tc_rd >> 3) & 0b1111
        self.aa = (qr_opcode_aa_tc_rd >> 2) & 1
        self.tc = (qr_opcode_aa_tc_rd >> 1) & 1
        self.rd = qr_opcode_aa_tc_rd & 1
        self.ra = ra_z_rcode >> 7
        self.rcode = ra_z_rcode & 0b1111
        self.qd = qd
        self.an = an
        self.ns = ns
        self.ar = ar

    @classmethod
    def parse_from_bytes(cls, buf: bytes) -> DNSPacket:
        (ident, qr_opcode_aa_tc_rd, ra_z_rcode, qd_count, an_count, ns_count, ar_count) = struct.unpack("!hBBhhhh", buf[:12])
        qd = []
        an = []
        ns = []
        ar = []
        i = 12
        for _ in range(qd_count):
            domain, i = parse_domain(buf, i)
            record_type, record_class = struct.unpack("!hh", buf[i : i + 4])
            i += 4
            qd.append((domain, record_type, record_class))
        for _ in range(an_count):
            domain, i = parse_domain(buf, i)
            (record_type, record_class, ttl, datalen) = struct.unpack("!hhIh", buf[i : i + 10])
            i += 10
            rdata = buf[i : i + datalen]
            i += datalen
            an.append((domain, record_type, record_class, ttl, datalen, rdata))
        return DNSPacket(ident, qr_opcode_aa_tc_rd, ra_z_rcode, qd, an, ns, ar)

def parse_domain(buf: bytes, i: int = 0) -> tuple[str, int]:
    parts = []
    while True:
        if buf[i] & 0b1100_0000:
            offset = ((buf[i] & 0b0011_1111) << 8) + buf[i + 1]
            domain, _ = parse_domain(buf, offset)
            parts.append(domain)
            return ".".join(parts), i + 2
        name_len = buf[i]
        i += 1
        if name_len == 0:
            break
        name = buf[i : i + name_len].decode()
        i += name_len
        parts.append(name)
    return ".".join(parts), i

def question_section(domain_name: str, record_type: int, record_class: int) -> bytes:
    buf = b""
    for part in domain_name.split("."):
        part = part.encode()
        part_len = len(part)
        buf += struct.pack(f"!B{part_len}s", part_len, part)
    return buf + struct.pack("!xhh", record_type, record_class)

def main(resolver):
    r_addr, r_port = resolver.split(":")
    resolver_addr = (r_addr, int(r_port))
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            packet = DNSPacket.parse_from_bytes(buf)

            # Forward the query to the resolver
            resolver_socket.sendto(buf, resolver_addr)
            response, _ = resolver_socket.recvfrom(512)

            # Send the response back to the original requester
            udp_socket.sendto(response, source)

        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    resolver = sys.argv[2]
    main(resolver)