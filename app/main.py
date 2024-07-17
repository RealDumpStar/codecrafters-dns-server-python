import socket
import sys
import struct

def decode_domain_name(data, offset):
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:  # Compression pointer
            pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            return decode_domain_name(data, pointer)[0], offset + 2
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode('ascii'))
            offset += length
    return '.'.join(labels), offset + 1

def encode_domain_name(domain):
    encoded = b''
    for label in domain.split('.'):
        encoded += struct.pack('B', len(label)) + label.encode('ascii')
    return encoded + b'\x00'

def parse_dns_packet(data):
    header = struct.unpack('!HHHHHH', data[:12])
    offset = 12
    questions = []
    for _ in range(header[2]):  # QDCOUNT
        domain, offset = decode_domain_name(data, offset)
        qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
        offset += 4
        questions.append((domain, qtype, qclass))
    return header, questions, data[offset:]

def create_query(id, domain, record_type):
    header = struct.pack('!HHHHHH', id, 0x0100, 1, 0, 0, 0)
    question = encode_domain_name(domain) + struct.pack('!HH', record_type, 1)
    return header + question

def forward_dns_query(resolver, query):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query, resolver)
        return sock.recvfrom(512)[0]

def main(resolver_address):
    resolver_ip, resolver_port = resolver_address.split(':')
    resolver = (resolver_ip, int(resolver_port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 2053))

    while True:
        data, addr = sock.recvfrom(512)
        header, questions, _ = parse_dns_packet(data)
        
        id = header[0]
        response_header = struct.pack('!HHHHHH', 
            id,           # ID
            0x8180,       # Flags: QR=1, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
            len(questions),  # QDCOUNT
            len(questions),  # ANCOUNT
            0,            # NSCOUNT
            0             # ARCOUNT
        )
        
        response_questions = b''
        response_answers = b''
        
        for domain, qtype, qclass in questions:
            query = create_query(id, domain, qtype)
            forwarded_response = forward_dns_query(resolver, query)
            _, _, answers = parse_dns_packet(forwarded_response)
            
            response_questions += encode_domain_name(domain) + struct.pack('!HH', qtype, qclass)
            response_answers += answers

        response = response_header + response_questions + response_answers
        sock.sendto(response, addr)

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != '--resolver':
        print("Usage: python dns_forwarder.py --resolver <ip>:<port>")
        sys.exit(1)
    main(sys.argv[2])