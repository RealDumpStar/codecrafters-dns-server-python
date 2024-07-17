import socket
import argparse
import struct

def encode_domain_name(domain):
    labels = domain.split('.')
    encoded_labels = []
    for label in labels:
        encoded_labels.append(len(label).to_bytes(1, byteorder='big'))
        encoded_labels.append(label.encode('ascii'))
    encoded_labels.append(b'\x00')  # Null byte to terminate the domain name
    return b''.join(encoded_labels)

def decode_domain_name(data, offset):
    labels = []
    original_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:  # Pointer (compression)
            pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            if pointer >= original_offset:
                raise ValueError("Invalid pointer in compressed name")
            return decode_domain_name(data, pointer)[0], offset + 2
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode('ascii'))
            offset += length
    return '.'.join(labels), offset + 1  # Skip the null byte

def forward_dns_query(resolver, query):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query, resolver)
        response, _ = sock.recvfrom(512)
    return response

def parse_question(data, offset):
    domain, offset = decode_domain_name(data, offset)
    qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
    return domain, qtype, qclass, offset + 4

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--resolver', required=True, help='Resolver address in format <ip>:<port>')
    args = parser.parse_args()

    resolver_ip, resolver_port = args.resolver.split(':')
    resolver = (resolver_ip, int(resolver_port))

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            query, source = udp_socket.recvfrom(512)
            
            # Extract query details
            id_bytes = query[:2]
            flags, qdcount = struct.unpack('!HH', query[2:6])

            # Parse questions
            offset = 12
            questions = []
            for _ in range(qdcount):
                domain, qtype, qclass, offset = parse_question(query, offset)
                questions.append((domain, qtype, qclass))

            # Forward each question separately and collect responses
            responses = []
            for domain, qtype, qclass in questions:
                single_query = id_bytes + struct.pack('!HHHHHH', flags, 1, 0, 0, 0, 0) + \
                               encode_domain_name(domain) + struct.pack('!HH', qtype, qclass)
                response = forward_dns_query(resolver, single_query)
                responses.append(response[12:])  # Exclude header

            # Combine responses
            combined_response = id_bytes + struct.pack('!HHHHHH', 
                flags | 0x8000,  # Set QR bit to 1 (response)
                qdcount, qdcount, 0, 0, 0) + query[12:offset] + b''.join(responses)

            udp_socket.sendto(combined_response, source)

        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    main()