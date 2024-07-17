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
    while data[offset] != 0:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # Pointer (compression)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            decoded_label, _ = decode_domain_name(data, pointer)
            labels.append(decoded_label)
            offset += 2
            return '.'.join(labels), offset
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
            qdcount = struct.unpack('!H', query[4:6])[0]

            # If multiple questions, split and process separately
            if qdcount > 1:
                responses = []
                offset = 12
                for _ in range(qdcount):
                    domain_name, offset = decode_domain_name(query, offset)
                    qtype = query[offset:offset+2]
                    qclass = query[offset+2:offset+4]
                    offset += 4

                    single_query = id_bytes + query[2:4] + struct.pack('!H', 1) + query[6:12] + \
                                   encode_domain_name(domain_name) + qtype + qclass

                    response = forward_dns_query(resolver, single_query)
                    responses.append(response[12:])  # Exclude header

                # Combine responses
                combined_response = id_bytes + query[2:4] + struct.pack('!H', qdcount) + \
                                    struct.pack('!H', qdcount) + b'\x00\x00\x00\x00' + b''.join(responses)
            else:
                combined_response = forward_dns_query(resolver, query)

            udp_socket.sendto(combined_response, source)

        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    main()