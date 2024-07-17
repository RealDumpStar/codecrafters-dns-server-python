import socket
import sys
import argparse

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

def main():
    parser = argparse.ArgumentParser(description='Forwarding DNS Server')
    parser.add_argument('--resolver', required=True, help='The resolver address in the form <ip>:<port>')
    args = parser.parse_args()

    resolver_ip, resolver_port = args.resolver.split(':')
    resolver_port = int(resolver_port)

    # Initialize and bind the UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            id_bytes = buf[:2]  # Extract the ID from the query packet

            # Forward the received query to the specified resolver
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
                resolver_socket.sendto(buf, (resolver_ip, resolver_port))
                resolver_response, _ = resolver_socket.recvfrom(512)

            # Extract parts from the resolver's response
            response_header = resolver_response[:12]
            question_section_offset = 12
            question_section = buf[question_section_offset:]  # Use the original question section
            answer_section_offset = question_section_offset + len(question_section)

            # Construct the full response packet
            response_packet = (
                id_bytes +
                response_header[2:12] +  # Use the rest of the header from the resolver's response
                question_section +
                resolver_response[answer_section_offset:]  # Append the answer section from the resolver's response
            )

            # Send the response to the source address
            udp_socket.sendto(response_packet, source)

        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
