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

def parse_questions(data, offset, qdcount):
    questions = []
    for _ in range(qdcount):
        domain_name, offset = decode_domain_name(data, offset)
        qtype = int.from_bytes(data[offset:offset+2], byteorder='big')
        qclass = int.from_bytes(data[offset+2:offset+4], byteorder='big')
        questions.append((domain_name, qtype, qclass))
        offset += 4
    return questions, offset

def construct_answer(domain_name, ip_address):
    encoded_domain_name = encode_domain_name(domain_name)
    answer_type = (1).to_bytes(2, byteorder='big')  # Type A record
    answer_class = (1).to_bytes(2, byteorder='big')  # Class IN (Internet)
    ttl = (60).to_bytes(4, byteorder='big')  # TTL = 60 seconds
    rdlength = (4).to_bytes(2, byteorder='big')  # Length of RDATA field
    rdata = socket.inet_aton(ip_address)  # Convert IP address to 4-byte format
    return encoded_domain_name + answer_type + answer_class + ttl + rdlength + rdata

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

            # Parse the header
            qdcount = int.from_bytes(buf[4:6], byteorder='big')

            # Parse the question section
            questions, offset = parse_questions(buf, 12, qdcount)

            # Forward the received query to the specified resolver
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
                resolver_socket.sendto(buf, (resolver_ip, resolver_port))
                resolver_response, _ = resolver_socket.recvfrom(512)

            # Extract parts from the resolver's response
            response_header = resolver_response[:12]
            response_question_section = resolver_response[12:offset]

            # Construct the full response packet
            response_packet = (
                id_bytes +
                response_header[2:12] +  # Use the rest of the header from the resolver's response
                response_question_section
            )

            # Append the question section to the response
            for question in questions:
                domain_name, qtype, qclass = question
                question_section = encode_domain_name(domain_name) + qtype.to_bytes(2, byteorder='big') + qclass.to_bytes(2, byteorder='big')
                response_packet += question_section

            # Append the answer section to the response
            for question in questions:
                domain_name, qtype, qclass = question
                answer_section = construct_answer(domain_name, "8.8.8.8")
                response_packet += answer_section

            # Send the response to the source address
            udp_socket.sendto(response_packet, source)

        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
