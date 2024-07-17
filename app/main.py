import socket

def encode_domain_name(domain):
    labels = domain.split('.')
    encoded_labels = []
    for label in labels:
        encoded_labels.append(len(label).to_bytes(1, byteorder='big'))
        encoded_labels.append(label.encode('ascii'))
    encoded_labels.append(b'\x00')  # Null byte to terminate the domain name
    return b''.join(encoded_labels)

def main():
    # Debugging logs
    print("Logs from your program will appear here!")

    # Initialize and bind the UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            
            # Construct the response header based on the given specifications
            # Packet Identifier (ID) = 1234 (16 bits)
            id_bytes = (1234).to_bytes(2, byteorder='big')
            
            # Flags (16 bits) - QR: 1, OPCODE: 0, AA: 0, TC: 0, RD: 0, RA: 0, Z: 0, RCODE: 0
            flags = (1 << 15)  # QR = 1 << 15 (setting the QR bit)
            flags_bytes = flags.to_bytes(2, byteorder='big')
            
            # Question Count (QDCOUNT) = 1 (16 bits)
            qdcount_bytes = (1).to_bytes(2, byteorder='big')
            
            # Answer Record Count (ANCOUNT) = 0 (16 bits)
            ancount_bytes = (0).to_bytes(2, byteorder='big')
            
            # Authority Record Count (NSCOUNT) = 0 (16 bits)
            nscount_bytes = (0).to_bytes(2, byteorder='big')
            
            # Additional Record Count (ARCOUNT) = 0 (16 bits)
            arcount_bytes = (0).to_bytes(2, byteorder='big')
            
            # Combine all parts to form the 12-byte header
            response = (
                id_bytes +
                flags_bytes +
                qdcount_bytes +
                ancount_bytes +
                nscount_bytes +
                arcount_bytes
            )

            # Construct the question section
            domain_name = "codecrafters.io"
            encoded_domain_name = encode_domain_name(domain_name)
            
            # Type (2 bytes, big-endian) - 1 for A record
            qtype = (1).to_bytes(2, byteorder='big')
            
            # Class (2 bytes, big-endian) - 1 for IN (Internet)
            qclass = (1).to_bytes(2, byteorder='big')
            
            # Combine to form the question section
            question_section = encoded_domain_name + qtype + qclass
            
            # Append the question section to the response
            response += question_section

            # Send the response to the source address
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
