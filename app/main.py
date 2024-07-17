import socket

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
        offset += 1
        labels.append(data[offset:offset+length].decode('ascii'))
        offset += length
    return '.'.join(labels), offset + 1  # Skip the null byte

def main():
    # Debugging logs
    print("Logs from your program will appear here!")

    # Initialize and bind the UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            
            # Parse the incoming DNS query packet
            id_bytes = buf[:2]  # Extract the ID from the query packet
            
            # Extract flags and other header fields from the query packet
            flags1 = buf[2]
            flags2 = buf[3]
            opcode = (flags1 & 0b01111000) >> 3  # Extract and mimic the OPCODE
            rd = (flags1 & 0b00000001)  # Extract and mimic the RD bit

            # Construct the response flags
            qr = 1 << 7  # QR = 1 (response)
            aa = 0 << 2  # AA = 0 (not authoritative)
            tc = 0 << 1  # TC = 0 (not truncated)
            ra = 0 << 7  # RA = 0 (recursion not available)
            z = 0 << 4   # Z = 0 (reserved)
            
            if opcode == 0:
                rcode = 0  # Response code 0 (no error) for standard query
            else:
                rcode = 4  # Response code 4 (not implemented) for other OPCODEs

            flags1 = qr | (opcode << 3) | aa | tc | rd
            flags2 = ra | z | rcode
            flags_bytes = bytes([flags1, flags2])

            qdcount_bytes = buf[4:6]  # QDCOUNT from the query packet
            ancount_bytes = (1).to_bytes(2, byteorder='big')  # ANCOUNT = 1 (one answer)
            nscount_bytes = (0).to_bytes(2, byteorder='big')
            arcount_bytes = (0).to_bytes(2, byteorder='big')
            
            # Combine all parts to form the 12-byte header
            response_header = (
                id_bytes +
                flags_bytes +
                qdcount_bytes +
                ancount_bytes +
                nscount_bytes +
                arcount_bytes
            )

            # Parse the question section from the query packet
            offset = 12  # Question section starts immediately after the 12-byte header
            domain_name, offset = decode_domain_name(buf, offset)
            qtype = buf[offset:offset+2]
            qclass = buf[offset+2:offset+4]
            question_section = encode_domain_name(domain_name) + qtype + qclass

            # Construct the answer section
            answer_name = encode_domain_name(domain_name)  # Same as in the question section
            answer_type = qtype  # Type A record
            answer_class = qclass  # Class IN (Internet)
            ttl = (60).to_bytes(4, byteorder='big')  # TTL = 60 seconds
            rdlength = (4).to_bytes(2, byteorder='big')  # Length of RDATA field
            ip_address = socket.inet_aton('8.8.8.8')  # Convert IP address to 4-byte format
            rdata = ip_address
            
            answer_section = answer_name + answer_type + answer_class + ttl + rdlength + rdata
            
            # Combine the header, question, and answer sections to form the complete response
            response = response_header + question_section + answer_section

            # Send the response to the source address
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
