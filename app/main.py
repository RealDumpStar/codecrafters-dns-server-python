import socket

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
            
            # Question Count (QDCOUNT) = 0 (16 bits)
            qdcount_bytes = (0).to_bytes(2, byteorder='big')
            
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

            # Send the response to the source address
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
