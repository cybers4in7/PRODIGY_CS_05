import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define a dictionary to store packet statistics
packet_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

def packet_callback(packet):
    # Get the IP layer information
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "Other")

        # Print packet information
        logging.info(f"Protocol: {proto_name}")
        logging.info(f"Source IP: {ip_src}")
        logging.info(f"Destination IP: {ip_dst}")

        # Update packet statistics
        packet_stats[proto_name] += 1

        # Print additional information based on protocol
        if proto_name == "TCP":
            if TCP in packet:
                logging.info(f"Source Port: {packet[TCP].sport}")
                logging.info(f"Destination Port: {packet[TCP].dport}")
                logging.info(f"Payload: {packet[TCP].payload.raw}")
        elif proto_name == "UDP":
            if UDP in packet:
                logging.info(f"Source Port: {packet[UDP].sport}")
                logging.info(f"Destination Port: {packet[UDP].dport}")
                logging.info(f"Payload: {packet[UDP].payload.raw}")
        elif proto_name == "ICMP":
            if ICMP in packet:
                logging.info(f"Type: {packet[ICMP].type}")
                logging.info(f"Code: {packet[ICMP].code}")
                logging.info(f"Payload: {packet[ICMP].payload.raw}")

        logging.info("\n")

def main():
    logging.info("Starting packet sniffer...")
    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"Error: {e}")

    # Print packet statistics
    logging.info("Packet Statistics:")
    for proto, count in packet_stats.items():
        logging.info(f"{proto}: {count}")

if __name__ == "__main__":
    main()