import os  # File system operations
import psutil  # System monitoring
import time  # Time-related functions
import scapy.all as scapy  # Network traffic analysis
import threading  # Multi-threading support

# Directory for storing encryption logs
encryption_log_dir = "encryption_logs"
os.makedirs(encryption_log_dir, exist_ok=True)


def log_encryption(encryption_type, packet_summary):
    log_file_name = ""

    # Determine log file based on encryption type
    encryption_log_map = {
        "TLS (HTTPS)": "tls_https_log.txt",
        "SSH": "ssh_log.txt",
        "IPsec (IKE)": "ipsec_ike_log.txt",
        "IPsec (ESP)": "ipsec_esp_log.txt",
        "IPsec (AH)": "ipsec_ah_log.txt"
    }

    log_file_name = encryption_log_map.get(encryption_type, "")

    # Write to log file if a matching file is found
    if log_file_name:
        log_file_path = os.path.join(encryption_log_dir, log_file_name)
        with open(log_file_path, "a") as log_file:
            log_file.write(f"{packet_summary}\n")


def parse_packet(packet):
    encryption_type = "Unencrypted"

    # Check TCP packets
    if packet.haslayer(scapy.TCP):
        if packet.dport == 443 or packet.sport == 443:
            encryption_type = "TLS (HTTPS)"
        elif packet.dport == 22 or packet.sport == 22:
            encryption_type = "SSH"

    # Check UDP packets
    elif packet.haslayer(scapy.UDP):
        if packet.dport in [500, 4500] or packet.sport in [500, 4500]:
            encryption_type = "IPsec (IKE)"

    # Check IPsec encryption
    elif packet.haslayer(scapy.ESP):
        encryption_type = "IPsec (ESP)"
    elif packet.haslayer(scapy.AH):
        encryption_type = "IPsec (AH)"

    # Get packet protocol
    protocol = packet.sprintf("%IP.proto%") if packet.haslayer(scapy.IP) else "Unknown"

    # Create packet summary
    packet_summary = f"Packet: {packet.summary()} | Protocol: {protocol} | Encryption: {encryption_type}"
    print(packet_summary)

    # Log encryption information
    log_encryption(encryption_type, packet_summary)


def monitor_traffic(interval=1):
    print("Monitoring network traffic... Press Ctrl+C to stop.")
    prev_net = psutil.net_io_counters()

    while True:
        time.sleep(interval)
        current_net = psutil.net_io_counters()

        # Calculate download and upload speeds in KB/s
        download_speed = (current_net.bytes_recv - prev_net.bytes_recv) / interval / 1024
        upload_speed = (current_net.bytes_sent - prev_net.bytes_sent) / interval / 1024

        print(f"Download: {download_speed:.2f} KB/s | Upload: {upload_speed:.2f} KB/s")
        prev_net = current_net


def main():
    try:
        print("Starting packet sniffing...")

        # Create a thread for monitoring traffic
        traffic_thread = threading.Thread(target=monitor_traffic)
        traffic_thread.daemon = True
        traffic_thread.start()

        # Capture and analyze packets in real-time
        scapy.sniff(prn=parse_packet, store=False)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


if __name__ == "__main__":
    main()