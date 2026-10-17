
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import Counter

print("Network Traffic Analyzer")
print("------------------------")

packets = rdpcap("Project-2-Network-Traffic-Analyzer/sample.pcapng")

print(f"Total packets captured: {len(packets)}")

protocol_counts = Counter()
syn_sources = Counter()

print("\nPacket Details")
print("=" * 70)

for i, packet in enumerate(packets, start=1):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            # Count TCP connection initiation attempts
            if packet[TCP].flags & 0x02:
                syn_sources[source_ip] += 1

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"
            source_port = "-"
            destination_port = "-"

        else:
            protocol = "Other IP"
            source_port = "-"
            destination_port = "-"

        protocol_counts[protocol] += 1

        print(
            f"{i}. {source_ip} -> {destination_ip} | "
            f"{protocol} | Ports: {source_port} -> {destination_port}"
        )

    else:
        protocol_counts["Non-IP"] += 1
        print(f"{i}. Non-IP packet")

print("\nProtocol Statistics")
print("=" * 30)

for protocol in ["TCP", "UDP", "ICMP", "Other IP", "Non-IP"]:
    print(f"{protocol}: {protocol_counts[protocol]}")

print(f"\nTotal packets processed: {sum(protocol_counts.values())}")

print("\nTCP SYN Analysis")
print("=" * 30)

if syn_sources:
    for source_ip, count in syn_sources.most_common():
        print(f"{source_ip}: {count} SYN packets")
else:
    print("No TCP SYN packets found.")


# Save analysis results to a report
report_path = "Project-2-Network-Traffic-Analyzer/analysis_report.txt"

with open(report_path, "w") as report:
    report.write("NETWORK TRAFFIC ANALYSIS REPORT\n")
    report.write("=" * 40 + "\n\n")

    report.write(f"Total packets analyzed: {len(packets)}\n\n")

    report.write("Protocol Statistics:\n")
    for protocol in ["TCP", "UDP", "ICMP", "Other IP", "Non-IP"]:
        report.write(f"{protocol}: {protocol_counts[protocol]}\n")

    report.write("\nTCP SYN Analysis:\n")
    if syn_sources:
        for source_ip, count in syn_sources.most_common():
            report.write(f"{source_ip}: {count} SYN packets\n")
    else:
        report.write("No TCP SYN packets found.\n")

print(f"\nReport saved to: {report_path}")
