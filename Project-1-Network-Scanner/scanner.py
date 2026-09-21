import socket
import time
from concurrent.futures import ThreadPoolExecutor
#Python's socket library for network connections, the time library to measure scan duration, and ThreadPoolExecutor to scan multiple ports concurrently and improve performance.

target = input("Enter target IP address: ")

print("\n========================================")
print("       PYTHON NETWORK PORT SCANNER")
print("========================================")
print(f"Target: {target}")
print("Scanning ports: 1-10000\n")

start_time = time.time()
scan_results = []


def scan_port(port):
    try:    #create a network socket, AF_INET → we're using IPv4. SOCK_STREAM → we're using TCP.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)

            if sock.connect_ex((target, port)) == 0:  #0 means port is open, Non 0 value means connection failed
                return port

    except OSError:
        pass    #network operation can produce error, if one port gives error, dont interrupt the whole scanner just ignore it

    return None


def identify_service(port):   #What service is running on port
    try:  #We create a socket and connect to the already-open port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((target, port))   #connect() can give error hence its under try/except

            request = (                          #Sending an HTTP req to check what service is running on port
                f"GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Connection: close\r\n\r\n"
            )

            sock.sendall(request.encode())       #encode() converts our text into bytes, because sockets send data as bytes
            response = sock.recv(4096)

            # HTTP detection
            if response.startswith(b"HTTP/"):    #checking whether the response begins with HTTP/
                text = response.decode(errors="ignore")
                lines = text.split("\r\n")

                server = "Unknown"

                for line in lines:
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()

                return "HTTP", server

            # MySQL detection , 0x0A is a hexadecimal byte representing 10. In the MySQL handshake, this byte indicates the protocol version 10
            if len(response) > 5 and response[4] == 0x0A:   #The scanner connects to the open port and examines the response. For MySQL, it checks for a characteristic byte in the MySQL handshake and then extracts the version information. Finding an open MySQL port doesn't automatically mean it's vulnerable; it just means a database service is accessible and should be reviewed
                version_data = response[5:]
                end = version_data.find(b"\x00")

                if end != -1:
                    version = version_data[:end].decode(
                        errors="ignore"
                    )
                else:
                    version = "Unknown"

                return "MySQL", version

            return "Unknown", "-"

    except (socket.timeout, OSError):
        return "Unknown", "-"


def security_finding(port, service):      #security observations about potentially exposed services (No vulnarability testing)
    if port == 445:
        return "Review SMB exposure and firewall rules."

    if port == 135:
        return "Review RPC exposure and firewall configuration."

    if service == "MySQL":
        return "Review whether database access needs to be network accessible."

    if service == "HTTP":
        return "Review web server configuration and exposed resources."

    return "Service could not be identified."


# Scan ports concurrently
with ThreadPoolExecutor(max_workers=100) as executor:    #100 tasks run concurrently

    results = executor.map(scan_port, range(1, 10001))

    for port in results:

        if port is not None:

            service, version = identify_service(port)   #analyze each open port
            finding = security_finding(port, service)

            scan_results.append({
                "port": port,
                "service": service,
                "version": version,
                "finding": finding
            })


# Display results
print("\n========================================")
print("             SCAN RESULTS")
print("========================================")

print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<12}VERSION")    #Table hedings (<8, <10 are spacing alignments)
print("-" * 60)

for result in scan_results:  #scan_results contains info collected

    print(
        f"{result['port']:<8}"
        f"{'OPEN':<10}"
        f"{result['service']:<12}"
        f"{result['version']}"
    )

    print(f"         [!] {result['finding']}")


# Save report
with open("scan_report.txt", "w", encoding="utf-8") as report:

    report.write("NETWORK SECURITY SCAN REPORT\n")
    report.write("=" * 40 + "\n\n")
    report.write(f"Target: {target}\n\n")          #write info into the file

    for result in scan_results:

        report.write(f"Port: {result['port']}\n")
        report.write("State: OPEN\n")
        report.write(f"Service: {result['service']}\n")
        report.write(f"Version: {result['version']}\n")
        report.write(f"Finding: {result['finding']}\n")
        report.write("-" * 40 + "\n")

#measuring scan time
end_time = time.time()

print("\n----------------------------------------")
print("Scan completed!")
print(f"Open ports found: {len(scan_results)}")
print(f"Time taken: {end_time - start_time:.2f} seconds")   
print("----------------------------------------")
print("[+] Report saved as scan_report.txt")