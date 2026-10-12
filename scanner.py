import socket
import json
import time
from concurrent.futures import ThreadPoolExecutor

class NetworkReconScanner:
    """
    A multi-threaded TCP port scanner and banner grabber designed for
    network reconnaissance and vulnerability assessment.
    """

    # Common well-known ports to inspect
    DEFAULT_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy"
    }

    def __init__(self, target_host, ports=None, max_threads=20, timeout=1.5):
        self.target_host = target_host
        self.ports = ports if ports else list(self.DEFAULT_PORTS.keys())
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = []

    def scan_port(self, port):
        service_name = self.DEFAULT_PORTS.get(port, "Unknown Service")
        
        try:
            # Create TCP socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_host, port))
                
                # 0 indicates successful connection (Port Open)
                if result == 0:
                    banner = self.grab_banner(sock, port)
                    port_data = {
                        "port": port,
                        "status": "open",
                        "service": service_name,
                        "banner": banner
                    }
                    print(f"  [+] Port {port:<5} OPEN | Service: {service_name:<12} | Banner: {banner}")
                    return port_data
        except Exception as e:
            pass
        return None

    def grab_banner(self, sock, port):
        """Attempts to grab service identification banner if available."""
        try:
            # Send HTTP request if probing web ports
            if port in [80, 8080]:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "No banner returned"
        except:
            return "Banner grab timed out"

    def run_scan(self):
        print(f"\n[🚀] Starting Recon Scan on target: {self.target_host}")
        print(f"[⚙️] Scanning {len(self.ports)} target ports using {self.max_threads} threads...\n" + "-"*60)
        
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            scanned_results = executor.map(self.scan_port, self.ports)

        for res in scanned_results:
            if res:
                self.results.append(res)

        elapsed = round(time.time() - start_time, 2)
        print("-" * 60)
        print(f"[✅] Scan finished in {elapsed}s. Found {len(self.results)} open ports.")
        
        self.export_report()

    def export_report(self, filename="scan_results.json"):
        report = {
            "target": self.target_host,
            "open_ports_count": len(self.results),
            "scan_results": self.results
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        print(f"[📁] Detailed report saved to {filename}\n")

if __name__ == "__main__":
    # Scan loopback / local test environment
    target = "127.0.0.1"
    scanner = NetworkReconScanner(target_host=target)
    scanner.run_scan()
