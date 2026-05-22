import os
import nmap


class NmapScanner:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def run_scan(self):
        print(f"\n[+] Starting Nmap scan on {self.target}...\n")

        self.scanner.scan(
            hosts=self.target,
            arguments="-sV -Pn -T4"
        )

        print("[+] Scan completed.")

        xml_output = self.scanner.get_nmap_last_output().decode()

        os.makedirs("data/raw", exist_ok=True)

        with open("data/raw/nmap_scan.xml", "w") as file:
            file.write(xml_output)

        print("[+] XML results saved to data/raw/nmap_scan.xml")

        return self.scanner
