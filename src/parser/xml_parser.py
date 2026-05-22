import json
import xml.etree.ElementTree as ET


class XMLParser:
    def __init__(self, xml_file):
        self.xml_file = xml_file

    def parse_nmap_xml(self):
        tree = ET.parse(self.xml_file)
        root = tree.getroot()

        findings = []

        for host in root.findall("host"):

            address = host.find("address")
            ip_address = address.get("addr") if address is not None else "Unknown"

            ports = host.find("ports")

            if ports is None:
                continue

            for port in ports.findall("port"):

                port_id = port.get("portid")
                protocol = port.get("protocol")

                state = port.find("state")
                service = port.find("service")

                findings.append({
                    "ip": ip_address,
                    "port": port_id,
                    "protocol": protocol,
                    "state": state.get("state") if state is not None else "unknown",
                    "service": service.get("name") if service is not None else "unknown",
                    "product": service.get("product") if service is not None else "",
                    "version": service.get("version") if service is not None else ""
                })

        return findings

    def save_findings(self, findings):
        with open("data/processed/findings.json", "w") as file:
            json.dump(findings, file, indent=4)

        print("\n[+] Findings saved to data/processed/findings.json")
