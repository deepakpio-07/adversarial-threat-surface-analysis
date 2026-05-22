class AttackChainEngine:

    def generate_chains(self, findings):

        services = []

        for finding in findings:
            services.append(
                finding["service"].lower()
            )

        attack_chains = []

        # RDP + SMB chain
        if (
            "rdp" in services or
            "ms-wbt-server" in services
        ) and (
            "smb" in services or
            "microsoft-ds" in services
        ):

            attack_chains.append(
                {
                    "chain": (
                        "RDP Exposure "
                        "→ Credential Attack "
                        "→ Internal Access "
                        "→ SMB Lateral Movement"
                    ),

                    "severity": "Critical"
                }
            )

        # SSH + HTTP chain
        if (
            "ssh" in services and
            "http" in services
        ):

            attack_chains.append(
                {
                    "chain": (
                        "Web Enumeration "
                        "→ Credential Discovery "
                        "→ SSH Access"
                    ),

                    "severity": "High"
                }
            )

        # FTP + HTTP chain
        if (
            "ftp" in services and
            "http" in services
        ):

            attack_chains.append(
                {
                    "chain": (
                        "Public File Exposure "
                        "→ Web Compromise "
                        "→ Data Exfiltration"
                    ),

                    "severity": "High"
                }
            )

        return attack_chains
