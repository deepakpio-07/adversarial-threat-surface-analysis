class AttackPathEngine:

    ATTACK_MAPPING = {
        "ssh": "Credential Access",
        "ftp": "Anonymous Access or Credential Attack",
        "telnet": "Plaintext Credential Interception",
        "http": "Web Enumeration",
        "https": "Web Enumeration",
        "microsoft-ds": "SMB Lateral Movement",
        "smb": "SMB Lateral Movement",
        "ms-wbt-server": "Remote Desktop Access",
        "rdp": "Remote Desktop Access"
    }

    def generate_paths(self, findings):

        attack_paths = []

        for finding in findings:

            service = finding["service"].lower()

            if service in self.ATTACK_MAPPING:

                attack_paths.append({
                    "service": service,
                    "port": finding["port"],
                    "attack_opportunity": self.ATTACK_MAPPING[service]
                })

        return attack_paths
