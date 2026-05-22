class ExposureAnalyzer:

    RISKY_SERVICES = {
        "ftp": {
            "risk": "Medium",
            "reason": "FTP may allow anonymous access or weak credential attacks."
        },

        "ssh": {
            "risk": "Medium",
            "reason": "SSH exposed to network may allow brute-force or credential attacks."
        },

        "telnet": {
            "risk": "Critical",
            "reason": "Telnet transmits credentials in plaintext."
        },

        "http": {
            "risk": "Info",
            "reason": "HTTP service detected. Requires web enumeration."
        },

        "https": {
            "risk": "Info",
            "reason": "HTTPS service detected. TLS analysis recommended."
        },

        "smb": {
            "risk": "High",
            "reason": "SMB exposure may enable lateral movement and NTLM attacks."
        },

        "microsoft-ds": {
            "risk": "High",
            "reason": "SMB exposure may enable lateral movement and NTLM attacks."
        },

        "rdp": {
            "risk": "Critical",
            "reason": "RDP exposed externally may allow unauthorized remote access."
        },

        "ms-wbt-server": {
            "risk": "Critical",
            "reason": "RDP exposed externally may allow unauthorized remote access."
        }
    }

    def analyze(self, findings):

        analyzed_results = []

        for finding in findings:

            service = finding["service"].lower()

            if service in self.RISKY_SERVICES:

                risk_data = self.RISKY_SERVICES[service]

                finding["risk"] = risk_data["risk"]
                finding["analysis"] = risk_data["reason"]

            else:
                finding["risk"] = "Unknown"
                finding["analysis"] = "No adversarial analysis available."

            analyzed_results.append(finding)

        return analyzed_results
