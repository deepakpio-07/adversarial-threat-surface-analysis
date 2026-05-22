class MitreMapper:

    MITRE_TECHNIQUES = {

        "ssh": {
            "technique": "Brute Force",
            "id": "T1110"
        },

        "ftp": {
            "technique": "Valid Accounts",
            "id": "T1078"
        },

        "telnet": {
            "technique": "Credential Access",
            "id": "T1110"
        },

        "http": {
            "technique": "Exploit Public-Facing Application",
            "id": "T1190"
        },

        "https": {
            "technique": "Exploit Public-Facing Application",
            "id": "T1190"
        },

        "microsoft-ds": {
            "technique": "SMB/Windows Admin Shares",
            "id": "T1021.002"
        },

        "smb": {
            "technique": "SMB/Windows Admin Shares",
            "id": "T1021.002"
        },

        "rdp": {
            "technique": "Remote Services",
            "id": "T1021"
        },

        "ms-wbt-server": {
            "technique": "Remote Services",
            "id": "T1021"
        }
    }

    def map_techniques(self, findings):

        mapped_results = []

        for finding in findings:

            service = finding["service"].lower()

            if service in self.MITRE_TECHNIQUES:

                mitre_data = self.MITRE_TECHNIQUES[service]

                finding["mitre_technique"] = mitre_data["technique"]
                finding["mitre_id"] = mitre_data["id"]

            else:

                finding["mitre_technique"] = "Unknown"
                finding["mitre_id"] = "N/A"

            mapped_results.append(finding)

        return mapped_results
