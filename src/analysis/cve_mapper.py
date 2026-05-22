class CVEMapper:

    CVE_DATABASE = {

        "openssh": {
            "cve": "CVE-2018-15473",
            "severity": "Medium",
            "description": (
                "OpenSSH username enumeration vulnerability."
            )
        },

        "apache httpd": {
            "cve": "CVE-2021-41773",
            "severity": "High",
            "description": (
                "Path traversal and file disclosure vulnerability."
            )
        },

        "vsftpd": {
            "cve": "CVE-2011-2523",
            "severity": "Critical",
            "description": (
                "Backdoor command execution vulnerability."
            )
        },

        "samba": {
            "cve": "CVE-2017-7494",
            "severity": "Critical",
            "description": (
                "Remote code execution vulnerability in Samba."
            )
        }
    }

    def map_cves(self, findings):

        enriched_findings = []

        for finding in findings:

            product = str(
                finding.get("product", "")
            ).lower()

            matched = False

            for software in self.CVE_DATABASE:

                if software in product:

                    cve_data = self.CVE_DATABASE[software]

                    finding["cve"] = cve_data["cve"]
                    finding["cve_severity"] = (
                        cve_data["severity"]
                    )

                    finding["cve_description"] = (
                        cve_data["description"]
                    )

                    matched = True

                    break

            if not matched:

                finding["cve"] = "N/A"
                finding["cve_severity"] = "N/A"

                finding["cve_description"] = (
                    "No mapped CVE."
                )

            enriched_findings.append(finding)

        return enriched_findings
        
