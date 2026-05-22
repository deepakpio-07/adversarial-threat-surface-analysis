class RemediationEngine:

    REMEDIATIONS = {

        "ssh": (
            "Restrict SSH exposure using firewall rules, "
            "disable password authentication, "
            "and enforce MFA."
        ),

        "ftp": (
            "Disable anonymous FTP access and "
            "replace insecure FTP with SFTP if possible."
        ),

        "telnet": (
            "Disable Telnet immediately and "
            "replace with SSH."
        ),

        "http": (
            "Perform web application assessment and "
            "ensure secure configurations."
        ),

        "https": (
            "Validate TLS configurations and "
            "perform web security testing."
        ),

        "smb": (
            "Disable SMBv1, restrict lateral movement, "
            "and segment internal networks."
        ),

        "microsoft-ds": (
            "Disable SMBv1, restrict lateral movement, "
            "and segment internal networks."
        ),

        "rdp": (
            "Restrict RDP access through VPN, "
            "enable MFA, and monitor login attempts."
        ),

        "ms-wbt-server": (
            "Restrict RDP access through VPN, "
            "enable MFA, and monitor login attempts."
        )
    }

    def apply_remediation(self, findings):

        updated_findings = []

        for finding in findings:

            service = finding["service"].lower()

            remediation = self.REMEDIATIONS.get(
                service,
                "No remediation guidance available."
            )

            finding["remediation"] = remediation

            updated_findings.append(finding)

        return updated_findings
