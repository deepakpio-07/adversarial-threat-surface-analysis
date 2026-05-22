class RiskScorer:

    SERVICE_SCORES = {

        "ssh": 5,

        "ftp": 6,

        "telnet": 9,

        "http": 3,

        "https": 3,

        "microsoft-ds": 8,

        "smb": 8,

        "rdp": 10,

        "ms-wbt-server": 10
    }

    def calculate_risk(self, findings):

        scored_findings = []

        for finding in findings:

            service = finding["service"].lower()

            score = self.SERVICE_SCORES.get(service, 1)

            if score >= 9:
                severity = "Critical"

            elif score >= 7:
                severity = "High"

            elif score >= 4:
                severity = "Medium"

            else:
                severity = "Low"

            finding["adversarial_score"] = score
            finding["severity"] = severity

            scored_findings.append(finding)

        return scored_findings
