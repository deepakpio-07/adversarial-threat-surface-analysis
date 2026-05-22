class ReportGenerator:

    def generate_report(self, findings, attack_paths, attack_chains):

        report_path = "reports/report.txt"

        with open(report_path, "w") as report:

            report.write("=== ADVERSARIAL THREAT SURFACE REPORT ===\n\n")

            report.write("=== FINDINGS ===\n\n")

            for finding in findings:

                report.write(
                    f"Host: {finding['ip']}\n"
                )

                report.write(
                    f"Port: {finding['port']}/{finding['protocol']}\n"
                )

                report.write(
                    f"Service: {finding['service']}\n"
                )

                report.write(
                    f"Risk: {finding['risk']}\n"
                )

                report.write(
                    f"Severity: {finding['severity']}\n"
                )

                report.write(
                    f"Adversarial Score: "
                    f"{finding['adversarial_score']}\n"
                )

                report.write(
                    f"MITRE Technique: "
                    f"{finding['mitre_technique']} "
                    f"({finding['mitre_id']})\n"
                )

                report.write(
                    f"Remediation: "
					f"{finding['remediation']}\n"
                )

                report.write("\n-------------------------\n\n")

            report.write("\n=== ATTACK OPPORTUNITIES ===\n\n")

            for attack in attack_paths:

                report.write(
                    f"{attack['service']} "
                    f"(Port {attack['port']}) "
                    f"→ {attack['attack_opportunity']}\n"
                )
            report.write(
                "\n=== ATTACK CHAINS ===\n\n"
            )

            for chain in attack_chains:

                report.write(
                    f"{chain['chain']} "
                    f"[Severity: "
                    f"{chain['severity']}]\n"
                )

        print(
            f"\n[+] Report generated: {report_path}"
        )
