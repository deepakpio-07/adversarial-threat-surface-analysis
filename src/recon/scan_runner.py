from src.reporting.report_generator import ReportGenerator
from src.scoring.risk_score import RiskScorer
from src.mitre.mitre_mapper import MitreMapper
from src.recon.nmap_scan import NmapScanner
from src.parser.xml_parser import XMLParser
from src.analysis.exposure_analyzer import ExposureAnalyzer
from src.analysis.remediation_engine import RemediationEngine
from src.analysis.cve_mapper import CVEMapper
from src.attackpath.path_engine import AttackPathEngine
from src.attackpath.chain_engine import AttackChainEngine


class ScanRunner:

    def __init__(self, target):
        self.target = target

    def execute(self):

        print("\n" + "=" * 70)
        print(" ADvERSARIAL THREAT SURFACE ANALYSIS FRAMEWORK ")
        print("=" * 70)

        print(f"\n[+] Target Selected: {self.target}")

        # Run Nmap scan
        print("\n[+] Starting Reconnaissance Phase...")

        scanner = NmapScanner(self.target)
        scanner.run_scan()

        # Parse XML results
        print("[+] Parsing Reconnaissance Results...")

        parser = XMLParser("data/raw/nmap_scan.xml")

        findings = parser.parse_nmap_xml()

        parser.save_findings(findings)

        # Exposure Analysis
        print("[+] Performing Exposure Analysis...")

        analyzer = ExposureAnalyzer()

        analyzed_findings = analyzer.analyze(findings)

        # MITRE ATT&CK Mapping
        print("[+] Mapping MITRE ATT&CK Techniques...")

        mitre_mapper = MitreMapper()

        mapped_findings = mitre_mapper.map_techniques(
            analyzed_findings
        )

        # Risk Scoring
        print("[+] Calculating Adversarial Risk Scores...")

        risk_scorer = RiskScorer()

        scored_findings = risk_scorer.calculate_risk(
            mapped_findings
        )

        # Remediation Intelligence
        print("[+] Generating Remediation Intelligence...")

        remediation_engine = RemediationEngine()

        remediated_findings = (
            remediation_engine.apply_remediation(
                scored_findings
            )
        )

        # CVE Intelligence
        print("[+] Enriching CVE Intelligence...")

        cve_mapper = CVEMapper()

        cve_findings = cve_mapper.map_cves(
            remediated_findings
        )

        print("\n" + "=" * 70)
        print(" EXTRACTED ADVERSARIAL FINDINGS ")
        print("=" * 70)

        for finding in cve_findings:

            print(
                f"\n[{finding['severity']}] "
                f"{finding['service'].upper()} "
                f"({finding['port']}/{finding['protocol']})"
            )

            print(f"Host           : {finding['ip']}")

            print(
                f"Risk Level     : "
                f"{finding['risk']}"
            )

            print(
                f"Adversarial Score : "
                f"{finding['adversarial_score']}"
            )

            print(
                f"MITRE Technique: "
                f"{finding['mitre_technique']} "
                f"({finding['mitre_id']})"
            )

            print(
                f"CVE            : "
                f"{finding['cve']} "
                f"[{finding['cve_severity']}]"
            )

            print(
                f"Analysis       : "
                f"{finding['analysis']}"
            )

            print(
                f"Remediation    : "
                f"{finding['remediation']}"
            )

            print("-" * 70)

        # Attack Opportunities
        attack_engine = AttackPathEngine()

        attack_paths = attack_engine.generate_paths(
            cve_findings
        )

        print("\n" + "=" * 70)
        print(" ATTACK OPPORTUNITIES ")
        print("=" * 70)

        for attack in attack_paths:

            print(
                f"\n[+] {attack['service']} "
                f"(Port {attack['port']})"
            )

            print(
                f"    → "
                f"{attack['attack_opportunity']}"
            )

        # Attack Chains
        chain_engine = AttackChainEngine()

        attack_chains = chain_engine.generate_chains(
            cve_findings
        )

        print("\n" + "=" * 70)
        print(" ATTACK CHAINS ")
        print("=" * 70)

        for chain in attack_chains:

            print(
                f"\n[!] {chain['chain']}"
            )

            print(
                f"    Severity: "
                f"{chain['severity']}"
            )

        # Generate Report
        print("\n[+] Generating Reports...")

        report_generator = ReportGenerator()

        report_generator.generate_report(
            cve_findings,
            attack_paths,
            attack_chains
        )

        print("\n" + "=" * 70)
        print(" ANALYSIS COMPLETED SUCCESSFULLY ")
        print("=" * 70)
