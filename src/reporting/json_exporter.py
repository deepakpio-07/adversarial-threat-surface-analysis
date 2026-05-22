import json


class JSONExporter:

    def export_findings(
        self,
        findings,
        attack_paths,
        attack_chains
    ):

        export_path = (
            "reports/findings.json"
        )

        export_data = {

            "findings": findings,

            "attack_opportunities":
                attack_paths,

            "attack_chains":
                attack_chains
        }

        with open(export_path, "w") as json_file:

            json.dump(
                export_data,
                json_file,
                indent=4
            )

        print(
            f"\n[+] JSON exported: "
            f"{export_path}"
        )
