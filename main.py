from src.recon.target_parser import TargetParser
from src.recon.scan_runner import ScanRunner


def main():
    target = input("Enter target IP or domain: ")

    parser = TargetParser(target)

    try:
        validated = parser.validate_target()

        print("\n[+] Valid Target Detected")
        print(f"Target : {validated['target']}")
        print(f"Type   : {validated['type']}")

        runner = ScanRunner(validated['target'])
        runner.execute()

    except ValueError as error:
        print(error)


if __name__ == "__main__":
    main()
