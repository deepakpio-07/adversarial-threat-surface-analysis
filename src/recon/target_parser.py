import re
import ipaddress


class TargetParser:
    def __init__(self, target):
        self.target = target.strip()

    def is_valid_ip(self):
        try:
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            return False

    def is_valid_domain(self):
        domain_regex = re.compile(
            r"^(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}$"
        )

        return re.match(domain_regex, self.target) is not None

    def validate_target(self):
        if self.is_valid_ip():
            return {
                "target": self.target,
                "type": "ip"
            }

        elif self.is_valid_domain():
            return {
                "target": self.target,
                "type": "domain"
            }

        else:
            raise ValueError(f"[!] Invalid target: {self.target}")
