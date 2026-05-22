from src.scoring.risk_score import (
    RiskScorer
)


def test_risk_scoring():

    scorer = RiskScorer()

    findings = [
        {
            "service": "rdp"
        }
    ]

    results = scorer.calculate_risk(
        findings
    )

    assert (
        results[0]["severity"]
        == "Critical"
    )
