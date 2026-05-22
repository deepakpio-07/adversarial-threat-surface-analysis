from src.analysis.exposure_analyzer import (
    ExposureAnalyzer
)


def test_exposure_analysis():

    analyzer = ExposureAnalyzer()

    findings = [
        {
            "service": "ssh"
        }
    ]

    results = analyzer.analyze(
        findings
    )

    assert (
        results[0]["risk"] == "Medium"
    )
