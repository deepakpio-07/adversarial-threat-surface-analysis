from src.attackpath.chain_engine import (
    AttackChainEngine
)


def test_attack_chain_generation():

    engine = AttackChainEngine()

    findings = [

        {
            "service": "rdp"
        },

        {
            "service": "smb"
        }
    ]

    chains = engine.generate_chains(
        findings
    )

    assert len(chains) > 0
