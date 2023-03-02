from tools.triage import ALL_SIGNATURES


def test_create_instances():
    """
    Simple test to make sure we can at-least create instances of all signatures
    """
    for signature in ALL_SIGNATURES:
        jira_client = None
        sig = signature(jira_client, "AITRIAGE-999999")
        assert sig is not None
