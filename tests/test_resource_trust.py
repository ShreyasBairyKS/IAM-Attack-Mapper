from iam_mapper.analyzer import analyze
from iam_mapper.models import Organization, ResourcePolicy, ResourcePolicyStatement
from iam_mapper.resource_trust import find_external_resource_trusts


def _account():
    return Organization(account_id="111111111111")


def test_wildcard_principal_flagged():
    org = _account()
    org.resource_policies = [ResourcePolicy(
        resource_arn="arn:aws:s3:::open-bucket", resource_type="s3_bucket",
        statements=[ResourcePolicyStatement(effect="Allow", principals=["*"], actions=["s3:GetObject"])],
    )]

    findings = find_external_resource_trusts(org, "111111111111")
    assert len(findings) == 1
    assert findings[0].resource_arn == "arn:aws:s3:::open-bucket"
    assert findings[0].resource_type == "s3_bucket"
    assert findings[0].principal_ref == "*"
    assert "wildcard" in findings[0].note


def test_external_account_principal_flagged():
    org = _account()
    org.resource_policies = [ResourcePolicy(
        resource_arn="arn:aws:s3:::shared-bucket", resource_type="s3_bucket",
        statements=[ResourcePolicyStatement(
            effect="Allow", principals=["arn:aws:iam::999999999999:root"], actions=["s3:GetObject"],
        )],
    )]

    findings = find_external_resource_trusts(org, "111111111111")
    assert len(findings) == 1
    assert "different AWS account" in findings[0].note


def test_same_account_principal_not_flagged():
    org = _account()
    org.resource_policies = [ResourcePolicy(
        resource_arn="arn:aws:s3:::internal-bucket", resource_type="s3_bucket",
        statements=[ResourcePolicyStatement(
            effect="Allow", principals=["arn:aws:iam::111111111111:role/some-role"], actions=["s3:GetObject"],
        )],
    )]

    assert find_external_resource_trusts(org, "111111111111") == []


def test_deny_statement_not_flagged():
    org = _account()
    org.resource_policies = [ResourcePolicy(
        resource_arn="arn:aws:s3:::guarded-bucket", resource_type="s3_bucket",
        statements=[ResourcePolicyStatement(effect="Deny", principals=["*"], actions=["s3:GetObject"])],
    )]

    assert find_external_resource_trusts(org, "111111111111") == []


def test_no_resource_policies_returns_empty():
    assert find_external_resource_trusts(_account(), "111111111111") == []


# --------------------------------------------------------------------------
# analyze() wiring: severity mapping and finding kind.
# --------------------------------------------------------------------------


def test_analyze_flags_wildcard_bucket_as_high():
    org = _account()
    org.resource_policies = [ResourcePolicy(
        resource_arn="arn:aws:s3:::open-bucket", resource_type="s3_bucket",
        statements=[ResourcePolicyStatement(effect="Allow", principals=["*"], actions=["s3:GetObject"])],
    )]

    result = analyze(org)
    findings = [f for f in result.findings if f.kind == "external_resource_trust"]
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].target == "arn:aws:s3:::open-bucket"
    assert "open-bucket" in findings[0].summary


def test_analyze_flags_cross_account_bucket_as_medium():
    org = _account()
    org.resource_policies = [ResourcePolicy(
        resource_arn="arn:aws:s3:::shared-bucket", resource_type="s3_bucket",
        statements=[ResourcePolicyStatement(
            effect="Allow", principals=["arn:aws:iam::999999999999:root"], actions=["s3:GetObject"],
        )],
    )]

    result = analyze(org)
    findings = [f for f in result.findings if f.kind == "external_resource_trust"]
    assert len(findings) == 1
    assert findings[0].severity == "Medium"
