from iam_mapper.models import Organization, Policy, ResourcePolicy, ResourcePolicyStatement, Statement
from iam_mapper.serialize import organization_from_dict, organization_to_dict, load_organization, save_organization


def test_scps_and_resource_policies_round_trip_through_dict():
    org = Organization(account_id="111111111111")
    org.scps = [Policy(
        name="DenyIAM", arn="arn:aws:organizations::111111111111:policy/p-1",
        statements=[Statement(effect="Deny", actions=["iam:*"], resources=["*"])],
    )]
    org.resource_policies = [ResourcePolicy(
        resource_arn="arn:aws:s3:::open-bucket", resource_type="s3_bucket",
        statements=[ResourcePolicyStatement(
            effect="Allow", principals=["*"], actions=["s3:GetObject"], resources=["arn:aws:s3:::open-bucket/*"],
        )],
    )]

    restored = organization_from_dict(organization_to_dict(org))

    assert len(restored.scps) == 1
    assert restored.scps[0].name == "DenyIAM"
    assert restored.scps[0].statements[0].effect == "Deny"

    assert len(restored.resource_policies) == 1
    assert restored.resource_policies[0].resource_arn == "arn:aws:s3:::open-bucket"
    assert restored.resource_policies[0].resource_type == "s3_bucket"
    assert restored.resource_policies[0].statements[0].principals == ["*"]


def test_organization_with_no_scps_or_resource_policies_round_trips_to_empty_lists():
    org = Organization(account_id="111111111111")
    restored = organization_from_dict(organization_to_dict(org))
    assert restored.scps == []
    assert restored.resource_policies == []


def test_save_and_load_organization_file_preserves_scps(tmp_path):
    org = Organization(account_id="111111111111")
    org.scps = [Policy(
        name="DenyIAM", arn="arn:aws:organizations::111111111111:policy/p-1",
        statements=[Statement(effect="Deny", actions=["iam:*"], resources=["*"])],
    )]
    path = tmp_path / "org.json"
    save_organization(org, str(path))

    restored = load_organization(str(path))
    assert restored.scps[0].name == "DenyIAM"


def test_loading_pre_existing_json_without_scps_field_still_works(tmp_path):
    """Old snapshots saved before scps/resource_policies existed shouldn't break."""
    import json

    path = tmp_path / "old_org.json"
    path.write_text(json.dumps({
        "account_id": "111111111111",
        "users": [], "roles": [], "groups": [], "policies": [],
    }))
    restored = load_organization(str(path))
    assert restored.scps == []
    assert restored.resource_policies == []
