import io
import json
import runpy
import sys
from contextlib import redirect_stdout

from iam_mapper.serialize import organization_to_dict
from iam_mapper.synthetic import build_sample_organization


def test_build_sample_organization_shape():
    org = build_sample_organization()
    expected_users = {"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heather"}
    expected_roles = {"data-pipeline-role", "ci-role", "audit-role", "ci-cd-service", "vendor-role"}
    assert set(org.users) == expected_users
    assert set(org.roles) == expected_roles
    assert org.account_id == "123456789012"


def test_module_run_as_script_prints_organization_json():
    """``python -m iam_mapper.synthetic`` is the documented way to regenerate
    data/sample_org.json -- make sure the ``__main__`` entry point actually
    produces valid, matching JSON on stdout."""
    sys.modules.pop("iam_mapper.synthetic", None)  # force a fresh run of the __main__ block
    buf = io.StringIO()
    with redirect_stdout(buf):
        runpy.run_module("iam_mapper.synthetic", run_name="__main__")

    data = json.loads(buf.getvalue())
    assert data == organization_to_dict(build_sample_organization())
