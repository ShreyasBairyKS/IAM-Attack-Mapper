# iam-attack-mapper

A BloodHound-style privilege-escalation path mapper for AWS IAM.

Give it a snapshot of an AWS account's users, roles, groups, and policies,
and it builds a graph of **who can escalate to whose privileges, and how**
— then reports the shortest path from every low-privileged principal to
admin-equivalent access, ranked by severity.

```
$ iam-mapper analyze -i data/sample_org.json --no-color

========================================================================
IAM Attack-Path Mapper -- Report
========================================================================
Principals analyzed : 13
Already admin        : 4
Findings             : 11

[Critical] SELF-ESCALATION
  alice -> --[PolicyVersionEscalation]--> alice
    - PolicyVersionEscalation: can iam:CreatePolicyVersion on policy 'AppDeployPolicy', which is attached to 'alice'

[Critical] ESCALATION PATH
  bob -> --[CreateAccessKey]--> carol
    - CreateAccessKey: can create an access key for user 'carol'

[High] ESCALATION PATH
  frank -> --[UpdateAssumeRolePolicy]--> audit-role -> --[AttachPolicy]--> ADMIN-EQUIVALENT ACCESS
    - UpdateAssumeRolePolicy: can rewrite the trust policy of role 'audit-role' to add itself
    - AttachPolicy: can iam:AttachRolePolicy on 'audit-role' (attach e.g. AdministratorAccess)
  ...
```

## Why this exists

IAM's `Allow`/`Deny`/`Condition` evaluation is expressive enough that
"who has permission X" is easy to answer, but "who can *become* an
admin, two or three permissions removed from what they hold today" is
not — you have to know the ~20 documented AWS IAM privilege-escalation
techniques and manually check for every combination across every
principal. Tools like [Rhino Security Labs' original
research](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/),
[Cloudsplaining](https://github.com/salesforce/cloudsplaining), and
[PMapper](https://github.com/nccgroup/PMapper) established this space;
this project's angle is to model it explicitly as a **graph reachability
problem** (the way [BloodHound](https://github.com/BloodHoundAD/BloodHound)
does for Active Directory) so multi-hop chains — "A can modify B's trust
policy, and B can attach a policy to itself" — are found automatically
instead of requiring a human to notice the chain.

## How it works

```
account JSON, or a live AWS account via aws_collector.py (boto3)
        |
        v
  models.py            <- typed Users / Roles / Groups / Policies
        |
        v
  policy_engine.py     <- "is action X on resource Y allowed for principal P?"
        |
        v
  escalation_rules.py  <- ~12 known privesc techniques, each emits graph edges
  trust.py             <- direct sts:AssumeRole edges + cross-account trust findings
        |
        v
  graph_builder.py      <- networkx.MultiDiGraph: nodes = principals, edges = "can become"
        |
        v
  analyzer.py           <- shortest path from every principal to admin-equivalent access
        |
        v
  report.py / export.py <- text/JSON report, GraphML/JSON graph export
  diff.py                <- compares two AnalysisResults: new/resolved/changed findings
```

### Escalation techniques implemented

Each of these is a documented, real AWS IAM privilege-escalation
technique, implemented as a rule that adds a `source -> target` edge
("source can end up with target's effective permissions") to the graph:

| Technique | Idea |
|---|---|
| `PolicyVersionEscalation` | `iam:CreatePolicyVersion` / `SetDefaultPolicyVersion` on a customer-managed policy lets you rewrite it to `"*"/"*"`. |
| `CreateAccessKey` | `iam:CreateAccessKey` on another user mints you a working credential as them. |
| `LoginProfileTakeover` | `iam:CreateLoginProfile` / `UpdateLoginProfile` on another user lets you set their console password. |
| `AttachPolicy` | `iam:Attach{User,Role,Group}Policy` lets you attach e.g. `AdministratorAccess` to yourself or someone else. |
| `InlinePolicyInjection` | `iam:Put{User,Role,Group}Policy` lets you write a fresh admin inline policy. |
| `AddUserToGroup` | `iam:AddUserToGroup` lets you add a principal (e.g. yourself) to a more privileged group. |
| `UpdateAssumeRolePolicy` | `iam:UpdateAssumeRolePolicy` lets you rewrite a role's trust policy to add yourself as trusted. |
| `PassRole+Lambda` / `PassRole+EC2` / `PassRole+GlueDevEndpoint` / `PassRole+CloudFormation` / `PassRole+DataPipeline` | `iam:PassRole` plus the matching service action lets you run code/instances *as* that role. |
| `AssumeRole` | (not an escalation on its own) direct, legitimate `sts:AssumeRole` reachability — still part of the graph, since an overly-trusting role is exactly what this tool should surface. |

This is a representative subset, not the full list of ~20 documented
techniques — see [Roadmap](#roadmap) for what's next.

### Severity model

- **1 hop** to admin-equivalent access = `Critical`, **2 hops** = `High`,
  **3 hops** = `Medium`, more = `Low`.
- A hop whose statement carries an IAM `Condition` is not fully evaluated
  (see [Limitations](#limitations)) — it's still counted, but the whole
  finding is downgraded one severity level and marked "conditional",
  since exploitability now depends on satisfying that condition.
- A principal that already has `"*"/"*"` (or `iam:*`, since full IAM
  control always leads back to `"*"/"*"`) is reported once as
  `already_admin`, not re-derived as a 1-hop "path".

## Installation

```bash
pip install -e .          # installs the `iam-mapper` command
# or, without installing:
pip install -r requirements.txt
python -m iam_mapper.cli --help

# To pull live data from a real AWS account, also install the `aws` extra:
pip install -e ".[aws]"
```

## Usage

```bash
# Regenerate the synthetic demo account (no AWS access needed):
iam-mapper generate-sample -o data/sample_org.json

# Analyze it:
iam-mapper analyze -i data/sample_org.json

# JSON output, for piping into other tools:
iam-mapper analyze -i data/sample_org.json --format json

# Export the graph for Gephi / yEd / a future web UI:
iam-mapper analyze -i data/sample_org.json --output-graph graph.graphml
iam-mapper analyze -i data/sample_org.json --output-graph graph.json

# CI use -- exit non-zero if anything Critical/High is found:
iam-mapper analyze -i data/sample_org.json --fail-on High

# Pull live IAM state from a real AWS account (read-only; requires the
# `aws` extra and credentials via the normal boto3 chain -- profile, env
# vars, or an instance/task role) into the same JSON schema, then analyze it:
iam-mapper collect --profile my-aws-profile -o live_org.json
iam-mapper analyze -i live_org.json --fail-on High

# Continuous scanning: diff two snapshots to see what changed, and fail
# CI only on genuine regressions (new findings, or existing ones that
# got more severe) -- not on pre-existing findings you already know about:
iam-mapper collect --profile my-aws-profile -o baseline.json   # e.g. last week
iam-mapper collect --profile my-aws-profile -o current.json    # today
iam-mapper diff baseline.json current.json --fail-on-regression
```

### Collecting from a live account

`iam-mapper collect` only ever calls read-only `iam:List*`/`iam:Get*`
APIs (plus one `sts:GetCallerIdentity` to default the account id) — it
cannot modify the account it's pointed at. It walks users, roles, and
groups and fetches each *referenced* customer-managed/AWS-managed policy
exactly once (never `iam:ListPolicies`, which would enumerate the
~1,000+ AWS-managed policies regardless of whether they're in use).

```bash
iam-mapper collect --profile my-aws-profile --region us-east-1 -o live_org.json
```

`--account-id` overrides the account id if your credentials belong to a
different account than the one being audited; `--profile`/`--region`
are passed straight through to `boto3.Session`.

### The account JSON format

See `data/sample_org.json` (generated by `iam_mapper/synthetic.py`) for
a full worked example, and `iam_mapper/models.py` for the schema. In
short: `users`, `roles`, `groups`, and customer/AWS-managed `policies`,
each shaped closely enough to real `iam:Get*`/`iam:List*` boto3
responses that a live-AWS backend can populate the same structures
without changing anything downstream.

### The synthetic demo account

`iam_mapper/synthetic.py` builds a 13-principal account with several
deliberately planted escalation paths, so you can see the analyzer work
without needing real AWS credentials:

- **alice** — can push a new version of her own attached policy (`PolicyVersionEscalation`, self, 1 hop).
- **bob** — has `iam:CreateAccessKey` scoped to `*` instead of just himself, so he can mint a key for **carol**, an existing admin (1 hop).
- **dave** — `iam:PassRole` + Lambda actions onto an over-privileged automation role (1 hop).
- **erin** — same idea via EC2 onto a role with full IAM control (1 hop).
- **frank** — can rewrite **audit-role**'s trust policy to add himself, and audit-role can (mistakenly) attach policies to itself — a genuine 2-hop chain (`High`).
- **grace** — an ordinary developer with no dangerous permissions: no finding (true negative).
- **heather** — already has `AdministratorAccess` via group membership: flagged as `already_admin`, not re-derived as a path.
- **vendor-role** — trusts an external AWS account: flagged separately as a trust-policy hygiene finding, not an internal escalation path.

## Limitations

This is a v1 focused on getting the graph model and the core escalation
techniques right, not on covering every corner of IAM evaluation:

- **Live AWS collection is single-account only** — `iam-mapper collect`
  pulls the caller's own account (or one overridden via `--account-id`,
  if credentials permit); cross-account collection via `sts:AssumeRole`
  is not yet implemented (see Roadmap).
- **`Federated` trust-policy principals are stored but not resolved
  further** — they're not IAM principals this tool can trace deeper.
- **IAM `Condition` blocks are not evaluated** — a matching statement
  with a condition is treated as "would allow" and flagged
  `conditional`, downgrading severity by one level, rather than
  resolving condition operators (`StringEquals`, `IpAddress`, etc).
- **No Service Control Policies (SCPs), resource-based policies (other
  than role trust policies), or session policies.**
- **`NotResource` is not supported** (only `Resource`/`NotAction`/`Action`).
- Wildcard matching follows IAM's `*`/`?` semantics but doesn't model
  every edge case of ARN structure.

## Roadmap

- [x] Live AWS backend: pull real IAM data via `boto3` (`iam:Get*`/`List*`)
      into the same `Organization` model (`iam-mapper collect`).
- [x] Continuous scanning + diffing (`iam-mapper diff`): "this deploy
      opened a new escalation path."
- [ ] Cross-account collection via `sts:AssumeRole`, for auditing an
      entire AWS Organization from one central role.
- [ ] Web UI: interactive graph visualization (the exported GraphML/JSON
      is already shaped for this).
- [ ] More escalation techniques (S3 bucket policy backdoors,
      `iam:CreateServiceLinkedRole` abuse, SSM `SendCommand` against an
      existing instance's role, etc).
- [ ] SCP-aware evaluation for multi-account AWS Organizations.
- [ ] Multi-cloud: the same graph-reachability model applied to GCP IAM
      and Azure RBAC.

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

## License

MIT — see [LICENSE](LICENSE).
