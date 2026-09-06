"""iam-attack-mapper: AWS IAM privilege-escalation path mapper.

A BloodHound-style analyzer for AWS IAM: given a description of an
account's users, roles, groups, and policies, it builds a graph of who
can escalate to whose privileges (and how), and reports the shortest
paths from low-privileged principals to admin-equivalent access.
"""

__version__ = "0.1.0"
