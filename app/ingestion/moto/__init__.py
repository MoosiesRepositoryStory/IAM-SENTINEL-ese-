"""Simulated AWS ingestion (moto).

The marquee Phase 2 ingestion path: exercise *real* ``boto3`` code against a
*fake* AWS (moto) so the pipeline is genuine but needs no cloud account (§5.2).

Two honest simplifications, both documented at their call sites:

1. **CloudTrail is a seeded JSONL event store**, not real moto CloudTrail — moto's
   CloudTrail support is too thin to drive the log checks, so the adapter reads a
   curated ``cloudtrail_events.jsonl`` directly (still through the existing,
   tested CloudTrail parser).
2. **Temporal attributes moto can't backdate** (access-key age, last-login,
   password age) plus the human/service distinction are carried as **IAM resource
   tags** and read back through genuine ``boto3`` calls — so the whole IAM read is
   still a real round-trip, not a side manifest.

Everything else (users, roles, managed + inline policies, attachments, trust
documents, MFA devices, login profiles) is created and read through real IAM API
calls against the moto mock.
"""
