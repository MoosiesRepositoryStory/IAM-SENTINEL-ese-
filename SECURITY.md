# Security Policy

IAM Sentinel is a security-tooling **portfolio project**, not a production
service with real customer data. Its whole point is careful handling of
security concerns, so genuine reports are very welcome and taken seriously —
please just keep in mind there is no commercial support or SLA behind it.

## Supported versions

Development is linear and pre-1.0; only the latest release line receives
fixes. There is no back-porting to older tags.

| Version | Supported |
|---------|-----------|
| 0.5.x (latest) | ✅ |
| < 0.5   | ❌ |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Instead, report it privately through GitHub's
[private vulnerability reporting](https://github.com/MoosiesRepositoryStory/IAM-SENTINEL-ese-/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). This keeps
the details confidential until a fix is available.

Please include:

- what the issue is and where (file/route/endpoint if you know it),
- how to reproduce it, and
- the impact you think it has.

### What to expect

- **Acknowledgement within 5 business days** that the report was received.
- An initial assessment (confirmed / need-more-info / not-applicable) within
  **10 business days**.
- For confirmed issues, a fix or a documented mitigation on the `master`
  branch, with credit to the reporter in the release notes unless you prefer
  otherwise.

Because this is a personal portfolio project maintained in spare time, these
are good-faith targets rather than a contractual guarantee — but they reflect
the intent to respond promptly.

## Scope notes

A few things are intentional, documented behaviors rather than
vulnerabilities:

- **The public-demo posture** hands out a *shared* seeded admin login for
  recruiter convenience. Several hardening measures exist precisely because
  "admin-configured" can't be fully trusted in that mode — e.g. the outbound
  SSRF guard on the webhook integration
  (`app/integrations/net_safety.py`) and `PUBLIC_MODE`, which clamps every
  capability above `read_only` (`app/services/rbac.py`). A shared demo admin
  being able to do demo-admin things is by design.
- **The dev/demo defaults are deliberately insecure** (`SECRET_KEY=dev-…`,
  SQLite, no TLS). Setting `ENVIRONMENT=production` makes `Settings.validate()`
  fail closed on weak or shared signing keys — see `app/config.py`. Reports
  about the *dev* defaults being weak are expected; reports about the
  production fail-closed path *not* firing are in scope.

All ingested "cloud" data is simulated (moto-backed); the app holds no real
AWS credentials.
