"""IAM Sentinel — cloud IAM security posture & entitlement analysis platform.

Package layout
--------------
- ``app.domain``     Pure, dependency-light types + logic (parser, checks, risk,
                     fingerprint). This is the heavily-tested core.
- ``app.analysis``   The rule registry + engine that drive the domain checks.
- ``app.ingestion``  Source adapters (file / REST / moto-AWS) + normalization.
- ``app.models``     SQLAlchemy ORM persistence layer.
- ``app.services``   Application services that orchestrate ingestion + analysis
                     + persistence (ScanService, IngestionService, ...).
- ``app.web``        Flask app (blueprints) — grows across the phased roadmap.
"""

__version__ = "0.1.0"
