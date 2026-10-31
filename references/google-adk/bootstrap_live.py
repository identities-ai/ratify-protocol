#!/usr/bin/env python3
"""Create separate receiver and presenter local demo configs.

Also publishes each issuer's signed status list to .local/status. The lists
are signed for 24 hours; after that the receiver denies with status_stale
until you remove .local/ and bootstrap again.
"""

from pathlib import Path

from authority_reference import issue_authority
from authority_reference.deployment_config import write_configs

target = Path(".local")
target.mkdir(exist_ok=True)
try:
    write_configs(
        issue_authority(status_lifetime_seconds=86_400),
        target / "receiver-trust.json",
        target / "presenter.json",
        status_dir=target / "status",
    )
except FileExistsError as exc:
    raise SystemExit(
        "local configs already exist; remove references/google-adk/.local/ "
        "before generating a new authority"
    ) from exc
print("created mode-0600 .local/receiver-trust.json and .local/presenter.json")
print("published signed status lists to .local/status")
