#!/usr/bin/env python3
"""Create separate receiver-public and presenter-private local demo configs."""

from pathlib import Path

from authority_reference import issue_authority
from authority_reference.deployment_config import write_configs

target = Path(".local")
target.mkdir(exist_ok=True)
try:
    write_configs(
        issue_authority(), target / "receiver-trust.json", target / "presenter.json"
    )
except FileExistsError as exc:
    raise SystemExit(
        "local configs already exist; remove references/google-adk/.local/ "
        "before generating a new authority"
    ) from exc
print("created mode-0600 .local/receiver-trust.json and .local/presenter.json")
