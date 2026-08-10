#!/usr/bin/env python3
"""Create separate receiver-public and presenter-private local demo configs."""

from pathlib import Path

from authority_reference import issue_authority
from authority_reference.deployment_config import write_configs

target = Path(".local")
target.mkdir(exist_ok=True)
write_configs(
    issue_authority(), target / "receiver-trust.json", target / "presenter.json"
)
print("created .local/receiver-trust.json and mode-0600 .local/presenter.json")
