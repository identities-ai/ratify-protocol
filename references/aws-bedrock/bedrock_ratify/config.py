"""Shared configuration for the two-agent Bedrock + Ratify reference."""
from __future__ import annotations

import os

# --- Bedrock -----------------------------------------------------------------
# Claude on Amazon Bedrock is reached through the Mantle client; Bedrock model
# IDs carry an `anthropic.` prefix.
AWS_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-opus-5")

# --- The protected resource --------------------------------------------------
# Agent 1 asks for this directory. Agent 2 owns it and will not read it without
# a Ratify proof that a recognised principal authorised this exact request.
PROTECTED_ROOT = os.environ.get("SIDE_EVENT_DIR", r"C:\SideEvents")

# Resource identity as it appears inside the signed delegation. The verifier
# compares this against what the caller asks for; a proof naming a different
# resource is refused even when its signatures are perfect.
RESOURCE_ID = "file:sideevents"

# Authority the receiver demands before the handler runs.
REQUIRED_SCOPE = "files:read"

# Agent 2's identity as a verifier, used for session-context binding.
VERIFIER_ID = "agent2.sideevents.local"
WORKSPACE_ID = "sideevents-demo"

# How long the principal's delegation lives, and the ceiling on any narrowed
# hop the requester passes onward.
DELEGATION_TTL_SECONDS = 3600
CHALLENGE_TTL_SECONDS = 60
