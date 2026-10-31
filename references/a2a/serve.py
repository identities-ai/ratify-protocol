"""Run the independent A2A receiver for the local HTTPS reference gate."""

import base64
import json
import os

import uvicorn
from ratify_protocol.v2 import HybridPublicKey

from authority_v2 import InfrastructureReceiverV2
from poc import build_app


def _key(value: dict) -> HybridPublicKey:
    return HybridPublicKey(ed25519=bytes.fromhex(value["ed25519"]), ml_dsa_65=bytes.fromhex(value["ml_dsa_65"]))


def main() -> None:
    port = int(os.environ["A2A_PORT"])
    token = os.environ["A2A_BEARER_TOKEN"]
    # Public trust material only: the pinned root key, the expected agent key,
    # each issuer's status key, and the signed status objects to start from.
    with open(os.environ["A2A_RECEIVER_CONFIG"], encoding="utf-8") as handle:
        config = json.load(handle)
    agent_key = _key(config["agent_public_key"])
    receiver = InfrastructureReceiverV2(
        trusted_root_id=config["root_id"],
        trusted_root_public_key=_key(config["root_public_key"]),
        expected_agent_public_key=agent_key,
        status_keys={issuer: _key(key) for issuer, key in config["status_keys"].items()},
        status_objects={
            issuer: [(obj["type"], base64.b64decode(obj["wire"])) for obj in objects]
            for issuer, objects in config["status_objects"].items()
        },
    )
    app = build_app(
        receiver, receiver.expected_agent_id,
        base_url=f"https://localhost:{port}/", bearer_token=token,
    )
    uvicorn.run(
        app, host="127.0.0.1", port=port, log_level="warning",
        ssl_certfile=os.environ["A2A_TLS_CERT"],
        ssl_keyfile=os.environ["A2A_TLS_KEY"],
    )


if __name__ == "__main__":
    main()
