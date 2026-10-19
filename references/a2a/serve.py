"""Run the independent A2A receiver for the local HTTPS reference gate."""

import os

import uvicorn
from ratify_protocol import HybridPublicKey

from poc import build_app
from authority_reference.receiver import InfrastructureReceiver


def main() -> None:
    port = int(os.environ["A2A_PORT"])
    token = os.environ["A2A_BEARER_TOKEN"]
    root = HybridPublicKey(
        ed25519=bytes.fromhex(os.environ["A2A_ROOT_ED25519"]),
        ml_dsa_65=bytes.fromhex(os.environ["A2A_ROOT_ML_DSA_65"]),
    )
    receiver = InfrastructureReceiver(
        trusted_root_id=os.environ["A2A_ROOT_ID"],
        trusted_root_public_key=root,
    )
    app = build_app(
        receiver, os.environ["A2A_AGENT_ID"],
        base_url=f"https://localhost:{port}/", bearer_token=token,
    )
    uvicorn.run(
        app, host="127.0.0.1", port=port, log_level="warning",
        ssl_certfile=os.environ["A2A_TLS_CERT"],
        ssl_keyfile=os.environ["A2A_TLS_KEY"],
    )


if __name__ == "__main__":
    main()
