r"""Key material split across the two processes, the way it splits in reality.

`python -m bedrock_ratify.web.keys` writes a keys/ directory:

    principal.json   private  — the client process holds this
    agent1.json      private  — the client process holds this
    agent2.json      private  — the server process holds this
    trusted-root.json         — the server's trust configuration:
                                the principal's PUBLIC key and nothing else

The server can therefore verify the client's proofs and cannot mint one. That
asymmetry is the whole point, and it only shows if the key files are separate.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ratify_protocol import (
    AgentIdentity,
    HumanRoot,
    HybridPrivateKey,
    HybridPublicKey,
    base64_standard_decode,
    base64_standard_encode,
    generate_agent,
    generate_human_root,
)

from ..identity import Party

KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"


def _pub(k: HybridPublicKey) -> dict:
    return {
        "ed25519": base64_standard_encode(k.ed25519),
        "ml_dsa_65": base64_standard_encode(k.ml_dsa_65),
    }


def _read_pub(d: dict) -> HybridPublicKey:
    return HybridPublicKey(
        ed25519=base64_standard_decode(d["ed25519"]),
        ml_dsa_65=base64_standard_decode(d["ml_dsa_65"]),
    )


def _read_priv(d: dict) -> HybridPrivateKey:
    return HybridPrivateKey(
        ed25519=base64_standard_decode(d["ed25519"]),
        ml_dsa_65=base64_standard_decode(d["ml_dsa_65"]),
    )


def generate(force: bool = False) -> None:
    KEYS_DIR.mkdir(exist_ok=True)
    if (KEYS_DIR / "principal.json").exists() and not force:
        print(f"keys already present in {KEYS_DIR}  (pass --force to regenerate)")
        return

    root, root_priv = generate_human_root()
    a1, a1_priv = generate_agent("SideEvents Requester", "api_agent")
    a2, a2_priv = generate_agent("SideEvents Custodian", "api_agent")

    (KEYS_DIR / "principal.json").write_text(json.dumps({
        "kind": "human_root", "id": root.id, "created_at": root.created_at,
        "public": _pub(root.public_key), "private": _pub(root_priv),
    }, indent=2))
    for name, ident, priv in (("agent1", a1, a1_priv), ("agent2", a2, a2_priv)):
        (KEYS_DIR / f"{name}.json").write_text(json.dumps({
            "kind": "agent", "id": ident.id, "name": ident.name,
            "agent_type": ident.agent_type, "created_at": ident.created_at,
            "public": _pub(ident.public_key), "private": _pub(priv),
        }, indent=2))

    # The server's copy: public half only.
    (KEYS_DIR / "trusted-root.json").write_text(json.dumps({
        "id": root.id, "public": _pub(root.public_key),
    }, indent=2))

    print(f"wrote {KEYS_DIR}")
    print(f"  principal      {root.id}   (client holds the private key)")
    print(f"  agent1         {a1.id}   (client)")
    print(f"  agent2         {a2.id}   (server)")
    print(f"  trusted-root   {root.id}   (server holds the public key only)")


def load_party(name: str) -> Party:
    d = json.loads((KEYS_DIR / f"{name}.json").read_text())
    pub = _read_pub(d["public"])
    priv = _read_priv(d["private"])
    if d["kind"] == "human_root":
        identity = HumanRoot(id=d["id"], public_key=pub, created_at=d["created_at"],
                             anchors=None)
    else:
        identity = AgentIdentity(id=d["id"], public_key=pub, name=d["name"],
                                 agent_type=d["agent_type"], created_at=d["created_at"])
    return Party(identity, priv)


def load_trusted_root_id() -> str:
    return json.loads((KEYS_DIR / "trusted-root.json").read_text())["id"]


def require_keys() -> None:
    if not (KEYS_DIR / "principal.json").exists():
        sys.exit("no keys found — run:  python -m bedrock_ratify.web.keys")


if __name__ == "__main__":
    generate(force="--force" in sys.argv)
