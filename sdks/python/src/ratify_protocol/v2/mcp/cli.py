"""ratify-mcp-signer command line (installed with the ``mcp-signer`` extra).

A wheel installs this console script even without the extra, so the first
thing it does is check for the extra's requirements and explain how to
install them."""
from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import re
import sys
import time
from typing import Optional, Sequence

from .. import _native
from .._version import __version__
from . import keys
from ._files import ensure_private_dir, read_private_file, write_private_file
from .config import CONSOLE_FIELDS
from .connect import parse_connect_token, prove_possession
from .errors import ConfigError, McpError, McpSignerError

INSTALL_HINT = f'pip install "ratify-protocol[protocol-v2,mcp-signer]=={__version__}"'


def missing_extra() -> Optional[str]:
    """Why the mcp-signer extra is not usable, or None when it is."""
    missing = []
    if importlib.util.find_spec("keyring") is None:
        missing.append("keyring (OS credential store)")
    if not _native.AVAILABLE:
        missing.append("ratify-protocol-native-v2 (v2 key generation and signing)")
    if not missing:
        return None
    return ("ratify-mcp-signer needs the mcp-signer extra; missing: " + ", ".join(missing)
            + f". Install it with: {INSTALL_HINT}")

_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")


def _init_key(directory: str, label: str, key_store: Optional[str], carry: Optional[dict] = None) -> int:
    directory = ensure_private_dir(directory)
    if not _NAME.fullmatch(label):
        raise ConfigError("--label may use letters, digits, '.', '_' and '-' (max 64)")
    config_path = os.path.join(directory, "config.json")
    if os.path.lexists(config_path):
        raise ConfigError(f"refusing to overwrite {config_path}: it already exists")
    if key_store is None:
        key_store = "keyring" if keys.keyring_usable() else "file"
    elif key_store == "keyring" and not keys.keyring_usable():
        raise ConfigError("no usable OS credential store; use --key-store file")
    pub, priv = keys.generate()
    key_id = keys.key_id(pub)
    name = f"{label}-{key_id[:16]}"
    ref = keys.store_key(pub, priv, kind=key_store, directory=directory, name=name)
    config = dict(carry or {})
    config["key"] = ref
    write_private_file(config_path, (json.dumps(config, indent=2) + "\n").encode(), exclusive=True)
    public = keys.public_key_json(pub)
    pub_path = os.path.join(directory, "agent-public.json")
    with open(pub_path, "xb") as f:
        f.write(public + b"\n")
    sys.stdout.write(public.decode() + "\n")
    sys.stdout.flush()
    store_desc = f"OS credential store item {ref['service']}/{ref['name']}" if ref["kind"] == "keyring" else ref["path"]
    sys.stderr.write(
        f"Key ID: {key_id}\n"
        f"Private key stored in {store_desc}.\n"
        f"Public key written to {pub_path} (use it with: ratify-keys delegate --subject {pub_path} ...).\n"
        f"Config skeleton written to {config_path}. After creating the connection in the console, run:\n"
        f"  ratify-mcp-signer configure --config {config_path} --from CONSOLE_CONFIG.json\n")
    return 0


def cmd_init(a: argparse.Namespace) -> int:
    return _init_key(a.dir, a.label, a.key_store)


def merge_console_config(config_path: str, console_json: bytes) -> dict:
    """Merge the console's client_config into the config file ``init`` wrote."""
    current = json.loads(read_private_file(config_path, "config file"))
    try:
        incoming = json.loads(console_json)
    except ValueError:
        raise ConfigError("console configuration is not valid JSON") from None
    if isinstance(incoming, dict) and isinstance(incoming.get("client_config"), dict):
        incoming = incoming["client_config"]
    if not isinstance(incoming, dict):
        raise ConfigError("console configuration must be a JSON object")
    if "key" in incoming:
        raise ConfigError("console configuration must not contain a key reference")
    missing = [k for k in CONSOLE_FIELDS if k not in incoming]
    if missing:
        raise ConfigError("console configuration is missing " + ", ".join(missing))
    merged = dict(current)
    for k in CONSOLE_FIELDS:
        merged[k] = incoming[k]
    from .signer import SignerConfig
    SignerConfig.from_dict(merged, config_path)
    write_private_file(config_path, (json.dumps(merged, indent=2) + "\n").encode(), exclusive=False)
    return merged


def cmd_configure(a: argparse.Namespace) -> int:
    with open(a.from_path, "rb") as f:
        data = f.read(1 << 20)
    merged = merge_console_config(a.config, data)
    # Confirm the connection was made for this key before reporting success.
    from .signer import Signer, SignerConfig
    cfg = SignerConfig.from_dict(merged, os.path.abspath(a.config))
    _, priv = keys.load_key(cfg.key)
    Signer(cfg.client, private_key=priv)
    sys.stderr.write(f"Configuration updated for connection {cfg.client.connection_id}.\n")
    return 0


def cmd_serve(a: argparse.Namespace) -> int:
    from .server import StdioServer
    from .signer import Signer
    signer = Signer.from_config(a.config)
    logging.getLogger("ratify_mcp_signer").info("serving connection %s as agent %s",
                                                  signer.config.connection_id, signer.agent_id)
    StdioServer(signer, sys.stdin.buffer, sys.stdout.buffer).serve()
    return 0


def cmd_test(a: argparse.Namespace) -> int:
    from .signer import Signer
    signer = Signer.from_config(a.config)
    try:
        result = signer.call_tool("get_metrics", {})
    except McpError as exc:
        sys.stdout.write(json.dumps({"outcome": "error", "error": exc.error}) + "\n")
        return 1
    outcome = "tool_error" if result.get("isError") else "allowed"
    sys.stdout.write(json.dumps({"outcome": outcome, "result": result}, ensure_ascii=False) + "\n")
    sys.stderr.write("Use \"Check test result\" in the console to open the decision for this call.\n")
    return 0 if outcome == "allowed" else 1


def cmd_prove_possession(a: argparse.Namespace) -> int:
    raw = json.loads(read_private_file(a.config, "config file"))
    if not isinstance(raw, dict) or not isinstance(raw.get("key"), dict):
        raise ConfigError("config file has no key reference (run ratify-mcp-signer init first)")
    token = parse_connect_token(a.challenge)
    # A config that is already pinned proves only for its own deployment.
    for field in ("workspace_id", "audience", "verifier_id"):
        if field in raw and raw[field] != getattr(token, field):
            raise ConfigError(f"the challenge's {field} does not match this configuration; refusing to sign")
    pub, priv = keys.load_key(raw["key"])
    out = prove_possession(a.challenge, priv)
    sys.stderr.write(f"Signed a connect proof for agent key {keys.key_id(pub)}\n"
                     f"  workspace {token.workspace_id}\n  endpoint  {token.audience}\n"
                     "Only continue if you are connecting this agent to that workspace.\n")
    sys.stdout.write(json.dumps(out.to_dict()) + "\n")
    return 0


def cmd_rotate(a: argparse.Namespace) -> int:
    raw = json.loads(read_private_file(a.config, "config file"))
    carry = {k: raw[k] for k in ("endpoint", "audience", "verifier_id", "workspace_id") if k in raw}
    label = a.label or f"rotated-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}"
    rc = _init_key(a.dir, label, a.key_store, carry)
    sys.stderr.write(
        "A new key needs a new connection. Next steps:\n"
        "  1. Sign a delegation for the new public key and create a new connection in the console.\n"
        f"  2. Run: ratify-mcp-signer configure --config {os.path.join(os.path.abspath(a.dir), 'config.json')} --from CONSOLE_CONFIG.json\n"
        "  3. Point your MCP client at the new config.\n"
        "  4. Revoke the old connection in the console and publish the status list it shows.\n"
        "Keys are per connection and per machine; do not copy a key file between machines.\n")
    return rc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ratify-mcp-signer",
                                description="Local signer for the Ratify Verify MCP server.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true", help="log each call (to stderr)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="generate the agent key and a config skeleton")
    s.add_argument("--dir", required=True)
    s.add_argument("--label", default="agent")
    s.add_argument("--key-store", choices=("keyring", "file"))
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("configure", help="merge the console's configuration")
    s.add_argument("--config", required=True)
    s.add_argument("--from", dest="from_path", required=True)
    s.set_defaults(func=cmd_configure)

    s = sub.add_parser("prove-possession", help="sign the console's connect challenge with the agent key")
    s.add_argument("--config", required=True)
    s.add_argument("--challenge", required=True, help="the ratify-mcp-connect-1 token the console shows")
    s.set_defaults(func=cmd_prove_possession)

    s = sub.add_parser("serve", help="run the stdio MCP server")
    s.add_argument("--config", required=True)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("test", help="make one get_metrics call")
    s.add_argument("--config", required=True)
    s.set_defaults(func=cmd_test)

    s = sub.add_parser("rotate", help="generate a new key for a new connection")
    s.add_argument("--config", required=True, help="the current config (endpoint pins are carried over)")
    s.add_argument("--dir", required=True, help="a new directory for the new key and config")
    s.add_argument("--label")
    s.add_argument("--key-store", choices=("keyring", "file"))
    s.set_defaults(func=cmd_rotate)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    reason = missing_extra()
    if reason is not None:
        sys.stderr.write(reason + "\n")
        return 2
    args = build_parser().parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.INFO if args.verbose else logging.WARNING,
                        format="ratify-mcp-signer: %(message)s")
    try:
        return args.func(args)
    except (ConfigError, McpError, McpSignerError, OSError) as exc:
        # Messages are written to carry no key material; no traceback.
        sys.stderr.write(f"ratify-mcp-signer: {exc}\n")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
