# A2A reference evidence

Records are dated and kept. A later record does not rewrite an earlier one.

## 2026-10-29: Protocol v2, one-directional, in-tree `2.0.0b1`

| Item | Value |
| --- | --- |
| Gate | `./scripts/a2a-reference-check.sh` (runs `./references/a2a/run-reference-check.sh`) at commit `5ad1bfc1529914fe06de9eed9693ebe0da7345bd` |
| Result | 8 passed, 0 failed, 0 skipped; zero xfailed or errored |
| Ratify | `ratify-protocol==2.0.0b1` with the `protocol-v2` extra (`ratify_protocol.v2`) and `ratify-protocol-native-v2==2.0.0b1`, both built from this repository by the gate (not published) |
| Platform | `a2a-sdk[http-server]==1.2.2`, `httpx==0.28.1`, `uvicorn==0.54.0`, `pytest==9.0.3`, Python 3.12.10, Node.js 26.10.0, OpenSSL 3.6.4, macOS arm64 |
| Stores | SDK in-memory reference stores (test-only): claim store, receipt log and checkpoint, security journal, challenge issuance store |

Command, from a clean checkout, in a fresh virtual environment:

```bash
RATIFY_REFERENCE_VENV="$TMPDIR/a2a-v2-gate-venv" PYTHON=python3.12 \
  ./scripts/a2a-reference-check.sh
```

Output (after the native wheel build):

```text
installed Ratify v2 SDK: .../a2a-v2-gate-venv/lib/python3.12/site-packages/ratify_protocol/v2/__init__.py
a2a-sdk==1.2.2 httpx==0.28.1 uvicorn==0.54.0 pytest==9.0.3 ratify-protocol==2.0.0b1 ratify-protocol-native-v2==2.0.0b1
........                                                                 [100%]
8 passed in 4.55s
gate: 8/8 passed; zero skipped, xfailed, failed, or errored
```

Changes from the 2026-10-22 record: the SDK is the unified `ratify-protocol`
distribution instead of the separate prerelease package; the receiver passes
its verifier key ID to verification, which the SDK now requires; and the
fixture publishes a revocation strictly after the issuer's previous status
list, which the status publisher now enforces. The tests are unchanged and
every deny case denies with the same status as before.

v2 features exercised and not covered: as in the 2026-10-22 record below.
This run used no published v2 package and must be repeated against the
published `2.0.0-beta.1` packages before a release claim.

## 2026-10-22: Protocol v2, one-directional (history)

| Item | Value |
| --- | --- |
| Gate | `./scripts/a2a-reference-check.sh` |
| Result | 8 passed; zero skipped, xfailed, failed, or errored |
| Ratify | `ratify-protocol-v2==2.0.0a1` and `ratify-protocol-native-v2==2.0.0a1`, local builds from the v2 source at commit `5f1093e07eaf280dfe6499a05036515b0aeaa98c` (not published) |
| Platform | `a2a-sdk[http-server]==1.2.2`, `httpx==0.28.1`, `uvicorn==0.54.0`, `pytest==9.0.3`, Python 3.12.10, Node.js 26.10.0, OpenSSL 3.6.4, macOS arm64 |
| Stores | SDK in-memory reference stores (test-only): claim store, receipt log and checkpoint, security journal, challenge issuance store |

Commands, run from the v2 source checkout and then from this checkout:

```bash
pip install 'maturin>=1.7,<2'
(cd sdks/python-native-v2 && maturin build --release --out "$DIST")

RATIFY_V2_NATIVE_WHEEL="$DIST/ratify_protocol_native_v2-2.0.0a1-cp310-abi3-macosx_11_0_arm64.whl" \
RATIFY_V2_PYTHON_SDK="$V2_SOURCE/sdks/python-v2" \
  ./scripts/a2a-reference-check.sh
```

Output (last lines):

```text
........                                                                 [100%]
8 passed
gate: 8/8 passed; zero skipped, xfailed, failed, or errored
```

v2 features exercised: exact custom scope `custom:infra:provision`; `resource_path`; the standard `com.ratifyprotocol.max_count/v1` profile with `extension_counts`; `ratify.receiver_audience` with `expected_receiver_id`; a bound session context; the challenge issuance helper; signed status from each issuer's status publisher under a separate status key, including a revocation; receipt publication, checkpoint acknowledgement, and release; 64-hex key IDs with complete-key root pinning.

Not covered: mutual presentation, the receiver-to-caller proof, the A2A mutual-presentation carrier, and `verification_result` (v1-only until Protocol 2.1); durable Part B stores; an independent checkpoint; a status distribution service; revocation in the separate-process network test.

## 2026-10-19: Protocol v1 (history)

| Item | Value |
| --- | --- |
| Gate | `./scripts/a2a-reference-check.sh` at commit `a01ff1b` |
| Result | 6 passed; zero skipped |
| Ratify | published `ratify-protocol==1.0.0a20` |
| Platform | `a2a-sdk[http-server]==1.2.2`, `google-adk==2.6.3`, `mcp==1.29.0`, `pytest==9.0.3`, Python 3.11, Node.js 22, OpenSSL |

The v1 carrier reused the Google ADK reference's receiver package. It used the scope `custom:infra:provision`, the extension constraint `com.ratifyprotocol.adk.max_nodes`, an in-process static revocation provider, and the provisional URI `https://ratifyprotocol.com/extensions/a2a-authority/poc-v0`.
