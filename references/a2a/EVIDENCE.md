# A2A reference evidence

Records are dated and kept. A later record does not rewrite an earlier one.

## 2026-10-22: Protocol v2, one-directional

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
