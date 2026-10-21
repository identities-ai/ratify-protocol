# ratify-protocol-native-v2

Optional native extra for [`ratify-protocol-v2`](https://pypi.org/project/ratify-protocol-v2/).
Install it through the SDK:

```bash
pip install 'ratify-protocol-v2[native]==2.0.0a1'
```

It provides native deterministic key generation (`hybrid_keypair_from_seeds_py`)
from the Ratify Rust core. It is not a wire verifier: all v2 signature and
object verification stays in `ratify-protocol-v2`.

It is versioned in lockstep with `ratify-protocol-v2`. Importing
`ratify_protocol_v2` fails if this extension's `version()` does not match.

It is a separate distribution and module from the v1 extension
(`ratify-protocol-native` / `ratify_protocol_native`), so both can be installed
in one environment.
