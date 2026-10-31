"""Recompute the external-mu bytes in the shared delegation fixture."""

import base64
import hashlib
import json
from pathlib import Path


fixture = json.loads(Path(__file__).with_name("delegation-signature.json").read_text())
decode = lambda name: base64.b64decode(fixture[name], validate=True)
pk = base64.b64decode(fixture["issuer_public_key"]["ml_dsa_65"], validate=True)
context = decode("mldsa_context")
message = decode("message")
if (len(pk), len(context), len(message)) != (1952, 22, 77):
    raise ValueError("invalid external-mu fixture input lengths")
tr = hashlib.shake_256(pk).digest(64)
mu = hashlib.shake_256(tr + b"\x00" + bytes([len(context)]) + context + message).digest(64)
for name, value in (("mldsa_tr", tr), ("mldsa_mu", mu)):
    encoded = base64.b64encode(value).decode("ascii")
    if fixture[name] != encoded:
        raise ValueError(f"{name} differs from the checked-in fixture: {encoded}")
    print(f"{name}: {encoded}")
