# Google ADK to Ratify Edge

> **Protocol v1 only.** This adapter speaks the Protocol v1 edge receiver's
> interface. The physical AI edge reference now runs a Protocol v2 receiver,
> and this adapter has not been ported to it: it does not work with the
> current receiver. It is kept as v1 history alongside the Protocol v1 Google
> ADK reference in `references/google-adk/v1/`.

This is the real Google ADK adapter for the physical-AI reference. ADK selects
an ordinary tool call. The adapter obtains a receiver-issued challenge, signs a
Ratify proof with the delegated agent key, and sends the proof to the Linux
edge receiver. The receiver remains the enforcement boundary and decides
whether the Arduino actuator can run.

The adapter uses the Protocol v1 Google ADK reference's `AuthorityFixture` and
`issue_authority` implementation (`references/google-adk/v1/`). It does not create a second protocol or
trust model.

## Run

Prerequisites: Python 3.11, the pinned dependencies in
`references/google-adk/v1/requirements.txt`, a running Protocol v1 edge
receiver (the one `references/physical-ai-edge-sentinel` shipped before its v2
port, available from git history), and
the v1 Google ADK reference on the same checkout.

From the protocol repository root:

```sh
python -m venv /tmp/ratify-adk-edge
. /tmp/ratify-adk-edge/bin/activate
pip install -r references/google-adk/v1/requirements.txt
PYTHONPATH=references/google-adk/v1:. \
  python -c 'from adk.edge_agent import build_edge_agent; print(build_edge_agent)' \
  
```

The import check above verifies the real ADK tool construction. To run an
agent against an edge receiver, use `build_edge_agent` from `adk/edge_agent.py`
with `edge_url` set to the receiver's URL. The agent receives only `zone` and
`duration_ms`; challenge and proof fields never enter model context.

The live Gemini model is not required to inspect or test the adapter. Use the
existing scripted-model harness in `references/google-adk/v1/tests` for
deterministic agent execution, and connect its tool to a running edge receiver
for hardware integration.
