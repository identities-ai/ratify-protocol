# Google ADK to Ratify Edge

This is the real Google ADK adapter for the physical-AI reference. ADK selects
an ordinary tool call. The adapter obtains a receiver-issued challenge, signs a
Ratify proof with the delegated agent key, and sends the proof to the Linux
edge receiver. The receiver remains the enforcement boundary and decides
whether the Arduino actuator can run.

The adapter uses the existing Google ADK reference's `AuthorityFixture` and
`issue_authority` implementation. It does not create a second protocol or
trust model.

## Run

Prerequisites: Python 3.11, the pinned dependencies in
`references/google-adk/requirements.txt`, a running edge receiver, and the
Google ADK reference on the same checkout.

From the protocol repository root:

```sh
python -m venv /tmp/ratify-adk-edge
. /tmp/ratify-adk-edge/bin/activate
pip install -r references/google-adk/requirements.txt
PYTHONPATH=references/google-adk:references/physical-ai-edge-sentinel \
  python -c 'from adk.edge_agent import build_edge_agent; print(build_edge_agent)' \
  
```

The import check above verifies the real ADK tool construction. To run an
agent against an edge receiver, use `build_edge_agent` from `adk/edge_agent.py`
with `edge_url` set to the receiver's URL. The agent receives only `zone` and
`duration_ms`; challenge and proof fields never enter model context.

The live Gemini model is not required to inspect or test the adapter. Use the
existing scripted-model harness in `references/google-adk/tests` for
deterministic agent execution, and connect its tool to a running edge receiver
for hardware integration.
