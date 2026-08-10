# SPDX-License-Identifier: Apache-2.0
"""The unified path, from inside an OpenShell sandbox.

    python3 nooa_openshell_client.py keygen <state-dir> <out.json>
    python3 nooa_openshell_client.py suite  <state-dir> <job.json> <out.json>
    python3 nooa_openshell_client.py run    <state-dir> <out.json> <job.json>

``suite`` is the mode the profile uses: it imports NOOA once and runs every
unified subcase in that single process. ``run`` executes one subcase per
process and is kept for isolated debugging; four consecutive ``run`` invocations
is precisely what destabilized the sandbox.

This is the only file where NOOA, MCP, OpenShell, the receiver, and Ratify are
all present in **one** execution. Running NOOA in one test and MCP through
OpenShell in another proves two seams; it does not prove the composition, so
this exists to make the composed claim a thing that executes.

Two invocations, for one reason. In ``keygen`` the agent generates its own
keypair *here*, inside its own process, and emits only public material. The
host principal then issues a delegation to that public key and uploads the
signed certificate. No private key is ever carried into the sandbox from
outside, which is both the protocol's intent (an agent's private half never
leaves the agent) and the harness's rule. The agent's own secret is written to
the sandbox's own directory at 0600 and deleted with the group.

Layers, and who decides what:

    NOOA          dispatches the capability and runs the presentation adapter
    the adapter   presents and reports. It never evaluates a delegation
    MCP           carries the request; the proof rides in ``_meta``
    OpenShell     admits or refuses the destination, method, and tool
    RefundService the sole authorization decision point
    Ratify        principal, resource, amount, expiry, revocation, chain

No LLM is reachable. ``FakeLLMClient`` is NOOA's public double, and the
subclass below raises if anything ever tries to generate, which turns "no LLM"
into a tested property rather than a claim.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import pathlib
import sys

# Bootstrapped from this file's own location rather than from the environment.
# `sandbox exec --env` did not reliably propagate PYTHONPATH, and a client that
# only imports when its caller remembered to set a variable is a client that
# fails for a reason unrelated to anything under test.
# /opt/ratify-nooa/site is where the sandbox image carries the dependency tree.
# The sibling ./site is the fallback for a run that delivered them by upload
# instead, so this file works under either arrangement.
_HERE = pathlib.Path(__file__).resolve().parent
for _path in ("/opt/ratify-nooa/site", str(_HERE / "site"), str(_HERE)):
    if _path not in sys.path and pathlib.Path(_path).is_dir():
        sys.path.insert(0, _path)

# litellm, imported transitively by nooa, fetches a model-cost map from
# raw.githubusercontent at import time. This policy refuses that request, and
# the refusal was observed to close the v0.0.102 exec relay, after which the
# sandbox fell back to Provisioning and every later case produced no result.
# Set before nooa is imported anywhere, because it is read at import time.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

#: Load attempts for the top-level module ``nooa`` **in this process**, measured
#: rather than declared. Installed before any other import in this file so nothing
#: can be loaded behind it.
#:
#: What it counts, exactly. CPython raises the ``import`` audit event from
#: ``importlib._bootstrap._find_and_load``, which the import system reaches only
#: on a ``sys.modules`` miss. So this counts *real load attempts for the name
#: ``nooa``*: the first ``import nooa`` increments it, every later ``import nooa``
#: or ``from nooa.x import y`` against the cached module does not, and a reload
#: after the entry is evicted from ``sys.modules`` does. It counts the name
#: ``nooa`` only, not its submodules.
#:
#: What it does not establish. It is scoped to one process and says nothing about
#: any other, which is why the runner counts nooa-importing processes separately.
#: "NOOA was imported once" is only true of the whole profile because those two
#: independent measurements are both 1; neither claim stands alone.
#:
#: It is measured because the earlier version reported ``"nooa_imports": 1`` as a
#: literal and the profile gated on that literal: a gate that reads back a
#: constant cannot fail, which is the same defect this suite's adjudicator exists
#: to prevent.
_NOOA_LOADS: list[str] = []


def _count_nooa_loads(event: str, args) -> None:
    if event == "import" and args and args[0] == "nooa":
        _NOOA_LOADS.append(args[0])


sys.addaudithook(_count_nooa_loads)

from ratify_protocol import (
    HybridPrivateKey,
    HybridPublicKey,
    derive_id,
    generate_agent,
)
from ratify_protocol.wire import decode_delegation_cert

from mcp_refund_client import MCPRefundClient, MCPTransportError


class RefusingLLM:
    """Wraps NOOA's public double so any generation attempt is a hard failure.

    Installed instead of a bare ``FakeLLMClient`` because a double that quietly
    answers would let an accidental LLM round-trip pass unnoticed, and "this
    path needs no model" is one of the claims under test.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.calls = 0

    def __getattr__(self, name):
        inner_attr = getattr(self._inner, name)
        if not callable(inner_attr):
            return inner_attr

        def guard(*args, **kwargs):
            self.calls += 1
            raise AssertionError(
                f"the unified path attempted an LLM call ({name}); this "
                "capability is an ordinary async method and must never generate"
            )

        return guard


def _pub_to_json(key: HybridPublicKey) -> dict:
    return {
        "ed25519": base64.b64encode(key.ed25519).decode(),
        "ml_dsa_65": base64.b64encode(key.ml_dsa_65).decode(),
    }


def _pub_from_json(obj: dict) -> HybridPublicKey:
    return HybridPublicKey(
        ed25519=base64.b64decode(obj["ed25519"]),
        ml_dsa_65=base64.b64decode(obj["ml_dsa_65"]),
    )


def _write(path: str, payload: dict) -> None:
    pathlib.Path(path).write_text(json.dumps(payload))
    print(json.dumps(payload))


def keygen(state_dir: str, out_path: str) -> None:
    """Generate the agent's own keypair. Emit public material only."""
    state = pathlib.Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    agent, private = generate_agent("nooa-openshell-agent", "assistant")

    secret = state / "agent-key.json"
    secret.write_text(
        json.dumps(
            {
                "ed25519": base64.b64encode(private.ed25519).decode(),
                "ml_dsa_65": base64.b64encode(private.ml_dsa_65).decode(),
            }
        )
    )
    secret.chmod(0o600)
    (state / "agent-pub.json").write_text(json.dumps(_pub_to_json(agent.public_key)))

    _write(
        out_path,
        {
            "step": "keygen",
            "agent_id": agent.id,
            "agent_pub": _pub_to_json(agent.public_key),
            # Stated so the host can confirm the identifier is derived from the
            # key rather than trusted from this side of the boundary.
            "derived_id_matches": derive_id(agent.public_key) == agent.id,
        },
    )


def _load_agent(state_dir: str):
    state = pathlib.Path(state_dir)
    secret = json.loads((state / "agent-key.json").read_text())
    public = json.loads((state / "agent-pub.json").read_text())
    private = HybridPrivateKey(
        ed25519=base64.b64decode(secret["ed25519"]),
        ml_dsa_65=base64.b64decode(secret["ml_dsa_65"]),
    )
    pub = _pub_from_json(public)
    return derive_id(pub), pub, private


def run(state_dir: str, out_path: str, job_path: str) -> None:
    job = json.loads(pathlib.Path(job_path).read_text())
    agent_id, agent_pub, agent_priv = _load_agent(state_dir)

    certs = [decode_delegation_cert(c) for c in job.get("delegations", [])]

    # Imported here rather than at module scope so `keygen` does not need NOOA
    # installed, which keeps the failure modes of the two steps separate.
    from nooa.unifiedllm import FakeLLMClient

    from nooa_adapter import CAPABILITY, RefundAgent, install_presentation_adapter

    llm = RefusingLLM(FakeLLMClient())
    agent = RefundAgent(llm=llm)

    client = MCPRefundClient(
        job["url"],
        agent_id,
        agent_pub,
        agent_priv,
        certs,
        job["tenant"],
        prepare_tool=job.get("prepare_tool", "refund.prepare"),
        execute_tool=job.get("execute_tool", "refund.execute"),
        trace_context=job.get("trace_context") or {},
    )

    unsubscribe = None
    if job.get("install_adapter", True):
        unsubscribe = install_presentation_adapter(agent, client)

    result: dict = {
        "step": "run",
        "case": job.get("case"),
        "agent_id": agent_id,
        "adapter_installed": unsubscribe is not None,
        "capability": CAPABILITY,
    }

    async def invoke():
        # The ordinary public NOOA call. Dispatch goes through the event
        # manager, so agent_call middleware runs; nothing here reaches past
        # NOOA's public surface.
        return await agent.issue_refund(job["order_id"], job["amount"])

    try:
        decision = asyncio.run(invoke())
        result["decision"] = decision
        result["outcome"] = "returned"
    except MCPTransportError as exc:
        # The MCP layer never produced a decision. Reported as its own outcome
        # so it can never be mistaken for a denial.
        result["outcome"] = "mcp_transport_error"
        result["error"] = str(exc)[:300]
    except RuntimeError as exc:
        # RefundAgent.issue_refund raises when no adapter is installed. That is
        # the inert-capability case, and it is an expected outcome.
        result["outcome"] = "capability_inert"
        result["error"] = str(exc)[:300]
    except Exception as exc:  # noqa: BLE001 - any failure is evidence
        result["outcome"] = f"error:{type(exc).__name__}"
        result["error"] = str(exc)[:300]
    finally:
        if unsubscribe is not None:
            unsubscribe()

    result["llm_calls"] = llm.calls
    # What the adapter observed, and what actually crossed MCP. The trace holds
    # no proof material, only tool names, statuses, and the proof's length.
    result["presented"] = [list(p) for p in agent.presented]
    result["mcp_trace"] = client.trace
    result["session_established"] = client.session is not None
    _write(out_path, result)




def suite(state_dir: str, job_path: str, out_path: str) -> None:
    """Every unified-path subcase, in one process, importing NOOA exactly once.

    This shape is a finding, not a preference. Running the subcases as four
    separate execs imported nooa (and litellm, openai, tokenizers, tiktoken)
    four times in one sandbox, and the sandbox did not survive it: the exec
    relay closed with a broken pipe and the sandbox fell back to Provisioning,
    so whichever subcases ran later produced no result at all. The defect was
    cumulative imports, so the fix is to import once.

    Isolation is per subcase, and deliberate:

    * a fresh ``RefundAgent`` and a fresh ``MCPRefundClient``, so no adapter
      registration or MCP session is shared
    * its own order id, so the receiver derives a distinct canonical resource
      and the runner can attribute server-side events without trusting this
      report
    * its own host-issued delegation bound to that resource
    * its own challenge, obtained by its own ``refund.prepare``

    A subcase that raises is recorded as a failed subcase and the suite
    continues, so one failure cannot erase the others. The process exits
    non-zero if it cannot emit a complete result for every subcase it was asked
    to run.
    """
    job = json.loads(pathlib.Path(job_path).read_text())
    agent_id, agent_pub, agent_priv = _load_agent(state_dir)

    from nooa.unifiedllm import FakeLLMClient

    from nooa_adapter import CAPABILITY, RefundAgent, install_presentation_adapter

    records = []
    for spec in job["subcases"]:
        # A new agent per subcase. Removing an adapter from a shared agent
        # would leave every later subcase inert for the wrong reason, and a
        # shared event manager is exactly the cross-case coupling this suite
        # has to avoid.
        llm = RefusingLLM(FakeLLMClient())
        agent = RefundAgent(llm=llm)
        client = MCPRefundClient(
            spec.get("url", job["url"]),
            agent_id,
            agent_pub,
            agent_priv,
            [decode_delegation_cert(c) for c in spec["delegations"]],
            spec["tenant"],
            prepare_tool=spec.get("prepare_tool", "refund.prepare"),
            execute_tool=spec.get("execute_tool", "refund.execute"),
            trace_context=spec.get("trace_context") or {},
        )

        unsubscribe = None
        if spec.get("install_adapter", True):
            unsubscribe = install_presentation_adapter(agent, client)

        record = {
            "subcase": spec["name"],
            "order_id": spec["order_id"],
            "amount": spec["amount"],
            "adapter_installed": unsubscribe is not None,
            "capability": CAPABILITY,
        }
        try:
            decision = asyncio.run(agent.issue_refund(spec["order_id"], spec["amount"]))
            record["outcome"] = "returned"
            record["decision"] = decision
        except MCPTransportError as exc:
            record["outcome"] = "mcp_transport_error"
            record["error"] = str(exc)[:300]
        except RuntimeError as exc:
            # RefundAgent.issue_refund raises when no adapter is installed:
            # the capability cannot be exercised without presenting authority.
            record["outcome"] = "capability_inert"
            record["error"] = str(exc)[:300]
        except Exception as exc:  # noqa: BLE001 - any failure is evidence
            record["outcome"] = f"error:{type(exc).__name__}"
            record["error"] = str(exc)[:300]
        finally:
            if unsubscribe is not None:
                unsubscribe()

        record["llm_calls"] = llm.calls
        record["presented"] = [list(p) for p in agent.presented]
        record["mcp_trace"] = client.trace
        record["session_established"] = client.session is not None
        records.append(record)

    payload = {
        "step": "suite",
        "agent_id": agent_id,
        # Counted by the audit hook above, not declared. The flag is what lets
        # the profile tell a measurement from an older client's constant.
        "nooa_imports": len(_NOOA_LOADS),
        "nooa_imports_measured": True,
        "subcases": records,
    }
    pathlib.Path(out_path).write_text(json.dumps(payload))
    print(json.dumps(payload))

    if len(records) != len(job["subcases"]):
        sys.exit("suite did not produce a record for every subcase")


def main() -> None:
    mode = sys.argv[1]
    if mode == "keygen":
        keygen(sys.argv[2], sys.argv[3])
    elif mode == "run":
        run(sys.argv[2], sys.argv[3], sys.argv[4])
    elif mode == "suite":
        suite(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit(f"unknown mode {mode!r}")


if __name__ == "__main__":
    main()
