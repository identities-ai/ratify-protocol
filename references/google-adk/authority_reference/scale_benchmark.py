"""Exact-call benchmark for the cross-domain authority path.

Each measured call issues a unique challenge, signs authority and admission
proofs with the leaf agent, verifies both hybrid chains, evaluates constraints
and revocation, atomically consumes the challenge, and increments the protected
action counter. Ten percent of calls intentionally exceed the node constraint.
"""

from __future__ import annotations

import argparse
from array import array
from concurrent.futures import ThreadPoolExecutor
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import threading
import time
from typing import Any

from ratify_protocol import encode_proof_bundle

from .authority import issue_dual_root_federated_authority
from .receiver import (
    DualPresentation,
    FederationPolicy,
    FederationRoute,
    InfrastructureReceiver,
    OperationRequest,
)


class _CountingProvisioner:
    """Constant-memory protected action for an endurance measurement."""

    def __init__(self) -> None:
        self.invocations = 0
        self._lock = threading.Lock()

    def provision(self, request: OperationRequest) -> None:
        with self._lock:
            self.invocations += 1


def run_scale_benchmark(calls: int, *, workers: int, mixed: bool = True) -> dict[str, Any]:
    """Run exact dual-root decisions with a deterministic deny mix."""
    if calls < 1:
        raise ValueError("calls must be positive")
    if workers < 1:
        raise ValueError("workers must be positive")
    now = int(time.time())
    authority = issue_dual_root_federated_authority(
        now=now - 1,
        expires_at=now + 86_400,
    )
    provisioner = _CountingProvisioner()
    receiver = InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
        federation_policy=FederationPolicy(
            roots={authority.root_id: authority.root_public_key},
            routes=[FederationRoute(
                agent_id=authority.specialist_id,
                root_id=authority.root_id,
                subjects_leaf_to_root=authority.agent_path,
            )],
        ),
        admission_policy=FederationPolicy(
            roots={authority.admission_root_id: authority.admission_root_public_key},
            routes=[FederationRoute(
                agent_id=authority.specialist_id,
                root_id=authority.admission_root_id,
                subjects_leaf_to_root=(authority.specialist_id,),
            )],
        ),
        provisioner=provisioner,
    )

    sample_request = OperationRequest(
        "proof-size-sample", "us-central1", "n2-standard-4", 1
    )
    sample_grant = receiver.issue_challenge(
        sample_request, expected_agent_id=authority.specialist_id
    )
    sample_bundle = DualPresentation(
        authority.present(challenge=sample_grant.challenge, session_context=sample_grant.session_context),
        authority.present_admission(challenge=sample_grant.challenge, session_context=sample_grant.session_context),
    )
    proof_bytes = sum(len(encode_proof_bundle(bundle).encode("ascii")) for bundle in (sample_bundle.authority, sample_bundle.admission))
    receiver.execute(sample_request, sample_bundle)
    receiver.tool_invocations = 0
    provisioner.invocations = 0

    effective_workers = min(workers, calls)
    batch_size = math.ceil(calls / effective_workers)

    def run_batch(worker_index: int, start: int, count: int):
        latencies = array("d")
        allowed = 0
        denied_by_reason: dict[str, int] = {}
        for offset in range(count):
            sequence = start + offset
            request = OperationRequest(
                f"scale-{worker_index}-{start + offset}",
                "us-central1",
                "n2-standard-4",
                2 if mixed and sequence % 10 == 9 else 1,
            )
            began = time.perf_counter_ns()
            grant = receiver.issue_challenge(
                request, expected_agent_id=authority.specialist_id
            )
            bundle = DualPresentation(
                authority.present(challenge=grant.challenge, session_context=grant.session_context),
                authority.present_admission(challenge=grant.challenge, session_context=grant.session_context),
            )
            result = receiver.execute(request, bundle)
            latencies.append((time.perf_counter_ns() - began) / 1_000_000)
            allowed += result["decision"] == "allow"
            if result["decision"] != "allow":
                reason = result.get("verification_code", result.get("status", "deny"))
                denied_by_reason[reason] = denied_by_reason.get(reason, 0) + 1
        return latencies, allowed, denied_by_reason

    started = time.perf_counter()
    futures = []
    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        remaining = calls
        start = 0
        worker_index = 0
        while remaining:
            count = min(batch_size, remaining)
            futures.append(executor.submit(
                run_batch, worker_index, start, count
            ))
            start += count
            remaining -= count
            worker_index += 1
    wall_seconds = time.perf_counter() - started

    latencies = array("d")
    allowed = 0
    denied_by_reason: dict[str, int] = {}
    for future in futures:
        batch_latencies, batch_allowed, batch_denied = future.result()
        latencies.extend(batch_latencies)
        allowed += batch_allowed
        for reason, count in batch_denied.items():
            denied_by_reason[reason] = denied_by_reason.get(reason, 0) + count
    ordered = sorted(latencies)
    return {
        "mode": "local_dual_root_authority_and_admission_path",
        "calls_requested": calls,
        "calls_completed": len(ordered),
        "allowed": allowed,
        "denied": len(ordered) - allowed,
        "denied_by_reason": denied_by_reason,
        "protected_action_invocations": provisioner.invocations,
        "workers": len(futures),
        "wall_seconds": round(wall_seconds, 6),
        "throughput_calls_per_second": round(calls / wall_seconds, 3),
        "latency_ms": {
            "p50": round(_percentile(ordered, 0.50), 3),
            "p95": round(_percentile(ordered, 0.95), 3),
            "p99": round(_percentile(ordered, 0.99), 3),
            "max": round(ordered[-1], 3),
        },
        "encoded_proof_bytes": proof_bytes,
    }


def benchmark_report(call_counts: list[int], *, workers: int) -> dict[str, Any]:
    return {
        "schema": "ratify.google-adk.federation-scale.v1",
        "measured_at": int(time.time()),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "logical_cpus": os.cpu_count(),
            "google_adk": importlib.metadata.version("google-adk"),
            "mcp": importlib.metadata.version("mcp"),
            "ratify_protocol": importlib.metadata.version("ratify-protocol"),
        },
        "methodology": {
            "measured": (
                "unique challenge, authority and admission leaf signatures, full "
                "dual-root hybrid verification, constraint and revocation evaluation, atomic challenge "
                "consumption, and protected counter increment"
            ),
            "excluded": (
                "ADK model latency, MCP HTTP transport, external revocation distribution, "
                "and multi-host orchestration"
            ),
            "claim_boundary": (
                "results are single-host measurements, not Google production capacity"
            ),
        },
        "results": [
            run_scale_benchmark(calls, workers=workers, mixed=True)
            for calls in call_counts
        ],
    }


def _percentile(ordered: list[float], percentile: float) -> float:
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--calls",
        default="10,100,1000",
        help="comma-separated exact call counts, for example 10,100,1000,1000000",
    )
    parser.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    call_counts = [int(value) for value in args.calls.split(",")]
    report = benchmark_report(call_counts, workers=args.workers)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
