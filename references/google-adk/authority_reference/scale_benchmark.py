"""Exact-call benchmark for the cross-domain dual-root authority path.

Each measured call opens one approval set, issues two challenges through the
SDK issuance helper, signs both presentations with the worker key, runs two
full v2 verifications (hybrid chain signatures, trust pinning, signed status
from the journal, constraint evaluation including the max_count profile),
publishes two signed receipts, waits for two checkpoint acknowledgements,
releases both decisions, records them in the approval ledger, executes the
set once, and increments the protected action counter. Ten percent of calls
intentionally exceed the node constraint.

DEVELOPMENT ONLY: the claim store, receipt log, checkpoint, issuance store,
journal and ledger are the SDK's in-memory reference stores. They retain
every claim and receipt, so memory grows with the call count.
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

from .authority import issue_dual_root_federated_authority
from .receiver import (
    DualPresentation,
    FederationPolicy,
    FederationRoute,
    InfrastructureReceiver,
    OperationRequest,
    encode_presentation,
)


class _CountingProvisioner:
    """Constant-memory protected action for an endurance measurement."""

    def __init__(self) -> None:
        self.invocations = 0
        self._lock = threading.Lock()

    def provision(self, request: OperationRequest) -> None:
        with self._lock:
            self.invocations += 1


def _receiver(authority, provisioner) -> InfrastructureReceiver:
    return InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
        status_keys=authority.status.status_keys(),
        status_source=authority.status.evidence,
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
        pending_capacity=1024,
    )


def run_scale_benchmark(calls: int, *, workers: int, mixed: bool = True) -> dict[str, Any]:
    """Run exact dual-root decisions with a deterministic deny mix."""
    if calls < 1:
        raise ValueError("calls must be positive")
    if workers < 1:
        raise ValueError("workers must be positive")
    now = int(time.time())
    authority = issue_dual_root_federated_authority(now=now - 1, expires_at=now + 86_400)
    provisioner = _CountingProvisioner()
    receiver = _receiver(authority, provisioner)

    sample = OperationRequest("proof-size-sample", "us-central1", "n2-standard-4", 1)
    grant = receiver.issue_challenge(sample, agent_public_key=authority.specialist_public_key)
    presented = DualPresentation(
        encode_presentation(authority.present(grant.authority)),
        encode_presentation(authority.present_admission(grant.admission)),
    )
    proof_bytes = len(presented.authority) + len(presented.admission)
    warmup = receiver.execute(sample, presented)
    if warmup["decision"] != "allow":
        raise RuntimeError(f"warm-up call was not allowed: {warmup}")
    receiver.tool_invocations = 0
    provisioner.invocations = 0

    effective_workers = min(workers, calls)
    batch_size = math.ceil(calls / effective_workers)

    def run_batch(worker_index: int, start: int, count: int):
        latencies = array("d")
        allowed = 0
        receipts = 0
        denied_by_reason: dict[str, int] = {}
        for offset in range(count):
            sequence = start + offset
            request = OperationRequest(
                f"scale-{worker_index}-{sequence}",
                "us-central1",
                "n2-standard-4",
                2 if mixed and sequence % 10 == 9 else 1,
            )
            began = time.perf_counter_ns()
            grant = receiver.issue_challenge(request, agent_public_key=authority.specialist_public_key)
            result = receiver.execute(request, DualPresentation(
                authority.present(grant.authority), authority.present_admission(grant.admission),
            ))
            latencies.append((time.perf_counter_ns() - began) / 1_000_000)
            if result["decision"] == "allow":
                allowed += 1
                receipts += len(result["receipt_sequences"])
            else:
                reason = result.get("protocol_reason", result.get("status", "deny"))
                denied_by_reason[reason] = denied_by_reason.get(reason, 0) + 1
                receipts += 1 if "receipt_sequence" in result else 0
        return latencies, allowed, receipts, denied_by_reason

    started = time.perf_counter()
    futures = []
    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        remaining = calls
        start = 0
        worker_index = 0
        while remaining:
            count = min(batch_size, remaining)
            futures.append(executor.submit(run_batch, worker_index, start, count))
            start += count
            remaining -= count
            worker_index += 1
    wall_seconds = time.perf_counter() - started

    latencies = array("d")
    allowed = 0
    receipts = 0
    denied_by_reason: dict[str, int] = {}
    for future in futures:
        batch_latencies, batch_allowed, batch_receipts, batch_denied = future.result()
        latencies.extend(batch_latencies)
        allowed += batch_allowed
        receipts += batch_receipts
        for reason, count in batch_denied.items():
            denied_by_reason[reason] = denied_by_reason.get(reason, 0) + count
    ordered = sorted(latencies)
    return {
        "mode": "local_dual_root_composition_profile",
        "calls_requested": calls,
        "calls_completed": len(ordered),
        "allowed": allowed,
        "denied": len(ordered) - allowed,
        "denied_by_reason": denied_by_reason,
        "released_receipts": receipts,
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
        "schema": "ratify.google-adk.federation-scale.v2",
        "measured_at": int(time.time()),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "logical_cpus": os.cpu_count(),
            "google_adk": importlib.metadata.version("google-adk"),
            "mcp": importlib.metadata.version("mcp"),
            "ratify_protocol_v2": importlib.metadata.version("ratify-protocol-v2"),
            "ratify_protocol_native_v2": importlib.metadata.version("ratify-protocol-native-v2"),
        },
        "methodology": {
            "measured": (
                "approval set, two issued challenges, two worker signatures, two full v2 "
                "verifications with signed status and the max_count profile, two signed "
                "receipts with checkpoint acknowledgement, two releases, the approval "
                "ledger, and the protected counter increment"
            ),
            "excluded": (
                "ADK model latency, MCP HTTP transport, status feed distribution, durable "
                "Part B stores, and multi-host orchestration"
            ),
            "claim_boundary": (
                "single-host measurements with in-memory reference stores, not Google "
                "production capacity"
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
        default="10,100",
        help="comma-separated exact call counts, for example 10,100,1000",
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
