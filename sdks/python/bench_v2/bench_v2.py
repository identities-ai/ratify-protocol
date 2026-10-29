"""Reproducible Python v2 benchmarks.

Four measurements, all on the in-memory reference stores (development only):

* ``hybrid_verify``: one strict hybrid verification of a delegation
  certificate signature (``verify_v2_statement``).
* ``cert_signature_verify``: ``verify_delegation_cert_v2_signature``, the
  certificate's structure and key-ID checks plus one hybrid verification. The
  Go and Rust counterparts in ``bench_v2/go`` and ``bench_v2/rust`` measure this same
  call (Go does not export the raw statement verifier).
* ``decision``: one complete verifier decision on the quickstart flow:
  ``verify_proof_bundle_v2`` (hybrid chain and presentation signatures, trust
  pinned to the root key, signed status evaluated against the journal,
  constraint evaluation, claim and commit), then receipt publication,
  checkpoint acknowledgement and ``release_v2_decision``.
* ``dual_root_decision``: two such decisions per call, one under each of two
  independent roots (a two-certificate chain and a one-certificate chain),
  as a cross-domain dual-root receiver performs them.

Challenge issuance and agent-side presentation signing are done before the
clock starts; only verifier work is timed.

Run from ``sdks/python`` with the SDK and its native extension installed::

    python bench_v2/bench_v2.py                       # print a table
    python bench_v2/bench_v2.py --json out.json       # also write JSON
    python bench_v2/bench_v2.py --check               # regression gate (CI)
    python bench_v2/bench_v2.py --profile decision    # cProfile one measurement

Set ``RATIFY_V2_PURE_VERIFY=1`` to measure the pure-Python verification
fallback instead of the native verifier.
"""
from __future__ import annotations

import argparse
import cProfile
import json
import platform
import pstats
import statistics
import sys
import time

from ratify_protocol.v2 import _native, background, key_id_v2
from ratify_protocol.v2.challenge_issuance_v2 import V2ChallengeIssuer, V2ChallengeIssueRequest, load_expected_challenge_v2
from ratify_protocol.v2.constraints_v2 import CONSTRAINT_MAX_AMOUNT, TZDB_VERSION_V2, ConstraintContextV2, ConstraintV2
from ratify_protocol.v2.context_policy_v2 import new_v2_context_policy
from ratify_protocol.v2.protocol_v2 import (
    DelegationCertV2,
    ProofBundleV2,
    encode_proof_bundle_v2,
    encode_revocation_list_v2,
    sign_delegation_cert_v2,
    sign_proof_bundle_v2,
    verify_delegation_cert_v2_signature,
)
from ratify_protocol.v2.release_v2 import V2_RELEASE_RELEASED, V2ReleaseConfig, release_v2_decision
from ratify_protocol.v2.security_journal_v2 import configure_status_key_epoch_v2, record_security_key_role_v2
from ratify_protocol.v2.signing_v2 import DELEGATION_CERTIFICATE, keypair_from_seeds_v2, verify_v2_statement
from ratify_protocol.v2.status_batch_v2 import V2StatusEvidenceBatch, V2StatusEvidenceObject
from ratify_protocol.v2.status_provenance_v2 import V2StatusKeyConfig
from ratify_protocol.v2.status_publisher_v2 import new_v2_status_publisher_with_key
from ratify_protocol.v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol.v2.v2reference.challenges import TestOnlyChallengeIssuanceStore
from ratify_protocol.v2.v2reference.journal import new_journal_store
from ratify_protocol.v2.v2reference.store import Store
from ratify_protocol.v2.verification_receipt_v2 import decode_verification_receipt_v2
from ratify_protocol.v2.verify_v2 import (
    V2_STAGE_COMMITTED,
    V2TrustResolution,
    V2VerifyCallbacks,
    V2VerifyRequest,
    verify_proof_bundle_v2,
)

START = 1800000000
EPOCH = 1
LOG_ID = "00000000000000000000000000000001"
SCOPE = "payments:send"

# Conservative floors for --check, in operations per second: between a tenth
# and a quarter of what the native build measures on an Apple M2 Pro (see the
# README), and above what the pure-Python verifier reaches there (82 / 6.7 /
# 2.4 ops/s for a verify / decision / dual-root decision). The gate fails when
# signature verification falls back to pure Python or a hotspot regresses
# severalfold, not on ordinary runner noise.
CHECK_FLOORS = {"hybrid_verify": 300.0, "cert_signature_verify": 250.0, "decision": 20.0, "dual_root_decision": 5.0}


def _key(n: int):
    """Deterministic hybrid keypair number ``n`` (reproducible runs)."""
    return keypair_from_seeds_v2(bytes([n]) * 32, bytes([n + 100]) * 32)


class Flow:
    """One root's quickstart verifier flow against a shared reference store."""

    def __init__(self, ctx, store, journal, verifier_pub, agent, root_n: int, depth: int, namespace: str):
        self.ctx, self.store, self.journal, self.namespace = ctx, store, journal, namespace
        self.agent_pub, self.agent_priv = agent
        self.verifier_id = key_id_v2(verifier_pub)
        self.verifier_pub = verifier_pub
        root_pub, root_priv = _key(root_n)
        status_pub, status_priv = _key(root_n + 1)
        self.root_pub, self.root_id = root_pub, key_id_v2(root_pub)
        agent_id = key_id_v2(self.agent_pub)
        self.agent_id = agent_id
        # Chain from the root down to the agent; depth 2 adds one intermediate.
        holders = [(root_pub, root_priv)]
        for i in range(depth - 1):
            holders.append(_key(root_n + 2 + i))
        holders.append((self.agent_pub, self.agent_priv))
        certs = []
        for i in range(depth):
            issuer_pub, issuer_priv = holders[i]
            subject_pub = holders[i + 1][0]
            certs.append(sign_delegation_cert_v2(DelegationCertV2(
                version=2, cert_id=f"{namespace}-cert-{i}",
                issuer_id=key_id_v2(issuer_pub), issuer_pub_key=issuer_pub,
                subject_id=key_id_v2(subject_pub), subject_pub_key=subject_pub,
                # Every certificate above the leaf must also grant identity:delegate.
                scope=[SCOPE] if i == depth - 1 else [SCOPE, "identity:delegate"],
                constraints=[ConstraintV2(type=CONSTRAINT_MAX_AMOUNT, currency="USD", max_amount_micros=50_000_000)],
                issued_at=START, expires_at=START + 86400,
            ), issuer_priv))
        self.certs = list(reversed(certs))  # leaf first
        for role, pub in [("issuer", root_pub), ("delegation", self.agent_pub)] + [
            ("delegation", h[0]) for h in holders[1:-1]
        ]:
            record_security_key_role_v2(ctx, journal, role, pub)
        # Every issuer in the chain publishes signed status under its own key.
        self.status_keys, self.status_wires = {}, {}
        for j, (issuer_pub, _issuer_priv) in enumerate(holders[:-1]):
            s_pub, s_priv = (status_pub, status_priv) if j == 0 else _key(root_n + 50 + j)
            issuer_id = key_id_v2(issuer_pub)
            configure_status_key_epoch_v2(ctx, journal, issuer_id, 1, s_pub)
            publisher = new_v2_status_publisher_with_key(ctx, journal, issuer_pub, s_priv, 3600)
            self.status_wires[issuer_id] = encode_revocation_list_v2(publisher.genesis(ctx, START).list)
            self.status_keys[issuer_id] = V2StatusKeyConfig(epoch=1, key=s_pub)
        self.issuance = TestOnlyChallengeIssuanceStore()
        self.policy = new_v2_context_policy("example.quickstart/v1", False, [], None)

    def present(self):
        """Issue a challenge and sign a presentation (agent side, untimed)."""
        challenge = V2ChallengeIssuer(clock=self.store, store=self.issuance).issue_challenge_v2(
            self.ctx, V2ChallengeIssueRequest(
                verifier_namespace=self.namespace, replay_epoch=EPOCH, verifier_id=self.verifier_id,
                lifetime_seconds=120, expected_agent_id=self.agent_id, expected_agent_public_key=self.agent_pub,
            ))
        bundle = sign_proof_bundle_v2(ProofBundleV2(
            version=2, verifier_id=self.verifier_id, agent_id=self.agent_id, agent_pub_key=self.agent_pub,
            delegations=self.certs, challenge=challenge.value, challenge_at=challenge.issued_at,
            delegation_digest=b"", challenge_sig=None,
        ), self.agent_priv)
        return bundle.challenge, encode_proof_bundle_v2(bundle)

    def decide(self, presentation) -> None:
        """Verify, commit, publish, acknowledge and release one decision."""
        ctx, store = self.ctx, self.store
        challenge, wire = presentation
        root_id, root_pub = self.root_id, self.root_pub

        def trust(_ctx, chain):
            if chain[-1].issuer_id == root_id:
                return V2TrustResolution(outcome="trusted", root_key=root_pub)
            return V2TrustResolution(outcome="untrusted")

        def status_evidence(_ctx, status_req):
            status_wire = self.status_wires[status_req.issuer_id]
            return V2StatusEvidenceBatch(objects=[V2StatusEvidenceObject(object_type=3, wire=status_wire)])

        expected = load_expected_challenge_v2(ctx, self.issuance, self.namespace, EPOCH, challenge)
        req = V2VerifyRequest(
            bundle=wire, expected=expected, context_policy=self.policy,
            required_scope=SCOPE, verifier_namespace=self.namespace, replay_epoch=EPOCH, verifier_id=self.verifier_id,
            now=store.now(), max_challenge_age_seconds=300, future_skew_seconds=5,
            context=ConstraintContextV2(has_amount=True, requested_amount_micros=12_500_000, requested_currency="USD"),
            tzdb_version=TZDB_VERSION_V2,
            status_keys=self.status_keys,
            status_policy=RevocationStatusPolicyV2(max_list_lifetime_seconds=3600, max_status_age_seconds=3600, clock_skew_seconds=5),
        )
        cb = V2VerifyCallbacks(claim_store=store, trust=trust, status_evidence=status_evidence, status_journal=self.journal)
        outcome = verify_proof_bundle_v2(ctx, req, cb)
        if outcome.stage != V2_STAGE_COMMITTED:
            raise RuntimeError(f"verify stopped at {outcome.stage}: {outcome.error}")
        receipt_wire = store.publish_v2_receipt(ctx, outcome.committed.claim_id(), outcome.committed.receipt_body())
        decode_verification_receipt_v2(receipt_wire)
        result = release_v2_decision(ctx, outcome.committed, receipt_wire, V2ReleaseConfig(
            verifier_public_key=self.verifier_pub, log_id=LOG_ID, claim_store=store, checkpoint=store,
        ))
        if result.status != V2_RELEASE_RELEASED or not result.decision.allowed(ctx, store):
            detail = result.decision and (result.decision.decision(), result.decision.reason())
            raise RuntimeError(f"release {result.status}: {result.reason} {detail}")


class Bench:
    def __init__(self):
        ctx = background()
        verifier_pub, verifier_priv = _key(1)
        agent = _key(2)
        store = Store(START, 30, LOG_ID, verifier_priv)
        journal = new_journal_store()
        record_security_key_role_v2(ctx, journal, "verifier", verifier_pub)
        self.single = Flow(ctx, store, journal, verifier_pub, agent, 10, 1, "bench-single")
        self.authority = Flow(ctx, store, journal, verifier_pub, agent, 20, 2, "bench-authority")
        self.admission = Flow(ctx, store, journal, verifier_pub, agent, 30, 1, "bench-admission")
        self.store = store
        self.clock = START
        cert = self.single.certs[0]
        from ratify_protocol.v2.protocol_v2 import cert_signable_bytes_v2
        self.verify_args = (DELEGATION_CERTIFICATE, cert_signable_bytes_v2(cert), cert.signature, cert.issuer_pub_key)

    def _tick(self) -> None:
        # The reference clock never moves backward: present, then verify 2s later.
        self.clock += 2
        self.store.set_time(self.clock)

    def run(self, name: str, n: int, profile: bool = False) -> list[float]:
        """Return per-operation latencies in seconds for ``n`` operations."""
        if name == "hybrid_verify":
            ops = [self.verify_args] * n
            fn = lambda args: verify_v2_statement(*args)  # noqa: E731
        elif name == "cert_signature_verify":
            ops = [self.single.certs[0]] * n
            fn = verify_delegation_cert_v2_signature
        elif name == "decision":
            self._tick()
            ops = [self.single.present() for _ in range(n)]
            self._tick()
            fn = self.single.decide
        elif name == "dual_root_decision":
            self._tick()
            ops = [(self.authority.present(), self.admission.present()) for _ in range(n)]
            self._tick()

            def fn(pair):
                self.authority.decide(pair[0])
                self.admission.decide(pair[1])
        else:
            raise ValueError(name)
        profiler = cProfile.Profile() if profile else None
        out = []
        if profiler:
            profiler.enable()
        for op in ops:
            t0 = time.perf_counter()
            fn(op)
            out.append(time.perf_counter() - t0)
        if profiler:
            profiler.disable()
            pstats.Stats(profiler).sort_stats("cumulative").print_stats(45)
            pstats.Stats(profiler).sort_stats("tottime").print_stats(30)
        return out


ITERATIONS = {"hybrid_verify": 200, "cert_signature_verify": 200, "decision": 50, "dual_root_decision": 25}


def _summary(latencies: list[float]) -> dict:
    total = sum(latencies)
    ordered = sorted(latencies)
    return {
        "n": len(latencies),
        "ops_per_s": round(len(latencies) / total, 2),
        "mean_ms": round(statistics.fmean(latencies) * 1000, 3),
        "p50_ms": round(ordered[len(ordered) // 2] * 1000, 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))] * 1000, 3),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", choices=sorted(ITERATIONS), action="append")
    parser.add_argument("--scale", type=float, default=1.0, help="multiply iteration counts")
    parser.add_argument("--json", help="write results as JSON to this path")
    parser.add_argument("--check", action="store_true", help="fail if any result is below its floor")
    parser.add_argument("--profile", choices=sorted(ITERATIONS), help="cProfile one measurement")
    args = parser.parse_args(argv)

    from ratify_protocol.v2 import signing_v2

    verifier = "native" if signing_v2.native_verify_enabled() else "pure-python"
    bench = Bench()
    if args.profile:
        bench.run(args.profile, max(1, int(ITERATIONS[args.profile] * args.scale)), profile=True)
        return 0
    names = args.only or ["hybrid_verify", "cert_signature_verify", "decision", "dual_root_decision"]
    results = {}
    for name in names:
        n = max(1, int(ITERATIONS[name] * args.scale))
        if verifier == "pure-python":
            n = max(1, n // 25)
        bench.run(name, min(n, 3))  # warm-up
        results[name] = _summary(bench.run(name, n))
    report = {
        "sdk": "python",
        "verifier": verifier,
        "python": platform.python_version(),
        "machine": f"{platform.system()} {platform.machine()} {platform.processor() or ''}".strip(),
        "native_extension": _native.AVAILABLE,
        "results": results,
    }
    print(f"python {report['python']} on {report['machine']}; signature verification: {verifier}")
    print(f"{'measurement':<22} {'n':>5} {'ops/s':>10} {'mean ms':>10} {'p50 ms':>10} {'p95 ms':>10}")
    for name, r in results.items():
        print(f"{name:<22} {r['n']:>5} {r['ops_per_s']:>10} {r['mean_ms']:>10} {r['p50_ms']:>10} {r['p95_ms']:>10}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
    if args.check:
        failed = [
            f"{name}: {r['ops_per_s']} ops/s < floor {CHECK_FLOORS[name]}"
            for name, r in results.items() if r["ops_per_s"] < CHECK_FLOORS[name]
        ]
        if verifier != "native":
            failed.append("signature verification is not native")
        for line in failed:
            print(f"FAIL {line}", file=sys.stderr)
        if failed:
            return 1
        print("ok   performance floors met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
