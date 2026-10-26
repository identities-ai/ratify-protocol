<!-- GENERATED FILE — do not edit directly.
     Sources: sdks/readme-src/preamble.md + README.body.md in this directory.
     Regenerate: python3 scripts/gen-sdk-readmes.py -->
# Ratify Protocol C/C++ SDK

**C and C++ reference SDK of the Ratify Protocol: delegated-authority proofs for human-agent and agent-agent interactions.**

Hybrid signatures: every signature is Ed25519 plus ML-DSA-65 (NIST FIPS 204), and both must verify, so a forger has to break both algorithms.

Byte-identical interoperability with the Go, TypeScript, Python, and Rust reference implementations. Validated against the **79 canonical test vectors** (Protocol v1) on every CI run. This package also implements Protocol v2 (version `2.0.0-alpha.1`, a prerelease) and runs every file in the shared `testvectors/v2` corpus and the cross-SDK fixtures of every other SDK.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof without calling back to whoever issued it. In Protocol v2 the verifier then **releases** the decision: it is actionable only after the verifier's signed receipt has been acknowledged by an independent checkpoint.

For Protocol v1, beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), single-use challenge acceptance through a pluggable challenge store (SPEC §10), the SessionToken fast path (one hybrid signature verification per turn instead of N+1) with scope, single-use, and binding enforcement on the streamed path, canonical operation- and session-context binding for middleware custody deployments (SPEC §6.4.9, §15.2.1), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec. Protocol v2 has its own session and stream binding, signed status, receipts, witness entries and key rotation; the SessionToken fast path, A2A mutual presentation, the HTTP and registry bindings, and the geo and speed constraints remain v1-only until Protocol 2.1.

- Protocol v1 spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Protocol v2 spec: [SPEC-v2.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC-v2.md), upgrade guide: [docs/PROTOCOL_V2_MIGRATION.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md)
- Runnable v2 examples in every SDK language: [examples/v2](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.ratifyprotocol.com](https://docs.ratifyprotocol.com)

---

## Which SDK should I use?

| You're writing | Use |
|---|---|
| A Go service or CLI | [Go SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/go) |
| A Node.js or browser app | [TypeScript SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/typescript) |
| A Python script, ML pipeline, data tool | [Python SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/python) |
| A Rust service or high-performance binary | [Rust SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/rust): use directly, no FFI overhead |
| **C or C++ code** | **This SDK** |
| **RTOS firmware with a std shim** (FreeRTOS, Zephyr) | **This SDK** (requires std/heap; see Embedded deployment guide) |
| **A language that FFIs to C** (Swift, Zig, Julia, Lua, etc.) | **This SDK** |
| **Air-gapped Linux or RTOS device** | **This SDK** (static library `libratify_c.a`, verifies offline) |
| **Bare-metal / no-OS firmware** (no heap, no std) | [Rust SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/rust) with `no_std` + `alloc` (the C SDK requires std/heap) |

The C SDK wraps the Rust SDK via a C ABI. If you're writing Rust, use the Rust SDK directly. The C SDK adds an FFI boundary with no benefit in a Rust context.

---

## Embedded deployment guide

### What "entropy" is and why it matters

**Entropy** = cryptographically unpredictable random bytes. The C SDK needs entropy for two
operations: generating challenge bytes (`ratify_challenge_generate`) and generating unique
cert IDs (`ratify_delegation_issue`). Without unpredictable entropy, challenges can be
replayed and certs can collide.

On standard OS targets (Linux, macOS, Windows, Raspberry Pi) entropy is automatic: the
OS provides `/dev/urandom` or an equivalent. On embedded targets, you may need to wire
in the hardware TRNG (True Random Number Generator) manually.

### Standard targets (Raspberry Pi, embedded Linux)

No configuration needed. `getrandom` reads from the OS entropy pool automatically.

```bash
# Cross-compile for Raspberry Pi (ARM64)
cross build --release --target aarch64-unknown-linux-gnu
# Copy and run on the Pi:
scp target/aarch64-unknown-linux-gnu/release/libratify_c.a pi@raspberrypi.local:~
```

### RTOS targets with hardware TRNG (FreeRTOS, Zephyr, STM32)

Enable the `custom-entropy` Cargo feature and register your hardware RNG:

**Cargo.toml:**
```toml
ratify-c = { path = "…", features = ["custom-entropy"] }
```

`ratify_set_entropy_source` is exported only by a `custom-entropy` build, and
`ratify.h` declares it only when `RATIFY_CUSTOM_ENTROPY` is defined, so define
it when compiling against that build (for example `-DRATIFY_CUSTOM_ENTROPY`).

**C application startup:**
```c
#define RATIFY_CUSTOM_ENTROPY  /* or -DRATIFY_CUSTOM_ENTROPY */
#include "ratify.h"

/* Provide random bytes from the STM32 hardware TRNG */
static int my_entropy(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t rnd;
        if (HAL_RNG_GenerateRandomNumber(&hrng, &rnd) != HAL_OK)
            return -1;  /* -1 means "entropy unavailable": the call fails */
        size_t copy = (len - i < 4) ? (len - i) : 4;
        memcpy(buf + i, &rnd, copy);
    }
    return 0;
}

int main(void) {
    /* MUST be called before any ratify_challenge_generate() or
       ratify_delegation_issue() call */
    ratify_set_entropy_source(my_entropy);
    /* … rest of your application */
}
```

If `ratify_set_entropy_source()` was never called when the `custom-entropy` feature is
enabled, or the callback reports failure, every operation that needs randomness fails with
`RatifyErrInternal` (or NULL) instead of producing output. This is intentional: generating
certs with weak randomness is worse than not running at all. See [Panic behavior](#panic-behavior).

### Note on std requirement

The C SDK currently requires Rust's standard library (`std`) because `serde_json`, which
the Ratify Protocol uses for its JSON wire format, does not support `no_std`. This means the
library cannot link into bare-metal firmware with no heap at all. Targets supported:

| Target | Works? | Notes |
|---|---|---|
| Linux (any arch) | ✅ | Raspberry Pi, BeagleBone, embedded Linux SBCs; built and tested in CI |
| FreeRTOS / Zephyr with a std shim | ⚠️ Unverified | Requires a custom toolchain and sysroot that provide a Rust `std` distribution (the crate imports `std` unconditionally). No reproducible RTOS build is gated yet, so treat this as unverified until you complete a target integration build |
| Bare-metal (no OS, no heap) | ❌ | No heap, no std; use the Rust SDK directly with `#[no_std]` + `alloc` |

RTOS targets are not covered by CI. Before relying on one, stand up the custom toolchain and run a full integration build; the tables below list the target triples but do not imply a gated, reproducible build for the non-Linux entries.

## Supported targets

| Architecture | Target triple | Example hardware |
|---|---|---|
| x86-64 | `x86_64-unknown-linux-gnu` | Intel/AMD server, Linux PC |
| ARM64 | `aarch64-unknown-linux-gnu` | Raspberry Pi 4, embedded Linux, Apple Silicon |
| ARM32 | `armv7-unknown-linux-gnueabihf` | Raspberry Pi 2/3, older embedded Linux |
| ARM Cortex-M4/M7 (RTOS, unverified) | `thumbv7em-none-eabihf` is a bare `none` triple with no upstream Rust `std`; an RTOS build needs a custom `std`-providing toolchain and is not gated in CI | STM32, NXP running FreeRTOS/Zephyr |
| x86-32 | `i686-unknown-linux-gnu` | Legacy industrial, 32-bit Linux |
| RISC-V 64 | `riscv64gc-unknown-linux-gnu` | SiFive, emerging IoT |
| macOS ARM64 | `aarch64-apple-darwin` | Apple Silicon Mac |
| macOS x86-64 | `x86_64-apple-darwin` | Intel Mac |
| Windows x86-64 | `x86_64-pc-windows-msvc` | Native Windows |

---

## Build

**Prerequisites:** [Rust toolchain](https://rustup.rs) 1.70+.

```bash
# Static + shared library for your native host
cargo build --release

# Outputs:
#   target/release/libratify_c.a    : static library (embed in firmware)
#   target/release/libratify_c.so   : shared library (Linux)
#   target/release/libratify_c.dylib: shared library (macOS)
#   include/ratify.h                : C/C++ header (auto-generated, committed)
```

**Cross-compile with `cross`:**

```bash
cargo install cross --git https://github.com/cross-rs/cross

# ARM64 (Raspberry Pi 4, embedded Linux)
cross build --release --target aarch64-unknown-linux-gnu

# ARM32 (Raspberry Pi 2/3)
cross build --release --target armv7-unknown-linux-gnueabihf

# RISC-V 64
cross build --release --target riscv64gc-unknown-linux-gnu
```

---

## Using the header without the Rust toolchain

The generated `include/ratify.h` is committed to the repository. You can vendor
it alongside the pre-built libraries from a [GitHub release](https://github.com/identities-ai/ratify-protocol/releases)
without installing Rust.

---

## Integration

### CMake

```cmake
cmake_minimum_required(VERSION 3.20)
project(my_agent C)

# Point to where you extracted the Ratify SDK
set(RATIFY_SDK_DIR "${CMAKE_SOURCE_DIR}/vendor/ratify-c")

add_library(ratify STATIC IMPORTED)
set_target_properties(ratify PROPERTIES
    IMPORTED_LOCATION "${RATIFY_SDK_DIR}/lib/libratify_c.a"
    INTERFACE_INCLUDE_DIRECTORIES "${RATIFY_SDK_DIR}/include"
)

add_executable(my_agent main.c)
target_link_libraries(my_agent PRIVATE ratify pthread dl m)
```

### Meson

```meson
project('my_agent', 'c')

ratify_dep = declare_dependency(
    include_directories: include_directories('vendor/ratify-c/include'),
    link_args: [
        '-L' + meson.source_root() / 'vendor/ratify-c/lib',
        '-lratify_c',
        '-lpthread', '-ldl', '-lm',
    ],
)

executable('my_agent', 'main.c', dependencies: [ratify_dep])
```

### Plain Makefile

```makefile
RATIFY_SDK = vendor/ratify-c

CFLAGS  = -I$(RATIFY_SDK)/include
LDFLAGS = -L$(RATIFY_SDK)/lib -lratify_c -lpthread -ldl -lm

my_agent: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
```

### C++ usage

The header emits `extern "C" { ... }` guards automatically. Use it as-is:

```cpp
#include "ratify.h"   // works in both C and C++
#include <string>
#include <stdexcept>

class RatifyVerifier {
    // RAII wrapper example
public:
    bool verify(const std::string& bundle_json, const std::string& scope) {
        RatifyVerifyResult* result = nullptr;
        char* err = nullptr;
        auto status = ratify_verify_bundle(
            bundle_json.c_str(), scope.empty() ? nullptr : scope.c_str(),
            0, // system clock
            &result, &err
        );
        if (status != RatifyOk || !result) {
            std::string msg = err ? err : "unknown error";
            ratify_error_free(err);
            throw std::runtime_error("verify failed: " + msg);
        }
        bool valid = ratify_verify_result_is_valid(result) != 0;
        ratify_verify_result_free(result);
        return valid;
    }
};
```

---

## API overview

### Key generation

Key generation returns a `RatifyStatus` (check it for null-pointer and argument
errors). On a standard OS target it has no recoverable failure mode, because the
operating system supplies entropy. It is not truly infallible on embedded targets:
if no entropy source is configured, it returns `RatifyErrInternal` rather than
generate a key from weak randomness. See the Embedded deployment guide.

```c
// Generate a HumanRoot keypair (the delegating principal)
RatifyHumanRoot *root = NULL;
ratify_human_root_generate(&root);

// Generate an AgentIdentity keypair
RatifyAgent *agent = NULL;
ratify_agent_generate("MyDroneBot", "drone", &agent);

// Get the identity ID strings (hex)
char *root_id  = ratify_human_root_id(root);
char *agent_id = ratify_agent_id(agent);
ratify_string_free(root_id);
ratify_string_free(agent_id);
```

### Delegation

```c
RatifyDelegationCert *cert = NULL;
char *err = NULL;

// Delegate "physical:enter" to the agent; expires_at 0 = no expiry (until revoked)
ratify_delegation_issue(root, agent, "[\"physical:enter\"]", 0 /* issued_at */, 0 /* expires_at: 0 = no-expiry sentinel */, &cert, &err);

char *cert_json = ratify_delegation_cert_to_json(cert, &err);
// Send cert_json to the agent over your transport layer
ratify_string_free(cert_json);
```

### Challenge and ProofBundle

```c
// Agent side: receive the cert JSON and a fresh challenge
uint8_t challenge[32];
ratify_challenge_generate(challenge, 32);

RatifyProofBundle *bundle = NULL;
int64_t now = (int64_t)time(NULL);
ratify_proof_bundle_create(agent, cert_json, challenge, 32, now, &bundle, &err);

char *bundle_json = ratify_proof_bundle_to_json(bundle, &err);
// Send bundle_json to the verifier
```

### Verification (Protocol v1), simple path

```c
// Verifier side: just scope + clock (the common embedded path)
RatifyVerifyResult *result = NULL;
ratify_verify_bundle(bundle_json, "physical:enter", 0, &result, &err);

if (ratify_verify_result_is_valid(result)) {
    char *agent_id = ratify_verify_result_agent_id(result);
    printf("authorized agent: %s\n", agent_id);
    ratify_string_free(agent_id);
} else {
    char *status = ratify_verify_result_identity_status(result);
    printf("rejected: %s\n", status);
    ratify_string_free(status);
}
ratify_verify_result_free(result);
```

### Verification (Protocol v1), full options (revocation, geo constraints, session binding)

The callback revocation and the geo constraints below are v1 constructions. Protocol v2 takes only signed status from a separate status key, and has no geo or speed constraint until 2.1.

```c
// Revocation callback
int my_revocation_check(const char *cert_id, void *userdata) {
    MyDB *db = (MyDB *)userdata;
    if (db_is_revoked(db, cert_id)) return 1;  // revoked
    if (db_error(db))               return -1; // fail-closed
    return 0;                                   // not revoked
}

// Location context for geo constraints
RatifyVerifierContext ctx = {0};
ctx.current_lat = 47.6062;
ctx.current_lon = -122.3321;
ctx.has_location = 1;

RatifyVerifyOptions opts = {0};
opts.required_scope      = "physical:enter";
opts.revocation_fn       = my_revocation_check;
opts.revocation_userdata = my_db;
opts.context             = &ctx;

RatifyVerifyResult *result = NULL;
ratify_verify_bundle_opts(bundle_json, &opts, &result, &err);
```

### Advanced surface (v1.1)

The core paths above cover one-shot verification. The full v1.1 surface is exported through the same header, and every symbol is documented in `include/ratify.h`:

| Family | Symbols | What it does |
|---|---|---|
| Resource-path verification | `ratify_verify_bundle_opts_v2` (`RatifyResourceContext`) | Carries the `requested_resource_id` / `requested_path` needed to evaluate a `resource_path` constraint (SPEC §5.16); `ratify_verify_bundle_opts` remains the non-resource path |
| Session tokens | `ratify_session_token_issue` / `_verify` / `_to_json` / `_from_json` | The streamed fast path: verify the chain once, verify each turn against an HMAC token |
| Streamed verification | `ratify_verify_streamed_turn_opts` | Per-turn verification with required scope, single-use challenges, and session/stream binding enforcement (`RatifyStreamedVerifyOptions`) |
| Challenge store | `ratify_challenge_store_new` / `_issue` / `_check` / `_consume` | Single-use challenge acceptance (SPEC §10); `ratify_verify_bundle_opts_with_challenge_store` wires it into full verification |
| Operation / session context | `ratify_operation_context_hash`, `ratify_session_context_build` | Canonical SPEC §6.4.9 constructions for session binding and the Middleware Custody Profile (§15.2.1) |
| Revocation | `ratify_revocation_list_*`, `ratify_revocation_push_*` | Signed revocation lists and push messages |
| Receipts + verdicts | `ratify_receipt_*`, `ratify_policy_verdict_*` | Verification receipts (§17.5) and HMAC-bound cached policy decisions (§17.6) |
| Multi-party + audit | `ratify_transaction_receipt_*`, `ratify_witness_entry_*`, `ratify_key_rotation_*` | Transaction receipts (§5.14), witness logs (§5.12), key rotation (§5.15) |
| Scope utilities | `ratify_scope_*`, `ratify_scopes_*`, `ratify_scope_vocabulary` | Expansion, intersection, validation, and vocabulary discovery |

The Protocol v2 C surface includes `ratify_derive_key_id_v2` for the full
256-bit hybrid key ID, `ratify_verify_delegation_signature_v2` for both signature
components over exact canonical signable bytes, and separate v2 operation and
session-context helpers. The signature primitive fixes the delegation object
code and v2 ML-DSA context. It writes 1 or 0 to `valid_out`, including 0 on
error. Malformed JSON returns an error status; a parsed but invalid key or
signature returns success with `valid_out` set to 0. The caller supplies a
non-null readable buffer and must construct and validate the exact canonical
signable projection. This function does not parse a certificate, check its key
ID, or authorize a chain.
`ratify_challenge_claim_digest_v2` writes 48 digest bytes;
`ratify_protocol_claim_id_v2` and
`ratify_protocol_claim_id_from_digest_v2` write a 64-character lowercase ID
plus NUL. They match `testvectors/v2/challenge-claim.json`. The namespace is
length-delimited UTF-8, so embedded NUL bytes are supported. These functions
require caller-provided output capacities and do not issue challenges or make
durable atomic claims. The digest buffer is zeroed on failure when its declared
capacity is at least 48 bytes; claim-ID buffers start with NUL on failure when
their declared capacity is nonzero.
`ratify_derive_id` and `ratify_verify_delegation_signature` retain their v1
behavior.

### Protocol v2 ABI (`ratify_v2_*`)

Version `2.0.0-alpha.1` is a prerelease on the separate v2 line. Review so far is
internal adversarial review; external independent review is a gate for
`2.0.0`, and v2 carries no production security claim yet. Runnable C programs
live in
[`examples/v2/c`](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2/c):
a quickstart (keys, delegation, challenge from the issuance helper, proof,
verify, receipt, checkpoint, release, `ratify_v2_released_allowed`), signed
status with a revocation, an exact `custom:` scope with the `max_count/v1`
evaluator profile, and an external signer. They print the same output as the
other SDKs' programs, and CI checks it. They link the test-only reference
stores and are development-only. Upgrading from v1 is covered in
[`docs/PROTOCOL_V2_MIGRATION.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md).

The `ratify_v2_*` functions are the complete Protocol v2 surface. They are an
ABI over the Rust `ratify-protocol` v2 implementation (SPEC-v2 §1.3), not an
independent implementation. Check `ratify_v2_abi_version()` against
`RATIFY_V2_ABI_VERSION` before use; the v1 functions above are unchanged.

| Area | Functions |
|---|---|
| Keys | `ratify_v2_keypair_from_seeds`, `ratify_v2_keypair_generate`, `ratify_v2_keypair_public_key`, `ratify_v2_keypair_key_id`, `ratify_v2_public_key_id`, `ratify_v2_key_id`, `ratify_v2_key_id_check` |
| Typed signing (every object) | `ratify_v2_sign_delegation_certificate`, `_proof_bundle`, `_revocation_list`, `_revocation_push`, `_key_rotation_statement`, `_witness_entry`, `_transaction_receipt_party`, `_verification_receipt`, `_prepared_verification_receipt` |
| Decode, transcripts, digests | `ratify_v2_object_decode` (strict, byte limits), `ratify_v2_signable_bytes`, `ratify_v2_signing_message`, `ratify_v2_mldsa_context`, `ratify_v2_external_mu`, `ratify_v2_verify_statement`, every SPEC-v2 §4 digest, `ratify_v2_canonical_json`, operation and session context |
| Stateless verification | `ratify_v2_verify_object`, `ratify_v2_proof_bundle_verify_signatures`, `ratify_v2_receipt_bundle_binding_check`, `ratify_v2_archival_verify` |
| Live verifier | `ratify_v2_verify_proof_bundle`, `ratify_v2_claim_proof_bundle`, `ratify_v2_recover_interrupted_claim`, `ratify_v2_issue_challenge`, `ratify_v2_load_expected_challenge`, `ratify_v2_verify_transaction_receipt` |
| Release | `ratify_v2_release_decision`, `ratify_v2_released_allowed` and the `ratify_v2_committed_*` / `ratify_v2_released_*` accessors |
| Store helpers | `ratify_v2_challenge_time_current`, `ratify_v2_check_stream_sequence`, `ratify_v2_validate_finalization_payload`, `ratify_v2_valid_release_record_outcome`, `ratify_v2_valid_evaluation_progress`, `ratify_v2_claim_id_matches_key` |
| State machines | status reducer (`ratify_v2_status_state_*`), `SecurityJournalV2` (`ratify_v2_journal_*`), status publisher (`ratify_v2_status_publish`), rotation journal (`ratify_v2_rotation_journal_*`), witness and receipt logs (`ratify_v2_witness_entry_append`, `ratify_v2_verification_receipt_append`) |

No function signs caller-selected bytes, codes, contexts, or prehash modes.
Each signing function takes a typed object (its wire JSON; absent signature
members are allowed) and exactly one signer: a library key pair or a
`RatifyV2ExternalSigner` (an HSM or KMS behind two callbacks, in direct or
external-μ mode). A key-rotation statement takes two signers of the same
kind: two key pairs or two external signers. Issuer duties are checked before
any signer callback runs, and every returned signature is verified before an
object is produced. `ratify_v2_keypair_free` wipes the private key.

**Result codes.** Every fallible function returns an `int32_t`: `0` on
success; a positive code naming exactly one of the 49 SPEC-v2 §2.7 classes,
numbered in the order of that table; or a negative code. `-1` to `-4` are ABI
conditions (`null_pointer`, `bad_argument`, `internal`, `cancelled`), `-10` to
`-17` are store sentinels a callback returns. A signing refusal reports its
§2.7 class like any other failure: an issuer-duty refusal is `malformed`, a
signer holding a key other than the one the object names is
`key_id_mismatch`, an invalid, unsupported, or failing signer is
`configuration_invalid`, a cancelled signer is `evaluation_cancelled`, and a
returned signature that does not verify is `invalid_signature`.
`ratify_v2_error_class_str` gives the stable spelling. The
diagnostic of the last call on the calling thread is
`ratify_v2_last_error_message()`; it is valid until the next `ratify_v2_*`
call on that thread and must not be freed. Messages are diagnostic only.

**Ownership and lifetimes.** Input buffers are borrowed for the duration of
the call; the library copies anything it keeps. A NULL input pointer is
`null_pointer` even with a zero length. A length is checked before the
library reads the bytes: an input with a SPEC-v2 §2.6 byte limit (every
strict decoder input, including the bundle and receipt a verifier decodes)
is `malformed` over that limit and is never read, and any other byte input
or count over `PTRDIFF_MAX` bytes in total is `bad_argument`. A length that
exceeds its allocation without exceeding these bounds is undefined
behaviour, as for any C API. Outputs the library allocates belong to
the caller and are released only through the matching function:
`ratify_v2_buffer_free` for a `RatifyV2Buffer`, `ratify_v2_string_free` for a
`char *`, and `ratify_v2_<handle>_free` for a handle. The library never frees
caller or callback memory. Structured inputs (requests, heads, policies) are
JSON with the schemas documented in `ratify.h`; unknown members and repeated
member names (at any nesting level) are rejected.

**Callbacks.** Every provider and store is a struct of function pointers with
an opaque `user` pointer: claim store and authoritative clock, trust provider
(including the ambiguous outcome), status evidence provider returning signed
batches, security journal store, audience provider, rate store (or rate
admission at finalization), receiver-binding hook, release store, checkpoint,
issuance store, and random source. A callback runs on the calling thread
before the ABI function returns and is never retained afterwards. Buffers the
library passes in are valid only until the callback returns. Pointers a
callback writes into an output struct are read after it returns, so they must
stay valid after the callback returns until the library has copied them
(before the ABI call returns), and must never point into the callback's own
stack frame. A callback returns `0`, a positive class
(for example `RatifyV2ClockRegressed`), a store sentinel, or
`RatifyV2ErrCancelled`. A callback failure is always handled fail-closed,
and so is an answer whose length or count is over `PTRDIFF_MAX` bytes in
total: the library never reads it, and treats it as that provider or store
failing (an audience answer is `constraint_unverifiable`). A string a
callback answers with (an identifier, digest or reason) must be valid UTF-8;
one that is not is treated the same way, never compared as a lossy copy.
Identifiers reach callbacks as NUL-terminated C strings, so the library
never passes one that contains U+0000 (and never strips the NUL): a
configured `verifier_namespace` containing U+0000 is `configuration_invalid`
before any callback runs (in verification, a preflight outcome reported
after the bundle decodes, so an undecodable bundle is `malformed`), and any
other such identifier fails the call closed as that provider or store being
unavailable, without calling it.

Constraint evaluators also run on the calling thread (SPEC-v2 §1.3). The
registry timeout is enforced by elapsed time, not by interrupting the call:
an evaluator answer returned at or after the deadline is discarded and the
constraint is `constraint_unverifiable`. An evaluator that never returns
blocks the ABI call indefinitely, so a custom evaluator should poll
`ratify_v2_evaluator_call_expired` and return once it reports 1.
The two standard profiles (`com.ratifyprotocol.max_count/v1`,
`com.ratifyprotocol.allowed_values/v1`) are built in.

**Cancellation.** A callback cancels an operation by returning
`RatifyV2ErrCancelled`; the library treats it as a provider cancellation
under SPEC-v2 §6.11. Its effect depends on the callback:

| Callback returning `RatifyV2ErrCancelled` | Result |
| --- | --- |
| receiver-binding hook (the only callback before the claim) | preflight `evaluation_cancelled`; nothing consumed |
| trust, status, journal, audience, rate, progress, finalize | `evaluation_cancelled`; nothing committed |
| `claim` | preflight `claim_store_unavailable`; nothing claimed |
| constraint evaluator | a provider failure: the constraint is `constraint_unverifiable` and the result is committed |
| release store or checkpoint (during release) | release status `pending` |

There is no other asynchronous cancellation.

**Decisions.** The `request_json` of `ratify_v2_verify_proof_bundle` and
`ratify_v2_claim_proof_bundle` carries the caller-authenticated `verifier_id`
(the verifier key ID) beside `verifier_namespace` and `replay_epoch`. It is
required (SPEC-v2 §6.1): an absent or non-canonical value is a preflight
`configuration_invalid`, and an expected challenge or proof naming another
verifier is a preflight `verifier_id_mismatch`, before any claim.
`ratify_v2_verify_proof_bundle` reports a stage (`preflight`,
`replay`, `evaluating`, `committed`) and never a decision. A committed
outcome is an opaque `RatifyV2Committed` handle that is not actionable.
`ratify_v2_release_decision` is the only constructor of a
`RatifyV2Released` handle, and every accessor returns a copy. Gate a side
effect only on `ratify_v2_released_allowed`, which reads your authoritative
clock and returns 1 only for an allow strictly before both sealed deadlines;
any failure returns 0.

**Release records.** A release store records two kinds of
`RatifyV2ReleaseRecord` through `record_release` (SPEC-v2 §6.9): a release
(`outcome` `RatifyV2ReleaseReleased`, `reason` "") and a withheld result of
release steps 7 and 8 (`outcome` `RatifyV2ReleaseWithheld`, `reason`
"clock_regressed", "challenge_expired" or "allow_horizon_passed"). The first
record for a claim wins: an identical record returns 0 and any different
one returns `RatifyV2StoreReleaseStateMismatch`. `load_terminal` returns the
record unchanged in `release_outcome` and `release_reason`; a recorded
withheld result makes every later release of the claim withheld with that
reason, and an outcome other than released or withheld (including the zero
value) is `rejected / release_state_mismatch`. If recording a withheld
result fails, that call is still withheld. `rejected` describes only the
call that returned it and records nothing. A claim store's `finalize`
refuses a receipt body that does not bind the sealed claim (SPEC-v2 §7.5),
which `ratify_v2_validate_finalization_payload` checks against the claim's
persisted `record`, and a checkpoint that sees a different entry hash at an
acknowledged sequence refuses it and acknowledges nothing further for that
log (§7.8).

**Store records.** The claim `record` a claim store receives is the
RatifyCanonicalJSON sealed claim object of SPEC-v2 §7.13, and a progress
record is the five-member canonical object of §7.5. Persist both unchanged:
`load_interrupted` must return the same bytes, and recovery refuses a record
that is not canonical or not valid as `RatifyV2Malformed`, committing
nothing. Before creating a claim, a store keyed by claim ID checks
`ratify_v2_claim_id_matches_key`. Expected challenges cross the issuance
store in the ABI's request encoding (`value_b64`,
`expected_session_context_b64`, absent optional members omitted), the same
form `request_json` takes.

**Thread safety.** Functions that take no handle are safe to call
concurrently. A handle is used by one thread at a time; serialize concurrent
use of one handle yourself. The status reducer handle
(`ratify_v2_status_state_*`) also serializes its own updates: each apply or
epoch transition reads, applies, and replaces the state under one lock, so
concurrent updates never overwrite each other. Store callbacks provide the
atomicity Part B requires (for example a claim store must make the claim
atomic across threads and processes).

**Panics.** Every export catches a panic and returns the internal-failure
value (see below). A handle in use when a panic is caught is poisoned: every
later call on it returns `RatifyV2ErrInternal`. Free it and create a new one.

**Test-only reference stores.** Building with the `test-reference` feature
exports `ratify_v2_ref_*`: the in-memory reference implementations of the
Part B stores and of the single-device offline and dual-root profile
components, presented through the same callback structs. They are not
durable or production-safe, are declared in the header only under
`RATIFY_V2_TEST_REFERENCE`, and a shipped build never enables them.

**Conformance.** The `tests/v2c_*.rs` runners call only `ratify_v2_*`
exports and run every file in `testvectors/v2` through the C ABI, including
the verifier ordering, lifecycle and profile scenarios, status, journal,
publisher, log, rotation, transaction, issuance, device-state projection,
and cross-SDK fixtures; `tests/v2c_inventory.rs` fails if any corpus file is
unconsumed. `tests/v2c_public_error_classes.rs` calls every fallible
`ratify_v2_*` export with inputs it must reject and requires a §2.7 class
(the reference class where Go fixes one) or a documented negative code.
`scripts/test-v2-c-abi.sh` runs keys, objects, negatives, hedged signatures,
limits, every verifier-ordering vector, a release lifecycle against a
C-implemented in-memory store, and every cross-SDK fixture from a plain C
program. Because C is an ABI over the Rust implementation, agreement between
C and Rust is not independent evidence (SPEC-v2 §1.3). The per-SDK record
against the gates in SPEC-v2 §8 is in
[`docs/V2_REFERENCE_COMPATIBILITY.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/V2_REFERENCE_COMPATIBILITY.md).

### Added in v1 alpha.16

The following first shipped in the v1 alpha.16 release and are covered by the
test suites. Every symbol below is declared
in `include/ratify.h`. The call snippets in this section are abbreviated and omit
the `RatifyStatus` error checking shown in the complete example above; check every
returned status in real code.

- **Resource-bound verification.** `ratify_verify_bundle_opts_v2` takes a
  `const RatifyResourceContext *` (fields `requested_resource_id` and
  `requested_path`) alongside `RatifyVerifyOptions`, supplying the context a
  `resource_path` constraint (the 8th constraint type, SPEC §5.7.3) needs; the
  verifier context fields are defined in SPEC §5.16.
  Passing `NULL` for `resource` is equivalent to `ratify_verify_bundle_opts`; a
  bundle whose cert bears a `resource_path` constraint verified without this
  context fails closed as `constraint_unverifiable`.
- **Streamed-turn verify options.** `ratify_verify_streamed_turn_opts` with
  `RatifyStreamedVerifyOptions` (`required_scope`, `now_unix`, `session_context`
  / `session_context_len`, `stream`) enforces required scope, single-use
  challenges (via a `RatifyChallengeStore`), and session/stream binding on each
  turn. It supersedes the deprecated positional `ratify_verify_streamed_turn`.
- **Operation and session context.** `ratify_operation_context_hash` and
  `ratify_session_context_build` produce the canonical SPEC §6.4.9 32-byte
  hashes for operation and session binding (and the Middleware Custody Profile,
  SPEC §15.2.1).
- **VerificationReceipt wire codecs.** `ratify_receipt_to_json` and
  `ratify_receipt_from_json` round-trip a `RatifyReceipt` through the strict JSON
  wire form (a decoded receipt carrying an unknown `identity_status` is
  rejected); `ratify_receipt_hash` computes its canonical 32-byte chain hash.
- **Extension-constraint params.** Certs may carry extension constraints with
  typed parameters. These evaluate through the normal verify path and route to
  `constraint_unknown` when the constraint type is unrecognized (no dedicated C
  symbol).
- **Chain-depth ceiling.** The maximum delegation-chain depth is now 8 (raised
  from 3); a deeper chain fails closed as `invalid`, with `error_reason`
  beginning `chain_too_deep`.
- **Input bounds (SPEC §5.1).** Enforced before signature work.
  `MAX_PROOF_BUNDLE_BYTES` (131072, i.e. 128 KiB) is checked before parsing, and
  an oversized payload yields an `invalid` result rather than being parsed.
  Further limits cap scopes per cert (128), constraints per cert (32), scope
  length (256 bytes), identifier length (512 bytes), agent-name length (256
  bytes), and JSON nesting depth (16).

### Memory management

Every function that returns a heap-allocated value documents which `_free`
function to call. **NULL is always safe to pass to `_free` functions.**

```c
ratify_human_root_free(root);   // safe even if root is NULL
ratify_agent_free(agent);
ratify_delegation_cert_free(cert);
ratify_proof_bundle_free(bundle);
ratify_verify_result_free(result);
ratify_string_free(any_string); // for *_to_json, *_id, *_status, *_reason
ratify_error_free(err);         // for err_out parameters
```

---

## Panic behavior

A Rust panic never unwinds into your code. Every exported function catches a
panic at the C ABI boundary and returns its internal-error value instead:

| Function returns | Value after a caught panic |
|---|---|
| `RatifyStatus` | `RatifyErrInternal` (5) |
| `int32_t` (`ratify_v2_*`) | `RatifyV2ErrInternal` (-3, class `"internal"`) |
| an owned pointer (`char *`, handles) | `NULL` |
| `ratify_verify_result_is_valid`, `ratify_scope_has` | `0` |
| `ratify_scope_is_sensitive`, `ratify_revocation_list_contains` | `1` (fail closed) |
| `ratify_v2_abi_version`, `ratify_v2_protocol_version` | `0` (matches no header) |
| `ratify_v2_released_allowed`, `ratify_v2_challenge_time_current` | `0` (fail closed) |
| `ratify_v2_evaluator_call_expired` | `1` (stop evaluating) |
| `void` (`*_free`) | returns normally |

Before returning, the function puts every output parameter in a defined state:
handle and string outputs are set to `NULL`, fixed-size byte outputs (hashes,
challenges, seeds) are zeroed, caller string buffers start with NUL, and
`valid_out` flags are 0. Never use an output after a non-OK status. When the
function has an `err_out` parameter it receives the message
`internal error: a panic was caught at the C ABI boundary` (prefixed with
`internal: ` for `ratify_v2_*`).

A caught panic is a library bug or an unusable environment (for example no
entropy source); report it. The library stays usable for later calls, with
one exception: a panic inside a challenge store operation leaves that store
returning `RatifyErrInternal`, so free it and create a new one. Rust's default
panic hook still prints the panic message to stderr.

Release builds use `panic = "unwind"` so this containment works. If you
rebuild with `panic = "abort"`, any panic terminates the process instead.

---

## Revocation callback return values

| Return | Meaning |
|---|---|
| `1` | Cert is revoked; bundle rejected |
| `0` | Cert is not revoked; verification continues |
| `-1` | Lookup failed; fail-closed (bundle rejected with `identity_status=invalid`) |

---

## Identity status values

| `identity_status` | Meaning |
|---|---|
| `authorized_agent` | Valid: agent is authorized |
| `expired` | Delegation cert has expired |
| `revoked` | Cert was revoked (revocation callback or signed revocation list) |
| `scope_denied` | Required scope not in the effective delegation |
| `constraint_denied` | A constraint (geo, time, speed, amount, rate, resource path) was violated |
| `constraint_unverifiable` | Constraint present but no context to evaluate it |
| `constraint_unknown` | Unknown constraint type |
| `delegation_not_authorized` | A non-root issuer lacks `identity:delegate` (signing-authority violation) |
| `invalid_scope` | A cert grants a scope that is not canonical, not a wildcard, and not a `custom:` extension |
| `invalid` | Generic failure: tampered bundle, bad signature, a chain deeper than the depth ceiling (`error_reason` begins `chain_too_deep`), stale or unknown challenge, session/stream binding failure, or a revocation lookup error |

`verified_human` and `unauthorized` are part of the status vocabulary but are not
emitted by proof-bundle verification through this SDK.

---

## Conformance

The C SDK is validated against the same 79 canonical cross-language test
vectors as the Go, TypeScript, Python, and Rust SDKs.

```bash
cargo test
```

All canonical fixture kinds pass through the C ABI:

- Proof-bundle verification, constraints, session/stream binding, and revocation
- Scope expansion/validation, revocation list, revocation push, key rotation,
  session tokens, transaction receipts, and witness entries

0 skipped. Full conformance parity with Go, TypeScript, Python, and Rust.

---

## Testing

```bash
# Unit tests (all functions, null pointers, malformed JSON, round-trips; 44 tests)
cargo test --test api

# Advanced surface (session tokens, streaming, challenge store, receipts,
# revocation, witness/key-rotation, scopes, policy verdicts, context builders; 33 tests)
cargo test --test advanced

# Protocol input bounds (max scopes, constraints, lengths, JSON nesting, bundle bytes; 7 tests)
cargo test --test bounds

# Forged lengths and counts up to SIZE_MAX at the v1 boundary (v2: v2c_forged_lengths)
cargo test --test forged_lengths

# Conformance tests (79/79 fixtures)
cargo test --test conformance

# Panic containment: injected panics in v1 and v2 exports return the internal
# error with outputs reset, and every header export goes through the guard
cargo test --test panic_containment

# Protocol v2 ABI: every testvectors/v2 file through ratify_v2_* only,
# the corpus inventory, the SPEC-v2 class table, concurrency, handle
# poisoning, and a panic sweep over every v2 export
cargo test --test v2_abi --test v2_panic_sweep
cargo test --test 'v2c_*'

# The same ABI from a plain C program (objects, negatives, hedged, limits,
# verifier ordering, a C-store release lifecycle, cross-SDK fixtures);
# SANITIZE=1 adds AddressSanitizer and UndefinedBehaviorSanitizer
./scripts/test-v2-c-abi.sh
SANITIZE=1 ./scripts/test-v2-c-abi.sh

# Cross-architecture via QEMU (requires `cross`)
cross test --target aarch64-unknown-linux-gnu
cross test --target armv7-unknown-linux-gnueabihf

# AddressSanitizer (Linux only)
cc examples/verify_bundle.c -I include -L target/release \
   -lratify_c -lpthread -ldl -fsanitize=address -g \
   -o /tmp/ratify_asan && /tmp/ratify_asan
```

---

## License

Apache-2.0. See [LICENSE](https://github.com/identities-ai/ratify-protocol/blob/main/LICENSE).

Ratify Protocol™ is a trademark of Identities AI, Inc. Patent pending.
