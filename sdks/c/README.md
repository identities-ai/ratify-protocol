# Ratify Protocol — C/C++ SDK

**C and C++ reference SDK for the Ratify Protocol v1 — a cryptographic trust protocol for human-agent and agent-agent interactions as agents start to transact.**

Quantum-safe by design: every signature is hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify.

Byte-identical interoperability with the Go, TypeScript, Python, and Rust reference implementations. Validated against the **59 canonical test vectors** on every CI run.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof — offline, without contacting a server — and get a cryptographically certain answer.

Beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), the SessionToken fast path (~95% less per-turn crypto — practical for live voice and video), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec, all covered by the 59 canonical fixtures.

- Full protocol spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.identities.ai](https://docs.identities.ai)

---

## Which SDK should I use?

| You're writing | Use |
|---|---|
| A Go service or CLI | [Go SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/go) |
| A Node.js or browser app | [TypeScript SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/typescript) |
| A Python script, ML pipeline, data tool | [Python SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/python) |
| A Rust service or high-performance binary | [Rust SDK](https://github.com/identities-ai/ratify-protocol/tree/main/sdks/rust) — use directly, no FFI overhead |
| **C or C++ code** | **This SDK** |
| **Firmware, RTOS, hardware driver** | **This SDK** (static library, `libratify_c.a`) |
| **A language that FFIs to C** (Swift, Zig, Julia, Lua, etc.) | **This SDK** |
| **Air-gapped embedded device** (no OS, no runtime) | **This SDK** (static library, no OS dependencies) |

The C SDK wraps the Rust SDK via a C ABI. If you're writing Rust, use the Rust SDK directly — the C SDK adds an FFI boundary with no benefit in a Rust context.

---

## Embedded deployment guide

### What "entropy" is and why it matters

**Entropy** = cryptographically unpredictable random bytes. The C SDK needs entropy for two
operations: generating challenge bytes (`ratify_challenge_generate`) and generating unique
cert IDs (`ratify_delegation_issue`). Without unpredictable entropy, challenges can be
replayed and certs can collide.

On standard OS targets (Linux, macOS, Windows, Raspberry Pi) entropy is automatic — the
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

**C application startup:**
```c
#include "ratify.h"

/* Provide random bytes from the STM32 hardware TRNG */
static int my_entropy(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t rnd;
        if (HAL_RNG_GenerateRandomNumber(&hrng, &rnd) != HAL_OK)
            return -1;  /* -1 means "entropy unavailable" → library panics */
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

The library **panics** (halts) if `ratify_set_entropy_source()` was never called when the
`custom-entropy` feature is enabled. This is intentional — generating certs with weak
randomness is worse than not running at all.

### Note on std requirement

The C SDK currently requires Rust's standard library (`std`) because `serde_json` — used
by the Ratify Protocol for JSON wire format — does not support `no_std`. This means the
library cannot link into bare-metal firmware with no heap at all. Targets supported:

| Target | Works? | Notes |
|---|---|---|
| Linux (any arch) | ✅ | Raspberry Pi, BeagleBone, embedded Linux SBCs |
| FreeRTOS + std shim | ✅ | Use `cargo-embassy` or `embedded-std` shim |
| Zephyr RTOS | ✅ | Zephyr's Rust support includes std |
| Bare-metal Cortex-M (no OS) | ❌ | No heap, no std — use Rust SDK directly |

For bare-metal Cortex-M with no OS, use the Rust SDK directly with `#[no_std]` + `alloc`.

## Supported targets

| Architecture | Target triple | Example hardware |
|---|---|---|
| x86-64 | `x86_64-unknown-linux-gnu` | Intel/AMD server, Linux PC |
| ARM64 | `aarch64-unknown-linux-gnu` | Raspberry Pi 4, embedded Linux, Apple Silicon |
| ARM32 | `armv7-unknown-linux-gnueabihf` | Raspberry Pi 2/3, older embedded Linux |
| ARM Cortex-M4/M7 | `thumbv7em-none-eabihf` | STM32, NXP — FreeRTOS, Zephyr |
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
#   target/release/libratify_c.a    — static library (embed in firmware)
#   target/release/libratify_c.so   — shared library (Linux)
#   target/release/libratify_c.dylib — shared library (macOS)
#   include/ratify.h                — C/C++ header (auto-generated, committed)
```

**Cross-compile with `cross`:**

```bash
cargo install cross --git https://github.com/cross-rs/cross

# ARM64 (Raspberry Pi 4, embedded Linux)
cross build --release --target aarch64-unknown-linux-gnu

# ARM32 (Raspberry Pi 2/3)
cross build --release --target armv7-unknown-linux-gnueabihf

# ARM Cortex-M4 bare metal (no OS)
rustup target add thumbv7em-none-eabihf
cargo build --release --target thumbv7em-none-eabihf

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

### Key generation (infallible)

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

// Delegate "physical:enter" to the agent; 0 = no expiry (signs as 2099-12-31)
ratify_delegation_issue(root, agent, "[\"physical:enter\"]", 0, &cert, &err);

char *cert_json = ratify_delegation_cert_to_json(cert, &err);
// Send cert_json to the agent over your transport layer
ratify_string_free(cert_json);
```

### Challenge and ProofBundle

```c
// Agent side: receive the cert JSON and a fresh challenge
uint8_t challenge[32];
ratify_challenge_generate(challenge);

RatifyProofBundle *bundle = NULL;
int64_t now = (int64_t)time(NULL);
ratify_proof_bundle_create(agent, cert_json, challenge, now, &bundle, &err);

char *bundle_json = ratify_proof_bundle_to_json(bundle, &err);
// Send bundle_json to the verifier
```

### Verification — simple path

```c
// Verifier side: just scope + clock — the common embedded path
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

### Verification — full options (revocation, geo constraints, session binding)

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

## Revocation callback return values

| Return | Meaning |
|---|---|
| `1` | Cert is revoked — bundle rejected |
| `0` | Cert is not revoked — verification continues |
| `-1` | Lookup failed — fail-closed (bundle rejected with `identity_status=invalid`) |

---

## Identity status values

| `identity_status` | Meaning |
|---|---|
| `authorized_agent` | Valid — agent is authorized |
| `expired` | Delegation cert has expired |
| `revoked` | Cert was revoked by the RevocationProvider |
| `scope_denied` | Required scope not in the effective delegation |
| `constraint_denied` | A constraint (geo, speed, amount) was violated |
| `constraint_unverifiable` | Constraint present but no context to evaluate it |
| `constraint_unknown` | Unknown constraint type |
| `delegation_not_authorized` | Chain depth / signing authority violation |
| `invalid` | Generic failure (tampered bundle, bad signature, lookup error) |
| `unauthorized` | Challenge freshness or session binding failure |

---

## Conformance

The C SDK is validated against the same 59 canonical cross-language test
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
# Unit tests (all functions, null pointers, malformed JSON, round-trips)
cargo test --test api

# Conformance tests (59/59 fixtures)
cargo test --test conformance

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

Apache-2.0 — see [LICENSE](https://github.com/identities-ai/ratify-protocol/blob/main/LICENSE).

Ratify Protocol™ is a trademark of Identities AI, Inc. Patent pending.
