#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible OpenShell + MCP + Ratify profile.
#
#   ./demos/nvidia-nooa-delegated-authority/run-openshell-profile.sh
#
# Brings up a pinned OpenShell v0.0.96 gateway on dynamic ports, renders the
# sandbox policy, starts the MCP receiver and its loopback control plane,
# drives every case group from inside an OpenShell sandbox, audits each log
# source for this run's canaries, writes a machine-readable artifact, and tears
# down exactly what it created.
#
# Exit code is the result: 0 if every required gate passed, non-zero otherwise.
#
# This is NOT part of the five-minute core claim. It needs Docker or Podman,
# pulls images, and takes minutes. The hermetic suites
# (test_verification.py, test_mcp_transport.py, test_nooa_presentation.py,
# test_adjudicator.py) remain the reproducible-in-one-command evidence.
#
# Everything with a bound lives in openshell_driver.py, because
# subprocess.run(timeout=) is portable and actually kills the child. GNU
# timeout is absent on a stock macOS, and `openshell sandbox exec --timeout`
# does not bound the CLI itself: with stdin inherited and not at EOF it blocks
# forever before the remote timeout is armed. This script keeps only the
# operations that must happen before the driver exists.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# --- pins -------------------------------------------------------------------
# The YAML cannot pin anything; these lines are the pin. Digests are multi-arch
# index digests, so one value covers linux/amd64 and linux/arm64. The resolved
# platform digest for the architecture actually executed is recorded in the
# artifact alongside the index digest.
OPENSHELL_CLI_VERSION="0.0.96"
GATEWAY_IMAGE="ghcr.io/nvidia/openshell/gateway@sha256:329adb1784989705a33c51f81df22eca33e2dc527675642364f013c5b8b79a67"
SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
SUPERVISOR_IMAGE="ghcr.io/nvidia/openshell/supervisor@sha256:523e0565f8957362d8f3c70c6ef7a221d92b10f32b96fbc76821febfb01bae8e"
UVICORN_PIN="uvicorn==0.52.1"
MCP_PIN="mcp==2.0.0"

RUN_ID="ratify-osp-$(date +%s)-$$"
# OpenShell caps sandbox names at 19 characters, so the sandbox gets a short
# derivative rather than the full run id.
SB_NAME="rat-$(date +%s | tail -c 7)-$$"
SB_NAME="${SB_NAME:0:18}"
# The gateway's data home is a bind mount whose host path and container path
# must be identical: the gateway extracts the supervisor binary there and then
# bind-mounts it into each sandbox container by *host* path. A named volume
# cannot serve that, because the host path would not exist. Per-run rather than
# the shared /var/lib/openshell, so two concurrent runs share no state.
OSHOME="/var/lib/openshell-$RUN_ID"
SB_DIR="/sandbox/ratify-profile"

# The work dir holds bind-mount sources for the gateway container, so it must
# be on a path the container runtime can see. On macOS with Colima or Lima the
# VM shares $HOME but not $TMPDIR (/var/folders/...), and a bind mount from an
# unshared path silently becomes an empty directory inside the container, which
# the gateway reports as "config file is a directory". Defaulting under $HOME
# avoids that; override with OPENSHELL_PROFILE_WORK.
WORK_ROOT="${OPENSHELL_PROFILE_WORK:-$HOME/.ratify-openshell-profile}"
mkdir -p "$WORK_ROOT"
WORK="$(mktemp -d "$WORK_ROOT/${RUN_ID}.XXXXXX")"
mkdir -p "$WORK/logs" "$WORK/gw/jwt"
ART="$WORK/artifact.json"
PYBIN="${PYTHON:-python3}"

freeport() {
  "$PYBIN" -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

note() { printf '  %s\n' "$*"; }

# --- gateway bootstrap lock --------------------------------------------------
# OpenShell v0.0.96 creates its supervisor-extraction container under a FIXED
# name, "openshell-supervisor-extract-1-0". Two gateways starting concurrently
# against the same container runtime therefore collide:
#
#   failed to create extractor container ...: Docker responded with status code
#   409: Conflict. The container name "/openshell-supervisor-extract-1-0" is
#   already in use
#
# That is an upstream constraint, not something this profile can configure
# away, and it is recorded as a finding rather than worked around silently.
# The accommodation is narrow: only the bootstrap is serialized, and only until
# the gateway reports ready. Everything the profile actually measures still runs
# concurrently, and each run keeps its own ports, data home, network, sandbox,
# and artifact.
GW_LOCK="${TMPDIR:-/tmp}/ratify-openshell-gateway-bootstrap.lock"
BOOTSTRAP_HELD=0
acquire_bootstrap_lock() {
  local waited=0
  while ! mkdir "$GW_LOCK" 2>/dev/null; do
    # Break a lock whose owner is gone, so a killed run cannot wedge the next.
    local owner
    owner="$(cat "$GW_LOCK/pid" 2>/dev/null || true)"
    if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
      note "clearing stale gateway bootstrap lock from pid $owner"
      rm -rf "$GW_LOCK"
      continue
    fi
    sleep 1
    waited=$((waited + 1))
    [ "$waited" -gt 300 ] && fail_now "timed out waiting for the gateway bootstrap lock"
  done
  printf '%s' "$$" > "$GW_LOCK/pid"
  BOOTSTRAP_HELD=1
}
release_bootstrap_lock() {
  [ "${BOOTSTRAP_HELD:-0}" = "1" ] || return 0
  rm -rf "$GW_LOCK"
  BOOTSTRAP_HELD=0
}
fail_now() { echo "openshell-profile: FAIL ($*)" >&2; exit 2; }

cleanup() {
  set +e
  set +u  # cleanup may run before every variable is assigned
  note "tearing down ${RUN_ID:-unknown}"
  release_bootstrap_lock
  [ -n "${MCP_PID:-}" ] && kill "$MCP_PID" 2>/dev/null

  # Log capture is the driver's job and has already happened by this point:
  # the canary audit has to read those files, so collecting them at teardown
  # would be too late.
  CLEANUP_OK=1
  if [ -n "${OS:-}" ] && [ -n "${GW_EP:-}" ]; then
    "$OS" --gateway-endpoint "$GW_EP" sandbox delete "$SB_NAME" >/dev/null 2>&1
  fi
  # Any sandbox container this run's gateway created, and nothing else. Named
  # by this run's sandbox, so a concurrent run's containers are untouched.
  for c in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -- "--${SB_NAME:-__none__}-"); do
    docker rm -f "$c" >/dev/null 2>&1 || CLEANUP_OK=0
  done
  if [ -n "${GW_UP:-}" ] && [ -d "${WORK:-/nonexistent}/gw" ]; then
    ( cd "$WORK/gw" && docker compose -p "$RUN_ID" down -v >/dev/null 2>&1 ) || CLEANUP_OK=0
  fi
  # The per-run data home lives inside the container runtime's filesystem, so
  # it is removed by a throwaway container mounting only its parent. Exactly
  # this run's directory, by name. No prune, no wildcard.
  if [ -n "${OSHOME:-}" ]; then
    docker run --rm --user 0 --entrypoint /bin/sh \
      -v /var/lib:/hostvarlib "$SANDBOX_IMAGE" \
      -c "rm -rf /hostvarlib/openshell-${RUN_ID}" >/dev/null 2>&1 || CLEANUP_OK=0
  fi

  LEFTOVER="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -c -- "${RUN_ID}\|--${SB_NAME:-__none__}-")"
  note "cleanup: containers left=${LEFTOVER:-?} ok=${CLEANUP_OK}"
  # The NOOA sandbox image is deliberately retained. Its tag is a content hash
  # of the dependency tree, so it is shared by every run with the same
  # dependency set and by any concurrent run in flight; deleting it here would
  # force a rebuild each time and could pull it out from under a neighbour.
  # Remove it by hand when finished:  docker image rm ${NOOA_IMAGE:-<tag>}
  [ -n "${NOOA_IMAGE:-}" ] && note "retained build image: $NOOA_IMAGE"

  if [ "${KEEP_WORK:-0}" = "1" ]; then
    note "work dir kept: $WORK"
  else
    # Ephemeral JWT signing key, rendered policy, downloaded results, and the
    # proof fragments the log audit searched for all live here.
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

echo "OpenShell profile  run=$RUN_ID"
echo "  work dir: $WORK"

# --- 1. prerequisites -------------------------------------------------------
command -v docker >/dev/null || fail_now "docker not found"
docker info >/dev/null 2>&1 || fail_now "docker daemon not reachable"
command -v openssl >/dev/null || fail_now "openssl not found"

OS="$(command -v openshell || true)"
if [ -z "$OS" ] && [ -x "$HOME/.local/bin/openshell" ]; then OS="$HOME/.local/bin/openshell"; fi
[ -n "$OS" ] || fail_now "openshell CLI not found; install: uv tool install openshell==$OPENSHELL_CLI_VERSION"
CLI_V="$("$OS" --version 2>/dev/null | awk '{print $2}')"
[ "$CLI_V" = "$OPENSHELL_CLI_VERSION" ] || fail_now "openshell CLI is $CLI_V, this profile pins $OPENSHELL_CLI_VERSION"
note "openshell CLI $CLI_V"

VENV="$WORK/venv"
"$PYBIN" -m venv "$VENV" >/dev/null
"$VENV/bin/pip" -q install -e "$REPO/sdks/python" "$MCP_PIN" "$UVICORN_PIN" >/dev/null 2>&1
note "receiver venv ready ($MCP_PIN, $UVICORN_PIN)"

# --- 2. dynamic ports -------------------------------------------------------
GW_PORT="$(freeport)"; GW_HEALTH="$(freeport)"; MCP_PORT="$(freeport)"; CTRL_PORT="$(freeport)"
MCP_HOST="host.openshell.internal"
note "ports: gateway=$GW_PORT health=$GW_HEALTH mcp=$MCP_PORT control=$CTRL_PORT"

# --- 2b. NOOA sandbox image -------------------------------------------------
# The unified path needs nooa==0.0.8 running *inside* the OpenShell-governed
# sandbox, and the sandbox has no egress once its policy is active, so the
# dependencies must exist before the test starts.
#
# Delivery through the released `openshell sandbox upload` was tried first and
# does not hold at this size. One 63-76 MB transfer failed with "error reading a
# body from connection ... broken pipe"; splitting it into 8 MB chunks still
# failed intermittently across several runs. So the tree is baked into an image
# built FROM the pinned base by digest, which removes every runtime transfer.
# Every other group in this profile still runs on the unmodified base image.
#
# No custom interpreter is needed: /usr/bin/python3 in the pinned base is
# CPython 3.12.3, inside nooa's >=3.12,<3.14 range. The default `python3` on
# PATH is 3.14 from a uv venv and cannot run nooa, which is why every exec here
# names the interpreter by absolute path.
DEPS_DIR="$WORK/deps"
mkdir -p "$DEPS_DIR"
# Installed from the committed, hash-pinned lock rather than resolved here. Naming
# only nooa, mcp and uvicorn left all 70-odd transitive dependencies floating:
# `packaging` moved 26.2 -> 26.3 between two runs an hour apart, changing the
# staged tree's content hash and the image tag with it. The lock is regenerated
# deliberately by ./stage-lock.sh, never as a side effect of a run.
LOCK="$HERE/sandbox-requirements.lock"
[ -f "$LOCK" ] || fail_now "sandbox-requirements.lock is missing; run ./stage-lock.sh"
LOCK_SHA="$("$PYBIN" -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$LOCK")"
note "dependency lock sha256=$LOCK_SHA"
if ! docker run --rm --user 0 --entrypoint /bin/sh \
  -v "$REPO/sdks/python:/src:ro" -v "$DEPS_DIR:/out" -v "$LOCK:/lock:ro" "$SANDBOX_IMAGE" \
  -c 'set -e
export UV_PYTHON_DOWNLOADS=never
# A writable copy: building the sdist writes egg-info, which a read-only mount
# refuses.
cp -r /src /build && rm -rf /build/*.egg-info /build/src/*.egg-info
# --require-hashes makes every distribution hash-verified and refuses any
# dependency the lock does not name. --no-deps on the SDK keeps it from pulling an
# unlocked transitive tree of its own; its runtime requirements are in the lock.
uv pip install -q --python /usr/bin/python3 --target /out/site \
  --require-hashes -r /lock
uv pip install -q --python /usr/bin/python3 --target /out/site --no-deps /build
find /out/site -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
# uv writes its own install bookkeeping into each dist-info. It has no runtime
# purpose, and for the locally built SDK wheel its length varies between builds,
# which was the *only* difference between two otherwise byte-identical staged
# trees (7983 files) and was enough to change the tree hash and the image tag.
find /out/site -name uv_cache.json -delete 2>/dev/null || true
# Ratify signs; it never encapsulates a key. pqcrypto ships every KEM as a
# separate compiled module, 39 MB of them, none reachable from this path.
rm -rf /out/site/pqcrypto/_kem /out/site/pqcrypto/kem
PYTHONPATH=/out/site /usr/bin/python3 -c "import nooa, mcp, ratify_protocol"
' > "$WORK/stage-deps.log" 2>&1; then
  tail -15 "$WORK/stage-deps.log"; fail_now "could not stage NOOA dependencies"
fi

DEPS_SHA="$("$PYBIN" "$HERE/stage-hash.py" "$DEPS_DIR/site")"
NOOA_IMAGE="ratify-nooa-sandbox:${DEPS_SHA:0:16}"
cp "$HERE/Dockerfile.nooa-sandbox" "$DEPS_DIR/Dockerfile"
if ! ( cd "$DEPS_DIR" && docker build --quiet \
        --build-arg "SANDBOX_BASE=$SANDBOX_IMAGE" -t "$NOOA_IMAGE" . ) \
      > "$WORK/image-build.log" 2>&1; then
  tail -15 "$WORK/image-build.log"; fail_now "could not build the NOOA sandbox image"
fi
NOOA_IMAGE_ID="$(docker image inspect "$NOOA_IMAGE" --format '{{.Id}}' 2>/dev/null)"

# Confirm nooa imports in the built image, before the policy is anywhere near
# it. A failure here is a build problem, and it must never be mistaken later for
# a policy result.
cp "$HERE/image-deps-check.py" "$WORK/image-deps-check.py"
docker run --rm --user 0 --entrypoint /usr/bin/python3 \
  -e PYTHONPATH=/opt/ratify-nooa/site -e LITELLM_LOCAL_MODEL_COST_MAP=True \
  -v "$WORK/image-deps-check.py:/check.py:ro" "$NOOA_IMAGE" /check.py \
  > "$WORK/image-deps.txt" 2>&1 || true
grep -q IMAGE_DEPS_OK "$WORK/image-deps.txt" || {
  tail -6 "$WORK/image-deps.txt"; fail_now "NOOA is not importable in the built image"
}
note "NOOA sandbox image $NOOA_IMAGE"
note "image deps: $(grep -o 'IMAGE_DEPS_OK.*' "$WORK/image-deps.txt")"

# --- 3. render config safely ------------------------------------------------
openssl genpkey -algorithm ed25519 -out "$WORK/gw/jwt/signing.pem" 2>/dev/null
openssl pkey -in "$WORK/gw/jwt/signing.pem" -pubout -out "$WORK/gw/jwt/public.pem" 2>/dev/null
printf '%s' "$RUN_ID" > "$WORK/gw/jwt/kid"
# A signing key is never world-readable, ephemeral or not.
chmod 700 "$WORK" "$WORK/gw" "$WORK/gw/jwt"
chmod 600 "$WORK/gw/jwt/signing.pem"
chmod 644 "$WORK/gw/jwt/public.pem" "$WORK/gw/jwt/kid"
ACTUAL_MODE="$(stat -f '%Lp' "$WORK/gw/jwt/signing.pem" 2>/dev/null || stat -c '%a' "$WORK/gw/jwt/signing.pem")"
[ "$ACTUAL_MODE" = "600" ] || fail_now "signing key mode is $ACTUAL_MODE, expected 600"

sed -e "s|@@MCP_HOST@@|$MCP_HOST|g" -e "s|@@MCP_PORT@@|$MCP_PORT|g" \
  "$HERE/openshell-policy.yaml.in" > "$WORK/policy.yaml"
grep -q '@@' "$WORK/policy.yaml" && fail_now "unresolved placeholder in rendered policy"
sha256_of() { "$PYBIN" -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1"; }
POLICY_SHA="$(sha256_of "$WORK/policy.yaml")"
note "policy rendered  sha256=$POLICY_SHA"

# The sandbox image the gateway creates sandboxes from is the NOOA image,
# which is the pinned base plus the dependency tree and nothing else.
sed -e "s|@@JWT_DIR@@|/etc/openshell/jwt|g" -e "s|@@SANDBOX_IMAGE@@|$NOOA_IMAGE|g" \
    -e "s|@@SUPERVISOR_IMAGE@@|$SUPERVISOR_IMAGE|g" -e "s|@@RUN_ID@@|$RUN_ID|g" \
    -e "s|@@OSHOME@@|$OSHOME|g" -e "s|@@GW_PORT@@|$GW_PORT|g" \
    -e "s|@@GW_HEALTH@@|$GW_HEALTH|g" \
  "$HERE/openshell-gateway.toml.in" > "$WORK/gw/gateway.toml"
grep -q '@@' "$WORK/gw/gateway.toml" && fail_now "unresolved placeholder in gateway.toml"
GATEWAY_SHA="$(sha256_of "$WORK/gw/gateway.toml")"

# The gateway image's default command is ["--bind-address","0.0.0.0","--port",
# "8080"], and CLI flags take precedence over the config file. The port has to
# be overridden here, not in the TOML, and it has to be the same inside the
# container as outside: the gateway derives the endpoint it hands each sandbox
# (OPENSHELL_ENDPOINT) from its own bind port, so a container port of 8080
# published on a dynamic host port leaves every sandbox dialling the wrong one
# and failing to fetch its policy.
cat > "$WORK/gw/docker-compose.yml" <<COMPOSE
services:
  gateway:
    image: $GATEWAY_IMAGE
    container_name: $RUN_ID-gateway
    command: ["--bind-address", "0.0.0.0", "--port", "$GW_PORT", "--health-port", "$GW_HEALTH"]
    user: "0"
    ports:
      - "127.0.0.1:$GW_PORT:$GW_PORT"
      - "127.0.0.1:$GW_HEALTH:$GW_HEALTH"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - type: bind
        source: $OSHOME
        target: $OSHOME
        bind: { create_host_path: true }
      - type: bind
        source: ./gateway.toml
        target: /etc/openshell/gateway.toml
        read_only: true
      - type: bind
        source: ./jwt
        target: /etc/openshell/jwt
        read_only: true
    environment:
      OPENSHELL_GATEWAY_CONFIG: /etc/openshell/gateway.toml
      OPENSHELL_DB_URL: "sqlite:$OSHOME/gateway.db?mode=rwc"
      XDG_DATA_HOME: $OSHOME
      HOME: $OSHOME
COMPOSE

# --- 4. gateway -------------------------------------------------------------
acquire_bootstrap_lock
GW_UP=1
if ! ( cd "$WORK/gw" && docker compose -p "$RUN_ID" up -d > "$WORK/compose.log" 2>&1 ); then
  release_bootstrap_lock
  sed -n '1,20p' "$WORK/compose.log"; fail_now "gateway failed to start"
fi
# No `gateway add`. That command writes to the CLI's shared gateway registry,
# and two concurrent runs racing on it lost one registration outright: the
# second run's gateway never resolved and the profile failed before it started.
# Every command addresses the gateway by endpoint instead, so this run touches
# no shared CLI state and leaves no registration to clean up.
GW_EP="http://localhost:$GW_PORT"
GW_V=""
for _ in $(seq 1 90); do
  # `openshell status` colourises its output; ANSI escapes contain digits
  # (\033[32m), so they must be stripped before the version is parsed.
  GW_V="$("$OS" --gateway-endpoint "$GW_EP" status 2>/dev/null \
    | sed -e $'s/\033\[[0-9;]*m//g' \
    | sed -n 's/.*Version:[[:space:]]*\([0-9][0-9.]*\).*/\1/p' | head -1 || true)"
  [ -n "$GW_V" ] && break
  sleep 1
done
if [ "$GW_V" != "$OPENSHELL_CLI_VERSION" ]; then
  release_bootstrap_lock
  echo "--- gateway container log:"; docker logs "$RUN_ID-gateway" 2>&1 | tail -25
  echo "--- compose log:"; tail -15 "$WORK/compose.log"
  fail_now "gateway reported '${GW_V:-nothing}', expected $OPENSHELL_CLI_VERSION"
fi
release_bootstrap_lock
note "gateway $GW_V on :$GW_PORT"

# --- 5. sandbox -------------------------------------------------------------
# The working directory is under /sandbox because `sandbox download` refuses
# any source outside the sandbox workspace, and the profile downloads every
# case result rather than trusting stdout alone.
# Resources are stated, not defaulted. Importing nooa pulls litellm, openai,
# tokenizers and tiktoken, which is a heavy import; under the default allocation
# the sandbox died mid-import and the exec relay closed with a broken pipe,
# after which the sandbox fell back to Provisioning and every later case
# produced no result. The failure looked like a transport fault and was a
# resource one, which is exactly the sort of thing worth stating explicitly.
"$OS" --gateway-endpoint "$GW_EP" sandbox create --name "$SB_NAME" --policy "$WORK/policy.yaml" \
  --memory "${SANDBOX_MEMORY:-6Gi}" --cpu "${SANDBOX_CPU:-2}" \
  -- /bin/sh -c "echo READY" \
  > "$WORK/create.txt" 2>&1 </dev/null || true
grep -q READY "$WORK/create.txt" || {
  tail -5 "$WORK/create.txt"; fail_now "sandbox creation failed"
}

# The working directory is made by a separate exec, not by the create-time
# command. Filesystem state from the create command does not survive into the
# running sandbox, so the directory would not exist when the first upload
# arrives, and `sandbox upload` materialises a missing destination path as
# directories: client.py became a *directory* and every exec died with
# "can't find '__main__' module".
"$OS" --gateway-endpoint "$GW_EP" sandbox exec --no-tty -n "$SB_NAME" -- \
  /bin/sh -c "mkdir -p $SB_DIR && chmod 700 $SB_DIR && test -d $SB_DIR && echo DIROK" \
  > "$WORK/mkdir.txt" 2>&1 </dev/null || true
grep -q DIROK "$WORK/mkdir.txt" || {
  tail -5 "$WORK/mkdir.txt"; fail_now "sandbox working directory was not created"
}
note "sandbox $SB_NAME  dir $SB_DIR (0700)"

# `sandbox upload` places the local file *inside* the destination when the
# local basename differs from the destination basename, so uploading
# openshell_client.py to .../client.py produced a client.py *directory*
# containing openshell_client.py, and every exec then died with
# "can't find '__main__' module". The local copy is therefore named exactly as
# it must appear in the sandbox. The assertion below is what caught this and
# stays as the regression.
cp "$HERE/openshell_client.py" "$WORK/client.py"
"$OS" --gateway-endpoint "$GW_EP" sandbox upload "$SB_NAME" "$WORK/client.py" \
  "$SB_DIR/client.py" > "$WORK/upload-client.txt" 2>&1 </dev/null || true
# Assert it landed as a regular file. An upload that quietly produced a
# directory is the failure this check exists for.
"$OS" --gateway-endpoint "$GW_EP" sandbox exec --no-tty -n "$SB_NAME" -- \
  /bin/sh -c "chmod 0500 $SB_DIR/client.py && test -f $SB_DIR/client.py && echo CLIENTOK" \
  > "$WORK/client-perm.txt" 2>&1 </dev/null || true
grep -q CLIENTOK "$WORK/client-perm.txt" || {
  echo "--- upload output:"; cat "$WORK/upload-client.txt"
  echo "--- perm check output:"; cat "$WORK/client-perm.txt"
  echo "--- sandbox listing:"
  "$OS" --gateway-endpoint "$GW_EP" sandbox exec --no-tty -n "$SB_NAME" -- \
    /bin/sh -c "ls -la $SB_DIR; ls -la $SB_DIR/client.py 2>&1 | head -5" 2>&1 </dev/null | tail -12
  fail_now "client.py did not upload as a regular file"
}

# --- 5b. upload the unified-path modules ------------------------------------
# Kilobytes, not megabytes, so the released upload path is entirely adequate
# here. Local names match remote names, because `sandbox upload` resolves its
# destination by basename.
for f in nooa_adapter.py mcp_refund_client.py nooa_openshell_client.py; do
  cp "$HERE/$f" "$WORK/$f"
  "$OS" --gateway-endpoint "$GW_EP" sandbox upload "$SB_NAME" "$WORK/$f" \
    "$SB_DIR/$f" >/dev/null 2>&1 </dev/null
done

if [ "${OPENSHELL_PROBE_OPT:-0}" = "1" ]; then
  echo "--- rendered default_image: $(grep default_image "$WORK/gw/gateway.toml")"
  echo "--- sandbox container image:"
  for c in $(docker ps -a --format '{{.Names}}' | grep -- "--${SB_NAME}-"); do
    docker inspect "$c" --format '    {{.Name}} -> {{.Config.Image}}'
  done
  "$OS" --gateway-endpoint "$GW_EP" sandbox exec --no-tty -n "$SB_NAME" -- \
    /usr/bin/python3 -c "
import pathlib, sys
for p in ('/opt', '/opt/ratify-nooa', '/opt/ratify-nooa/site'):
    print(p, 'is_dir=', pathlib.Path(p).is_dir())
try:
    print('opt listing:', sorted(x.name for x in pathlib.Path('/opt').iterdir())[:6])
except Exception as e:
    print('opt listing failed:', type(e).__name__, e)
sys.path.insert(0, '/opt/ratify-nooa/site')
try:
    import ratify_protocol; print('ratify ok', ratify_protocol.__version__)
except Exception as e:
    print('import failed:', type(e).__name__, e)
" 2>&1 </dev/null | tail -12
fi

# --- 6. receiver, on the narrowest interface the sandbox can actually reach --
# A loopback-only bind is not reachable from a container through
# host.openshell.internal, which resolves to host-gateway. Rather than assume
# which interface works on a given runtime, each candidate is bound in turn and
# the sandbox is asked to complete an MCP initialize against it. The first one
# the sandbox can genuinely reach is used, and which one that was is recorded
# in the artifact. Nothing is claimed about interfaces that were not executed.
MCP_BIND=""
for candidate in "127.0.0.1" "0.0.0.0"; do
  rm -f "$WORK/ready.json"
  "$VENV/bin/python" "$HERE/openshell_probe.py" --run-id "$RUN_ID" \
    --mcp-port "$MCP_PORT" --ctrl-port "$CTRL_PORT" --mcp-bind "$candidate" \
    --mcp-host "$MCP_HOST" --ready-file "$WORK/ready.json" \
    >> "$WORK/logs/receiver.log" 2>&1 &
  MCP_PID=$!
  for _ in $(seq 1 60); do [ -f "$WORK/ready.json" ] && break; sleep 0.5; done
  if [ ! -f "$WORK/ready.json" ]; then
    kill "$MCP_PID" 2>/dev/null
    note "receiver could not bind $candidate"
    continue
  fi
  "$OS" --gateway-endpoint "$GW_EP" sandbox exec --no-tty -n "$SB_NAME" -- \
    /usr/bin/python3 -c "
import json, urllib.request
body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
    'protocolVersion': '2026-07-28', 'capabilities': {},
    'clientInfo': {'name': 'reachability', 'version': '1'}}}).encode()
req = urllib.request.Request('http://$MCP_HOST:$MCP_PORT/mcp', data=body, method='POST',
    headers={'Content-Type': 'application/json',
             'Accept': 'application/json, text/event-stream',
             'mcp-method': 'initialize'})
try:
    print('REACHABLE' if urllib.request.urlopen(req, timeout=10).status == 200 else 'UNREACHABLE')
except Exception as exc:
    print('UNREACHABLE', type(exc).__name__, str(exc)[:80])
" > "$WORK/reach-$candidate.txt" 2>&1 </dev/null || true
  if grep -q REACHABLE "$WORK/reach-$candidate.txt"; then
    MCP_BIND="$candidate"
    break
  fi
  note "sandbox cannot reach receiver on $candidate: $(tail -1 "$WORK/reach-$candidate.txt")"
  kill "$MCP_PID" 2>/dev/null
  wait "$MCP_PID" 2>/dev/null || true
done
[ -n "$MCP_BIND" ] || fail_now "no candidate receiver interface was reachable from the sandbox"
note "receiver on $MCP_BIND:$MCP_PORT (verified from the sandbox); control plane on 127.0.0.1:$CTRL_PORT"

# --- 7. environment facts for the artifact ----------------------------------
ARCH="$(uname -m)"
resolve_digest() {
  docker image inspect "$1" --format '{{index .RepoDigests 0}}' 2>/dev/null \
    | sed 's/.*@//' || echo "unresolved"
}
"$PYBIN" - "$WORK/env.json" <<ENVJSON
import json, platform, subprocess, sys

def cmd(*argv):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return "unavailable"

json.dump({
    "run_id": "$RUN_ID",
    "components": {
        "openshell_cli": "$CLI_V",
        "gateway_image": "$GATEWAY_IMAGE",
        "sandbox_image": "$SANDBOX_IMAGE",
        "supervisor_image": "$SUPERVISOR_IMAGE",
        "gateway_resolved_digest": "$(resolve_digest "$GATEWAY_IMAGE")",
        "sandbox_resolved_digest": "$(resolve_digest "$SANDBOX_IMAGE")",
        "supervisor_resolved_digest": "$(resolve_digest "$SUPERVISOR_IMAGE")",
        "mcp": "2.0.0",
        "uvicorn": "0.52.1",
        "mcp_protocol": "2026-07-28",
        "sandbox_python": "/usr/bin/python3 (CPython 3.12.3, from the pinned sandbox image)",
        "nooa": "0.0.8",
        "nooa_sandbox_image": "$NOOA_IMAGE",
        "nooa_sandbox_image_id": "$NOOA_IMAGE_ID",
        "nooa_sandbox_image_provenance": "built locally from the pinned base by digest; "
                                         "not published to any registry",
        "staged_deps_content_sha256": "$DEPS_SHA",
        "dependency_lock_sha256": "$LOCK_SHA",
        "dependency_lock": "demos/nvidia-nooa-delegated-authority/sandbox-requirements.lock",
    },
    "platform": {
        "executed_on": {"os": platform.system(), "release": platform.release(),
                        "arch": "$ARCH", "python": platform.python_version()},
        "container_runtime": cmd("docker", "version", "--format", "{{.Server.Version}}"),
        "compatibility_targets_not_executed": ["linux/amd64"],
    },
    "ports": {"gateway": $GW_PORT, "gateway_health": $GW_HEALTH,
              "mcp": $MCP_PORT, "control": $CTRL_PORT},
    "hashes": {"rendered_policy_sha256": "$POLICY_SHA",
               "gateway_config_sha256": "$GATEWAY_SHA"},
    "network": {"mcp_bind": "$MCP_BIND", "mcp_host": "$MCP_HOST",
                "control_bind": "127.0.0.1",
                "control_in_policy": False},
    "concurrency": {
        "gateway_bootstrap_serialized": True,
        "reason": "OpenShell v0.0.96 names its supervisor-extraction container "
                  "openshell-supervisor-extract-1-0, a fixed name, so two gateways "
                  "bootstrapping concurrently against one container runtime collide "
                  "with a Docker 409. Only bootstrap is serialized; the measured "
                  "matrix runs concurrently.",
        "per_run_isolated": ["ports", "data_home", "compose_project", "network",
                             "sandbox", "work_dir", "artifact"],
        "shared_cli_registry_used": False,
    },
}, open(sys.argv[1], "w"), indent=2)
ENVJSON

# --- 8. drive the matrix ----------------------------------------------------
"$VENV/bin/python" "$HERE/openshell_driver.py" \
  --work "$WORK" --openshell "$OS" --gateway-endpoint "$GW_EP" \
  --sandbox "$SB_NAME" --sandbox-dir "$SB_DIR" \
  --mcp-host "$MCP_HOST" --mcp-port "$MCP_PORT" --ctrl-port "$CTRL_PORT" \
  --env-json "$WORK/env.json" --artifact "$ART" \
  --run-id "$RUN_ID" --gateway-dir "$WORK/gw" && DRIVER=0 || DRIVER=1

if [ -f "$ART" ]; then
  DEST="${OPENSHELL_ARTIFACT:-$REPO/openshell-profile-$RUN_ID.json}"
  cp "$ART" "$DEST"
  note "artifact: $DEST"
fi

if [ "$DRIVER" = "0" ]; then echo; echo "openshell-profile: PASS"; exit 0; fi
echo; echo "openshell-profile: FAIL"; exit 1
