#!/usr/bin/env bash
# The authoritative deterministic gate for the NVIDIA NOOA delegated-authority
# reference on Ratify Protocol v2.
#
#   PYTHON=/path/to/python3.12 ./demos/nvidia-nooa-delegated-authority/reference-check-v2.sh
#
# This script owns the environment rather than assuming it: a clean venv on a
# supported interpreter, exact pins, every optional integration required, and a
# failure on any skip and on any unexpected count. An ordinary pytest run once
# reported "91 passed, 1 skipped" and exited 0 while the whole MCP module had
# not run; there is no configuration here that passes with less.
#
# It does not run the live OpenShell profile. That needs a container runtime
# and the OpenShell CLI: see run-openshell-profile.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DEMO="demos/nvidia-nooa-delegated-authority"
cd "$ROOT"

NOOA_VERSION="${NOOA_VERSION:-0.0.8}"
MCP_VERSION="${MCP_VERSION:-2.0.0}"
UVICORN_VERSION="${UVICORN_VERSION:-0.52.1}"

# Expected counts, per module. Stated rather than derived: a count that is read
# from the run it is meant to check cannot detect a module that vanished.
EXPECT_RECEIVER="${EXPECT_RECEIVER:-64}"
EXPECT_TRANSPORT="${EXPECT_TRANSPORT:-40}"
EXPECT_ADJUDICATOR="${EXPECT_ADJUDICATOR:-84}"
EXPECT_NOOA="${EXPECT_NOOA:-4}"
EXPECT_TOTAL="${EXPECT_TOTAL:-192}"

PY="${PYTHON:-python3}"
"$PY" - <<'EOF'
import sys
if not ((3, 12) <= sys.version_info[:2] < (3, 14)):
    sys.exit(
        f"reference-check-v2 requires Python >=3.12,<3.14 (nooa's own floor "
        f"and ceiling); this is {sys.version.split()[0]}.\n"
        "Set PYTHON=/path/to/python3.12 and re-run."
    )
EOF

WORKDIR="$(mktemp -d)"
VENV="$WORKDIR/venv"
LOG="$WORKDIR/pytest.log"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==> venv ($("$PY" -V))"
"$PY" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip

# Where the Ratify v2 SDK comes from. `local` builds the native signing
# extension (ratify-protocol-native-v2, Rust, via maturin) and installs
# ratify-protocol with its protocol-v2 extra from this checkout: it proves the
# reference against the code in the tree. `published` installs the released packages and is what the
# final evidence must use.
#
# TODO(RATIFY_V2_PIN): switch the default to `published` once
# ratify-protocol and ratify-protocol-native-v2 2.0.0-beta.1 (PEP 440:
# 2.0.0b1) are on PyPI, and re-record the evidence from that run.
RATIFY_SDK="${RATIFY_SDK:-local}"
RATIFY_V2_VERSION="${RATIFY_V2_VERSION:-2.0.0b1}"  # TODO(RATIFY_V2_PIN)
case "$RATIFY_SDK" in
  local)
      "$VENV/bin/pip" install --quiet 'maturin>=1.7,<2'
      (cd sdks/python-native-v2 && "$VENV/bin/maturin" build --release --quiet --out "$WORKDIR/dist")
      "$VENV/bin/pip" install --quiet "$WORKDIR"/dist/*.whl
      "$VENV/bin/pip" install --quiet -e "./sdks/python[protocol-v2]" ;;
  published)
      "$VENV/bin/pip" install --quiet \
          "ratify-protocol[protocol-v2]==${RATIFY_V2_VERSION}" ;;
  *)  echo "RATIFY_SDK must be 'local' or 'published', got '$RATIFY_SDK'" >&2; exit 2 ;;
esac
"$VENV/bin/pip" install --quiet \
    pytest \
    "mcp==${MCP_VERSION}" \
    "uvicorn==${UVICORN_VERSION}" \
    "nooa==${NOOA_VERSION}"

echo "==> versions"
RATIFY_SDK="$RATIFY_SDK" "$VENV/bin/python" - <<'EOF'
import importlib.metadata as md
import os
import pathlib
import sys

print("  python                     ", sys.version.split()[0])
# Where ratify_protocol.v2 was actually imported from. An editable install
# resolves into the repository, a published one into site-packages, and the
# difference is the whole provenance claim.
import ratify_protocol.v2

module_path = pathlib.Path(ratify_protocol.v2.__file__).resolve()
inside_repo = pathlib.Path.cwd().resolve() in module_path.parents
print("  ratify_protocol.v2 module  ", module_path)
print("  ratify source              ", "repository checkout" if inside_repo else "installed package")
expected = os.environ.get("RATIFY_SDK", "local")
if expected == "published" and inside_repo:
    sys.exit(f"RATIFY_SDK=published but ratify_protocol.v2 resolved inside the repository at {module_path}")
if expected == "local" and not inside_repo:
    sys.exit(f"RATIFY_SDK=local but ratify_protocol.v2 resolved outside the repository at {module_path}")
if not ratify_protocol.v2.NATIVE_AVAILABLE:
    sys.exit("the native signing extension is not importable; v2 signing cannot run")

for dist in ("ratify-protocol", "ratify-protocol-native-v2", "mcp", "uvicorn", "nooa", "pytest"):
    try:
        print(f"  {dist:<27}", md.version(dist))
    except md.PackageNotFoundError:
        sys.exit(f"{dist} is not installed; the gate cannot run")
EOF

# Both integrations are mandatory here. The modules guard their imports so they
# can skip in general SDK environments; these variables turn that guard into a
# hard failure, which is the whole point of this script.
export RATIFY_REQUIRE_NOOA=1
export RATIFY_REQUIRE_MCP=1

echo "==> full reference suite (any skip is a failure)"
set +e
"$VENV/bin/python" -m pytest \
    "$DEMO/test_verification.py" \
    "$DEMO/test_mcp_transport.py" \
    "$DEMO/test_adjudicator.py" \
    "$DEMO/test_nooa_presentation.py" \
    -v -rs --strict-markers -p no:cacheprovider \
    --junit-xml "$WORKDIR/results.xml" | tee "$LOG"
STATUS="${PIPESTATUS[0]}"
set -e

fail() { echo "reference-check-v2: FAILED, $*" >&2; exit 1; }

[ "$STATUS" = "0" ] || fail "pytest exited $STATUS"
if grep -qE "^SKIPPED|[0-9]+ skipped" "$LOG"; then
    grep -E "^SKIPPED|skipped" "$LOG" | head -5 >&2
    fail "a test skipped"
fi
grep -qE "[0-9]+ (error|errors)" "$LOG" && fail "pytest reported collection errors"

# Counts come from pytest's JUnit XML, not from its console text.
read -r RECEIVER TRANSPORT ADJUDICATOR NOOA TOTAL SKIPPED FAILED <<<"$(
"$VENV/bin/python" - "$WORKDIR/results.xml" <<'COUNTPY'
import sys
import xml.etree.ElementTree as ET

per_file = {}
skipped = failed = 0
order = ["test_verification.py", "test_mcp_transport.py",
         "test_adjudicator.py", "test_nooa_presentation.py"]

for case in ET.parse(sys.argv[1]).getroot().iter("testcase"):
    where = f"{case.get('file') or ''} {case.get('classname') or ''}"
    module = next((name for name in order if name[:-3] in where), None)
    kinds = {child.tag for child in case}
    if "skipped" in kinds:
        skipped += 1
        continue
    if kinds & {"failure", "error"}:
        failed += 1
        continue
    if module is None:
        sys.exit(f"could not attribute a test to a module: {case.attrib}")
    per_file[module] = per_file.get(module, 0) + 1

counts = [per_file.get(name, 0) for name in order]
print(*counts, sum(counts), skipped, failed)
COUNTPY
)"

[ "${SKIPPED:-0}" = "0" ] || fail "$SKIPPED test(s) skipped"
[ "${FAILED:-0}" = "0" ] || fail "$FAILED test(s) failed or errored"

printf '  %-24s %s (expected %s)\n' "receiver security"  "$RECEIVER"    "$EXPECT_RECEIVER"
printf '  %-24s %s (expected %s)\n' "MCP transport"      "$TRANSPORT"   "$EXPECT_TRANSPORT"
printf '  %-24s %s (expected %s)\n' "adjudicator"        "$ADJUDICATOR" "$EXPECT_ADJUDICATOR"
printf '  %-24s %s (expected %s)\n' "NOOA integration"   "$NOOA"        "$EXPECT_NOOA"
printf '  %-24s %s (expected %s)\n' "total"              "$TOTAL"       "$EXPECT_TOTAL"

# Exact, not "at least". A module that grew silently is as much a drift signal
# as one that shrank, and the documented counts have to stay true.
[ "$RECEIVER"    = "$EXPECT_RECEIVER" ]    || fail "receiver security ran $RECEIVER, expected $EXPECT_RECEIVER"
[ "$TRANSPORT"   = "$EXPECT_TRANSPORT" ]   || fail "MCP transport ran $TRANSPORT, expected $EXPECT_TRANSPORT"
[ "$ADJUDICATOR" = "$EXPECT_ADJUDICATOR" ] || fail "adjudicator ran $ADJUDICATOR, expected $EXPECT_ADJUDICATOR"
[ "$NOOA"        = "$EXPECT_NOOA" ]        || fail "NOOA integration ran $NOOA, expected $EXPECT_NOOA"
[ "$TOTAL"       = "$EXPECT_TOTAL" ]       || fail "total ran $TOTAL, expected $EXPECT_TOTAL"

echo "==> narrated scenario (must run to completion)"
"$VENV/bin/python" "$DEMO/scenarios.py" > "$WORKDIR/scenarios.txt" \
    || { tail -20 "$WORKDIR/scenarios.txt" >&2; fail "scenarios.py exited non-zero"; }
grep -q "log verifies end to end: True" "$WORKDIR/scenarios.txt" \
    || fail "scenarios.py did not report a verifying receipt log"
grep -q "THIS IS A BUG" "$WORKDIR/scenarios.txt" && fail "scenarios.py reported a bug line"

echo
echo "reference-check-v2: ok ($TOTAL tests, zero skips, ratify-sdk=$RATIFY_SDK, nooa==$NOOA_VERSION, mcp==$MCP_VERSION)"
echo "Note: this gate does not run the live OpenShell profile, which needs a"
echo "container runtime and the OpenShell CLI: $DEMO/run-openshell-profile.sh"
