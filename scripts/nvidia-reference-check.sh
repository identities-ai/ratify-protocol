#!/usr/bin/env bash
# The authoritative gate for the NVIDIA NOOA delegated-authority reference.
#
#   ./scripts/nvidia-reference-check.sh
#
# This exists because the obvious command lies. Running the three hermetic
# modules with an ordinary pytest invocation on Python 3.11 produces:
#
#     91 passed, 1 skipped
#
# and exits 0. The entire 34-test MCP transport module had skipped, because
# `mcp` was not installed and the module guards its import. A gate that reports
# success while a third of it did not run is worse than no gate: it converts a
# missing dependency into a green tick.
#
# So this script owns the environment rather than assuming it. It builds a
# clean venv on a supported interpreter, installs exact pins, requires every
# optional integration to be present, and fails on any skip and on any
# unexpected count. There is no configuration that makes it pass with less.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="demos/nvidia-nooa-delegated-authority"
cd "$ROOT"

NOOA_VERSION="${NOOA_VERSION:-0.0.8}"
MCP_VERSION="${MCP_VERSION:-2.0.0}"
UVICORN_VERSION="${UVICORN_VERSION:-0.52.1}"

# Expected counts, per module. Stated rather than derived: a count that is read
# from the run it is meant to check cannot detect a module that vanished.
EXPECT_RECEIVER="${EXPECT_RECEIVER:-54}"
EXPECT_TRANSPORT="${EXPECT_TRANSPORT:-39}"
EXPECT_ADJUDICATOR="${EXPECT_ADJUDICATOR:-84}"
EXPECT_NOOA="${EXPECT_NOOA:-4}"
EXPECT_TOTAL="${EXPECT_TOTAL:-181}"

PY="${PYTHON:-python3}"
"$PY" - <<'EOF'
import sys
if not ((3, 12) <= sys.version_info[:2] < (3, 14)):
    sys.exit(
        f"nvidia-reference-check requires Python >=3.12,<3.14 (nooa's own floor "
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

# Where the Ratify SDK comes from. `local` installs this checkout and is correct
# for development and for every pre-release run: it is what proves the reference
# against the code in the tree. `published` installs the release artifact and is
# what the *final* evidence must use, because otherwise the evidence proves the
# checkout rather than the package a reader will install.
#
# RELEASE GATE: switch to published once v1.0.0-alpha.16 is tagged and on PyPI.
#   RATIFY_SDK=published ./scripts/nvidia-reference-check.sh
# The reference needs alpha.16's resource_path constraint, so a published run
# cannot succeed against alpha.15.
RATIFY_SDK="${RATIFY_SDK:-local}"
RATIFY_SDK_VERSION="${RATIFY_SDK_VERSION:-1.0.0a16}"
case "$RATIFY_SDK" in
  local)
      "$VENV/bin/pip" install --quiet -e ./sdks/python ;;
  published)
      "$VENV/bin/pip" install --quiet "ratify-protocol==${RATIFY_SDK_VERSION}" ;;
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
import sys

print("  python           ", sys.version.split()[0])
# Where ratify_protocol was actually imported from. An editable install resolves
# into the repository, a published one into site-packages, and the difference is
# the whole provenance claim: printing it means the final gate cannot silently
# prove the checkout while reporting the release.
import pathlib

import ratify_protocol

module_path = pathlib.Path(ratify_protocol.__file__).resolve()
repo_root = pathlib.Path.cwd().resolve()
inside_repo = repo_root in module_path.parents
print("  ratify module     ", module_path)
print("  ratify source     ", "repository checkout" if inside_repo else "installed package")
expected = os.environ.get("RATIFY_SDK", "local")
if expected == "published" and inside_repo:
    sys.exit(
        "RATIFY_SDK=published but ratify_protocol resolved inside the repository "
        f"at {module_path}; the final gate must import the published package"
    )
if expected == "local" and not inside_repo:
    sys.exit(
        "RATIFY_SDK=local but ratify_protocol resolved outside the repository "
        f"at {module_path}; an unexpected package is shadowing the checkout"
    )

for dist in ("ratify-protocol", "mcp", "uvicorn", "nooa", "pytest"):
    try:
        print(f"  {dist:<17}", md.version(dist))
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

if [ "$STATUS" != "0" ]; then
    echo "nvidia-reference-check: FAILED, pytest exited $STATUS" >&2
    exit 1
fi

fail() { echo "nvidia-reference-check: FAILED, $*" >&2; exit 1; }

# Any skip at all. A reference whose claims depend on an optional dependency has
# to install it, not tolerate its absence.
if grep -qE "^SKIPPED|[0-9]+ skipped" "$LOG"; then
    grep -E "^SKIPPED|skipped" "$LOG" | head -5 >&2
    fail "a test skipped"
fi
grep -qE "[0-9]+ (error|errors)" "$LOG" && fail "pytest reported collection errors"

# Counts come from pytest's JUnit XML, not from its console text. Parsing the
# verbose output undercounted by four: several transport tests print size
# margins, so their PASSED lands on a line that does not begin with the module
# path. A gate that miscounts is a gate that fails for the wrong reason.
read -r RECEIVER TRANSPORT ADJUDICATOR NOOA TOTAL SKIPPED FAILED <<<"$(
"$VENV/bin/python" - "$WORKDIR/results.xml" <<'COUNTPY'
import sys
import xml.etree.ElementTree as ET

per_file = {}
skipped = failed = 0
order = ["test_verification.py", "test_mcp_transport.py",
         "test_adjudicator.py", "test_nooa_presentation.py"]

for case in ET.parse(sys.argv[1]).getroot().iter("testcase"):
    # `file` is the reliable attribute in recent pytest, `classname` in older
    # ones. Match on either, so the gate does not silently count zero and fail
    # for a reason that has nothing to do with the tests.
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

echo
echo "nvidia-reference-check: ok ($TOTAL tests, zero skips, nooa==$NOOA_VERSION, mcp==$MCP_VERSION)"
echo "Note: this gate does not run the live OpenShell profile. That needs a"
echo "container runtime: $DEMO/run-openshell-profile.sh"
