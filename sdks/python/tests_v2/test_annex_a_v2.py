"""SPEC-v2 Annex A from "annex-a.json": the pinned v1 clauses, RatifyCanonicalJSON
and strict-decode cases, and the scope vocabulary, expansion, and intersection."""
from __future__ import annotations

import base64
import hashlib

import pytest

from corpus import V2_DIR, load
from ratify_protocol.v2 import _v2json
from ratify_protocol.v2.errors_v2 import V2ErrorClass
from ratify_protocol.v2.scope import (
    expand_scopes,
    intersect_scopes,
    is_sensitive,
    scope_wildcards,
    validate_scopes_v2,
    vocabulary,
)
from ratify_protocol.v2.transaction_receipt_v2 import validate_canonical_transaction_terms_v2

ANNEX = load("annex-a.json")


def strict_decode(data: bytes):
    """SPEC-v2 §2.1 strict decode over the Annex A §A.2 value model."""
    return _v2json.check_wire_json(data)


def _is_canonical_terms(data: bytes) -> bool:
    try:
        validate_canonical_transaction_terms_v2(data)
    except ValueError:
        return False
    return True


def test_annex_clauses_are_pinned():
    annex = (V2_DIR.parents[1] / "SPEC-v2-ANNEX-A.md").read_text(encoding="utf-8")
    lines = annex.split("\n")
    assert len(ANNEX["clauses"]) == 3
    for c in ANNEX["clauses"]:
        begin = lines.index(f"<!-- annex-a:begin {c['id']} -->")
        end = lines.index(f"<!-- annex-a:end {c['id']} -->")
        block = "\n".join(lines[begin + 1:end]).encode("utf-8")
        assert len(block) == c["bytes"] and hashlib.sha256(block).hexdigest() == c["sha256"], c["id"]
        assert f"`{c['sha256']}`" in annex, c["id"]


@pytest.mark.parametrize("v", ANNEX["canonical_json"], ids=lambda v: v["name"])
def test_canonical_json(v):
    data = base64.b64decode(v["input_b64"], validate=True)
    got = _v2json.canonical(strict_decode(data))
    assert got == v["canonical"].encode("utf-8")
    assert _is_canonical_terms(got)
    is_canonical = _is_canonical_terms(data)
    assert is_canonical == v["input_is_canonical"] == (data == got)


@pytest.mark.parametrize("v", ANNEX["strict_decode_rejections"], ids=lambda v: v["name"])
def test_strict_decode_rejection(v):
    assert v["error_class"] == V2ErrorClass.MALFORMED
    with pytest.raises(ValueError):
        strict_decode(base64.b64decode(v["input_b64"], validate=True))


def test_scope_vocabulary():
    voc = ANNEX["vocabulary"]
    assert list(vocabulary()) == voc["canonical"]
    assert [s for s in voc["canonical"] if is_sensitive(s)] == voc["sensitive"]
    for s in voc["canonical"]:
        validate_scopes_v2([s])
    assert len(voc["wildcards"]) == len(scope_wildcards())
    for w, want in voc["wildcards"].items():
        assert expand_scopes([w]) == want, w
        assert not any(is_sensitive(s) for s in want)


@pytest.mark.parametrize("v", ANNEX["scope_validation"], ids=lambda v: v["name"])
def test_scope_validation(v):
    try:
        validate_scopes_v2(v["scopes"])
        valid = True
    except ValueError:
        valid = False
    assert valid == v["valid"]


@pytest.mark.parametrize("v", ANNEX["scope_expansion"], ids=lambda v: v["name"])
def test_scope_expansion(v):
    assert expand_scopes(v["scopes"]) == v["expanded"]


@pytest.mark.parametrize("v", ANNEX["scope_intersection"], ids=lambda v: v["name"])
def test_scope_intersection(v):
    assert intersect_scopes(*v["lists"]) == v["effective"]


def test_annex_counts():
    assert len(ANNEX["canonical_json"]) == 8 and len(ANNEX["strict_decode_rejections"]) == 16
    assert len(ANNEX["vocabulary"]["canonical"]) == 54 and len(ANNEX["vocabulary"]["sensitive"]) == 22
    assert len(ANNEX["vocabulary"]["wildcards"]) == 14
    assert len(ANNEX["scope_validation"]) == 17 and len(ANNEX["scope_expansion"]) == 6
    assert len(ANNEX["scope_intersection"]) == 8
