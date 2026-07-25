"""Vocabulary parity tests — the public scope vocabulary accessors must
match the Go reference's Vocabulary(): 54 canonical scopes, sorted
lexicographically, returned as immutable copies."""
from __future__ import annotations

from ratify_protocol import (
    SCOPE_PRESENCE_REPRESENT,
    expand_scopes,
    is_sensitive,
    scope_wildcards,
    validate_scopes,
    vocabulary,
)


def test_vocabulary_54_entries_sorted_all_canonical():
    v = vocabulary()
    assert len(v) == 54, "canonical vocabulary size drift"
    assert list(v) == sorted(v), "vocabulary must be lex-sorted"
    assert len(set(v)) == len(v), "vocabulary must not contain duplicates"
    assert SCOPE_PRESENCE_REPRESENT in v
    # Every entry is a valid canonical scope.
    assert validate_scopes(list(v)) is None


def test_vocabulary_returns_immutable_fresh_copy():
    v = vocabulary()
    assert isinstance(v, tuple)
    assert v == vocabulary()
    assert v is not vocabulary()


def test_scope_wildcards_expansions_are_non_sensitive_vocabulary_members():
    wildcards = scope_wildcards()
    vocab = set(vocabulary())
    assert len(wildcards) == 14, "wildcard count drift"
    for wildcard, children in wildcards.items():
        assert wildcard.endswith(":*")
        assert isinstance(children, tuple)
        assert children, f"wildcard {wildcard} must expand to something"
        for c in children:
            assert c in vocab, f"{wildcard} expands to unknown scope {c}"
            assert not is_sensitive(c), f"{wildcard} must not expand to sensitive {c}"
        # The map agrees with expand_scopes.
        assert expand_scopes([wildcard]) == sorted(children)


def test_scope_wildcards_returns_fresh_copy():
    w = scope_wildcards()
    w["meeting:*"] = ()
    assert scope_wildcards()["meeting:*"], "mutating the returned dict must not persist"
