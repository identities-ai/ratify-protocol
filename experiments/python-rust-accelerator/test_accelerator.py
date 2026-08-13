import accelerator
from ratify_protocol import VerifierContext


class Marker:
    def __init__(self):
        self.called = False

    def is_revoked(self, _cert_id):
        self.called = True
        return False, None


def test_provider_options_use_python_fallback(monkeypatch):
    marker = Marker()
    sentinel = object()
    monkeypatch.setattr(accelerator, "python_verify_bundle", lambda bundle, options: sentinel)
    options = type("Options", (), {
        "is_revoked": None, "revocation": marker, "force_revocation_check": False,
        "policy": None, "audit": None, "constraint_evaluators": None,
        "policy_verdict": None, "policy_secret": None, "anchor_resolver": None,
        "challenge_store": None, "context": None,
    })()
    assert accelerator.verify_bundle(object(), options) is sentinel


def test_rate_callback_uses_python_fallback():
    options = type("Options", (), {
        "is_revoked": None, "revocation": None, "force_revocation_check": False,
        "policy": None, "audit": None, "constraint_evaluators": None,
        "policy_verdict": None, "policy_secret": None, "anchor_resolver": None,
        "challenge_store": None,
        "context": VerifierContext(invocations_in_window=lambda _cert, _window: 0),
    })()
    assert not accelerator.native_eligible(options)
