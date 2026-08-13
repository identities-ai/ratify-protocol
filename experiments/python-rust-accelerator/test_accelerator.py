import accelerator
from ratify_protocol import VerifyOptions, VerifierContext


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


def test_every_provider_option_disables_native_path():
    fields = (
        "is_revoked", "revocation", "policy", "audit", "constraint_evaluators",
        "policy_verdict", "policy_secret", "anchor_resolver", "challenge_store",
    )
    for field in fields:
        options = VerifyOptions()
        setattr(options, field, object())
        assert not accelerator.native_eligible(options), field

    assert not accelerator.native_eligible(VerifyOptions(force_revocation_check=True))


def test_missing_native_module_uses_python_fallback(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(accelerator, "_native_verify_bundle_object", None)
    monkeypatch.setattr(accelerator, "python_verify_bundle", lambda bundle, options: sentinel)
    assert accelerator.verify_bundle(object(), VerifyOptions()) is sentinel


def test_native_exception_uses_python_fallback(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(accelerator, "_native_verify_bundle_object", lambda *_: (_ for _ in ()).throw(ValueError("corrupt native result")))
    monkeypatch.setattr(accelerator, "python_verify_bundle", lambda bundle, options: sentinel)
    assert accelerator.verify_bundle(object(), VerifyOptions()) is sentinel
