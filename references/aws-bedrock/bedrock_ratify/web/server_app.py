r"""Server console — port 3200.

The custodian of C:\SideEvents. It holds its own verifier key and the principal's
PUBLIC key, so it can check a proof and cannot mint one. Every request that
arrives is verified before the directory is read, and every decision is written
to the console feed exactly as the verifier returned it.

    python -m bedrock_ratify.web.server_app
"""
from __future__ import annotations

import json
import time

from ratify_protocol import decode_proof_bundle

from ..agents import CUSTODIAN_SYSTEM, CUSTODIAN_TOOLS, bedrock_client, bedrock_status, run_tool_loop
from ..a2a import RequestEnvelope
from ..config import PROTECTED_ROOT, REQUIRED_SCOPE, RESOURCE_ID, VERIFIER_ID
from ..receiver import DirectoryRequest, SideEventsCustodian
from .common import Router, serve
from .keys import load_party, load_trusted_root_id, require_keys

PORT = 3200

require_keys()
CUSTODIAN = SideEventsCustodian(
    verifier=load_party("agent2"), trusted_root_id=load_trusted_root_id()
)
FEED: list[dict] = []

# Agent 2 runs on Bedrock. The model reviews the incoming request and chooses
# whether to call the verifier; it never sees a key and cannot approve anything.
# If Bedrock is unreachable the console says so in its header and the verifier
# is called directly — the authority decision is identical either way.
BEDROCK = bedrock_status()
MODEL = bedrock_client() if BEDROCK["available"] else None
MODEL_LABEL = (f'{BEDROCK["model"]} @ {BEDROCK["region"]}' if BEDROCK["available"]
               else "no model — verifier called directly")

# The order the console displays. On a refusal the verifier reports one reason;
# the console marks that check failed and leaves the rest unreported rather than
# claiming they passed.
CHECKS = [
    ("signatures", "hybrid signatures on every certificate in the chain",
     ("bad_signature", "invalid_chain", "malformed")),
    ("window", "certificate window covers now", ("expired", "not_yet_valid")),
    ("freshness", "challenge issued by this verifier, unused, bound to this request",
     ("challenge", "session_context", "stale")),
    ("scope", f"scope {REQUIRED_SCOPE!r} present in the effective chain scope",
     ("scope_denied",)),
    ("resource", "resource_path constraint covers the requested resource and path",
     ("constraint_denied",)),
    ("revocation", "certificate is not revoked (checked fail-closed)",
     ("revoked", "revocation_error")),
    ("trust", "chain anchors to the principal this custodian trusts",
     ("untrusted_root", "unserved_resource")),
]


def checklist(allowed: bool, reason: str) -> list[dict]:
    if allowed:
        return [{"key": k, "text": t, "state": "pass"} for k, t, _ in CHECKS]
    lowered = reason.lower()
    hit = next((k for k, _, markers in CHECKS if any(m in lowered for m in markers)), None)
    out = []
    for key, text, _ in CHECKS:
        state = "fail" if key == hit else "unreported"
        out.append({"key": key, "text": text, "state": state})
    return out


def record(event: dict) -> dict:
    event["at"] = time.strftime("%H:%M:%S")
    FEED.insert(0, event)
    del FEED[60:]
    return event


# ---------------------------------------------------------------- endpoints


def api_config(_payload):
    return 200, {
        "verifier_id": VERIFIER_ID,
        "resource_id": RESOURCE_ID,
        "protected_root": PROTECTED_ROOT,
        "required_scope": REQUIRED_SCOPE,
        "trusted_root": CUSTODIAN.trusted_root_id,
        "verifier_agent": CUSTODIAN.verifier.id,
        "bedrock": BEDROCK,
    }


def api_challenge(payload):
    from ratify_protocol import base64_standard_encode

    req = DirectoryRequest(**payload["request"])
    challenge, ctx = CUSTODIAN.issue_challenge(req, payload["agent_id"])
    record({
        "kind": "challenge",
        "agent": payload["agent_id"],
        "asking": f'{req.resource_id} at "{req.path}"',
        "challenge": base64_standard_encode(challenge),
    })
    return 200, {
        "challenge": base64_standard_encode(challenge),
        "session_context": base64_standard_encode(ctx),
    }


def _verify_and_list(req: DirectoryRequest, proof: str) -> dict:
    """The enforcement point. Reached by the model as a tool, or directly when
    Bedrock is unavailable — either way this is the only path to the disk."""
    before = CUSTODIAN.handler_invocations
    try:
        bundle = decode_proof_bundle(proof)
    except ValueError as exc:
        return {"allowed": False, "reason": f"malformed_proof: {exc}", "entries": [],
                "checks": checklist(False, "malformed"), "handler_ran": False,
                "agent": "(undecodable)", "proof_bytes": len(proof or ""),
                "receipt": "", "receipt_hash": ""}

    started = time.perf_counter()
    decision = CUSTODIAN.list_directory(req, bundle)
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "entries": decision.entries,
        "granted_scope": decision.granted_scope,
        "principal": decision.human_id,
        "agent": bundle.agent_id,
        "cert_id": bundle.delegations[0].cert_id if bundle.delegations else "",
        "chain_depth": len(bundle.delegations),
        "proof_bytes": len(proof),
        "checks": checklist(decision.allowed, decision.reason),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "receipt": decision.receipt_b64,
        "receipt_hash": decision.receipt_hash_b64,
        "handler_ran": CUSTODIAN.handler_invocations > before,
    }


NO_CALL = {
    "allowed": False,
    "reason": "no_verification_attempted: the custodian model never called the verifier",
    "entries": [], "handler_ran": False, "receipt": "", "receipt_hash": "",
}


def api_list(payload):
    req = DirectoryRequest(**payload["request"])
    proof = payload["proof_bundle"]

    if MODEL is None:
        out = _verify_and_list(req, proof)
        narration = ""
    else:
        envelope = RequestEnvelope(req, proof).to_json()
        captured: list[dict] = []

        def tool(args):
            result = _verify_and_list(
                DirectoryRequest(**json.loads(args["envelope_json"])["request"]),
                json.loads(args["envelope_json"])["proof_bundle"],
            )
            captured.append(result)
            # What goes back to the model: the decision, never the key material.
            return {k: result[k] for k in
                    ("allowed", "reason", "entries", "granted_scope", "receipt_hash")}

        try:
            narration, _trace = run_tool_loop(
                MODEL,
                system=CUSTODIAN_SYSTEM,
                user_message=("An agent is requesting a directory listing. Review what "
                              "it is asking for, then verify its authority.\n\n"
                              "Envelope:\n" + envelope),
                tools=CUSTODIAN_TOOLS,
                handlers={"verify_and_list": tool},
            )
        except Exception as exc:
            narration = f"(bedrock call failed: {type(exc).__name__}: {exc})"
        out = captured[-1] if captured else dict(NO_CALL,
                                                 checks=checklist(False, "no_call"),
                                                 agent="(model did not present)",
                                                 proof_bytes=len(proof))

    record({
        "kind": "decision",
        "asking": f'{req.resource_id} at "{req.path}"',
        "model": MODEL_LABEL,
        "narration": narration,
        **{k: v for k, v in out.items() if k != "receipt"},
    })
    return 200, {
        "allowed": out["allowed"], "reason": out["reason"], "entries": out["entries"],
        "granted_scope": out.get("granted_scope", []),
        "receipt": out.get("receipt", ""), "receipt_hash": out.get("receipt_hash", ""),
        "elapsed_ms": out.get("elapsed_ms"), "custodian_said": narration,
    }


def api_revoke(payload):
    cert_id = payload["cert_id"]
    CUSTODIAN.revoke(cert_id)
    record({"kind": "revocation", "cert_id": cert_id,
            "note": "applied — the next presentation of this certificate fails core "
                    "verification, whatever validity it has left"})
    return 200, {"applied": True, "cert_id": cert_id}


def api_feed(_payload):
    return 200, {"events": FEED, "handler_invocations": CUSTODIAN.handler_invocations}


PAGE = r"""
<!-- server console -->
<title>SideEvents Custodian</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>
  :root{
    --bg:#12100C; --panel:#1B1813; --sunk:#100E0A; --rule:#2E2921; --rule2:#463E31;
    --ink:#EDE6DA; --muted:#A0947F; --faint:#6E6555;
    --accent:#E0A14E; --accent-dim:#3A2C15;
    --ok:#79B87A; --no:#E2766B;
  }
  *{box-sizing:border-box}
  body{background:var(--bg);color:var(--ink);font:14px/1.55 "IBM Plex Sans",system-ui,sans-serif}
  .top{border-bottom:1px solid var(--rule);padding:20px 26px;display:flex;flex-wrap:wrap;
       gap:18px 34px;align-items:baseline;background:var(--panel)}
  .top h1{margin:0;font-size:1.05rem;font-weight:600;letter-spacing:.01em}
  .port{font-family:"IBM Plex Mono",monospace;color:var(--accent);font-size:.8rem;
        border:1px solid var(--accent-dim);background:var(--accent-dim);padding:2px 8px;border-radius:3px}
  .cfg{display:flex;gap:8px 26px;flex-wrap:wrap;font-family:"IBM Plex Mono",monospace;font-size:.76rem}
  .cfg span{color:var(--faint)}
  .cfg b{font-weight:500;color:var(--muted)}
  .model{font-family:"IBM Plex Mono",monospace;font-size:.74rem;padding:3px 9px;border-radius:3px;
         border:1px solid}
  .model.on{color:var(--ok);border-color:#2C4A32;background:#12200F}
  .model.off{color:var(--no);border-color:#4A2A25;background:#1F110E}
  .say{background:var(--sunk);border:1px solid var(--rule);border-left:2px solid var(--accent);
       border-radius:0 3px 3px 0;padding:10px 13px;font-size:.86rem;color:var(--muted)}
  .say i{font-style:normal;display:block;font-family:"IBM Plex Mono",monospace;font-size:.66rem;
         letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-bottom:4px}
  main{padding:24px 26px 80px;max-width:1080px;margin:0 auto;display:flex;flex-direction:column;gap:16px}
  .bar{display:flex;justify-content:space-between;align-items:baseline;gap:16px;flex-wrap:wrap}
  .eyebrow{font-family:"IBM Plex Mono",monospace;font-size:.68rem;letter-spacing:.14em;
           text-transform:uppercase;color:var(--faint)}
  .counter{font-family:"IBM Plex Mono",monospace;font-size:.78rem;color:var(--muted)}
  .counter b{color:var(--accent);font-weight:600}
  .empty{border:1px dashed var(--rule2);border-radius:4px;padding:34px;text-align:center;
         color:var(--faint);font-size:.88rem}
  .ev{border:1px solid var(--rule);border-radius:4px;background:var(--panel);overflow:hidden}
  .ev.allow{border-left:3px solid var(--ok)}
  .ev.deny{border-left:3px solid var(--no)}
  .ev.info{border-left:3px solid var(--rule2)}
  .ev-head{display:flex;gap:14px;align-items:baseline;flex-wrap:wrap;padding:12px 16px;
           border-bottom:1px solid var(--rule)}
  .ev-head.bare{border-bottom:none}
  .t{font-family:"IBM Plex Mono",monospace;font-size:.78rem;color:var(--faint);
     font-variant-numeric:tabular-nums}
  .verdict{font-family:"IBM Plex Mono",monospace;font-size:.78rem;font-weight:600;
           letter-spacing:.08em;text-transform:uppercase}
  .verdict.allow{color:var(--ok)} .verdict.deny{color:var(--no)} .verdict.info{color:var(--muted)}
  .asking{font-family:"IBM Plex Mono",monospace;font-size:.8rem;color:var(--ink)}
  .grow{flex:1}
  .ev-body{padding:14px 16px;display:flex;flex-direction:column;gap:12px}
  .kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px 22px}
  .kv div{font-family:"IBM Plex Mono",monospace;font-size:.76rem;overflow-wrap:anywhere}
  .kv i{font-style:normal;color:var(--faint);display:block;font-size:.68rem;letter-spacing:.08em;
        text-transform:uppercase;margin-bottom:1px}
  ul.checks{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:4px}
  ul.checks li{font-family:"IBM Plex Mono",monospace;font-size:.77rem;display:flex;gap:10px;
               align-items:baseline}
  .mark{width:4.2em;flex:none;font-weight:600}
  .mark.pass{color:var(--ok)} .mark.fail{color:var(--no)} .mark.unreported{color:var(--faint)}
  li.unreported{color:var(--faint)}
  .reason{font-family:"IBM Plex Mono",monospace;font-size:.79rem;color:var(--no);
          background:var(--sunk);border:1px solid var(--rule);border-radius:3px;padding:9px 12px;
          overflow-x:auto}
  .served{background:var(--sunk);border:1px solid var(--rule);border-radius:3px;padding:10px 12px;
          display:flex;flex-direction:column;gap:3px}
  .served .row{font-family:"IBM Plex Mono",monospace;font-size:.79rem;display:flex;gap:12px}
  .served .row span:first-child{color:var(--faint);width:3em;flex:none}
  .served .sz{color:var(--faint);margin-left:auto}
  .legend{font-size:.76rem;color:var(--faint)}
  @media (prefers-reduced-motion:no-preference){
    .ev{animation:in .18s ease-out}
    @keyframes in{from{opacity:.3;transform:translateY(-3px)}to{opacity:1;transform:none}}
  }
</style>

<div class="top">
  <h1>SideEvents Custodian</h1>
  <span class="port">server · :3200</span>
  <span class="model" id="model">…</span>
  <div class="cfg" id="cfg"></div>
</div>

<main>
  <div class="bar">
    <div class="eyebrow">Incoming · verify · serve</div>
    <div class="counter">protected handler ran <b id="hits">0</b> times</div>
  </div>
  <div class="legend">On a refusal the verifier reports one reason. The failing check is
    marked; the rest are left <em>unreported</em> rather than claimed as passing.</div>
  <div id="feed"><div class="empty">Waiting for a request from the client on :3100.</div></div>
</main>

<script>
const esc = s => String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));

fetch("/api/config").then(r => r.json()).then(c => {
  const m = document.getElementById("model");
  m.className = "model " + (c.bedrock.available ? "on" : "off");
  m.textContent = c.bedrock.available
    ? "agent 2 on bedrock · " + c.bedrock.model + " @ " + c.bedrock.region
    : "no bedrock · " + c.bedrock.reason;
  m.title = c.bedrock.available
    ? "The model reviews each request and chooses whether to call the verifier. It cannot approve one."
    : "Verifier called directly. The authority decision is identical either way.";
  document.getElementById("cfg").innerHTML = [
    ["serves", c.resource_id + "  =  " + c.protected_root],
    ["requires", c.required_scope],
    ["trusts root", c.trusted_root],
    ["verifier key", c.verifier_agent],
  ].map(([k, v]) => `<span>${esc(k)} <b>${esc(v)}</b></span>`).join("");
});

function checksHTML(checks) {
  if (!checks) return "";
  return `<ul class="checks">` + checks.map(c =>
    `<li class="${c.state}"><span class="mark ${c.state}">${
      c.state === "pass" ? "pass" : c.state === "fail" ? "FAIL" : "·"
    }</span><span>${esc(c.text)}</span></li>`).join("") + `</ul>`;
}

function kv(pairs) {
  const rows = pairs.filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `<div><i>${esc(k)}</i>${esc(v)}</div>`).join("");
  return rows ? `<div class="kv">${rows}</div>` : "";
}

function eventHTML(e) {
  if (e.kind === "challenge") {
    return `<div class="ev info"><div class="ev-head bare">
      <span class="t">${esc(e.at)}</span>
      <span class="verdict info">challenge</span>
      <span class="asking">${esc(e.asking)}</span>
      <span class="grow"></span>
      <span class="t">agent ${esc(e.agent)}</span></div></div>`;
  }
  if (e.kind === "revocation") {
    return `<div class="ev info"><div class="ev-head">
      <span class="t">${esc(e.at)}</span>
      <span class="verdict info">revocation</span>
      <span class="asking">${esc(e.cert_id)}</span></div>
      <div class="ev-body"><div class="legend">${esc(e.note)}</div></div></div>`;
  }
  const cls = e.allowed ? "allow" : "deny";
  const served = e.allowed && e.entries && e.entries.length
    ? `<div class="served">` + e.entries.map(x =>
        `<div class="row"><span>${x.type === "dir" ? "dir" : "file"}</span><span>${esc(x.name)}</span>` +
        `<span class="sz">${x.bytes === null ? "" : x.bytes + " B"}</span></div>`).join("") + `</div>`
    : "";
  return `<div class="ev ${cls}">
    <div class="ev-head">
      <span class="t">${esc(e.at)}</span>
      <span class="verdict ${cls}">${e.allowed ? "allow" : "deny"}</span>
      <span class="asking">${esc(e.asking)}</span>
      <span class="grow"></span>
      <span class="t">${e.elapsed_ms !== undefined ? e.elapsed_ms + " ms" : ""}</span>
    </div>
    <div class="ev-body">
      ${kv([
        ["from agent", e.agent],
        ["cert", e.cert_id],
        ["chain depth", e.chain_depth],
        ["proof", e.proof_bytes ? e.proof_bytes + " bytes" : ""],
        ["principal", e.principal],
        ["granted", (e.granted || []).join(", ")],
        ["receipt", e.receipt_hash],
        ["handler", e.handler_ran ? "ran once" : "not reached"],
      ])}
      ${e.narration ? `<div class="say"><i>agent 2 · ${esc(e.model || "")}</i>${esc(e.narration)}</div>` : ""}
      ${checksHTML(e.checks)}
      ${e.allowed ? "" : `<div class="reason">${esc(e.reason)}</div>`}
      ${served}
    </div></div>`;
}

let last = "";
async function poll() {
  try {
    const d = await (await fetch("/api/feed")).json();
    document.getElementById("hits").textContent = d.handler_invocations;
    const html = d.events.length
      ? d.events.map(eventHTML).join("")
      : `<div class="empty">Waiting for a request from the client on :3100.</div>`;
    if (html !== last) { document.getElementById("feed").innerHTML = html; last = html; }
  } catch (_) { /* server restarting */ }
}
poll();
setInterval(poll, 900);
</script>
"""


class Handler(Router):
    page = PAGE
    routes = {
        ("GET", "/api/config"): api_config,
        ("GET", "/api/feed"): api_feed,
        ("POST", "/challenge"): api_challenge,
        ("POST", "/list"): api_list,
        ("POST", "/revoke"): api_revoke,
    }


if __name__ == "__main__":
    serve(Handler, PORT,
          f"SideEvents custodian — serving {RESOURCE_ID} = {PROTECTED_ROOT}\n"
          f"  trusts root {CUSTODIAN.trusted_root_id}")
