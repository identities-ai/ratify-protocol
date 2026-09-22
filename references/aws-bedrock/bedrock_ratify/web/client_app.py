r"""Client console — port 3100.

The human signs a delegation scoped to a directory; the agent presents it to the
custodian on :3200 and shows what came back. The principal's private key lives
in this process and never leaves it.

    python -m bedrock_ratify.web.client_app
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid

from ratify_protocol import (
    base64_standard_decode,
    base64_standard_encode,
    decode_verification_receipt,
    encode_delegation_cert,
    verify_verification_receipt,
)

from ..agents import (
    REQUESTER_SYSTEM, REQUESTER_TOOLS, bedrock_client, bedrock_status, run_tool_loop,
)
from ..config import PROTECTED_ROOT, RESOURCE_ID
from ..identity import issue_directory_delegation
from ..presenter import build_proof, wire
from ..receiver import DirectoryRequest
from .common import Router, serve
from .keys import load_party, require_keys

PORT = 3100
SERVER = "http://127.0.0.1:3200"

require_keys()
PRINCIPAL = load_party("principal")
AGENT = load_party("agent1")
SESSION_ID = f"session-{uuid.uuid4().hex[:8]}"

# The certificates this client has signed, newest last.
WALLET: list = []

# Agent 1 runs on Bedrock. The model decides what to ask for; the tool handler
# below does the Ratify half. The model never touches a key or a signature.
BEDROCK = bedrock_status()
MODEL = bedrock_client() if BEDROCK["available"] else None


def call(path: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(SERVER + path, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def cert_view(cert) -> dict:
    c = cert.constraints[0]
    return {
        "cert_id": cert.cert_id,
        "issuer": cert.issuer_id,
        "subject": cert.subject_id,
        "scope": cert.scope,
        "resource_id": c.resource_id,
        "path_prefix": c.path_prefix,
        "issued_at": cert.issued_at,
        "expires_at": cert.expires_at,
        "ttl": cert.expires_at - cert.issued_at,
        "sig_ed25519": len(cert.signature.ed25519),
        "sig_ml_dsa": len(cert.signature.ml_dsa_65),
        "wire_bytes": len(encode_delegation_cert(cert)),
    }


# ---------------------------------------------------------------- endpoints


def api_identity(_payload):
    return 200, {
        "principal": PRINCIPAL.id,
        "agent": AGENT.id,
        "server": SERVER,
        "resource_id": RESOURCE_ID,
        "protected_root": PROTECTED_ROOT,
        "session_id": SESSION_ID,
        "wallet": [cert_view(c) for c in WALLET],
        "bedrock": BEDROCK,
    }


def api_delegate(payload):
    """DELEGATE — the human signs. This is the only place authority is created."""
    cert = issue_directory_delegation(
        PRINCIPAL,
        AGENT,
        scopes=payload.get("scopes") or ["files:read"],
        path_prefix=payload.get("path_prefix") or "/",
        ttl_seconds=int(payload.get("ttl") or 3600),
        resource_id=payload.get("resource_id") or RESOURCE_ID,
    )
    WALLET.append(cert)
    return 200, {"cert": cert_view(cert)}


def api_present(payload):
    """PRESENT — the agent signs a fresh challenge and ships the bundle."""
    if not WALLET:
        return 200, {"error": "no delegation signed yet — sign one first"}
    cert = next((c for c in WALLET if c.cert_id == payload.get("cert_id")), WALLET[-1])

    req = DirectoryRequest(
        session_id=SESSION_ID,
        invocation_id=f"inv-{uuid.uuid4().hex[:8]}",
        resource_id=payload.get("resource_id") or RESOURCE_ID,
        path=payload.get("path") or "/",
    )
    try:
        issued = call("/challenge", {"request": req.__dict__, "agent_id": AGENT.id})
    except (urllib.error.URLError, OSError) as exc:
        return 200, {"error": f"custodian on :3200 is unreachable — {exc}"}

    challenge = base64_standard_decode(issued["challenge"])
    ctx = base64_standard_decode(issued["session_context"])
    bundle = build_proof(AGENT, [cert], challenge, ctx)
    body = wire(bundle)

    presented = {
        "cert_id": cert.cert_id,
        "request": req.__dict__,
        "challenge": issued["challenge"],
        "session_context": issued["session_context"],
        "sig_ed25519": len(bundle.challenge_sig.ed25519),
        "sig_ml_dsa": len(bundle.challenge_sig.ml_dsa_65),
        "wire_bytes": len(body),
        "wire_keys": sorted(json.loads(body).keys()),
    }

    try:
        answer = call("/list", {"request": req.__dict__, "proof_bundle": body})
    except (urllib.error.URLError, OSError) as exc:
        return 200, {"presented": presented, "error": f"custodian unreachable — {exc}"}

    # The client checks the receipt itself rather than taking the answer on trust.
    receipt_check = {"checked": False}
    if answer.get("receipt"):
        receipt = decode_verification_receipt(answer["receipt"])
        err = verify_verification_receipt(receipt)
        receipt_check = {
            "checked": True,
            "valid": err is None,
            "error": err or "",
            "verifier_id": receipt.verifier_id,
            "decision": receipt.decision,
            "verified_at": receipt.verified_at,
            "hash": answer.get("receipt_hash", ""),
            "prev_hash": base64_standard_encode(receipt.prev_hash) if receipt.prev_hash else "",
        }

    return 200, {"presented": presented, "answer": answer, "receipt_check": receipt_check}


LAST_PRESENT: dict = {}


def api_ask(payload):
    """Agent 1's Bedrock loop. The model picks the path and calls the tool."""
    if MODEL is None:
        return 200, {"error": f"bedrock unavailable — {BEDROCK['reason']}"}
    if not WALLET:
        return 200, {"error": "no delegation signed yet — sign one first"}

    cert_id = payload.get("cert_id")
    calls: list[dict] = []

    def tool(args):
        out = api_present({"cert_id": cert_id, "path": args.get("path") or "/",
                           "resource_id": payload.get("resource_id") or RESOURCE_ID})[1]
        calls.append(out)
        answer = out.get("answer") or {}
        return {"allowed": answer.get("allowed"), "reason": answer.get("reason") or out.get("error"),
                "entries": answer.get("entries", []), "receipt_hash": answer.get("receipt_hash", "")}

    try:
        text, _trace = run_tool_loop(
            MODEL,
            system=REQUESTER_SYSTEM,
            user_message=payload.get("instruction") or
            f"Get me a listing of {PROTECTED_ROOT} and tell me what is in it.",
            tools=REQUESTER_TOOLS,
            handlers={"request_directory": tool},
        )
    except Exception as exc:
        return 200, {"error": f"bedrock call failed: {type(exc).__name__}: {exc}"}

    last = calls[-1] if calls else {}
    return 200, {"agent_said": text, "tool_calls": len(calls), **last}


def api_revoke(payload):
    """The kill switch, exercised from the side that holds the authority."""
    cert_id = payload.get("cert_id") or (WALLET[-1].cert_id if WALLET else "")
    if not cert_id:
        return 200, {"error": "nothing to revoke"}
    try:
        return 200, call("/revoke", {"cert_id": cert_id})
    except (urllib.error.URLError, OSError) as exc:
        return 200, {"error": f"custodian unreachable — {exc}"}


PAGE = r"""
<!-- client console -->
<title>SideEvents Requester</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>
  :root{
    --bg:#0A1211; --panel:#111C1A; --sunk:#0B1514; --rule:#1E2E2B; --rule2:#314743;
    --ink:#DCE8E5; --muted:#8FA5A1; --faint:#5F7370;
    --accent:#54C8B4; --accent-dim:#0F2B27;
    --ok:#6FC79E; --no:#E2766B;
  }
  *{box-sizing:border-box}
  body{background:var(--bg);color:var(--ink);font:14px/1.55 "IBM Plex Sans",system-ui,sans-serif}
  .top{border-bottom:1px solid var(--rule);padding:20px 26px;display:flex;flex-wrap:wrap;
       gap:18px 34px;align-items:baseline;background:var(--panel)}
  .top h1{margin:0;font-size:1.05rem;font-weight:600}
  .port{font-family:"IBM Plex Mono",monospace;color:var(--accent);font-size:.8rem;
        border:1px solid var(--accent-dim);background:var(--accent-dim);padding:2px 8px;border-radius:3px}
  .cfg{display:flex;gap:8px 26px;flex-wrap:wrap;font-family:"IBM Plex Mono",monospace;font-size:.76rem}
  .cfg span{color:var(--faint)} .cfg b{font-weight:500;color:var(--muted)}
  .model{font-family:"IBM Plex Mono",monospace;font-size:.74rem;padding:3px 9px;border-radius:3px;
         border:1px solid}
  .model.on{color:var(--ok);border-color:#22483A;background:#0C1F19}
  .model.off{color:var(--no);border-color:#472622;background:#1D100E}
  textarea{background:var(--sunk);border:1px solid var(--rule2);color:var(--ink);width:100%;
    font:400 .85rem/1.5 "IBM Plex Mono",monospace;padding:9px 11px;border-radius:3px;resize:vertical}
  textarea:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
  .say{background:var(--sunk);border:1px solid var(--rule);border-left:2px solid var(--accent);
    border-radius:0 3px 3px 0;padding:11px 13px;font-size:.88rem;color:var(--muted)}
  .say i{font-style:normal;display:block;font-family:"IBM Plex Mono",monospace;font-size:.66rem;
    letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-bottom:5px}
  main{padding:24px 26px 80px;max-width:1000px;margin:0 auto;display:flex;flex-direction:column;gap:22px}
  .step{border:1px solid var(--rule);border-radius:4px;background:var(--panel);overflow:hidden}
  .step-head{display:flex;gap:14px;align-items:baseline;padding:13px 18px;border-bottom:1px solid var(--rule)}
  .verb{font-family:"IBM Plex Mono",monospace;font-size:.74rem;letter-spacing:.16em;
        text-transform:uppercase;color:var(--accent);font-weight:600}
  .side{font-family:"IBM Plex Mono",monospace;font-size:.72rem;color:var(--faint)}
  .step-body{padding:16px 18px;display:flex;flex-direction:column;gap:14px}
  label{display:flex;flex-direction:column;gap:5px;font-size:.74rem;letter-spacing:.09em;
        text-transform:uppercase;color:var(--faint)}
  input,select{background:var(--sunk);border:1px solid var(--rule2);color:var(--ink);
    font:400 .85rem/1.4 "IBM Plex Mono",monospace;padding:8px 10px;border-radius:3px;width:100%}
  input:focus,select:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
  .fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px}
  .actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  button{font:500 .82rem/1 "IBM Plex Sans",sans-serif;padding:10px 16px;border-radius:3px;
    border:1px solid var(--accent);background:var(--accent);color:#06201B;cursor:pointer}
  button.ghost{background:transparent;color:var(--accent)}
  button.danger{background:transparent;border-color:var(--no);color:var(--no)}
  button:disabled{opacity:.4;cursor:not-allowed}
  button:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
  .kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:9px 22px}
  .kv div{font-family:"IBM Plex Mono",monospace;font-size:.77rem;overflow-wrap:anywhere}
  .kv i{font-style:normal;color:var(--faint);display:block;font-size:.67rem;letter-spacing:.09em;
        text-transform:uppercase;margin-bottom:1px}
  .hint{font-size:.8rem;color:var(--faint)}
  .none{font-size:.84rem;color:var(--faint);font-style:italic}
  .banner{border-radius:3px;padding:10px 13px;font-family:"IBM Plex Mono",monospace;font-size:.8rem;
          border:1px solid;overflow-x:auto}
  .banner.ok{color:var(--ok);border-color:#22483A;background:#0C1F19}
  .banner.no{color:var(--no);border-color:#472622;background:#1D100E}
  .listing{background:var(--sunk);border:1px solid var(--rule);border-radius:3px;padding:12px 14px;
    display:flex;flex-direction:column;gap:4px}
  .listing .row{font-family:"IBM Plex Mono",monospace;font-size:.82rem;display:flex;gap:14px}
  .listing .row span:first-child{color:var(--faint);width:3em;flex:none}
  .listing .sz{color:var(--faint);margin-left:auto}
  .wallet{display:flex;flex-direction:column;gap:8px}
  .cert{border:1px solid var(--rule);border-radius:3px;padding:10px 12px;background:var(--sunk);
    display:flex;gap:12px;align-items:baseline;flex-wrap:wrap;font-family:"IBM Plex Mono",monospace;
    font-size:.77rem;cursor:pointer}
  .cert.sel{border-color:var(--accent)}
  .cert .id{color:var(--muted)} .cert .sc{color:var(--accent)} .cert .bd{color:var(--faint)}
</style>

<div class="top">
  <h1>SideEvents Requester</h1>
  <span class="port">client · :3100</span>
  <span class="model" id="model">…</span>
  <div class="cfg" id="cfg"></div>
</div>

<main>

  <section class="step">
    <div class="step-head"><span class="verb">Delegate</span>
      <span class="side">human → agent · signed here, private key never leaves this process</span></div>
    <div class="step-body">
      <div class="fields">
        <label>scope
          <select id="scope">
            <option value="files:read">files:read</option>
            <option value="files:write">files:write &nbsp;(not what the custodian requires)</option>
          </select></label>
        <label>resource
          <select id="resource">
            <option value="file:sideevents">file:sideevents</option>
            <option value="file:payroll">file:payroll &nbsp;(custodian does not serve)</option>
          </select></label>
        <label>path prefix
          <select id="prefix">
            <option value="/">/ &nbsp;(whole directory)</option>
            <option value="/tools">/tools &nbsp;(subdirectory only)</option>
          </select></label>
        <label>ttl seconds <input id="ttl" value="3600" inputmode="numeric"></label>
      </div>
      <div class="actions">
        <button id="sign">Sign delegation</button>
        <span class="hint">The certificate names a directory and an expiry — not an account.</span>
      </div>
      <div class="wallet" id="wallet"><div class="none">No delegation signed yet.</div></div>
    </div>
  </section>

  <section class="step">
    <div class="step-head"><span class="verb">Present</span>
      <span class="side">agent → server :3200 · fresh challenge signed on every request</span></div>
    <div class="step-body">
      <div class="fields">
        <label>ask for resource
          <select id="askResource">
            <option value="file:sideevents">file:sideevents</option>
            <option value="file:payroll">file:payroll</option>
          </select></label>
        <label>ask for path
          <select id="askPath">
            <option value="/">/</option>
            <option value="/tools">/tools</option>
          </select></label>
      </div>
      <div class="actions">
        <button id="present" disabled>Present to custodian</button>
        <button id="revoke" class="danger" disabled>Revoke selected certificate</button>
      </div>

      <label style="margin-top:4px">ask agent 1 (bedrock) instead
        <textarea id="instruction" rows="2">Get me a listing of the SideEvents directory and tell me what is in it.</textarea>
      </label>
      <div class="actions">
        <button id="ask" class="ghost" disabled>Send to agent 1</button>
        <span class="hint" id="askHint">The model chooses the path and calls the tool. It never
          touches a key, a signature, or the directory.</span>
      </div>

      <div id="agentSaid"></div>
      <div id="presented"></div>
    </div>
  </section>

  <section class="step">
    <div class="step-head"><span class="verb">Result</span>
      <span class="side">agent → human · the client checks the receipt itself</span></div>
    <div class="step-body" id="result">
      <div class="none">Nothing presented yet.</div>
    </div>
  </section>

</main>

<script>
const esc = s => String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const $ = id => document.getElementById(id);
let wallet = [], selected = null;

function kv(pairs){
  const rows = pairs.filter(([,v]) => v !== undefined && v !== null && v !== "")
    .map(([k,v]) => `<div><i>${esc(k)}</i>${esc(v)}</div>`).join("");
  return rows ? `<div class="kv">${rows}</div>` : "";
}
const clock = ts => new Date(ts * 1000).toISOString().replace(".000Z","Z");

function renderWallet(){
  if (!wallet.length){ $("wallet").innerHTML = `<div class="none">No delegation signed yet.</div>`; return; }
  $("wallet").innerHTML = wallet.map(c => `
    <div class="cert ${c.cert_id === selected ? "sel" : ""}" data-id="${esc(c.cert_id)}">
      <span class="id">${esc(c.cert_id.slice(0,18))}…</span>
      <span class="sc">${esc(c.scope.join(" "))}</span>
      <span class="bd">${esc(c.resource_id)} under "${esc(c.path_prefix)}"</span>
      <span class="bd">ttl ${c.ttl}s</span>
      <span class="bd">${c.wire_bytes} B on the wire</span>
    </div>`).join("");
  document.querySelectorAll(".cert").forEach(el =>
    el.onclick = () => { selected = el.dataset.id; renderWallet(); });
  $("present").disabled = false;
  $("revoke").disabled = false;
  $("ask").disabled = !MODEL_ON;
}
let MODEL_ON = false;

$("sign").onclick = async () => {
  const r = await (await fetch("/api/delegate", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({
      scopes:[$("scope").value], resource_id:$("resource").value,
      path_prefix:$("prefix").value, ttl:$("ttl").value })})).json();
  wallet.push(r.cert); selected = r.cert.cert_id; renderWallet();
};

$("present").onclick = async () => {
  $("present").disabled = true;
  const r = await (await fetch("/api/present", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ cert_id:selected, resource_id:$("askResource").value,
                           path:$("askPath").value })})).json();
  $("present").disabled = false;

  if (r.error && !r.presented){ $("presented").innerHTML =
    `<div class="banner no">${esc(r.error)}</div>`; return; }

  renderPresented(r);
};

function renderPresented(r){
  const p = r.presented;
  if (!p) return;
  $("presented").innerHTML = kv([
    ["presenting cert", p.cert_id],
    ["asking for", `${p.request.resource_id} at "${p.request.path}"`],
    ["invocation", p.request.invocation_id],
    ["challenge (from server)", p.challenge],
    ["session context", p.session_context],
    ["challenge signature", `ed25519 ${p.sig_ed25519}B + ml-dsa-65 ${p.sig_ml_dsa}B`],
    ["proof on the wire", `${p.wire_bytes} bytes`],
    ["bundle fields", p.wire_keys.join(", ")],
  ]);

  if (r.error){ $("result").innerHTML = `<div class="banner no">${esc(r.error)}</div>`; return; }

  const a = r.answer, rc = r.receipt_check;
  let html = a.allowed
    ? `<div class="banner ok">allowed — ${esc(a.reason)} · ${a.elapsed_ms} ms</div>`
    : `<div class="banner no">refused — ${esc(a.reason)}</div>`;

  if (a.allowed && a.entries.length){
    html += `<div class="listing">` + a.entries.map(x =>
      `<div class="row"><span>${x.type === "dir" ? "dir" : "file"}</span><span>${esc(x.name)}</span>` +
      `<span class="sz">${x.bytes === null ? "" : x.bytes + " bytes"}</span></div>`).join("") + `</div>`;
  }
  if (rc.checked){
    html += `<div class="banner ${rc.valid ? "ok" : "no"}">receipt signature ${
      rc.valid ? "verifies against the verifier's key" : "FAILED: " + esc(rc.error)}</div>`;
    html += kv([
      ["receipt decision", rc.decision],
      ["verifier", rc.verifier_id],
      ["verified at", clock(rc.verified_at)],
      ["receipt hash", rc.hash],
      ["chains to", rc.prev_hash],
    ]);
    html += `<div class="hint">The client did not take the server's word for this —
      it verified the signed receipt itself, offline.</div>`;
  }
  $("result").innerHTML = html;
}

$("ask").onclick = async () => {
  $("ask").disabled = true; $("agentSaid").innerHTML = `<div class="hint">agent 1 is thinking…</div>`;
  const r = await (await fetch("/api/ask", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ cert_id:selected, instruction:$("instruction").value,
                           resource_id:$("askResource").value })})).json();
  $("ask").disabled = false;
  if (r.error){ $("agentSaid").innerHTML = `<div class="banner no">${esc(r.error)}</div>`; return; }
  $("agentSaid").innerHTML =
    `<div class="say"><i>agent 1 · ${r.tool_calls} tool call${r.tool_calls === 1 ? "" : "s"}</i>${esc(r.agent_said)}</div>`;
  if (r.presented) renderPresented(r);
};

$("revoke").onclick = async () => {
  const r = await (await fetch("/api/revoke", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({cert_id: selected})})).json();
  $("presented").innerHTML = r.error
    ? `<div class="banner no">${esc(r.error)}</div>`
    : `<div class="banner ok">revocation sent for ${esc(r.cert_id)} — present it again to see
       the custodian refuse a certificate that has not expired.</div>`;
};

fetch("/api/identity").then(r => r.json()).then(c => {
  MODEL_ON = c.bedrock.available;
  const m = $("model");
  m.className = "model " + (MODEL_ON ? "on" : "off");
  m.textContent = MODEL_ON
    ? "agent 1 on bedrock · " + c.bedrock.model + " @ " + c.bedrock.region
    : "no bedrock · " + c.bedrock.reason;
  if (!MODEL_ON) $("askHint").textContent =
    "Needs AWS credentials. The buttons above run the same Ratify path without a model.";
  $("cfg").innerHTML = [
    ["principal", c.principal],
    ["agent", c.agent],
    ["custodian", c.server],
    ["session", c.session_id],
  ].map(([k,v]) => `<span>${esc(k)} <b>${esc(v)}</b></span>`).join("");
  wallet = c.wallet; if (wallet.length) selected = wallet[wallet.length-1].cert_id;
  renderWallet();
});
</script>
"""


class Handler(Router):
    page = PAGE
    routes = {
        ("GET", "/api/identity"): api_identity,
        ("POST", "/api/delegate"): api_delegate,
        ("POST", "/api/present"): api_present,
        ("POST", "/api/ask"): api_ask,
        ("POST", "/api/revoke"): api_revoke,
    }


if __name__ == "__main__":
    serve(Handler, PORT,
          f"SideEvents requester — principal {PRINCIPAL.id}\n"
          f"  agent {AGENT.id}, custodian at {SERVER}")
