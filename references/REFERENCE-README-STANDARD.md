# Required structure for a reference README

Every platform reference in this repository uses the same README structure, in
the same order. This is a requirement for publication, not a style preference.

The reason is narrow. A reference exists to be understood by someone who does
not already know what Ratify does, arriving from a search result or a link in an
email. That reader decides within a paragraph whether this is relevant to them.
References that open with a build command or a boundary definition lose that
reader, whatever the quality of the code beneath.

`references/github-copilot/README.md` is the worked example of this structure.

## The required sections, in order

### 1. Title and one-sentence claim

The title names the platform and what the reader gets. The sentence under it
states the outcome in the reader's terms, not the protocol's.

> **Let GitHub Copilot use consequential tools without treating access to a tool
> as unlimited authority.**

Then two or three sentences on what the reference demonstrates, its current
status, and a plain statement that it is an independent Ratify Protocol project
rather than an endorsed integration. Close with jump links to the run
instructions, the evidence, and the open-source-versus-managed choice.

### 2. Why would a developer or enterprise need this?

Written for someone who has not decided they have this problem yet.

State what the platform's own controls already do, honestly and without
diminishing them, then what remains unanswered. A comparison table is the
clearest form:

| Question | Platform controls | Ratify authority |
| --- | --- | --- |
| Can this agent reach the tool? | Yes | Not its purpose |
| Did a recognized principal authorize this exact action? | Not expressed by tool access alone | Yes |

Follow with a short list of the situations where this matters. Do not claim the
platform is insecure. The claim is that access and authority are different
questions, and the platform answers the first one well.

### 3. Who implements what

**Required, and most often missing.** A reader evaluating this for their
organization needs to know what they would have to build before they read
anything else technical.

A table with one row per role: the principal, the agent operator, the receiver
operator, and the platform. Say plainly what each does and what each builds,
including where the answer is nothing.

This is also the section anyone reaching out to a platform team will quote,
because it answers their first question: what do we have to do?

Two ways this section goes wrong, both of which cost more credibility than they
save:

- **Claiming no work where there is configuration.** "Nothing to build" and
  "nothing to decide" are different. An operator who installs a plugin still
  chooses a receiver address, a trusted principal, and which tools are
  protected. Say so.
- **Quoting a line count for the verification call alone.** The call is not the
  integration. Give the size of the working receiver and say what the rest of it
  does, because that is the work the reader is actually estimating.

### 4. What does this reference do?

The concrete scenario. Show the actual delegation, in a literal block rather
than described:

```text
scope       custom:github:deploy
repository  identities-ai/copilot-authority-demo
path        /services/payments/environments/staging
```

Then a `mermaid` sequence diagram of one request end to end. Close by naming the
enforcement boundary explicitly: which component decides, and what cannot be
bypassed.

### 5. What the reference proves

A table with one row per tested case: the request, the decision, and whether the
protected handler ran. The handler column is the load-bearing one. A decision
without an observed effect is not evidence.

State the test count and that there are zero skips. A suite that reports success
while quietly skipping is the failure this column exists to rule out.

### 6. Use it now

Numbered steps a reader can copy. Every command must run from a clean checkout.
If it needs credentials, an account, or hardware, say so before step one rather
than at the point of failure.

Include a way to run it without the platform where that is possible, so a reader
can see the mechanism without signing up for anything.

### 7. Which path should I use?

When the inspectable open-source reference is the right choice, and when to
register interest in Ratify Verify. Required by
`decisions/reference-publication-discoverability.md`.

### 8. What is cryptographically bound?

Exactly which fields are covered by the signature and which are not. A reader
assessing this for a security review needs the boundary of the claim, not a
summary of it.

### 9. Repository map

One row per file that matters, with its purpose. Skip generated and vendored
files.

### 10. Evidence, security status, and limitations

What was executed, on what versions, with what result. Then what this reference
does not do, does not claim, and would need before production use.

Never soften this section. A reference that states its limits precisely is more
credible than one that implies it has none, and a reader who finds an
undisclosed limit stops trusting the rest.

## Visuals

At least two `mermaid` diagrams, and they must carry information the prose does
not.

**Required:**

- **A sequence diagram** in section 4, showing one request from user intent
  through to allow or deny. It must show the receiver as a distinct participant
  from the agent and the platform, because that separation is the whole idea.
- **A decision or role diagram**, in section 2 or 3, showing what is checked and
  by whom, with both outcomes visible.

**Rules, each one checkable by reading the diagram source:**

- Both branches always appear. A diagram that only shows the happy path is
  marketing, not documentation.
- Label edges with what is actually carried: "signed delegation", "proof
  bundle", "routed call + proof". Not "request" or "data".
- Render on GitHub without a plugin. `mermaid` in a fenced block, nothing else.
- **No semicolons inside a message.** A semicolon separates statements in a
  sequence diagram, so `DENY; tool untouched` ends the message at the semicolon
  and the remainder is parsed as a new statement. GitHub then shows "Unable to
  render rich display" where the diagram should be. Use a comma.
  `scripts/check-reference-readmes.py` rejects this, but the lint only knows the
  pitfalls it has been taught.
- **Every diagram is parsed in CI** by `scripts/mermaid-check`, which runs the
  real mermaid parser over every fenced block in the repository. The lint above
  catches one known pitfall; the parser catches the rest. To run it locally:

  ```bash
  cd scripts/mermaid-check && npm ci && node check.mjs
  ```

  If you would rather check a single diagram by hand before committing, paste it
  into the GitHub preview, or:

  ```bash
  npm install mermaid jsdom
  node -e '
    const {JSDOM} = require("jsdom");
    const dom = new JSDOM("<!doctype html><body></body>", {pretendToBeVisual: true});
    globalThis.window = dom.window; globalThis.document = dom.window.document;
    Object.defineProperty(globalThis, "navigator", {value: dom.window.navigator, configurable: true});
    import("mermaid").then(async ({default: m}) => {
      m.initialize({startOnLoad: false});
      await m.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      console.log("ok");
    }).catch(e => { console.error(e.message); process.exit(1); });
  ' diagram.mmd
  ```
- Never use a diagram to restate a table. If the diagram adds nothing the prose
  lacks, remove it.

## Language

- Name the platform's real strengths before naming the gap. A reference that
  reads as an attack on the platform will not be forwarded by anyone inside it.
- Use the protocol's own vocabulary: delegated-authority proof, portable
  authority proofs, verify before action.
- Give measurements, not adjectives. "Seven deterministic tests, zero skips"
  rather than "thoroughly tested".
- State the endorsement status once, near the top, in plain words.

## Before publication

Check every item:

- [ ] All ten sections present, in order
- [ ] "Who implements what" names every role including the platform, and says
      where the answer is nothing
- [ ] At least two mermaid diagrams, both branches shown, edges labelled with
      what they carry
- [ ] Every command runs from a clean checkout
- [ ] Prerequisites stated before the first step
- [ ] Test counts and skip counts are current, and match the registry entry
- [ ] Endorsement status stated plainly
- [ ] Limitations section names what a reader would otherwise discover themselves
- [ ] `scripts/check-reference-versions.py` passes
