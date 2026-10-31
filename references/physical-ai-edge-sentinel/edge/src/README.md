# Edge receiver source

| File | Purpose |
| --- | --- |
| `main.c` | Daemon entry point: `--init`, actuator selection, listener |
| `http.c` | Bounded HTTP/1.1 listener: `/challenge`, `/action`, `/status`, `/health` |
| `verifier.c` | v2 decision path, release, local policy, release gate |
| `store.c` | Durable Part B stores behind the library's callback structs, anchored in the checkpoint |
| `ckpt_client.c` | Client for the checkpoint; accepts only answers signed by the pinned checkpoint key |
| `trust.c` | Trust directory: pinned keys, role separation, local policy |
| `actx.c` | Action context and session context, shared with the controller |
| `clock.c` | RTC clock; fixture clock in test builds only |
| `util.c` | base64, hex, SHA-256, SHA-384, durable file writes |
