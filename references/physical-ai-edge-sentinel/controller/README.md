# Controller

Demonstration principal, status publisher, and agent. It keeps four key pairs
as seed files in its own directory (root, status, agent, and an unrelated
"rogue" root), issues v2 delegations, publishes signed status with the
separate status key, provisions a receiver's trust directory, and presents
proofs. It has no actuator path; every action goes through the receiver.

```sh
controller init ctl
controller provision ctl trust --checkpoint-pub ckpt/checkpoint_pub.json
controller delegate ctl cert.json --cert-id edge-cert-1
controller act ctl --cert cert.json --zone greenhouse-b --resource irrigation-valve-3 --ms 500
controller revoke ctl --cert-id edge-cert-1
```

The keys are plain files for demonstration only. A deployment keeps the root
and status keys in an HSM or KMS behind `RatifyV2ExternalSigner`.
