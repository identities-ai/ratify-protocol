# Scenarios

The deterministic v2 scenario matrix is `../edge/tests/scenarios.sh`. It runs
the test builds with a fixture clock and the mock actuator, issues a fresh
challenge for every row that reaches verification, and asserts each row's
recorded stage and outcome and whether the actuator fired. Its results are in
`../docs/evidence.md`.

Use canonical Ratify scopes such as `infrastructure:monitor` and
`physical:actuate`; these are scopes, not action names. The action (zone,
resource, duration, invocation) travels in request headers and is bound into
the challenge's session context.

The matrix starts one receiver without the quarantine override and checks that
actuation is refused during the post-boot quarantine; the other rows use the
test-only override. The override does not exist in the production binary.
