import { readFileSync } from "node:fs";
import { monitorEventLoopDelay } from "node:perf_hooks";

import native from "./native/index.js";

const fixture = JSON.parse(readFileSync(new URL("../../testvectors/v1/happy_path_depth_3.json", import.meta.url), "utf8"));
const bundle = JSON.stringify(fixture.bundle);
const options = JSON.stringify(fixture.expected.verify_options);
const delay = monitorEventLoopDelay({ resolution: 1 });
delay.enable();
await new Promise((resolve) => setTimeout(resolve, 5));
await Promise.all(Array.from({ length: 2_000 }, () => native.verifyBundleJsonAsync(bundle, options)));
await new Promise((resolve) => setTimeout(resolve, 5));
delay.disable();
const maxMs = delay.max / 1_000_000;
console.log(`event_loop_max_delay_ms=${maxMs.toFixed(2)}`);
if (maxMs > 50) throw new Error("synchronous native verification blocks the Node event loop");
