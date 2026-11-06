import Foundation

/// Runs one blocking FFI call off the caller's executor (build plan §2.4).
///
/// Each call gets its own SDK thread, never the cooperative pool or the main
/// thread, so a call that waits on a callback cannot starve the executor the
/// callback needs. The call's `FfiCancelToken` is cancelled when the calling
/// task is cancelled (or its deadline passes); cancellation is cooperative,
/// so this returns only after the Rust call itself returns.
func onWorker<T: Sendable>(
    timeout: Duration? = nil,
    _ body: @escaping @Sendable (FfiCancelToken) throws(RatifyError) -> T
) async throws(RatifyError) -> T {
    let token = try ffi { try FfiCancelToken(timeoutMs: timeout.map(milliseconds)) }
    let handoff = NSLock()
    let result: Result<T, RatifyError> = await withTaskCancellationHandler {
        await withCheckedContinuation { (cont: CheckedContinuation<Result<T, RatifyError>, Never>) in
            let thread = Thread {
                let value = Result { () throws(RatifyError) in try body(token) }
                handoff.withLock { cont.resume(returning: value) }
            }
            thread.name = "ratify-protocol-worker"
            thread.start()
        }
    } onCancel: {
        _ = try? token.cancel()
    }
    handoff.withLock { }
    return try result.get()
}

private func milliseconds(_ d: Duration) -> UInt64 {
    let (s, attos) = d.components
    return UInt64(max(0, s)) * 1000 + UInt64(max(0, attos)) / 1_000_000_000_000_000
}
