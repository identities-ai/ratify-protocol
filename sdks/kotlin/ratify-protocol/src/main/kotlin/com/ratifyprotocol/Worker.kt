package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiCancelToken
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration

/**
 * The SDK's own worker threads (build plan §2.4): an unbounded cached pool,
 * never Dispatchers.Default, so a call that waits on a callback cannot starve
 * the dispatcher the callback needs. Callback bodies never run here.
 */
internal object Workers {
    private val n = AtomicInteger()
    val pool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "ratify-protocol-worker-${n.incrementAndGet()}").apply { isDaemon = true }
    }
}

/**
 * Runs one blocking FFI call on an SDK worker thread. Cancelling the calling
 * coroutine (or passing [timeout]) cancels the call's token; cancellation is
 * cooperative, so this returns only after the Rust call itself returns.
 */
internal suspend fun <T> onWorker(timeout: Duration? = null, body: (FfiCancelToken) -> T): T {
    val token = ffi { FfiCancelToken(timeout?.inWholeMilliseconds?.toULong()) }
    // Awaiting a CompletableDeferred and being cancelled does not cancel the
    // deferred, so the body's completion can still be awaited afterwards.
    val done = CompletableDeferred<Result<T>>()
    Workers.pool.execute { done.complete(runCatching { body(token) }) }
    try {
        return done.await().getOrThrow()
    } catch (e: CancellationException) {
        runCatching { token.cancel() }
        withContext(NonCancellable) { done.await() }
        throw e
    }
}
