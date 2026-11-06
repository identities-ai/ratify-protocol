package com.ratifyprotocol

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration.Companion.milliseconds

/**
 * The SDK worker: blocking calls run on SDK threads, and coroutine
 * cancellation and deadlines reach the call's token. Cancellation is
 * cooperative, so the call returns only after its body returns.
 */
class WorkerTest {
    @Test
    fun runsOnAnSdkThread() = runBlocking {
        assertTrue(onWorker { Thread.currentThread().name }.startsWith("ratify-protocol-worker-"))
    }

    @Test
    fun cancellationReachesTheTokenAndWaitsForTheBody() = runBlocking {
        val started = CompletableDeferred<Unit>()
        val sawCancel = AtomicBoolean(false)
        val bodyDone = AtomicBoolean(false)
        val call = async {
            onWorker { token ->
                started.complete(Unit)
                val deadline = System.nanoTime() + 10_000_000_000
                while (!token.isCancelled() && System.nanoTime() < deadline) Thread.sleep(1)
                sawCancel.set(token.isCancelled())
                Thread.sleep(50) // the body keeps running after cancellation
                bodyDone.set(true)
            }
        }
        started.await()
        call.cancel()
        val threw = try {
            call.await(); false
        } catch (e: CancellationException) {
            true
        }
        assertTrue(threw)
        assertTrue("the blocking body observed the coroutine's cancellation", sawCancel.get())
        assertTrue("the call returned only after the body finished", bodyDone.get())
    }

    @Test
    fun successfulWorkerResultSurvivesCancellation() = runBlocking {
        val started = CompletableDeferred<Unit>()
        val observed = AtomicReference<String?>()
        val call = launch {
            val value = onWorker { token ->
                started.complete(Unit)
                val deadline = System.nanoTime() + 10_000_000_000
                while (!token.isCancelled() && System.nanoTime() < deadline) Thread.sleep(1)
                "committed"
            }
            observed.set(value)
        }
        started.await()
        call.cancel()
        call.join()
        assertEquals("committed", observed.get())
    }

    @Test
    fun callbackCancelledBeforeDispatchStillFinishes() {
        val finished = CountDownLatch(1)
        val result = AtomicReference<Throwable?>()
        Thread {
            try { callbackWait(cancelled = { true }) { awaitCancellation() } }
            catch (e: Throwable) { result.set(e) }
            finally { finished.countDown() }
        }.apply { isDaemon = true }.start()
        assertTrue("cancelled callback must not strand its worker", finished.await(5, TimeUnit.SECONDS))
        assertTrue(result.get() is CancellationException)
    }

    @Test
    fun deadlineReachesTheToken() = runBlocking {
        val saw = onWorker(timeout = 30.milliseconds) { token ->
            val deadline = System.nanoTime() + 10_000_000_000
            while (!token.isCancelled() && System.nanoTime() < deadline) Thread.sleep(1)
            token.isCancelled()
        }
        assertTrue(saw)
    }

    @Test
    fun errorsPropagate() = runBlocking {
        val e = try {
            onWorker<Int> { throw RatifyException.Protocol(ErrorClass.CLAIM_STORE_UNAVAILABLE, "test") }
            null
        } catch (e: RatifyException) {
            e
        }
        assertEquals(ErrorClass.CLAIM_STORE_UNAVAILABLE, e?.errorClass)
    }
}
