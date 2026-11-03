import Foundation
import XCTest
@testable import RatifyProtocol

/// The SDK worker: blocking calls run on their own thread, and task
/// cancellation and deadlines reach the call's token. Cancellation is
/// cooperative, so the call returns only after its body returns.
final class WorkerTests: XCTestCase {
    func testRunsOffTheCallerThread() async throws {
        let name = try await onWorker { _ in Thread.current.name ?? "" }
        XCTAssertEqual(name, "ratify-protocol-worker")
    }

    func testTaskCancellationReachesTheTokenAndWaitsForTheBody() async throws {
        let started = expectation(description: "body started")
        let bodyDone = Flag()
        let task = Task {
            try await onWorker { token -> Bool in
                started.fulfill()
                let deadline = Date().addingTimeInterval(10)
                while !token.isCancelled() && Date() < deadline { usleep(1_000) }
                let saw = token.isCancelled()
                usleep(50_000) // the body keeps running after cancellation
                bodyDone.set()
                return saw
            }
        }
        await fulfillment(of: [started], timeout: 5)
        task.cancel()
        let sawCancel = try await task.value
        XCTAssertTrue(sawCancel, "the blocking body observed the task's cancellation")
        XCTAssertTrue(bodyDone.value, "the call returned only after the body finished")
    }

    func testDeadlineReachesTheToken() async throws {
        let sawDeadline = try await onWorker(timeout: .milliseconds(30)) { token -> Bool in
            let deadline = Date().addingTimeInterval(10)
            while !token.isCancelled() && Date() < deadline { usleep(1_000) }
            return token.isCancelled()
        }
        XCTAssertTrue(sawDeadline)
    }

    func testErrorsPropagateTyped() async {
        do {
            _ = try await onWorker { _ throws(RatifyError) -> Int in
                throw .protocol(.claimStoreUnavailable, message: "test")
            }
            XCTFail("no error")
        } catch {
            XCTAssertEqual(error.errorClass, .claimStoreUnavailable)
        }
    }
}

final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var v = false
    func set() { lock.lock(); v = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return v }
}
