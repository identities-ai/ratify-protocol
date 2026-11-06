import XCTest

enum ConcurrencyRunner {
    static func run() async throws {
        let tests = ClaimTests(selector: #selector(ClaimTests.corpusHarness))
        let runners: [String: () async throws -> Void] = [
            "same_challenge_claim_storm": tests.testConcurrentClaimStormHasOneCommit,
            "same_challenge_claim_storm_store_level": tests.testConcurrentClaimsRecoverOnceAfterLease,
            "conflicting_proofs_for_one_challenge": tests.testConcurrentConflictingProofsSealOneChallenge,
            "owner_finalize_races_lease_expiry_and_recovery": tests.testConcurrentOwnerFinalizeAgainstLeaseExpiryRecovery,
            "recovery_races_after_owner_committed": tests.testConcurrentRecoveryCannotReplaceCommittedAllow,
            "late_worker_finalize_after_recovery": tests.testConcurrentLateOwnerCannotReplaceRecovery,
            "cancel_races_finalization": tests.testConcurrentCancellationAgainstFinalization,
            "concurrent_identical_retries": tests.testConcurrentIdenticalFinalizationsAndProofRetries,
            "concurrent_identical_recoveries": tests.testConcurrentIdenticalRecoveriesCommitOnce,
            "release_while_acknowledgement_lands": tests.testConcurrentReleaseWhileAcknowledgementLands,
            "concurrent_release_of_one_decision": tests.testConcurrentReleaseIsIdentical,
            "concurrent_stream_advances": tests.testConcurrentStreamAdvanceAdmitsOneSequenceTwo,
            "rate_admission_under_contention": tests.testConcurrentRateAdmissionHasTwoWinners,
            "rate_two_counter_admission_under_contention": tests.testConcurrentTwoCounterRateAdmissionIsAtomic,
            "resume_races_owner_finalize": tests.testConcurrentResumeSeesOwnerFinalizeOrLiveLease,
            "resume_races_lease_expiry_recovery": tests.testConcurrentResumeDuringLeaseExpiryRecovery,
            "resume_races_owner_allow_finalize": tests.testConcurrentResumeAndReleaseDuringOwnerAllowFinalize,
            "concurrent_resumes_and_releases_of_one_allow": tests.testConcurrentResumeAndReleaseOfOneAllow,
        ]
        let scenarios = Corpus.load("concurrency-scenarios.json").arr("scenarios").map { $0.s("name") }
        XCTAssertEqual(Set(runners.keys), Set(scenarios))
        let tally = Tally("concurrency-scenarios.json")
        for name in scenarios {
            let runner = try XCTUnwrap(runners[name])
            try await runner()
            tally.check("scenarios", name, true)
        }
        tally.finish([("scenarios", scenarios.count)])
    }
}
