package com.ratifyprotocol

import org.junit.Assert.assertEquals

object ConcurrencyVectors {
    fun run() {
        val tests = ClaimTest()
        val runners: Map<String, () -> Unit> = mapOf(
            "same_challenge_claim_storm" to tests::concurrentClaimStormHasOneCommit,
            "same_challenge_claim_storm_store_level" to tests::concurrentClaimsRecoverOnceAfterLease,
            "conflicting_proofs_for_one_challenge" to tests::concurrentConflictingProofsSealOneChallenge,
            "owner_finalize_races_lease_expiry_and_recovery" to tests::concurrentOwnerFinalizeAgainstLeaseExpiryRecovery,
            "recovery_races_after_owner_committed" to tests::concurrentRecoveryCannotReplaceCommittedAllow,
            "late_worker_finalize_after_recovery" to tests::concurrentLateOwnerCannotReplaceRecovery,
            "cancel_races_finalization" to tests::concurrentCancellationAgainstFinalization,
            "concurrent_identical_retries" to tests::concurrentIdenticalFinalizationsAndProofRetries,
            "concurrent_identical_recoveries" to tests::concurrentIdenticalRecoveriesCommitOnce,
            "release_while_acknowledgement_lands" to tests::concurrentReleaseWhileAcknowledgementLands,
            "concurrent_release_of_one_decision" to tests::concurrentReleaseIsIdentical,
            "concurrent_stream_advances" to tests::concurrentStreamAdvanceAdmitsOneSequenceTwo,
            "rate_admission_under_contention" to tests::concurrentRateAdmissionHasTwoWinners,
            "rate_two_counter_admission_under_contention" to tests::concurrentTwoCounterRateAdmissionIsAtomic,
            "resume_races_owner_finalize" to tests::concurrentResumeSeesOwnerFinalizeOrLiveLease,
            "resume_races_lease_expiry_recovery" to tests::concurrentResumeDuringLeaseExpiryRecovery,
            "resume_races_owner_allow_finalize" to tests::concurrentResumeAndReleaseDuringOwnerAllowFinalize,
            "concurrent_resumes_and_releases_of_one_allow" to tests::concurrentResumeAndReleaseOfOneAllow,
        )
        val scenarios = Corpus.load("concurrency-scenarios.json").arr("scenarios").map { it.getString("name") }
        assertEquals(scenarios.toSet(), runners.keys)
        val tally = Tally("concurrency-scenarios.json")
        for (name in scenarios) {
            checkNotNull(runners[name]) { name }()
            tally.check("scenarios", name, true)
        }
        tally.finish(listOf("scenarios" to scenarios.size))
    }
}
