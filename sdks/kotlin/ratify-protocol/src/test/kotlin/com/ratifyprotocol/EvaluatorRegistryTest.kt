package com.ratifyprotocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EvaluatorRegistryTest {
    @Test fun registryValidatesAndFreezesProfiles() {
        val descriptor = ConstraintProfileDescriptor("com.example.limit/v1", "com.example.limit")
        val entry = ConstraintEvaluatorRegistration(descriptor, object : ConstraintEvaluator {
            override suspend fun evaluate(input: ConstraintEvaluationInput) =
                ConstraintEvaluationResult(ConstraintOutcome.PASS)
        })
        val registry = ConstraintEvaluatorRegistry(100u, listOf(entry))
        assertEquals(100uL, registry.timeoutMilliseconds)
        assertEquals(listOf("com.example.limit"), registry.refs().map { it.kind })
        assertEquals(constraintProfileDigest(descriptor), registry.refs().first().profileDigest)
        assertTrue(runCatching { ConstraintEvaluatorRegistry(0u, listOf(entry)) }.isFailure)
        assertTrue(runCatching { ConstraintEvaluatorRegistry(100u, listOf(entry, entry)) }.isFailure)
    }
}
