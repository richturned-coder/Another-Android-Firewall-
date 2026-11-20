package org.aafw.firewall

import java.lang.reflect.InvocationTargetException
import java.security.Provider
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Regression test for CVE-2026-8763 (GHSA-9pwp-9qqc-pr26):
 * Bouncy Castle Name Constraints bypass via trailing dot in rfc822Name and URI.
 *
 * Uses reflection so the app does not introduce a direct compile dependency on Bouncy Castle while
 * still verifying the transitive runtime version resolved on the test classpath (via Robolectric).
 */
class BouncyCastleNameConstraintsRegressionTest {

    @Test
    fun bouncyCastleProviderIsPatchedAgainstCve20268763() {
        val providerClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
        val provider = providerClass.getDeclaredConstructor().newInstance() as Provider
        val versionParts = provider.versionStr.split(".").mapNotNull { it.toIntOrNull() }
        assertTrue(
            "Expected Bouncy Castle >= 1.85 to remediate CVE-2026-8763, found ${provider.versionStr}",
            versionParts.size >= 2 &&
                (versionParts[0] > 1 || (versionParts[0] == 1 && versionParts[1] >= 85))
        )
    }

    @Test
    fun nameConstraintValidatorRejectsTrailingDotInRfc822NameAndUri() {
        val generalNameClass = Class.forName("org.bouncycastle.asn1.x509.GeneralName")
        val generalSubtreeClass = Class.forName("org.bouncycastle.asn1.x509.GeneralSubtree")
        val validatorClass = Class.forName("org.bouncycastle.asn1.x509.PKIXNameConstraintValidator")
        val exceptionClass = Class.forName("org.bouncycastle.asn1.x509.NameConstraintValidatorException")

        val generalNameCtor = generalNameClass.getConstructor(Int::class.javaPrimitiveType, String::class.java)
        val generalSubtreeCtor = generalSubtreeClass.getConstructor(generalNameClass)
        val addExcluded = validatorClass.getMethod("addExcludedSubtree", generalSubtreeClass)
        val checkExcluded = validatorClass.getMethod("checkExcluded", generalNameClass)

        val rfc822Tag = generalNameClass.getField("rfc822Name").getInt(null)
        val uriTag = generalNameClass.getField("uniformResourceIdentifier").getInt(null)

        // 1. rfc822Name trailing-dot bypass check
        val emailValidator = validatorClass.getDeclaredConstructor().newInstance()
        val excludedEmailSubtree = generalSubtreeCtor.newInstance(
            generalNameCtor.newInstance(rfc822Tag, "forbidden.example")
        )
        addExcluded.invoke(emailValidator, excludedEmailSubtree)

        val trailingDotEmail = generalNameCtor.newInstance(rfc822Tag, "user@forbidden.example.")
        try {
            checkExcluded.invoke(emailValidator, trailingDotEmail)
            fail("Expected trailing-dot rfc822Name to be rejected by excluded subtree")
        } catch (e: InvocationTargetException) {
            assertTrue(
                "Expected NameConstraintValidatorException, got ${e.targetException}",
                exceptionClass.isInstance(e.targetException)
            )
        }

        // 2. URI trailing-dot bypass check
        val uriValidator = validatorClass.getDeclaredConstructor().newInstance()
        val excludedUriSubtree = generalSubtreeCtor.newInstance(
            generalNameCtor.newInstance(uriTag, "forbidden.example")
        )
        addExcluded.invoke(uriValidator, excludedUriSubtree)

        val trailingDotUri = generalNameCtor.newInstance(uriTag, "https://forbidden.example./path")
        try {
            checkExcluded.invoke(uriValidator, trailingDotUri)
            fail("Expected trailing-dot URI to be rejected by excluded subtree")
        } catch (e: InvocationTargetException) {
            assertTrue(
                "Expected NameConstraintValidatorException, got ${e.targetException}",
                exceptionClass.isInstance(e.targetException)
            )
        }
    }
}
