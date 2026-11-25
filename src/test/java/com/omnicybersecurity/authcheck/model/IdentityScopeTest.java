package com.omnicybersecurity.authcheck.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One project can cover several apps, each with its own logins. An identity
 * scoped to app 1 must never be replayed against app 2.
 */
class IdentityScopeTest {

    @Test
    void anUnscopedIdentityAppliesEverywhere() {
        Identity identity = new Identity("id", "User");

        assertTrue(identity.appliesTo("https://app1.example.com/api/orders"));
        assertTrue(identity.appliesTo("https://app2.example.com/"));
    }

    @Test
    void aScopedIdentityAppliesOnlyToMatchingUrls() {
        Identity identity = new Identity("id", "App 1 user");
        identity.scopeRegex("^https://app1\\.example\\.com/");

        assertTrue(identity.appliesTo("https://app1.example.com/api/orders"));
        assertFalse(identity.appliesTo("https://app2.example.com/api/orders"));
        assertFalse(identity.appliesTo("https://app1.example.com.evil.test/"));
    }

    @Test
    void scopeCanSeparateAppsSharingAHost() {
        Identity identity = new Identity("id", "Billing user");
        identity.scopeRegex("^https://portal\\.example\\.com/billing/");

        assertTrue(identity.appliesTo("https://portal.example.com/billing/invoices"));
        assertFalse(identity.appliesTo("https://portal.example.com/hr/payslips"));
    }

    @Test
    void anInvalidScopeMatchesNothingRatherThanEverything() {
        // Falling open would replay the identity exactly where the tester tried
        // to fence it off.
        Identity identity = new Identity("id", "Typo");
        identity.scopeRegex("^https://app1.example.com/(");

        assertFalse(identity.appliesTo("https://app1.example.com/"));
    }

    @Test
    void aDuplicateKeepsTheScope() {
        Identity identity = new Identity("id", "App 1 user");
        identity.scopeRegex("app1");

        assertEquals("app1", identity.duplicate().scopeRegex());
    }
}
