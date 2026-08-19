package com.omnicybersecurity.authcheck.engine;

import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.support.FakeHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** What reaches the results table, and what is dropped before costing a replay. */
class TrafficFilterTest {

    private Settings settings;
    private TrafficFilter filter;

    @BeforeEach
    void setUp() {
        settings = new Settings();
        filter = new TrafficFilter(settings, url -> true);
    }

    // -- methods -------------------------------------------------------------

    @Test
    void optionsIsFilteredOutByDefault() {
        // A CORS preflight carries no authorisation decision, and testing one per
        // request would triple the traffic for nothing.
        assertFalse(filter.shouldTest(
                FakeHttp.requestFor("OPTIONS", "https://api.host/api/patients"), null));
    }

    @Test
    void theUsualMethodsStillGetTested() {
        for (String method : new String[] { "GET", "POST", "PUT", "PATCH", "DELETE" }) {
            assertTrue(filter.shouldTest(
                            FakeHttp.requestFor(method, "https://api.host/api/patients"), null),
                    method + " must still be tested");
        }
    }

    @Test
    void theMethodListIsConfigurable() {
        settings.skipMethods("OPTIONS, HEAD, TRACE");

        assertFalse(filter.shouldTest(FakeHttp.requestFor("HEAD", "https://api.host/x"), null));
        assertFalse(filter.shouldTest(FakeHttp.requestFor("TRACE", "https://api.host/x"), null));
        assertTrue(filter.shouldTest(FakeHttp.requestFor("GET", "https://api.host/x"), null));
    }

    @Test
    void methodMatchingIsCaseInsensitive() {
        settings.skipMethods("options");

        assertFalse(filter.shouldTest(FakeHttp.requestFor("OPTIONS", "https://api.host/x"), null));
    }

    @Test
    void clearingTheListTestsEveryMethod() {
        settings.skipMethods("");

        assertTrue(filter.shouldTest(FakeHttp.requestFor("OPTIONS", "https://api.host/x"), null));
    }

    @Test
    void theReasonNamesTheMethodSoTheUiCanExplainItself() {
        String reason = filter.rejectionReason(
                FakeHttp.requestFor("OPTIONS", "https://api.host/x"), null);

        assertNotNull(reason);
        assertTrue(reason.contains("OPTIONS"), () -> "reason was: " + reason);
    }

    // -- the rules that already existed, now covered -------------------------

    @Test
    void outOfScopeTrafficIsSkippedWhenScopeIsEnforced() {
        TrafficFilter scoped = new TrafficFilter(settings, url -> false);

        assertEquals("out of scope",
                scoped.rejectionReason(FakeHttp.requestFor("GET", "https://api.host/x"), null));
    }

    @Test
    void scopeIsIgnoredWhenTheSettingIsOff() {
        settings.onlyInScope(false);
        TrafficFilter scoped = new TrafficFilter(settings, url -> false);

        assertTrue(scoped.shouldTest(FakeHttp.requestFor("GET", "https://api.host/x"), null));
    }

    @Test
    void staticResourcesAreSkipped() {
        assertFalse(filter.shouldTest(
                FakeHttp.requestFor("GET", "https://api.host/assets/app.js"), null));
        assertTrue(filter.shouldTest(
                FakeHttp.requestFor("GET", "https://api.host/api/patients"), null));
    }

    @Test
    void filteredBaselineStatusesAreSkipped() {
        assertFalse(filter.shouldTest(
                FakeHttp.requestFor("GET", "https://api.host/api/missing"),
                FakeHttp.response(404, "")));
    }

    @Test
    void urlIncludeAndExcludePatternsAreApplied() {
        settings.includeUrlRegex("/api/");
        assertTrue(filter.shouldTest(FakeHttp.requestFor("GET", "https://api.host/api/x"), null));
        assertFalse(filter.shouldTest(FakeHttp.requestFor("GET", "https://api.host/web/x"), null));

        settings.includeUrlRegex("");
        settings.excludeUrlRegex("/health");
        assertFalse(filter.shouldTest(FakeHttp.requestFor("GET", "https://api.host/health"), null));
    }

    @Test
    void anOrdinaryApiCallSurvivesEveryRule() {
        assertNull(filter.rejectionReason(
                FakeHttp.requestFor("GET", "https://api.host/api/orgs/5207/patients?q=Ahr"),
                FakeHttp.response(200, "{}")));
    }
}
