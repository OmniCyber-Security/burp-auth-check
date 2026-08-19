package com.omnicybersecurity.authcheck.engine;

import com.omnicybersecurity.authcheck.TestApis;
import com.omnicybersecurity.authcheck.support.FakeHttp;
import com.omnicybersecurity.authcheck.config.ConfigStore;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.model.Verdict;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The verdict rules -- the part that decides whether you have a finding. */
class ResponseAnalyserTest {

    private Configuration configuration;
    private ResponseAnalyser analyser;

    private static final String OWNER_PAGE = """
            <html><body><h1>Order 1001</h1>
            <p>Customer: Alice Anderson</p>
            <p>Card ending 4242, shipped to 14 Mill Lane</p>
            <p>Total: 249.99</p></body></html>
            """;

    @BeforeEach
    void setUp() {
        configuration = new Configuration(new ConfigStore(TestApis.montoyaApi()));
        analyser = new ResponseAnalyser(TestApis.montoyaApi(), configuration);
    }

    @Test
    void identicalSuccessfulResponseIsABypass() {
        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, OWNER_PAGE),
                FakeHttp.response(200, OWNER_PAGE));

        assertEquals(Verdict.BYPASSED, analysis.verdict());
        assertEquals(1.0, analysis.similarity(), 0.001);
    }

    @Test
    void deniedStatusCodeIsEnforcement() {
        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, OWNER_PAGE),
                FakeHttp.response(403, "Forbidden"));

        assertEquals(Verdict.ENFORCED, analysis.verdict());
        assertTrue(analysis.detail().contains("403"));
    }

    @Test
    void denialTextInATwoHundredIsStillEnforcement() {
        // Plenty of apps return 200 with an error body.
        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, OWNER_PAGE),
                FakeHttp.response(200, "{\"error\":\"Access denied for this resource\"}"));

        assertEquals(Verdict.ENFORCED, analysis.verdict());
    }

    @Test
    void redirectToLoginIsEnforcement() {
        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, OWNER_PAGE),
                FakeHttp.response(302, "", Map.of("Location", "https://target.example.com/login?next=/orders/1")));

        assertEquals(Verdict.ENFORCED, analysis.verdict());
        assertTrue(analysis.detail().contains("login"));
    }

    @Test
    void redirectElsewhereIsNotAssumedToBeEnforcement() {
        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, OWNER_PAGE),
                FakeHttp.response(302, "", Map.of("Location", "/orders/1/summary")));

        assertEquals(Verdict.NEEDS_REVIEW, analysis.verdict());
    }

    @Test
    void ownDataForTheSameEndpointIsReviewNotBypass() {
        // The second user gets a 200, but it is their own record. Reporting this
        // as a bypass is the classic false positive.
        String otherUsersPage = """
                <html><body><h1>Order 2002</h1>
                <p>Customer: Bob Brown</p>
                <p>Card ending 1111, shipped to 3 Dock Road</p>
                <p>Total: 12.50</p></body></html>
                """;

        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, OWNER_PAGE),
                FakeHttp.response(200, otherUsersPage));

        assertEquals(Verdict.NEEDS_REVIEW, analysis.verdict());
        assertTrue(analysis.similarity() < 0.95,
                () -> "different customers' data should not look identical, got " + analysis.similarity());
    }

    @Test
    void perSessionNoiseDoesNotBreakTheSamenessCheck() {
        // Same page, different CSRF token: still a bypass.
        String withTokenA = OWNER_PAGE + "<input name=csrf value=8f2b19c4d5e6f7a8b9c0d1e2f3a4b5c6>";
        String withTokenB = OWNER_PAGE + "<input name=csrf value=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d>";

        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, withTokenA),
                FakeHttp.response(200, withTokenB));

        assertEquals(Verdict.BYPASSED, analysis.verdict());
    }

    @Test
    void unsuccessfulBaselineNeverProducesABypass() {
        // Two matching 404s prove nothing about authorisation.
        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(404, "Not found"),
                FakeHttp.response(404, "Not found"));

        assertEquals(Verdict.NEEDS_REVIEW, analysis.verdict());
        assertTrue(analysis.detail().contains("404"), () -> "detail was: " + analysis.detail());
    }

    @Test
    void serverErrorOnTheReplayIsFlaggedForReview() {
        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, OWNER_PAGE),
                FakeHttp.response(500, "Internal server error"));

        assertEquals(Verdict.NEEDS_REVIEW, analysis.verdict());
    }

    @Test
    void missingResponseIsAnError() {
        ResponseAnalyser.Analysis analysis = analyser.analyse(FakeHttp.response(200, OWNER_PAGE), null);

        assertEquals(Verdict.ERROR, analysis.verdict());
    }

    @Test
    void thresholdIsRespected() {
        configuration.settings().sameThresholdPercent(100);
        String almost = OWNER_PAGE.replace("249.99", "249.98");

        assertEquals(Verdict.NEEDS_REVIEW,
                analyser.analyse(FakeHttp.response(200, OWNER_PAGE), FakeHttp.response(200, almost)).verdict());

        configuration.settings().sameThresholdPercent(80);
        assertEquals(Verdict.BYPASSED,
                analyser.analyse(FakeHttp.response(200, OWNER_PAGE), FakeHttp.response(200, almost)).verdict());
    }

    @Test
    void customDenialPatternIsHonoured() {
        configuration.settings().deniedBodyRegex("(?i)nope, not yours");

        ResponseAnalyser.Analysis analysis = analyser.analyse(
                FakeHttp.response(200, OWNER_PAGE),
                FakeHttp.response(200, "Nope, not yours"));

        assertEquals(Verdict.ENFORCED, analysis.verdict());
    }

    // -- the similarity primitive -------------------------------------------

    @Test
    void diceScoresIdenticalTextAsOne() {
        assertEquals(1.0, ResponseAnalyser.dice("hello world hello world", "hello world hello world"), 0.0001);
    }

    @Test
    void diceIgnoresWhitespaceFormatting() {
        assertEquals(1.0, ResponseAnalyser.dice("a b   c\n d", "a b c d"), 0.0001);
    }

    @Test
    void diceScoresUnrelatedTextLow() {
        double score = ResponseAnalyser.dice(
                "the quick brown fox jumps over the lazy dog",
                "zzzz yyyy xxxx wwww vvvv uuuu tttt ssss rrrr");
        assertTrue(score < 0.2, () -> "expected a low score, got " + score);
    }

    @Test
    void diceTreatsEmptyBodiesAsIdentical() {
        assertEquals(1.0, ResponseAnalyser.dice("", ""), 0.0001);
        assertEquals(0.0, ResponseAnalyser.dice("", "something"), 0.0001);
    }

    // -- token masking: must kill session noise without hiding real data ----

    @Test
    void maskingHidesTokenLikeRuns() {
        // The field name must survive; only the value is masked.
        assertEquals("csrf=" + ResponseAnalyser.TOKEN_PLACEHOLDER,
                ResponseAnalyser.maskHighEntropyTokens("csrf=8f2b19c4d5e6f7a8b9c0d1e2f3a4b5c6"));
    }

    @Test
    void maskingLeavesUserDataAlone() {
        // Names, addresses, prices and short ids are what tell two users' records
        // apart, so masking any of them would invent bypasses.
        String data = "Customer: Alice Anderson, 14 Mill Lane, total 249.99, order 1001";
        assertEquals(data, ResponseAnalyser.maskHighEntropyTokens(data));
    }

    @Test
    void maskingLeavesLongPureNumbersAlone() {
        // A 19-digit account number is data, not a session token.
        String data = "account 1234567890123456789";
        assertEquals(data, ResponseAnalyser.maskHighEntropyTokens(data));
    }

    @Test
    void maskingHandlesSeveralTokensInOneBody() {
        String token = ResponseAnalyser.TOKEN_PLACEHOLDER;
        String masked = ResponseAnalyser.maskHighEntropyTokens(
                "a=abc123def456ghi789 b=plain c=zzz999yyy888xxx777");
        assertEquals("a=" + token + " b=plain c=" + token, masked);
    }

    @Test
    void maskingIsANoOpForShortBodies() {
        assertEquals("ok", ResponseAnalyser.maskHighEntropyTokens("ok"));
    }

    @Test
    void differentSessionTokensDoNotHideDifferentUserData() {
        // Both effects at once: same template, different customer, different CSRF.
        // The customer difference must still win.
        String owner = OWNER_PAGE + "<input name=csrf value=8f2b19c4d5e6f7a8b9c0d1e2f3a4b5c6>";
        String other = """
                <html><body><h1>Order 2002</h1>
                <p>Customer: Bob Brown</p>
                <p>Card ending 1111, shipped to 3 Dock Road</p>
                <p>Total: 12.50</p></body></html>
                """ + "<input name=csrf value=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d>";

        assertEquals(Verdict.NEEDS_REVIEW,
                analyser.analyse(FakeHttp.response(200, owner), FakeHttp.response(200, other)).verdict());
    }
}
