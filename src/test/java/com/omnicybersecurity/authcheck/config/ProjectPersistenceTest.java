package com.omnicybersecurity.authcheck.config;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.omnicybersecurity.authcheck.model.AuthTestRecord;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.model.VariantResult;
import com.omnicybersecurity.authcheck.model.Verdict;
import com.omnicybersecurity.authcheck.support.FakeHttp;
import com.omnicybersecurity.authcheck.support.FakePersistence;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trips everything the extension keeps in the Burp project: identities and
 * their auth scripts, the tested requests and responses, and the login traffic
 * each script generated.
 *
 * <p>Every case runs against both child-object semantics, because the API does
 * not promise which one Burp implements.
 */
class ProjectPersistenceTest {

    // -- identities, credentials and scripts --------------------------------

    @Test
    void identitiesCredentialsAndScriptsSurviveAReopen() {
        forBothPersistenceModes(persistence -> {
            ConfigStore store = new ConfigStore(persistence.api());
            Settings settings = new Settings();

            Identity user = new Identity("id-1", "User 1");
            user.authScript("return [headers: ['Authorization': \"Bearer ${creds.token}\"]]");
            user.credentials().put("username", "alice");
            user.credentials().put("token", "s3cr3t");
            user.sessionInvalidRegex("(?i)token_expired");
            user.refreshIntervalSeconds(240);
            settings.maxPersistedRecords(123);
            settings.persistOnlyInteresting(true);

            store.save(settings, List.of(user));

            Settings reopened = new Settings();
            List<Identity> restored = new ArrayList<>();
            new ConfigStore(persistence.api()).load(reopened, restored);

            assertEquals(1, restored.size());
            Identity back = restored.get(0);
            assertEquals("User 1", back.name());
            assertEquals(user.authScript(), back.authScript(), "the auth script must come back verbatim");
            assertEquals("alice", back.credentials().get("username"));
            assertEquals("s3cr3t", back.credentials().get("token"));
            assertEquals("(?i)token_expired", back.sessionInvalidRegex());
            assertEquals(240, back.refreshIntervalSeconds());
            assertEquals(123, reopened.maxPersistedRecords());
            assertTrue(reopened.persistOnlyInteresting());
        });
    }

    @Test
    void identityOrderIsPreserved() {
        forBothPersistenceModes(persistence -> {
            ConfigStore store = new ConfigStore(persistence.api());
            List<Identity> original = List.of(
                    new Identity("c", "Third"), new Identity("a", "First"), new Identity("b", "Second"));
            store.save(new Settings(), original);

            List<Identity> restored = new ArrayList<>();
            store.load(new Settings(), restored);

            assertEquals(List.of("Third", "First", "Second"),
                    restored.stream().map(Identity::name).toList());
        });
    }

    // -- tested requests and responses --------------------------------------

    @Test
    void testedRequestsAndResponsesSurviveAReopen() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            repository.append(record(1, "GET", 200, Verdict.BYPASSED, "reached the resource"));
            repository.append(record(2, "POST", 403, Verdict.ENFORCED, "denied"));
            repository.shutdown();

            List<AuthTestRecord> restored = new ResultsRepository(persistence.api(), settings).load();

            assertEquals(2, restored.size());
            AuthTestRecord first = restored.get(0);
            assertEquals(1, first.index());
            assertEquals("Manual", first.source());

            assertNotNull(first.baseline(), "the baseline exchange must be stored");
            assertEquals("GET", first.baseline().request().method());
            assertEquals((short) 200, first.baseline().response().statusCode());

            VariantResult variant = first.result("id-user-2");
            assertNotNull(variant, "the identity's replay must be stored");
            assertEquals(Verdict.BYPASSED, variant.verdict());
            assertEquals("User 2", variant.label());
            assertEquals("reached the resource", variant.detail());
            assertNotNull(variant.exchange(), "the replayed request and response must be stored");
            assertEquals((short) 200, variant.exchange().response().statusCode());
        });
    }

    @Test
    void verdictSimilarityAndFlagsRoundTrip() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            Map<String, VariantResult> results = new LinkedHashMap<>();
            results.put(Identity.UNAUTHENTICATED_KEY, new VariantResult(Identity.UNAUTHENTICATED_KEY,
                    "Unauthenticated", Verdict.BYPASSED, 0.9876, "anonymous access worked", true,
                    exchange("GET", 200)));
            repository.append(new AuthTestRecord(7, "Proxy", exchange("GET", 200), results, true,
                    "endpoint appears public"));
            repository.shutdown();

            AuthTestRecord restored = new ResultsRepository(persistence.api(), settings).load().get(0);

            assertTrue(restored.publicEndpoint());
            assertEquals("endpoint appears public", restored.note());
            VariantResult variant = restored.result(Identity.UNAUTHENTICATED_KEY);
            assertEquals(0.9876, variant.similarity(), 0.0001);
            assertTrue(variant.reAuthed());
            assertEquals("Unauthenticated", variant.label());
        });
    }

    @Test
    void recordsWithoutAReplayStillRoundTrip() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            Map<String, VariantResult> results = new LinkedHashMap<>();
            results.put("id-user-2", VariantResult.failed("id-user-2", "User 2",
                    Verdict.AUTH_FAILED, "login script threw"));
            repository.append(new AuthTestRecord(3, "Manual", exchange("GET", 200), results, false, ""));
            repository.shutdown();

            VariantResult restored = new ResultsRepository(persistence.api(), settings)
                    .load().get(0).result("id-user-2");

            assertEquals(Verdict.AUTH_FAILED, restored.verdict());
            assertNull(restored.exchange(), "there was no replay to store");
            assertEquals("login script threw", restored.detail());
        });
    }

    @Test
    void storedResultsAreCappedSoTheProjectDoesNotGrowForever() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            settings.maxPersistedRecords(3);
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            for (int index = 1; index <= 6; index++) {
                repository.append(record(index, "GET", 200, Verdict.ENFORCED, "denied"));
            }
            repository.shutdown();

            List<AuthTestRecord> restored = new ResultsRepository(persistence.api(), settings).load();

            assertEquals(3, restored.size());
            assertEquals(List.of(4, 5, 6), restored.stream().map(AuthTestRecord::index).toList(),
                    "the newest results are the ones kept");
        });
    }

    @Test
    void storageCanBeTurnedOff() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            settings.persistResults(false);
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            repository.append(record(1, "GET", 200, Verdict.BYPASSED, "reached it"));
            repository.shutdown();

            assertTrue(new ResultsRepository(persistence.api(), settings).load().isEmpty());
        });
    }

    @Test
    void uninterestingResultsCanBeLeftOut() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            settings.persistOnlyInteresting(true);
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            repository.append(record(1, "GET", 200, Verdict.ENFORCED, "denied"));
            repository.append(record(2, "GET", 200, Verdict.BYPASSED, "reached it"));
            repository.append(record(3, "GET", 200, Verdict.NEEDS_REVIEW, "different content"));
            repository.shutdown();

            List<AuthTestRecord> restored = new ResultsRepository(persistence.api(), settings).load();

            assertEquals(List.of(2, 3), restored.stream().map(AuthTestRecord::index).toList(),
                    "enforced rows are the ones not worth the disk space");
        });
    }

    @Test
    void clearingRemovesStoredResults() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();
            repository.append(record(1, "GET", 200, Verdict.BYPASSED, "reached it"));
            repository.clear();
            repository.shutdown();

            assertTrue(new ResultsRepository(persistence.api(), settings).load().isEmpty());
        });
    }

    // -- login traffic ------------------------------------------------------

    @Test
    void loginTrafficIsStoredWithTheIdentity() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            repository.storeAuthTranscript("id-user-2", List.of(
                    exchange("GET", 200), exchange("POST", 302)));
            repository.shutdown();

            List<HttpRequestResponse> restored =
                    new ResultsRepository(persistence.api(), settings).loadAuthTranscript("id-user-2");

            assertEquals(2, restored.size(), "the whole login flow must be kept");
            assertEquals("GET", restored.get(0).request().method());
            assertEquals("POST", restored.get(1).request().method());
            assertEquals((short) 302, restored.get(1).response().statusCode());
        });
    }

    @Test
    void loginTrafficIsReplacedNotAppendedOnEachLogin() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            repository.storeAuthTranscript("id-user-2", List.of(exchange("GET", 200), exchange("POST", 302)));
            repository.storeAuthTranscript("id-user-2", List.of(exchange("POST", 201)));
            repository.shutdown();

            List<HttpRequestResponse> restored =
                    new ResultsRepository(persistence.api(), settings).loadAuthTranscript("id-user-2");

            assertEquals(1, restored.size(), "only the most recent login is kept");
            assertEquals((short) 201, restored.get(0).response().statusCode());
        });
    }

    @Test
    void deletingAnIdentityDropsItsLoginTraffic() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();

            repository.storeAuthTranscript("id-user-2", List.of(exchange("POST", 200)));
            repository.forgetIdentity("id-user-2");
            repository.shutdown();

            assertTrue(new ResultsRepository(persistence.api(), settings)
                    .loadAuthTranscript("id-user-2").isEmpty());
        });
    }

    @Test
    void missingLoginTrafficIsEmptyNotAnError() {
        forBothPersistenceModes(persistence -> {
            ResultsRepository repository = new ResultsRepository(persistence.api(), new Settings());
            assertTrue(repository.loadAuthTranscript("never-seen").isEmpty());
            repository.shutdown();
        });
    }

    // -- results and configuration must not tread on each other -------------

    @Test
    void resultsAndConfigurationCoexistInOneProject() {
        forBothPersistenceModes(persistence -> {
            Settings settings = new Settings();
            ConfigStore store = new ConfigStore(persistence.api());

            Identity user = new Identity("id-user-2", "User 2");
            user.authScript("return 'Bearer x'");
            store.save(settings, List.of(user));

            ResultsRepository repository = new ResultsRepository(persistence.api(), settings);
            repository.load();
            repository.append(record(1, "GET", 200, Verdict.BYPASSED, "reached it"));
            repository.storeAuthTranscript("id-user-2", List.of(exchange("POST", 200)));
            repository.shutdown();

            // Saving the configuration again must not wipe the stored results.
            store.save(settings, List.of(user));

            ResultsRepository reopened = new ResultsRepository(persistence.api(), settings);
            assertEquals(1, reopened.load().size(), "a config save must not disturb stored results");
            assertEquals(1, reopened.loadAuthTranscript("id-user-2").size());

            List<Identity> identities = new ArrayList<>();
            store.load(new Settings(), identities);
            assertEquals("return 'Bearer x'", identities.get(0).authScript());
            reopened.shutdown();
        });
    }

    @Test
    void anEmptyProjectLoadsCleanly() {
        forBothPersistenceModes(persistence -> {
            ResultsRepository repository = new ResultsRepository(persistence.api(), new Settings());
            assertTrue(repository.load().isEmpty());
            repository.shutdown();

            List<Identity> identities = new ArrayList<>();
            new ConfigStore(persistence.api()).load(new Settings(), identities);
            assertTrue(identities.isEmpty());
        });
    }

    @Test
    void theLivenessProbeLeavesNothingBehind() {
        forBothPersistenceModes(persistence -> {
            ResultsRepository repository = new ResultsRepository(persistence.api(), new Settings());
            repository.load();
            repository.shutdown();

            assertFalse(persistence.extensionData().childObjectKeys().stream()
                            .anyMatch(key -> key.contains("probe")),
                    "the probe key must be cleaned up");
        });
    }

    // -- helpers ------------------------------------------------------------

    /** Runs a case against both live-view and copying child-object semantics. */
    private static void forBothPersistenceModes(java.util.function.Consumer<FakePersistence> body) {
        for (boolean live : new boolean[] { true, false }) {
            try (FakePersistence persistence = live
                    ? FakePersistence.installLive() : FakePersistence.installCopying()) {
                body.accept(persistence);
            }
        }
    }

    private static HttpRequestResponse exchange(String method, int status) {
        return FakeHttp.exchange(
                FakeHttp.request(Map.of("Host", "target.example.com", "X-Method", method), method),
                FakeHttp.response(status, "body for " + method + " " + status));
    }

    private static AuthTestRecord record(int index, String method, int status, Verdict verdict, String detail) {
        Map<String, VariantResult> results = new LinkedHashMap<>();
        results.put("id-user-2", new VariantResult("id-user-2", "User 2", verdict, 0.5, detail, false,
                exchange(method, status)));
        return new AuthTestRecord(index, "Manual", exchange(method, status), results, false, "");
    }
}
