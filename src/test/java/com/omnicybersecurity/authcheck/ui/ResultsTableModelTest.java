package com.omnicybersecurity.authcheck.ui;

import com.omnicybersecurity.authcheck.TestApis;
import com.omnicybersecurity.authcheck.config.ConfigStore;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.engine.RecordStore;
import com.omnicybersecurity.authcheck.model.Identity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Column identity, which is what makes a remembered sort survive a restart.
 * Indices move whenever the identity roster changes, so the sort is stored
 * against something that does not.
 */
class ResultsTableModelTest {

    private Configuration configuration;
    private ResultsTableModel model;

    @BeforeEach
    void setUp() {
        configuration = new Configuration(new ConfigStore(TestApis.montoyaApi()));
        // The store is only read here, so it needs no repository behind it.
        model = new ResultsTableModel(new RecordStore(configuration.settings(), null), configuration);
    }

    @Test
    void fixedColumnsRoundTripThroughTheirKey() {
        for (int column = 0; column < 7; column++) {
            String key = model.columnKey(column);
            assertEquals(column, model.columnForKey(key), "column " + column + " (" + key + ")");
        }
    }

    @Test
    void anIdentityColumnIsKeyedByIdentityNotPosition() {
        Identity first = new Identity("id-alice", "Alice");
        Identity second = new Identity("id-bob", "Bob");
        configuration.identities().add(first);
        configuration.identities().add(second);
        model.rebuildColumns(false);

        int bobColumn = model.columnForKey("variant:id-bob");
        assertTrue(bobColumn > 0, "Bob should have a column");

        // Remove the identity in front of Bob: his index moves, his key does not.
        configuration.identities().remove(first);
        model.rebuildColumns(false);

        int movedColumn = model.columnForKey("variant:id-bob");
        assertNotEquals(bobColumn, movedColumn, "Bob's column index should have shifted");
        assertEquals("variant:id-bob", model.columnKey(movedColumn),
                "the remembered sort must still land on Bob");
    }

    @Test
    void aRemovedIdentitysColumnIsReportedGone() {
        configuration.identities().add(new Identity("id-alice", "Alice"));
        model.rebuildColumns(false);
        assertTrue(model.columnForKey("variant:id-alice") > 0);

        configuration.identities().clear();
        model.rebuildColumns(false);

        // -1 lets the panel fall back to no sort rather than sorting a stale column.
        assertEquals(-1, model.columnForKey("variant:id-alice"));
    }

    @Test
    void anUnknownOrBlankKeyIsRejected() {
        assertEquals(-1, model.columnForKey(""));
        assertEquals(-1, model.columnForKey(null));
        assertEquals(-1, model.columnForKey("variant:never-existed"));
    }

    @Test
    void theUnauthenticatedColumnHasAStableKeyToo() {
        model.rebuildColumns(false);

        assertEquals(7, model.columnForKey("variant:" + Identity.UNAUTHENTICATED_KEY),
                "unauthenticated is the first variant column by default");
    }
}
