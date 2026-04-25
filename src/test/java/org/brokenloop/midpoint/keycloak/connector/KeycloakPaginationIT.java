package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.junit.jupiter.api.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakGroupHandler.GROUP_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies pagination correctness and ConnId search-contract compliance.
 *
 * Creates > queryPageSize objects to force multi-page reads and asserts:
 * - Off-by-one fixes: all created objects are returned (no skips)
 * - Wrong-API-parameter fix: KC respects queryPageSize, total returned == created
 * - ConnId contract: SearchResultsHandler receives handleResult(allResultsReturned=true)
 * - Early termination: returning false from handler stops iteration
 */
class KeycloakPaginationIT extends AbstractKeycloakIT {

    static final String REALM = "test-pagination";
    /**
     * Small page size so a handful of objects forces multiple pages.
     */
    static final int PAGE_SIZE = 3;
    /**
     * Total objects to create per type. Chosen so multiple pages are needed
     * and the total is not a multiple of PAGE_SIZE (catches off-by-one).
     */
    static final int OBJECT_COUNT = 7;

    static KeycloakConnector connector;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        connector = newConnectorWithPageSize(REALM, PAGE_SIZE);

        // Create OBJECT_COUNT users
        for (int i = 0; i < OBJECT_COUNT; i++) {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("page-user-" + i));
            attrs.add(AttributeBuilder.build("email", "page-user-" + i + "@test.com"));
            attrs.add(AttributeBuilder.buildEnabled(true));
            connector.create(USER_OBJECT_CLASS, attrs, null);
        }

        // Create OBJECT_COUNT groups
        for (int i = 0; i < OBJECT_COUNT; i++) {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("page-group-" + i));
            connector.create(GROUP_OBJECT_CLASS, attrs, null);
        }
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    @Test
    void getUsers_returnsAllAcrossMultiplePages_noSkips() {
        // KC creates one default service-account-* user when client is service-enabled,
        // so just verify our created users all show up.
        List<ConnectorObject> all = searchAll(connector, USER_OBJECT_CLASS);

        long pageUserCount = all.stream()
                .filter(o -> o.getName().getNameValue().startsWith("page-user-"))
                .count();
        assertEquals(OBJECT_COUNT, pageUserCount,
                "All created users must be returned across pages. Got names: " +
                        all.stream().map(o -> o.getName().getNameValue()).toList());
    }

    @Test
    void getGroups_returnsAllAcrossMultiplePages_noSkips() {
        List<ConnectorObject> all = searchAll(connector, GROUP_OBJECT_CLASS);

        long pageGroupCount = all.stream()
                .filter(o -> o.getName().getNameValue().startsWith("page-group-"))
                .count();
        assertEquals(OBJECT_COUNT, pageGroupCount,
                "All created groups must be returned across pages. Got names: " +
                        all.stream().map(o -> o.getName().getNameValue()).toList());
    }

    @Test
    void getUsers_signalsAllResultsReturned_toSearchResultsHandler() {
        AtomicBoolean signalReceived = new AtomicBoolean(false);
        AtomicBoolean signalIsTrue = new AtomicBoolean(false);

        SearchResultsHandler handler = new SearchResultsHandler() {
            @Override
            public boolean handle(ConnectorObject obj) {
                return true;
            }

            @Override
            public void handleResult(SearchResult result) {
                signalReceived.set(true);
                signalIsTrue.set(result.isAllResultsReturned());
            }
        };
        connector.executeQuery(USER_OBJECT_CLASS, null, handler, new OperationOptionsBuilder().build());

        assertTrue(signalReceived.get(), "SearchResultsHandler.handleResult must be called");
        assertTrue(signalIsTrue.get(), "SearchResult.isAllResultsReturned must be true");
    }

    @Test
    void getGroups_signalsAllResultsReturned_toSearchResultsHandler() {
        AtomicBoolean signalReceived = new AtomicBoolean(false);

        SearchResultsHandler handler = new SearchResultsHandler() {
            @Override
            public boolean handle(ConnectorObject obj) {
                return true;
            }

            @Override
            public void handleResult(SearchResult result) {
                signalReceived.set(true);
                assertTrue(result.isAllResultsReturned());
            }
        };
        connector.executeQuery(GROUP_OBJECT_CLASS, null, handler, new OperationOptionsBuilder().build());

        assertTrue(signalReceived.get());
    }

    // Note: the off-by-one fix in getUser(Name)/getGroup(Name) is largely defensive --
    // KC enforces unique names per realm, so the substring search that drives those
    // paginated loops returns at most one exact match, which always fits in the first
    // page. The fix is still correct (would manifest if a future KC version changed
    // search semantics or if non-unique synthesized names appeared) but is not
    // directly exercisable as an integration test against a stock Keycloak realm.

    @Test
    void getUsers_earlyTermination_whenHandlerReturnsFalse() {
        // Stop after the 4th object (which is mid-second-page given PAGE_SIZE=3).
        // The handler must NOT receive more than 4 objects, and handleResult must
        // still be called to terminate the search cleanly.
        List<String> received = new ArrayList<>();
        AtomicBoolean signalReceived = new AtomicBoolean(false);

        SearchResultsHandler handler = new SearchResultsHandler() {
            @Override
            public boolean handle(ConnectorObject obj) {
                received.add(obj.getName().getNameValue());
                return received.size() < 4;
            }

            @Override
            public void handleResult(SearchResult result) {
                signalReceived.set(true);
            }
        };
        connector.executeQuery(USER_OBJECT_CLASS, null, handler, new OperationOptionsBuilder().build());

        assertEquals(4, received.size(),
                "Handler must stop receiving objects after returning false. Got: " + received);
        assertTrue(signalReceived.get(),
                "handleResult must still be called even on early termination");
    }
}
