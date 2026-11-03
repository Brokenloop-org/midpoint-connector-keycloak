package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;

import static org.junit.jupiter.api.Assertions.*;

class FederatedIdentityCodecTest {

    private static FederatedIdentityRepresentation rep(String idp, String userId, String userName) {
        FederatedIdentityRepresentation r = new FederatedIdentityRepresentation();
        r.setIdentityProvider(idp);
        r.setUserId(userId);
        r.setUserName(userName);
        return r;
    }

    @Test
    void formatIsCanonical() {
        assertEquals("{\"identityProvider\":\"idp-1\",\"userId\":\"Alice@example.com\",\"userName\":\"alice\"}",
                FederatedIdentityCodec.format(rep("idp-1", "Alice@example.com", "alice")));
    }

    @Test
    void parseAcceptsAnyKeyOrderAndWhitespace() {
        FederatedIdentityRepresentation r = FederatedIdentityCodec.parse(
                "{ \"userName\" : \"alice\",\n \"userId\":\"A@example.com\", \"identityProvider\": \"idp-1\" }");
        assertEquals("idp-1", r.getIdentityProvider());
        assertEquals("A@example.com", r.getUserId());
        assertEquals("alice", r.getUserName());
    }

    @Test
    void userNameDefaultsToUserId() {
        FederatedIdentityRepresentation r = FederatedIdentityCodec.parse(
                "{\"identityProvider\":\"idp-1\",\"userId\":\"a@example.com\"}");
        assertEquals("a@example.com", r.getUserName());
    }

    @Test
    void rejectsMissingAlias() {
        assertThrows(InvalidAttributeValueException.class,
                () -> FederatedIdentityCodec.parse("{\"userId\":\"a@example.com\"}"));
        assertThrows(InvalidAttributeValueException.class,
                () -> FederatedIdentityCodec.parse("{\"identityProvider\":\"\",\"userId\":\"a\"}"));
        assertThrows(InvalidAttributeValueException.class,
                () -> FederatedIdentityCodec.parse("{\"identityProvider\":\"idp-1\"}"));
    }

    @Test
    void rejectsNonJson() {
        assertThrows(InvalidAttributeValueException.class, () -> FederatedIdentityCodec.parse("not json"));
        assertThrows(InvalidAttributeValueException.class, () -> FederatedIdentityCodec.parse("[1,2]"));
        assertThrows(InvalidAttributeValueException.class, () -> FederatedIdentityCodec.parse(null));
    }
}
