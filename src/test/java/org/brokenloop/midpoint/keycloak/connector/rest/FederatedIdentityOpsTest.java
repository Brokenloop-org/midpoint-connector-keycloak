package org.brokenloop.midpoint.keycloak.connector.rest;

import jakarta.ws.rs.core.Response;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Keycloak 26.8 accepts an identity linked to several users, so the 409 path cannot be provoked
 * against a live server; the failed-replace behaviour is verified with a mocked user resource.
 */
class FederatedIdentityOpsTest {

    private static FederatedIdentityRepresentation link(String idp, String userId) {
        FederatedIdentityRepresentation r = new FederatedIdentityRepresentation();
        r.setIdentityProvider(idp);
        r.setUserId(userId);
        r.setUserName(userId);
        return r;
    }

    private static FederatedIdentityOps.Plan replacePlan(FederatedIdentityRepresentation old,
                                                          FederatedIdentityRepresentation wanted) {
        return new FederatedIdentityOps.Plan(List.of(old.getIdentityProvider()), List.of(wanted),
                Map.of(old.getIdentityProvider(), old));
    }

    @Test
    void conflictOnReplaceRestoresOldLinkAndReportsAlreadyLinked() {
        UserResource user = mock(UserResource.class);
        FederatedIdentityRepresentation old = link("idp-1", "old");
        FederatedIdentityRepresentation wanted = link("idp-1", "x");
        when(user.addFederatedIdentity(eq("idp-1"), same(wanted))).thenReturn(Response.status(409).build());
        when(user.addFederatedIdentity(eq("idp-1"), same(old))).thenReturn(Response.noContent().build());

        AlreadyExistsException e = assertThrows(AlreadyExistsException.class,
                () -> FederatedIdentityOps.apply(user, replacePlan(old, wanted)));

        assertTrue(e.getMessage().contains("idp-1/x"), e.getMessage());
        assertTrue(e.getMessage().contains("already linked to another user"), e.getMessage());
        InOrder order = inOrder(user);
        order.verify(user).removeFederatedIdentity("idp-1");
        order.verify(user).addFederatedIdentity(eq("idp-1"), same(wanted));
        order.verify(user).addFederatedIdentity(eq("idp-1"), same(old));
    }

    @Test
    void otherClientErrorIsInvalidAttributeValueAndRestoresOldLink() {
        UserResource user = mock(UserResource.class);
        FederatedIdentityRepresentation old = link("idp-1", "old");
        FederatedIdentityRepresentation wanted = link("idp-1", "x");
        when(user.addFederatedIdentity(eq("idp-1"), same(wanted))).thenReturn(Response.status(400).build());
        when(user.addFederatedIdentity(eq("idp-1"), same(old))).thenReturn(Response.noContent().build());

        assertThrows(InvalidAttributeValueException.class,
                () -> FederatedIdentityOps.apply(user, replacePlan(old, wanted)));
        verify(user).addFederatedIdentity(eq("idp-1"), same(old));
    }

    @Test
    void failedRestoreDoesNotMaskTheOriginalError() {
        UserResource user = mock(UserResource.class);
        FederatedIdentityRepresentation old = link("idp-1", "old");
        FederatedIdentityRepresentation wanted = link("idp-1", "x");
        when(user.addFederatedIdentity(eq("idp-1"), same(wanted))).thenReturn(Response.status(409).build());
        when(user.addFederatedIdentity(eq("idp-1"), same(old))).thenThrow(new IllegalStateException("down"));

        assertThrows(AlreadyExistsException.class,
                () -> FederatedIdentityOps.apply(user, replacePlan(old, wanted)));
    }

    @Test
    void plainAddWithoutRemovedLinkDoesNotRestoreAnything() {
        UserResource user = mock(UserResource.class);
        FederatedIdentityRepresentation wanted = link("idp-1", "x");
        when(user.addFederatedIdentity(eq("idp-1"), any())).thenReturn(Response.status(409).build());

        assertThrows(AlreadyExistsException.class, () -> FederatedIdentityOps.apply(user,
                new FederatedIdentityOps.Plan(List.of(), List.of(wanted), Map.of())));
        verify(user, times(1)).addFederatedIdentity(eq("idp-1"), any());
    }
}
