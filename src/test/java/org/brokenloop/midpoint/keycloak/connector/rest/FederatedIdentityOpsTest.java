package org.brokenloop.midpoint.keycloak.connector.rest;

import jakarta.ws.rs.core.Response;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.keycloak.admin.client.resource.IdentityProvidersResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
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
        org.keycloak.representations.idm.UserRepresentation rep = new org.keycloak.representations.idm.UserRepresentation();
        rep.setUsername("alice");
        when(user.toRepresentation()).thenReturn(rep);

        AlreadyExistsException e = assertThrows(AlreadyExistsException.class,
                () -> FederatedIdentityOps.apply(user, replacePlan(old, wanted)));

        assertTrue(e.getMessage().contains("User alice already has a link for identity provider idp-1"), e.getMessage());
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

    @Test
    void restoresOnServerError() {
        UserResource user = mock(UserResource.class);
        FederatedIdentityRepresentation old = link("idp-1", "old");
        FederatedIdentityRepresentation wanted = link("idp-1", "x");
        when(user.addFederatedIdentity(eq("idp-1"), same(wanted))).thenReturn(Response.status(500).build());
        when(user.addFederatedIdentity(eq("idp-1"), same(old))).thenReturn(Response.noContent().build());

        assertThrows(ConnectorException.class, () -> FederatedIdentityOps.apply(user, replacePlan(old, wanted)));
        verify(user).addFederatedIdentity(eq("idp-1"), same(old));
    }

    @Test
    void restoresWhenAddThrows() {
        UserResource user = mock(UserResource.class);
        FederatedIdentityRepresentation old = link("idp-1", "old");
        FederatedIdentityRepresentation wanted = link("idp-1", "x");
        RuntimeException boom = new IllegalStateException("network");
        when(user.addFederatedIdentity(eq("idp-1"), same(wanted))).thenThrow(boom);
        when(user.addFederatedIdentity(eq("idp-1"), same(old))).thenReturn(Response.noContent().build());

        RuntimeException thrown = assertThrows(RuntimeException.class,
                () -> FederatedIdentityOps.apply(user, replacePlan(old, wanted)));
        assertSame(boom, thrown);
        verify(user).addFederatedIdentity(eq("idp-1"), same(old));
    }

    private static RealmResource realmWithIdp1() {
        RealmResource realm = mock(RealmResource.class);
        IdentityProvidersResource idps = mock(IdentityProvidersResource.class);
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias("idp-1");
        when(realm.identityProviders()).thenReturn(idps);
        when(idps.findAll()).thenReturn(List.of(idp));
        return realm;
    }

    private static RealmResource realmWithTwoIdps() {
        RealmResource realm = mock(RealmResource.class);
        IdentityProvidersResource idps = mock(IdentityProvidersResource.class);
        IdentityProviderRepresentation idp1 = new IdentityProviderRepresentation();
        idp1.setAlias("idp-1");
        IdentityProviderRepresentation idp2 = new IdentityProviderRepresentation();
        idp2.setAlias("idp-2");
        when(realm.identityProviders()).thenReturn(idps);
        when(idps.findAll()).thenReturn(List.of(idp1, idp2));
        return realm;
    }

    private static String json2(String userId) {
        return "{\"identityProvider\":\"idp-2\",\"userId\":\"" + userId + "\",\"userName\":\"" + userId + "\"}";
    }

    private static String json(String userId) {
        return "{\"identityProvider\":\"idp-1\",\"userId\":\"" + userId + "\",\"userName\":\"" + userId + "\"}";
    }

    @Test
    void staleRemovalKeepsCurrentLink() {
        AttributeDelta delta = AttributeDeltaBuilder.build("federatedIdentities", List.of(), List.of(json("old")));
        FederatedIdentityOps.Plan plan = FederatedIdentityOps.plan(realmWithIdp1(), List.of(link("idp-1", "new")), delta);
        assertTrue(plan.isEmpty());
    }

    @Test
    void removalComparesUserIdCaseSensitively() {
        AttributeDelta delta = AttributeDeltaBuilder.build("federatedIdentities", List.of(), List.of(json("NEW")));
        assertTrue(FederatedIdentityOps.plan(realmWithIdp1(), List.of(link("idp-1", "new")), delta).isEmpty());
    }

    @Test
    void matchingRemovalUnlinks() {
        AttributeDelta delta = AttributeDeltaBuilder.build("federatedIdentities", List.of(), List.of(json("new")));
        FederatedIdentityOps.Plan plan = FederatedIdentityOps.plan(realmWithIdp1(), List.of(link("idp-1", "new")), delta);
        assertEquals(List.of("idp-1"), plan.remove());
        assertTrue(plan.add().isEmpty());
    }

    @Test
    void duplicateAliasInAddIsRejected() {
        AttributeDelta delta = AttributeDeltaBuilder.build("federatedIdentities",
                List.of(json("a"), json("b")), List.of());
        InvalidAttributeValueException e = assertThrows(InvalidAttributeValueException.class,
                () -> FederatedIdentityOps.plan(realmWithIdp1(), List.of(), delta));
        assertTrue(e.getMessage().contains("idp-1"), e.getMessage());
    }

    @Test
    void duplicateAliasInReplaceIsRejected() {
        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("federatedIdentities");
        b.addValueToReplace(json("a"));
        b.addValueToReplace(json("b"));
        assertThrows(InvalidAttributeValueException.class,
                () -> FederatedIdentityOps.plan(realmWithIdp1(), List.of(), b.build()));
    }

    @Test
    void duplicateAliasInCreateIsRejected() {
        assertThrows(InvalidAttributeValueException.class,
                () -> FederatedIdentityOps.parseAndValidate(realmWithIdp1(), List.of(json("a"), json("b"))));
    }

    @Test
    void twoAliasesOnlyOneChangesPlansOnlyThatAlias() {
        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("federatedIdentities");
        b.addValueToReplace(json("a"));
        b.addValueToReplace(json2("changed"));
        FederatedIdentityOps.Plan plan = FederatedIdentityOps.plan(realmWithTwoIdps(),
                List.of(link("idp-1", "a"), link("idp-2", "b")), b.build());
        assertEquals(List.of("idp-2"), plan.remove());
        assertEquals(1, plan.add().size());
        assertEquals("idp-2", plan.add().get(0).getIdentityProvider());
        assertEquals("changed", plan.add().get(0).getUserId());
    }

    @Test
    void twoAliasesRemovingOneLeavesTheOtherUntouched() {
        AttributeDelta delta = AttributeDeltaBuilder.build("federatedIdentities", List.of(), List.of(json2("b")));
        FederatedIdentityOps.Plan plan = FederatedIdentityOps.plan(realmWithTwoIdps(),
                List.of(link("idp-1", "a"), link("idp-2", "b")), delta);
        assertEquals(List.of("idp-2"), plan.remove());
        assertTrue(plan.add().isEmpty());
    }
}
