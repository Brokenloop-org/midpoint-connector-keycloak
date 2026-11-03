package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPAttributePermissions;
import org.keycloak.representations.userprofile.config.UPConfig;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakUserProfileIT extends AbstractKeycloakIT {

    static final String REALM = "it-profile";

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        setProfile(null);
    }

    @AfterAll
    static void teardown() {
        teardownRealm(REALM);
    }

    private static void setProfile(UPConfig.UnmanagedAttributePolicy policy) {
        try (Keycloak admin = adminClient()) {
            var users = admin.realm(REALM).users();
            UPConfig config = users.userProfile().getConfiguration();
            config.removeAttribute("dept");
            config.removeAttribute("tags");
            UPAttributePermissions perms = new UPAttributePermissions(Set.of("admin"), Set.of("admin"));
            config.addOrReplaceAttribute(new UPAttribute("dept", perms));
            UPAttribute tags = new UPAttribute("tags", perms);
            tags.setMultivalued(true);
            config.addOrReplaceAttribute(tags);
            config.setUnmanagedAttributePolicy(policy);
            users.userProfile().update(config);
        }
    }

    private static KeycloakConnector connector(boolean profileSchema, String userAttributes) {
        KeycloakConfiguration cfg = buildConfiguration(REALM);
        cfg.setUserProfileSchemaEnabled(profileSchema);
        cfg.setUserAttributes(userAttributes);
        KeycloakConnector c = new KeycloakConnector();
        c.setInstanceName("test");
        c.init(cfg);
        return c;
    }

    private static ObjectClassInfo userClass(KeycloakConnector c) {
        return c.schema().findObjectClassInfo(USER_OBJECT_CLASS.getObjectClassValue());
    }

    @Test
    void schemaIncludesProfileAttributesWhenEnabled() {
        setProfile(null);
        KeycloakConnector c = connector(true, null);
        try {
            ObjectClassInfo info = userClass(c);
            AttributeInfo dept = AttributeInfoUtil.find("dept", info.getAttributeInfo());
            AttributeInfo tags = AttributeInfoUtil.find("tags", info.getAttributeInfo());
            assertNotNull(dept);
            assertFalse(dept.isMultiValued());
            assertNotNull(tags);
            assertTrue(tags.isMultiValued());
            long emailCount = info.getAttributeInfo().stream().filter(a -> a.is("email")).count();
            assertEquals(1, emailCount);
        } finally {
            c.dispose();
        }
    }

    @Test
    void schemaUnchangedWhenDisabled() {
        setProfile(null);
        KeycloakConnector c = connector(false, null);
        try {
            ObjectClassInfo info = userClass(c);
            assertNull(AttributeInfoUtil.find("dept", info.getAttributeInfo()));
            assertNull(AttributeInfoUtil.find("tags", info.getAttributeInfo()));
        } finally {
            c.dispose();
        }
    }

    @Test
    void writeAndReadProfileAttributes() {
        setProfile(null);
        KeycloakConnector c = connector(true, null);
        try {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("alice-profile"));
            attrs.add(AttributeBuilder.build("dept", "sales"));
            attrs.add(AttributeBuilder.build("tags", "x", "y"));
            Uid uid = c.create(USER_OBJECT_CLASS, attrs, null);

            ConnectorObject o = searchByUid(c, USER_OBJECT_CLASS, uid);
            assertEquals(List.of("sales"), o.getAttributeByName("dept").getValue());
            assertEquals(Set.of("x", "y"), new HashSet<>(o.getAttributeByName("tags").getValue()));
        } finally {
            c.dispose();
        }
    }

    @Test
    void unmanagedPolicyEnabledAllowsExplicitExtra() {
        setProfile(UPConfig.UnmanagedAttributePolicy.ENABLED);
        KeycloakConnector c = connector(true, "extra");
        try {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("alice-extra"));
            attrs.add(AttributeBuilder.build("extra", "value-1"));
            Uid uid = c.create(USER_OBJECT_CLASS, attrs, null);

            ConnectorObject o = searchByUid(c, USER_OBJECT_CLASS, uid);
            assertEquals(List.of("value-1"), o.getAttributeByName("extra").getValue());
        } finally {
            c.dispose();
            setProfile(null);
        }
    }
}
