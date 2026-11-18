package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.brokenloop.midpoint.keycloak.connector.ConnIdTestFixtures.emptyOptions;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakFilterTranslatorTest {

    private final KeycloakFilterTranslator translator =
            new KeycloakFilterTranslator(new ObjectClass("user"), emptyOptions());

    @Test
    void translate_equalsByUid_returnsFilterByUid() {
        EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(new Uid("abc-123"));
        List<KeycloakFilter> result = translator.translate(filter);
        assertEquals(1, result.size());
        assertTrue(result.get(0).isByUid());
        assertEquals("abc-123", result.get(0).uid.getUidValue());
    }

    @Test
    void translate_equalsByName_returnsFilterByName() {
        EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(new Name("admin"));
        List<KeycloakFilter> result = translator.translate(filter);
        assertEquals(1, result.size());
        assertTrue(result.get(0).isByName());
        assertEquals("admin", result.get(0).name.getNameValue());
    }

    @Test
    void translate_equalsByOtherAttribute_returnsEmptyList() {
        Attribute emailAttr = AttributeBuilder.build("email", "test@example.com");
        EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(emailAttr);
        List<KeycloakFilter> result = translator.translate(filter);
        assertTrue(result.isEmpty());
    }

    @Test
    void translate_notEqualsByUid_returnsEmptyList() {
        EqualsFilter equalsFilter = (EqualsFilter) FilterBuilder.equalTo(new Uid("abc-123"));
        // Wrap in NOT
        List<KeycloakFilter> result = translator.translate(FilterBuilder.not(equalsFilter));
        assertTrue(result.isEmpty());
    }

    @Test
    void translate_andOfUidAndOtherAttr_returnsOnlyUidFilter() {
        // Compound filter: Uid AND email. Since email is unsupported natively,
        // only the Uid filter survives. The framework ANDs them, but null from
        // createEqualsExpression means "no native filter for this part".
        EqualsFilter uidFilter = (EqualsFilter) FilterBuilder.equalTo(new Uid("abc-123"));
        Attribute emailAttr = AttributeBuilder.build("email", "test@example.com");
        EqualsFilter emailFilter = (EqualsFilter) FilterBuilder.equalTo(emailAttr);

        List<KeycloakFilter> result = translator.translate(
                FilterBuilder.and(uidFilter, emailFilter));
        // The UID filter should still be present
        assertFalse(result.isEmpty());
        assertTrue(result.stream().anyMatch(KeycloakFilter::isByUid));
    }
}
