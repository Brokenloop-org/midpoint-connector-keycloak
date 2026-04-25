package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.AbstractMap;

import static org.brokenloop.midpoint.keycloak.connector.ConnIdTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakUtilsTest {

    // --- toZoneDateTime ---

    @Test
    void toZoneDateTime_fromInstant_preservesInstant() {
        Instant instant = Instant.parse("2024-06-15T10:30:00Z");
        ZonedDateTime result = KeycloakUtils.toZoneDateTime(instant);
        assertEquals(instant, result.toInstant());
    }

    @Test
    void toZoneDateTime_fromEpochMillis_matchesInstant() {
        long epoch = 1718446200000L; // 2024-06-15T10:30:00Z
        ZonedDateTime result = KeycloakUtils.toZoneDateTime(epoch);
        assertEquals(Instant.ofEpochMilli(epoch), result.toInstant());
    }

    @Test
    void toZoneDateTime_fromEpochMillis_zero_returns1970() {
        ZonedDateTime result = KeycloakUtils.toZoneDateTime(0L);
        assertEquals(Instant.EPOCH, result.toInstant());
    }

    @Test
    void toZoneDateTime_fromString_parsesCorrectly() {
        ZonedDateTime result = KeycloakUtils.toZoneDateTime("2024-01-15");
        assertEquals(LocalDate.of(2024, 1, 15), result.toLocalDate());
        assertEquals(ZoneId.systemDefault(), result.getZone());
    }

    @Test
    void toZoneDateTime_fromString_invalidFormat_throws() {
        assertThrows(DateTimeParseException.class, () ->
                KeycloakUtils.toZoneDateTime("not-a-date"));
    }

    // --- toConnectorAttribute(AttributeInfo, Map.Entry) ---

    @Test
    void toConnectorAttribute_singleValued_string_returnsValue() {
        AttributeInfo info = stringAttrInfo("myAttr");
        Attribute result = KeycloakUtils.toConnectorAttribute(info, entry("myAttr", "hello"));
        assertEquals("hello", AttributeUtil.getStringValue(result));
    }

    @Test
    void toConnectorAttribute_singleValued_integer_parsesInt() {
        AttributeInfo info = intAttrInfo("age");
        Attribute result = KeycloakUtils.toConnectorAttribute(info, entry("age", "42"));
        assertEquals(42, AttributeUtil.getIntegerValue(result));
    }

    @Test
    void toConnectorAttribute_singleValued_boolean_parsesBoolean() {
        AttributeInfo info = booleanAttrInfo("active");
        Attribute result = KeycloakUtils.toConnectorAttribute(info, entry("active", "true"));
        assertEquals(Boolean.TRUE, AttributeUtil.getSingleValue(result));
    }

    @Test
    void toConnectorAttribute_singleValued_zonedDateTime_parsesDate() {
        AttributeInfo info = dateTimeAttrInfo("birthdate");
        Attribute result = KeycloakUtils.toConnectorAttribute(info, entry("birthdate", "2024-01-15"));
        Object value = AttributeUtil.getSingleValue(result);
        assertInstanceOf(ZonedDateTime.class, value);
        assertEquals(LocalDate.of(2024, 1, 15), ((ZonedDateTime) value).toLocalDate());
    }

    @Test
    void toConnectorAttribute_multiValued_returnsAllValues() {
        AttributeInfo info = multiValuedAttrInfo("tags");
        Attribute result = KeycloakUtils.toConnectorAttribute(info, entry("tags", "a", "b", "c"));
        assertEquals(List.of("a", "b", "c"), result.getValue());
    }

    @Test
    void toConnectorAttribute_multiValued_integerType_parsesAllElements() {
        AttributeInfo info = AttributeInfoBuilder.define("ages")
                .setType(Integer.class).setMultiValued(true).build();
        Attribute result = KeycloakUtils.toConnectorAttribute(info, entry("ages", "25", "30", "45"));
        assertEquals(List.of(25, 30, 45), result.getValue());
    }

    @Test
    void toConnectorAttribute_emptyValueList_returnsEmptyAttribute() {
        AttributeInfo info = stringAttrInfo("myAttr");
        Attribute result = KeycloakUtils.toConnectorAttribute(info, entryWithEmptyList("myAttr"));
        assertEquals("myAttr", result.getName());
        assertTrue(result.getValue() == null || result.getValue().isEmpty());
    }

    // --- toConnectorAttributeSingleValue ---

    @Test
    void toConnectorAttributeSingleValue_nonNull_returnsTypedAttribute() {
        AttributeInfo info = intAttrInfo("count");
        Map.Entry<String, String> singleEntry = Map.of("count", "7").entrySet().iterator().next();
        Attribute result = KeycloakUtils.toConnectorAttributeSingleValue(info, singleEntry);
        assertEquals(7, AttributeUtil.getIntegerValue(result));
    }

    @Test
    void toConnectorAttributeSingleValue_null_returnsEmptyAttribute() {
        AttributeInfo info = stringAttrInfo("empty");
        Map.Entry<String, String> singleEntry = new AbstractMap.SimpleEntry<>("empty", null);
        Attribute result = KeycloakUtils.toConnectorAttributeSingleValue(info, singleEntry);
        assertEquals("empty", result.getName());
        assertTrue(result.getValue() == null || result.getValue().isEmpty());
    }

    // --- toConnectorAttribute(info, attrName, attrValue) single-value overload ---

    @Test
    void toConnectorAttribute_singleValueOverload_string() {
        AttributeInfo info = stringAttrInfo("city");
        Attribute result = KeycloakUtils.toConnectorAttribute(info, "city", "Berlin");
        assertEquals("Berlin", AttributeUtil.getStringValue(result));
    }

    @Test
    void toConnectorAttribute_singleValueOverload_integer() {
        AttributeInfo info = intAttrInfo("level");
        Attribute result = KeycloakUtils.toConnectorAttribute(info, "level", "5");
        assertEquals(5, AttributeUtil.getIntegerValue(result));
    }

    // --- shouldReturn ---

    @Test
    void shouldReturn_nullSet_returnsTrue() {
        assertTrue(KeycloakUtils.shouldReturn(null, "anything"));
    }

    @Test
    void shouldReturn_setContainsAttr_returnsTrue() {
        assertTrue(KeycloakUtils.shouldReturn(Set.of("a", "b"), "a"));
    }

    @Test
    void shouldReturn_setMissingAttr_returnsFalse() {
        assertFalse(KeycloakUtils.shouldReturn(Set.of("a", "b"), "c"));
    }

    // --- shouldAllowPartialAttributeValues ---

    @Test
    void shouldAllowPartialAttributeValues_true_returnsTrue() {
        assertTrue(KeycloakUtils.shouldAllowPartialAttributeValues(optionsWithPartialValues()));
    }

    @Test
    void shouldAllowPartialAttributeValues_notSet_returnsFalse() {
        assertFalse(KeycloakUtils.shouldAllowPartialAttributeValues(emptyOptions()));
    }

    // --- shouldReturnDefaultAttributes ---

    @Test
    void shouldReturnDefaultAttributes_true_returnsTrue() {
        assertTrue(KeycloakUtils.shouldReturnDefaultAttributes(optionsWithReturnDefault()));
    }

    @Test
    void shouldReturnDefaultAttributes_notSet_returnsFalse() {
        assertFalse(KeycloakUtils.shouldReturnDefaultAttributes(emptyOptions()));
    }

    // --- invalidSchema ---

    @Test
    void invalidSchema_throwsWithCorrectMessage() {
        InvalidAttributeValueException ex = assertThrows(
                InvalidAttributeValueException.class,
                () -> KeycloakUtils.invalidSchema("badAttr"));
        assertTrue(ex.getMessage().contains("badAttr"));
    }

    @Test
    void invalidSchema_setsAffectedAttributeNames() {
        InvalidAttributeValueException ex = assertThrows(
                InvalidAttributeValueException.class,
                () -> KeycloakUtils.invalidSchema("badAttr"));
        assertEquals(List.of("badAttr"), ex.getAffectedAttributeNames());
    }

    // --- createFullAttributesToGet ---

    @Test
    void createFullAttributesToGet_neitherSet_returnsNull() {
        Map<String, AttributeInfo> schema = schemaMap(
                returnedByDefaultAttrInfo("a"),
                notReturnedByDefaultAttrInfo("b"));
        Set<String> result = KeycloakUtils.createFullAttributesToGet(schema, emptyOptions());
        assertNull(result);
    }

    @Test
    void createFullAttributesToGet_returnDefaultOnly_includesDefaults() {
        Map<String, AttributeInfo> schema = schemaMap(
                returnedByDefaultAttrInfo("a"),
                notReturnedByDefaultAttrInfo("b"));
        Set<String> result = KeycloakUtils.createFullAttributesToGet(schema, optionsWithReturnDefault());
        assertTrue(result.contains("a"));
        assertFalse(result.contains("b"));
    }

    @Test
    void createFullAttributesToGet_attrsToGetOnly_returnsThoseAttrs() {
        Map<String, AttributeInfo> schema = schemaMap(
                returnedByDefaultAttrInfo("a"),
                notReturnedByDefaultAttrInfo("b"));
        Set<String> result = KeycloakUtils.createFullAttributesToGet(schema, optionsWithAttrsToGet("b"));
        assertTrue(result.contains("b"));
        assertFalse(result.contains("a"));
    }

    @Test
    void createFullAttributesToGet_bothSet_merges() {
        Map<String, AttributeInfo> schema = schemaMap(
                returnedByDefaultAttrInfo("a"),
                notReturnedByDefaultAttrInfo("b"));
        OperationOptions opts = new OperationOptionsBuilder()
                .setReturnDefaultAttributes(true)
                .setAttributesToGet("b")
                .build();
        Set<String> result = KeycloakUtils.createFullAttributesToGet(schema, opts);
        assertTrue(result.contains("a"));
        assertTrue(result.contains("b"));
    }

    // --- getRootCause ---

    @Test
    void getRootCause_singleException_returnsNull() {
        Exception e = new Exception("top");
        assertNull(KeycloakUtils.getRootCause(e));
    }

    @Test
    void getRootCause_chainOfTwo_returnsInnerCause() {
        Exception root = new Exception("root");
        Exception top = new Exception("top", root);
        assertEquals(root, KeycloakUtils.getRootCause(top));
    }

    @Test
    void getRootCause_chainOfThree_returnsDeepest() {
        Exception deepest = new Exception("deepest");
        Exception middle = new Exception("middle", deepest);
        Exception top = new Exception("top", middle);
        assertEquals(deepest, KeycloakUtils.getRootCause(top));
    }

    @Test
    void getRootCause_null_returnsNull() {
        assertNull(KeycloakUtils.getRootCause(null));
    }

    // --- mergeList ---

    @Test
    void mergeList_addToNull_createsNewList() {
        AttributeDelta delta = AttributeDeltaBuilder.build("attr", List.of("a", "b"), null);
        List<String> result = KeycloakUtils.mergeList(null, delta);
        assertEquals(List.of("a", "b"), result);
    }

    @Test
    void mergeList_addToExisting_appendsValues() {
        List<String> current = new ArrayList<>(List.of("existing"));
        AttributeDelta delta = AttributeDeltaBuilder.build("attr", List.of("new"), null);
        List<String> result = KeycloakUtils.mergeList(current, delta);
        assertEquals(List.of("existing", "new"), result);
    }

    @Test
    void mergeList_removeFromExisting_removesValues() {
        List<String> current = new ArrayList<>(List.of("a", "b", "c"));
        AttributeDelta delta = AttributeDeltaBuilder.build("attr", null, List.of("b"));
        List<String> result = KeycloakUtils.mergeList(current, delta);
        assertEquals(List.of("a", "c"), result);
    }

    @Test
    void mergeList_addAndRemove_appliesBoth() {
        List<String> current = new ArrayList<>(List.of("a", "b"));
        AttributeDelta delta = AttributeDeltaBuilder.build("attr", List.of("c"), List.of("a"));
        List<String> result = KeycloakUtils.mergeList(current, delta);
        assertEquals(List.of("b", "c"), result);
    }

    @Test
    void mergeList_removeNonExistent_noError() {
        List<String> current = new ArrayList<>(List.of("a"));
        AttributeDelta delta = AttributeDeltaBuilder.build("attr", null, List.of("z"));
        List<String> result = KeycloakUtils.mergeList(current, delta);
        assertEquals(List.of("a"), result);
    }

    @Test
    void mergeList_nonNullInput_mutatesAndReturnsSameInstance() {
        List<String> current = new ArrayList<>(List.of("a"));
        AttributeDelta delta = AttributeDeltaBuilder.build("attr", List.of("b"), null);
        List<String> result = KeycloakUtils.mergeList(current, delta);
        assertSame(current, result);
    }
}
