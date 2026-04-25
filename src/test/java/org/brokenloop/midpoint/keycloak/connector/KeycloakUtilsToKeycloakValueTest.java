package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import static org.brokenloop.midpoint.keycloak.connector.ConnIdTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakUtilsToKeycloakValueTest {

    // --- toKeycloakValue(schema, AttributeDelta) ---

    @Test
    void delta_stringType_returnsStringValue() {
        Map<String, AttributeInfo> schema = schemaMap(stringAttrInfo("name"));
        AttributeDelta delta = AttributeDeltaBuilder.build("name", "hello");
        assertEquals("hello", KeycloakUtils.toKeycloakValue(schema, delta));
    }

    @Test
    void delta_integerType_returnsStringOfInt() {
        Map<String, AttributeInfo> schema = schemaMap(intAttrInfo("age"));
        AttributeDelta delta = AttributeDeltaBuilder.build("age", 42);
        assertEquals("42", KeycloakUtils.toKeycloakValue(schema, delta));
    }

    @Test
    void delta_booleanType_returnsStringOfBoolean() {
        Map<String, AttributeInfo> schema = schemaMap(booleanAttrInfo("active"));
        AttributeDelta delta = AttributeDeltaBuilder.build("active", true);
        assertEquals("true", KeycloakUtils.toKeycloakValue(schema, delta));
    }

    @Test
    void delta_zonedDateTimeType_returnsIsoInstant() {
        Map<String, AttributeInfo> schema = schemaMap(dateTimeAttrInfo("date"));
        ZonedDateTime date = ZonedDateTime.of(2024, 1, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
        AttributeDelta delta = AttributeDeltaBuilder.build("date", date);
        String result = KeycloakUtils.toKeycloakValue(schema, delta);
        assertEquals(date.format(DateTimeFormatter.ISO_INSTANT), result);
    }

    @Test
    void delta_nullValue_returnsEmptyString() {
        Map<String, AttributeInfo> schema = schemaMap(stringAttrInfo("name"));
        // Build a delta with a null replacement value
        AttributeDelta delta = AttributeDeltaBuilder.build("name", (Object) null);
        assertEquals("", KeycloakUtils.toKeycloakValue(schema, delta));
    }

    @Test
    void delta_unknownAttribute_throwsInvalidAttributeValueException() {
        Map<String, AttributeInfo> schema = schemaMap(stringAttrInfo("known"));
        AttributeDelta delta = AttributeDeltaBuilder.build("unknown", "value");
        assertThrows(InvalidAttributeValueException.class,
                () -> KeycloakUtils.toKeycloakValue(schema, delta));
    }

    // --- toKeycloakValue(schema, Attribute) ---

    @Test
    void attr_stringType_returnsStringValue() {
        Map<String, AttributeInfo> schema = schemaMap(stringAttrInfo("name"));
        Attribute attr = AttributeBuilder.build("name", "hello");
        assertEquals("hello", KeycloakUtils.toKeycloakValue(schema, attr));
    }

    @Test
    void attr_integerType_returnsStringOfInt() {
        Map<String, AttributeInfo> schema = schemaMap(intAttrInfo("age"));
        Attribute attr = AttributeBuilder.build("age", 42);
        assertEquals("42", KeycloakUtils.toKeycloakValue(schema, attr));
    }

    @Test
    void attr_booleanType_returnsStringOfBoolean() {
        Map<String, AttributeInfo> schema = schemaMap(booleanAttrInfo("active"));
        Attribute attr = AttributeBuilder.build("active", true);
        assertEquals("true", KeycloakUtils.toKeycloakValue(schema, attr));
    }

    @Test
    void attr_zonedDateTimeType_returnsIsoLocalDate() {
        Map<String, AttributeInfo> schema = schemaMap(dateTimeAttrInfo("date"));
        ZonedDateTime date = ZonedDateTime.of(2024, 1, 15, 10, 30, 0, 0, ZoneId.of("UTC"));
        Attribute attr = AttributeBuilder.build("date", date);
        String result = KeycloakUtils.toKeycloakValue(schema, attr);
        // Note: Attribute overload uses ISO_LOCAL_DATE (not ISO_INSTANT like Delta)
        assertEquals(date.format(DateTimeFormatter.ISO_LOCAL_DATE), result);
    }

    @Test
    void attr_unknownAttribute_throwsInvalidAttributeValueException() {
        Map<String, AttributeInfo> schema = schemaMap(stringAttrInfo("known"));
        Attribute attr = AttributeBuilder.build("unknown", "value");
        assertThrows(InvalidAttributeValueException.class,
                () -> KeycloakUtils.toKeycloakValue(schema, attr));
    }

    @Test
    void nullHandling_differs_between_delta_and_attribute() {
        // Documents behavioral inconsistency: Delta returns "" for null, Attribute returns null
        Map<String, AttributeInfo> schema = schemaMap(stringAttrInfo("name"));

        AttributeDelta delta = AttributeDeltaBuilder.build("name", (Object) null);
        String deltaResult = KeycloakUtils.toKeycloakValue(schema, delta);
        assertEquals("", deltaResult, "Delta overload should return empty string for null");

        Attribute attr = AttributeBuilder.build("name");
        String attrResult = KeycloakUtils.toKeycloakValue(schema, attr);
        assertNull(attrResult, "Attribute overload returns null (no null guard)");
    }

    @Test
    void dateFormat_differs_between_delta_and_attribute() {
        // Documents the behavioral difference: Delta uses ISO_INSTANT, Attribute uses ISO_LOCAL_DATE
        Map<String, AttributeInfo> schema = schemaMap(dateTimeAttrInfo("date"));
        ZonedDateTime date = ZonedDateTime.of(2024, 1, 15, 10, 30, 0, 0, ZoneId.of("UTC"));

        AttributeDelta delta = AttributeDeltaBuilder.build("date", date);
        Attribute attr = AttributeBuilder.build("date", date);

        String deltaResult = KeycloakUtils.toKeycloakValue(schema, delta);
        String attrResult = KeycloakUtils.toKeycloakValue(schema, attr);

        // They produce different formats for the same date
        assertNotEquals(deltaResult, attrResult);
        assertTrue(deltaResult.contains("T")); // ISO_INSTANT has time component
        assertFalse(attrResult.contains("T")); // ISO_LOCAL_DATE is date only
    }
}
