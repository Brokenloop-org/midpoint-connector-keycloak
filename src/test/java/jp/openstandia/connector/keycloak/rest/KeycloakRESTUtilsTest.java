package jp.openstandia.connector.keycloak.rest;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeycloakRESTUtilsTest {

    // --- checkCreateResult ---

    @Test
    void checkCreateResult_201Created_returnsIdFromLocation() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("http://localhost/admin/realms/test/users/abc-123-def"));

        String id = KeycloakRESTUtils.checkCreateResult(response, "createUser");
        assertEquals("abc-123-def", id);
    }

    @Test
    void checkCreateResult_201Created_deepPath_returnsLastSegment() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("/a/b/c/d/my-id"));

        String id = KeycloakRESTUtils.checkCreateResult(response, "createGroup");
        assertEquals("my-id", id);
    }

    @Test
    void checkCreateResult_409Conflict_throwsAlreadyExistsException() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(409);

        assertThrows(AlreadyExistsException.class,
                () -> KeycloakRESTUtils.checkCreateResult(response, "createUser"));
    }

    @Test
    void checkCreateResult_unexpectedStatus_exceptionMessageContainsApiNameAndStatus() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(503);

        ConnectorException ex = assertThrows(ConnectorException.class,
                () -> KeycloakRESTUtils.checkCreateResult(response, "createUser"));
        assertTrue(ex.getMessage().contains("createUser"), "Message should contain API name");
        assertTrue(ex.getMessage().contains("503"), "Message should contain status code");
    }

    @Test
    void checkCreateResult_500ServerError_throwsConnectorException() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(500);

        assertThrows(ConnectorException.class,
                () -> KeycloakRESTUtils.checkCreateResult(response, "createUser"));
    }

    @Test
    void checkCreateResult_400BadRequest_throwsConnectorException() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(400);

        assertThrows(ConnectorException.class,
                () -> KeycloakRESTUtils.checkCreateResult(response, "createUser"));
    }

    // --- checkDeleteResult ---

    @Test
    void checkDeleteResult_204NoContent_succeeds() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(204);

        assertDoesNotThrow(() -> KeycloakRESTUtils.checkDeleteResult(response, "deleteUser"));
    }

    @Test
    void checkDeleteResult_404NotFound_throwsNotFoundException() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(404);

        assertThrows(NotFoundException.class,
                () -> KeycloakRESTUtils.checkDeleteResult(response, "deleteUser"));
    }

    @Test
    void checkDeleteResult_500ServerError_throwsConnectorException() {
        Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(500);

        assertThrows(ConnectorException.class,
                () -> KeycloakRESTUtils.checkDeleteResult(response, "deleteUser"));
    }

    // --- getGeneratedId ---

    @Test
    void getGeneratedId_extractsLastPathSegment() {
        Response response = mock(Response.class);
        when(response.getLocation()).thenReturn(URI.create("/realms/test/users/uuid-value"));

        assertEquals("uuid-value", KeycloakRESTUtils.getGeneratedId(response));
    }

    @Test
    void getGeneratedId_singleSegment_returnsIt() {
        Response response = mock(Response.class);
        when(response.getLocation()).thenReturn(URI.create("/my-id"));

        assertEquals("my-id", KeycloakRESTUtils.getGeneratedId(response));
    }
}
