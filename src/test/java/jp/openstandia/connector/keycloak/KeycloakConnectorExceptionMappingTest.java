package jp.openstandia.connector.keycloak;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.identityconnectors.framework.common.exceptions.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeycloakConnectorExceptionMappingTest {

    private final KeycloakConnector connector = new KeycloakConnector();

    @Test
    void connectorException_returnedAsIs() {
        ConnectorException original = new ConnectorException("test");
        ConnectorException result = connector.processRuntimeException(original);
        assertSame(original, result);
    }

    @Test
    void badRequestException_returnsInvalidAttributeValueException() {
        BadRequestException e = new BadRequestException("bad");
        ConnectorException result = connector.processRuntimeException(e);
        assertInstanceOf(InvalidAttributeValueException.class, result);
    }

    @Test
    void notFoundException_returnsUnknownUidException() {
        NotFoundException e = new NotFoundException("not found");
        ConnectorException result = connector.processRuntimeException(e);
        assertInstanceOf(UnknownUidException.class, result);
    }

    @Test
    void clientErrorException_409Conflict_returnsAlreadyExistsException() {
        ClientErrorException e = mock(ClientErrorException.class);
        Response response = mock(Response.class);
        when(e.getResponse()).thenReturn(response);
        when(response.getStatusInfo()).thenReturn(Response.Status.CONFLICT);

        ConnectorException result = connector.processRuntimeException(e);
        assertInstanceOf(AlreadyExistsException.class, result);
    }

    @Test
    void clientErrorException_429TooManyRequests_returnsRetryableException() {
        ClientErrorException e = mock(ClientErrorException.class);
        Response response = mock(Response.class);
        when(e.getResponse()).thenReturn(response);
        when(response.getStatusInfo()).thenReturn(Response.Status.TOO_MANY_REQUESTS);
        when(e.getMessage()).thenReturn("rate limited");

        ConnectorException result = connector.processRuntimeException(e);
        assertInstanceOf(RetryableException.class, result);
    }

    @Test
    void clientErrorException_otherStatus_throwsConnectorIOException() {
        ClientErrorException e = mock(ClientErrorException.class);
        Response response = mock(Response.class);
        when(e.getResponse()).thenReturn(response);
        when(response.getStatusInfo()).thenReturn(Response.Status.FORBIDDEN);

        assertThrows(ConnectorIOException.class,
                () -> connector.processRuntimeException(e));
    }

    @Test
    void internalServerErrorException_returnsRetryableException() {
        InternalServerErrorException e = new InternalServerErrorException("server error");
        ConnectorException result = connector.processRuntimeException(e);
        assertInstanceOf(RetryableException.class, result);
    }

    @Test
    void otherWebApplicationException_throwsConnectorIOException() {
        // ServiceUnavailableException is a ServerErrorException (subclass of WebApplicationException)
        // but not InternalServerErrorException
        ServiceUnavailableException e = new ServiceUnavailableException("unavailable");
        assertThrows(ConnectorIOException.class,
                () -> connector.processRuntimeException(e));
    }

    @Test
    void plainRuntimeException_returnsConnectorExceptionWrapper() {
        RuntimeException e = new RuntimeException("generic");
        ConnectorException result = connector.processRuntimeException(e);
        assertInstanceOf(ConnectorException.class, result);
        assertEquals(e, result.getCause());
    }

    @Test
    void badRequestException_takePriorityOverClientErrorException() {
        // BadRequestException extends ClientErrorException, but the code checks
        // BadRequestException first. Verify it maps to InvalidAttributeValueException,
        // NOT AlreadyExistsException/ConnectorIOException from the ClientErrorException branch.
        BadRequestException e = new BadRequestException("bad input");
        ConnectorException result = connector.processRuntimeException(e);
        assertInstanceOf(InvalidAttributeValueException.class, result);
        assertNotInstanceOf(ConnectorIOException.class, result);
    }

    private void assertNotInstanceOf(Class<?> unexpected, Object actual) {
        assertFalse(unexpected.isInstance(actual),
                "Expected NOT an instance of " + unexpected.getSimpleName());
    }
}
