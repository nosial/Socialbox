package net.nosial.socialbox.enums;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum StandardError
{
    /**
     * Fallback for codes this implementation does not know.
     */
    UNKNOWN(-1),


    // -100 Error code range: Server/Request related

    /**
     * An unexpected error occurred on the server.
     */
    INTERNAL_SERVER_ERROR(-100),

    /**
     * The server is temporarily unavailable.
     */
    SERVER_UNAVAILABLE(-101),

    /**
     * The request was malformed.
     */
    BAD_REQUEST(-102),

    /**
     * The caller is not allowed to perform the operation.
     */
    FORBIDDEN(-103),

    /**
     * The caller is not authorized to perform the operation.
     */
    UNAUTHORIZED(-104),

    /**
     * The requested resource was not found.
     */
    NOT_FOUND(-105),

    /**
     * A remote domain or peer could not be resolved.
     */
    RESOLUTION_FAILED(-106),

    /**
     * The operation conflicts with existing state.
     */
    CONFLICT(-107),

    /**
     * The resource or token has expired.
     */
    EXPIRED(-108),

    /**
     * A cryptographic operation failed.
     */
    CRYPTOGRAPHIC_ERROR(-109),

    /**
     * The caller is sending too many requests.
     */
    RATE_LIMITED(-110),

    /**
     * A configured limit was exceeded.
     */
    LIMIT_EXCEEDED(-111),


    // -1000 Range, RPC Communication Related

    /**
     * The requested method does not exist.
     */
    RPC_METHOD_NOT_FOUND(-1000),

    /**
     * The parameters of the request are missing or invalid.
     */
    RPC_INVALID_ARGUMENTS(-1001),

    /**
     * The RPC request could not be parsed.
     */
    RPC_BAD_REQUEST(-1002),

    /**
     * The method exists but is not available on the transport the request arrived on.
     */
    METHOD_NOT_SUPPORTED_ON_TRANSPORT(-1003),

    /**
     * The server does not offer the transport the client connected with; the client should use another one. Servers
     * answer in the protocol of the disabled transport, so every client recognizes this error.
     */
    TRANSPORT_DISABLED(-1004),



    // -2000 Range, Protocol related errors

    /**
     * The protocol version is not supported.
     */
    UNSUPPORTED_VERSION(-2000),

    /**
     * An algorithm is not supported or does not match what the server requires.
     */
    UNSUPPORTED_ALGORITHM(-2001),

    /**
     * The handshake failed.
     */
    HANDSHAKE_FAILED(-2002),

    /**
     * The envelope was already received or is outside the replay window.
     */
    REPLAY_DETECTED(-2003),

    /**
     * The session does not exist.
     */
    SESSION_NOT_FOUND(-2004),

    /**
     * The session has expired or was closed.
     */
    SESSION_EXPIRED(-2005),

    /**
     * The hello was addressed to a different domain.
     */
    WRONG_DOMAIN(-2006),

    /**
     * The information a server presents does not match its DNS record.
     */
    DNS_MISMATCH(-2007),

    /**
     * A signature did not verify.
     */
    INVALID_SIGNATURE(-2008),


    // -3000 Range, authentication/registration related errors

    /**
     * The method is not allowed for this session.
     */
    METHOD_NOT_ALLOWED(-3001),

    /**
     * The session is already authenticated.
     */
    ALREADY_AUTHENTICATED(-3002),

    /**
     * The session must complete its pending challenges first.
     */
    AUTHENTICATION_REQUIRED(-3003),

    /**
     * Registration is disabled on this server.
     */
    REGISTRATION_DISABLED(-3004),

    /**
     * The answer to a challenge was incorrect.
     */
    INCORRECT_ANSWER(-3005),

    /**
     * The challenge type is not supported by this server.
     */
    UNSUPPORTED_CHALLENGE(-3006),


    // -4000 Range, device related errors

    /**
     * A device certificate or revocation is malformed or not signed by the account key.
     */
    INVALID_CERTIFICATE(-4000),

    /**
     * The device is revoked, expired or unknown.
     */
    DEVICE_NOT_ACTIVE(-4001),

    /**
     * A standing statement is invalid, expired or not ACTIVE.
     */
    STANDING_INVALID(-4002),

    /**
     * The account reached its maximum number of devices.
     */
    DEVICE_LIMIT_REACHED(-4003),


    // -5000 Range, Peer related errors

    /**
     * The peer does not exist.
     */
    PEER_NOT_FOUND(-5000),

    /**
     * The address is malformed.
     */
    INVALID_ADDRESS(-5001),

    /**
     * The username is already taken.
     */
    USERNAME_TAKEN(-5002),

    /**
     * The username is reserved.
     */
    USERNAME_RESERVED(-5003),

    /**
     * The peer has not completed its registration.
     */
    NOT_REGISTERED(-5004);

    private final int code;
    StandardError(int code)
    {
        this.code = code;
    }

    /**
     * Returns the numeric error code.
     *
     * @return The error code.
     */
    @JsonValue
    public int getCode()
    {
        return this.code;
    }

    /**
     * Returns the error for the given code, or {@link #UNKNOWN} if the code is unknown.
     *
     * @param code The numeric error code.
     * @return The matching error.
     */
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public static StandardError fromCode(int code)
    {
        for(StandardError error : values())
        {
            if(error.code == code)
            {
                return error;
            }
        }

        return UNKNOWN;
    }
}
