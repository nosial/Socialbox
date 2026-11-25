package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.CodedEnumInterface;

public enum EnvelopeType implements CodedEnumInterface
{
    /**
     * A batch of RPC requests from the client, signed by the session identity.
     */
    REQUEST(1),

    /**
     * A batch of RPC responses from the server.
     */
    RESPONSE(2),

    /**
     * A server pushed event (streaming transports only).
     */
    EVENT(3),

    /**
     * The client's handshake finish, proving possession of the identity key.
     */
    FINISH(4);

    private final int code;

    EnvelopeType(int code)
    {
        this.code = code;
    }

    /**
     * Returns the type byte.
     *
     * @return The type byte.
     */
    @Override
    public int getCode()
    {
        return this.code;
    }
}
