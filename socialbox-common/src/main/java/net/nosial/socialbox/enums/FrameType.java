package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.CodedEnumInterface;

public enum FrameType implements CodedEnumInterface
{
    /**
     * Client hello, MessagePack payload.
     */
    HELLO(0x01),

    /**
     * Server hello, MessagePack payload.
     */
    HELLO_REPLY(0x02),

    /**
     * An encrypted envelope, binary payload.
     */
    ENVELOPE(0x03),

    /**
     * An unauthenticated transport error, MessagePack payload {@code {code, message, ref}}.
     */
    ERROR(0x04),

    /**
     * Keep-alive request, empty payload.
     */
    PING(0x05),

    /**
     * Keep-alive response, empty payload.
     */
    PONG(0x06),

    /**
     * Server information request, empty payload.
     */
    INFO(0x07),

    /**
     * SignedInterface server information, MessagePack payload.
     */
    INFO_REPLY(0x08);

    private final int code;

    FrameType(int code)
    {
        this.code = code;
    }

    /**
     * Returns the frame type byte.
     *
     * @return The frame type byte.
     */
    @Override
    public int getCode()
    {
        return this.code;
    }
}
