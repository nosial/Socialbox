package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum HttpHeader implements NamedEnumInterface
{
    /**
     * The protocol version of the envelope, e.g. {@code 1.0}.
     */
    VERSION("Socialbox-Version"),

    /**
     * The envelope type by its wire name: {@code request}, {@code response}, {@code event} or {@code finish}.
     */
    ENVELOPE("Socialbox-Envelope"),

    /**
     * The session identifier.
     */
    SESSION("Socialbox-Session"),

    /**
     * The sequence number of the envelope in its direction.
     */
    SEQUENCE("Socialbox-Sequence"),

    /**
     * The sequence number the envelope answers, 0 if none.
     */
    REFERENCE("Socialbox-Reference"),

    /**
     * When the envelope was sealed, in milliseconds.
     */
    TIMESTAMP("Socialbox-Timestamp"),

    /**
     * The numeric error code of a request that failed outside a sealed response.
     */
    ERROR("Socialbox-Error"),

    /**
     * The standard header telling a rate limited client how many seconds to wait.
     */
    RETRY_AFTER("Retry-After"),

    /**
     * The standard content type header.
     */
    CONTENT_TYPE("Content-Type");

    private final String name;

    HttpHeader(String name)
    {
        this.name = name;
    }

    /**
     * Returns the header name.
     *
     * @return The header name.
     */
    @Override
    public String getName()
    {
        return this.name;
    }
}
