package net.nosial.socialbox.classes.protocol;

import net.nosial.socialbox.enums.EnvelopeType;
import net.nosial.socialbox.enums.HttpHeader;
import net.nosial.socialbox.exceptions.ProtocolException;
import net.nosial.socialbox.objects.protocol.EnvelopeHeader;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

public final class HttpEnvelopes
{
    private HttpEnvelopes()
    {
    }

    /**
     * Returns the HTTP headers of an envelope header.
     *
     * @param header The envelope header.
     * @return The header names and values, in a stable order.
     */
    public static Map<String, String> toHeaders(EnvelopeHeader header)
    {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HttpHeader.VERSION.getName(), header.version());
        headers.put(HttpHeader.ENVELOPE.getName(), typeName(header.type()));
        headers.put(HttpHeader.SESSION.getName(), header.sessionUuid().toString());
        headers.put(HttpHeader.SEQUENCE.getName(), Long.toString(header.seq()));
        headers.put(HttpHeader.REFERENCE.getName(), Long.toString(header.ref()));
        headers.put(HttpHeader.TIMESTAMP.getName(), Long.toString(header.timestamp()));
        return headers;
    }

    /**
     * Rebuilds an envelope header from HTTP headers.
     *
     * @param headers Looks up a header value by name, returning null if absent.
     * @return The envelope header.
     * @throws ProtocolException If a header is missing or malformed.
     */
    public static EnvelopeHeader fromHeaders(Function<String, String> headers)
    {
        String version = require(headers, HttpHeader.VERSION);
        EnvelopeType type = parseType(require(headers, HttpHeader.ENVELOPE));

        try
        {
            UUID session = UUID.fromString(require(headers, HttpHeader.SESSION));
            long seq = Long.parseUnsignedLong(require(headers, HttpHeader.SEQUENCE));
            long ref = Long.parseUnsignedLong(require(headers, HttpHeader.REFERENCE));
            long timestamp = Long.parseLong(require(headers, HttpHeader.TIMESTAMP));
            if(seq < 0 || ref < 0)
            {
                throw new ProtocolException("Sequence numbers must be below 2^63");
            }

            EnvelopeHeader header = new EnvelopeHeader(version, type, session, seq, ref, timestamp);
            header.encode();
            return header;
        }
        catch(IllegalArgumentException e)
        {
            throw new ProtocolException("Malformed envelope headers", e);
        }
    }

    /**
     * Returns a required header value.
     *
     * @param headers The header lookup.
     * @param header The header.
     * @return The trimmed value.
     * @throws ProtocolException If the header is missing or empty.
     */
    private static String require(Function<String, String> headers, HttpHeader header)
    {
        String value = headers.apply(header.getName());
        if(value == null || value.isBlank())
        {
            throw new ProtocolException("Missing header " + header.getName());
        }

        return value.strip();
    }

    /**
     * Returns the header value of an envelope type: its lower case name.
     *
     * @param type The envelope type.
     * @return The value, e.g. {@code request}.
     */
    private static String typeName(EnvelopeType type)
    {
        return type.name().toLowerCase(Locale.ROOT);
    }

    /**
     * Parses the header value of an envelope type.
     *
     * @param value The value.
     * @return The envelope type.
     * @throws ProtocolException If no type has the value.
     */
    private static EnvelopeType parseType(String value)
    {
        for(EnvelopeType type : EnvelopeType.values())
        {
            if(typeName(type).equals(value))
            {
                return type;
            }
        }

        throw new ProtocolException("Unknown envelope type " + value);
    }
}
