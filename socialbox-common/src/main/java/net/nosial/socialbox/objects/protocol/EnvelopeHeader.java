package net.nosial.socialbox.objects.protocol;

import net.nosial.socialbox.Protocol;
import net.nosial.socialbox.enums.EnvelopeType;
import net.nosial.socialbox.exceptions.ProtocolException;
import net.nosial.socialbox.interfaces.CodedEnumInterface;

import java.nio.ByteBuffer;
import java.util.UUID;

public record EnvelopeHeader(String version, EnvelopeType type, UUID sessionUuid, long seq, long ref, long timestamp)
{
    /**
     * The encoded size of a header in bytes.
     */
    public static final int SIZE = 43;

    /**
     * The highest sequence number a session may use. Keys rotate every 2^32 sequence numbers (see
     * {@link SessionKeys#epochKey}), so this only keeps sequence numbers non-negative.
     */
    public static final long MAX_SEQ = Long.MAX_VALUE;

    /**
     * Creates a header for the current time and protocol version.
     *
     * @param type The envelope type.
     * @param sessionUuid The session identifier.
     * @param seq The sequence number.
     * @param ref The referenced sequence number.
     * @return The header.
     */
    public static EnvelopeHeader now(EnvelopeType type, UUID sessionUuid, long seq, long ref)
    {
        return new EnvelopeHeader(Protocol.VERSION, type, sessionUuid, seq, ref, System.currentTimeMillis());
    }

    /**
     * Encodes the header.
     *
     * @return The 43 header bytes.
     * @throws ProtocolException If the version is not a valid "major.minor" version.
     */
    public byte[] encode()
    {
        int[] version = parseVersion(this.version);
        ByteBuffer buffer = ByteBuffer.allocate(SIZE);
        buffer.put((byte) version[0]);
        buffer.put((byte) version[1]);
        buffer.put((byte) this.type.getCode());
        buffer.putLong(this.sessionUuid.getMostSignificantBits());
        buffer.putLong(this.sessionUuid.getLeastSignificantBits());
        buffer.putLong(this.seq);
        buffer.putLong(this.ref);
        buffer.putLong(this.timestamp);
        return buffer.array();
    }

    /**
     * Decodes a header from the start of an envelope.
     *
     * @param envelope The envelope bytes.
     * @return The header.
     * @throws ProtocolException If the header is malformed.
     */
    public static EnvelopeHeader decode(byte[] envelope)
    {
        if(envelope == null || envelope.length < SIZE)
        {
            throw new ProtocolException("Envelope is too short");
        }

        ByteBuffer buffer = ByteBuffer.wrap(envelope, 0, SIZE);
        String version = (buffer.get() & 0xFF) + "." + (buffer.get() & 0xFF);
        EnvelopeType type = CodedEnumInterface.fromCode(EnvelopeType.class, buffer.get() & 0xFF);
        if(type == null)
        {
            throw new ProtocolException("Unknown envelope type");
        }

        UUID sessionUuid = new UUID(buffer.getLong(), buffer.getLong());
        return new EnvelopeHeader(version, type, sessionUuid, buffer.getLong(), buffer.getLong(), buffer.getLong());
    }

    /**
     * Parses a "major.minor" protocol version into its two parts.
     *
     * @param version The version, e.g. "1.0".
     * @return The major and minor version.
     * @throws ProtocolException If the version is malformed or a part does not fit in a byte.
     */
    private static int[] parseVersion(String version)
    {
        if(version == null || !version.matches("\\d{1,3}\\.\\d{1,3}"))
        {
            throw new ProtocolException(String.format("Invalid protocol version '%s'", version));
        }

        int separator = version.indexOf('.');
        int major = Integer.parseInt(version.substring(0, separator));
        int minor = Integer.parseInt(version.substring(separator + 1));
        if(major > 255 || minor > 255)
        {
            throw new ProtocolException(String.format("Invalid protocol version '%s'", version));
        }

        return new int[]{major, minor};
    }
}
