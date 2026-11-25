package net.nosial.socialbox.classes.encoding;

import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.objects.cryptography.TypedKey;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public final class LpWriter
{
    private final ByteArrayOutputStream buffer;

    /**
     * Creates an empty writer.
     */
    public LpWriter()
    {
        this.buffer = new ByteArrayOutputStream();
    }

    /**
     * Creates a writer that starts with the given label.
     *
     * @param label The domain separation label.
     * @return The new writer.
     */
    public static LpWriter label(DomainLabel label)
    {
        return new LpWriter().str(label.getLabel());
    }

    /**
     * Writes a length-prefixed byte string.
     *
     * @param data The bytes to write, null is written as an empty string.
     * @return This writer.
     */
    public LpWriter lp(byte[] data)
    {
        byte[] value = data == null ? new byte[0] : data;
        this.buffer.writeBytes(ByteBuffer.allocate(4).putInt(value.length).array());
        this.buffer.writeBytes(value);
        return this;
    }

    /**
     * Writes a length-prefixed UTF-8 string.
     *
     * @param value The string to write, null is written as an empty string.
     * @return This writer.
     */
    public LpWriter str(String value)
    {
        return this.lp(value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Writes a length-prefixed signed 64-bit big-endian integer.
     *
     * @param value The integer to write.
     * @return This writer.
     */
    public LpWriter integer(long value)
    {
        return this.lp(ByteBuffer.allocate(8).putLong(value).array());
    }

    /**
     * Writes a length-prefixed UUID as its 16 raw bytes.
     *
     * @param uuid The UUID to write.
     * @return This writer.
     */
    public LpWriter uuid(UUID uuid)
    {
        ByteBuffer bytes = ByteBuffer.allocate(16);
        bytes.putLong(uuid.getMostSignificantBits());
        bytes.putLong(uuid.getLeastSignificantBits());
        return this.lp(bytes.array());
    }

    /**
     * Writes a typed key as its algorithm name followed by its raw bytes. A null key is written as two empty strings.
     *
     * @param key The key to write.
     * @return This writer.
     */
    public LpWriter key(TypedKey key)
    {
        if(key == null)
        {
            return this.str("").lp(new byte[0]);
        }

        return this.str(key.algorithm().getName()).lp(key.raw());
    }

    /**
     * Writes a boolean as an integer (1 or 0).
     *
     * @param value The boolean to write.
     * @return This writer.
     */
    public LpWriter bool(boolean value)
    {
        return this.integer(value ? 1 : 0);
    }

    /**
     * Writes raw bytes without a length prefix.
     *
     * @param data The bytes to write.
     * @return This writer.
     */
    public LpWriter raw(byte[] data)
    {
        this.buffer.writeBytes(data);
        return this;
    }

    /**
     * Returns the bytes written so far.
     *
     * @return The encoded bytes.
     */
    public byte[] toByteArray()
    {
        return this.buffer.toByteArray();
    }
}