package net.nosial.socialbox.cryptography;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public final class LpReader
{
    private final ByteBuffer buffer;

    /**
     * Creates a reader over the given bytes.
     *
     * @param data The bytes to read.
     */
    public LpReader(byte[] data)
    {
        this.buffer = ByteBuffer.wrap(data);
    }

    /**
     * Reads a length-prefixed byte string.
     *
     * @return The bytes read.
     * @throws IllegalArgumentException If the data is truncated.
     */
    public byte[] lp()
    {
        if(this.buffer.remaining() < 4)
        {
            throw new IllegalArgumentException("Truncated length prefix");
        }

        int length = this.buffer.getInt();
        if(length < 0 || length > this.buffer.remaining())
        {
            throw new IllegalArgumentException("Invalid length prefix");
        }

        byte[] value = new byte[length];
        this.buffer.get(value);
        return value;
    }

    /**
     * Reads a length-prefixed UTF-8 string.
     *
     * @return The string read.
     */
    public String str()
    {
        return new String(this.lp(), StandardCharsets.UTF_8);
    }

    /**
     * Reads a length-prefixed 64-bit integer.
     *
     * @return The integer read.
     */
    public long integer()
    {
        byte[] value = this.lp();
        if(value.length != 8)
        {
            throw new IllegalArgumentException("Invalid integer length");
        }

        return ByteBuffer.wrap(value).getLong();
    }

    /**
     * Returns whether there is unread data left.
     *
     * @return True if data remains.
     */
    public boolean hasRemaining()
    {
        return this.buffer.hasRemaining();
    }
}