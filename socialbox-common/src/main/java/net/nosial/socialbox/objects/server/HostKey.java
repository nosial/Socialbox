package net.nosial.socialbox.objects.server;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.objects.cryptography.TypedKey;

public record HostKey(TypedKey key, long expires)
{
    /**
     * Parses a host key from its DNS form.
     *
     * @param value The value, e.g. "ed25519:abc/1798761600" or "ed25519:abc" (never expires).
     * @return The host key.
     * @throws CryptographyException If the key is malformed.
     */
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public static HostKey parse(String value)
    {
        int separator = value.lastIndexOf('/');
        if(separator < 0)
        {
            return new HostKey(TypedKey.parse(value.trim()), 0);
        }

        try
        {
            return new HostKey(TypedKey.parse(value.substring(0, separator).trim()), Long.parseLong(value.substring(separator + 1).trim()));
        }
        catch(NumberFormatException e)
        {
            throw new CryptographyException("Invalid host key expiry", e);
        }
    }

    /**
     * Returns whether the key has expired.
     *
     * @param nowMillis The current time in milliseconds.
     * @return True if expired.
     */
    public boolean isExpired(long nowMillis)
    {
        return this.expires != 0 && this.expires * 1000L <= nowMillis;
    }

    /**
     * Returns the DNS form of the host key.
     *
     * @return The host key string.
     */
    @JsonValue
    @Override
    public String toString()
    {
        return this.key + "/" + this.expires;
    }
}
