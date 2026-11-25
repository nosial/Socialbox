package net.nosial.socialbox.objects.cryptography;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import net.nosial.socialbox.classes.encoding.Base64Url;
import net.nosial.socialbox.enums.cryptography.Algorithms;
import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.interfaces.NamedEnumInterface;

import java.security.MessageDigest;
import java.util.Arrays;

public record TypedKey(Algorithms algorithm, byte[] raw)
{
    /**
     * Validates the key on construction.
     *
     * @throws CryptographyException If the algorithm is unknown or the key has the wrong length.
     */
    public TypedKey
    {
        if(algorithm == null || raw == null)
        {
            throw new CryptographyException("Typed keys require an algorithm and key bytes");
        }

        int expectedLength = switch(algorithm)
        {
            case Algorithms.ED25519, Algorithms.X25519 -> 32;
            default -> throw new CryptographyException(String.format("Unsupported key algorithm '%s'", algorithm));
        };

        if(raw.length != expectedLength)
        {
            throw new CryptographyException(String.format("Invalid %s key length %d", algorithm, raw.length));
        }

        raw = raw.clone();
    }

    /**
     * Parses a typed key from its string form.
     *
     * @param value The typed key string, e.g. "ed25519:...".
     * @return The parsed key.
     * @throws CryptographyException If the key is malformed or unsupported.
     */
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public static TypedKey parse(String value)
    {
        if(value == null)
        {
            throw new CryptographyException("Typed key cannot be null");
        }

        int separator = value.indexOf(':');
        if(separator <= 0)
        {
            throw new CryptographyException("Typed key is missing its algorithm prefix");
        }

        try
        {
            return new TypedKey(algorithmOf(value.substring(0, separator)), Base64Url.decode(value.substring(separator + 1)));
        }
        catch(IllegalArgumentException e)
        {
            throw new CryptographyException("Typed key is not valid base64url", e);
        }
    }

    /**
     * Returns the algorithm of a wire name, e.g. "ed25519".
     *
     * @param name The algorithm name.
     * @return The algorithm.
     * @throws CryptographyException If no algorithm has the name.
     */
    private static Algorithms algorithmOf(String name)
    {
        Algorithms algorithm = NamedEnumInterface.fromName(Algorithms.class, name);
        if(algorithm != null)
        {
            return algorithm;
        }

        throw new CryptographyException(String.format("Unsupported key algorithm '%s'", name));
    }

    /**
     * Returns whether this key is of the given algorithm.
     *
     * @param algorithmName The algorithm name to compare.
     * @return True if the algorithm matches.
     */
    public boolean isAlgorithm(Algorithms algorithmName)
    {
        return this.algorithm == algorithmName;
    }

    /**
     * Returns a copy of the raw key bytes.
     *
     * @return The raw key bytes.
     */
    @Override
    public byte[] raw()
    {
        return this.raw.clone();
    }

    /**
     * Returns the string form of this key.
     *
     * @return The typed key string.
     */
    @JsonValue
    @Override
    public String toString()
    {
        return this.algorithm.getName() + ":" + Base64Url.encode(this.raw);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object other)
    {
        if(this == other)
        {
            return true;
        }

        if(!(other instanceof TypedKey(Algorithms otherAlgorithm, byte[] otherRaw)))
        {
            return false;
        }

        return this.algorithm.equals(otherAlgorithm) && MessageDigest.isEqual(this.raw, otherRaw);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        return 31 * this.algorithm.hashCode() + Arrays.hashCode(this.raw);
    }
}