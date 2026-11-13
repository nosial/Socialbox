package net.nosial.socialbox.cryptography;

import java.util.Base64;

public final class Base64Url
{
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url()
    {
    }

    /**
     * Encodes the given bytes as base64url without padding.
     *
     * @param data The bytes to encode.
     * @return The encoded string.
     */
    public static String encode(byte[] data)
    {
        return ENCODER.encodeToString(data);
    }

    /**
     * Decodes a canonical base64url string: no padding, only the URL-safe alphabet, and unused trailing bits set to
     * zero. Every value therefore has exactly one accepted encoding, as in libsodium's
     * {@code sodium_base642bin(..., sodium_base64_VARIANT_URLSAFE_NO_PADDING)}.
     *
     * @param data The string to decode.
     * @return The decoded bytes.
     * @throws IllegalArgumentException If the string is not canonical base64url.
     */
    public static byte[] decode(String data)
    {
        if(data == null)
        {
            throw new IllegalArgumentException("Base64url data cannot be null");
        }

        if(data.indexOf('=') >= 0)
        {
            throw new IllegalArgumentException("Base64url data must not be padded");
        }

        byte[] decoded = DECODER.decode(data);
        if(!ENCODER.encodeToString(decoded).equals(data))
        {
            throw new IllegalArgumentException("Base64url data is not canonical");
        }

        return decoded;
    }
}
