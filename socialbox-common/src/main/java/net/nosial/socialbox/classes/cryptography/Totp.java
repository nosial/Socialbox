package net.nosial.socialbox.classes.cryptography;

import net.nosial.socialbox.exceptions.CryptographyException;

import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Totp
{
    /**
     * The number of digits of a code.
     */
    public static final int DIGITS = 6;

    /**
     * The time step in seconds.
     */
    public static final int PERIOD = 30;

    /**
     * The length of generated secrets in bytes.
     */
    public static final int SECRET_LENGTH = 20;

    private static final char[] BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private Totp()
    {
    }

    /**
     * Generates a new random secret.
     *
     * @return The secret bytes.
     */
    public static byte[] generateSecret()
    {
        return Cryptography.randomBytes(SECRET_LENGTH);
    }

    /**
     * Generates the code for the given time.
     *
     * @param secret The secret.
     * @param epochSeconds The time in seconds since the epoch.
     * @return The zero padded code.
     */
    public static String generate(byte[] secret, long epochSeconds)
    {
        return generateForCounter(secret, Math.floorDiv(epochSeconds, PERIOD));
    }

    /**
     * Generates the code for the current time.
     *
     * @param secret The secret.
     * @return The zero padded code.
     */
    public static String generate(byte[] secret)
    {
        return generate(secret, System.currentTimeMillis() / 1000L);
    }

    /**
     * Verifies a code, accepting one step of clock drift in either direction.
     *
     * @param secret The secret.
     * @param code The code to verify.
     * @param epochSeconds The current time in seconds.
     * @return True if the code is valid.
     */
    public static boolean verify(byte[] secret, String code, long epochSeconds)
    {
        return match(secret, code, epochSeconds) >= 0;
    }

    /**
     * Finds the time step a code belongs to, accepting one step of clock drift in either direction. Servers record the
     * step of every accepted code and reject codes of that step or earlier ones, so a code is only accepted once.
     *
     * @param secret The secret.
     * @param code The code to verify.
     * @param epochSeconds The current time in seconds.
     * @return The time step (counter) of the code, or -1 if the code is invalid.
     */
    public static long match(byte[] secret, String code, long epochSeconds)
    {
        if(code == null || code.length() != DIGITS)
        {
            return -1;
        }

        long counter = Math.floorDiv(epochSeconds, PERIOD);
        long matched = -1;
        for(long offset = -1; offset <= 1; offset++)
        {
            // Every step is compared, in constant time, whether or not an earlier one matched
            if(Cryptography.constantTimeEquals(generateForCounter(secret, counter + offset).getBytes(StandardCharsets.US_ASCII),
                    code.getBytes(StandardCharsets.US_ASCII)))
            {
                matched = counter + offset;
            }
        }

        return matched;
    }

    /**
     * Builds the otpauth:// URI authenticator apps import, usually shown as a QR code.
     *
     * @param issuer The issuer (the server domain).
     * @param account The account name (the peer address).
     * @param secret The secret.
     * @return The otpauth URI.
     */
    public static String buildUri(String issuer, String account, byte[] secret)
    {
        String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8).replace("+", "%20");
        String encodedAccount = URLEncoder.encode(account, StandardCharsets.UTF_8).replace("+", "%20");
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
                encodedIssuer, encodedAccount, base32Encode(secret), encodedIssuer, DIGITS, PERIOD);
    }

    /**
     * Encodes bytes as unpadded base32 (RFC 4648), the secret format of otpauth URIs.
     *
     * @param data The bytes to encode.
     * @return The base32 string.
     */
    public static String base32Encode(byte[] data)
    {
        StringBuilder builder = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for(byte b : data)
        {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while(bits >= 5)
            {
                builder.append(BASE32_ALPHABET[(buffer >> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }

        if(bits > 0)
        {
            builder.append(BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1F]);
        }

        return builder.toString();
    }

    /**
     * Decodes unpadded or padded base32 (RFC 4648), case-insensitively.
     *
     * @param data The base32 string.
     * @return The decoded bytes.
     */
    public static byte[] base32Decode(String data)
    {
        String normalized = data.replace("=", "").replace(" ", "").toUpperCase();
        ByteBuffer output = ByteBuffer.allocate(normalized.length() * 5 / 8);
        int buffer = 0;
        int bits = 0;
        for(char c : normalized.toCharArray())
        {
            int value = c >= 'A' && c <= 'Z' ? c - 'A' : c >= '2' && c <= '7' ? c - '2' + 26 : -1;
            if(value < 0)
            {
                throw new IllegalArgumentException("Invalid base32 character");
            }

            buffer = (buffer << 5) | value;
            bits += 5;
            if(bits >= 8)
            {
                output.put((byte) ((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return output.array();
    }

    /**
     * Generates the HOTP code (RFC 4226) for a counter value.
     *
     * @param secret The secret.
     * @param counter The counter.
     * @return The zero padded code.
     */
    private static String generateForCounter(byte[] secret, long counter)
    {
        try
        {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);
            return String.format("%0" + DIGITS + "d", binary % 1_000_000);
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("Failed to generate a one-time password", e);
        }
    }
}
