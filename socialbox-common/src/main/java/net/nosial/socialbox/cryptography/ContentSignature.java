package net.nosial.socialbox.cryptography;

import net.nosial.socialbox.objects.SigningKeyPair;

public final class ContentSignature
{
    /**
     * Returns the signing input of a content hash.
     *
     * @param sha256 The SHA-256 hash of the content.
     * @param time The time in milliseconds, or 0 for an untimed signature.
     * @return The signing input.
     */
    public static byte[] input(byte[] sha256, long time)
    {
        return LpWriter.label("SB signature").lp(sha256).integer(time).toByteArray();
    }

    /**
     * Signs content.
     *
     * @param deviceKeyPair The device key pair.
     * @param content The content.
     * @param time The time in milliseconds, or 0 for an untimed signature.
     * @return The signature.
     */
    public static byte[] sign(SigningKeyPair deviceKeyPair, byte[] content, long time)
    {
        return deviceKeyPair.sign(input(Cryptography.hash(content), time));
    }
}
