package net.nosial.socialbox.classes.cryptography;

import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.SigningKeyPair;
import net.nosial.socialbox.objects.cryptography.TypedKey;

public final class ContentSignature
{
    private ContentSignature()
    {
    }

    /**
     * Returns the signed bytes of a content signature.
     *
     * @param author The author.
     * @param sha256 The SHA-256 hash of the content.
     * @param time When the content was signed (ms), 0 if not stated.
     * @param signer The session's signing key.
     * @return The signed bytes.
     */
    public static byte[] input(PeerAddress author, byte[] sha256, long time, TypedKey signer)
    {
        return LpWriter.label(DomainLabel.CONTENT_SIGNATURE).str(author.toString()).lp(sha256).integer(time).key(signer).toByteArray();
    }

    /**
     * Signs content.
     *
     * @param author The author.
     * @param sessionKeyPair The session's signing key pair.
     * @param content The content.
     * @param time When the content was signed (ms), 0 if not stated.
     * @return The signature.
     */
    public static byte[] sign(PeerAddress author, SigningKeyPair sessionKeyPair, byte[] content, long time)
    {
        return sessionKeyPair.sign(input(author, Cryptography.hash(content), time, sessionKeyPair.publicKey()));
    }
}
