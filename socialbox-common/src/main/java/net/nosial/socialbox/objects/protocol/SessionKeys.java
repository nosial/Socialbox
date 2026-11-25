package net.nosial.socialbox.objects.protocol;

import net.nosial.socialbox.classes.cryptography.Cryptography;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.DomainLabel;

public record SessionKeys(byte[] clientToServer, byte[] serverToClient)
{
    /**
     * Derives the session keys.
     *
     * @param transcript The transcript hash.
     * @param sharedSecret The ephemeral key agreement result.
     * @return The session keys.
     */
    public static SessionKeys derive(byte[] transcript, byte[] sharedSecret)
    {
        byte[] prk = Cryptography.hkdfExtract(transcript, sharedSecret);
        return new SessionKeys(
                Cryptography.hkdfExpand(prk, LpWriter.label(DomainLabel.SESSION_CLIENT_TO_SERVER).toByteArray(), Cryptography.KEY_LENGTH),
                Cryptography.hkdfExpand(prk, LpWriter.label(DomainLabel.SESSION_SERVER_TO_CLIENT).toByteArray(), Cryptography.KEY_LENGTH));
    }

    /**
     * The number of envelopes sealed under one key: the AEAD nonces are random, so a key must stay well below the
     * 96-bit birthday bound.
     */
    public static final int EPOCH_BITS = 32;

    /**
     * Returns the key that seals the envelope with a sequence number. Every 2^32 sequence numbers form an epoch with
     * its own key, so sessions never run out of sequence numbers while no key seals more than 2^32 envelopes. Epoch 0
     * uses the direction key itself.
     *
     * @param directionKey The direction's session key.
     * @param seq The envelope's sequence number.
     * @return The key of the sequence number's epoch.
     */
    public static byte[] epochKey(byte[] directionKey, long seq)
    {
        long epoch = seq >>> EPOCH_BITS;
        if(epoch == 0)
        {
            return directionKey;
        }

        return Cryptography.hkdfExpand(directionKey, LpWriter.label(DomainLabel.SESSION_EPOCH).integer(epoch).toByteArray(), Cryptography.KEY_LENGTH);
    }
}
