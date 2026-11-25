package net.nosial.socialbox.objects.cryptography;

import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.Algorithms;
import net.nosial.socialbox.objects.addresses.PeerAddress;

public record SealedKey(PeerAddress recipient, TypedKey ephemeralKey, byte[] wrappedKey)
{
    /**
     * Appends the seal's canonical bytes to a signing input.
     * <pre>
     *     seal = str(recipient) || key(ephemeral_key) || lp(wrapped_key)
     * </pre>
     *
     * @param writer The writer.
     * @return The writer.
     */
    public LpWriter appendTo(LpWriter writer)
    {
        return writer.str(this.recipient.toString()).key(this.ephemeralKey).lp(this.wrappedKey);
    }

    /**
     * Returns whether every field is present and the ephemeral key is an X25519 key.
     *
     * @return True if well formed.
     */
    public boolean isWellFormed()
    {
        return this.recipient != null && !this.recipient.isHost() && this.ephemeralKey != null && this.ephemeralKey.isAlgorithm(Algorithms.X25519) &&
                this.wrappedKey != null && this.wrappedKey.length > 0;
    }
}
