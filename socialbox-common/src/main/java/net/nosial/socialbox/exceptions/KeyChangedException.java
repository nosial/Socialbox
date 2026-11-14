package net.nosial.socialbox.exceptions;

import net.nosial.socialbox.cryptography.TypedKey;
import net.nosial.socialbox.objects.PeerAddress;

public class KeyChangedException extends CryptographyException
{
    private final PeerAddress peer;
    private final TypedKey presentedKey;

    /**
     * Creates a new exception.
     *
     * @param peer The peer.
     * @param presentedKey The account key that was presented for the peer.
     */
    public KeyChangedException(PeerAddress peer, TypedKey presentedKey)
    {
        super(String.format("The account key of %s is not the one pinned for them; confirm the new key before continuing", peer));
        this.peer = peer;
        this.presentedKey = presentedKey;
    }

    /**
     * Returns the peer.
     *
     * @return The peer.
     */
    public PeerAddress getPeer()
    {
        return this.peer;
    }

    /**
     * Returns the account key that was presented for the peer.
     *
     * @return The key.
     */
    public TypedKey getPresentedKey()
    {
        return this.presentedKey;
    }
}
