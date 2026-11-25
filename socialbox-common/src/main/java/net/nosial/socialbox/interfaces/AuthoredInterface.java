package net.nosial.socialbox.interfaces;

import net.nosial.socialbox.objects.addresses.PeerAddress;

public interface AuthoredInterface extends SignedInterface
{
    /**
     * Returns the user who wrote the content.
     *
     * @return The author.
     */
    PeerAddress author();

    /**
     * Returns when the content was signed.
     *
     * @return The time in milliseconds.
     */
    long timestamp();

    /**
     * Returns whether the object has an author who is a user; servers never author user content.
     *
     * @return True if well formed.
     */
    @Override
    default boolean isWellFormed()
    {
        PeerAddress author = this.author();
        return author != null && !author.isHost();
    }
}
