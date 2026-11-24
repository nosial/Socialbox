package net.nosial.socialbox.interfaces;

import net.nosial.socialbox.objects.PeerAddress;

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
}
