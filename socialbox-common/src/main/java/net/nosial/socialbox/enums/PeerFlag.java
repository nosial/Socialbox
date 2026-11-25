package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum PeerFlag implements NamedEnumInterface
{
    /**
     * A server administrator.
     */
    ADMIN,

    /**
     * A server moderator.
     */
    MODERATOR,

    /**
     * A verified account.
     */
    VERIFIED,

    /**
     * A bot account.
     */
    BOT
}
