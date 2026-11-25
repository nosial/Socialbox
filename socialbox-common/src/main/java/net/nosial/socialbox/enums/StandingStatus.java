package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum StandingStatus implements NamedEnumInterface
{
    /**
     * The account is active
     */
    ACTIVE,

    /**
     * The account is disabled
     */
    DISABLED,

    /**
     * The account wasn't found in the server
     */
    NOT_FOUND,

    /**
     * The account is active, but the session key the standing was asked for is not served any more: it was not used
     * within the server's session lifetime
     */
    SESSION_EXPIRED
}
