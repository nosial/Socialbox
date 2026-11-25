package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum SessionStatus implements NamedEnumInterface
{
    /**
     * Added to the account log, not revoked and not expired.
     */
    ACTIVE,

    /**
     * Revoked by the account log; revocation is final.
     */
    REVOKED,

    /**
     * Added to the account log, but past its expiry.
     */
    EXPIRED,

    /**
     * Not in the account log.
     */
    NOT_FOUND
}
