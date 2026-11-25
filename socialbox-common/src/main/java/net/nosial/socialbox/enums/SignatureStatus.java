package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum SignatureStatus implements NamedEnumInterface
{
    /**
     * The signature is valid and the session is active.
     */
    VERIFIED,

    /**
     * The signature does not verify.
     */
    INVALID,

    /**
     * The peer or session is unknown.
     */
    NOT_FOUND,

    /**
     * The session was revoked.
     */
    REVOKED,

    /**
     * The session or the signed timestamp expired.
     */
    EXPIRED,

    /**
     * The peer's home server could not be reached or answered incorrectly.
     */
    RESOLUTION_ERROR
}
