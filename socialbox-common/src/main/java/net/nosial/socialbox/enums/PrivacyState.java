package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum PrivacyState implements NamedEnumInterface
{
    /**
     * Visible to everyone through {@code resolvePeer}.
     */
    PUBLIC,

    /**
     * Visible to the owner's own sessions (and their server, which may need it to operate) only.
     */
    PRIVATE;

    /**
     * Returns whether a field of this privacy is visible to peers other than the owner.
     *
     * @return True if the field is visible to others.
     */
    public boolean isPublic()
    {
        return this == PUBLIC;
    }
}
