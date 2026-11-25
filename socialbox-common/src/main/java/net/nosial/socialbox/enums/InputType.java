package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum InputType implements NamedEnumInterface
{
    /**
     * No input; the user confirms (accepting a document) or acts elsewhere (opening a URL).
     */
    NONE,

    /**
     * Free text.
     */
    TEXT,

    /**
     * A password. The client never sends the password itself; it derives the password authenticator
     * ({@code PBKDF2-SHA256(password, H(str("SB password") || str(address)))}) and sends that.
     */
    PASSWORD,

    /**
     * A numeric one-time password from an authenticator app.
     */
    OTP
}
