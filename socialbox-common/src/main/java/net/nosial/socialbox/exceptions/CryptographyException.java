package net.nosial.socialbox.exceptions;

import net.nosial.socialbox.enums.StandardError;

public class CryptographyException extends SocialboxException
{
    /**
     * Creates a new exception.
     *
     * @param message The error message.
     */
    public CryptographyException(String message)
    {
        super(StandardError.CRYPTOGRAPHIC_ERROR, message);
    }

    /**
     * Creates a new exception with a cause.
     *
     * @param message The error message.
     * @param cause The cause.
     */
    public CryptographyException(String message, Throwable cause)
    {
        super(StandardError.CRYPTOGRAPHIC_ERROR, message, cause);
    }
}
