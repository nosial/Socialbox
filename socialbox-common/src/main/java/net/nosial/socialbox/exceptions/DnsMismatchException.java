package net.nosial.socialbox.exceptions;

import net.nosial.socialbox.enums.StandardError;

public class DnsMismatchException extends SocialboxException
{
    /**
     * Creates a new exception.
     *
     * @param message The error message.
     */
    public DnsMismatchException(String message)
    {
        super(StandardError.DNS_MISMATCH, message);
    }

    /**
     * Creates a new exception with a cause.
     *
     * @param message The error message.
     * @param cause The cause.
     */
    public DnsMismatchException(String message, Throwable cause)
    {
        super(StandardError.DNS_MISMATCH, message, cause);
    }
}
