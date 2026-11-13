package net.nosial.socialbox.exceptions;

import net.nosial.socialbox.enums.StandardError;

public class TransportException extends SocialboxException
{
    /**
     * Creates a new exception.
     *
     * @param message The error message.
     */
    public TransportException(String message)
    {
        super(StandardError.SERVER_UNAVAILABLE, message);
    }

    /**
     * Creates a new exception with a cause.
     *
     * @param message The error message.
     * @param cause The cause.
     */
    public TransportException(String message, Throwable cause)
    {
        super(StandardError.SERVER_UNAVAILABLE, message, cause);
    }
}
