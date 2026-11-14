package net.nosial.socialbox.exceptions;

import net.nosial.socialbox.enums.StandardError;

public class ProtocolException extends SocialboxException
{
    /**
     * Creates a new exception.
     *
     * @param message The error message.
     */
    public ProtocolException(String message)
    {
        super(StandardError.BAD_REQUEST, message);
    }

    /**
     * Creates a new exception with a cause.
     *
     * @param message The error message.
     * @param cause The cause.
     */
    public ProtocolException(String message, Throwable cause)
    {
        super(StandardError.BAD_REQUEST, message, cause);
    }
}
