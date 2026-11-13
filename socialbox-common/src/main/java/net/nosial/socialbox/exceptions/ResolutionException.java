package net.nosial.socialbox.exceptions;

import net.nosial.socialbox.enums.StandardError;

public class ResolutionException extends SocialboxException
{
    /**
     * Creates a new exception.
     *
     * @param message The error message.
     */
    public ResolutionException(String message)
    {
        super(StandardError.RESOLUTION_FAILED, message);
    }

    /**
     * Creates a new exception with a cause.
     *
     * @param message The error message.
     * @param cause The cause.
     */
    public ResolutionException(String message, Throwable cause)
    {
        super(StandardError.RESOLUTION_FAILED, message, cause);
    }
}