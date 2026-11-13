package net.nosial.socialbox.exceptions;

import net.nosial.socialbox.enums.StandardError;

public class SocialboxException extends RuntimeException
{
    private final StandardError error;
    private final Object data;

    /**
     * Creates a new exception.
     *
     * @param error The standard error.
     * @param message The error message.
     */
    public SocialboxException(StandardError error, String message)
    {
        this(error, message, null, null);
    }

    /**
     * Creates a new exception with a cause.
     *
     * @param error The standard error.
     * @param message The error message.
     * @param cause The cause.
     */
    public SocialboxException(StandardError error, String message, Throwable cause)
    {
        this(error, message, null, cause);
    }

    /**
     * Creates a new exception with structured data and a cause.
     *
     * @param error The standard error.
     * @param message The error message.
     * @param data Optional structured data describing the error.
     * @param cause The cause, may be null.
     */
    public SocialboxException(StandardError error, String message, Object data, Throwable cause)
    {
        super(message, cause);
        this.error = error == null ? StandardError.UNKNOWN : error;
        this.data = data;
    }

    /**
     * Returns the standard error.
     *
     * @return The standard error.
     */
    public StandardError getError()
    {
        return this.error;
    }

    /**
     * Returns the structured error data, if any.
     *
     * @return The error data or null.
     */
    public Object getData()
    {
        return this.data;
    }
}
