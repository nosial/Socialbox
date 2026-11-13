package net.nosial.socialbox.exceptions;

import net.nosial.socialbox.enums.StandardError;

public class RpcException extends SocialboxException
{
    /**
     * Creates a new RPC exception.
     *
     * @param error The standard error.
     * @param message The error message.
     */
    public RpcException(StandardError error, String message)
    {
        super(error, message);
    }

    /**
     * Creates a new RPC exception with structured data.
     *
     * @param error The standard error.
     * @param message The error message.
     * @param data Structured data describing the error.
     */
    public RpcException(StandardError error, String message, Object data)
    {
        super(error, message, data, null);
    }

    /**
     * Creates a new RPC exception with a cause.
     *
     * @param error The standard error.
     * @param message The error message.
     * @param cause The cause.
     */
    public RpcException(StandardError error, String message, Throwable cause)
    {
        super(error, message, cause);
    }
}
