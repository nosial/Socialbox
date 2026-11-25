package net.nosial.socialbox.exceptions;

public class SyncIntegrityException extends CryptographyException
{
    /**
     * Creates a new exception.
     *
     * @param message The error message.
     */
    public SyncIntegrityException(String message)
    {
        super(message);
    }
}
