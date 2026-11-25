package net.nosial.socialbox.objects.sync;

/**
 * The plaintext of a sync record, which only the account's sessions see.
 *
 * @param collection The collection, such as {@code sb/core.contacts}.
 * @param name The record's name within the collection; empty for the collection's head record.
 * @param value The value.
 */
public record SyncEntry(String collection, String name, byte[] value)
{
    /**
     * Returns whether this is the head record of its collection.
     *
     * @return True for the head record.
     */
    public boolean isHead()
    {
        return this.name.isEmpty();
    }
}
