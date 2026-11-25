package net.nosial.socialbox.objects.sync;

/**
 * A record of an account's sync store as the server holds it. The server sees only the opaque identifier, the
 * revision, the generation the value was sealed under, the padded size and the record's position in the change
 * sequence; the value is sealed by the account's sessions.
 *
 * @param recordId The opaque identifier, {@code MAC(index_key, collection || name)}.
 * @param revision The revision, starting at 1 and increasing by one per write.
 * @param generation The root secret generation the value is sealed under.
 * @param value The sealed, padded value, null for a deleted record (tombstone).
 * @param modseq The record's position in the account's change sequence.
 */
public record SyncRecord(byte[] recordId, long revision, int generation, byte[] value, long modseq)
{
    /**
     * Returns whether the record was deleted.
     *
     * @return True for a tombstone.
     */
    public boolean isDeleted()
    {
        return this.value == null;
    }
}
