package net.nosial.socialbox.objects.sync;

/**
 * One write of a {@code syncPut}. The new revision is {@code expected_revision + 1}.
 *
 * @param recordId The opaque identifier of the record.
 * @param expectedRevision The revision the client expects is stored, 0 for a new record.
 * @param generation The root secret generation the value is sealed under.
 * @param value The sealed, padded value, null to delete the record.
 */
public record SyncWrite(byte[] recordId, long expectedRevision, int generation, byte[] value)
{
}
