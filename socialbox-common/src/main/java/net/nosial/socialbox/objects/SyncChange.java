package net.nosial.socialbox.objects;

/**
 * One changed record of an account's sync store, as announced by a {@code sync.changed} event. The event only says
 * that a record changed; sessions fetch the record itself to learn what changed.
 *
 * @param recordId The opaque identifier of the record.
 * @param revision The record's revision after the change.
 * @param modseq The record's position in the account's change sequence.
 */
public record SyncChange(byte[] recordId, long revision, long modseq)
{
}
