package net.nosial.socialbox.objects.spaces;

import net.nosial.socialbox.enums.RecordClass;

import java.util.UUID;

/**
 * One record of a private space (a private board or group chat) as its origin server stores it: opaque and padded.
 *
 * @param recordId 16 random bytes chosen by the writer.
 * @param recordClass Governance or content, in the clear for the origin's cleanup.
 * @param epoch The epoch whose content key sealed it.
 * @param sealed The sealed, padded record.
 * @param modseq Its position in the space's record stream (0 when submitting).
 */
public record SealedRecord(UUID recordId, long epoch, RecordClass recordClass, byte[] sealed, long modseq)
{
}
