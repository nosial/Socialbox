package net.nosial.socialbox.objects.attachments;

import net.nosial.socialbox.cryptography.AttachmentCryptography;
import net.nosial.socialbox.cryptography.Cryptography;
import net.nosial.socialbox.cryptography.LpWriter;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public record AttachmentManifest(UUID attachmentUuid, long size, int chunkCount, byte[] root)
{
    /**
     * Appends the manifest's canonical bytes to a signing input.
     *
     * @param writer The writer.
     * @return The writer.
     */
    public LpWriter appendTo(LpWriter writer)
    {
        return writer.uuid(this.attachmentUuid).integer(this.size).integer(this.chunkCount).lp(this.root);
    }

    /**
     * Returns whether the manifest is structurally valid: every field present and the size consistent with the chunk
     * count.
     *
     * @return True if valid.
     */
    public boolean isValid()
    {
        return this.attachmentUuid != null && this.root != null && this.root.length == Cryptography.HASH_LENGTH &&
                AttachmentCryptography.isConsistent(this.size, this.chunkCount);
    }

    /**
     * Appends a list of manifests to a signing input.
     *
     * @param writer The writer.
     * @param attachments The manifests.
     * @return The writer.
     */
    public static LpWriter appendAll(LpWriter writer, List<AttachmentManifest> attachments)
    {
        writer.integer(attachments.size());
        for(AttachmentManifest attachment : attachments)
        {
            attachment.appendTo(writer);
        }

        return writer;
    }

    /**
     * Returns whether every manifest of a list is valid, the list is within a size limit and no attachment is listed
     * twice.
     *
     * @param attachments The manifests, may be null.
     * @param maxAttachments The largest number of attachments.
     * @return True if valid.
     */
    public static boolean isValidList(List<AttachmentManifest> attachments, int maxAttachments)
    {
        if(attachments == null || attachments.size() > maxAttachments)
        {
            return false;
        }

        Set<UUID> seen = new HashSet<>();
        for(AttachmentManifest attachment : attachments)
        {
            if(attachment == null || !attachment.isValid() || !seen.add(attachment.attachmentUuid()))
            {
                return false;
            }
        }

        return true;
    }
}
