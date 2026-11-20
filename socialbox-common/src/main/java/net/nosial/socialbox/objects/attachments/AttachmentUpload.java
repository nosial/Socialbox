package net.nosial.socialbox.objects.attachments;

import java.util.List;
import java.util.UUID;

public record AttachmentUpload(UUID attachmentUuid, long size, int chunkCount, int chunkSize, List<Integer> missing, boolean complete,
                          long expires)
{
}
