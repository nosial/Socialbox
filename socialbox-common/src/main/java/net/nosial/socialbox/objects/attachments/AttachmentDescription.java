package net.nosial.socialbox.objects.attachments;

import java.util.UUID;

public record AttachmentDescription(UUID attachmentUuid, byte[] key, String name, String contentType, long size)
{
}
