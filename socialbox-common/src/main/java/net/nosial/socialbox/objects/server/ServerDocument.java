package net.nosial.socialbox.objects.server;

import net.nosial.socialbox.enums.DocumentType;

public record ServerDocument(DocumentType type, String title, String contentType, String content, long lastUpdated)
{
}
