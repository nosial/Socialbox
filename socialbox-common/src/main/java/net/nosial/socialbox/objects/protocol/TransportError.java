package net.nosial.socialbox.objects.protocol;

public record TransportError(int code, String message, long ref, Object data)
{
}
