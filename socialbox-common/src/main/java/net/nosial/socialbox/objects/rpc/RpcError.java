package net.nosial.socialbox.objects.rpc;

public record RpcError(int code, String message, Object data)
{
}
