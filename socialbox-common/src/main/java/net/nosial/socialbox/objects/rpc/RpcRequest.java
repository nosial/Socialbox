package net.nosial.socialbox.objects.rpc;

import java.util.Map;

public record RpcRequest(String id, String method, Map<String, Object> params)
{
}
