package net.nosial.socialbox.objects.rpc;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.ALWAYS)
public record RpcResponse(String id, Object result, RpcError error)
{
    /**
     * Creates a successful response.
     *
     * @param id The request identifier.
     * @param result The result.
     * @return The response.
     */
    public static RpcResponse success(String id, Object result)
    {
        return new RpcResponse(id, result, null);
    }

    /**
     * Creates an error response.
     *
     * @param id The request identifier.
     * @param error The error.
     * @return The response.
     */
    public static RpcResponse failure(String id, RpcError error)
    {
        return new RpcResponse(id, null, error);
    }
}
