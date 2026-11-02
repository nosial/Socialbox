package net.nosial.socialbox.objects;

import java.util.HashMap;

/**
 * Represents a Remote Procedure Call (RPC) request.
 * This record encapsulates the necessary data to represent a request
 * that can be sent to an RPC endpoint for processing.
 * </p>
 * The RpcRequest consists of the following components:
 * - method: The name of the RPC method to be invoked.
 * - id: A unique identifier for the request, often used to correlate responses.
 * - params: A collection of key-value pairs representing the parameters required by the RPC method.
 * - headers: A collection of key-value pairs representing the optional headers to be associated with the request.
 */
public record RpcRequest(String method, String id, HashMap<String, String> params, HashMap<String, String> headers)
{

}
