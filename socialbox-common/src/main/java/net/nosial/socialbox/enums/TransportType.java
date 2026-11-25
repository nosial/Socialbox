package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum TransportType implements NamedEnumInterface
{
    /**
     * Raw TCP with length prefixed frames, MessagePack bodies. Supports events and streaming.
     */
    TCP("tcp", Encoding.MSGPACK, true),

    /**
     * WebSocket binary frames, MessagePack bodies. Supports events and streaming.
     */
    WEBSOCKET("ws", Encoding.MSGPACK, true),

    /**
     * HTTP request/response, JSON bodies. Does not support events or streaming methods.
     */
    HTTP("http", Encoding.JSON, false);

    private final String name;
    private final Encoding encoding;
    private final boolean streaming;

    TransportType(String name, Encoding encoding, boolean streaming)
    {
        this.name = name;
        this.encoding = encoding;
        this.streaming = streaming;
    }

    /**
     * Returns the transport name as used in DNS records and server information.
     *
     * @return The transport name.
     */
    @Override
    public String getName()
    {
        return this.name;
    }

    /**
     * Returns the body encoding of the transport.
     *
     * @return The encoding.
     */
    public Encoding getEncoding()
    {
        return this.encoding;
    }

    /**
     * Returns whether the transport keeps a connection open and can carry server pushed events.
     *
     * @return True for streaming transports.
     */
    public boolean isStreaming()
    {
        return this.streaming;
    }
}
