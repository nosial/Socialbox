package net.nosial.socialbox;

import java.nio.charset.StandardCharsets;

public final class Protocol
{
    /**
     * The protocol version carried in DNS records, hellos and envelope headers.
     */
    public static final String VERSION = "1.0";

    /**
     * The value of the "v" parameter of a Socialbox DNS TXT record.
     */
    public static final String DNS_VERSION = "sb";

    /**
     * The DNS name prefix under which the Socialbox TXT record of a domain is published.
     */
    public static final String DNS_PREFIX = "_socialbox.";

    /**
     * The preamble a raw TCP client sends right after connecting, used by the server to sniff the connection type.
     */
    public static final byte[] TCP_PREAMBLE = "SBX".getBytes(StandardCharsets.US_ASCII);

    /**
     * The HTTP path that is upgraded to a WebSocket connection.
     */
    public static final String WEBSOCKET_PATH = "/ws";

    /**
     * The WebSocket subprotocol negotiated by clients and servers.
     */
    public static final String WEBSOCKET_SUBPROTOCOL = "socialbox.sb";

    /**
     * The port of servers that use TLS when their DNS record names none: the standard HTTPS port, so an instance is
     * reached like any website, e.g. {@code https://socialbox.example.com/}.
     */
    public static final int HTTPS_PORT = 443;

    /**
     * The port of servers without TLS when their DNS record names none: the standard HTTP port.
     */
    public static final int HTTP_PORT = 80;

    /**
     * The content type of JSON bodies on the HTTP transport.
     */
    public static final String CONTENT_TYPE_JSON = "application/json";

    /**
     * The content type of a sealed envelope payload on the HTTP transport, whose header travels as
     * {@code Socialbox-*} HTTP headers.
     */
    public static final String CONTENT_TYPE_SEALED = "application/vnd.socialbox.sealed";

    /**
     * The username every server uses when it acts as a client of another server.
     */
    public static final String HOST_USERNAME = "host";

    private Protocol()
    {
    }
}
