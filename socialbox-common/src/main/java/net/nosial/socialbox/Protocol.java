package net.nosial.socialbox;

import java.nio.charset.StandardCharsets;

public final class Protocol
{
    /**
     * The protocol version carried in DNS records, hellos and envelope headers.
     */
    public static final int VERSION = 1;

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
     * The default port a Socialbox server listens on for all transports.
     */
    public static final int DEFAULT_PORT = 7700;

    /**
     * The maximum size of a single frame, HTTP body or envelope in bytes.
     */
    public static final int MAX_FRAME_SIZE = 1024 * 1024;

    /**
     * The maximum number of requests in a single RPC batch.
     */
    public static final int MAX_BATCH_SIZE = 32;

    /**
     * The maximum accepted clock skew between peers in milliseconds.
     */
    public static final long MAX_CLOCK_SKEW = 60_000L;

    /**
     * The maximum lifetime of a standing statement in milliseconds.
     */
    public static final long MAX_STANDING_LIFETIME = 600_000L;

    /**
     * The time a pending handshake may take before it is discarded, in milliseconds.
     */
    public static final long HANDSHAKE_TIMEOUT = 30_000L;

    /**
     * The size of the replay window of envelope sequence numbers.
     */
    public static final int REPLAY_WINDOW_SIZE = 1024;

    /**
     * The username every server uses when it acts as a client of another server.
     */
    public static final String HOST_USERNAME = "host";

}
