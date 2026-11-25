package net.nosial.socialbox.enums.cryptography;

public enum DomainLabel
{
    /**
     * A standing statement signed by a host key.
     */
    STANDING("standing"),

    /**
     * An entry of an account log, signed by the account key.
     */
    ACCOUNT_LOG_ENTRY("account-log-entry"),

    /**
     * A host key endorsed by another host key.
     */
    HOST_KEY_ENDORSEMENT("host-key-endorsement"),

    /**
     * The signed server information.
     */
    SERVER_INFORMATION("server-information"),

    /**
     * A detached content signature.
     */
    CONTENT_SIGNATURE("content-signature"),

    /**
     * A passphrase protected identity or session file.
     */
    PROTECTED_FILE("protected-file"),

    /**
     * The key a server encrypts data with that only it reads back (stored session keys, OTP secrets), derived from
     * its host key.
     */
    INTERNAL_KEY("internal-key"),

    /**
     * The additional data binding a stored OTP secret to its account.
     */
    OTP_SECRET("otp-secret"),

    /**
     * The additional data binding stored session keys to their session.
     */
    SESSION_KEYS("session-keys"),

    /**
     * The signing input of a request envelope.
     */
    REQUEST("request"),

    /**
     * The handshake transcript.
     */
    TRANSCRIPT("transcript"),

    /**
     * The server's handshake signature.
     */
    SERVER_HELLO("server-hello"),

    /**
     * The client's handshake signature.
     */
    CLIENT_FINISH("client-finish"),

    /**
     * The account kex key, derived from the account key's seed. Key boxes for the identity file are sealed to it.
     */
    ACCOUNT_KEX("account-kex"),

    /**
     * The account encryption key of a generation, derived from its root secret.
     */
    ENCRYPTION_KEY("encryption-key"),

    /**
     * The key that seals sync records of a generation, derived from its root secret.
     */
    SYNC_KEY("sync-key"),

    /**
     * The key that names sync records, derived from the first root secret.
     */
    SYNC_INDEX("sync-index"),

    /**
     * A key box: the root secrets sealed to a session or to the account kex key.
     */
    ROOT_SECRET("root-secret"),

    /**
     * The sealed value of a sync record.
     */
    SYNC_RECORD("sync-record"),

    /**
     * A term of a collection's integrity digest.
     */
    SYNC_DIGEST("sync-digest"),

    /**
     * A session heartbeat, signed by the session inside its sync record.
     */
    HEARTBEAT("heartbeat"),

    /**
     * The salt of the password authenticator.
     */
    PASSWORD("password"),

    /**
     * The client to server session key.
     */
    SESSION_CLIENT_TO_SERVER("session-c2s"),

    /**
     * The server to client session key.
     */
    SESSION_SERVER_TO_CLIENT("session-s2c"),

    /**
     * The key of a session direction for an epoch of 2^32 sequence numbers past the first.
     */
    SESSION_EPOCH("session-epoch");

    /**
     * The prefix of every label.
     */
    public static final String PREFIX = "SB ";

    private final String label;

    DomainLabel(String name)
    {
        this.label = PREFIX + name;
    }

    /**
     * Returns the label.
     *
     * @return The label, e.g. {@code "SB standing"}.
     */
    public String getLabel()
    {
        return this.label;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return this.label;
    }
}
