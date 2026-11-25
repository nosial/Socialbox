package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum AccountLogEntryType implements NamedEnumInterface
{
    /**
     * The first entry of every log, signed by the account key. {@code key} is the account key and {@code kex_key} the
     * account kex key, derived from the account key, which key boxes for the identity file are sealed to.
     */
    GENESIS,

    /**
     * Adds a session, signed by the account key. {@code key} is the session's signing key and {@code kex_key} the key
     * its key boxes are sealed to.
     */
    SESSION_ADD,

    /**
     * Revokes the session whose signing key is {@code key}, signed by the account key. Final.
     */
    SESSION_REVOKE,

    /**
     * Starts a new root secret generation, signed by the account key or by an active session. {@code key} is the
     * account's encryption key derived from the new root secret, which others seal to, and {@code members} lists the
     * signing keys of the sessions that receive the new root secret.
     */
    GENERATION,

    /**
     * Replaces the account key with {@code key} and the account kex key with {@code kex_key}, signed by the current
     * account key. The next entry signed by the account key must be signed by the new key.
     */
    ACCOUNT_KEY_ROTATE
}
