package net.nosial.socialbox.objects.accounts;

import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.interfaces.SignedInterface;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.SigningKeyPair;
import net.nosial.socialbox.objects.cryptography.TypedKey;

/**
 * A session's proof of life, stored sealed in the collection {@code sb/core.sessions} and signed by the session
 * itself. The server can neither read nor forge one, so it cannot keep a stolen session alive in the eyes of the
 * account's other sessions; it can only hide heartbeats. Sessions also compare the account log heads in each other's
 * heartbeats to notice a server that shows them different logs.
 *
 * @param address The account.
 * @param signingKey The session's signing key, which signs the heartbeat.
 * @param label The session's human name, which the account log no longer carries.
 * @param lastActive When the session was last used (ms).
 * @param logSeq The seq of the account log head the session last saw.
 * @param logHash The hash of that head.
 * @param signer The session's signing key.
 * @param signature The signature.
 */
public record Heartbeat(PeerAddress address, TypedKey signingKey, String label, long lastActive, long logSeq, byte[] logHash,
                        TypedKey signer, byte[] signature) implements SignedInterface
{
    /**
     * The maximum length of a session label.
     */
    public static final int MAX_LABEL_LENGTH = 64;

    /**
     * Creates and signs a heartbeat.
     *
     * @param address The account.
     * @param sessionKeyPair The session's signing key pair.
     * @param label The session's label.
     * @param head The account log head the session sees.
     * @return The heartbeat.
     */
    public static Heartbeat create(PeerAddress address, SigningKeyPair sessionKeyPair, String label, AccountLogHead head)
    {
        String safeLabel = label == null ? "" : label.length() > MAX_LABEL_LENGTH ? label.substring(0, MAX_LABEL_LENGTH) : label;
        long now = System.currentTimeMillis();
        Heartbeat unsigned = new Heartbeat(address, sessionKeyPair.publicKey(), safeLabel, now, head.seq(), head.hash(),
                sessionKeyPair.publicKey(), new byte[0]);
        return new Heartbeat(address, sessionKeyPair.publicKey(), safeLabel, now, head.seq(), head.hash(), sessionKeyPair.publicKey(),
                sessionKeyPair.sign(unsigned.tbs()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] tbs()
    {
        return LpWriter.label(DomainLabel.HEARTBEAT)
                .str(this.address == null ? null : this.address.toString())
                .key(this.signingKey)
                .str(this.label)
                .integer(this.lastActive)
                .integer(this.logSeq)
                .lp(this.logHash)
                .key(this.signer)
                .toByteArray();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isWellFormed()
    {
        return this.address != null && this.signingKey != null && this.signingKey.equals(this.signer) && this.label != null &&
                this.label.length() <= MAX_LABEL_LENGTH && this.logHash != null;
    }
}
