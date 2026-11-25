package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.ProtocolLimit;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.StandingStatus;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.interfaces.SignedInterface;
import net.nosial.socialbox.objects.accounts.AccountLogHead;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.SigningKeyPair;
import net.nosial.socialbox.objects.cryptography.TypedKey;

/**
 * A short-lived statement in which a home server vouches for the server-side state of one of its accounts: whether
 * it is active, and which head of the account log it holds. A standing never carries keys; which keys and sessions
 * belong to the account is in the log, which only the account key can write.
 *
 * @param address The account.
 * @param sessionKey The session key the standing was asked for, null if none. With a session key, the status is
 *                   SESSION_EXPIRED once the home server no longer serves that session.
 * @param status The account status.
 * @param logSeq The seq of the account log head the server holds, -1 if it holds none.
 * @param logHash The hash of that head, empty if none.
 * @param issued When the statement was issued (ms).
 * @param expires When the statement expires (ms).
 * @param hostKey The host key that signed it.
 * @param signature The signature.
 */
public record Standing(PeerAddress address, TypedKey sessionKey, StandingStatus status, long logSeq, byte[] logHash, long issued, long expires, TypedKey hostKey,
                       byte[] signature) implements SignedInterface
{
    /**
     * Creates a signed standing statement.
     *
     * @param address The account.
     * @param sessionKey The session key the standing is for, may be null.
     * @param status The account status.
     * @param head The account log head the server holds.
     * @param lifetime The lifetime in milliseconds, capped at the protocol's largest {@code max_standing_lifetime}.
     * @param hostKeyPair The host key pair.
     * @return The signed statement.
     */
    public static Standing create(PeerAddress address, TypedKey sessionKey, StandingStatus status, AccountLogHead head, long lifetime, SigningKeyPair hostKeyPair)
    {
        long issued = System.currentTimeMillis();
        long expires = issued + Math.min(lifetime, ProtocolLimit.MAX_STANDING_LIFETIME.getMaximum());
        Standing unsigned = new Standing(address, sessionKey, status, head.seq(), head.hash(), issued, expires, hostKeyPair.publicKey(), new byte[0]);
        return new Standing(address, sessionKey, status, head.seq(), head.hash(), issued, expires, hostKeyPair.publicKey(), hostKeyPair.sign(unsigned.tbs()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] tbs()
    {
        return LpWriter.label(DomainLabel.STANDING)
                .str(this.address == null ? null : this.address.toString())
                .key(this.sessionKey)
                .str(this.status == null ? null : this.status.getName())
                .integer(this.logSeq)
                .lp(this.logHash)
                .integer(this.issued)
                .integer(this.expires)
                .key(this.hostKey)
                .toByteArray();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isWellFormed()
    {
        return this.address != null && this.status != null && this.logHash != null && this.expires - this.issued <= ProtocolLimit.MAX_STANDING_LIFETIME.getMaximum();
    }

    /**
     * Verifies the signature and the lifetime. The caller must separately check that the host key is trusted for the
     * address's domain.
     *
     * @param nowMillis The current time in milliseconds.
     * @param maxClockSkew How far in the future the statement may claim to be issued: the verifier's own {@code max_clock_skew}.
     * @return True if the statement is authentic and current.
     */
    public boolean verify(long nowMillis, long maxClockSkew)
    {
        return this.issued <= nowMillis + maxClockSkew && this.expires > nowMillis && this.verifySignature();
    }

    /**
     * Returns whether the account is active.
     *
     * @return True if in good standing.
     */
    public boolean isGood()
    {
        return this.status == StandingStatus.ACTIVE;
    }

    /**
     * Returns the account log head the statement vouches for.
     *
     * @return The head.
     */
    public AccountLogHead getHead()
    {
        return new AccountLogHead(this.logSeq, this.logHash);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TypedKey signer()
    {
        return this.hostKey;
    }
}
