package net.nosial.socialbox.objects.server;

import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.interfaces.SignedInterface;
import net.nosial.socialbox.objects.cryptography.SigningKeyPair;
import net.nosial.socialbox.objects.cryptography.TypedKey;

public record HostKeyEndorsement(String domain, TypedKey key, long issued, TypedKey endorser, byte[] signature) implements SignedInterface
{
    /**
     * Creates and signs an endorsement.
     *
     * @param domain The domain.
     * @param key The endorsed key.
     * @param endorser The key pair of the endorsing key.
     * @return The endorsement.
     */
    public static HostKeyEndorsement create(String domain, TypedKey key, SigningKeyPair endorser)
    {
        HostKeyEndorsement unsigned = new HostKeyEndorsement(domain, key, System.currentTimeMillis(), endorser.publicKey(), new byte[0]);
        return new HostKeyEndorsement(domain, key, unsigned.issued(), endorser.publicKey(), endorser.sign(unsigned.tbs()));
    }

    /**
     * Returns the bytes covered by the signature.
     *
     * @return The signing input.
     */
    @Override
    public byte[] tbs()
    {
        return LpWriter.label(DomainLabel.HOST_KEY_ENDORSEMENT).str(this.domain).key(this.key).integer(this.issued).key(this.endorser).toByteArray();
    }

    /**
     * Returns whether the host key endorsement has the structure its type requires.
     *
     * @return True if well formed.
     */
    @Override
    public boolean isWellFormed()
    {
        return this.key != null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TypedKey signer()
    {
        return this.endorser;
    }
}
