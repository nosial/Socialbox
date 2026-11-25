package net.nosial.socialbox.objects.server;

import net.nosial.socialbox.Protocol;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.ProtocolLimit;
import net.nosial.socialbox.enums.TransportType;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.interfaces.SignedInterface;
import net.nosial.socialbox.objects.cryptography.CryptographyParameters;
import net.nosial.socialbox.objects.cryptography.SigningKeyPair;
import net.nosial.socialbox.objects.cryptography.TypedKey;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public record ServerInformation(String domain, String version, CryptographyParameters crypto, List<HostKey> keys,
                                List<TransportType> transports, Map<String, Long> limits, boolean registrationEnabled, long issued, TypedKey hostKey,
                                byte[] signature, List<HostKeyEndorsement> endorsements) implements SignedInterface
{
    /**
     * Normalizes the endorsements.
     */
    public ServerInformation
    {
        endorsements = endorsements == null ? List.of() : List.copyOf(endorsements);
        limits = limits == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(limits));
    }

    /**
     * Creates and signs server information.
     *
     * @param domain The domain.
     * @param crypto The required algorithms.
     * @param keys The published host keys.
     * @param transports The offered transports.
     * @param limits The server's limits by name (section 6.6 of the protocol).
     * @param registrationEnabled Whether registration is open.
     * @param hostKeyPair The host key pair to sign with.
     * @param endorsements The endorsements of the published keys by previous host keys.
     * @return The signed information.
     */
    public static ServerInformation create(String domain, CryptographyParameters crypto, List<HostKey> keys, List<TransportType> transports,
                                         Map<String, Long> limits, boolean registrationEnabled, SigningKeyPair hostKeyPair, List<HostKeyEndorsement> endorsements)
    {
        ServerInformation unsigned = new ServerInformation(domain, Protocol.VERSION, crypto, keys, transports, limits,
                registrationEnabled, System.currentTimeMillis(), hostKeyPair.publicKey(), new byte[0], endorsements);
        return new ServerInformation(domain, Protocol.VERSION, crypto, keys, transports, limits, registrationEnabled,
                unsigned.issued(), hostKeyPair.publicKey(), hostKeyPair.sign(unsigned.tbs()), endorsements);
    }

    /**
     * Returns the bytes covered by the signature.
     *
     * @return The signing input.
     */
    @Override
    public byte[] tbs()
    {
        LpWriter writer = LpWriter.label(DomainLabel.SERVER_INFORMATION).str(this.domain).str(this.version);
        this.crypto.writeTo(writer);
        writer.integer(this.keys.size());
        for(HostKey key : this.keys)
        {
            writer.key(key.key()).integer(key.expires());
        }

        writer.integer(this.transports.size());
        for(TransportType transport : this.transports)
        {
            writer.str(transport.getName());
        }

        // Limits are written sorted by name
        writer.integer(this.limits.size());
        for(Map.Entry<String, Long> limit : this.limits.entrySet())
        {
            writer.str(limit.getKey()).integer(limit.getValue());
        }

        return writer.bool(this.registrationEnabled).integer(this.issued).key(this.hostKey).toByteArray();
    }

    /**
     * Returns one of the server's limits: the published value, or the protocol's default when the server publishes
     * none. Callers check the published values with {@link #hasLimitsWithinBounds()} first.
     *
     * @param limit The limit.
     * @return The value.
     */
    public long getLimit(ProtocolLimit limit)
    {
        Long value = this.limits.get(limit.getName());
        return value == null ? limit.getDefault() : value;
    }

    /**
     * Returns whether every limit the server publishes that this implementation knows is within the protocol's
     * bounds. Unknown limits are ignored.
     *
     * @return True if the limits are acceptable.
     */
    public boolean hasLimitsWithinBounds()
    {
        for(ProtocolLimit limit : ProtocolLimit.values())
        {
            Long value = this.limits.get(limit.getName());
            if(value != null && !limit.isWithinBounds(value))
            {
                return false;
            }
        }

        return true;
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
