package net.nosial.socialbox.objects.cryptography;

import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.StandardError;
import net.nosial.socialbox.enums.cryptography.Algorithms;
import net.nosial.socialbox.enums.cryptography.CryptographyRole;
import net.nosial.socialbox.exceptions.SocialboxException;

import java.util.Map;

public record CryptographyParameters(String sign, String kex, String kdf, String aead, String hash, String mac, String pbkdf)
{
    /**
     * The parameters every SB implementation supports.
     */
    public static final CryptographyParameters DEFAULT = new CryptographyParameters(Algorithms.ED25519.getName(),
            Algorithms.X25519.getName(), Algorithms.HKDF_SHA256.getName(), Algorithms.CHACHA20_POLY1305.getName(),
            Algorithms.SHA256.getName(), Algorithms.HMAC_SHA256.getName(), Algorithms.PBKDF2_SHA256.getName());

    /**
     * Returns the algorithm configured for the given role.
     *
     * @param role The role.
     * @return The algorithm name.
     */
    public String get(CryptographyRole role)
    {
        return switch(role)
        {
            case SIGN -> this.sign;
            case KEX -> this.kex;
            case KDF -> this.kdf;
            case AEAD -> this.aead;
            case HASH -> this.hash;
            case MAC -> this.mac;
            case PBKDF -> this.pbkdf;
        };
    }

    /**
     * Returns the first role whose algorithm this implementation does not support.
     *
     * @return The unsupported role, or null if every algorithm is supported.
     */
    public CryptographyRole getUnsupportedRole()
    {
        for(CryptographyRole role : CryptographyRole.values())
        {
            if(!role.isSupported(this.get(role)))
            {
                return role;
            }
        }

        return null;
    }

    /**
     * Throws if any algorithm is not supported by this implementation.
     *
     * @throws SocialboxException With {@link StandardError#UNSUPPORTED_ALGORITHM} if a role is unsupported.
     */
    public void requireSupported()
    {
        CryptographyRole role = this.getUnsupportedRole();
        if(role != null)
        {
            throw new SocialboxException(StandardError.UNSUPPORTED_ALGORITHM,
                    String.format("Unsupported %s algorithm '%s'", role.getName(), this.get(role)),
                    Map.of("role", role.getName(), "algorithm", String.valueOf(this.get(role)), "supported", role.getSupported()),
                    null);
        }
    }

    /**
     * Writes the parameters into a signing input in role order.
     *
     * @param writer The writer to append to.
     * @return The same writer.
     */
    public LpWriter writeTo(LpWriter writer)
    {
        for(CryptographyRole role : CryptographyRole.values())
        {
            writer.str(this.get(role));
        }

        return writer;
    }
}
