package net.nosial.socialbox.enums.cryptography;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

import java.util.List;

public enum CryptographyRole implements NamedEnumInterface
{
    /**
     * Signatures: host keys, account keys, session keys.
     */
    SIGN(List.of(Algorithms.ED25519.getName())),

    /**
     * Key exchange: handshake ephemeral keys, session and account encryption keys.
     */
    KEX(List.of(Algorithms.X25519.getName())),

    /**
     * Key derivation.
     */
    KDF(List.of(Algorithms.HKDF_SHA256.getName())),

    /**
     * Authenticated encryption.
     */
    AEAD(List.of(Algorithms.CHACHA20_POLY1305.getName())),

    /**
     * Hashing.
     */
    HASH(List.of(Algorithms.SHA256.getName())),

    /**
     * Message authentication.
     */
    MAC(List.of(Algorithms.HMAC_SHA256.getName())),

    /**
     * Password based key derivation.
     */
    PBKDF(List.of(Algorithms.PBKDF2_SHA256.getName()));

    private final List<String> supported;

    CryptographyRole(List<String> supported)
    {
        this.supported = supported;
    }

    /**
     * Returns the algorithm names this implementation supports for the role.
     *
     * @return The supported algorithm names.
     */
    public List<String> getSupported()
    {
        return this.supported;
    }

    /**
     * Returns whether the given algorithm is supported for this role.
     *
     * @param algorithm The algorithm name.
     * @return True if supported.
     */
    public boolean isSupported(String algorithm)
    {
        return this.supported.contains(algorithm);
    }
}
