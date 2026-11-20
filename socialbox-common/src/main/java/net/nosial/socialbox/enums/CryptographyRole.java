package net.nosial.socialbox.enums;

import java.util.List;

public enum CryptographyRole
{
    /**
     * Signatures: host keys, account keys, device keys.
     */
    SIGN("sign", List.of(Algorithms.ED25519.getAlgorithm())),

    /**
     * Key exchange: handshake ephemeral keys, device encryption keys, channel keys.
     */
    KEX("kex", List.of(Algorithms.X25519.getAlgorithm())),

    /**
     * Key derivation.
     */
    KDF("kdf", List.of(Algorithms.HKDF_SHA256.getAlgorithm())),

    /**
     * Authenticated encryption.
     */
    AEAD("aead", List.of(Algorithms.CHACHA20_POLY1305.getAlgorithm())),

    /**
     * Hashing.
     */
    HASH("hash", List.of(Algorithms.SHA256.getAlgorithm())),

    /**
     * Message authentication.
     */
    MAC("mac", List.of(Algorithms.HMAC_SHA256.getAlgorithm())),

    /**
     * Password based key derivation.
     */
    PBKDF("pbkdf", List.of(Algorithms.PBKDF2_SHA256.getAlgorithm()));

    private final String name;
    private final List<String> supported;

    CryptographyRole(String name, List<String> supported)
    {
        this.name = name;
        this.supported = supported;
    }

    /**
     * Returns the role name as written in DNS records and hellos.
     *
     * @return The role name.
     */
    public String getName()
    {
        return this.name;
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
