package net.nosial.socialbox.enums;

public enum Algorithms
{
    /**
     * Ed25519 signatures (RFC 8032, pure). 32 byte public key and seed, 64 byte signature.
     */
    ED25519("ed25519"),

    /**
     * X25519 key agreement (RFC 7748). 32 byte keys; an all-zero shared secret is rejected.
     */
    X25519("x25519"),

    /**
     * HKDF with HMAC-SHA256 (RFC 5869).
     */
    HKDF_SHA256("hkdf-sha256"),

    /**
     * ChaCha20-Poly1305, IETF variant (RFC 8439). 32 byte key, 12 byte nonce, 16 byte tag appended to the ciphertext.
     */
    CHACHA20_POLY1305("chacha20-poly1305"),

    /**
     * SHA-256 (FIPS 180-4).
     */
    SHA256("sha256"),

    /**
     * HMAC-SHA256 (RFC 2104).
     */
    HMAC_SHA256("hmac-sha256"),

    /**
     * PBKDF2 with HMAC-SHA256 (RFC 8018).
     */
    PBKDF2_SHA256("pbkdf2-sha256");

    private final String algorithm;
    Algorithms(String algorithm)
    {
        this.algorithm = algorithm;
    }

    public String getAlgorithm()
    {
        return this.algorithm;
    }
}
