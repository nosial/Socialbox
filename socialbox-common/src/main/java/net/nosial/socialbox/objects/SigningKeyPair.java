package net.nosial.socialbox.objects;

import net.nosial.socialbox.cryptography.Base64Url;
import net.nosial.socialbox.cryptography.Cryptography;
import net.nosial.socialbox.cryptography.TypedKey;

public record SigningKeyPair(TypedKey publicKey, byte[] seed)
{
    /**
     * Copies the seed on construction.
     */
    public SigningKeyPair
    {
        seed = seed.clone();
    }

    /**
     * Generates a new random signing key pair.
     *
     * @return The new key pair.
     */
    public static SigningKeyPair generate()
    {
        return Cryptography.generateSigningKeyPair();
    }

    /**
     * Restores a key pair from its private string form ({@code ed25519:<base64url(seed)>}).
     *
     * @param privateKey The private key string.
     * @return The restored key pair.
     */
    public static SigningKeyPair fromPrivateString(String privateKey)
    {
        TypedKey key = TypedKey.parse(privateKey);
        return Cryptography.signingKeyPairFromSeed(key.raw());
    }

    /**
     * Signs the given data.
     *
     * @param data The data to sign.
     * @return The signature.
     */
    public byte[] sign(byte[] data)
    {
        return Cryptography.sign(this.seed, data);
    }

    /**
     * Returns the private key in its string form ({@code ed25519:<base64url(seed)>}).
     *
     * @return The private key string.
     */
    public String toPrivateString()
    {
        return this.publicKey.algorithm() + ":" + Base64Url.encode(this.seed);
    }

    /**
     * Returns a copy of the seed.
     *
     * @return The seed.
     */
    @Override
    public byte[] seed()
    {
        return this.seed.clone();
    }

    /**
     * Returns a representation that never contains the seed.
     *
     * @return The public key string.
     */
    @Override
    public String toString()
    {
        return "SigningKeyPair[" + this.publicKey + "]";
    }
}