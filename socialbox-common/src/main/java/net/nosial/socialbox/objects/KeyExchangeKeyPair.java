package net.nosial.socialbox.objects;

import net.nosial.socialbox.cryptography.Base64Url;
import net.nosial.socialbox.cryptography.Cryptography;
import net.nosial.socialbox.cryptography.TypedKey;

public record KeyExchangeKeyPair(TypedKey publicKey, byte[] privateKey)
{
    /**
     * Copies the private key on construction.
     */
    public KeyExchangeKeyPair
    {
        privateKey = privateKey.clone();
    }

    /**
     * Generates a new random key exchange key pair.
     *
     * @return The new key pair.
     */
    public static KeyExchangeKeyPair generate()
    {
        return Cryptography.generateKeyExchangeKeyPair();
    }

    /**
     * Restores a key pair from its private string form ({@code x25519:<base64url(private)>}).
     *
     * @param privateKey The private key string.
     * @return The restored key pair.
     */
    public static KeyExchangeKeyPair fromPrivateString(String privateKey)
    {
        TypedKey key = TypedKey.parse(privateKey);
        return Cryptography.keyExchangeKeyPairFromPrivate(key.raw());
    }

    /**
     * Performs the key agreement with a peer's public key.
     *
     * @param peerPublicKey The peer's public key.
     * @return The shared secret.
     */
    public byte[] agree(TypedKey peerPublicKey)
    {
        return Cryptography.keyExchange(this.privateKey, peerPublicKey);
    }

    /**
     * Returns the private key in its string form.
     *
     * @return The private key string.
     */
    public String toPrivateString()
    {
        return this.publicKey.algorithm() + ":" + Base64Url.encode(this.privateKey);
    }

    /**
     * Returns a copy of the private key.
     *
     * @return The private key.
     */
    @Override
    public byte[] privateKey()
    {
        return this.privateKey.clone();
    }

    /**
     * Returns a representation that never contains the private key.
     *
     * @return The public key string.
     */
    @Override
    public String toString()
    {
        return "KeyExchangeKeyPair[" + this.publicKey + "]";
    }
}
