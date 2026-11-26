package net.nosial.socialbox.classes.cryptography;

import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.Algorithms;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.KeyExchangeKeyPair;
import net.nosial.socialbox.objects.cryptography.SealedKey;
import net.nosial.socialbox.objects.cryptography.TypedKey;

public final class SealCryptography
{
    private static final byte[] ZERO_NONCE = new byte[Cryptography.NONCE_LENGTH];

    private SealCryptography()
    {
    }

    /**
     * Seals a secret to one account.
     *
     * @param label The domain separation label of the kind of seal, for example the label of the kind of secret being sealed.
     * @param context The bytes the seal is bound to.
     * @param recipient The account the seal is for.
     * @param encryptionKey The recipient's encryption public key.
     * @param secret The secret to seal.
     * @return The seal.
     * @throws CryptographyException If the encryption key is not an X25519 key.
     */
    public static SealedKey seal(DomainLabel label, byte[] context, PeerAddress recipient, TypedKey encryptionKey, byte[] secret)
    {
        if(encryptionKey == null || !encryptionKey.isAlgorithm(Algorithms.X25519))
        {
            throw new CryptographyException(recipient + " has no encryption key");
        }

        // The wrapping key is derived from a fresh ephemeral key for every seal and used for exactly one encryption,
        // which is what makes the fixed nonce safe; a seal must never reuse an ephemeral key
        KeyExchangeKeyPair ephemeral = KeyExchangeKeyPair.generate();
        byte[] wrappingKey = wrappingKey(label, context, recipient, ephemeral.publicKey(), encryptionKey, ephemeral.agree(encryptionKey));
        return new SealedKey(recipient, ephemeral.publicKey(), Cryptography.encrypt(wrappingKey, ZERO_NONCE, secret, context));
    }

    /**
     * Opens a seal addressed to this account.
     *
     * @param label The domain separation label the seal was made with.
     * @param context The bytes the seal is bound to.
     * @param seal The seal.
     * @param encryptionKeyPair The recipient's encryption key pair.
     * @return The secret.
     * @throws CryptographyException If the seal does not open.
     */
    public static byte[] unseal(DomainLabel label, byte[] context, SealedKey seal, KeyExchangeKeyPair encryptionKeyPair)
    {
        if(seal == null || seal.ephemeralKey() == null || seal.wrappedKey() == null)
        {
            throw new CryptographyException("Missing seal");
        }

        byte[] wrappingKey = wrappingKey(label, context, seal.recipient(), seal.ephemeralKey(), encryptionKeyPair.publicKey(),
                encryptionKeyPair.agree(seal.ephemeralKey()));
        return Cryptography.decrypt(wrappingKey, ZERO_NONCE, seal.wrappedKey(), context);
    }

    /**
     * Derives the key that wraps a secret for one recipient.
     *
     * @param label The domain separation label.
     * @param context The bytes the seal is bound to.
     * @param recipient The recipient.
     * @param ephemeralKey The ephemeral public key.
     * @param encryptionKey The recipient's encryption public key.
     * @param secret The shared secret.
     * @return The wrapping key.
     */
    private static byte[] wrappingKey(DomainLabel label, byte[] context, PeerAddress recipient, TypedKey ephemeralKey, TypedKey encryptionKey,
                                      byte[] secret)
    {
        return Cryptography.deriveKey(label, new LpWriter().lp(context).str(recipient.toString()).key(ephemeralKey).key(encryptionKey).toByteArray(), secret);
    }
}
