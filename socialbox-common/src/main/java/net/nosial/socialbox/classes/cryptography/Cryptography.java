package net.nosial.socialbox.classes.cryptography;

import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.Algorithms;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.objects.cryptography.KeyExchangeKeyPair;
import net.nosial.socialbox.objects.cryptography.SigningKeyPair;
import net.nosial.socialbox.objects.cryptography.TypedKey;

import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class Cryptography
{
    public static final int KEY_LENGTH = 32;
    public static final int NONCE_LENGTH = 12;
    public static final int HASH_LENGTH = 32;
    public static final int PBKDF2_ITERATIONS = 600_000;
    private static final byte[] ED25519_PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b657004220420");
    private static final byte[] ED25519_X509_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final byte[] X25519_PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b656e04220420");
    private static final byte[] X25519_X509_PREFIX = HexFormat.of().parseHex("302a300506032b656e032100");
    private static final SecureRandom RANDOM = new SecureRandom();

    private Cryptography()
    {
    }

    /**
     * Returns cryptographically secure random bytes.
     *
     * @param length The number of bytes.
     * @return The random bytes.
     */
    public static byte[] randomBytes(int length)
    {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates a new random Ed25519 key pair.
     *
     * @return The key pair.
     */
    public static SigningKeyPair generateSigningKeyPair()
    {
        return signingKeyPairFromSeed(randomBytes(32));
    }

    /**
     * Derives the Ed25519 key pair of a 32 byte seed.
     *
     * @param seed The seed.
     * @return The key pair.
     * @throws CryptographyException If the seed is invalid.
     */
    public static SigningKeyPair signingKeyPairFromSeed(byte[] seed)
    {
        if(seed == null || seed.length != 32)
        {
            throw new CryptographyException("Ed25519 seeds must be 32 bytes");
        }

        try
        {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, new FixedSecureRandom(seed));
            KeyPair keyPair = generator.generateKeyPair();
            return new SigningKeyPair(new TypedKey(Algorithms.ED25519, rawPublicKey(keyPair.getPublic())), seed);
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("Failed to derive the Ed25519 key pair", e);
        }
    }

    /**
     * Signs data with an Ed25519 seed.
     *
     * @param seed The 32 byte seed.
     * @param data The data to sign.
     * @return The 64 byte signature.
     * @throws CryptographyException If signing fails.
     */
    public static byte[] sign(byte[] seed, byte[] data)
    {
        try
        {
            KeyFactory factory = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(concat(ED25519_PKCS8_PREFIX, seed)));
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("Failed to sign data", e);
        }
    }

    /**
     * Verifies an Ed25519 signature. Never throws for malformed input; returns false instead.
     *
     * @param publicKey The signer's public key.
     * @param data The signed data.
     * @param signature The signature.
     * @return True if the signature is valid.
     */
    public static boolean verify(TypedKey publicKey, byte[] data, byte[] signature)
    {
        if(publicKey == null || data == null || signature == null || signature.length != 64 ||
                !publicKey.isAlgorithm(Algorithms.ED25519))
        {
            return false;
        }

        try
        {
            KeyFactory factory = KeyFactory.getInstance("Ed25519");
            PublicKey key = factory.generatePublic(new X509EncodedKeySpec(concat(ED25519_X509_PREFIX, publicKey.raw())));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(signature);
        }
        catch(GeneralSecurityException | RuntimeException e)
        {
            return false;
        }
    }

    /**
     * Generates a new random X25519 key pair.
     *
     * @return The key pair.
     */
    public static KeyExchangeKeyPair generateKeyExchangeKeyPair()
    {
        return keyExchangeKeyPairFromPrivate(randomBytes(32));
    }

    /**
     * Derives the X25519 key pair of a raw private key.
     *
     * @param privateKey The raw 32 byte private key.
     * @return The key pair.
     * @throws CryptographyException If the private key is invalid.
     */
    public static KeyExchangeKeyPair keyExchangeKeyPairFromPrivate(byte[] privateKey)
    {
        if(privateKey == null || privateKey.length != 32)
        {
            throw new CryptographyException("X25519 private keys must be 32 bytes");
        }

        try
        {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
            generator.initialize(NamedParameterSpec.X25519, new FixedSecureRandom(privateKey));
            KeyPair keyPair = generator.generateKeyPair();
            return new KeyExchangeKeyPair(new TypedKey(Algorithms.X25519, rawPublicKey(keyPair.getPublic())), privateKey);
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("Failed to derive the X25519 key pair", e);
        }
    }

    /**
     * Performs an X25519 key agreement.
     *
     * @param privateKey The raw local private key.
     * @param peerPublicKey The peer's public key.
     * @return The 32 byte shared secret.
     * @throws CryptographyException If the agreement fails or produces an all-zero secret.
     */
    public static byte[] keyExchange(byte[] privateKey, TypedKey peerPublicKey)
    {
        if(peerPublicKey == null || !peerPublicKey.isAlgorithm(Algorithms.X25519))
        {
            throw new CryptographyException("Key exchange requires an x25519 public key");
        }

        try
        {
            KeyFactory factory = KeyFactory.getInstance("XDH");
            PrivateKey local = factory.generatePrivate(new PKCS8EncodedKeySpec(concat(X25519_PKCS8_PREFIX, privateKey)));
            PublicKey remote = factory.generatePublic(new X509EncodedKeySpec(concat(X25519_X509_PREFIX, peerPublicKey.raw())));
            KeyAgreement agreement = KeyAgreement.getInstance("XDH");
            agreement.init(local);
            agreement.doPhase(remote, true);
            byte[] secret = agreement.generateSecret();
            if(isAllZero(secret))
            {
                throw new CryptographyException("Key exchange produced an all-zero shared secret");
            }

            return secret;
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("Key exchange failed", e);
        }
    }

    /**
     * Computes SHA-256.
     *
     * @param data The data to hash.
     * @return The 32 byte hash.
     */
    public static byte[] hash(byte[] data)
    {
        try
        {
            return MessageDigest.getInstance("SHA-256").digest(data);
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("SHA-256 is unavailable", e);
        }
    }

    /**
     * Computes HMAC-SHA256.
     *
     * @param key The MAC key.
     * @param data The data to authenticate.
     * @return The 32 byte MAC.
     */
    public static byte[] hmac(byte[] key, byte[] data)
    {
        try
        {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[HASH_LENGTH] : key, "HmacSHA256"));
            return mac.doFinal(data);
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("HMAC-SHA256 failed", e);
        }
    }

    /**
     * HKDF-Extract (RFC 5869) with HMAC-SHA256. An empty or null salt is replaced by 32 zero bytes.
     *
     * @param salt The salt.
     * @param ikm The input keying material.
     * @return The 32 byte pseudorandom key.
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm)
    {
        return hmac(salt == null || salt.length == 0 ? new byte[HASH_LENGTH] : salt, ikm);
    }

    /**
     * HKDF-Expand (RFC 5869) with HMAC-SHA256.
     *
     * @param prk The pseudorandom key.
     * @param info The context information.
     * @param length The output length, at most 255 * 32 bytes.
     * @return The output keying material.
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length)
    {
        if(length <= 0 || length > 255 * HASH_LENGTH)
        {
            throw new CryptographyException("Invalid HKDF output length");
        }

        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        for(int counter = 1; offset < length; counter++)
        {
            previous = hmac(prk, concat(previous, info == null ? new byte[0] : info, new byte[]{(byte) counter}));
            int copy = Math.min(previous.length, length - offset);
            System.arraycopy(previous, 0, output, offset, copy);
            offset += copy;
        }

        return output;
    }

    /**
     * Derives a 32 byte key bound to a label and a context: HKDF-SHA256 with {@code H(str(label) || lp(context))} as
     * salt and {@code str(label)} as info. Every derived key of the protocol goes through here, each kind with its
     * own label.
     *
     * @param label The label of the key's kind.
     * @param context The bytes the key is bound to, such as an address or a chat identifier.
     * @param ikm The input keying material.
     * @return The 32 byte key.
     */
    public static byte[] deriveKey(DomainLabel label, byte[] context, byte[] ikm)
    {
        byte[] salt = hash(LpWriter.label(label).lp(context).toByteArray());
        return hkdf(salt, ikm, LpWriter.label(label).toByteArray(), KEY_LENGTH);
    }

    /**
     * HKDF (RFC 5869) with HMAC-SHA256: extract then expand.
     *
     * @param salt The salt.
     * @param ikm The input keying material.
     * @param info The context information.
     * @param length The output length.
     * @return The output keying material.
     */
    public static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length)
    {
        return hkdfExpand(hkdfExtract(salt, ikm), info, length);
    }

    /**
     * Encrypts with ChaCha20-Poly1305 (IETF).
     *
     * @param key The 32 byte key.
     * @param nonce The 12 byte nonce, never reused with the same key.
     * @param plaintext The plaintext.
     * @param aad The additional authenticated data, may be null.
     * @return The ciphertext with the 16 byte tag appended.
     */
    public static byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
            if(aad != null && aad.length > 0)
            {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(plaintext);
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("Encryption failed", e);
        }
    }

    /**
     * Decrypts with ChaCha20-Poly1305 (IETF).
     *
     * @param key The 32 byte key.
     * @param nonce The 12 byte nonce.
     * @param ciphertext The ciphertext with the tag appended.
     * @param aad The additional authenticated data, may be null.
     * @return The plaintext.
     * @throws CryptographyException If authentication fails.
     */
    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
            if(aad != null && aad.length > 0)
            {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(ciphertext);
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("Decryption failed", e);
        }
    }

    /**
     * Encrypts with a random nonce and returns {@code nonce || ciphertext}.
     *
     * @param key The 32 byte key.
     * @param plaintext The plaintext.
     * @param aad The additional authenticated data, may be null.
     * @return The nonce followed by the ciphertext.
     */
    public static byte[] seal(byte[] key, byte[] plaintext, byte[] aad)
    {
        byte[] nonce = randomBytes(NONCE_LENGTH);
        return concat(nonce, encrypt(key, nonce, plaintext, aad));
    }

    /**
     * Decrypts data produced by {@link #seal(byte[], byte[], byte[])}.
     *
     * @param key The 32 byte key.
     * @param sealed The nonce followed by the ciphertext.
     * @param aad The additional authenticated data, may be null.
     * @return The plaintext.
     */
    public static byte[] unseal(byte[] key, byte[] sealed, byte[] aad)
    {
        if(sealed == null || sealed.length < NONCE_LENGTH + 16)
        {
            throw new CryptographyException("Sealed data is too short");
        }

        return decrypt(key, Arrays.copyOfRange(sealed, 0, NONCE_LENGTH), Arrays.copyOfRange(sealed, NONCE_LENGTH, sealed.length), aad);
    }

    /**
     * Derives a key from a password with PBKDF2-SHA256. The password is encoded as UTF-8.
     *
     * @param password The password.
     * @param salt The salt.
     * @param iterations The iteration count.
     * @param length The output length in bytes.
     * @return The derived key.
     */
    public static byte[] pbkdf2(String password, byte[] salt, int iterations, int length)
    {
        if(password == null || password.isEmpty())
        {
            throw new CryptographyException("Passwords cannot be empty");
        }

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, length * 8);
        try
        {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        }
        catch(GeneralSecurityException e)
        {
            throw new CryptographyException("PBKDF2 failed", e);
        }
        finally
        {
            spec.clearPassword();
        }
    }

    /**
     * Compares two byte arrays in constant time.
     *
     * @param a The first array.
     * @param b The second array.
     * @return True if both arrays are equal.
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b)
    {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Checks the platform's primitives against published test vectors (RFC 8032 section 7.1 test 1, RFC 7748 section
     * 6.1, RFC 5869 A.1). Keys are derived from seeds through the platform's key generators, which only works with
     * providers that read the seed the way the JDK's do; a provider that does not would silently derive different keys,
     * so servers and clients run this once before using any key.
     *
     * @throws CryptographyException If a primitive does not reproduce its test vector.
     */
    public static void selfTest()
    {
        HexFormat hex = HexFormat.of();
        SigningKeyPair signing = signingKeyPairFromSeed(hex.parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        requireVector("Ed25519 public key", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", signing.publicKey().raw());
        requireVector("Ed25519 signature", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f" +
                "0595bbe24655141438e7a100b", signing.sign(new byte[0]));

        KeyExchangeKeyPair alice = keyExchangeKeyPairFromPrivate(hex.parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        KeyExchangeKeyPair bob = keyExchangeKeyPairFromPrivate(hex.parseHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
        requireVector("X25519 public key", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", alice.publicKey().raw());
        requireVector("X25519 shared secret", "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", alice.agree(bob.publicKey()));

        requireVector("HKDF-SHA256", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                hkdf(hex.parseHex("000102030405060708090a0b0c"), hex.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        hex.parseHex("f0f1f2f3f4f5f6f7f8f9"), 42));
    }

    /**
     * Requires a computed value to equal a test vector.
     *
     * @param name The primitive.
     * @param expected The expected value (hex).
     * @param actual The computed value.
     * @throws CryptographyException If they differ.
     */
    private static void requireVector(String name, String expected, byte[] actual)
    {
        if(!MessageDigest.isEqual(HexFormat.of().parseHex(expected), actual))
        {
            throw new CryptographyException(String.format("The platform's %s does not reproduce its test vector; check the security provider", name));
        }
    }

    /**
     * Concatenates byte arrays.
     *
     * @param parts The arrays to concatenate.
     * @return The concatenation.
     */
    public static byte[] concat(byte[]... parts)
    {
        int length = 0;
        for(byte[] part : parts)
        {
            length += part.length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        for(byte[] part : parts)
        {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }

        return result;
    }

    /**
     * Extracts the raw 32 byte key from an X.509 encoded Ed25519 or X25519 public key.
     *
     * @param key The JDK public key.
     * @return The raw key bytes.
     */
    private static byte[] rawPublicKey(PublicKey key)
    {
        byte[] encoded = key.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    /**
     * Returns whether every byte is zero, in constant time.
     *
     * @param data The data to check.
     * @return True if all bytes are zero.
     */
    private static boolean isAllZero(byte[] data)
    {
        int accumulator = 0;
        for(byte b : data)
        {
            accumulator |= b;
        }

        return accumulator == 0;
    }

    /**
     * A SecureRandom that returns a fixed private key, used to derive JDK key pairs from existing private keys.
     */
    private static final class FixedSecureRandom extends SecureRandom
    {
        private final byte[] value;

        private FixedSecureRandom(byte[] value)
        {
            this.value = value.clone();
        }

        @Override
        public void nextBytes(byte[] bytes)
        {
            if(bytes.length != this.value.length)
            {
                throw new IllegalStateException("Unexpected key generation length");
            }

            System.arraycopy(this.value, 0, bytes, 0, bytes.length);
        }
    }
}