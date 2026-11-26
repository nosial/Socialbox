package net.nosial.socialbox.classes.cryptography;

import net.nosial.socialbox.classes.encoding.LpReader;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.objects.accounts.AccountState;
import net.nosial.socialbox.objects.accounts.Generation;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.KeyExchangeKeyPair;
import net.nosial.socialbox.objects.cryptography.SealedKey;
import net.nosial.socialbox.objects.cryptography.SigningKeyPair;
import net.nosial.socialbox.objects.cryptography.TypedKey;
import net.nosial.socialbox.objects.sync.KeyBox;
import net.nosial.socialbox.objects.sync.RootLink;
import net.nosial.socialbox.objects.sync.SyncEntry;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class SyncCryptography
{
    public static final int ROOT_SECRET_LENGTH = 32;
    public static final int MIN_BUCKET = 256;
    public static final int SEAL_OVERHEAD = Cryptography.NONCE_LENGTH + 16;
    public static final int RECORD_ID_LENGTH = 32;
    private static final BigInteger DIGEST_MODULUS = BigInteger.ONE.shiftLeft(256);

    private SyncCryptography()
    {
    }

    /**
     * Derives the account kex key pair from the account key. Key boxes for the identity file are sealed to it, so the
     * identity file never stores a root secret.
     *
     * @param address The account.
     * @param accountKeyPair The account key pair.
     * @return The account kex key pair.
     */
    public static KeyExchangeKeyPair accountKexKeyPair(PeerAddress address, SigningKeyPair accountKeyPair)
    {
        return Cryptography.keyExchangeKeyPairFromPrivate(Cryptography.deriveKey(DomainLabel.ACCOUNT_KEX,
                new LpWriter().str(address.toString()).toByteArray(), accountKeyPair.seed()));
    }

    /**
     * Generates a new root secret.
     *
     * @return The root secret.
     */
    public static byte[] generateRootSecret()
    {
        return Cryptography.randomBytes(ROOT_SECRET_LENGTH);
    }

    /**
     * Derives the encryption key pair of a generation: the key the account log publishes and others seal to.
     *
     * @param address The account.
     * @param generation The generation number.
     * @param rootSecret The generation's root secret.
     * @return The key pair.
     */
    public static KeyExchangeKeyPair encryptionKeyPair(PeerAddress address, long generation, byte[] rootSecret)
    {
        return Cryptography.keyExchangeKeyPairFromPrivate(Cryptography.deriveKey(DomainLabel.ENCRYPTION_KEY,
                new LpWriter().str(address.toString()).integer(generation).toByteArray(), rootSecret));
    }

    /**
     * Derives the sync key of a generation.
     *
     * @param address The account.
     * @param generation The generation number.
     * @param rootSecret The generation's root secret.
     * @return The 32 byte key.
     */
    public static byte[] syncKey(PeerAddress address, long generation, byte[] rootSecret)
    {
        return Cryptography.deriveKey(DomainLabel.SYNC_KEY, new LpWriter().str(address.toString()).integer(generation).toByteArray(), rootSecret);
    }

    /**
     * Derives the index key from the first root secret.
     *
     * @param address The account.
     * @param firstRootSecret The root secret of generation 1.
     * @return The 32 byte key.
     */
    public static byte[] indexKey(PeerAddress address, byte[] firstRootSecret)
    {
        return Cryptography.deriveKey(DomainLabel.SYNC_INDEX, new LpWriter().str(address.toString()).toByteArray(), firstRootSecret);
    }

    /**
     * Computes a record identifier.
     *
     * @param indexKey The index key.
     * @param collection The collection.
     * @param name The name within the collection, empty for the head record.
     * @return The 32 byte identifier.
     */
    public static byte[] recordId(byte[] indexKey, String collection, String name)
    {
        return Cryptography.hmac(indexKey, LpWriter.label(DomainLabel.SYNC_INDEX).str(collection).str(name).toByteArray());
    }

    /**
     * Pads a plaintext to its bucket: a 4 byte length, the plaintext and zeros.
     *
     * @param plaintext The plaintext.
     * @return The padded plaintext.
     */
    public static byte[] pad(byte[] plaintext)
    {
        byte[] padded = new byte[bucketSize(plaintext.length)];
        ByteBuffer.wrap(padded).putInt(plaintext.length).put(plaintext);
        return padded;
    }

    /**
     * Removes the padding.
     *
     * @param padded The padded plaintext.
     * @return The plaintext.
     * @throws CryptographyException If the padding is malformed.
     */
    public static byte[] unpad(byte[] padded)
    {
        if(padded.length < 4)
        {
            throw new CryptographyException("Malformed padding");
        }

        int length = ByteBuffer.wrap(padded).getInt();
        if(length < 0 || length > padded.length - 4 || padded.length != bucketSize(length))
        {
            throw new CryptographyException("Malformed padding");
        }

        for(int i = 4 + length; i < padded.length; i++)
        {
            if(padded[i] != 0)
            {
                throw new CryptographyException("Malformed padding");
            }
        }

        return Arrays.copyOfRange(padded, 4, 4 + length);
    }

    /**
     * Returns the padded size of a plaintext: the smallest power of two of at least {@value #MIN_BUCKET} bytes that
     * holds the plaintext and its length.
     *
     * @param length The plaintext length.
     * @return The padded size.
     */
    public static int bucketSize(int length)
    {
        int needed = Math.max(MIN_BUCKET, length + 4);
        return Integer.highestOneBit(needed) == needed ? needed : Integer.highestOneBit(needed) << 1;
    }

    /**
     * Returns whether a sealed value has the shape every sealed sync value has, without opening it: a padded bucket
     * plus the nonce and tag, within a maximum size. Servers use it to refuse malformed values.
     *
     * @param sealedLength The sealed value's length.
     * @param maxSealedLength The largest sealed value allowed.
     * @return True if well formed.
     */
    public static boolean isWellFormedSealedValue(int sealedLength, int maxSealedLength)
    {
        int padded = sealedLength - SEAL_OVERHEAD;
        return sealedLength <= maxSealedLength && padded >= MIN_BUCKET && Integer.bitCount(padded) == 1;
    }

    /**
     * Encodes and seals a record value.
     *
     * @param syncKey The sync key of the generation.
     * @param address The account.
     * @param recordId The record identifier.
     * @param revision The record's new revision.
     * @param generation The generation.
     * @param entry The plaintext entry.
     * @return The sealed value.
     */
    public static byte[] sealRecord(byte[] syncKey, PeerAddress address, byte[] recordId, long revision, long generation, SyncEntry entry)
    {
        byte[] plaintext = new LpWriter().str(entry.collection()).str(entry.name()).lp(entry.value()).toByteArray();
        return Cryptography.seal(syncKey, pad(plaintext), recordAad(address, recordId, revision, generation));
    }

    /**
     * Opens and decodes a record value.
     *
     * @param syncKey The sync key of the record's generation.
     * @param address The account.
     * @param recordId The record identifier.
     * @param revision The record's revision.
     * @param generation The record's generation.
     * @param sealed The sealed value.
     * @return The plaintext entry.
     * @throws CryptographyException If the value does not open or is malformed.
     */
    public static SyncEntry openRecord(byte[] syncKey, PeerAddress address, byte[] recordId, long revision, long generation, byte[] sealed)
    {
        byte[] plaintext = unpad(Cryptography.unseal(syncKey, sealed, recordAad(address, recordId, revision, generation)));
        try
        {
            LpReader reader = new LpReader(plaintext);
            SyncEntry entry = new SyncEntry(reader.str(), reader.str(), reader.lp());
            if(reader.hasRemaining())
            {
                throw new CryptographyException("Malformed sync record");
            }

            return entry;
        }
        catch(IllegalArgumentException e)
        {
            throw new CryptographyException("Malformed sync record", e);
        }
    }

    /**
     * Builds the additional data that binds a value to its account, record, revision and generation, so the server
     * cannot move, replay or relabel it.
     */
    private static byte[] recordAad(PeerAddress address, byte[] recordId, long revision, long generation)
    {
        return LpWriter.label(DomainLabel.SYNC_RECORD).str(address.toString()).lp(recordId).integer(revision).integer(generation).toByteArray();
    }

    /**
     * Returns the digest term of one record revision.
     *
     * @param indexKey The index key.
     * @param recordId The record identifier.
     * @param revision The revision.
     * @return The 32 byte term.
     */
    public static byte[] digestTerm(byte[] indexKey, byte[] recordId, long revision)
    {
        return Cryptography.hmac(indexKey, LpWriter.label(DomainLabel.SYNC_DIGEST).lp(recordId).integer(revision).toByteArray());
    }

    /**
     * Adds a term to a digest, modulo 2^256.
     *
     * @param digest The digest (32 bytes, or empty for zero).
     * @param term The term.
     * @return The new digest.
     */
    public static byte[] digestAdd(byte[] digest, byte[] term)
    {
        return toDigest(toNumber(digest).add(toNumber(term)));
    }

    /**
     * Subtracts a term from a digest, modulo 2^256.
     *
     * @param digest The digest.
     * @param term The term.
     * @return The new digest.
     */
    public static byte[] digestSubtract(byte[] digest, byte[] term)
    {
        return toDigest(toNumber(digest).subtract(toNumber(term)));
    }

    private static BigInteger toNumber(byte[] value)
    {
        return value == null || value.length == 0 ? BigInteger.ZERO : new BigInteger(1, value);
    }

    private static byte[] toDigest(BigInteger value)
    {
        byte[] raw = value.mod(DIGEST_MODULUS).toByteArray();
        byte[] digest = new byte[32];
        int length = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - length, digest, 32 - length, length);
        return digest;
    }

    /**
     * The exact length of the sealed bytes of every key box: {@code int(g) || lp(root secret)} and the tag. Boxes carry
     * only the newest root secret, so their size does not grow with the generations.
     */
    public static final int KEY_BOX_LENGTH = 12 + 4 + ROOT_SECRET_LENGTH + 16;

    /**
     * Returns the exact length of the sealed bytes of a key box; servers refuse boxes of any other length.
     *
     * @param generation The generation in the box.
     * @return The length of {@link SealedKey#wrappedKey()}.
     */
    public static int keyBoxLength(long generation)
    {
        return KEY_BOX_LENGTH;
    }

    /**
     * Seals a generation's root secret to one recipient.
     *
     * @param address The account.
     * @param recipient The recipient: a session's signing key, or the account kex key.
     * @param recipientKexKey The key to seal to: the session's kex key, or the account kex key.
     * @param generation The generation.
     * @param secret Its root secret.
     * @return The key box.
     */
    public static KeyBox sealKeyBox(PeerAddress address, TypedKey recipient, TypedKey recipientKexKey, long generation, byte[] secret)
    {
        if(secret == null || secret.length != ROOT_SECRET_LENGTH)
        {
            throw new CryptographyException("Root secrets are 32 bytes");
        }

        byte[] payload = new LpWriter().integer(generation).lp(secret).toByteArray();
        return new KeyBox(recipient, generation, SealCryptography.seal(DomainLabel.ROOT_SECRET, boxContext(generation, recipient), address,
                recipientKexKey, payload));
    }

    /**
     * Opens a key box and unwinds the root chain it came with, verifying every secret against the account log: each
     * generation's secret must derive the encryption key the log lists for it. A box or link a server made up fails.
     *
     * @param state The account log.
     * @param box The key box, with its chain.
     * @param kexKeyPair The recipient's kex key pair.
     * @return The root secrets, oldest first.
     * @throws CryptographyException If the box or a link does not open, or a secret does not match the log.
     */
    public static List<byte[]> openKeyBox(AccountState state, KeyBox box, KeyExchangeKeyPair kexKeyPair)
    {
        if(box == null || box.box() == null || box.generation() < 1 || state.getGeneration(box.generation()) == null ||
                box.box().wrappedKey() == null || box.box().wrappedKey().length != KEY_BOX_LENGTH ||
                !state.getAddress().equals(box.box().recipient()))
        {
            throw new CryptographyException("Malformed key box");
        }

        byte[] payload = SealCryptography.unseal(DomainLabel.ROOT_SECRET, boxContext(box.generation(), box.recipient()), box.box(), kexKeyPair);
        byte[] newest;
        try
        {
            LpReader reader = new LpReader(payload);
            if(reader.integer() != box.generation())
            {
                throw new CryptographyException("Malformed key box");
            }

            newest = reader.lp();
            if(reader.hasRemaining())
            {
                throw new CryptographyException("Malformed key box");
            }
        }
        catch(IllegalArgumentException e)
        {
            throw new CryptographyException("Malformed key box", e);
        }

        return unwind(state, box.generation(), newest, box.chain());
    }

    /**
     * Seals the previous generation's root secret under the next one: the link a session that starts a generation
     * uploads with it.
     *
     * @param address The account.
     * @param generation The new generation.
     * @param secret The new generation's root secret.
     * @param previous The previous generation's root secret.
     * @return The link.
     */
    public static RootLink sealRootLink(PeerAddress address, long generation, byte[] secret, byte[] previous)
    {
        byte[] context = new LpWriter().str(address.toString()).integer(generation).toByteArray();
        byte[] key = Cryptography.deriveKey(DomainLabel.ROOT_CHAIN, context, secret);
        return new RootLink(generation, Cryptography.seal(key, previous, LpWriter.label(DomainLabel.ROOT_CHAIN).raw(context).toByteArray()));
    }

    /**
     * Unwinds the root chain from a generation's secret down to the first generation, checking every secret against
     * the account log.
     *
     * @param state The account log.
     * @param generation The newest generation.
     * @param newest Its root secret.
     * @param chain The links, in any order.
     * @return The root secrets, oldest first.
     * @throws CryptographyException If a link is missing or does not open, or a secret does not match the log.
     */
    public static List<byte[]> unwind(AccountState state, long generation, byte[] newest, List<RootLink> chain)
    {
        java.util.Map<Long, byte[]> links = new java.util.HashMap<>();
        for(RootLink link : chain == null ? List.<RootLink>of() : chain)
        {
            if(link != null && link.sealed() != null)
            {
                links.put(link.generation(), link.sealed());
            }
        }

        java.util.LinkedList<byte[]> secrets = new java.util.LinkedList<>();
        byte[] current = newest;
        for(long g = generation; g >= 1; g--)
        {
            checkSecret(state, g, current);
            secrets.addFirst(current);
            if(g == 1)
            {
                break;
            }

            byte[] sealed = links.get(g);
            if(sealed == null)
            {
                throw new CryptographyException(String.format("The root chain misses the link of generation %d", g));
            }

            byte[] context = new LpWriter().str(state.getAddress().toString()).integer(g).toByteArray();
            current = Cryptography.unseal(Cryptography.deriveKey(DomainLabel.ROOT_CHAIN, context, current), sealed,
                    LpWriter.label(DomainLabel.ROOT_CHAIN).raw(context).toByteArray());
        }

        return new ArrayList<>(secrets);
    }

    /**
     * Verifies that root secrets match the account log: each generation's secret derives its listed encryption key.
     *
     * @param state The account log.
     * @param secrets The root secrets, oldest first.
     * @throws CryptographyException If a secret does not match.
     */
    public static void verifySecrets(AccountState state, List<byte[]> secrets)
    {
        for(int i = 0; i < secrets.size(); i++)
        {
            checkSecret(state, i + 1, secrets.get(i));
        }
    }

    /**
     * Checks one generation's root secret against the account log.
     */
    private static void checkSecret(AccountState state, long number, byte[] secret)
    {
        Generation generation = state.getGeneration(number);
        if(generation == null || secret == null || secret.length != ROOT_SECRET_LENGTH ||
                !encryptionKeyPair(state.getAddress(), number, secret).publicKey().equals(generation.encryptionKey()))
        {
            throw new CryptographyException(String.format("The root secret of generation %d does not match the account log", number));
        }
    }

    private static byte[] boxContext(long generation, TypedKey recipient)
    {
        return new LpWriter().integer(generation).key(recipient).toByteArray();
    }

    /**
     * Encodes a string as UTF-8.
     *
     * @param value The string.
     * @return The bytes.
     */
    public static byte[] utf8(String value)
    {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
