package net.nosial.socialbox.cryptography;

import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.objects.KeyExchangeKeyPair;
import net.nosial.socialbox.objects.RatchetState;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public final class DoubleRatchet
{
    public static final int MAX_SKIP = 1000;
    private static final int MAX_STORED_SKIPPED = 2000;
    private static final byte[] ZERO_SALT = new byte[Cryptography.KEY_LENGTH];
    private static final byte[] RATCHET_INFO = new LpWriter().str("SB e2e ratchet").toByteArray();
    private static final byte[] MESSAGE_INFO = new LpWriter().str("SB e2e message").toByteArray();

    private byte[] rootKey;
    private byte[] sendingChainKey;
    private byte[] receivingChainKey;
    private KeyExchangeKeyPair ratchetKeyPair;
    private TypedKey remoteRatchetKey;
    private long sendCount;
    private long receiveCount;
    private long previousCount;
    private final Map<String, byte[]> skippedKeys;
    private final byte[] associatedData;

    /**
     * Creates a ratchet from its parts.
     *
     * @param state The state to restore.
     */
    private DoubleRatchet(RatchetState state)
    {
        this.rootKey = state.rootKey();
        this.sendingChainKey = state.sendingChainKey();
        this.receivingChainKey = state.receivingChainKey();
        this.ratchetKeyPair = KeyExchangeKeyPair.fromPrivateString(state.ratchetPrivateKey());
        this.remoteRatchetKey = state.remoteRatchetKey();
        this.sendCount = state.sendCount();
        this.receiveCount = state.receiveCount();
        this.previousCount = state.previousCount();
        this.skippedKeys = new LinkedHashMap<>(state.skippedKeys() == null ? Map.of() : state.skippedKeys());
        this.associatedData = state.associatedData();
    }

    /**
     * Starts the ratchet of the initiator, who sends first.
     *
     * @param sharedSecret The handshake's shared secret.
     * @param responderSignedPreKey The responder's signed pre key, the responder's first ratchet key.
     * @param associatedData The handshake's associated data.
     * @return The ratchet.
     */
    public static DoubleRatchet initiator(byte[] sharedSecret, TypedKey responderSignedPreKey, byte[] associatedData)
    {
        KeyExchangeKeyPair ratchetKeyPair = KeyExchangeKeyPair.generate();
        byte[][] derived = kdfRoot(sharedSecret, ratchetKeyPair.agree(responderSignedPreKey));
        return new DoubleRatchet(new RatchetState(derived[0], derived[1], null, ratchetKeyPair.toPrivateString(), responderSignedPreKey,
                0, 0, 0, Map.of(), associatedData));
    }

    /**
     * Starts the ratchet of the responder, who can send once the first message arrived.
     *
     * @param sharedSecret The handshake's shared secret.
     * @param signedPreKeyPair The responder's signed pre key pair, its first ratchet key.
     * @param associatedData The handshake's associated data.
     * @return The ratchet.
     */
    public static DoubleRatchet responder(byte[] sharedSecret, KeyExchangeKeyPair signedPreKeyPair, byte[] associatedData)
    {
        return new DoubleRatchet(new RatchetState(sharedSecret, null, null, signedPreKeyPair.toPrivateString(), null, 0, 0, 0, Map.of(),
                associatedData));
    }

    /**
     * Restores a ratchet from its saved state.
     *
     * @param state The state.
     * @return The ratchet.
     */
    public static DoubleRatchet restore(RatchetState state)
    {
        return new DoubleRatchet(state);
    }

    /**
     * Returns the state to save after every encryption or decryption.
     *
     * @return The state.
     */
    public RatchetState toState()
    {
        return new RatchetState(this.rootKey, this.sendingChainKey, this.receivingChainKey, this.ratchetKeyPair.toPrivateString(),
                this.remoteRatchetKey, this.sendCount, this.receiveCount, this.previousCount, new LinkedHashMap<>(this.skippedKeys),
                this.associatedData);
    }

    /**
     * Returns whether the ratchet can send, which the responder can only after receiving the first message.
     *
     * @return True if it can send.
     */
    public boolean canSend()
    {
        return this.sendingChainKey != null;
    }

    /**
     * Advances the sending chain and returns the header values and message key of the next message. Build the
     * envelope header from the returned values, then encrypt with {@link #encrypt(SendingKey, byte[], byte[])}.
     *
     * @return The next sending key.
     * @throws CryptographyException If the ratchet cannot send yet.
     */
    public SendingKey nextSendingKey()
    {
        if(this.sendingChainKey == null)
        {
            throw new CryptographyException("The session cannot send before it received a message");
        }

        byte[][] chain = kdfChain(this.sendingChainKey);
        this.sendingChainKey = chain[0];
        SendingKey key = new SendingKey(this.ratchetKeyPair.publicKey(), this.previousCount, this.sendCount, chain[1]);
        this.sendCount++;
        return key;
    }

    /**
     * Encrypts a message with a sending key.
     *
     * @param key The sending key.
     * @param header The envelope header.
     * @param plaintext The plaintext.
     * @return The ciphertext.
     */
    public byte[] encrypt(SendingKey key, byte[] header, byte[] plaintext)
    {
        byte[][] keys = messageKeys(key.messageKey());
        return Cryptography.encrypt(keys[0], keys[1], plaintext, this.aad(header));
    }

    /**
     * Decrypts a received message, advancing the receiving chain and, for a new ratchet key, the Diffie-Hellman
     * ratchet. The state only changes if the message decrypts.
     *
     * @param ratchetKey The sender's ratchet key from the header.
     * @param previousCount The sender's previous chain length from the header.
     * @param counter The message number from the header.
     * @param header The envelope header.
     * @param ciphertext The ciphertext.
     * @return The plaintext.
     * @throws CryptographyException If the message does not decrypt or skips too many messages.
     */
    public byte[] decrypt(TypedKey ratchetKey, long previousCount, long counter, byte[] header, byte[] ciphertext)
    {
        String skippedId = skippedId(ratchetKey, counter);
        byte[] skipped = this.skippedKeys.get(skippedId);
        if(skipped != null)
        {
            byte[][] keys = messageKeys(skipped);
            byte[] plaintext = Cryptography.decrypt(keys[0], keys[1], ciphertext, this.aad(header));
            this.skippedKeys.remove(skippedId);
            return plaintext;
        }

        RatchetState snapshot = this.toState();
        try
        {
            if(!ratchetKey.equals(this.remoteRatchetKey))
            {
                this.skipMessageKeys(previousCount);
                this.ratchetStep(ratchetKey);
            }

            this.skipMessageKeys(counter);
            byte[][] chain = kdfChain(this.receivingChainKey);
            this.receivingChainKey = chain[0];
            this.receiveCount++;
            byte[][] keys = messageKeys(chain[1]);
            return Cryptography.decrypt(keys[0], keys[1], ciphertext, this.aad(header));
        }
        catch(RuntimeException e)
        {
            this.restoreFrom(snapshot);
            throw e instanceof CryptographyException ? e : new CryptographyException("The message does not decrypt", e);
        }
    }

    /**
     * Performs a Diffie-Hellman ratchet step for a new remote ratchet key.
     *
     * @param newRemoteKey The new remote ratchet key.
     */
    private void ratchetStep(TypedKey newRemoteKey)
    {
        this.previousCount = this.sendCount;
        this.sendCount = 0;
        this.receiveCount = 0;
        this.remoteRatchetKey = newRemoteKey;
        byte[][] receiving = kdfRoot(this.rootKey, this.ratchetKeyPair.agree(newRemoteKey));
        this.rootKey = receiving[0];
        this.receivingChainKey = receiving[1];
        this.ratchetKeyPair = KeyExchangeKeyPair.generate();
        byte[][] sending = kdfRoot(this.rootKey, this.ratchetKeyPair.agree(newRemoteKey));
        this.rootKey = sending[0];
        this.sendingChainKey = sending[1];
    }

    /**
     * Stores the message keys of the current receiving chain up to a message number.
     *
     * @param until The message number to stop at.
     * @throws CryptographyException If too many messages would be skipped.
     */
    private void skipMessageKeys(long until)
    {
        if(this.receivingChainKey == null)
        {
            return;
        }

        if(until - this.receiveCount > MAX_SKIP)
        {
            throw new CryptographyException("Too many skipped messages");
        }

        while(this.receiveCount < until)
        {
            byte[][] chain = kdfChain(this.receivingChainKey);
            this.receivingChainKey = chain[0];
            this.skippedKeys.put(skippedId(this.remoteRatchetKey, this.receiveCount), chain[1]);
            this.receiveCount++;
        }

        // The oldest skipped keys are dropped first; their messages can no longer be read
        Iterator<String> iterator = this.skippedKeys.keySet().iterator();
        while(this.skippedKeys.size() > MAX_STORED_SKIPPED && iterator.hasNext())
        {
            iterator.next();
            iterator.remove();
        }
    }

    /**
     * Restores the fields from a snapshot.
     *
     * @param state The snapshot.
     */
    private void restoreFrom(RatchetState state)
    {
        this.rootKey = state.rootKey();
        this.sendingChainKey = state.sendingChainKey();
        this.receivingChainKey = state.receivingChainKey();
        this.ratchetKeyPair = KeyExchangeKeyPair.fromPrivateString(state.ratchetPrivateKey());
        this.remoteRatchetKey = state.remoteRatchetKey();
        this.sendCount = state.sendCount();
        this.receiveCount = state.receiveCount();
        this.previousCount = state.previousCount();
        this.skippedKeys.clear();
        this.skippedKeys.putAll(state.skippedKeys());
    }

    /**
     * Builds the additional data of a message.
     *
     * @param header The envelope header.
     * @return The additional data.
     */
    private byte[] aad(byte[] header)
    {
        return new LpWriter().lp(this.associatedData).lp(header).toByteArray();
    }

    /**
     * The root key derivation.
     *
     * @param rootKey The root key.
     * @param dhOutput The Diffie-Hellman output.
     * @return The new root key and chain key.
     */
    private static byte[][] kdfRoot(byte[] rootKey, byte[] dhOutput)
    {
        byte[] output = Cryptography.hkdf(rootKey, dhOutput, RATCHET_INFO, Cryptography.KEY_LENGTH * 2);
        return new byte[][]{Arrays.copyOfRange(output, 0, Cryptography.KEY_LENGTH), Arrays.copyOfRange(output, Cryptography.KEY_LENGTH, output.length)};
    }

    /**
     * The chain key derivation.
     *
     * @param chainKey The chain key.
     * @return The next chain key and the message key.
     */
    private static byte[][] kdfChain(byte[] chainKey)
    {
        return new byte[][]{Cryptography.hmac(chainKey, new byte[]{0x02}), Cryptography.hmac(chainKey, new byte[]{0x01})};
    }

    /**
     * Expands a message key into the AEAD key and nonce.
     *
     * @param messageKey The message key.
     * @return The AEAD key and nonce.
     */
    private static byte[][] messageKeys(byte[] messageKey)
    {
        byte[] output = Cryptography.hkdf(ZERO_SALT, messageKey, MESSAGE_INFO, Cryptography.KEY_LENGTH + Cryptography.NONCE_LENGTH);
        return new byte[][]{Arrays.copyOfRange(output, 0, Cryptography.KEY_LENGTH), Arrays.copyOfRange(output, Cryptography.KEY_LENGTH, output.length)};
    }

    /**
     * Returns the identifier of a skipped message key.
     *
     * @param ratchetKey The ratchet key of the chain.
     * @param counter The message number.
     * @return The identifier.
     */
    private static String skippedId(TypedKey ratchetKey, long counter)
    {
        return Base64Url.encode(ratchetKey.raw()) + ":" + counter;
    }

    /**
     * The header values and message key of one outgoing message.
     *
     * @param ratchetKey The own ratchet public key.
     * @param previousCount The previous sending chain's length.
     * @param counter The message number.
     * @param messageKey The message key.
     */
    public record SendingKey(TypedKey ratchetKey, long previousCount, long counter, byte[] messageKey)
    {
    }
}