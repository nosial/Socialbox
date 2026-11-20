package net.nosial.socialbox.cryptography;

import net.nosial.socialbox.enums.Encoding;
import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.objects.KeyExchangeKeyPair;
import net.nosial.socialbox.objects.PeerAddress;
import net.nosial.socialbox.objects.SigningKeyPair;
import net.nosial.socialbox.objects.attachments.AttachmentManifest;
import net.nosial.socialbox.objects.chats.ChatContent;
import net.nosial.socialbox.objects.groups.GroupKeyEnvelope;
import net.nosial.socialbox.objects.groups.GroupMessage;
import net.nosial.socialbox.objects.groups.GroupProperties;
import net.nosial.socialbox.protocol.Codec;

import java.util.List;
import java.util.UUID;

public final class GroupChatCrypto
{
    /**
     * Generates a new epoch secret.
     *
     * @return The 32 byte secret.
     */
    public static byte[] newEpochSecret()
    {
        return Cryptography.randomBytes(Cryptography.KEY_LENGTH);
    }

    /**
     * Derives the key of an epoch.
     *
     * @param groupUuid The group identifier.
     * @param host The hosting domain.
     * @param epoch The epoch.
     * @param epochSecret The epoch secret.
     * @return The 32 byte epoch key.
     */
    public static byte[] deriveEpochKey(UUID groupUuid, String host, long epoch, byte[] epochSecret)
    {
        byte[] salt = Cryptography.hash(LpWriter.label("SB group-key").uuid(groupUuid).str(host).integer(epoch).toByteArray());
        return Cryptography.hkdf(salt, epochSecret, new LpWriter().str("SB group key").toByteArray(), Cryptography.KEY_LENGTH);
    }

    /**
     * Seals an epoch secret to one member.
     *
     * @param groupUuid The group identifier.
     * @param host The hosting domain.
     * @param epoch The epoch.
     * @param member The member.
     * @param encryptionKey The member's encryption public key.
     * @param epochSecret The epoch secret.
     * @return The envelope.
     */
    public static GroupKeyEnvelope sealEpoch(UUID groupUuid, String host, long epoch, PeerAddress member, TypedKey encryptionKey, byte[] epochSecret)
    {
        return new GroupKeyEnvelope(epoch, SealCrypto.seal(GroupKeyEnvelope.SEAL_LABEL, GroupKeyEnvelope.sealContext(groupUuid, host, epoch), member,
                encryptionKey, epochSecret));
    }

    /**
     * Opens an epoch secret sealed to this account.
     *
     * @param groupUuid The group identifier.
     * @param host The hosting domain.
     * @param envelope The envelope.
     * @param encryptionKeyPair The account's encryption key pair.
     * @return The epoch secret.
     */
    public static byte[] openEpoch(UUID groupUuid, String host, GroupKeyEnvelope envelope, KeyExchangeKeyPair encryptionKeyPair)
    {
        return SealCrypto.unseal(GroupKeyEnvelope.SEAL_LABEL, GroupKeyEnvelope.sealContext(groupUuid, host, envelope.epoch()), envelope.seal(),
                encryptionKeyPair);
    }

    /**
     * Encrypts properties under an epoch key.
     *
     * @param epochKey The epoch key.
     * @param groupUuid The group identifier.
     * @param host The hosting domain.
     * @param epoch The epoch.
     * @param properties The properties.
     * @return The nonce followed by the ciphertext.
     */
    public static byte[] encryptProperties(byte[] epochKey, UUID groupUuid, String host, long epoch, GroupProperties properties)
    {
        return Cryptography.seal(epochKey, Codec.encode(Encoding.JSON, properties), propertiesAad(groupUuid, host, epoch));
    }

    /**
     * Decrypts properties.
     *
     * @param epochKey The key of the epoch they were encrypted in.
     * @param groupUuid The group identifier.
     * @param host The hosting domain.
     * @param epoch The epoch.
     * @param sealed The nonce followed by the ciphertext.
     * @return The properties.
     */
    public static GroupProperties decryptProperties(byte[] epochKey, UUID groupUuid, String host, long epoch, byte[] sealed)
    {
        return Codec.decode(Encoding.JSON, Cryptography.unseal(epochKey, sealed, propertiesAad(groupUuid, host, epoch)), GroupProperties.class);
    }

    /**
     * Encodes plain properties of a public group.
     *
     * @param properties The properties.
     * @return The JSON bytes.
     */
    public static byte[] encodeProperties(GroupProperties properties)
    {
        return Codec.encode(Encoding.JSON, properties);
    }

    /**
     * Decodes plain properties of a public group.
     *
     * @param properties The JSON bytes.
     * @return The properties.
     */
    public static GroupProperties decodeProperties(byte[] properties)
    {
        return Codec.decode(Encoding.JSON, properties, GroupProperties.class);
    }

    /**
     * Signs a message, encrypting it if an epoch key is given.
     *
     * @param epochKey The epoch key, null for public groups.
     * @param deviceKeyPair The sender's device key pair.
     * @param groupUuid The group identifier.
     * @param host The hosting domain.
     * @param sender The sender.
     * @param epoch The epoch (0 for public groups).
     * @param attachments The manifests of uploaded attachments.
     * @param content The content.
     * @return The signed message.
     */
    public static GroupMessage createMessage(byte[] epochKey, SigningKeyPair deviceKeyPair, UUID groupUuid, String host, PeerAddress sender,
                                             long epoch, List<AttachmentManifest> attachments, ChatContent content)
    {
        UUID messageUuid = UUID.randomUUID();
        long timestamp = System.currentTimeMillis();
        byte[] nonce = epochKey == null ? null : Cryptography.randomBytes(Cryptography.NONCE_LENGTH);
        GroupMessage template = new GroupMessage(groupUuid, host, messageUuid, sender, deviceKeyPair.publicKey(), epoch, timestamp,
                List.copyOf(attachments), nonce, new byte[0], null, null);
        byte[] plaintext = Codec.encode(Encoding.JSON, content);
        byte[] body = epochKey == null ? plaintext : Cryptography.encrypt(epochKey, nonce, plaintext, template.header());
        GroupMessage unsigned = new GroupMessage(groupUuid, host, messageUuid, sender, template.deviceKey(), epoch, timestamp,
                template.attachments(), nonce, body, null, null);
        return new GroupMessage(groupUuid, host, messageUuid, sender, unsigned.deviceKey(), epoch, timestamp, unsigned.attachments(), nonce, body,
                deviceKeyPair.sign(unsigned.tbs()), null);
    }

    /**
     * Verifies a message and returns its content, decrypting it if an epoch key is given.
     *
     * @param epochKey The key of the message's epoch, null for public groups.
     * @param message The message.
     * @return The content.
     * @throws CryptographyException If the signature is invalid or the message does not decrypt.
     */
    public static ChatContent openMessage(byte[] epochKey, GroupMessage message)
    {
        if(!message.verifySignature())
        {
            throw new CryptographyException("The message signature is invalid");
        }

        if(epochKey == null)
        {
            if(message.nonce() != null)
            {
                throw new CryptographyException("The message is encrypted");
            }

            return Codec.decode(Encoding.JSON, message.content(), ChatContent.class);
        }

        if(message.nonce() == null)
        {
            throw new CryptographyException("The message is not encrypted");
        }

        return Codec.decode(Encoding.JSON, Cryptography.decrypt(epochKey, message.nonce(), message.content(), message.header()), ChatContent.class);
    }

    /**
     * Builds the additional data of encrypted properties.
     *
     * @param groupUuid The group identifier.
     * @param host The hosting domain.
     * @param epoch The epoch.
     * @return The additional data.
     */
    private static byte[] propertiesAad(UUID groupUuid, String host, long epoch)
    {
        return LpWriter.label("SB group-properties").uuid(groupUuid).str(host).integer(epoch).toByteArray();
    }
}
