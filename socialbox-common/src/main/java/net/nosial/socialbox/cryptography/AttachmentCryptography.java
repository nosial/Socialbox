package net.nosial.socialbox.cryptography;

import net.nosial.socialbox.exceptions.CryptographyException;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;

public final class AttachmentCryptography
{
    public static final int CHUNK_SIZE = 512 * 1024;
    public static final int TAG_SIZE = 16;

    /**
     * Returns the number of chunks of an attachment.
     *
     * @param plaintextSize The plaintext size.
     * @return The chunk count (at least 1).
     */
    public static int chunkCount(long plaintextSize)
    {
        return (int) Math.max(1, (plaintextSize + CHUNK_SIZE - 1) / CHUNK_SIZE);
    }

    /**
     * Returns the ciphertext size of an attachment.
     *
     * @param plaintextSize The plaintext size.
     * @return The ciphertext size.
     */
    public static long ciphertextSize(long plaintextSize)
    {
        return plaintextSize + (long) chunkCount(plaintextSize) * TAG_SIZE;
    }

    /**
     * Returns whether a declared ciphertext size and chunk count fit each other.
     *
     * @param size The ciphertext size.
     * @param chunkCount The chunk count.
     * @return True if consistent.
     */
    public static boolean isConsistent(long size, int chunkCount)
    {
        if(chunkCount < 1 || size < (long) chunkCount * TAG_SIZE)
        {
            return false;
        }

        long full = (long) (CHUNK_SIZE + TAG_SIZE) * (chunkCount - 1);
        long last = size - full;
        return last >= TAG_SIZE && last <= CHUNK_SIZE + TAG_SIZE;
    }

    /**
     * Returns the expected ciphertext size of a chunk.
     *
     * @param size The attachment's ciphertext size.
     * @param chunkCount The chunk count.
     * @param index The chunk index.
     * @return The chunk's ciphertext size.
     */
    public static int expectedChunkSize(long size, int chunkCount, int index)
    {
        if(index < chunkCount - 1)
        {
            return CHUNK_SIZE + TAG_SIZE;
        }

        return (int) (size - (long) (CHUNK_SIZE + TAG_SIZE) * (chunkCount - 1));
    }

    /**
     * Encrypts one attachment chunk.
     *
     * @param attachmentKey The attachment key.
     * @param attachmentUuid The attachment identifier.
     * @param index The chunk index.
     * @param last Whether this is the last chunk.
     * @param plaintext The chunk plaintext (at most {@link #CHUNK_SIZE} bytes; exactly that unless last).
     * @return The chunk ciphertext.
     * @throws CryptographyException If the chunk has an invalid size.
     */
    public static byte[] encryptChunk(byte[] attachmentKey, UUID attachmentUuid, int index, boolean last, byte[] plaintext)
    {
        if(plaintext.length > CHUNK_SIZE || (!last && plaintext.length != CHUNK_SIZE))
        {
            throw new CryptographyException("Invalid chunk size");
        }

        return Cryptography.encrypt(attachmentKey, chunkNonce(index), plaintext, chunkAad(attachmentUuid, index, last));
    }

    /**
     * Decrypts one attachment chunk.
     *
     * @param attachmentKey The attachment key.
     * @param attachmentUuid The attachment identifier.
     * @param index The chunk index.
     * @param last Whether this is the last chunk.
     * @param ciphertext The chunk ciphertext.
     * @return The chunk plaintext.
     */
    public static byte[] decryptChunk(byte[] attachmentKey, UUID attachmentUuid, int index, boolean last, byte[] ciphertext)
    {
        return Cryptography.decrypt(attachmentKey, chunkNonce(index), ciphertext, chunkAad(attachmentUuid, index, last));
    }

    /**
     * Hashes a chunk ciphertext.
     *
     * @param ciphertext The chunk ciphertext.
     * @return The hash.
     */
    public static byte[] hashChunk(byte[] ciphertext)
    {
        return Cryptography.hash(ciphertext);
    }

    /**
     * Computes the root over every chunk's hash.
     *
     * @param chunkHashes The chunk hashes in order.
     * @return The root.
     */
    public static byte[] root(List<byte[]> chunkHashes)
    {
        LpWriter writer = LpWriter.label("SB attachment-chunks");
        for(byte[] hash : chunkHashes)
        {
            writer.lp(hash);
        }

        return Cryptography.hash(writer.toByteArray());
    }

    /**
     * Builds the nonce of a chunk.
     *
     * @param index The chunk index.
     * @return The nonce.
     */
    private static byte[] chunkNonce(int index)
    {
        return ByteBuffer.allocate(Cryptography.NONCE_LENGTH).putInt(0).putLong(index).array();
    }

    /**
     * Builds the additional data of a chunk.
     *
     * @param attachmentUuid The attachment identifier.
     * @param index The chunk index.
     * @param last Whether this is the last chunk.
     * @return The additional data.
     */
    private static byte[] chunkAad(UUID attachmentUuid, int index, boolean last)
    {
        return LpWriter.label("SB attachment-chunk").uuid(attachmentUuid).integer(index).bool(last).toByteArray();
    }
}
