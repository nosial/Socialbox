package net.nosial.socialbox.objects.protocol;

import net.nosial.socialbox.classes.cryptography.Cryptography;
import net.nosial.socialbox.classes.encoding.LpReader;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.exceptions.ProtocolException;

import java.util.Arrays;

public record Envelope(EnvelopeHeader header, byte[] headerBytes, byte[] body, byte[] signature)
{
    /**
     * Seals an envelope.
     *
     * @param header The header, which becomes the AEAD additional data.
     * @param key The direction's session key; the key of the sequence number's epoch is derived from it.
     * @param body The body.
     * @param signature The signature, null or empty if none.
     * @return The sealed envelope.
     */
    public static SealedEnvelope seal(EnvelopeHeader header, byte[] key, byte[] body, byte[] signature)
    {
        byte[] plaintext = new LpWriter().lp(body).lp(signature == null ? new byte[0] : signature).toByteArray();
        byte[] nonce = Cryptography.randomBytes(Cryptography.NONCE_LENGTH);
        return new SealedEnvelope(header, Cryptography.concat(nonce, Cryptography.encrypt(SessionKeys.epochKey(key, header.seq()), nonce, plaintext, header.encode())));
    }

    /**
     * Opens an envelope, authenticating its header with the payload. A header rebuilt from HTTP headers authenticates
     * exactly like one read from a frame, because both encode to the same bytes.
     *
     * @param envelope The sealed envelope.
     * @param key The direction's session key.
     * @return The opened envelope.
     * @throws CryptographyException If the envelope does not authenticate.
     * @throws ProtocolException If the envelope is malformed.
     */
    public static Envelope open(SealedEnvelope envelope, byte[] key)
    {
        byte[] headerBytes = envelope.header().encode();
        byte[] payload = envelope.payload();
        byte[] nonce = Arrays.copyOfRange(payload, 0, Cryptography.NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(payload, Cryptography.NONCE_LENGTH, payload.length);
        byte[] plaintext = Cryptography.decrypt(SessionKeys.epochKey(key, envelope.header().seq()), nonce, ciphertext, headerBytes);

        try
        {
            LpReader reader = new LpReader(plaintext);
            byte[] body = reader.lp();
            byte[] signature = reader.lp();
            return new Envelope(envelope.header(), headerBytes, body, signature);
        }
        catch(IllegalArgumentException e)
        {
            throw new ProtocolException("Malformed envelope plaintext", e);
        }
    }

    /**
     * Returns the input a REQUEST envelope's signature covers.
     *
     * @param headerBytes The raw header bytes.
     * @param body The body.
     * @return The signing input.
     */
    public static byte[] requestSignatureInput(byte[] headerBytes, byte[] body)
    {
        return LpWriter.label(DomainLabel.REQUEST).lp(headerBytes).lp(body).toByteArray();
    }
}
