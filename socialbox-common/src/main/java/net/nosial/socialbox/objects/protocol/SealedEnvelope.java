package net.nosial.socialbox.objects.protocol;

import net.nosial.socialbox.classes.cryptography.Cryptography;
import net.nosial.socialbox.exceptions.ProtocolException;

import java.util.Arrays;

/**
 * An envelope as it travels: the plain header, which is also the AEAD additional data, and the sealed payload
 * ({@code nonce || AEAD(lp(body) || lp(signature))}). Streaming transports carry both as one byte string
 * ({@link #toBytes()}); HTTP carries the header as {@code Socialbox-*} headers and the payload as the body.
 *
 * @param header The header.
 * @param payload The nonce followed by the ciphertext.
 */
public record SealedEnvelope(EnvelopeHeader header, byte[] payload)
{
    /**
     * The smallest payload: a nonce and an authentication tag.
     */
    public static final int MIN_PAYLOAD_SIZE = Cryptography.NONCE_LENGTH + 16;

    /**
     * Validates the parts.
     *
     * @throws ProtocolException If a part is missing or the payload is too short.
     */
    public SealedEnvelope
    {
        if(header == null || payload == null || payload.length < MIN_PAYLOAD_SIZE)
        {
            throw new ProtocolException("Envelope is too short");
        }
    }

    /**
     * Parses the byte string form: the encoded header followed by the payload.
     *
     * @param envelope The envelope bytes.
     * @return The envelope.
     * @throws ProtocolException If the envelope is malformed.
     */
    public static SealedEnvelope fromBytes(byte[] envelope)
    {
        EnvelopeHeader header = EnvelopeHeader.decode(envelope);
        return new SealedEnvelope(header, Arrays.copyOfRange(envelope, EnvelopeHeader.SIZE, envelope.length));
    }

    /**
     * Returns the byte string form: the encoded header followed by the payload.
     *
     * @return The envelope bytes.
     */
    public byte[] toBytes()
    {
        return Cryptography.concat(this.header.encode(), this.payload);
    }
}
