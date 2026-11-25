package net.nosial.socialbox.classes.protocol;

import net.nosial.socialbox.classes.cryptography.Cryptography;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.objects.protocol.ClientHello;
import net.nosial.socialbox.objects.server.ServerHello;

public final class Transcript
{
    private Transcript()
    {
    }

    /**
     * Computes the transcript hash of a handshake.
     *
     * @param clientHello The client hello.
     * @param serverHello The server hello (its signature is not part of the transcript).
     * @return The 32 byte transcript hash.
     */
    public static byte[] compute(ClientHello clientHello, ServerHello serverHello)
    {
        LpWriter writer = LpWriter.label(DomainLabel.TRANSCRIPT).str(clientHello.version());
        clientHello.crypto().writeTo(writer);
        writer.key(clientHello.ephemeralKey())
                .str(clientHello.identifyAs() == null ? "" : clientHello.identifyAs().toString())
                .key(clientHello.identityKey())
                .lp(clientHello.genesis() == null ? new byte[0] : clientHello.genesis().hash())
                .str(clientHello.serverDomain())
                .str(clientHello.clientName())
                .str(clientHello.clientVersion())
                .uuid(serverHello.sessionUuid())
                .key(serverHello.ephemeralKey())
                .key(serverHello.hostKey());
        return Cryptography.hash(writer.toByteArray());
    }

    /**
     * Returns the input the server's hello signature covers.
     *
     * @param transcript The transcript hash.
     * @return The signing input.
     */
    public static byte[] serverSignatureInput(byte[] transcript)
    {
        return LpWriter.label(DomainLabel.SERVER_HELLO).lp(transcript).toByteArray();
    }

    /**
     * Returns the input the client's finish signature covers.
     *
     * @param transcript The transcript hash.
     * @return The signing input.
     */
    public static byte[] finishSignatureInput(byte[] transcript)
    {
        return LpWriter.label(DomainLabel.CLIENT_FINISH).lp(transcript).toByteArray();
    }
}
