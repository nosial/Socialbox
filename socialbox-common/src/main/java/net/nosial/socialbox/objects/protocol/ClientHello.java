package net.nosial.socialbox.objects.protocol;

import net.nosial.socialbox.objects.accounts.AccountLogEntry;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.CryptographyParameters;
import net.nosial.socialbox.objects.cryptography.TypedKey;

/**
 * The first message of the handshake.
 *
 * @param version The protocol version.
 * @param crypto The algorithms the client uses, which must equal the server's.
 * @param ephemeralKey The client's ephemeral key exchange key.
 * @param identifyAs The address the session acts as, null for anonymous sessions.
 * @param identityKey The session's signing key (a user's session key or a server's host key), null for anonymous.
 * @param genesis The first entry of the account log, sent by clients holding the account key so a new account can be
 *                registered; ignored for existing accounts.
 * @param serverDomain The domain the client believes it is talking to.
 * @param clientName The client software name.
 * @param clientVersion The client software version.
 */
public record ClientHello(String version, CryptographyParameters crypto, TypedKey ephemeralKey, PeerAddress identifyAs,
                          TypedKey identityKey, AccountLogEntry genesis, String serverDomain, String clientName,
                          String clientVersion)
{
}
