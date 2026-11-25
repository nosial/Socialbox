package net.nosial.socialbox.classes.cryptography;

import net.nosial.socialbox.classes.encoding.Base64Url;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.objects.addresses.PeerAddress;

public final class PasswordAuthenticator
{
    private PasswordAuthenticator()
    {
    }

    /**
     * Derives the authenticator of a password.
     *
     * @param address The account address.
     * @param password The password.
     * @return The 32 byte authenticator.
     */
    public static byte[] derive(PeerAddress address, String password)
    {
        byte[] salt = Cryptography.hash(LpWriter.label(DomainLabel.PASSWORD).str(address.toString()).toByteArray());
        return Cryptography.pbkdf2(password, salt, Cryptography.PBKDF2_ITERATIONS, Cryptography.KEY_LENGTH);
    }

    /**
     * Derives the authenticator of a password in its wire form (base64url).
     *
     * @param address The account address.
     * @param password The password.
     * @return The base64url authenticator.
     */
    public static String deriveEncoded(PeerAddress address, String password)
    {
        return Base64Url.encode(derive(address, password));
    }
}
