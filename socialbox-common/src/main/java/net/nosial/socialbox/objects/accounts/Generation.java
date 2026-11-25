package net.nosial.socialbox.objects.accounts;

import net.nosial.socialbox.objects.cryptography.TypedKey;

import java.util.List;

/**
 * A root secret generation as the account log describes it.
 *
 * @param number The generation number, starting at 1.
 * @param encryptionKey The account encryption key derived from the generation's root secret.
 * @param members The signing keys of the sessions the generation includes.
 * @param signer The key that started the generation: the account key or a session key.
 * @param timestamp When the generation started (ms).
 */
public record Generation(int number, TypedKey encryptionKey, List<TypedKey> members, TypedKey signer, long timestamp)
{
    /**
     * Returns whether the generation includes a session.
     *
     * @param signingKey The session's signing key.
     * @return True if included.
     */
    public boolean includes(TypedKey signingKey)
    {
        return this.members.contains(signingKey);
    }
}
