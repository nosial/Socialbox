package net.nosial.socialbox.objects.accounts;

import net.nosial.socialbox.enums.SessionStatus;
import net.nosial.socialbox.objects.cryptography.TypedKey;

/**
 * A session of an account as its account log describes it. Whether a session is still alive by use is not in the
 * log: sessions prove their activity to each other with sealed heartbeats, and exclude inactive ones from the next
 * root secret generation.
 *
 * @param signingKey The session's signing key, which identifies it.
 * @param kexKey The session's key exchange key, which its key boxes are sealed to.
 * @param added When the session was added (ms).
 * @param revoked When the session was revoked (ms), 0 if it was not.
 * @param status ACTIVE or REVOKED.
 */
public record AccountSession(TypedKey signingKey, TypedKey kexKey, long added, long revoked, SessionStatus status)
{
    /**
     * Returns whether the session is active (added and not revoked).
     *
     * @return True if active.
     */
    public boolean isActive()
    {
        return this.status == SessionStatus.ACTIVE;
    }
}
