package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.SignatureStatus;
import net.nosial.socialbox.objects.accounts.AccountSession;

/**
 * The result of verifying a content signature.
 *
 * @param status The outcome.
 * @param session The session that signed, as the author's account log describes it; null if it could not be resolved.
 */
public record SignatureVerification(SignatureStatus status, AccountSession session)
{
}
