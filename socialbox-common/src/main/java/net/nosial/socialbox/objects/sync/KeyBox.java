package net.nosial.socialbox.objects.sync;

import net.nosial.socialbox.objects.cryptography.SealedKey;
import net.nosial.socialbox.objects.cryptography.TypedKey;

/**
 * The root secrets of every generation up to {@code generation}, sealed to one recipient: a session (identified by
 * its signing key and sealed to its kex key) or the account (sealed to the account kex key). Only the newest box of
 * each recipient matters, since it carries every generation. A client accepts a box only if each secret in it derives
 * the encryption key the account log lists for its generation, so a server cannot plant a secret it knows.
 *
 * @param recipient The recipient: a session's signing key, or the account kex key.
 * @param generation The newest generation in the box.
 * @param box The sealed secrets.
 */
public record KeyBox(TypedKey recipient, int generation, SealedKey box)
{
}
