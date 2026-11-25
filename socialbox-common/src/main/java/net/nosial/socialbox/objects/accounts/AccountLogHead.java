package net.nosial.socialbox.objects.accounts;

/**
 * The head of an account log: the position and hash of its last entry. Verifiers pin heads; a log is only accepted if
 * it extends every head pinned before.
 *
 * @param seq The seq of the last entry, -1 for an empty log.
 * @param hash The hash of the last entry, empty for an empty log.
 */
public record AccountLogHead(long seq, byte[] hash)
{
}
