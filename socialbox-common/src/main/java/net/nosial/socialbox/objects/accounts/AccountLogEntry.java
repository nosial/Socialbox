package net.nosial.socialbox.objects.accounts;

import net.nosial.socialbox.classes.cryptography.Cryptography;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.AccountLogEntryType;
import net.nosial.socialbox.enums.cryptography.Algorithms;
import net.nosial.socialbox.enums.cryptography.DomainLabel;
import net.nosial.socialbox.interfaces.SignedInterface;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.SigningKeyPair;
import net.nosial.socialbox.objects.cryptography.TypedKey;

import java.util.HashSet;
import java.util.List;

/**
 * One entry of an account log: the append-only, hash-chained record of an account's keys, sessions and root secret
 * generations. Entries are signed by the account key current at that point, except {@code generation} entries, which
 * any active session may sign. Servers store and serve entries but cannot write one. (see {@link AccountLogEntryType}).
 *
 * @param address The account.
 * @param seq The position in the log, starting at 0.
 * @param prev The hash of the previous entry, empty for the first one.
 * @param type The entry type.
 * @param key The key the entry is about: the account key, a session signing key or the encryption key.
 * @param kexKey The account kex key of a {@code genesis} or {@code account_key_rotate}, or the session's kex key of a
 *               {@code session_add}; otherwise null.
 * @param members The signing keys of the sessions a {@code generation} includes; otherwise empty.
 * @param timestamp When the entry was signed (ms); never goes backwards.
 * @param signer The key that signed the entry.
 * @param signature The signature.
 */
public record AccountLogEntry(PeerAddress address, long seq, byte[] prev, AccountLogEntryType type, TypedKey key, TypedKey kexKey,
                              List<TypedKey> members, long timestamp, TypedKey signer, byte[] signature) implements SignedInterface
{
    /**
     * The maximum number of sessions one generation can include.
     */
    public static final int MAX_MEMBERS = 256;

    /**
     * Normalizes a missing member list to an empty one.
     */
    public AccountLogEntry
    {
        members = members == null ? List.of() : List.copyOf(members);
    }

    /**
     * Creates and signs an entry that follows the given state.
     *
     * @param head The state of the log so far, null for the first entry.
     * @param address The account.
     * @param type The entry type.
     * @param key The key the entry is about.
     * @param kexKey The kex key, null unless {@code genesis}, {@code session_add} or {@code account_key_rotate}.
     * @param members The included sessions, null unless {@code generation}.
     * @param signerKeyPair The account key pair, or an active session's key pair for a {@code generation}.
     * @return The signed entry.
     */
    public static AccountLogEntry create(AccountState head, PeerAddress address, AccountLogEntryType type, TypedKey key, TypedKey kexKey,
                                         List<TypedKey> members, SigningKeyPair signerKeyPair)
    {
        long seq = head == null || head.isEmpty() ? 0 : head.getSeq() + 1;
        byte[] prev = head == null || head.isEmpty() ? new byte[0] : head.getHash();
        long timestamp = Math.max(System.currentTimeMillis(), head == null ? 0 : head.getTimestamp());
        AccountLogEntry unsigned = new AccountLogEntry(address, seq, prev, type, key, kexKey, members, timestamp, signerKeyPair.publicKey(),
                new byte[0]);
        return new AccountLogEntry(address, seq, prev, type, key, kexKey, members, timestamp, signerKeyPair.publicKey(),
                signerKeyPair.sign(unsigned.tbs()));
    }

    /**
     * Creates the first entry of a new account's log.
     *
     * @param address The account.
     * @param accountKeyPair The account key pair.
     * @param accountKexKey The account kex public key derived from the account key.
     * @return The signed entry.
     */
    public static AccountLogEntry genesis(PeerAddress address, SigningKeyPair accountKeyPair, TypedKey accountKexKey)
    {
        return create(null, address, AccountLogEntryType.GENESIS, accountKeyPair.publicKey(), accountKexKey, null, accountKeyPair);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] tbs()
    {
        LpWriter writer = LpWriter.label(DomainLabel.ACCOUNT_LOG_ENTRY)
                .str(this.address == null ? null : this.address.toString())
                .integer(this.seq)
                .lp(this.prev)
                .str(this.type == null ? null : this.type.getName())
                .key(this.key)
                .key(this.kexKey)
                .integer(this.members.size());
        for(TypedKey member : this.members)
        {
            writer.key(member);
        }

        return writer.integer(this.timestamp).key(this.signer).toByteArray();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isWellFormed()
    {
        if(this.address == null || this.address.isHost() || this.type == null || this.key == null || this.seq < 0 || this.prev == null ||
                (this.seq == 0) != (this.prev.length == 0) || (this.seq > 0 && this.prev.length != Cryptography.HASH_LENGTH) ||
                this.signer == null || !this.signer.isAlgorithm(Algorithms.ED25519))
        {
            return false;
        }

        boolean generation = this.type == AccountLogEntryType.GENERATION;
        if(generation == this.members.isEmpty() || this.members.size() > MAX_MEMBERS ||
                this.members.stream().anyMatch(member -> member == null || !member.isAlgorithm(Algorithms.ED25519)) ||
                new HashSet<>(this.members).size() != this.members.size())
        {
            return false;
        }

        boolean hasKex = this.type == AccountLogEntryType.GENESIS || this.type == AccountLogEntryType.SESSION_ADD ||
                this.type == AccountLogEntryType.ACCOUNT_KEY_ROTATE;
        if(hasKex == (this.kexKey == null) || (hasKex && !this.kexKey.isAlgorithm(Algorithms.X25519)))
        {
            return false;
        }

        return switch(this.type)
        {
            case GENESIS -> this.seq == 0 && this.key.equals(this.signer) && this.key.isAlgorithm(Algorithms.ED25519);
            case SESSION_ADD, SESSION_REVOKE, ACCOUNT_KEY_ROTATE -> this.seq > 0 && this.key.isAlgorithm(Algorithms.ED25519);
            case GENERATION -> this.seq > 0 && this.key.isAlgorithm(Algorithms.X25519);
        };
    }
}
