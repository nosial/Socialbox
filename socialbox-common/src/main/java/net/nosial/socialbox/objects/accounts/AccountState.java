package net.nosial.socialbox.objects.accounts;

import net.nosial.socialbox.enums.AccountLogEntryType;
import net.nosial.socialbox.enums.SessionStatus;
import net.nosial.socialbox.enums.StandardError;
import net.nosial.socialbox.exceptions.SocialboxException;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.TypedKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class AccountState
{
    private final PeerAddress address;
    private final TypedKey accountKey;
    private final TypedKey accountKexKey;
    private final Map<TypedKey, AccountSession> sessions;
    private final List<Generation> generations;
    private final List<byte[]> hashes;
    private final long timestamp;

    private AccountState(PeerAddress address, TypedKey accountKey, TypedKey accountKexKey, Map<TypedKey, AccountSession> sessions,
                         List<Generation> generations, List<byte[]> hashes, long timestamp)
    {
        this.address = address;
        this.accountKey = accountKey;
        this.accountKexKey = accountKexKey;
        this.sessions = sessions;
        this.generations = generations;
        this.hashes = hashes;
        this.timestamp = timestamp;
    }

    /**
     * Returns the state of an empty log.
     *
     * @param address The account.
     * @return The state.
     */
    public static AccountState empty(PeerAddress address)
    {
        return new AccountState(address, null, null, Map.of(), List.of(), List.of(), 0);
    }

    /**
     * Replays a whole log.
     *
     * @param address The account.
     * @param entries The entries, starting at seq 0.
     * @return The state.
     * @throws SocialboxException With ACCOUNT_LOG_INVALID if any entry is invalid.
     */
    public static AccountState replay(PeerAddress address, List<AccountLogEntry> entries)
    {
        return empty(address).apply(entries);
    }

    /**
     * Applies entries in order.
     *
     * @param entries The entries that follow this state.
     * @return The new state.
     * @throws SocialboxException With ACCOUNT_LOG_INVALID if any entry is invalid.
     */
    public AccountState apply(List<AccountLogEntry> entries)
    {
        AccountState state = this;
        for(AccountLogEntry entry : entries)
        {
            state = state.apply(entry);
        }

        return state;
    }

    /**
     * Verifies an entry against this state and applies it.
     *
     * @param entry The entry that follows this state.
     * @return The new state.
     * @throws SocialboxException With ACCOUNT_LOG_INVALID if the entry does not validly follow this state.
     */
    public AccountState apply(AccountLogEntry entry)
    {
        if(entry == null || !entry.isWellFormed() || !this.address.equals(entry.address()) || entry.seq() != this.hashes.size() ||
                !Arrays.equals(entry.prev(), this.isEmpty() ? new byte[0] : this.getHash()) || entry.timestamp() < this.timestamp)
        {
            throw invalid("The entry is malformed or does not follow the log");
        }

        if(!this.isAllowedSigner(entry) || !entry.verifySignature())
        {
            throw invalid("The entry is not signed by a key allowed to sign it");
        }

        TypedKey newAccountKey = this.accountKey;
        TypedKey newAccountKexKey = this.accountKexKey;
        Map<TypedKey, AccountSession> newSessions = new LinkedHashMap<>(this.sessions);
        List<Generation> newGenerations = this.generations;
        switch(entry.type())
        {
            case GENESIS ->
            {
                newAccountKey = entry.key();
                newAccountKexKey = entry.kexKey();
            }
            case SESSION_ADD ->
            {
                if(newSessions.containsKey(entry.key()) || entry.key().equals(this.accountKey))
                {
                    throw invalid("The session was added before");
                }

                newSessions.put(entry.key(), new AccountSession(entry.key(), entry.kexKey(), entry.timestamp(), 0, SessionStatus.ACTIVE));
            }
            case SESSION_REVOKE ->
            {
                AccountSession session = newSessions.get(entry.key());
                if(session == null || !session.isActive())
                {
                    throw invalid("Only added sessions can be revoked, once");
                }

                newSessions.put(entry.key(), new AccountSession(session.signingKey(), session.kexKey(), session.added(), entry.timestamp(),
                        SessionStatus.REVOKED));
            }
            case GENERATION ->
            {
                for(TypedKey member : entry.members())
                {
                    AccountSession session = newSessions.get(member);
                    if(session == null || !session.isActive())
                    {
                        throw invalid("A generation can only include active sessions");
                    }
                }

                if(this.generations.stream().anyMatch(generation -> generation.encryptionKey().equals(entry.key())))
                {
                    throw invalid("Every generation has a new encryption key");
                }

                List<Generation> extended = new ArrayList<>(this.generations);
                extended.add(new Generation(this.generations.size() + 1, entry.key(), entry.members(), entry.signer(), entry.timestamp()));
                newGenerations = Collections.unmodifiableList(extended);
            }
            case ACCOUNT_KEY_ROTATE ->
            {
                if(entry.key().equals(this.accountKey) || newSessions.containsKey(entry.key()))
                {
                    throw invalid("The new account key must be a new key");
                }

                newAccountKey = entry.key();
                newAccountKexKey = entry.kexKey();
            }
        }

        List<byte[]> newHashes = new ArrayList<>(this.hashes);
        newHashes.add(entry.hash());
        return new AccountState(this.address, newAccountKey, newAccountKexKey, Collections.unmodifiableMap(newSessions), newGenerations,
                Collections.unmodifiableList(newHashes), entry.timestamp());
    }

    /**
     * Returns whether the entry's signer may sign it: the account key for every entry, and also any active session for
     * a generation. The first entry signs itself.
     *
     * @param entry The entry.
     * @return True if the signer is allowed.
     */
    private boolean isAllowedSigner(AccountLogEntry entry)
    {
        if(this.isEmpty())
        {
            return entry.type() == AccountLogEntryType.GENESIS;
        }

        if(entry.signer().equals(this.accountKey))
        {
            return true;
        }

        AccountSession session = this.sessions.get(entry.signer());
        return entry.type() == AccountLogEntryType.GENERATION && session != null && session.isActive();
    }

    /**
     * Returns whether this log extends a pinned head: it reaches the pinned position with the pinned hash.
     *
     * @param seq The pinned seq.
     * @param hash The pinned hash.
     * @return True if the pin is part of this log.
     */
    public boolean extendsHead(long seq, byte[] hash)
    {
        return seq >= 0 && seq < this.hashes.size() && Arrays.equals(this.hashes.get((int) seq), hash);
    }

    /**
     * Returns the status of a session.
     *
     * @param signingKey The session's signing key.
     * @return ACTIVE or REVOKED, NOT_FOUND if the log never added it.
     */
    public SessionStatus getSessionStatus(TypedKey signingKey)
    {
        AccountSession session = signingKey == null ? null : this.sessions.get(signingKey);
        return session == null ? SessionStatus.NOT_FOUND : session.status();
    }

    /**
     * Returns a session.
     *
     * @param signingKey The session's signing key.
     * @return The session, null if the log never added it.
     */
    public AccountSession getSession(TypedKey signingKey)
    {
        return signingKey == null ? null : this.sessions.get(signingKey);
    }

    /**
     * Returns every session the log added, in order.
     *
     * @return The sessions.
     */
    public List<AccountSession> getSessions()
    {
        return List.copyOf(this.sessions.values());
    }

    /**
     * Returns the sessions that are active.
     *
     * @return The active sessions, in the order they were added.
     */
    public List<AccountSession> getActiveSessions()
    {
        return this.sessions.values().stream().filter(AccountSession::isActive).toList();
    }

    /**
     * Returns the number of sessions that are active.
     *
     * @return The count.
     */
    public long countActiveSessions()
    {
        return this.sessions.values().stream().filter(AccountSession::isActive).count();
    }

    /**
     * Returns the account.
     *
     * @return The address.
     */
    public PeerAddress getAddress()
    {
        return this.address;
    }

    /**
     * Returns the current account key.
     *
     * @return The key, null for an empty log.
     */
    public TypedKey getAccountKey()
    {
        return this.accountKey;
    }

    /**
     * Returns the current account kex key, which key boxes for the identity file are sealed to.
     *
     * @return The key, null for an empty log.
     */
    public TypedKey getAccountKexKey()
    {
        return this.accountKexKey;
    }

    /**
     * Returns the root secret generations, oldest first.
     *
     * @return The generations.
     */
    public List<Generation> getGenerations()
    {
        return this.generations;
    }

    /**
     * Returns the current generation.
     *
     * @return The newest generation, null if none was started.
     */
    public Generation getCurrentGeneration()
    {
        return this.generations.isEmpty() ? null : this.generations.getLast();
    }

    /**
     * Returns a generation by number.
     *
     * @param number The generation number, starting at 1.
     * @return The generation, null if there is no such generation.
     */
    public Generation getGeneration(int number)
    {
        return number < 1 || number > this.generations.size() ? null : this.generations.get(number - 1);
    }

    /**
     * Returns the current encryption key, the one others seal to.
     *
     * @return The key, null if no generation was started.
     */
    public TypedKey getEncryptionKey()
    {
        Generation current = this.getCurrentGeneration();
        return current == null ? null : current.encryptionKey();
    }

    /**
     * Returns whether the log is empty.
     *
     * @return True if no entry was applied.
     */
    public boolean isEmpty()
    {
        return this.hashes.isEmpty();
    }

    /**
     * Returns the seq of the head.
     *
     * @return The seq of the last entry, -1 for an empty log.
     */
    public long getSeq()
    {
        return this.hashes.size() - 1L;
    }

    /**
     * Returns the hash of the head.
     *
     * @return The hash of the last entry, empty for an empty log.
     */
    public byte[] getHash()
    {
        return this.isEmpty() ? new byte[0] : this.hashes.getLast().clone();
    }

    /**
     * Returns the head of the log.
     *
     * @return The head.
     */
    public AccountLogHead getHead()
    {
        return new AccountLogHead(this.getSeq(), this.getHash());
    }

    /**
     * Returns the timestamp of the last entry.
     *
     * @return The timestamp (ms), 0 for an empty log.
     */
    public long getTimestamp()
    {
        return this.timestamp;
    }

    private static SocialboxException invalid(String message)
    {
        return new SocialboxException(StandardError.ACCOUNT_LOG_INVALID, message);
    }
}
