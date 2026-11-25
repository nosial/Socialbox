package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

import java.util.Map;
import java.util.TreeMap;

public enum ProtocolLimit implements NamedEnumInterface
{
    /**
     * The largest frame, HTTP body or envelope, in bytes.
     */
    MAX_FRAME_SIZE(64L * 1024, 16L * 1024 * 1024, 1024L * 1024),

    /**
     * The most requests of one RPC batch.
     */
    MAX_BATCH_SIZE(1, 64, 32),

    /**
     * The largest accepted difference between a timestamp and the receiver's clock, in milliseconds. Every receiver
     * applies its own.
     */
    MAX_CLOCK_SKEW(1_000, 300_000, 60_000),

    /**
     * The longest lifetime of a standing statement, in milliseconds. Verifiers refuse longer ones.
     */
    MAX_STANDING_LIFETIME(10_000, 600_000, 600_000),

    /**
     * How long a pending handshake may take before it is discarded, in milliseconds.
     */
    HANDSHAKE_TIMEOUT(5_000, 60_000, 30_000),

    /**
     * The size of the window of envelope sequence numbers accepted out of order; also how far a restored session
     * skips its counter ahead.
     */
    REPLAY_WINDOW(1024, 65_536, 1024),

    /**
     * How long a session may go unused, in milliseconds. A server stops serving session keys unused this long
     * (availability); an account's sessions leave out sessions silent this long from the next root secret generation
     * (security), defaulting to this limit's default unless the account sets its own.
     */
    SESSION_LIFETIME(3_600_000L, 365L * 24 * 3_600_000, 14L * 24 * 3_600_000),

    /**
     * The largest sealed sync value, padding included, in bytes.
     */
    SYNC_MAX_VALUE_SIZE(256 + 28, 8L * 1024 * 1024 + 28, 512L * 1024 + 28),

    /**
     * The most writes of one syncPut, and record ids of one syncGet.
     */
    SYNC_MAX_BATCH(1, 256, 100),

    /**
     * The most live sync records of one account.
     */
    SYNC_MAX_RECORDS(1, 10_000_000, 100_000),

    /**
     * The most sealed bytes of one account's sync records.
     */
    SYNC_MAX_BYTES(1024L * 1024, 1024L * 1024 * 1024 * 1024, 1024L * 1024 * 1024),

    /**
     * The most account log entries one account may append per day.
     */
    MAX_LOG_ENTRIES_PER_DAY(8, 10_000, 64),

    /**
     * The most root secret generations one account may start per day.
     */
    MAX_GENERATIONS_PER_DAY(2, 1_000, 16);

    private final long minimum;
    private final long maximum;
    private final long defaultValue;

    ProtocolLimit(long minimum, long maximum, long defaultValue)
    {
        this.minimum = minimum;
        this.maximum = maximum;
        this.defaultValue = defaultValue;
    }

    /**
     * Returns the smallest value the protocol allows.
     *
     * @return The minimum.
     */
    public long getMinimum()
    {
        return this.minimum;
    }

    /**
     * Returns the largest value the protocol allows.
     *
     * @return The maximum.
     */
    public long getMaximum()
    {
        return this.maximum;
    }

    /**
     * Returns the suggested default.
     *
     * @return The default.
     */
    public long getDefault()
    {
        return this.defaultValue;
    }

    /**
     * Returns whether a value is within the protocol's bounds.
     *
     * @param value The value.
     * @return True if allowed.
     */
    public boolean isWithinBounds(long value)
    {
        return value >= this.minimum && value <= this.maximum;
    }

    /**
     * Returns a value moved into the protocol's bounds.
     *
     * @param value The value.
     * @return The nearest allowed value.
     */
    public long clamp(long value)
    {
        return Math.clamp(value, this.minimum, this.maximum);
    }

    /**
     * Returns every limit at its default, by name, sorted.
     *
     * @return The defaults.
     */
    public static Map<String, Long> defaults()
    {
        Map<String, Long> defaults = new TreeMap<>();
        for(ProtocolLimit limit : values())
        {
            defaults.put(limit.getName(), limit.defaultValue);
        }

        return defaults;
    }
}
