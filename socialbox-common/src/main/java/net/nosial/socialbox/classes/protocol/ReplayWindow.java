package net.nosial.socialbox.classes.protocol;

import net.nosial.socialbox.objects.protocol.EnvelopeHeader;

import java.util.BitSet;

public final class ReplayWindow
{
    private final int size;
    private final BitSet seen;
    private final long floor;
    private long highest;

    /**
     * Creates a window.
     *
     * @param highest The highest sequence number already received (0 for a new session). It and every sequence number
     *                below it are rejected.
     * @param size The window size, the {@code replay_window} limit of the receiving side.
     */
    public ReplayWindow(long highest, int size)
    {
        this.size = size;
        this.seen = new BitSet(this.size);
        this.floor = Math.max(0, highest);
        this.highest = this.floor;
    }

    /**
     * Accepts a sequence number if it was not received before.
     *
     * @param seq The sequence number.
     * @return True if accepted, false if it is a replay or too old.
     */
    public synchronized boolean accept(long seq)
    {
        if(seq <= this.floor || seq < 0 || seq > EnvelopeHeader.MAX_SEQ)
        {
            return false;
        }

        if(seq > this.highest)
        {
            long shift = seq - this.highest;
            if(shift >= this.size)
            {
                this.seen.clear();
            }
            else
            {
                for(long i = this.highest + 1; i <= seq; i++)
                {
                    this.seen.clear((int) (i % this.size));
                }
            }

            this.highest = seq;
            this.seen.set((int) (seq % this.size));
            return true;
        }

        if(this.highest - seq >= this.size)
        {
            return false;
        }

        int index = (int) (seq % this.size);
        if(this.seen.get(index))
        {
            return false;
        }

        this.seen.set(index);
        return true;
    }

    /**
     * Returns the highest sequence number received.
     *
     * @return The highest sequence number.
     */
    public synchronized long getHighest()
    {
        return this.highest;
    }
}
