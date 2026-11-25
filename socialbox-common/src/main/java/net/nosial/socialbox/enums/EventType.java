package net.nosial.socialbox.enums;

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;
import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum EventType implements NamedEnumInterface
{
    /**
     * An event of a newer server this implementation does not know. Clients advance their cursor past it and tell
     * nobody; servers never send it.
     */
    @JsonEnumDefaultValue
    UNKNOWN("unknown.unknown"),

    /**
     * The account log grew. Data: the new AccountLogHead; sessions fetch the entries with getAccountLog.
     */
    ACCOUNT_LOG("account.log"),

    /**
     * Records of the account's encrypted store changed, written by one of its sessions. Data: the SyncChange list;
     * the content itself is fetched from the store.
     */
    SYNC_CHANGED("sync.changed");

    private final String name;

    EventType(String name)
    {
        this.name = name;
    }

    /**
     * Returns the event name.
     *
     * @return The event name.
     */
    @Override
    public String getName()
    {
        return this.name;
    }

    /**
     * Returns the category of the event, the part of its name before the dot (e.g. {@code sync}), so
     * clients can route events to the view they concern.
     *
     * @return The category.
     */
    public String getCategory()
    {
        return this.name.substring(0, this.name.indexOf('.'));
    }
}
