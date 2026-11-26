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
     * Files of the account changed as the server sees them (an upload completed, a file was deleted). Data: the
     * FileChange list.
     */
    FILES_CHANGED("files.changed"),

    /**
     * The account's incoming settings changed (which kinds of messages it accepts). Data: the new {@code InboxSettings}.
     */
    INBOX_SETTINGS("inbox.settings"),

    /**
     * An outgoing delivery was delivered or failed for good. Data: the DeliveryStatus list.
     */
    INBOX_DELIVERY("inbox.delivery"),

    /**
     * A board of this server the account owns or administers changed (an entry was appended). Data: the BoardNotice.
     */
    BOARD_CHANGED("board.changed");

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
