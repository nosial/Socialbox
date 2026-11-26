package net.nosial.socialbox.enums;

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;
import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum RecordClass implements NamedEnumInterface
{
    /**
     * Anything this version does not know; kept like governance.
     */
    @JsonEnumDefaultValue
    UNKNOWN,

    /**
     * Governance: log entries, pins (which carry what they pin), key chains. Kept for good.
     */
    LOG,

    /**
     * Content: messages, posts, comments, votes and reactions. Subject to cleanup.
     */
    CONTENT
}
