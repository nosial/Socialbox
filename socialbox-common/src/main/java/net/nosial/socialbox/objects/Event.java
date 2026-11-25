package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.EventType;

public record Event(long id, EventType event, Object data, long created)
{
}
