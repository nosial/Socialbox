package net.nosial.socialbox.objects;

import java.util.List;

public record EventPage(List<Event> events, long cursor, boolean reset)
{
}
