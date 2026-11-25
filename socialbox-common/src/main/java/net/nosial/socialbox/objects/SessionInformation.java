package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.SessionFlag;
import net.nosial.socialbox.objects.addresses.PeerAddress;

import java.util.List;
import java.util.UUID;

public record SessionInformation(UUID sessionUuid, PeerAddress address, boolean authenticated,
                                 List<SessionFlag> flags, List<Challenge> challenges, long created, long expires)
{
}
