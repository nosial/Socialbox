package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.PeerFlag;
import net.nosial.socialbox.objects.addresses.PeerAddress;
import net.nosial.socialbox.objects.cryptography.TypedKey;

import java.util.List;

public record Peer(PeerAddress address, TypedKey accountKey, List<InformationField> information, List<PeerFlag> flags, long registered)
{
}
