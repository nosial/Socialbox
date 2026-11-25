package net.nosial.socialbox.objects.server;

import net.nosial.socialbox.objects.cryptography.TypedKey;

import java.util.UUID;

public record ServerHello(String version, UUID sessionUuid, TypedKey ephemeralKey, TypedKey hostKey, byte[] signature)
{
}
