package net.nosial.socialbox.objects;

import net.nosial.socialbox.cryptography.TypedKey;

import java.util.Map;

public record RatchetState(byte[] rootKey, byte[] sendingChainKey, byte[] receivingChainKey, String ratchetPrivateKey, TypedKey remoteRatchetKey,
                           long sendCount, long receiveCount, long previousCount, Map<String, byte[]> skippedKeys, byte[] associatedData)
{
}
