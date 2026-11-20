package net.nosial.socialbox.cryptography;

import net.nosial.socialbox.enums.Algorithms;
import net.nosial.socialbox.exceptions.CryptographyException;
import net.nosial.socialbox.objects.KeyExchangeKeyPair;
import net.nosial.socialbox.objects.PeerAddress;
import net.nosial.socialbox.objects.e2e.E2EInit;
import net.nosial.socialbox.objects.e2e.E2EPreKeyBundle;
import net.nosial.socialbox.objects.e2e.E2EPreKeys;

import java.util.Arrays;

public final class E2EHandshake
{
    private static final byte[] ZERO_SALT = new byte[Cryptography.KEY_LENGTH];
    private static final byte[] PREFIX = filled();
    private static final byte[] INFO = new LpWriter().str("SB e2e x3dh").toByteArray();

    /**
     * Starts a session with a device from its pre key bundle. The caller must have verified that the bundle's device
     * belongs to the responder (its device certificate) before calling.
     *
     * @param self The initiator's address.
     * @param selfDevice The initiator's device signing key.
     * @param identityKeyPair The initiator device's E2E identity key pair.
     * @param responder The responder's address.
     * @param bundle The responder device's bundle.
     * @return The handshake keys to attach and the started ratchet.
     * @throws CryptographyException If the bundle is not signed by the expected account's device.
     */
    public static Initiated initiate(PeerAddress self, TypedKey selfDevice, KeyExchangeKeyPair identityKeyPair, PeerAddress responder,
                                     E2EPreKeyBundle bundle)
    {
        E2EPreKeys preKeys = bundle.preKeys();
        if(preKeys == null || !preKeys.verifySignature() || !responder.equals(preKeys.address()))
        {
            throw new CryptographyException("The pre key bundle is not signed by a device of " + responder);
        }

        if(bundle.oneTimePreKey() != null && !bundle.oneTimePreKey().isAlgorithm(Algorithms.X25519))
        {
            throw new CryptographyException("The one-time pre key is not an X25519 key");
        }

        KeyExchangeKeyPair ephemeral = KeyExchangeKeyPair.generate();
        LpWriter material = new LpWriter()
                .raw(PREFIX)
                .raw(identityKeyPair.agree(preKeys.signedPreKey()))
                .raw(ephemeral.agree(preKeys.identityKey()))
                .raw(ephemeral.agree(preKeys.signedPreKey()));
        if(bundle.oneTimePreKey() != null)
        {
            material.raw(ephemeral.agree(bundle.oneTimePreKey()));
        }

        byte[] secret = Cryptography.hkdf(ZERO_SALT, material.toByteArray(), INFO, Cryptography.KEY_LENGTH);
        byte[] associatedData = associatedData(self, selfDevice, identityKeyPair.publicKey(), responder, preKeys.deviceKey(), preKeys.identityKey());
        E2EInit init = new E2EInit(identityKeyPair.publicKey(), ephemeral.publicKey(), preKeys.signedPreKey(), bundle.oneTimePreKey());
        return new Initiated(init, DoubleRatchet.initiator(secret, preKeys.signedPreKey(), associatedData));
    }

    /**
     * Answers a handshake from the first envelope of an initiator.
     *
     * @param self The responder's address.
     * @param selfDevice The responder's device signing key.
     * @param identityKeyPair The responder device's E2E identity key pair.
     * @param signedPreKeyPair The signed pre key pair the initiator used.
     * @param oneTimePreKeyPair The one-time pre key pair the initiator used, null if none.
     * @param initiator The initiator's address.
     * @param initiatorDevice The initiator's device signing key.
     * @param init The handshake keys.
     * @return The started ratchet.
     */
    public static DoubleRatchet respond(PeerAddress self, TypedKey selfDevice, KeyExchangeKeyPair identityKeyPair,
                                        KeyExchangeKeyPair signedPreKeyPair, KeyExchangeKeyPair oneTimePreKeyPair, PeerAddress initiator,
                                        TypedKey initiatorDevice, E2EInit init)
    {
        LpWriter material = new LpWriter()
                .raw(PREFIX)
                .raw(signedPreKeyPair.agree(init.identityKey()))
                .raw(identityKeyPair.agree(init.ephemeralKey()))
                .raw(signedPreKeyPair.agree(init.ephemeralKey()));
        if(init.oneTimePreKey() != null)
        {
            if(oneTimePreKeyPair == null)
            {
                throw new CryptographyException("The one-time pre key is no longer available");
            }

            material.raw(oneTimePreKeyPair.agree(init.ephemeralKey()));
        }

        byte[] secret = Cryptography.hkdf(ZERO_SALT, material.toByteArray(), INFO, Cryptography.KEY_LENGTH);
        byte[] associatedData = associatedData(initiator, initiatorDevice, init.identityKey(), self, selfDevice, identityKeyPair.publicKey());
        return DoubleRatchet.responder(secret, signedPreKeyPair, associatedData);
    }

    /**
     * Builds the associated data binding both devices' identities into every message.
     *
     * @param initiator The initiator.
     * @param initiatorDevice The initiator's device signing key.
     * @param initiatorIdentity The initiator's E2E identity key.
     * @param responder The responder.
     * @param responderDevice The responder's device signing key.
     * @param responderIdentity The responder's E2E identity key.
     * @return The associated data.
     */
    private static byte[] associatedData(PeerAddress initiator, TypedKey initiatorDevice, TypedKey initiatorIdentity, PeerAddress responder,
                                         TypedKey responderDevice, TypedKey responderIdentity)
    {
        return LpWriter.label("SB e2e-ad").str(initiator.toString()).key(initiatorDevice).key(initiatorIdentity).str(responder.toString())
                .key(responderDevice).key(responderIdentity).toByteArray();
    }

    /**
     * Returns 32 bytes of 0xFF, prefixed to the key material as in X3DH.
     *
     * @return The prefix.
     */
    private static byte[] filled()
    {
        byte[] prefix = new byte[Cryptography.KEY_LENGTH];
        Arrays.fill(prefix, (byte) 0xFF);
        return prefix;
    }

    /**
     * The result of starting a handshake.
     *
     * @param init The handshake keys to attach to envelopes until the responder answers.
     * @param ratchet The started ratchet.
     */
    public record Initiated(E2EInit init, DoubleRatchet ratchet)
    {
    }
}
