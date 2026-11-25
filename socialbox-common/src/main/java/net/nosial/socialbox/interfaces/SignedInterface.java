package net.nosial.socialbox.interfaces;

import net.nosial.socialbox.classes.cryptography.Cryptography;
import net.nosial.socialbox.classes.encoding.LpWriter;
import net.nosial.socialbox.enums.cryptography.Algorithms;
import net.nosial.socialbox.objects.cryptography.TypedKey;

public interface SignedInterface
{
    /**
     * Returns the bytes covered by the signature.
     *
     * @return The signing input.
     */
    byte[] tbs();

    /**
     * Returns the key that signed the object.
     *
     * @return The signing key.
     */
    TypedKey signer();

    /**
     * Returns the signature.
     *
     * @return The signature.
     */
    byte[] signature();

    /**
     * Returns the hash that identifies the signed object: {@code H(lp(signed bytes) || lp(signature))}. Objects that
     * refer to another signed object (a chain, a nested object) write this hash.
     *
     * @return The hash.
     */
    default byte[] hash()
    {
        return Cryptography.hash(new LpWriter().lp(this.tbs()).lp(this.signature()).toByteArray());
    }

    /**
     * Returns whether the object has the structure its type requires, before any signature is checked. Objects
     * received from a peer are checked with {@link #verifySignature()}, which includes this check.
     *
     * @return True if well formed.
     */
    default boolean isWellFormed()
    {
        return true;
    }

    /**
     * Verifies the object: its structure, an Ed25519 signer, and the signature over {@link #tbs()}. Implementations
     * add their own structural rules by overriding {@link #isWellFormed()}, never this method.
     *
     * @return True if well formed and the signature is valid.
     */
    default boolean verifySignature()
    {
        TypedKey signer = this.signer();
        byte[] signature = this.signature();
        return this.isWellFormed() && signer != null && signer.isAlgorithm(Algorithms.ED25519) && signature != null &&
                Cryptography.verify(signer, this.tbs(), signature);
    }
}
