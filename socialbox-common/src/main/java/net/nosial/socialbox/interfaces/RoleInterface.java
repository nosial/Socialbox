package net.nosial.socialbox.interfaces;

public interface RoleInterface<P extends Enum<P>>
{
    /**
     * Returns the rank; higher ranks are more privileged.
     *
     * @return The rank.
     */
    int rank();

    /**
     * Returns whether the role holds a permission.
     *
     * @param permission The permission.
     * @return True if granted.
     */
    boolean has(P permission);

    /**
     * Returns whether this role is more privileged than another.
     *
     * @param other The other role.
     * @return True if this role ranks higher.
     */
    default boolean outranks(RoleInterface<P> other)
    {
        return this.rank() > other.rank();
    }
}
