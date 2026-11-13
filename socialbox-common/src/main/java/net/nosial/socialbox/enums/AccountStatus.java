package net.nosial.socialbox.enums;

public enum AccountStatus
{
    /**
     * Registration started but hasn't been completed yet
     */
    PENDING,

    /**
     * Registered account -- Good standing.
     */
    ACTIVE,

    /**
     * Disabled by the server, cannot create sessions
     */
    DISABLED;

    /**
     * Returns the standing status of the account, an indicator based off the internal account status
     *
     * @return The StandingStatus state derived from the AccountStatus
     */
    public StandingStatus toStandingStatus()
    {
        return switch(this)
        {
            case PENDING -> StandingStatus.NOT_FOUND;
            case ACTIVE -> StandingStatus.ACTIVE;
            case DISABLED -> StandingStatus.DISABLED;
        };
    }
}
