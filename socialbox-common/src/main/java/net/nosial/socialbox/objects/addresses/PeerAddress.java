package net.nosial.socialbox.objects.addresses;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import net.nosial.socialbox.Protocol;
import net.nosial.socialbox.classes.Validate;
import net.nosial.socialbox.enums.StandardError;
import net.nosial.socialbox.exceptions.SocialboxException;
import net.nosial.socialbox.interfaces.AddressInterface;

import java.util.Set;

public record PeerAddress(String username, String domain) implements AddressInterface
{
    private static final Set<String> RESERVED_USERNAMES = Set.of("host", "admin", "root", "system", "anonymous", "guest", "support", "abuse", "postmaster");

    /**
     * Validates the address on construction.
     *
     * @throws SocialboxException With {@link StandardError#INVALID_ADDRESS} if the address is malformed.
     */
    public PeerAddress
    {
        if(!Validate.username(username))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid username");
        }

        if(!Validate.domain(domain))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid domain");
        }
    }

    /**
     * Parses an address.
     *
     * @param address The address string.
     * @return The parsed address.
     * @throws SocialboxException With {@link StandardError#INVALID_ADDRESS} if the address is malformed.
     */
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public static PeerAddress parse(String address)
    {
        if(address == null || address.length() > 287)
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid address");
        }

        int separator = address.indexOf('@');
        if(separator <= 0 || separator != address.lastIndexOf('@'))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Addresses must have the form username@domain");
        }

        return new PeerAddress(address.substring(0, separator), address.substring(separator + 1));
    }

    /**
     * Returns whether the string is a valid address.
     *
     * @param address The address string.
     * @return True if valid.
     */
    public static boolean isValid(String address)
    {
        try
        {
            parse(address);
            return true;
        }
        catch(SocialboxException e)
        {
            return false;
        }
    }

    /**
     * Returns the host address of a domain, {@code host@domain}, used by servers acting as clients.
     *
     * @param domain The domain.
     * @return The host address.
     */
    public static PeerAddress host(String domain)
    {
        return new PeerAddress(Protocol.HOST_USERNAME, domain);
    }


    /**
     * Returns whether this is a host address.
     *
     * @return True for {@code host@domain}.
     */
    public boolean isHost()
    {
        return Protocol.HOST_USERNAME.equals(this.username);
    }

    /**
     * Returns whether the username is reserved and cannot be registered: the reserved names and any name starting
     * with an underscore.
     *
     * @return True if reserved.
     */
    public boolean isReserved()
    {
        return RESERVED_USERNAMES.contains(this.username) || this.username.startsWith("_");
    }

    /**
     * Returns whether the address is a bot's: its username ends in {@code bot}. Only bots may use such usernames, so
     * anyone can tell a bot from its address alone.
     *
     * @return True for bot addresses.
     */
    public boolean isBot()
    {
        return this.username.endsWith("bot");
    }

    /**
     * Returns the address string.
     *
     * @return The address string.
     */
    @JsonValue
    @Override
    public String toString()
    {
        return this.username + "@" + this.domain;
    }
}
