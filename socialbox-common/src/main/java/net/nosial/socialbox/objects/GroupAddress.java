package net.nosial.socialbox.objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import net.nosial.socialbox.enums.StandardError;
import net.nosial.socialbox.exceptions.SocialboxException;

import java.util.UUID;
import java.util.regex.Pattern;

public record GroupAddress(String name, UUID uuid, String domain) implements AddressInterface
{
    private static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9_])?$");
    public static final char PUBLIC_PREFIX = '#';
    public static final char PRIVATE_PREFIX = '!';

    /**
     * Validates the parts.
     *
     * @param name The name, or null.
     * @param uuid The identifier, or null.
     * @param domain The domain.
     */
    public GroupAddress
    {
        if((name == null) == (uuid == null))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "A group address has either a name or an identifier");
        }

        if(name != null && !isValidName(name))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid group name");
        }

        if(!AddressInterface.isValidDomain(domain))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid domain");
        }
    }

    /**
     * Returns the address of a public group's name.
     *
     * @param name The name without the {@code #}.
     * @param domain The hosting domain.
     * @return The address.
     */
    public static GroupAddress ofName(String name, String domain)
    {
        return new GroupAddress(name, null, domain);
    }

    /**
     * Returns the address of a group's identifier.
     *
     * @param uuid The identifier.
     * @param domain The hosting domain.
     * @return The address.
     */
    public static GroupAddress ofUuid(UUID uuid, String domain)
    {
        return new GroupAddress(null, uuid, domain);
    }

    /**
     * Parses {@code #name@domain} or {@code !uuid@domain}.
     *
     * @param address The address.
     * @return The parsed address.
     * @throws SocialboxException With INVALID_ADDRESS if malformed.
     */
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public static GroupAddress parse(String address)
    {
        if(address == null || address.length() < 4 || address.length() > 320)
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid group address");
        }

        int separator = address.indexOf('@');
        if(separator <= 1 || separator != address.lastIndexOf('@'))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Group addresses have the form #name@domain or !uuid@domain");
        }

        String local = address.substring(1, separator);
        String domain = address.substring(separator + 1);
        return switch(address.charAt(0))
        {
            case PUBLIC_PREFIX -> ofName(local, domain); // Public Groups
            case PRIVATE_PREFIX -> ofUuid(parseUuid(local), domain); // Encrypted Groups
            default -> throw new SocialboxException(StandardError.INVALID_ADDRESS, "Group addresses start with # or !");
        };
    }

    /**
     * Returns whether a public group name is valid: 1 to 64 letters, digits, dots, dashes and underscores, starting
     * with a letter or digit.
     *
     * @param name The name without the {@code #}.
     * @return True if valid.
     */
    public static boolean isValidName(String name)
    {
        return name != null && NAME_PATTERN.matcher(name).matches() && !name.contains("..");
    }

    /**
     * Returns the case-insensitive key of the name, which is unique per hosting server.
     *
     * @return The lower case key, null for an address by identifier.
     */
    public String nameKey()
    {
        return this.name == null ? null : AddressInterface.nameKey(this.name);
    }

    /**
     * Returns whether the address names the group by its identifier.
     *
     * @return True for {@code !uuid@domain}.
     */
    public boolean isUuid()
    {
        return this.uuid != null;
    }

    /**
     * Returns the address as a string.
     *
     * @return {@code #name@domain} or {@code !uuid@domain}.
     */
    @JsonValue
    @Override
    public String toString()
    {
        return this.uuid != null ? "!" + this.uuid + "@" + this.domain : "#" + this.name + "@" + this.domain;
    }

    /**
     * Parses an identifier.
     *
     * @param value The identifier text.
     * @return The identifier.
     */
    private static UUID parseUuid(String value)
    {
        try
        {
            return UUID.fromString(value);
        }
        catch(IllegalArgumentException e)
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid group identifier");
        }
    }
}
