package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.StandardError;
import net.nosial.socialbox.exceptions.SocialboxException;

import java.util.Locale;
import java.util.regex.Pattern;

public sealed interface AddressInterface permits PeerAddress, GroupAddress, BoardAddress
{
    int MAX_DOMAIN_LENGTH = 253;

    /**
     * Returns the domain the address lives in.
     *
     * @return The domain.
     */
    String domain();

    /**
     * Parses an address of any kind, telling the kinds apart by their first character.
     *
     * @param value The address.
     * @return The address.
     * @throws SocialboxException With INVALID_ADDRESS if the value is no valid address.
     */
    static AddressInterface parse(String value)
    {
        if(value == null || value.isEmpty())
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "The address is empty");
        }

        return switch(value.charAt(0))
        {
            case GroupAddress.PUBLIC_PREFIX, GroupAddress.PRIVATE_PREFIX -> GroupAddress.parse(value);
            case BoardAddress.PREFIX -> BoardAddress.parse(value);
            default -> PeerAddress.parse(value);
        };
    }

    /**
     * Returns whether a domain is valid: lower case, at most {@value #MAX_DOMAIN_LENGTH} characters, at least two
     * labels of letters, digits and inner dashes.
     *
     * @param domain The domain.
     * @return True if valid.
     */
    static boolean isValidDomain(String domain)
    {
        if(domain == null || domain.isEmpty() || domain.length() > MAX_DOMAIN_LENGTH)
        {
            return false;
        }

        String[] labels = domain.split("\\.", -1);
        if(labels.length < 2)
        {
            return false;
        }

        for(String label : labels)
        {
            if(!Patterns.DOMAIN_LABEL.matcher(label).matches())
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns the case-insensitive key of a group or board name, which is unique per hosting server.
     *
     * @param name The name.
     * @return The lower case key.
     */
    static String nameKey(String name)
    {
        return name.toLowerCase(Locale.ROOT);
    }

    /**
     * The patterns of the address rules.
     */
    final class Patterns
    {
        private static final Pattern DOMAIN_LABEL = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");

        private Patterns()
        {
        }
    }
}
