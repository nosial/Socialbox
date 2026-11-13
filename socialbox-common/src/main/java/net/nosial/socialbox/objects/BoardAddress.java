package net.nosial.socialbox.objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import net.nosial.socialbox.enums.StandardError;
import net.nosial.socialbox.exceptions.SocialboxException;

public record BoardAddress(String name, String domain) implements AddressInterface
{
    /**
     * The character that starts a board address. eg; ~PublicBoard@example.com
     */
    public static final char PREFIX = '~';

    /**
     * Validates the parts.
     *
     * @param name The name.
     * @param domain The domain.
     */
    public BoardAddress
    {
        if(!isValidName(name))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid board name");
        }

        if(!AddressInterface.isValidDomain(domain))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Invalid domain");
        }
    }

    /**
     * Parses {@code ~name@domain}.
     *
     * @param address The address.
     * @return The parsed address.
     * @throws SocialboxException With INVALID_ADDRESS if malformed.
     */
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public static BoardAddress parse(String address)
    {
        if(address == null || address.length() < 4 || address.length() > 320 || address.charAt(0) != PREFIX)
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Board addresses have the form ~name@domain");
        }

        int separator = address.indexOf('@');
        if(separator <= 1 || separator != address.lastIndexOf('@'))
        {
            throw new SocialboxException(StandardError.INVALID_ADDRESS, "Board addresses have the form ~name@domain");
        }

        return new BoardAddress(address.substring(1, separator), address.substring(separator + 1));
    }

    /**
     * Returns whether a board name is valid: the same rules as public group names (1 to 64 letters, digits, dots,
     * dashes and underscores, starting with a letter or digit).
     *
     * @param name The name without the {@code ~}.
     * @return True if valid.
     */
    public static boolean isValidName(String name)
    {
        return GroupAddress.isValidName(name);
    }

    /**
     * Returns the case-insensitive key of the name, which is unique per hosting server.
     *
     * @return The lower case key.
     */
    public String nameKey()
    {
        return AddressInterface.nameKey(this.name);
    }

    /**
     * Returns whether two addresses name the same board, ignoring the name's case.
     *
     * @param other The other address.
     * @return True if the same board.
     */
    public boolean sameBoard(BoardAddress other)
    {
        return other != null && this.domain.equals(other.domain()) && this.nameKey().equals(other.nameKey());
    }

    /**
     * Returns the address as a string.
     *
     * @return {@code ~name@domain}.
     */
    @JsonValue
    @Override
    public String toString()
    {
        return PREFIX + this.name + "@" + this.domain;
    }
}
