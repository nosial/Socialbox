package net.nosial.socialbox.interfaces;

import net.nosial.socialbox.enums.StandardError;
import net.nosial.socialbox.exceptions.SocialboxException;
import net.nosial.socialbox.objects.addresses.PeerAddress;

public interface AddressInterface
{
    /**
     * Returns the domain the address lives in.
     *
     * @return The domain.
     */
    String domain();

    /**
     * Parses an address.
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

        return PeerAddress.parse(value);
    }
}
