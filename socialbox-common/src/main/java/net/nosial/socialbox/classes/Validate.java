package net.nosial.socialbox.classes;

import java.net.URI;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.regex.Pattern;

public final class Validate
{
    public static final int MAX_DOMAIN_LENGTH = 253;
    public static final int MAX_EMAIL_LENGTH = 254;

    private static final Pattern DOMAIN_LABEL_PATTERN = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$");
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9_])?$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern TELEPHONE_PATTERN = Pattern.compile("^\\+?[0-9]{1,3}-?[0-9]{3}-?[0-9]{3}-?[0-9]{4}$");
    private static final Pattern DATE_PATTERN = Pattern.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}$");

    private Validate()
    {
    }

    /**
     * Returns whether a domain is valid: lower case, at most {@value #MAX_DOMAIN_LENGTH} characters, at least two
     * labels of letters, digits and inner dashes.
     *
     * @param domain The domain, may be null.
     * @return True if valid.
     */
    public static boolean domain(String domain)
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
            if(!DOMAIN_LABEL_PATTERN.matcher(label).matches())
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns whether a host name of a DNS record is valid: letters, digits, dots and dashes, starting and ending with
     * a letter or digit. Unlike {@link #domain(String)}, any case and single labels are accepted.
     *
     * @param host The host, may be null.
     * @return True if valid.
     */
    public static boolean host(String host)
    {
        return host != null && HOST_PATTERN.matcher(host).matches();
    }

    /**
     * Returns whether a port number is valid.
     *
     * @param port The port.
     * @return True if valid.
     */
    public static boolean port(int port)
    {
        return port >= 1 && port <= 65535;
    }

    /**
     * Returns whether a username is valid: 1 to 32 lower case letters, digits, dots, dashes and underscores, starting
     * with a letter or digit, without consecutive dots.
     *
     * @param username The username, may be null.
     * @return True if valid.
     */
    public static boolean username(String username)
    {
        return username != null && USERNAME_PATTERN.matcher(username).matches() && !username.contains("..");
    }

    /**
     * Returns whether an email address is valid.
     *
     * @param emailAddress The email address, may be null.
     * @return True if valid.
     */
    public static boolean emailAddress(String emailAddress)
    {
        return emailAddress != null && emailAddress.length() <= MAX_EMAIL_LENGTH && EMAIL_PATTERN.matcher(emailAddress).matches();
    }

    /**
     * Returns whether a telephone number is valid.
     *
     * @param telephoneNumber The telephone number, may be null.
     * @return True if valid.
     */
    public static boolean telephoneNumber(String telephoneNumber)
    {
        return telephoneNumber != null && TELEPHONE_PATTERN.matcher(telephoneNumber).matches();
    }

    /**
     * Returns whether a value is an ISO date (yyyy-mm-dd) that is not in the future.
     *
     * @param date The date, may be null.
     * @return True if valid.
     */
    public static boolean pastDate(String date)
    {
        if(date == null || !DATE_PATTERN.matcher(date).matches())
        {
            return false;
        }

        try
        {
            return !LocalDate.parse(date).isAfter(LocalDate.now());
        }
        catch(DateTimeParseException e)
        {
            return false;
        }
    }

    /**
     * Returns whether a value is an absolute http or https URL with a host.
     *
     * @param url The URL, may be null.
     * @return True if valid.
     */
    public static boolean httpUrl(String url)
    {
        if(url == null)
        {
            return false;
        }

        try
        {
            URI uri = new URI(url);
            return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())) && uri.getHost() != null;
        }
        catch(Exception e)
        {
            return false;
        }
    }
}
