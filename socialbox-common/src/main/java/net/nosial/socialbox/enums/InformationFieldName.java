package net.nosial.socialbox.enums;

import net.nosial.socialbox.classes.Validate;
import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum InformationFieldName implements NamedEnumInterface
{
    /**
     * The name shown to other peers, 3 to 50 characters.
     */
    DISPLAY_NAME(PrivacyState.PUBLIC),

    /**
     * A URL of the profile picture.
     */
    DISPLAY_PICTURE(PrivacyState.PUBLIC),

    /**
     * The first name, 2 to 50 characters.
     */
    FIRST_NAME(PrivacyState.PRIVATE),

    /**
     * The middle name, 2 to 50 characters.
     */
    MIDDLE_NAME(PrivacyState.PRIVATE),

    /**
     * The last name, 2 to 50 characters.
     */
    LAST_NAME(PrivacyState.PRIVATE),

    /**
     * An email address.
     */
    EMAIL_ADDRESS(PrivacyState.PRIVATE),

    /**
     * A phone number.
     */
    PHONE_NUMBER(PrivacyState.PRIVATE),

    /**
     * A birthday as YYYY-MM-DD.
     */
    BIRTHDAY(PrivacyState.PRIVATE),

    /**
     * A website URL.
     */
    URL(PrivacyState.PUBLIC),

    /**
     * The presence the user shows, one of {@link PresenceStatus} by name ({@code ONLINE}, {@code OFFLINE}, {@code AWAY},
     * {@code BUSY}). Set by the user's clients; the server only checks the value.
     */
    STATUS(PrivacyState.PUBLIC),

    /**
     * When the user was last seen, in milliseconds since the epoch, as the user's clients choose to publish it; never
     * in the future (beyond the clock skew).
     */
    LAST_SEEN(PrivacyState.PRIVATE),

    /**
     * The user's accent color, one of {@link AccentColor} by name.
     */
    ACCENT_COLOR(PrivacyState.PUBLIC);

    /**
     * The maximum length of any information field value.
     */
    public static final int MAX_VALUE_LENGTH = 8192;


    private final PrivacyState defaultPrivacy;

    InformationFieldName(PrivacyState defaultPrivacy)
    {
        this.defaultPrivacy = defaultPrivacy;
    }

    /**
     * Returns the privacy applied when the user does not choose one.
     *
     * @return The default privacy.
     */
    public PrivacyState getDefaultPrivacy()
    {
        return this.defaultPrivacy;
    }

    /**
     * Returns the session flag that requires this field to be set during registration.
     *
     * @return The registration flag, null for fields registration never requires.
     */
    public SessionFlag getRegistrationFlag()
    {
        return switch(this)
        {
            case DISPLAY_NAME -> SessionFlag.SET_DISPLAY_NAME;
            case DISPLAY_PICTURE -> SessionFlag.SET_DISPLAY_PICTURE;
            case FIRST_NAME -> SessionFlag.SET_FIRST_NAME;
            case MIDDLE_NAME -> SessionFlag.SET_MIDDLE_NAME;
            case LAST_NAME -> SessionFlag.SET_LAST_NAME;
            case EMAIL_ADDRESS -> SessionFlag.SET_EMAIL;
            case PHONE_NUMBER -> SessionFlag.SET_PHONE;
            case BIRTHDAY -> SessionFlag.SET_BIRTHDAY;
            case URL -> SessionFlag.SET_URL;
            case STATUS, LAST_SEEN, ACCENT_COLOR -> null;
        };
    }

    /**
     * Validates a value for this field.
     *
     * @param value The value to validate.
     * @return True if the value is valid.
     */
    public boolean validate(String value)
    {
        if(value == null || value.isBlank() || value.length() > MAX_VALUE_LENGTH)
        {
            return false;
        }

        return switch(this)
        {
            case DISPLAY_NAME -> value.length() >= 3 && value.length() <= 50;
            case FIRST_NAME, MIDDLE_NAME, LAST_NAME -> value.length() >= 2 && value.length() <= 50;
            case EMAIL_ADDRESS -> Validate.emailAddress(value);
            case PHONE_NUMBER -> Validate.telephoneNumber(value);
            case BIRTHDAY -> Validate.pastDate(value);
            case URL, DISPLAY_PICTURE -> Validate.httpUrl(value);
            case STATUS -> NamedEnumInterface.isName(PresenceStatus.class, value);
            case ACCENT_COLOR -> NamedEnumInterface.isName(AccentColor.class, value);
            case LAST_SEEN -> isPastTimestamp(value);
        };
    }

    /**
     * Returns whether a value is a time in milliseconds since the epoch, not in the future beyond the default clock
     * skew.
     */
    private static boolean isPastTimestamp(String value)
    {
        if(value.length() > 15 || !value.chars().allMatch(Character::isDigit))
        {
            return false;
        }

        long time = Long.parseLong(value);
        return time <= System.currentTimeMillis() + ProtocolLimit.MAX_CLOCK_SKEW.getDefault();
    }
}
