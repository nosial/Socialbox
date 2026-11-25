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
    URL(PrivacyState.PUBLIC);

    /**
     * The maximum length of any information field value.
     */
    public static final int MAX_VALUE_LENGTH = 2048;


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
     * @return The registration flag.
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
        };
    }
}
