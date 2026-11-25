package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum SessionFlag implements NamedEnumInterface
{
    /**
     * The session registers a new account and has registration steps left.
     */
    REGISTRATION_REQUIRED(Category.STATE, null, null, InputType.NONE, null, null, null),

    /**
     * The session signs in to an existing account and has second factor steps left.
     */
    AUTHENTICATION_REQUIRED(Category.STATE, null, null, InputType.NONE, null, null, null),

    /**
     * The session is rate limited.
     */
    RATE_LIMITED(Category.STATE, null, null, InputType.NONE, null, null, null),

    /**
     * Set a password, required in addition to the key when creating sessions.
     */
    SET_PASSWORD(Category.REGISTRATION, StandardMethods.SETTINGS_SET_PASSWORD, null, InputType.PASSWORD, "password",
            "Password", "Choose a password that is required in addition to your key when you sign in"),

    /**
     * Set up a one-time password app, required in addition to the key when creating sessions.
     */
    SET_OTP(Category.REGISTRATION, StandardMethods.SETTINGS_SET_OTP, null, InputType.NONE, null,
            "Authenticator app", "Set up an authenticator app that is required in addition to your key when you sign in"),

    /**
     * Set a display name.
     */
    SET_DISPLAY_NAME(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.DISPLAY_NAME,
            InputType.TEXT, "value", "Display name", "The name other people see"),

    /**
     * Set a display picture.
     */
    SET_DISPLAY_PICTURE(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.DISPLAY_PICTURE,
            InputType.TEXT, "value", "Display picture", "A URL of your profile picture"),

    /**
     * Set a first name.
     */
    SET_FIRST_NAME(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.FIRST_NAME,
            InputType.TEXT, "value", "First name", "Your first name"),

    /**
     * Set a middle name.
     */
    SET_MIDDLE_NAME(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.MIDDLE_NAME,
            InputType.TEXT, "value", "Middle name", "Your middle name"),

    /**
     * Set a last name.
     */
    SET_LAST_NAME(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.LAST_NAME,
            InputType.TEXT, "value", "Last name", "Your last name"),

    /**
     * Set an email address.
     */
    SET_EMAIL(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.EMAIL_ADDRESS,
            InputType.TEXT, "value", "Email address", "Your email address"),

    /**
     * Set a phone number.
     */
    SET_PHONE(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.PHONE_NUMBER,
            InputType.TEXT, "value", "Phone number", "Your phone number"),

    /**
     * Set a birthday.
     */
    SET_BIRTHDAY(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.BIRTHDAY,
            InputType.TEXT, "value", "Birthday", "Your birthday as YYYY-MM-DD"),

    /**
     * Set a website URL.
     */
    SET_URL(Category.REGISTRATION, StandardMethods.SETTINGS_ADD_INFORMATION_FIELD, InformationFieldName.URL,
            InputType.TEXT, "value", "Website", "A URL of your website"),

    /**
     * Accept the privacy policy (readable through getPrivacyPolicy).
     */
    VER_PRIVACY_POLICY(Category.REGISTRATION, StandardMethods.ACCEPT_PRIVACY_POLICY, null, InputType.NONE, null,
            "Privacy Policy", "Read and accept the privacy policy"),

    /**
     * Accept the terms of service (readable through getTermsOfService).
     */
    VER_TERMS_OF_SERVICE(Category.REGISTRATION, StandardMethods.ACCEPT_TERMS_OF_SERVICE, null, InputType.NONE, null,
            "Terms of Service", "Read and accept the terms of service"),

    /**
     * Accept the community guidelines (readable through getCommunityGuidelines).
     */
    VER_COMMUNITY_GUIDELINES(Category.REGISTRATION, StandardMethods.ACCEPT_COMMUNITY_GUIDELINES, null, InputType.NONE, null,
            "Community Guidelines", "Read and accept the community guidelines"),

    /**
     * Verify an email address (reserved, no standard implementation yet).
     */
    VER_EMAIL(Category.REGISTRATION, null, null, InputType.TEXT, "code", "Email verification",
            "Enter the code sent to your email address"),

    /**
     * Verify a phone number by SMS (reserved, no standard implementation yet).
     */
    VER_SMS(Category.REGISTRATION, null, null, InputType.TEXT, "code", "SMS verification",
            "Enter the code sent to your phone"),

    /**
     * Verify a phone number by call (reserved, no standard implementation yet).
     */
    VER_PHONE_CALL(Category.REGISTRATION, null, null, InputType.TEXT, "code", "Phone verification",
            "Enter the code you were told on the phone call"),

    /**
     * Solve an image captcha (reserved). A provider supplies an {@code image/png} URL to display next to the input.
     */
    VER_IMAGE_CAPTCHA(Category.REGISTRATION, null, null, InputType.TEXT, "answer", "Captcha",
            "Enter the text shown in the image"),

    /**
     * Solve a text captcha (reserved).
     */
    VER_TEXT_CAPTCHA(Category.REGISTRATION, null, null, InputType.TEXT, "answer", "Captcha",
            "Answer the question"),

    /**
     * Complete a verification on an external web page (reserved). A provider supplies a {@code text/html} URL that
     * the client opens in a browser.
     */
    VER_EXTERNAL_URL(Category.REGISTRATION, null, null, InputType.NONE, null, "External verification",
            "Complete the verification in your browser"),

    /**
     * Enter the account password (second factor).
     */
    VER_PASSWORD(Category.AUTHENTICATION, StandardMethods.VERIFICATION_PASSWORD_AUTHENTICATION, null, InputType.PASSWORD,
            "password", "Password", "Enter your account password"),

    /**
     * Enter a one-time password from the authenticator app (second factor).
     */
    VER_OTP(Category.AUTHENTICATION, StandardMethods.VERIFICATION_OTP_AUTHENTICATION, null, InputType.OTP, "code",
            "One-time password", "Enter the code from your authenticator app"),

    /**
     * The session's signing key is not in the account log yet. The client signs a {@code session_add} entry with the
     * account key and appends it once every other challenge is done; until then the session stays limited. Clients
     * without the account key cannot complete it.
     */
    LOG_SESSION(Category.AUTHENTICATION, StandardMethods.APPEND_ACCOUNT_LOG, null, InputType.NONE, "entries", "Add this session",
            "Sign this session into your account with your identity");

    private final Category category;
    private final StandardMethods method;
    private final InformationFieldName field;
    private final InputType inputType;
    private final String parameter;
    private final String label;
    private final String description;

    SessionFlag(Category category, StandardMethods method, InformationFieldName field, InputType inputType, String parameter,
                String label, String description)
    {
        this.category = category;
        this.method = method;
        this.field = field;
        this.inputType = inputType;
        this.parameter = parameter;
        this.label = label;
        this.description = description;
    }

    /**
     * Returns whether the flag is a registration step.
     *
     * @return True for registration steps.
     */
    public boolean isRegistrationFlag()
    {
        return this.category == Category.REGISTRATION;
    }

    /**
     * Returns whether the flag is a second factor step of an existing account.
     *
     * @return True for authentication steps.
     */
    public boolean isAuthenticationFlag()
    {
        return this.category == Category.AUTHENTICATION;
    }

    /**
     * Returns whether the flag is a step the client has to complete.
     *
     * @return True for registration and authentication steps.
     */
    public boolean isChallenge()
    {
        return this.category != Category.STATE;
    }

    /**
     * Returns the method that completes the step, or null for reserved steps without a standard method.
     *
     * @return The method or null.
     */
    public StandardMethods getMethod()
    {
        return this.method;
    }

    /**
     * Returns the information field the step sets, if any.
     *
     * @return The information field or null.
     */
    public InformationFieldName getField()
    {
        return this.field;
    }

    /**
     * Returns the kind of input the step expects.
     *
     * @return The input type.
     */
    public InputType getInputType()
    {
        return this.inputType;
    }

    /**
     * Returns the method parameter that receives the user's input, if any.
     *
     * @return The parameter name or null.
     */
    public String getParameter()
    {
        return this.parameter;
    }

    /**
     * Returns a short human readable label.
     *
     * @return The label or null.
     */
    public String getLabel()
    {
        return this.label;
    }

    /**
     * Returns a human readable description.
     *
     * @return The description or null.
     */
    public String getDescription()
    {
        return this.description;
    }

    /**
     * Categories of session flags.
     */
    private enum Category
    {
        STATE,
        REGISTRATION,
        AUTHENTICATION
    }
}
