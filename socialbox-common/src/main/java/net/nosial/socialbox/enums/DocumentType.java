package net.nosial.socialbox.enums;

import net.nosial.socialbox.interfaces.NamedEnumInterface;

public enum DocumentType implements NamedEnumInterface
{
    /**
     * The terms of service.
     */
    TERMS_OF_SERVICE("Terms of Service", "terms_of_service.html"),

    /**
     * The privacy policy.
     */
    PRIVACY_POLICY("Privacy Policy", "privacy_policy.html"),

    /**
     * The community guidelines.
     */
    COMMUNITY_GUIDELINES("Community Guidelines", "community_guidelines.html");

    private final String title;
    private final String resource;

    DocumentType(String title, String resource)
    {
        this.title = title;
        this.resource = resource;
    }

    /**
     * Returns the human readable title.
     *
     * @return The title.
     */
    public String getTitle()
    {
        return this.title;
    }

    /**
     * Returns the file name of the bundled default document.
     *
     * @return The resource file name.
     */
    public String getResource()
    {
        return this.resource;
    }
}
