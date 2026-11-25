package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.InformationFieldName;
import net.nosial.socialbox.enums.PrivacyState;

public record InformationField(InformationFieldName name, String value, PrivacyState privacy)
{
}
