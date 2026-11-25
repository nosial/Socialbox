package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.InputType;

public record ChallengeInput(InputType type, String parameter, String label, String description, Integer length,
                             String contentType, String url)
{
}
