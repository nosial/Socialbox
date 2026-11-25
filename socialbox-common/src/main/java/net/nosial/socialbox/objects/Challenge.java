package net.nosial.socialbox.objects;

import net.nosial.socialbox.enums.SessionFlag;

import java.util.Map;

public record Challenge(SessionFlag flag, String method, Map<String, Object> parameters, boolean optional, ChallengeInput input)
{
}
