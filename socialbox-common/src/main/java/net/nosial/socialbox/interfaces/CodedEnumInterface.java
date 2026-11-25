package net.nosial.socialbox.interfaces;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public interface CodedEnumInterface
{
    /**
     * Returns the protocol code.
     *
     * @return The code.
     */
    int getCode();

    /**
     * Returns the constant of an enum with a protocol code.
     *
     * @param type The enum type.
     * @param code The protocol code.
     * @param <E> The enum type.
     * @return The constant, the enum's default constant if the code is unknown, or null.
     */
    @SuppressWarnings("unchecked")
    static <E extends Enum<E> & CodedEnumInterface> E fromCode(Class<E> type, int code)
    {
        E constant = (E) Index.CODES.get(type).get(code);
        return constant == null ? NamedEnumInterface.getDefault(type) : constant;
    }

    /**
     * The cached code indexes of the enum types.
     */
    final class Index
    {
        private static final ClassValue<Map<Integer, Object>> CODES = new ClassValue<>()
        {
            @Override
            protected Map<Integer, Object> computeValue(Class<?> type)
            {
                return Arrays.stream(type.getEnumConstants()).collect(Collectors.toUnmodifiableMap(constant -> ((CodedEnumInterface) constant).getCode(),
                        Function.identity()));
            }
        };

        private Index()
        {
        }
    }
}
