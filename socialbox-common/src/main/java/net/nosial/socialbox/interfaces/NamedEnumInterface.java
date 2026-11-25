package net.nosial.socialbox.interfaces;

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public interface NamedEnumInterface
{
    /**
     * Returns the protocol name.
     *
     * @return The name.
     */
    default String getName()
    {
        return ((Enum<?>) this).name().toLowerCase(Locale.ROOT);
    }

    /**
     * Returns the constant of an enum with a protocol name.
     *
     * @param type The enum type.
     * @param name The protocol name, may be null.
     * @param <E> The enum type.
     * @return The constant, the enum's default constant if the name is unknown, or null.
     */
    @SuppressWarnings("unchecked")
    static <E extends Enum<E> & NamedEnumInterface> E fromName(Class<E> type, String name)
    {
        if(name == null)
        {
            return null;
        }

        E constant = (E) Index.NAMES.get(type).get(name);
        return constant == null ? getDefault(type) : constant;
    }

    /**
     * Returns the constant of an enum marked with {@link JsonEnumDefaultValue}, which stands in for unknown values.
     *
     * @param type The enum type.
     * @param <E> The enum type.
     * @return The default constant, or null if the enum has none.
     */
    @SuppressWarnings("unchecked")
    static <E extends Enum<E>> E getDefault(Class<E> type)
    {
        return (E) Index.DEFAULTS.get(type);
    }

    /**
     * The cached name indexes and default constants of the enum types.
     */
    final class Index
    {
        private static final ClassValue<Map<String, Object>> NAMES = new ClassValue<>()
        {
            @Override
            protected Map<String, Object> computeValue(Class<?> type)
            {
                return Arrays.stream(type.getEnumConstants()).collect(Collectors.toUnmodifiableMap(constant -> ((NamedEnumInterface) constant).getName(),
                        Function.identity()));
            }
        };

        private static final ClassValue<Object> DEFAULTS = new ClassValue<>()
        {
            @Override
            protected Object computeValue(Class<?> type)
            {
                for(Object constant : type.getEnumConstants())
                {
                    try
                    {
                        if(type.getField(((Enum<?>) constant).name()).isAnnotationPresent(JsonEnumDefaultValue.class))
                        {
                            return constant;
                        }
                    }
                    catch(NoSuchFieldException e)
                    {
                        throw new IllegalStateException(e);
                    }
                }

                return null;
            }
        };

        private Index()
        {
        }
    }
}
