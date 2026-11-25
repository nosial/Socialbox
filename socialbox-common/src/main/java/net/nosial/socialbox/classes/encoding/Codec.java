package net.nosial.socialbox.classes.encoding;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.deser.std.StringDeserializer;
import com.fasterxml.jackson.databind.module.SimpleDeserializers;
import com.fasterxml.jackson.databind.module.SimpleModule;
import net.nosial.socialbox.enums.Encoding;
import net.nosial.socialbox.enums.ProtocolLimit;
import net.nosial.socialbox.exceptions.ProtocolException;
import net.nosial.socialbox.interfaces.CodedEnumInterface;
import net.nosial.socialbox.interfaces.NamedEnumInterface;
import org.msgpack.jackson.dataformat.MessagePackFactory;
import org.msgpack.jackson.dataformat.MessagePackGenerator;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

public final class Codec
{
    private static final ObjectMapper JSON_MAPPER = configure(new ObjectMapper(constrain(new JsonFactory())))
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final ObjectMapper MSGPACK_MAPPER = configure(new ObjectMapper(constrain(new MessagePackFactory())));

    private Codec()
    {
    }

    /**
     * Returns the object mapper of an encoding.
     *
     * @param encoding The encoding.
     * @return The object mapper.
     */
    public static ObjectMapper getMapper(Encoding encoding)
    {
        return encoding == Encoding.MSGPACK ? MSGPACK_MAPPER : JSON_MAPPER;
    }

    /**
     * Encodes a value.
     *
     * @param encoding The encoding.
     * @param value The value.
     * @return The encoded bytes.
     * @throws ProtocolException If the value cannot be encoded.
     */
    public static byte[] encode(Encoding encoding, Object value)
    {
        try
        {
            return getMapper(encoding).writeValueAsBytes(value);
        }
        catch(IOException | RuntimeException e)
        {
            throw new ProtocolException("Failed to encode value", e);
        }
    }

    /**
     * Decodes a value.
     *
     * @param encoding The encoding.
     * @param data The encoded bytes.
     * @param type The target type.
     * @param <T> The target type.
     * @return The decoded value.
     * @throws ProtocolException If the data cannot be decoded.
     */
    public static <T> T decode(Encoding encoding, byte[] data, Class<T> type)
    {
        try
        {
            validate(encoding, data);
            return getMapper(encoding).readValue(data, type);
        }
        catch(ProtocolException e)
        {
            throw e;
        }
        catch(IOException | RuntimeException e)
        {
            throw new ProtocolException("Failed to decode " + type.getSimpleName(), e);
        }
    }

    /**
     * Decodes a value of a generic type.
     *
     * @param encoding The encoding.
     * @param data The encoded bytes.
     * @param type The target type.
     * @param <T> The target type.
     * @return The decoded value.
     * @throws ProtocolException If the data cannot be decoded.
     */
    public static <T> T decode(Encoding encoding, byte[] data, TypeReference<T> type)
    {
        try
        {
            validate(encoding, data);
            return getMapper(encoding).readValue(data, type);
        }
        catch(ProtocolException e)
        {
            throw e;
        }
        catch(IOException | RuntimeException e)
        {
            throw new ProtocolException("Failed to decode value", e);
        }
    }

    /**
     * Converts a decoded value (maps, lists, strings, numbers) to a typed value.
     *
     * @param value The value.
     * @param type The target type.
     * @param <T> The target type.
     * @return The converted value.
     * @throws IllegalArgumentException If the value cannot be converted.
     */
    public static <T> T convert(Object value, Class<T> type)
    {
        return JSON_MAPPER.convertValue(value, type);
    }

    /**
     * Converts a decoded value to a typed value of a generic type.
     *
     * @param value The value.
     * @param type The target type.
     * @param <T> The target type.
     * @return The converted value.
     * @throws IllegalArgumentException If the value cannot be converted.
     */
    public static <T> T convert(Object value, TypeReference<T> type)
    {
        return JSON_MAPPER.convertValue(value, type);
    }

    /**
     * Converts a decoded value to a reflected type.
     *
     * @param value The value.
     * @param type The target type.
     * @return The converted value.
     * @throws IllegalArgumentException If the value cannot be converted.
     */
    public static Object convert(Object value, Type type)
    {
        JavaType javaType = JSON_MAPPER.getTypeFactory().constructType(type);
        return JSON_MAPPER.convertValue(value, javaType);
    }

    /**
     * Converts a typed value to its plain representation: maps, lists, strings, numbers, booleans, null and byte
     * arrays for binary values. The plain value encodes to the same bytes as the typed value in either encoding.
     *
     * @param value The value.
     * @return The plain value.
     */
    public static Object toPlain(Object value)
    {
        return JSON_MAPPER.convertValue(value, Object.class);
    }

    /**
     * Converts a typed value to a map.
     *
     * @param value The value.
     * @return The map.
     */
    public static Map<String, Object> toMap(Object value)
    {
        return JSON_MAPPER.convertValue(value, new TypeReference<>() {});
    }

    /**
     * Validates data before decoding. MessagePack is checked by {@link MsgpackValidator}; JSON is constrained by the
     * parser settings of {@link #constrain(JsonFactory)}.
     *
     * @param encoding The encoding.
     * @param data The data.
     */
    private static void validate(Encoding encoding, byte[] data)
    {
        if(data == null)
        {
            throw new ProtocolException("No data to decode");
        }

        if(encoding == Encoding.MSGPACK)
        {
            MsgpackValidator.validate(data);
        }
    }

    /**
     * Applies the protocol's parser limits to a factory: nesting depth, string length, number of tokens, duplicate keys.
     *
     * @param factory The factory.
     * @param <F> The factory type.
     * @return The same factory.
     */
    private static <F extends JsonFactory> F constrain(F factory)
    {
        factory.setStreamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(MsgpackValidator.MAX_DEPTH)
                .maxStringLength((int) (4 * ProtocolLimit.MAX_FRAME_SIZE.getMaximum()))
                .maxTokenCount(2L * MsgpackValidator.MAX_ELEMENTS)
                .build());
        factory.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        return factory;
    }

    /**
     * Applies the protocol's settings to a mapper.
     *
     * @param mapper The mapper.
     * @return The same mapper.
     */
    private static ObjectMapper configure(ObjectMapper mapper)
    {
        EnumDeserializers deserializers = new EnumDeserializers();
        deserializers.addDeserializer(byte[].class, new Base64UrlDeserializer());
        deserializers.addDeserializer(String.class, new StrictStringDeserializer());

        SimpleModule module = new SimpleModule("socialbox");
        module.addSerializer(byte[].class, new Base64UrlSerializer());
        module.addSerializer(NamedEnumInterface.class, new NamedEnumSerializer());
        module.addSerializer(CodedEnumInterface.class, new CodedEnumSerializer());
        module.setDeserializers(deserializers);

        mapper.registerModule(module);
        // Objects are records: only their components are properties, never helper methods such as isWellFormed()
        mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker()
                .withFieldVisibility(JsonAutoDetect.Visibility.ANY)
                .withGetterVisibility(JsonAutoDetect.Visibility.NONE)
                .withIsGetterVisibility(JsonAutoDetect.Visibility.NONE)
                .withSetterVisibility(JsonAutoDetect.Visibility.NONE));
        mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        mapper.setDefaultPropertyInclusion(JsonInclude.Include.NON_NULL);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false);
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        return mapper;
    }

    /**
     * Writes byte arrays as MessagePack binary values, as base64url strings in JSON, and as raw byte arrays when
     * converting to plain values.
     */
    private static final class Base64UrlSerializer extends JsonSerializer<byte[]>
    {
        @Override
        public void serialize(byte[] value, JsonGenerator generator, SerializerProvider provider) throws IOException
        {
            if(generator instanceof MessagePackGenerator || generator.canWriteBinaryNatively())
            {
                generator.writeBinary(value);
                return;
            }

            generator.writeString(Base64Url.encode(value));
        }
    }

    /**
     * Reads strings, refusing binary values: a binary value where the protocol expects text is a client error, not
     * something to re-encode silently.
     */
    private static final class StrictStringDeserializer extends JsonDeserializer<String>
    {
        @Override
        public String deserialize(JsonParser parser, DeserializationContext context) throws IOException
        {
            if(parser.currentToken() == JsonToken.VALUE_EMBEDDED_OBJECT)
            {
                return (String) context.handleUnexpectedToken(String.class, parser);
            }

            return StringDeserializer.instance.deserialize(parser, context);
        }
    }

    /**
     * Reads byte arrays from base64url strings (JSON) or binary values (MessagePack, plain values).
     */
    private static final class Base64UrlDeserializer extends JsonDeserializer<byte[]>
    {
        @Override
        public byte[] deserialize(JsonParser parser, DeserializationContext context) throws IOException
        {
            if(parser.currentToken() == JsonToken.VALUE_STRING)
            {
                try
                {
                    return Base64Url.decode(parser.getText());
                }
                catch(IllegalArgumentException e)
                {
                    throw context.weirdStringException(parser.getText(), byte[].class, "Not valid base64url");
                }
            }

            if(parser.currentToken() == JsonToken.VALUE_EMBEDDED_OBJECT)
            {
                return parser.getBinaryValue();
            }

            return (byte[]) context.handleUnexpectedToken(byte[].class, parser);
        }
    }

    /**
     * Writes enums by their protocol name.
     */
    private static final class NamedEnumSerializer extends JsonSerializer<NamedEnumInterface>
    {
        @Override
        public void serialize(NamedEnumInterface value, JsonGenerator generator, SerializerProvider provider) throws IOException
        {
            generator.writeString(value.getName());
        }
    }

    /**
     * Writes enums by their protocol code.
     */
    private static final class CodedEnumSerializer extends JsonSerializer<CodedEnumInterface>
    {
        @Override
        public void serialize(CodedEnumInterface value, JsonGenerator generator, SerializerProvider provider) throws IOException
        {
            generator.writeNumber(value.getCode());
        }
    }

    /**
     * Finds the deserializers of named and coded enums, besides the simple deserializers registered on it.
     */
    private static final class EnumDeserializers extends SimpleDeserializers
    {
        @Override
        public JsonDeserializer<?> findEnumDeserializer(Class<?> type, DeserializationConfig config, BeanDescription description) throws JsonMappingException
        {
            if(NamedEnumInterface.class.isAssignableFrom(type))
            {
                return new NamedEnumDeserializer(type);
            }

            if(CodedEnumInterface.class.isAssignableFrom(type))
            {
                return new CodedEnumDeserializer(type);
            }

            return super.findEnumDeserializer(type, config, description);
        }
    }

    /**
     * Reads enums by their protocol name. Only strings are accepted, and an unknown name fails unless the enum has a
     * default constant.
     */
    private static final class NamedEnumDeserializer extends JsonDeserializer<Object>
    {
        private final Class<?> type;

        private NamedEnumDeserializer(Class<?> type)
        {
            this.type = type;
        }

        @Override
        @SuppressWarnings({"unchecked", "rawtypes"})
        public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException
        {
            if(parser.currentToken() != JsonToken.VALUE_STRING)
            {
                return context.handleUnexpectedToken(this.type, parser);
            }

            String name = parser.getText();
            Object constant = NamedEnumInterface.fromName((Class) this.type, name);
            return constant != null ? constant : context.handleWeirdStringValue(this.type, name, "Unknown %s", this.type.getSimpleName());
        }
    }

    /**
     * Reads enums by their protocol code. Only integers are accepted, and an unknown code fails unless the enum has a
     * default constant.
     */
    private static final class CodedEnumDeserializer extends JsonDeserializer<Object>
    {
        private final Class<?> type;

        private CodedEnumDeserializer(Class<?> type)
        {
            this.type = type;
        }

        @Override
        @SuppressWarnings({"unchecked", "rawtypes"})
        public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException
        {
            if(parser.currentToken() != JsonToken.VALUE_NUMBER_INT)
            {
                return context.handleUnexpectedToken(this.type, parser);
            }

            int code = parser.getIntValue();
            Object constant = CodedEnumInterface.fromCode((Class) this.type, code);
            return constant != null ? constant : context.handleWeirdNumberValue(this.type, code, "Unknown %s", this.type.getSimpleName());
        }
    }
}
