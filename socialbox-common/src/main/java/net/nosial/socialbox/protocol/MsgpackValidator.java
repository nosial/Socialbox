package net.nosial.socialbox.protocol;

import net.nosial.socialbox.exceptions.ProtocolException;
import org.msgpack.core.MessageFormat;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePackException;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.ValueType;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

public final class MsgpackValidator
{
    public static final int MAX_DEPTH = 32;
    private static final BigInteger MAX_INTEGER = BigInteger.valueOf(Long.MAX_VALUE);

    /**
     * Validates MessagePack data.
     *
     * @param data The data.
     * @throws ProtocolException If the data breaks one of the rules.
     */
    public static void validate(byte[] data)
    {
        try(MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data))
        {
            if(!unpacker.hasNext())
            {
                throw new ProtocolException("Empty MessagePack value");
            }

            value(unpacker, data.length, 0);
            if(unpacker.hasNext())
            {
                throw new ProtocolException("Trailing bytes after the MessagePack value");
            }
        }
        catch(IOException | MessagePackException e)
        {
            throw new ProtocolException("Malformed MessagePack value", e);
        }
    }

    /**
     * Validates one value.
     *
     * @param unpacker The unpacker.
     * @param size The size of the data.
     * @param depth The nesting depth of the value.
     * @throws IOException If reading fails.
     */
    private static void value(MessageUnpacker unpacker, int size, int depth) throws IOException
    {
        MessageFormat format = unpacker.getNextFormat();
        switch(format.getValueType())
        {
            case NIL, BOOLEAN, FLOAT -> unpacker.skipValue();
            case INTEGER ->
            {
                if(format != MessageFormat.UINT64)
                {
                    unpacker.skipValue();
                }
                else if(unpacker.unpackBigInteger().compareTo(MAX_INTEGER) > 0)
                {
                    throw new ProtocolException("Integer out of range");
                }
            }
            case STRING -> string(unpacker, size);
            case BINARY ->
            {
                int length = unpacker.unpackBinaryHeader();
                requireAvailable(unpacker, size, length);
                unpacker.readPayload(length);
            }
            case ARRAY ->
            {
                int count = unpacker.unpackArrayHeader();
                requireAvailable(unpacker, size, count);
                requireDepth(depth + 1);
                for(int i = 0; i < count; i++)
                {
                    value(unpacker, size, depth + 1);
                }
            }
            case MAP ->
            {
                int count = unpacker.unpackMapHeader();
                requireAvailable(unpacker, size, (long) count * 2);
                requireDepth(depth + 1);
                Set<String> keys = new HashSet<>();
                for(int i = 0; i < count; i++)
                {
                    if(unpacker.getNextFormat().getValueType() != ValueType.STRING)
                    {
                        throw new ProtocolException("Map keys must be strings");
                    }

                    if(!keys.add(string(unpacker, size)))
                    {
                        throw new ProtocolException("Duplicate map key");
                    }

                    value(unpacker, size, depth + 1);
                }
            }
            case EXTENSION -> throw new ProtocolException("MessagePack extension types are not allowed");
        }
    }

    /**
     * Reads and validates a string.
     *
     * @param unpacker The unpacker.
     * @param size The size of the data.
     * @return The string.
     * @throws IOException If reading fails.
     */
    private static String string(MessageUnpacker unpacker, int size) throws IOException
    {
        int length = unpacker.unpackRawStringHeader();
        requireAvailable(unpacker, size, length);
        byte[] bytes = unpacker.readPayload(length);
        try
        {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        }
        catch(CharacterCodingException e)
        {
            throw new ProtocolException("Strings must be valid UTF-8");
        }
    }

    /**
     * Rejects a length header claiming more bytes (or, for arrays and maps, more entries) than remain.
     *
     * @param unpacker The unpacker.
     * @param size The size of the data.
     * @param length The claimed length.
     */
    private static void requireAvailable(MessageUnpacker unpacker, int size, long length)
    {
        if(length < 0 || length > size - unpacker.getTotalReadBytes())
        {
            throw new ProtocolException("MessagePack length exceeds the data");
        }
    }

    /**
     * Rejects nesting deeper than {@value #MAX_DEPTH}.
     *
     * @param depth The depth.
     */
    private static void requireDepth(int depth)
    {
        if(depth > MAX_DEPTH)
        {
            throw new ProtocolException("MessagePack value nested too deeply");
        }
    }
}