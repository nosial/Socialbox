package net.nosial.socialbox.classes.protocol;

import net.nosial.socialbox.enums.ProtocolLimit;
import net.nosial.socialbox.enums.FrameType;
import net.nosial.socialbox.exceptions.ProtocolException;
import net.nosial.socialbox.interfaces.CodedEnumInterface;

import java.util.Arrays;

public final class Frames
{
    private static final int MAX_PAYLOAD = (int) ProtocolLimit.MAX_FRAME_SIZE.getMaximum();

    private Frames()
    {
    }

    /**
     * Builds a frame.
     *
     * @param type The frame type.
     * @param payload The payload, may be null.
     * @return The frame bytes.
     * @throws ProtocolException If the payload exceeds the protocol's largest {@code max_frame_size}; each side
     *                            enforces its own, smaller limit when it reads.
     */
    public static byte[] build(FrameType type, byte[] payload)
    {
        byte[] data = payload == null ? new byte[0] : payload;
        if(data.length > MAX_PAYLOAD)
        {
            throw new ProtocolException("The frame payload is too large");
        }

        byte[] frame = new byte[data.length + 1];
        frame[0] = (byte) type.getCode();
        System.arraycopy(data, 0, frame, 1, data.length);
        return frame;
    }

    /**
     * Returns the payload of a frame.
     *
     * @param frame The frame bytes.
     * @return The payload.
     */
    public static byte[] payload(byte[] frame)
    {
        return Arrays.copyOfRange(frame, 1, frame.length);
    }

    /**
     * Returns the type of a frame.
     *
     * @param frame The frame bytes.
     * @return The frame type.
     * @throws ProtocolException If the frame is empty, too large or of an unknown type.
     */
    public static FrameType type(byte[] frame)
    {
        if(frame == null || frame.length == 0 || frame.length > MAX_PAYLOAD + 1)
        {
            throw new ProtocolException("Invalid frame size");
        }

        FrameType type = CodedEnumInterface.fromCode(FrameType.class, frame[0] & 0xFF);
        if(type == null)
        {
            throw new ProtocolException(String.format("Unknown frame type 0x%02x", frame[0] & 0xFF));
        }

        return type;
    }
}
