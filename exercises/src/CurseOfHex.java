import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/**
 * Group Members: Filippo De Grandi
 * Cool Name: okmel'erodimenticato
 */
public class CurseOfHex {

    public record DecodedData(
            boolean LE,
            boolean rightRot,
            int rotAmount,
            int M32,
            int length,
            List<Integer> encodedValues
    ) {}

    public static DecodedData parseHeader(String hexString) {
        HexFormat hex = HexFormat.of();
        hex.parseHex(hexString);
        byte[] bytes = hex.parseHex(hexString);

        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        byte flags = buffer.get();
        boolean LE = (flags & 0x01) != 0;
        boolean rightRot = (flags & 0x02) != 0;

        int rotation = buffer.get() & 0xFF;

        buffer.order(ByteOrder.BIG_ENDIAN);
        short M16 = buffer.getShort();
        int M32 = ((M16 & 0xFFFF) << 16) | (M16 & 0xFFFF);

        if (LE) {
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
        int length = buffer.getInt();

        List<Integer> encodedValues = new ArrayList<>();
        while(buffer.remaining() >= 4) {
            encodedValues.add(buffer.getInt());
        }

        return new DecodedData(LE, rightRot, rotation, M32, length, encodedValues);
    }

    // P = (rotate -1 (E.toUInt(bit0), rotation_direction, rotation_amount) ^ M32).toBytes(bit0)
    public static String breakCurseOfHex(String input) {
        DecodedData data = parseHeader(input);
        List<Byte> decoded = new ArrayList<>();
        ByteOrder byteOrder = data.LE ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;

        for (int encodedVal : data.encodedValues) {
            int decodedVal = data.rightRot ?
                    Integer.rotateLeft(encodedVal, data.rotAmount)
                    : Integer.rotateRight(encodedVal, data.rotAmount);
            decodedVal ^= data.M32;

            ByteBuffer decodedBuffer = ByteBuffer
                    .allocate(4)
                    .order(byteOrder);
            decodedBuffer.putInt(decodedVal);

            decodedBuffer.flip();
            while (decodedBuffer.hasRemaining()) {
                decoded.add(decodedBuffer.get());
            }
        }

        byte[] decodedArray = new byte[decoded.size()];
        for (int i = 0; i < decoded.size(); i++) {
            decodedArray[i] = decoded.get(i);
        }

        byte[] actualPayload = Arrays.copyOf(decodedArray, data.length);
        return new String(actualPayload, StandardCharsets.US_ASCII);
    }

    public static void main(String[] args) {
        String cipher = "0305A1B2460000006F9F37A7AED6264E173E9E6E266E770EF6374EA6F6D726BEF6DF96561F06766E26E6F6CF4EBEF63776EE9EB677A6F66F4EBEF6379E5E8E8EF6DF96367FEEB66E7716266EE6960DE5";
        String plain = CurseOfHex.breakCurseOfHex(cipher);
        System.out.println(plain);
    }
}
