import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CurseOfHex {
    public static void main(String[] args) {
        String cipher = "0305A1B2460000006F9F37A7AED6264E173E9E6E266E770EF6374EA6F6D726BEF6DF96561F06766E26E6F6CF4EBEF63776EE9EB677A6F66F4EBEF6379E5E8E8EF6DF96367FEEB66E7716266EE6960DE5";
        String plain = new CurseOfHex().breakCurseOfHex(cipher);
        System.out.println(plain);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private String breakCurseOfHex(String input) {
        byte[] bytes = hexStringToByteArray(input);
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

        List<Byte> decoded = new ArrayList<>();
        while(buffer.remaining() >= 4) {
            int encodedVal = buffer.getInt();
            encodedVal = rightRot ?
                    Integer.rotateLeft(encodedVal, rotation)
                    : Integer.rotateRight(encodedVal, rotation);

            int decodedVal = encodedVal ^ M32;
            ByteBuffer decodedBuffer = ByteBuffer
                    .allocate(4)
                    .order(LE ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
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

        byte[] actualPayload = Arrays.copyOf(decodedArray, length);
        return new String(actualPayload, StandardCharsets.US_ASCII);
    }
}
