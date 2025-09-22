import java.util.Arrays;

public class Salsa20 {

    private static final int[] SIGMA = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    private static int rotateLeft(int value, int bits) {
        return (value << bits) | (value >>> (32 - bits));
    }

    private static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[b] ^= rotateLeft(x[a] + x[d], 7);
        x[c] ^= rotateLeft(x[b] + x[a], 9);
        x[d] ^= rotateLeft(x[c] + x[b], 13);
        x[a] ^= rotateLeft(x[d] + x[c], 18);
    }

    private static int toIntLE(byte[] b, int offset) {
        return (b[offset] & 0xFF)
                | ((b[offset + 1] & 0xFF) << 8)
                | ((b[offset + 2] & 0xFF) << 16)
                | ((b[offset + 3] & 0xFF) << 24);
    }

    private static void intToBytesLE(int val, byte[] b, int offset) {
        b[offset] = (byte) (val & 0xFF);
        b[offset + 1] = (byte) ((val >>> 8) & 0xFF);
        b[offset + 2] = (byte) ((val >>> 16) & 0xFF);
        b[offset + 3] = (byte) ((val >>> 24) & 0xFF);
    }

    public static byte[] salsa20Block(byte[] key, byte[] nonce, long counter) {
        if (key.length != 32) throw new IllegalArgumentException("Key must be 32 bytes");
        if (nonce.length != 8) throw new IllegalArgumentException("Nonce must be 8 bytes");

        int[] state = new int[16];

        state[0] = SIGMA[0];
        state[1] = toIntLE(key, 0);
        state[2] = toIntLE(key, 4);
        state[3] = toIntLE(key, 8);
        state[4] = toIntLE(key, 12);
        state[5] = SIGMA[1];
        state[6] = toIntLE(nonce, 0);
        state[7] = toIntLE(nonce, 4);
        state[8] = (int) (counter & 0xFFFFFFFFL);
        state[9] = (int) ((counter >>> 32) & 0xFFFFFFFFL);
        state[10] = SIGMA[2];
        state[11] = toIntLE(key, 16);
        state[12] = toIntLE(key, 20);
        state[13] = toIntLE(key, 24);
        state[14] = toIntLE(key, 28);
        state[15] = SIGMA[3];

        int[] workingState = Arrays.copyOf(state, 16);

        for (int i = 0; i < 10; i++) {
            quarterRound(workingState, 0, 4, 8, 12);
            quarterRound(workingState, 5, 9, 13, 1);
            quarterRound(workingState, 10, 14, 2, 6);
            quarterRound(workingState, 15, 3, 7, 11);
            quarterRound(workingState, 0, 1, 2, 3);
            quarterRound(workingState, 5, 6, 7, 4);
            quarterRound(workingState, 10, 11, 8, 9);
            quarterRound(workingState, 15, 12, 13, 14);
        }

        byte[] output = new byte[64];
        for (int i = 0; i < 16; i++) {
            intToBytesLE(workingState[i] + state[i], output, i * 4);
        }

        return output;
    }

    private static String toHexString(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(String.format("%02x", data[i]));
            if ((i + 1) % 16 == 0) sb.append("\n");
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte) i;

        byte[] nonce = new byte[8];
        for (int i = 0; i < 8; i++) nonce[i] = (byte) i;

        long counter = 0L;

        byte[] block = salsa20Block(key, nonce, counter);

        String expectedHex =
                "2ead0f5f185729ced672b3a928e454f7" +
                        "2fdb44a87b9cd8d219e4ec14aef9c6bc" +
                        "77bf057f5659d7753848f8d3fe769ca5" +
                        "fdd8057d46326990e5f136e2fcb7bb7c";

        byte[] expected = hexStringToByteArray(expectedHex);

        System.out.println("Computed Salsa20 keystream block 0:");
        System.out.print(toHexString(block));

        System.out.println("Expected Salsa20 keystream block 0:");
        System.out.print(toHexString(expected));

        System.out.println("Match? " + Arrays.equals(block, expected));
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}