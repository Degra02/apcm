import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Interface for a generic compression function used in the Merkle-Damgård construction.
 * A compression function takes a chaining value (previous hash state) and a message block,
 * and produces a new chaining value.
 *
 * The input and output byte arrays are assumed to be of a fixed size,
 * which should be consistent with the hash function's block size and output size.
 */
interface CompressionFunction {
    /**
     * Applies the compression function.
     *
     * @param chainingValue The current chaining value (previous hash state).
     * Its length must match the output size of the compression function.
     * @param messageBlock  A block of the message. Its length must match the block size.
     * @return The new chaining value after compression. Its length must match the output size.
     */
    byte[] compress(byte[] chainingValue, byte[] messageBlock);

    /**
     * Returns the block size of the compression function in bytes.
     * This is the size of the message block input.
     * @return The block size in bytes.
     */
    int getBlockSize();

    /**
     * Returns the output size of the compression function in bytes.
     * This is the size of the chaining value input and output.
     * @return The output size in bytes.
     */
    int getOutputSize();
}

/**
 * Implements the Merkle-Damgård construction for a cryptographic hash function.
 * This class abstracts the actual compression logic to a `CompressionFunction` interface,
 * allowing different compression functions to be plugged in.
 */
public class MerkleDamgardHash {

    private final CompressionFunction compressionFunction;
    private final byte[] initialHashValue; // IV (Initial Vector)

    /**
     * Constructs a MerkleDamgardHash instance.
     *
     * @param compressionFunction The underlying compression function to use.
     * @param initialHashValue    The initial vector (IV) for the hash computation.
     * Its length must match the compression function's output size.
     * @throws IllegalArgumentException If the initialHashValue's length does not match
     * the compression function's output size.
     */
    public MerkleDamgardHash(CompressionFunction compressionFunction, byte[] initialHashValue) {
        if (initialHashValue.length != compressionFunction.getOutputSize()) {
            throw new IllegalArgumentException("Initial hash value length must match compression function output size.");
        }
        this.compressionFunction = compressionFunction;
        // Create a defensive copy to prevent external modification
        this.initialHashValue = Arrays.copyOf(initialHashValue, initialHashValue.length);
    }

    /**
     * Hashes the input message using the Merkle-Damgård construction.
     *
     * @param message The input message as a byte array.
     * @return The final hash value as a byte array.
     */
    public byte[] hash(byte[] message) {
        // 1. Padding the message
        byte[] paddedMessage = padMessage(message);

        // 2. Initialize current hash state with IV
        byte[] currentHashState = Arrays.copyOf(initialHashValue, initialHashValue.length);

        // 3. Process message in blocks
        int blockSize = compressionFunction.getBlockSize();
        for (int i = 0; i < paddedMessage.length; i += blockSize) {
            byte[] messageBlock = Arrays.copyOfRange(paddedMessage, i, i + blockSize);
            // Apply the compression function
            currentHashState = compressionFunction.compress(currentHashState, messageBlock);
        }

        // 4. Return the final hash state
        return currentHashState;
    }

    /**
     * Pads the message according to the Merkle-Damgård padding scheme.
     * This involves appending a '1' bit, then '0' bits until the message length
     * is 64 bits less than a multiple of the block size, and finally appending
     * the original message length in bits as a 64-bit big-endian integer.
     *
     * @param message The original message bytes.
     * @return The padded message bytes.
     */
    private byte[] padMessage(byte[] message) {
        long originalBitLength = (long) message.length * 8; // Original message length in bits
        int blockSize = compressionFunction.getBlockSize(); // Block size in bytes

        // Calculate the number of bytes needed for padding
        // Append '1' bit (0x80 byte)
        // Then append '0' bits until the length is (N * blockSize) - 8 bytes (for 64-bit length field)
        // The total padded length must be a multiple of blockSize.

        // The padding rule for SHA-256 is:
        // 1. Append a '1' bit.
        // 2. Append '0' bits until the message length is 448 mod 512 bits (i.e., 64 bits short of a multiple of 512 bits).
        // 3. Append the original message length (in bits) as a 64-bit big-endian integer.

        // Convert message length to bits
        long messageBitLength = (long) message.length * 8;

        // Calculate the number of zero bits needed
        // The total length after padding (before the 64-bit length field) must be 448 mod 512.
        // This means (messageBitLength + 1 + k) % 512 = 448, where k is the number of zero bits.
        // Or, more simply, the length of the padded message (in bits), excluding the 64-bit length field,
        // must be a multiple of 512, minus 64 bits.
        int k = 0;
        // Find k such that (messageBitLength + 1 + k) % 512 == 448
        // Or, more practically, find the smallest number of bits to add (1 + k)
        // such that the total length is 448 mod 512.
        // The total length of the padded message (including the 64-bit length) must be a multiple of 512 bits (64 bytes).
        // The part before the 64-bit length must be 448 bits modulo 512 bits.

        // Calculate the number of bytes for padding:
        // message.length (original bytes) + 1 (for 0x80) + zeros + 8 (for length) must be a multiple of blockSize.
        int numBytesAfterMessageAndOne = message.length + 1;
        int remainingBytesToReach448BitBoundary = (blockSize - (numBytesAfterMessageAndOne % blockSize + 8) % blockSize) % blockSize;

        int paddedLengthBytes = numBytesAfterMessageAndOne + remainingBytesToReach448BitBoundary + 8;

        ByteBuffer buffer = ByteBuffer.allocate(paddedLengthBytes);
        buffer.put(message);
        buffer.put((byte) 0x80); // Append '1' bit (as 0x80 byte)

        // Fill with zeros
        for (int i = 0; i < remainingBytesToReach448BitBoundary; i++) {
            buffer.put((byte) 0x00);
        }

        // Append the original message length in bits (64-bit big-endian)
        buffer.putLong(originalBitLength);

        return buffer.array();
    }

    /**
     * Main method for demonstration.
     * Shows how to use the MerkleDamgardHash with a dummy compression function.
     */
    public static void main(String[] args) {
        // --- Using the Dummy Compression Function (for comparison) ---
        CompressionFunction dummyCompression = new CompressionFunction() {
            private final int BLOCK_SIZE = 64; // 64 bytes (512 bits)
            private final int OUTPUT_SIZE = 32; // 32 bytes (256 bits)

            @Override
            public byte[] compress(byte[] chainingValue, byte[] messageBlock) {
                byte[] newChainingValue = new byte[OUTPUT_SIZE];
                for (int i = 0; i < OUTPUT_SIZE; i++) {
                    newChainingValue[i] = (byte) (chainingValue[i] ^ messageBlock[i % BLOCK_SIZE]);
                }
                return newChainingValue;
            }

            @Override
            public int getBlockSize() {
                return BLOCK_SIZE;
            }

            @Override
            public int getOutputSize() {
                return OUTPUT_SIZE;
            }
        };

        byte[] dummyIv = new byte[dummyCompression.getOutputSize()];
        Arrays.fill(dummyIv, (byte) 0x01);
        MerkleDamgardHash mdHashDummy = new MerkleDamgardHash(dummyCompression, dummyIv);

        String message1 = "Hello, Merkle-Damgard!";
        String message2 = "Hello, Merkle-Damgard!!";
        String message3 = "Hello, Merkle-Damgard!";

        byte[] hash1Dummy = mdHashDummy.hash(message1.getBytes());
        byte[] hash2Dummy = mdHashDummy.hash(message2.getBytes());
        byte[] hash3Dummy = mdHashDummy.hash(message3.getBytes());

        System.out.println("--- Dummy Compression Function Results ---");
        System.out.println("Message 1: \"" + message1 + "\"");
        System.out.println("Hash 1: " + bytesToHex(hash1Dummy));
        System.out.println("Message 2: \"" + message2 + "\"");
        System.out.println("Hash 2: " + bytesToHex(hash2Dummy));
        System.out.println("Message 3: \"" + message3 + "\"");
        System.out.println("Hash 3: " + bytesToHex(hash3Dummy));
        System.out.println("Hash 1 == Hash 3? " + Arrays.equals(hash1Dummy, hash3Dummy));
        System.out.println("Hash 1 == Hash 2? " + Arrays.equals(hash1Dummy, hash2Dummy));
        System.out.println("----------------------------------------\n");


        // --- Using the SHA256 Compression Function ---
        SHA256CompressionFunction sha256Compression = new SHA256CompressionFunction();
        // SHA-256 IV (Initial Hash Value) constants (first 32 bits of the fractional parts of the square roots of the first 8 prime numbers)
        byte[] sha256IvBytes = {
                (byte)0x6a, (byte)0x09, (byte)0xe6, (byte)0x67, // H0
                (byte)0xbb, (byte)0x67, (byte)0xae, (byte)0x85, // H1
                (byte)0x3c, (byte)0x6e, (byte)0xf3, (byte)0x72, // H2
                (byte)0xa5, (byte)0x4f, (byte)0xf5, (byte)0x3a, // H3
                (byte)0x51, (byte)0x0e, (byte)0x52, (byte)0x7f, // H4
                (byte)0x9b, (byte)0x05, (byte)0x68, (byte)0x8c, // H5
                (byte)0x1f, (byte)0x83, (byte)0xd9, (byte)0xab, // H6
                (byte)0x5b, (byte)0xe0, (byte)0xcd, (byte)0x19  // H7
        };

        MerkleDamgardHash mdHashSHA256 = new MerkleDamgardHash(sha256Compression, sha256IvBytes);

        String sha256Message1 = "abc";
        String sha256Message2 = "abcd";
        String sha256Message3 = "";

        byte[] hash1SHA256 = mdHashSHA256.hash(sha256Message1.getBytes());
        byte[] hash2SHA256 = mdHashSHA256.hash(sha256Message2.getBytes());
        byte[] hash3SHA256 = mdHashSHA256.hash(sha256Message3.getBytes());

        System.out.println("--- SHA-256 Compression Function Results ---");
        System.out.println("Message 1: \"" + sha256Message1 + "\"");
        System.out.println("Hash 1 (SHA-256): " + bytesToHex(hash1SHA256));
        // Expected for "abc": ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        System.out.println("Message 2: \"" + sha256Message2 + "\"");
        System.out.println("Hash 2 (SHA-256): " + bytesToHex(hash2SHA256));
        // Expected for "abcd": 88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589
        System.out.println("Message 3: \"" + sha256Message3 + "\"");
        System.out.println("Hash 3 (SHA-256): " + bytesToHex(hash3SHA256));
        // Expected for "": e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        System.out.println("----------------------------------------\n");
    }

    /**
     * Helper method to convert a byte array to a hexadecimal string for display.
     * @param bytes The byte array to convert.
     * @return A hexadecimal string representation.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

/**
 * Implements the SHA-256 compression function as per FIPS 180-4.
 * This class adheres to the CompressionFunction interface.
 */
class SHA256CompressionFunction implements CompressionFunction {

    // SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers)
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private static final int BLOCK_SIZE = 64; // 512 bits = 64 bytes
    private static final int OUTPUT_SIZE = 32; // 256 bits = 32 bytes

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public int getOutputSize() {
        return OUTPUT_SIZE;
    }

    /**
     * Implements the SHA-256 compression function (main loop).
     *
     * @param chainingValue The 256-bit (32-byte) current hash state (a, b, c, d, e, f, g, h).
     * @param messageBlock  The 512-bit (64-byte) message block.
     * @return The new 256-bit (32-byte) hash state.
     */
    @Override
    public byte[] compress(byte[] chainingValue, byte[] messageBlock) {
        // Initialize the eight working variables (a, b, c, d, e, f, g, h)
        // with the current chaining value.
        int a = bytesToInt(chainingValue, 0);
        int b = bytesToInt(chainingValue, 4);
        int c = bytesToInt(chainingValue, 8);
        int d = bytesToInt(chainingValue, 12);
        int e = bytesToInt(chainingValue, 16);
        int f = bytesToInt(chainingValue, 20);
        int g = bytesToInt(chainingValue, 24);
        int h = bytesToInt(chainingValue, 28);

        // Prepare the message schedule W (64 words of 32 bits)
        int[] W = new int[64];
        // First 16 words are directly from the message block
        for (int i = 0; i < 16; i++) {
            W[i] = bytesToInt(messageBlock, i * 4);
        }
        // Extend the remaining 48 words
        for (int i = 16; i < 64; i++) {
            W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
        }

        // Main compression loop (64 rounds)
        for (int i = 0; i < 64; i++) {
            int T1 = h + BigSigma1(e) + Ch(e, f, g) + K[i] + W[i];
            int T2 = BigSigma0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Add the compressed chunk to the current hash value
        // The result is the new chaining value
        byte[] newChainingValue = new byte[OUTPUT_SIZE];
        intToBytes(a + bytesToInt(chainingValue, 0), newChainingValue, 0);
        intToBytes(b + bytesToInt(chainingValue, 4), newChainingValue, 4);
        intToBytes(c + bytesToInt(chainingValue, 8), newChainingValue, 8);
        intToBytes(d + bytesToInt(chainingValue, 12), newChainingValue, 12);
        intToBytes(e + bytesToInt(chainingValue, 16), newChainingValue, 16);
        intToBytes(f + bytesToInt(chainingValue, 20), newChainingValue, 20);
        intToBytes(g + bytesToInt(chainingValue, 24), newChainingValue, 24);
        intToBytes(h + bytesToInt(chainingValue, 28), newChainingValue, 28);

        return newChainingValue;
    }

    // --- SHA-256 Helper Functions (Bitwise Operations) ---

    // Right Rotate (circular right shift)
    private static int rotR(int x, int n) {
        return (x >>> n) | (x << (32 - n));
    }

    // Right Shift
    private static int shR(int x, int n) {
        return x >>> n;
    }

    // SHA-256 functions
    private static int Ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    private static int Maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static int BigSigma0(int x) {
        return rotR(x, 2) ^ rotR(x, 13) ^ rotR(x, 22);
    }

    private static int BigSigma1(int x) {
        return rotR(x, 6) ^ rotR(x, 11) ^ rotR(x, 25);
    }

    private static int sigma0(int x) {
        return rotR(x, 7) ^ rotR(x, 18) ^ shR(x, 3);
    }

    private static int sigma1(int x) {
        return rotR(x, 17) ^ rotR(x, 19) ^ shR(x, 10);
    }

    // --- Utility methods for byte-to-int and int-to-byte conversion ---

    /**
     * Converts 4 bytes from a byte array into an int (big-endian).
     * @param bytes The byte array.
     * @param offset The starting offset in the byte array.
     * @return The integer value.
     */
    private static int bytesToInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 24) |
                ((bytes[offset + 1] & 0xFF) << 16) |
                ((bytes[offset + 2] & 0xFF) << 8) |
                (bytes[offset + 3] & 0xFF);
    }

    /**
     * Converts an int into 4 bytes and writes them to a byte array (big-endian).
     * @param value The integer value.
     * @param bytes The byte array to write to.
     * @param offset The starting offset in the byte array.
     */
    private static void intToBytes(int value, byte[] bytes, int offset) {
        bytes[offset] = (byte) (value >>> 24);
        bytes[offset + 1] = (byte) (value >>> 16);
        bytes[offset + 2] = (byte) (value >>> 8);
        bytes[offset + 3] = (byte) value;
    }
}