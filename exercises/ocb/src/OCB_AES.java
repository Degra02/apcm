import java.io.IOException;
import java.util.Arrays;

import static java.lang.System.*;

public class OCB_AES {
    private final byte[][] L;
    private final byte[] sum;
    private final byte[] offset;
    private final byte[] checksum;
    private final AES cipher;
    private final AES bid_cipher;
    private final boolean decrypt;

    public OCB_AES(boolean decrypt, byte[] key) throws IOException {
        checksum = new byte[16];
        offset = new byte[16];
        sum = new byte[16];
        final int MAX_LOG_MESSAGES = 64;
        L = new byte[MAX_LOG_MESSAGES][16];

        cipher = new AES();
        cipher.init(true, key);
        cipher.processBlock(new byte[16], 0, L[0], 0);

        this.decrypt = decrypt;
        if (decrypt) {
            bid_cipher = new AES();
            bid_cipher.init(false, key);
        } else {
            bid_cipher = cipher;
        }

        // BUG: Fixed out of bounds
        for (int i = 0; i < MAX_LOG_MESSAGES - 1; i++) {
            L[i + 1] = dbl(L[i]);
        }
    }

    // Doubling operation in GF(2^128)
    private byte[] dbl(byte[] S) {
        byte[] res = new byte[16];
        // BUG: fixed missing parentheses
        if (((S[0] >>> 7) & 1) == 1) {
            res[15] = (byte) 0x87;
        }
        for (int i = 0; i < 15; i++) {
            res[i] = (byte) ((S[i] << 1) | ((S[i + 1] >> 7) & 1));
        }
        res[15] ^= (byte) (S[15] << 1);
        return res;
    }

    ///  Number of trailing zeroes
    private int ntz(int i) {
        assert i != 0;
        int n = 0;
        while ((i & 1) == 0) {
            i >>>= 1;
            n++;
        }
        return  n;
    }

    private void hash(byte[] A) throws IOException {
        int m = A.length >> 4;
        final byte[] c_in = new byte[16];
        final byte[] c_out = new byte[16];

        for (int i = 0; i < m; i++) {
            // Offset_i = Offset_{i-1} XOR L_{ntz(i)}
            for (int j = 0; j < 16; j++) {
                // BUG: ntz(0) is faulty
                // BUG: Moreover, it should be L[ntz(i + 1) + 2]
                offset[j] ^= L[ntz(i + 1) + 2][j];

                // A_i xor Offset_i
                c_in[j] = (byte) (A[(i << 4) + j] ^ offset[j]);
            }
            // c_out = ENCIPHER(K, A_i xor Offset_i)
            cipher.processBlock(c_in, 0, c_out, 0);

            // Sum_i = Sum_{i-1} XOR c_out
            for (int j = 0; j < 16; j++) {
                sum[j] ^= c_out[j];
            }
        }

        // Processing of remaining block
        // A_* is used to denote the last partial block (in RFC)
        int rem_bytes = A.length & 0xF;
        if (rem_bytes > 0){
            // Offset_* = Offset_m XOR L_*
            for (int i = 0; i < rem_bytes; i++) {
                c_in[i] = (byte) (A[(m << 4) + i] ^ offset[i] ^ L[0][i]);
            }

            // CipherInput = (A_* || 1 || zeros(127 - bitlength(A_*))) XOR Offset_*
            // BUG: 1 is wrong, should be 0x80
            c_in[rem_bytes] = (byte) (0x80 ^ offset[rem_bytes] ^ L[0][rem_bytes]);
            for (int i = rem_bytes + 1; i < 16; i++) {
                c_in[i] = (byte) (offset[i] ^ L[0][i]);
            }

            // c_out = ENCIPHER(K, CipherInput)
            cipher.processBlock(c_in, 0, c_out, 0);
            for (int j = 0; j < 16; j++) {
                sum[j] ^= c_out[j];
            }
        }
    }

    public byte[] process(byte[] N, byte[] A, byte[] P) throws Exception {
        Arrays.fill(offset, (byte)0);
        Arrays.fill(checksum, (byte)0);
        Arrays.fill(sum, (byte)0);

        hash(A);

        if (decrypt && P.length < 16) {
            throw new IllegalArgumentException("ciphertext too short (no tag)");
        }

        // BUG: if plaintext is <= 16 bytes and decrypting, access to negative index
        int plen;
        byte[] inBuf;
        byte[] outBuf;
        byte[] receivedTag = null;

        if (decrypt) {
            plen = P.length - 16;
            inBuf = Arrays.copyOfRange(P, 0, plen); // ciphertext-only
            receivedTag = Arrays.copyOfRange(P, plen, P.length);
            outBuf = new byte[plen]; // plaintext output
        } else {
            plen = P.length;
            inBuf = P; // plaintext input
            outBuf = new byte[plen + 16]; // ciphertext + tag output
        }

        byte[] C = new byte[plen + 16];
        byte[] nonce = new byte[16];

        // Fine since this code only supports 128 bit nonces
        nonce[15 - N.length] = 1;
        arraycopy(N, 0, nonce, 16 - N.length, N.length);

        // we take just the bottom 6 bits
        int bottom = nonce[15] & 0x3f;
        // clear bottom 6 bits
        nonce[15] &= (byte) 0xc0;

        // Ktop = ENCIPHER(K, Nonce[1..122] || 0^6
        cipher.processBlock(nonce, 0, offset, 0);

        // stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
        long[] stretch = new long[3];

        // Ktop[1..64] xor Ktop[9..72]
        // BUG: fixed offset signs via & 0xFF
        for (int i = 0; i < 8; i++) {
            stretch[0] |= (((long) offset[i]) & 0xFF)  << (56 - (i << 3));
            stretch[1] |= (((long) offset[i + 8]) & 0xFF)  << (56 - (i << 3));
            stretch[2] |= (((long) (offset[i] ^ offset[i + 1])) & 0xFF) << (56 - (i << 3));
        }
        for (int i = 0; i < 2; i++) {
            stretch[i] = (stretch[i] << bottom) | (stretch[i + 1] >>> (64 - bottom));
        }
        for (int i = 0; i < 16; i++) {
            offset[i] = (byte) (stretch[i >> 3] >>> (56 - ((i & 7) << 3)));
        }

        final byte[] c_in = new byte[16];
        final byte[] tmp_out = new byte[16];
        for (int i = 0; i < plen - 15; i += 16) {
            int li = ntz((i >>> 4) + 1) + 2;

            for (int j = 0; j < 16; j++) {
                offset[j] ^= L[li][j];
                c_in[j] = (byte) (P[i + j] ^ offset[j]);
            }

            // This is either encryption or decryption
            bid_cipher.processBlock(c_in, 0, tmp_out, i);

            if (!decrypt) {
                for (int j = 0; j < 16; j++) {
                    C[i + j] = (byte) (tmp_out[j] ^ offset[j]);
                    checksum[j] ^= inBuf[i + j];
                }
            } else {
                for (int j = 0; j < 16; j++) {
                    outBuf[i + j] = (byte) (tmp_out[j] ^ offset[j]);
                    checksum[j] ^= outBuf[i + j];
                }
            }
        }

        int rem_bytes = plen & 0xf;
        int full_blocks = plen & 0xfffffff0;

        if (rem_bytes > 0) {
            // Offset_* = Offset_m xor L_*
            for (int j = 0; j < 16; j++) offset[j] ^= L[0][j];

            // c_in <- PAD = ENCIPHER(K, Offset_*)
            cipher.processBlock(offset, 0, c_in, 0);

            if (!decrypt) {
                // C_* = P_* xor Pad[1..bitlen(P_*)]
                for (int j = 0; j < rem_bytes; j++) {
                    C[full_blocks + j] = (byte) (c_in[j] ^ inBuf[full_blocks + j]);
                    checksum[j] ^= inBuf[full_blocks + j];
                }
            } else {
                // P_* = C_* xor Pad[1..bitlen(C_*)]
                for (int j = 0; j < rem_bytes; j++) {
                    outBuf[full_blocks + j] = (byte) (c_in[j] ^ inBuf[full_blocks + j]);
                    checksum[j] ^= outBuf[full_blocks + j];
                }
            }

            // Bug: this was 1, should be 0x80
            checksum[rem_bytes] ^= (byte) 0x80;
        }

        // TAG computation
        // BUG: this should start from 0, not rem_bytes
        for (int i = 0; i < 16; i++) {
            checksum[i] ^= (byte) (offset[i] ^ L[1][i]);
        }

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        byte[] computed_tag = new byte[16];
        cipher.processBlock(checksum, 0, computed_tag, 0);

        for (int j = 0; j < 16; j++) {
            computed_tag[j] ^= sum[j]; // sum = HASH(K,A)
        }

        // BUG: missing tag verification
        if (decrypt) {
            if (!check_tag(receivedTag, computed_tag)) {
                throw new SecurityException("Tag mismatch!");
            }
            return outBuf;
        } else {
            // BUG: implementation was missing tag appending
            // Append tag to ciphertext
            System.arraycopy(computed_tag, 0, C, plen, 16);

            return C;
        }
    }

    // BUG: timing attack
    public boolean check_tag(byte[] o_tag, byte[] r_tag) {
        boolean res = o_tag.length == r_tag.length;

        int len = Math.max(o_tag.length, r_tag.length);
        for (int i = 0; i < len; i++) {
            res &= (o_tag[i % o_tag.length] == r_tag[i % r_tag.length]);
        }
        return res;
    }

    public static void printHex(byte[] bb) {
        for (byte b : bb) {
            // pad with 0
            System.out.printf("%02X", b);
        }
        // new line for clarity
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
        byte[] key = java.util.HexFormat.of().parseHex("000102030405060708090A0B0C0D0E0F");
        byte[] nonce = java.util.HexFormat.of().parseHex("BBAA99887766554433221101");
        byte[] associatedData = java.util.HexFormat.of().parseHex("0001020304050607");
        byte[] plaintext = java.util.HexFormat.of().parseHex("0001020304050607");

        OCB_AES enc = new OCB_AES(false,
                key
        );

        byte[] ciphertext = enc.process(
                // Nonce, can be 0 length
                nonce,
                // Associated Data, any length
                associatedData,
                // Plaintext, any length
                plaintext
        );
        printHex(ciphertext);

        OCB_AES dec = new OCB_AES(true,
                key
        );

        byte[] decrypted = dec.process(
                // Nonce, can be 0 length
                nonce,
                // Associated Data, any length
                associatedData,
                // Ciphertext + Tag, any length
                ciphertext
        );

        printHex(decrypted);
    }
}
