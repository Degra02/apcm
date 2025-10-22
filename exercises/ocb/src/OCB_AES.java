import java.io.IOException;

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
//        L_dollar = dbl(L_ast);
//        L[0] = dbl(L_dollar);
//        for (int i = 1; i < MAX_LOG_MESSAGES; i++) {
//            L[i] = dbl(L[i - 1]);
//        }

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
                // Moreover, it should be L[ntz(i + 1) + 2]
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
//        int rem_bytes = A.length & 0xF;
//        if (rem_bytes > 0){
//            // Offset_* = Offset_m XOR L_*
//            for (int i = 0; i < rem_bytes; i++) {
//                c_in[i] = (byte) (A[(m << 4) + i] ^ offset[i] ^ L_ast[i]);
//            }
//
//            // CipherInput = (A_* || 1 || zeros(127 - bitlength(A_*))) XOR Offset_*
//            // TODO: should this be with 0x80 or 1?
//            c_in[rem_bytes] = (byte) (0x80 ^ offset[rem_bytes] ^ L[0][rem_bytes]);
//            for (int i = rem_bytes + 1; i < 16; i++) {
//                c_in[i] = (byte) (offset[i] ^ L[0][i]);
//            }
//
//            // c_out = ENCIPHER(K, CipherInput)
//            cipher.processBlock(c_in, 0, c_out, 0);
//            for (int j = 0; j < 16; j++) {
//                sum[j] ^= c_out[j];
//            }
//        }

        // Cleaner version, following RFC pseudocode
        int rem_bytes = A.length & 0xF;
        if (rem_bytes > 0) {
            byte[] offset_star = new byte[16];
            for (int j = 0; j < 16; j++) {
                offset_star[j] = (byte) (offset[j] ^ L[0][j]);
            }

            for (int i = 0; i < rem_bytes; i++) {
                c_in[i] = (byte) (A[(m << 4) + i] ^ offset_star[i]);
            }
            c_in[rem_bytes] = (byte) (0x80 ^ offset_star[rem_bytes]);
            System.arraycopy(offset_star, rem_bytes + 1, c_in, rem_bytes + 1, 16 - (rem_bytes + 1));

            // c_out = ENCIPHER(K, c_in)
            cipher.processBlock(c_in, 0, c_out, 0);

            // Sum = Sum_m XOR c_out
            for (int j = 0; j < 16; j++) {
                sum[j] ^= c_out[j];
            }
        }
    }

    public byte[] process(byte[] N, byte[] A, byte[] P) throws Exception {
        hash(A);

        // BUG: if plaintext is <= 16 bytes and decrypting, access to P[-1]
        int plen = P.length;
        if (decrypt) {
            plen -= 16;
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
        for (int i = 0; i < 8; i++) {
            stretch[0] |= (long) offset[i]  << (56 - (i << 3));
            stretch[1] |= (long) offset[i + 8]  << (56 - (i << 3));
            stretch[2] |= (long) (offset[i] ^ offset[i + 1]) << (56 - (i << 3));
        }
        for (int i = 0; i < 2; i++) {
            stretch[i] = (stretch[i] << bottom) | (stretch[i + 1] >>> (64 - bottom));
        }
        for (int i = 0; i < 16; i++) {
            offset[i] = (byte) (stretch[i >> 3] >>> (56 - ((i & 7) << 3)));
        }

        final byte[] c_in = new byte[16];
        for (int i = 0; i < plen - 15; i += 16) {
            int li = ntz((i >>> 4) + 1) + 2;
            for (int j = 0; j < 16; j++) {
                offset[j] ^= L[li][j];
                c_in[j] = (byte) (P[i + j] ^ offset[j]);
            }

            // This is either encryption or decryption
            bid_cipher.processBlock(c_in, 0, C, i);
            for (int j = 0; j < 16; j++) {
                C[i + j] ^= offset[j];
                checksum[j] ^= P[i + j];
            }
        }

        int rem_bytes = plen & 0xf;
        int full_blocks = plen & 0xfffffff0;

        if (rem_bytes > 0) {
            // Offset_* = Offset_m xor L_*
            for (int j = 0; j < 16; j++) {
                offset[j] ^= L[0][j];
            }
            // c_in <- PAD = ENCIPHER(K, Offset_*)
            cipher.processBlock(offset, 0, c_in, 0);

            // C_* = P_* xor Pad[1..bitlen(P_*)]
            for (int j = 0; j < rem_bytes; j++) {
                C[full_blocks + j] = (byte) (c_in[j] ^ P[full_blocks + j]);
                checksum[j] ^= P[full_blocks + j];
            }
            // Bug: this was 1, should be 0x80
            checksum[rem_bytes] ^= (byte) 0x80;
        }

        // TAG computation
        for (int i = 0; i < 16; i++) {
            checksum[i] ^= (byte) (offset[i] ^ L[1][i]);
        }

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        byte[] tag = new byte[16];
        cipher.processBlock(checksum, 0, tag, 0);

        for (int j = 0; j < 16; j++) {
            tag[j] ^= sum[j]; // sum = HASH(K,A)
        }

        // Append tag to ciphertext
        System.arraycopy(tag, 0, C, plen, 16);

        return C;
    }

    // BUG: timing attack
    public boolean check_tag(byte[] o_tag, byte[] r_tag) {
        boolean res = o_tag.length == r_tag.length;

        int len = Math.max(o_tag.length, r_tag.length);
        for (int i = 0; i < len; i++) {
            if (o_tag[i % o_tag.length] != r_tag[i % r_tag.length]) {
                res = false;
            }
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
        printHex(new OCB_AES(false,
                // Key
                java.util.HexFormat.of().parseHex("000102030405060708090A0B0C0D0E0F")
        ).process(
                // Nonce, can be 0 length
                java.util.HexFormat.of().parseHex("BBAA9988776655443322110F"),
                // Associated Data, any length
                java.util.HexFormat.of().parseHex(""),
                // Plaintext, any length
                java.util.HexFormat.of().parseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627")
        ));
        System.out.println("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479");
    }
}
